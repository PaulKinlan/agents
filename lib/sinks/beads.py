"""The `beads` sink: one bead per finding via `bd create`, deduped by fingerprint.

Moved from lib/findings.py unchanged in behaviour (fleet-km8). Beads is a synced tracker:
it takes critical/high/medium only, and core's embargo has already withheld the bands a
public target must not publish.
"""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from lib.embargo import effective_severity, embargo_reason
from lib.redaction import redact_finding
from lib.sinks.base import Sink, SinkContext

# Phrases in a target's AGENTS.md that make beads its tracker (sink discovery step 1).
AGENTS_MD_PHRASES = (
    "beads only",
    "bd is the only",
    "uses **bd**",
    "use `bd` for all task tracking",
)


BEAD_EXTERNAL_REF_PREFIX = "factory:"
_BEAD_FINGERPRINT_LINE = re.compile(r"Fingerprint:\s*([0-9a-f]{64})")


def _existing_bead_fingerprints(bd_bin: str, target_dir: Path) -> Optional[Dict[str, List[Dict[str, str]]]]:
    """fingerprint -> [{id, status}] for every bead (any status) the factory filed before.

    A bead is matched by its `external_ref` (`factory:<fingerprint>`), or, for beads filed
    before that existed, by the `Fingerprint: <sha256>` line the description always carried.
    Returns None when the tracker cannot be listed.
    """
    cmd = [bd_bin, "list", "--all", "--json", "-n", "0", "-C", str(target_dir)]
    try:
        res = subprocess.run(cmd, cwd=str(target_dir), capture_output=True, text=True,
                             check=False, timeout=60)
        if res.returncode != 0:
            return None
        beads = json.loads(res.stdout or "[]")
    except Exception:
        return None
    if not isinstance(beads, list):
        return None
    index: Dict[str, List[Dict[str, str]]] = {}
    for bead in beads:
        if not isinstance(bead, dict):
            continue
        fingerprints = set()
        ref = bead.get("external_ref")
        if isinstance(ref, str) and ref.startswith(BEAD_EXTERNAL_REF_PREFIX):
            fingerprints.add(ref[len(BEAD_EXTERNAL_REF_PREFIX):].strip())
        description = bead.get("description")
        if isinstance(description, str):
            fingerprints.update(_BEAD_FINGERPRINT_LINE.findall(description))
        for fp in fingerprints:
            index.setdefault(fp, []).append({"id": str(bead.get("id", "?")),
                                             "status": str(bead.get("status", ""))})
    return index


def _dispatch_beads(target_dir: Path, findings: List[Dict[str, Any]], visibility: Any = "public") -> Dict[str, Any]:
    """Creates beads for active findings if bd is available. Returns delivery counts."""
    result: Dict[str, Any] = {"published": 0, "failed": 0, "skipped": 0, "duplicate": 0, "note": ""}
    # Classify first, so the totals do not depend on finding order and never exceed what
    # was eligible: embargoed or below-band findings are `skipped` whatever happens next;
    # only the ones this sink would actually file can be `failed` (fleet-xkf review).
    to_file: List[Dict[str, Any]] = []
    for f in findings:
        if "beads" in f.get("dispatched_sinks", []):
            continue
        # dispatch_to_sink already applied and logged the embargo; this keeps a direct call to
        # the sink safe. Beads publishes medium only, as it did before: critical and high are
        # exactly what the embargo withholds from a synced tracker (agents-681).
        if embargo_reason(f, "beads", visibility):
            result["skipped"] += 1
            continue
        # Beads is a synced tracker and never takes low/info. On a public target the central
        # filter has already withheld critical/high; on a private one the embargo lets them
        # through, which is the point of reading visibility (agents-5rx).
        if f["state"] in ("new", "regressed") and effective_severity(f) in ("critical", "high", "medium"):
            to_file.append(f)
        else:
            # low/info never go to a synced tracker; counted, so a zero is explained.
            result["skipped"] += 1
    if not to_file:
        return result

    if not (target_dir / ".beads").exists():
        print(f"Warning: .beads directory not found in {target_dir}. Falling back to file sink.")
        result["failed"] += len(to_file)
        result["note"] = f"no .beads directory in {target_dir}: nothing filed"
        return result

    bd_bin = shutil.which("bd") or str(Path.home() / ".local" / "bin" / "bd")
    if not os.path.exists(bd_bin):
        print("Warning: bd binary not available. Findings stored in JSON only.")
        result["failed"] += len(to_file)
        result["note"] = "bd binary not available: nothing filed"
        return result

    # Dedupe against the beads that already exist (fleet-xkf). The store's receipts only
    # cover this store; a fresh worktree, a renamed target or a reset store re-filed every
    # finding. Read once; if the tracker cannot be read, file nothing rather than risk
    # duplicates, and say so.
    existing = _existing_bead_fingerprints(bd_bin, target_dir)
    if existing is None:
        result["failed"] += len(to_file)
        result["note"] = "could not list existing beads to dedupe against: nothing filed"
        print(f"Warning: {result['note']}")
        return result

    for f in to_file:
        matches = existing.get(f["fingerprint"], [])
        open_matches = [m for m in matches if m.get("status") != "closed"]
        if open_matches or (matches and f["state"] != "regressed"):
            # An open bead already tracks it; or a closed one does and nothing regressed.
            result["duplicate"] = result.get("duplicate", 0) + 1
            ids = ", ".join(m.get("id", "?") for m in (open_matches or matches))
            print(f"Skipped duplicate: {f['fingerprint'][:16]} already tracked by {ids}")
            continue
        # Both title and description come from the published view. Building the title from
        # the raw finding let a credential the scanner had recognised reach `bd --title`
        # unchanged even though the body was masked (agents-tcd review).
        published = redact_finding(f)
        title = f"[{published['agent']}] {published['title']}"
        desc = (f"{published['description']}\n\nPath: {published['path']}:{published.get('line_number', '?')}\n"
                f"Fingerprint: {f['fingerprint']}\nSnippet:\n{published['snippet']}")
        cmd = [
            bd_bin, "create",
            "--title", title,
            "--description", desc,
            "--type", "bug" if "vuln" in f['agent'] or "secret" in f['agent'] else "task",
            # The finding's identity, queryable, so the next run can dedupe (fleet-xkf).
            "--external-ref", f"{BEAD_EXTERNAL_REF_PREFIX}{f['fingerprint']}",
            "-C", str(target_dir)
        ]
        try:
            res = subprocess.run(cmd, cwd=str(target_dir), capture_output=True, text=True, check=False, timeout=30)
            if res.returncode == 0:
                f.setdefault("dispatched_sinks", []).append("beads")
                existing.setdefault(f["fingerprint"], []).append({"id": res.stdout.strip(), "status": "open"})
                result["published"] += 1
                print(f"Created bead for: {published['title']}")
            else:
                result["failed"] += 1
                print(f"Failed to create bead (exit {res.returncode}): {res.stderr.strip()}")
        except Exception as e:
            result["failed"] += 1
            print(f"Failed to create bead: {e}")
    return result


class BeadsSink(Sink):
    name = "beads"

    def detect(self, target_dir: Path) -> bool:
        agents_md = target_dir / "AGENTS.md"
        if not agents_md.exists():
            return False
        content = agents_md.read_text(encoding="utf-8", errors="ignore").lower()
        return any(phrase in content for phrase in AGENTS_MD_PHRASES)

    def publish(self, ctx: SinkContext, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        return _dispatch_beads(ctx.target_dir, findings, ctx.visibility)
