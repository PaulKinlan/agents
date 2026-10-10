#!/usr/bin/env python3
"""Beads tracker sink: file findings as beads automatically (agents-eyo).

Moved out of lib/findings.py for layering (fleet-km8). The only guard is fingerprint dedupe
(external_ref `factory:<fingerprint>`), never a human: a re-run matches the existing bead and
files nothing new. A tracker that cannot be listed files nothing rather than risk duplicates.
The embargo partition (which findings this sink may receive) is decided by
lib.findings.dispatch_to_sink before this adapter is called; this module re-checks it so a
direct call stays safe.
"""

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from lib.redaction import redact_finding
from lib.embargo import effective_severity, embargo_reason
from lib.tool_pins import ToolPinError, resolve_tool
from lib.sinks.base import Sink, SinkContext


_BEAD_EXTERNAL_REF_PREFIX = "factory:"

_BEAD_EXTERNAL_REF_RE = re.compile(
    r"^factory:(?:github\.com/[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*:)?([0-9a-f]{64})$"
)

_BEAD_FINGERPRINT_LINE = re.compile(r"Fingerprint:\s*([0-9a-f]{64})")

_BEAD_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

def _bd_json(bd_bin: str, beads_dir: Path, args: List[str]) -> Any:
    """Run one bounded Beads operation in the explicitly configured project DB.

    Verified against real bd 1.3.1 (c1c4b642a, 2026-10-07) in a throwaway DB by
    tests/test_bd_json_contract.py: create --json returns {id,...}, list --all --json
    returns [{id,external_ref,description,status,...}], and update --json returns
    [{id,...}] (an ARRAY, not an object). Promotion intentionally ignores the
    update value. The recorder matches these shapes; do not trust stubs alone.
    """
    res = subprocess.run([bd_bin, *args, "-C", str(beads_dir)], cwd=str(beads_dir),
                         capture_output=True, text=True, check=False, timeout=60)
    if res.returncode != 0:
        # Tracker error output can contain raw finding text; do not copy it to logs.
        raise RuntimeError(f"bd {args[0]} failed (exit {res.returncode}); promotion may be retried")
    try:
        return json.loads(res.stdout)
    except ValueError as e:
        raise RuntimeError(f"bd {args[0]} returned invalid JSON; refusing a second create") from e

def _existing_bead_fingerprints(bd_bin: str, beads_dir: Path) -> Optional[Dict[str, List[Dict[str, str]]]]:
    """fingerprint -> [{id, status}] for every bead (any status) the factory filed before.

    A bead is matched by its `external_ref` (`factory:<fingerprint>`), or, for beads filed
    before that existed, by the `Fingerprint: <sha256>` line the description always carried.
    Returns None when the tracker cannot be listed (never treat an unreadable listing as empty).
    """
    cmd = [bd_bin, "list", "--all", "--json", "-n", "0", "-C", str(beads_dir)]
    try:
        res = subprocess.run(cmd, cwd=str(beads_dir), capture_output=True, text=True,
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
        if isinstance(ref, str):
            m = _BEAD_EXTERNAL_REF_RE.match(ref.strip())
            if m:
                fingerprints.add(m.group(1))
        description = bead.get("description")
        if isinstance(description, str):
            fingerprints.update(_BEAD_FINGERPRINT_LINE.findall(description))
        for fp in fingerprints:
            index.setdefault(fp, []).append({"id": str(bead.get("id", "?")),
                                             "status": str(bead.get("status", ""))})
    return index


def _dispatch_beads(beads_dir: Path, findings: List[Dict[str, Any]],
                    visibility: Any = None) -> Dict[str, Any]:
    """File findings as beads automatically (agents-eyo): beads is the tracked owner-visible
    surface where untriaged findings belong, with no public GitHub issue and no human gate.

    The only guard is fingerprint dedupe (external_ref `factory:<fingerprint>`), never a human:
    a re-run matches the existing bead and files nothing new. A tracker that cannot be listed
    files nothing rather than risk duplicates. Returns delivery counts.
    """
    result: Dict[str, Any] = {"published": 0, "failed": 0, "skipped": 0, "duplicate": 0, "note": ""}
    # Classify first so the totals do not depend on finding order and never exceed what was
    # eligible: embargoed or below-band findings are `skipped`; only ones this sink would
    # actually file can be `failed`.
    to_file: List[Dict[str, Any]] = []
    for f in findings:
        if "beads" in f.get("dispatched_sinks", []):
            continue
        # dispatch_to_sink already applied and logged the embargo; this keeps a direct call to
        # the sink safe. Beads publishes medium and above: critical and high are what the
        # embargo withholds from a synced tracker when visibility is missing.
        if embargo_reason(f, "beads", visibility):
            result["skipped"] += 1
            continue
        # Beads is a synced tracker and never takes low/info.
        if f["state"] in ("new", "regressed") and effective_severity(f) in ("critical", "high", "medium"):
            to_file.append(f)
        else:
            result["skipped"] += 1
    if not to_file:
        return result

    beads_dir = beads_dir.expanduser().resolve()
    if not beads_dir.is_dir() or not (beads_dir / ".beads").is_dir():
        result["failed"] += len(to_file)
        result["note"] = f"no initialized Beads DB in {beads_dir}: nothing filed"
        print(f"Warning: {result['note']}")
        return result

    try:
        bd_bin = resolve_tool("bd")
    except ToolPinError as e:
        # Fail closed, but retain the finding and report a clean failure (agents-7bj): a
        # missing bd or a bd that does not match its integrity pin must never silently file
        # nothing and look like a pass.
        result["failed"] += len(to_file)
        result["note"] = f"bd unavailable or unverified: {e}"
        print(f"Warning: {result['note']}")
        return result

    # Dedupe against the beads that already exist. The store's receipts only cover this store;
    # a fresh worktree, a renamed target or a reset store re-filed every finding. Read once;
    # if the tracker cannot be read, file nothing rather than risk duplicates, and say so.
    existing = _existing_bead_fingerprints(bd_bin, beads_dir)
    if existing is None:
        result["failed"] += len(to_file)
        result["note"] = "could not list existing beads to dedupe against: nothing filed"
        print(f"Warning: {result['note']}")
        return result

    for f in to_file:
        matches = existing.get(f["fingerprint"], [])
        open_matches = [m for m in matches if m.get("status") != "closed"]
        if open_matches or (matches and f["state"] != "regressed"):
            result["duplicate"] += 1
            ids = ", ".join(m.get("id", "?") for m in (open_matches or matches))
            print(f"Skipped duplicate: {f['fingerprint'][:16]} already tracked by {ids}")
            continue
        published = redact_finding(f)
        title = f"[{published['agent']}] {published['title']}"
        desc = (f"{published['description']}\n\n"
                f"Path: {published['path']}:{published.get('line_number', '?')}\n"
                f"Fingerprint: {f['fingerprint']}\nSnippet:\n{published['snippet']}")
        try:
            bead = _bd_json(bd_bin, beads_dir, [
                "create", "--title", title, "--description", desc,
                "--type", "bug" if "vuln" in f.get("agent", "") or "secret" in f.get("agent", "") else "task",
                "--external-ref", f"{_BEAD_EXTERNAL_REF_PREFIX}{f['fingerprint']}", "--json",
            ])
            bead_id = bead.get("id") if isinstance(bead, dict) else None
            if not isinstance(bead_id, str) or not _BEAD_ID.fullmatch(bead_id):
                raise RuntimeError("bd create did not return a valid id")
            f.setdefault("dispatched_sinks", []).append("beads")
            existing.setdefault(f["fingerprint"], []).append({"id": bead_id, "status": "open"})
            result["published"] += 1
            print(f"Created bead for: {published['title']}")
        except (OSError, subprocess.TimeoutExpired, RuntimeError, ValueError) as e:
            result["failed"] += 1
            result["note"] = str(e)
            print(f"Failed to create bead: {e}")
    return result


# Target guidance is only consulted when the manifest has no explicit sink.
AGENTS_MD_PHRASES = ("beads only", "bd is the only", "uses **bd**",
                     "use `bd` for all task tracking")


class BeadsSink(Sink):
    name = "beads"

    def detect(self, target_dir: Path) -> bool:
        agents_md = target_dir / "AGENTS.md"
        if not agents_md.exists():
            return False
        content = agents_md.read_text(encoding="utf-8", errors="ignore").lower()
        return any(phrase in content for phrase in AGENTS_MD_PHRASES)

    def publish(self, ctx: SinkContext, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        return _dispatch_beads(ctx.beads_dir or ctx.target_dir, findings, ctx.visibility)
