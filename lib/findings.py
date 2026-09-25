#!/usr/bin/env python3
"""Findings Store and State Machine for Software Factory.

Handles finding identity (excluding line numbers), deduplication, lifecycle
state transitions (new -> accepted | wontfix -> fixed -> regressed), and
sink dispatch (file, beads, github-issues).
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

FACTORY_ROOT = Path(__file__).resolve().parent.parent

# The committed suppressions register. AGENTS.md's noise-control contract requires a written
# reason in a *committed* file; the old per-target JSON was gitignored, so that contract could
# not be satisfied by any path (agents-411).
SUPPRESSIONS_FILENAME = "suppressions.yaml"


class SuppressionFileError(ValueError):
    """The suppressions register cannot be parsed. Loud, never a silent empty dict."""

try:  # imported as lib.findings (root on sys.path), or run as a script (lib/ on it)
    from lib.redaction import redact_finding
except ImportError:
    sys.path.insert(0, str(FACTORY_ROOT))
    from lib.redaction import redact_finding

# Redaction removes the value from published text; the embargo decides whether a finding is
# routed to a tracker at all. It is a separate module so the policy has one home and one test.
from lib.embargo import effective_severity, embargo_reason

def normalize_text(text: Any) -> str:
    """Strip and collapse internal whitespace to make fingerprint resilient to reformatting.

    A malformed field (the model returned a dict or a number instead of text) is coerced rather
    than allowed to raise: identity has to stay deterministic, and a crash here would abort the
    whole run before the publish boundary can sanitise anything. Publishing is a separate gate —
    see lib/redaction.py.
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    return re.sub(r"\s+", " ", text.strip())

def normalize_path(path: Any) -> str:
    """The one path normalization used for fingerprints and candidate binding."""
    if not isinstance(path, str):
        return ""
    return path.replace("\\", "/").strip().lstrip("./")

def compute_fingerprint(agent: str, rule_id: str, path: str, snippet: str) -> str:
    """Compute stable fingerprint: sha256(agent:rule_id:normalized_path:normalized_snippet).
    
    Deliberately excludes line numbers to survive refactor churn.
    """
    norm_path = normalize_path(path)
    norm_snippet = normalize_text(snippet)
    key = f"{agent}:{rule_id}:{norm_path}:{norm_snippet}".encode("utf-8")
    return hashlib.sha256(key).hexdigest()

def load_candidate_index(candidates_file: Path) -> Optional[Dict[str, Any]]:
    """The scanner's authoritative rule ids and paths, for binding model output (agents-nha).

    Returns None when the payload carries no candidate list or neither field, so an agent with
    no deterministic pre-pass — or one whose candidates are not location-shaped, like
    issue-triage's issue records — keeps the model's values.
    """
    try:
        data = json.loads(candidates_file.read_text(encoding="utf-8"))
    except Exception as e:
        sys.stderr.write(f"Warning: could not read candidates {candidates_file}: {e}\n")
        return None

    candidates = data.get("candidates") if isinstance(data, dict) else data
    if not isinstance(candidates, list):
        return None

    rule_ids = set()
    paths = set()
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        rule_id = candidate.get("rule_id")
        if isinstance(rule_id, str) and rule_id.strip():
            rule_ids.add(rule_id.strip())
        path = normalize_path(candidate.get("path"))
        if path:
            paths.add(path)

    if not rule_ids and not paths:
        return None
    return {"rule_ids": rule_ids, "paths": paths}

def bind_candidates(item: Dict[str, Any], candidate_index: Optional[Dict[str, Any]]) -> Tuple[Any, Any]:
    """Bind a finding's `rule_id` and `path` to the deterministic scanner's output.

    The triage model returns these strings, so without a contract any string it invents is
    stored, fingerprinted and rendered. A scanner rule id that is not in the candidate set is
    replaced with `unclassified`; a path that is not among the candidate paths with `unknown`.
    When no candidate set exists there is nothing to bind to, and the model's values pass
    through to the redaction backstop exactly as before (agents-nha).
    """
    rule_id = item.get("rule_id") or "generic"
    path = item.get("path") or ""
    if not candidate_index:
        return rule_id, path

    if candidate_index["rule_ids"]:
        if not (isinstance(rule_id, str) and rule_id.strip() in candidate_index["rule_ids"]):
            rule_id = "unclassified"
    if candidate_index["paths"] and normalize_path(path) not in candidate_index["paths"]:
        path = "unknown"
    return rule_id, path

def _strip_yaml_comment(line: str) -> str:
    """Cut a YAML comment without touching a '#' inside a quoted scalar."""
    quote = None
    for index, char in enumerate(line):
        if quote:
            if char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            quote = char
        elif char == "#" and (index == 0 or line[index - 1] in " \t"):
            return line[:index]
    return line


def parse_suppressions_yaml(text: str, source: str = SUPPRESSIONS_FILENAME) -> Dict[str, Any]:
    """Parse the committed register: `<fingerprint>:` plus indented scalar fields.

    Deliberately the same small subset the agent manifests use — comments, blank lines, one
    level of nesting — and no more: this file is committed and human-edited, so anything
    unexpected raises rather than being ignored. An entry without a reason is rejected because
    AGENTS.md requires one.
    """
    entries: Dict[str, Dict[str, str]] = {}
    current: Optional[Dict[str, str]] = None

    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = _strip_yaml_comment(raw).rstrip()
        if not line.strip():
            continue
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))

        if indent == 0:
            if not stripped.endswith(":"):
                raise SuppressionFileError(
                    f"{source}:{lineno}: expected a '<fingerprint>:' entry, found {stripped!r}"
                )
            fingerprint = stripped[:-1].strip().strip("'\"").lower()
            if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
                raise SuppressionFileError(
                    f"{source}:{lineno}: {stripped[:-1].strip()!r} is not a sha256 fingerprint"
                )
            if fingerprint in entries:
                raise SuppressionFileError(f"{source}:{lineno}: duplicate entry {fingerprint}")
            current = {}
            entries[fingerprint] = current
            continue

        if current is None:
            raise SuppressionFileError(
                f"{source}:{lineno}: field {stripped!r} appears before any fingerprint"
            )
        if ":" not in stripped:
            raise SuppressionFileError(
                f"{source}:{lineno}: expected 'field: value', found {stripped!r}"
            )
        field, value = stripped.split(":", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        current[field.strip()] = value

    for fingerprint, entry in entries.items():
        if not str(entry.get("reason", "")).strip():
            raise SuppressionFileError(
                f"{source}: entry {fingerprint} has no reason; AGENTS.md requires one"
            )
    return entries

class FindingsStore:
    def __init__(self, target_name: str, findings_dir: Optional[Path] = None):
        self.target_name = target_name
        self.findings_dir = findings_dir or (FACTORY_ROOT / "findings")
        self.findings_dir.mkdir(parents=True, exist_ok=True)
        self.store_file = self.findings_dir / f"{target_name}.json"
        self.suppressions_file = self.findings_dir / SUPPRESSIONS_FILENAME
        self.legacy_suppressions_file = self.findings_dir / f"{target_name}.suppressions.json"
        self.data: Dict[str, Any] = self._load_store()
        self.suppressions: Dict[str, Any] = self._load_suppressions()

    def _load_store(self) -> Dict[str, Any]:
        if self.store_file.exists():
            try:
                return json.loads(self.store_file.read_text(encoding="utf-8"))
            except Exception as e:
                sys.stderr.write(f"Warning: could not read {self.store_file}: {e}\n")
        return {"target": self.target_name, "findings": {}}

    def _load_suppressions(self) -> Dict[str, Any]:
        """Read the committed suppressions register (agents-411).

        A parse failure raises instead of returning {}: silently suppressing nothing would
        un-wontfix the whole register without telling anyone.
        """
        if self.legacy_suppressions_file.exists():
            sys.stderr.write(
                f"Warning: {self.legacy_suppressions_file} is ignored (and gitignored); move its "
                f"entries into {self.suppressions_file}\n"
            )
        if not self.suppressions_file.exists():
            return {}
        return parse_suppressions_yaml(
            self.suppressions_file.read_text(encoding="utf-8"), str(self.suppressions_file)
        )

    def save(self):
        self.store_file.write_text(json.dumps(self.data, indent=2), encoding="utf-8")

    def process_run(self, agent: str, raw_findings: List[Dict[str, Any]], candidate_index: Optional[Dict[str, Any]] = None) -> Tuple[List[Dict[str, Any]], Dict[str, int], List[Dict[str, Any]]]:
        """Ingests raw findings from an agent run, applies fingerprinting and state transitions.
        
        Returns:
            processed_findings: list of findings with fingerprints and updated states.
            delta_stats: counts of new, regressed, fixed, unchanged, and suppressed findings.
            fixed_items: findings resolved by this run.
        """
        now = datetime.now(timezone.utc).isoformat()
        current_fps = set()
        delta_stats = {"new": 0, "regressed": 0, "fixed": 0, "unchanged": 0, "suppressed": 0}
        processed = []

        # 1. Process observed findings
        for item in raw_findings:
            rule_id, path = bind_candidates(item, candidate_index)
            fp = compute_fingerprint(
                agent=agent,
                rule_id=rule_id,
                path=path,
                snippet=item.get("snippet", "")
            )
            if fp in current_fps:
                continue
            current_fps.add(fp)
            
            existing = self.data["findings"].get(fp)
            
            # Check for committed suppression
            if fp in self.suppressions:
                state = "wontfix"
                suppression_reason = self.suppressions[fp].get("reason", "Suppressed")
                change = "suppressed"
            elif existing is None:
                state = "new"
                change = "new"
                suppression_reason = None
            elif existing.get("state") == "fixed":
                state = "regressed"
                change = "regressed"
                suppression_reason = None
            else:
                state = existing.get("state", "new")
                change = "unchanged"
                suppression_reason = existing.get("suppression_reason")

            delta_stats[change] += 1
            finding_record = {
                "fingerprint": fp,
                "agent": agent,
                "rule_id": rule_id,
                "path": path,
                "line_number": item.get("line_number"),
                "snippet": item.get("snippet"),
                # Fail closed, and record the severity the publication boundary will enforce: a
                # missing or unrecognised label is critical, and a credential-class agent's
                # finding is critical on identity whatever the model called it (agents-94f). The
                # old default was medium, the exact band the public sinks publish.
                "severity": effective_severity({"agent": agent, "severity": item.get("severity")}),
                "title": item.get("title", ""),
                "description": item.get("description", ""),
                "remediation": item.get("remediation", ""),
                "state": state,
                # Lifecycle and this run's delta are separate: 'new' can remain active.
                "change": change,
                # Retry failed deliveries, but only notify once per sink and recurrence.
                "dispatched_sinks": list(existing.get("dispatched_sinks", []))
                    if existing and change != "regressed" else [],
                "first_seen": existing.get("first_seen", now) if existing else now,
                "last_seen": now,
                "suppression_reason": suppression_reason
            }
            self.data["findings"][fp] = finding_record
            processed.append(finding_record)

        # 2. Check for findings previously detected by this agent that are now missing (fixed)
        fixed_items = []
        for fp, existing in self.data["findings"].items():
            if existing.get("agent") == agent and fp not in current_fps:
                if existing.get("state") in ("new", "accepted", "regressed"):
                    existing["state"] = "fixed"
                    existing["fixed_at"] = now
                    delta_stats["fixed"] += 1
                    fixed_items.append(existing)

        self.save()

        # 3. Append to target history ledger
        history_file = self.findings_dir / f"{self.target_name}-history.jsonl"
        with open(history_file, "a", encoding="utf-8") as hf:
            hf.write(json.dumps({
                "timestamp": now,
                "agent": agent,
                "delta": delta_stats
            }) + "\n")

        return processed, delta_stats, fixed_items

def _publishable_for_sink(sink: str, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Filter a run's findings down to what `sink` may receive.

    The one choke point every sink goes through. Eligibility (state, delivery receipt) and the
    publication embargo are both decided here, so a new dispatch branch cannot silently publish
    an embargoed finding. `embargo_reason` fails closed for every sink except the local `file`
    evidence trail (agents-681 / SF-01, agents-94f / SF-03).
    """
    publishable = []
    for f in findings:
        if f.get("state") not in ("new", "regressed") or sink in f.get("dispatched_sinks", []):
            continue
        reason = embargo_reason(f, sink)
        if reason:
            # The guard line is published too, so it derives every rendered value from the
            # redacted copy; the severity is a deterministic enum member.
            guarded = redact_finding(f)
            print(f"[SECURITY GUARD] Suppressing {sink} publication of {effective_severity(f)} finding: {guarded['title']}")
            continue
        publishable.append(f)
    return publishable


def dispatch_to_sink(sink: str, target_name: str, target_dir: Path, processed_findings: List[Dict[str, Any]], stats: Dict[str, int], fixed_items: List[Dict[str, Any]] = None):
    """Dispatch findings, mutating their successful-delivery receipts.

    The caller must save its FindingsStore after dispatch to persist those receipts.
    """
    print(f"\n[Findings Store] Target: {target_name} | Delta: {stats['new']} new, {stats['regressed']} regressed, {stats['fixed']} fixed, {stats['unchanged']} unchanged, {stats['suppressed']} suppressed")

    # Always write the local factory delta report. It is the complete evidence trail, so it
    # deliberately includes findings the publication embargo withholds from a tracker sink.
    _dispatch_file(target_name, processed_findings, stats, fixed_items or [])

    publishable = _publishable_for_sink(sink, processed_findings)
    if sink == "beads":
        _dispatch_beads(target_dir, publishable)
    elif sink == "github-issues":
        _dispatch_github(target_name, target_dir, publishable)

def _dispatch_file(target_name: str, findings: List[Dict[str, Any]], stats: Dict[str, int], fixed_items: List[Dict[str, Any]]):
    report_file = FACTORY_ROOT / "findings" / f"{target_name}-delta.md"
    report_file.parent.mkdir(parents=True, exist_ok=True)
    # This report is the file the composite action appends to a public step summary, so the
    # rendered copy is redacted. The raw values stay in the run artifacts and the store.
    findings = [redact_finding(f) for f in findings]
    fixed_items = [redact_finding(f) for f in fixed_items]
    new_or_regressed = [f for f in findings if f["change"] in ("new", "regressed")]
    unchanged = [f for f in findings if f["change"] == "unchanged"]
    suppressed = [f for f in findings if f["state"] == "wontfix"]

    lines = [
        f"# Software Factory Delta Report: {target_name}",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"",
        f"| New | Regressed | Fixed | Unchanged | Suppressed |",
        f"|:---:|:---:|:---:|:---:|:---:|",
        f"| **{stats['new']}** | **{stats['regressed']}** | **{stats['fixed']}** | {stats['unchanged']} | {stats['suppressed']} |",
        f""
    ]

    if stats["new"] == 0 and stats["regressed"] == 0 and stats["fixed"] == 0:
        lines.append("> **Clean Delta**: No new, regressed, or resolved findings in this run.")
        lines.append("")

    if new_or_regressed:
        lines.append("## Action Required: New & Regressed Findings")
        lines.append("")
        for f in new_or_regressed:
            badge = f"[{f['severity'].upper()}]"
            lines.append(f"### {badge} {f['title']} (`{f['state']}`)")
            lines.append(f"- **Rule**: `{f['rule_id']}`")
            lines.append(f"- **Location**: `{f['path']}:{f.get('line_number', '?')}`")
            lines.append(f"- **Fingerprint**: `{f['fingerprint'][:16]}...`")
            lines.append(f"- **Description**: {f['description']}")
            lines.append(f"- **Snippet**: `{f['snippet']}`")
            if f.get("remediation"):
                lines.append(f"- **Remediation**: {f['remediation']}")
            lines.append("")

    if fixed_items:
        lines.append("## Resolved in this Run (Fixed)")
        lines.append("")
        for f in fixed_items:
            lines.append(f"- **`{f.get('rule_id')}`**: {f.get('title')} (`{f.get('path')}:{f.get('line_number', '?')}`)")
        lines.append("")

    if unchanged:
        lines.append("## Active Findings (Unchanged)")
        lines.append("")
        for f in unchanged:
            badge = f"[{f['severity'].upper()}]"
            lines.append(f"- {badge} **{f['title']}** (`{f['path']}:{f.get('line_number', '?')}`)")
        lines.append("")

    if suppressed:
        lines.append("## Suppressed Findings (Wontfix)")
        lines.append("")
        for f in suppressed:
            lines.append(f"- **{f['title']}**: {f.get('suppression_reason') or 'Suppressed'}")
        lines.append("")

    report = "\n".join(lines)
    report_file.write_text(report, encoding="utf-8")
    # Preserve the original path for existing consumers.
    report_file.with_name(f"{target_name}-latest.md").write_text(report, encoding="utf-8")
    print(f"Delta report written to: {report_file}")

def _dispatch_beads(target_dir: Path, findings: List[Dict[str, Any]]):
    """Creates beads for active findings if bd is available."""
    if not (target_dir / ".beads").exists():
        print(f"Warning: .beads directory not found in {target_dir}. Falling back to file sink.")
        return

    bd_bin = shutil.which("bd") or str(Path.home() / ".local" / "bin" / "bd")
    if not os.path.exists(bd_bin):
        print("Warning: bd binary not available. Findings stored in JSON only.")
        return

    for f in findings:
        if "beads" in f.get("dispatched_sinks", []):
            continue
        # dispatch_to_sink already applied and logged the embargo; this keeps a direct call to
        # the sink safe. Beads publishes medium only, as it did before: critical and high are
        # exactly what the embargo withholds from a synced tracker (agents-681).
        if embargo_reason(f, "beads"):
            continue
        if f["state"] in ("new", "regressed") and effective_severity(f) == "medium":
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
                "-C", str(target_dir)
            ]
            try:
                res = subprocess.run(cmd, cwd=str(target_dir), capture_output=True, text=True, check=False, timeout=30)
                if res.returncode == 0:
                    f.setdefault("dispatched_sinks", []).append("beads")
                    print(f"Created bead for: {published['title']}")
                else:
                    print(f"Failed to create bead (exit {res.returncode}): {res.stderr.strip()}")
            except Exception as e:
                print(f"Failed to create bead: {e}")

def _dispatch_github(target_name: str, target_dir: Path, findings: List[Dict[str, Any]]):
    """Public disclosure guard and issue creation for GitHub Issues."""
    gh_bin = shutil.which("gh")
    for f in findings:
        if f["state"] not in ("new", "regressed") or "github-issues" in f.get("dispatched_sinks", []):
            continue
        # dispatch_to_sink already logged and filtered this; the check keeps a direct call to
        # this sink safe. Fail-closed severity and credential-agent identity live in one place.
        if embargo_reason(f, "github-issues"):
            # The guard's own log line is published too: derive every value it renders.
            guarded = redact_finding(f)
            print(f"[SECURITY GUARD] Suppressing public GitHub issue for {effective_severity(f)} finding: {guarded['title']}")
            print(f"-> Please review in private store or file private security advisory.")
            continue
        if gh_bin and effective_severity(f) in ("medium", "low"):
            published = redact_finding(f)
            title = f"[factory:{published['agent']}] {published['title']}"
            body = (
                f"**Rule**: `{published['rule_id']}`\n"
                f"**Severity**: `{published['severity']}`\n"
                f"**Location**: `{published['path']}:{published.get('line_number', '?')}`\n"
                f"**Fingerprint**: `{f['fingerprint']}`\n\n"
                f"### Description\n{published['description']}\n\n"
                f"### Remediation\n{published.get('remediation', 'N/A')}\n"
            )
            cmd = [gh_bin, "issue", "create", "--title", title, "--body", body]
            try:
                res = subprocess.run(cmd, cwd=str(target_dir), capture_output=True, text=True, check=False, timeout=30)
                if res.returncode == 0:
                    f.setdefault("dispatched_sinks", []).append("github-issues")
                    print(f"Created GitHub issue: {res.stdout.strip()}")
                else:
                    print(f"Failed to create GitHub issue (exit {res.returncode}): {res.stderr.strip()}")
            except Exception as e:
                print(f"Failed to create GitHub issue: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process findings into findings store")
    parser.add_argument("--target", required=True, help="Target name")
    parser.add_argument("--agent", required=True, help="Agent name")
    parser.add_argument("--input", required=True, help="JSON file with raw findings")
    parser.add_argument("--candidates", help="Scanner candidates JSON to bind rule_id/path against")
    parser.add_argument("--sink", default="file", help="Sink type (file, beads, github-issues)")
    parser.add_argument("--target-dir", default=".", help="Target repository directory")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        sys.stderr.write(f"Input file not found: {input_path}\n")
        sys.exit(1)

    raw_data = json.loads(input_path.read_text(encoding="utf-8"))
    findings_list = raw_data.get("findings", []) if isinstance(raw_data, dict) else raw_data

    try:
        store = FindingsStore(target_name=args.target)
    except SuppressionFileError as e:
        # Loud and non-zero: a register that cannot be parsed must not silently suppress nothing.
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(2)
    candidate_index = load_candidate_index(Path(args.candidates)) if args.candidates else None
    processed, stats, fixed_items = store.process_run(
        agent=args.agent, raw_findings=findings_list, candidate_index=candidate_index,
    )
    try:
        dispatch_to_sink(
            sink=args.sink,
            target_name=args.target,
            target_dir=Path(args.target_dir).resolve(),
            processed_findings=processed,
            stats=stats,
            fixed_items=fixed_items
        )
    finally:
        store.save()
