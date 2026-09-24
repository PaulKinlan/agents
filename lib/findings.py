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

try:  # imported as lib.findings (root on sys.path), or run as a script (lib/ on it)
    from lib.redaction import mask_text, redact_finding
except ImportError:
    sys.path.insert(0, str(FACTORY_ROOT))
    from lib.redaction import mask_text, redact_finding

def normalize_text(text: str) -> str:
    """Strip and collapse internal whitespace to make fingerprint resilient to reformatting."""
    if not text:
        return ""
    return re.sub(r"\s+", " ", text.strip())

def compute_fingerprint(agent: str, rule_id: str, path: str, snippet: str) -> str:
    """Compute stable fingerprint: sha256(agent:rule_id:normalized_path:normalized_snippet).
    
    Deliberately excludes line numbers to survive refactor churn.
    """
    norm_path = path.replace("\\", "/").strip().lstrip("./")
    norm_snippet = normalize_text(snippet)
    key = f"{agent}:{rule_id}:{norm_path}:{norm_snippet}".encode("utf-8")
    return hashlib.sha256(key).hexdigest()

class FindingsStore:
    def __init__(self, target_name: str, findings_dir: Optional[Path] = None):
        self.target_name = target_name
        self.findings_dir = findings_dir or (FACTORY_ROOT / "findings")
        self.findings_dir.mkdir(parents=True, exist_ok=True)
        self.store_file = self.findings_dir / f"{target_name}.json"
        self.suppressions_file = self.findings_dir / f"{target_name}.suppressions.json"
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
        if self.suppressions_file.exists():
            try:
                return json.loads(self.suppressions_file.read_text(encoding="utf-8"))
            except Exception as e:
                sys.stderr.write(f"Warning: could not read {self.suppressions_file}: {e}\n")
        return {}

    def save(self):
        self.store_file.write_text(json.dumps(self.data, indent=2), encoding="utf-8")

    def process_run(self, agent: str, raw_findings: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, int], List[Dict[str, Any]]]:
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
            fp = compute_fingerprint(
                agent=agent,
                rule_id=item.get("rule_id", "generic"),
                path=item.get("path", ""),
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
                "rule_id": item.get("rule_id"),
                "path": item.get("path"),
                "line_number": item.get("line_number"),
                "snippet": item.get("snippet"),
                "severity": item.get("severity", "medium"),
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

def dispatch_to_sink(sink: str, target_name: str, target_dir: Path, processed_findings: List[Dict[str, Any]], stats: Dict[str, int], fixed_items: List[Dict[str, Any]] = None):
    """Dispatch findings, mutating their successful-delivery receipts.

    The caller must save its FindingsStore after dispatch to persist those receipts.
    """
    print(f"\n[Findings Store] Target: {target_name} | Delta: {stats['new']} new, {stats['regressed']} regressed, {stats['fixed']} fixed, {stats['unchanged']} unchanged, {stats['suppressed']} suppressed")
    
    # Always write the local factory delta report
    _dispatch_file(target_name, processed_findings, stats, fixed_items or [])

    if sink == "beads":
        _dispatch_beads(target_dir, processed_findings)
    elif sink == "github-issues":
        _dispatch_github(target_name, target_dir, processed_findings)

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
        if f["state"] in ("new", "regressed") and f["severity"] in ("critical", "high", "medium"):
            title = f"[{f['agent']}] {f['title']}"
            published = redact_finding(f)
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
                    print(f"Created bead for: {mask_text(f['title'])}")
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
        if f["severity"] in ("critical", "high"):
            print(f"[SECURITY GUARD] Suppressing public GitHub issue for {f['severity']} finding: {mask_text(f['title'])}")
            print(f"-> Please review in private store or file private security advisory.")
            continue
        if gh_bin and f["severity"] in ("medium", "low"):
            published = redact_finding(f)
            title = f"[factory:{f['agent']}] {published['title']}"
            body = (
                f"**Rule**: `{f['rule_id']}`\n"
                f"**Severity**: `{f['severity']}`\n"
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
    parser.add_argument("--sink", default="file", help="Sink type (file, beads, github-issues)")
    parser.add_argument("--target-dir", default=".", help="Target repository directory")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        sys.stderr.write(f"Input file not found: {input_path}\n")
        sys.exit(1)

    raw_data = json.loads(input_path.read_text(encoding="utf-8"))
    findings_list = raw_data.get("findings", []) if isinstance(raw_data, dict) else raw_data

    store = FindingsStore(target_name=args.target)
    processed, stats, fixed_items = store.process_run(agent=args.agent, raw_findings=findings_list)
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
