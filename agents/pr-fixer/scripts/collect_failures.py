#!/usr/bin/env python3
"""Deterministic Pre-Pass for PR Fixer (agents/pr-fixer/scripts/collect_failures.py)

Collects active/new findings from `findings/<target>-findings.json` along with
any syntax/test failure signals and extracts the exact surrounding lines of code
from the target repository so the Proposer model can generate minimal, clean
unified diffs (`proposed_patches`).
"""

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List

FACTORY_ROOT = Path(__file__).resolve().parent.parent.parent.parent
FINDINGS_DIR = FACTORY_ROOT / "findings"


def load_active_findings(target_name: str, target_dir: Path) -> List[Dict[str, Any]]:
    store_file = FINDINGS_DIR / f"{target_name}-findings.json"
    if not store_file.exists():
        return []

    try:
        data = json.loads(store_file.read_text(encoding="utf-8"))
    except Exception:
        return []

    records = list(data.values()) if isinstance(data, dict) else data
    fixable: List[Dict[str, Any]] = []

    for rec in records:
        if not isinstance(rec, dict):
            continue
        if rec.get("status") in {"wontfix", "fixed"}:
            continue
        rel_path = rec.get("path", "")
        fpath = target_dir / rel_path
        if not rel_path or not fpath.exists() or not fpath.is_file():
            continue

        line_no = int(rec.get("line_number") or 1)
        try:
            lines = fpath.read_text(encoding="utf-8", errors="ignore").splitlines()
            start = max(0, line_no - 8)
            end = min(len(lines), line_no + 8)
            numbered_window = "\n".join(
                f"{i + 1}: {lines[i]}" for i in range(start, end)
            )
        except Exception:
            numbered_window = rec.get("snippet", "")

        fixable.append({
            "fingerprint": rec.get("fingerprint", "")[:12],
            "agent": rec.get("agent"),
            "rule_id": rec.get("rule_id"),
            "severity": rec.get("severity", "medium"),
            "path": rel_path,
            "line_number": line_no,
            "title": rec.get("title"),
            "description": rec.get("description"),
            "remediation": rec.get("remediation"),
            "source_context": numbered_window
        })

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    fixable.sort(key=lambda x: severity_rank.get(x["severity"], 3))
    return fixable[:12]


def main():
    parser = argparse.ArgumentParser(description="Collect verified findings and test failures for pr-fixer")
    parser.add_argument("--target", required=True, help="Target repository directory")
    parser.add_argument("--output", help="Output JSON path")
    args = parser.parse_args()

    target_dir = Path(args.target).resolve()
    target_name = target_dir.name

    fixable_findings = load_active_findings(target_name, target_dir)

    git_branch = "main"
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=str(target_dir), capture_output=True, text=True, timeout=3
        )
        if res.returncode == 0:
            git_branch = res.stdout.strip()
    except Exception:
        pass

    payload: Dict[str, Any] = {
        "target": target_name,
        "base_branch": git_branch,
        "fixable_candidates_count": len(fixable_findings),
        "candidates": fixable_findings
    }

    out = json.dumps(payload, indent=2)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
    else:
        print(out)


if __name__ == "__main__":
    main()
