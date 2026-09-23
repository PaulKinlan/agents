#!/usr/bin/env python3
"""Deterministic verification helper for vuln-verify agent.

Receives candidate vulnerability findings (from findings store, recent discovery runs,
or direct input) and loads the specific referenced source files with contextual code
windows, upstream handler definitions, and threat model invariants to prepare a clean,
isolated context for adversarial verification.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

FACTORY_ROOT = Path(__file__).resolve().parent.parent.parent.parent


def find_latest_findings(target_name: str, target_dir: Path) -> List[Dict[str, Any]]:
    """Locate candidate findings from the findings store or most recent discovery runs."""
    # 1. Check findings store for this target
    store_path = FACTORY_ROOT / "findings" / f"{target_name}.json"
    if store_path.exists():
        try:
            store_data = json.loads(store_path.read_text(encoding="utf-8"))
            raw_findings = store_data.get("findings", {})
            if isinstance(raw_findings, dict) and raw_findings:
                # Return unsuppressed, non-fixed findings
                candidates = []
                for fp, f in raw_findings.items():
                    if f.get("state") in ("new", "regressed", "accepted", None):
                        candidates.append(f)
                if candidates:
                    return candidates
        except Exception as e:
            sys.stderr.write(f"Warning: Could not read findings store {store_path}: {e}\n")

    # 2. Check recent run directories for vuln-discovery or threat-model
    runs_dir = FACTORY_ROOT / "runs"
    if runs_dir.exists():
        pattern = re.compile(rf"^(?:vuln-discovery|threat-model)-{re.escape(target_name)}-\d{{8}}-\d{{6}}$")
        matching_runs = sorted(
            [d for d in runs_dir.iterdir() if d.is_dir() and pattern.match(d.name)],
            key=lambda x: x.name,
            reverse=True
        )
        for run_dir in matching_runs:
            report_file = run_dir / "report.json"
            if report_file.exists():
                try:
                    data = json.loads(report_file.read_text(encoding="utf-8"))
                    findings = data.get("findings", [])
                    if findings:
                        return findings
                except Exception:
                    continue

    return []


def load_file_context(target_dir: Path, rel_path: str, line_number: Optional[int]) -> Dict[str, Any]:
    """Read source file and extract rich window around candidate line."""
    filepath = target_dir / rel_path
    if not filepath.exists():
        return {"error": f"File not found: {rel_path}", "lines": []}

    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return {"error": f"Error reading file {rel_path}: {e}", "lines": []}

    all_lines = content.splitlines()
    total_lines = len(all_lines)

    if line_number is None or line_number <= 0:
        line_number = 1

    # Extract window of ~30 lines before and after
    start_idx = max(0, line_number - 30)
    end_idx = min(total_lines, line_number + 30)

    context_lines = []
    for idx in range(start_idx, end_idx):
        context_lines.append(f"{idx + 1:4d} | {all_lines[idx]}")

    # Check for defense primitives in file
    has_try_catch = bool(re.search(r"\btry\s*\{", content))
    has_auth_gate = bool(re.search(r"(?:authenticate|requireAuth|checkToken|verifySession|authHeader|bearerToken)", content, re.IGNORECASE))
    has_sanitizer = bool(re.search(r"(?:sanitize|escape|DOMPurify|validator|encodeURI|encodeURIComponent)", content, re.IGNORECASE))

    return {
        "total_lines": total_lines,
        "window_start": start_idx + 1,
        "window_end": end_idx,
        "context_snippet": "\n".join(context_lines),
        "file_has_try_catch": has_try_catch,
        "file_has_auth_gate": has_auth_gate,
        "file_has_sanitizer": has_sanitizer,
    }


def load_threat_model_summary(target_dir: Path) -> Dict[str, Any]:
    """Load threat model invariants and trusted boundaries if available."""
    candidates = [
        target_dir / "THREAT_MODEL.md",
        FACTORY_ROOT / "findings" / f"{target_dir.name}-THREAT_MODEL.md",
    ]
    for c in candidates:
        if c.exists():
            try:
                text = c.read_text(encoding="utf-8", errors="replace")
                # Extract explicit trust lines
                trusted = []
                invariants = []
                for line in text.splitlines():
                    if line.strip().startswith("- ") or line.strip().startswith("* "):
                        clean = line.strip()[2:].strip()
                        if "trust" in clean.lower():
                            trusted.append(clean)
                        if "invariant" in clean.lower() or "must" in clean.lower():
                            invariants.append(clean)
                return {
                    "threat_model_path": str(c.name),
                    "explicitly_trusted": trusted[:10],
                    "security_invariants": invariants[:10]
                }
            except Exception:
                pass
    return {}


def main():
    parser = argparse.ArgumentParser(description="Prepare findings and source context for adversarial verification")
    parser.add_argument("--target", "--target-dir", dest="target_dir", required=True, help="Target repository directory")
    parser.add_argument("--findings", help="Path to findings JSON input")
    parser.add_argument("--output", help="Output candidates verification JSON path")
    args = parser.parse_args()

    target_dir = Path(args.target_dir).resolve()
    if not target_dir.exists():
        sys.stderr.write(f"Target directory not found: {target_dir}\n")
        sys.exit(1)

    target_name = target_dir.name

    # 1. Load candidate findings
    findings = []
    if args.findings:
        input_path = Path(args.findings)
        if input_path.exists():
            try:
                data = json.loads(input_path.read_text(encoding="utf-8"))
                findings = data.get("findings", data if isinstance(data, list) else [])
            except Exception as e:
                sys.stderr.write(f"Error reading findings from {input_path}: {e}\n")

    if not findings:
        findings = find_latest_findings(target_name, target_dir)

    sys.stderr.write(f"Preparing verification bundle for {len(findings)} candidate findings in {target_name}...\n")

    # 2. Enrich each finding with source code context
    verification_candidates: List[Dict[str, Any]] = []
    for f in findings:
        path = f.get("path")
        line_no = f.get("line_number")
        if not path:
            continue

        file_ctx = load_file_context(target_dir, path, line_no)
        verification_candidates.append({
            "rule_id": f.get("rule_id", "generic-vuln"),
            "path": path,
            "line_number": line_no,
            "original_snippet": f.get("snippet", ""),
            "original_severity": f.get("severity", "medium"),
            "original_title": f.get("title", ""),
            "original_description": f.get("description", ""),
            "original_remediation": f.get("remediation", ""),
            "original_exploit_chain": f.get("exploit_chain"),
            "source_context": file_ctx
        })

    tm_summary = load_threat_model_summary(target_dir)

    result = {
        "target": target_name,
        "candidate_count": len(verification_candidates),
        "threat_model_summary": tm_summary,
        "candidates": verification_candidates
    }

    output_json = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(output_json, encoding="utf-8")
        print(f"Prepared {len(verification_candidates)} candidate findings with source context to {args.output}")
    else:
        print(output_json)


if __name__ == "__main__":
    main()
