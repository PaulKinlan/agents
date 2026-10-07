#!/usr/bin/env python3
"""Deterministic verification helper for vuln-verify agent.

Receives candidate vulnerability LOCATIONS (from the findings store, recent discovery runs, or
direct input) and loads the specific referenced source files with contextual code windows,
upstream handler definitions, and threat model invariants to prepare a clean, isolated context
for adversarial verification.

Non-negotiable #3: discovery and verification are separate agents with zero shared session
state, so this pre-pass never forwards the discovery model's conclusions — no title,
description, severity, remediation or exploit chain. Only the scanner's location data and raw
snippet cross the boundary; a prompt is the weakest available control against anchoring (SF-08).
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

FACTORY_ROOT = Path(__file__).resolve().parent.parent.parent.parent

# The only fields that cross from discovery to verification (SF-08). Everything the discovery
# model wrote about a candidate — title, description, severity, remediation, exploit chain —
# stays on the discovery side; the verifier re-derives its own judgement from the code.
LOCATION_FIELDS = ("fingerprint", "rule_id", "path", "line_number", "snippet")

# The store is shared by every agent, so select the records discovery actually produced.
DISCOVERY_AGENTS = ("vuln-discovery", "threat-model")


def location_candidate(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """One candidate reduced to its scanner location data, or None when it has no path."""
    if not isinstance(item, dict) or not item.get("path"):
        return None
    return {field: item.get(field) for field in LOCATION_FIELDS if item.get(field) is not None}


def find_latest_findings(target_name: str, target_dir: Path) -> List[Dict[str, Any]]:
    """Locate candidate LOCATIONS from the findings store or the most recent discovery runs.

    Both sources are reduced to `location_candidate`, and the store is filtered to the
    discovery agents, so no other model's conclusions reach the verifier (SF-08).
    """
    # 1. Check findings store for this target
    store_path = FACTORY_ROOT / "findings" / f"{target_name}.json"
    if store_path.exists():
        try:
            store_data = json.loads(store_path.read_text(encoding="utf-8"))
            raw_findings = store_data.get("findings", {})
            if isinstance(raw_findings, dict) and raw_findings:
                # Return unsuppressed, non-fixed discovery findings, locations only.
                candidates = []
                for f in raw_findings.values():
                    if not isinstance(f, dict):
                        continue
                    if f.get("agent") not in DISCOVERY_AGENTS:
                        continue
                    if f.get("state") not in ("new", "regressed", "accepted", None):
                        continue
                    candidate = location_candidate(f)
                    if candidate:
                        candidates.append(candidate)
                if candidates:
                    return candidates
        except Exception as e:
            sys.stderr.write(f"Warning: Could not read findings store {store_path}: {e}\n")

    # 2. Check recent run directories for vuln-discovery or threat-model. Prefer the
    #    deterministic scanner output; the model report is the fallback, reduced the same way.
    runs_dir = FACTORY_ROOT / "runs"
    if runs_dir.exists():
        pattern = re.compile(rf"^(?:vuln-discovery|threat-model)-{re.escape(target_name)}-\d{{8}}-\d{{6}}$")
        matching_runs = sorted(
            [d for d in runs_dir.iterdir() if d.is_dir() and pattern.match(d.name)],
            key=lambda x: x.name,
            reverse=True
        )
        for run_dir in matching_runs:
            for source_name in ("candidates.json", "report.json"):
                source_file = run_dir / source_name
                if not source_file.exists():
                    continue
                try:
                    data = json.loads(source_file.read_text(encoding="utf-8"))
                except Exception:
                    continue
                if isinstance(data, dict):
                    raw = data.get("candidates" if source_name == "candidates.json" else "findings", [])
                else:
                    raw = data
                if not isinstance(raw, list):
                    continue
                candidates = [c for c in (location_candidate(i) for i in raw) if c]
                if candidates:
                    return candidates

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

    # 1. Load candidate findings, reduced to locations the moment they are read
    findings = []
    if args.findings:
        input_path = Path(args.findings)
        if input_path.exists():
            try:
                data = json.loads(input_path.read_text(encoding="utf-8"))
                raw = data.get("findings", data if isinstance(data, list) else [])
                findings = [c for c in (location_candidate(i) for i in raw) if c]
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
        candidate = {
            "rule_id": f.get("rule_id", "generic-vuln"),
            "path": path,
            "line_number": line_no,
            "snippet": f.get("snippet", ""),
            "source_context": file_ctx,
        }
        if f.get("fingerprint"):
            candidate["fingerprint"] = f["fingerprint"]
        verification_candidates.append(candidate)

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
