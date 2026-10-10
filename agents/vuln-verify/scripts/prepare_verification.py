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
from typing import Any, Dict, List, Optional, Tuple

FACTORY_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(FACTORY_ROOT))

from lib.line_numbers import usable_line_number  # noqa: E402
from lib.path_security import resolve_within_target  # noqa: E402

# The only fields that cross from discovery to verification (SF-08). Everything the discovery
# model wrote about a candidate — title, description, severity, remediation, exploit chain —
# stays on the discovery side; the verifier re-derives its own judgement from the code.
LOCATION_FIELDS = ("fingerprint", "rule_id", "path", "line_number", "snippet",
                   # The station's own emitted candidate id (agents-rdyb). Carried through so this
                   # pre-pass hands a COPY of identity downstream. A hard allowlist drops unknown
                   # fields SILENTLY, which would bring the reconstruction back for exactly the rows
                   # that had escaped it - the failure mode agents-q0mt exists to remove.
                   "candidate_id")

# The store is shared by every agent, so select the records discovery actually produced.
DISCOVERY_AGENTS = ("vuln-discovery", "threat-model")


def location_candidate(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """One candidate reduced to its scanner location data, or None when it has no path."""
    if not isinstance(item, dict) or not item.get("path"):
        return None
    return {field: item.get(field) for field in LOCATION_FIELDS if item.get(field) is not None}


def unlocatable_candidate(item: Dict[str, Any]) -> Dict[str, Any]:
    """One candidate with NO usable path, KEPT and MARKED rather than dropped (agents-nhpb).

    A candidate the scanner produced is still a finding. Dropping it made the station report
    "nothing to verify" for something it declined to look at, which a reader cannot tell apart
    from "looked at and clean" - the same class as the silently sliced document and the dropped
    line number we removed today. The markers are machine-readable so no downstream reader has to
    infer the reason from prose: `location_present` is False, and `line_number_unknown` is True
    because a candidate with no path has no line either. The verifier can only return
    `unverifiable` for these, since agents-0tl rejects `verified`/`disproved` without a resolvable
    location - which is exactly the verdict this station should be making here.
    """
    marked = {
        "rule_id": item.get("rule_id", "generic-vuln"),
        "path": None,
        "line_number": None,
        "snippet": item.get("snippet", ""),
        "source_context": "",
        "location_present": False,
        "line_number_unknown": True,
    }
    # Same two passthroughs as a located candidate, so nothing that survived the reduction is lost
    # here and an unlocatable candidate stays recognisable as the same finding.
    if item.get("fingerprint"):
        marked["fingerprint"] = item["fingerprint"]
    if item.get("candidate_id"):
        marked["candidate_id"] = item["candidate_id"]
    return marked


def find_latest_findings(
    target_name: str, target_dir: Path
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Locate candidate LOCATIONS from the findings store or the most recent discovery runs.

    Both sources are reduced to `location_candidate`, and the store is filtered to the
    discovery agents, so no other model's conclusions reach the verifier (SF-08).

    Returns (located, unlocatable). The second list is NOT a discard pile: a discovery
    candidate with no path is carried out of the reduction marked, so the bundle can keep it and
    the report can state how many could not be located (agents-nhpb).
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
                unlocatable = []
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
                    else:
                        unlocatable.append(unlocatable_candidate(f))
                # `or unlocatable`: a store whose candidates ALL lack a path must not fall through to
                # an older run and lose the count, which would report "nothing to verify" for
                # findings that are sitting right here (agents-nhpb).
                if candidates or unlocatable:
                    return candidates, unlocatable
        except Exception as e:
            sys.stderr.write(f"Warning: Could not read findings store {store_path}: {e}\n")

    # 2. Check recent run directories for vuln-discovery or threat-model. Prefer the
    #    deterministic scanner output; the model report is the fallback, reduced the same way.
    runs_dir = FACTORY_ROOT / "runs"
    if runs_dir.exists():
        # The dispatcher adds -attempt2 on repair-retry and an eight-hex suffix on
        # same-second collisions (including collisions of retry directories). A
        # successful retry must remain visible even when its first attempt had no verdict.
        pattern = re.compile(
            rf"^(?:vuln-discovery|threat-model)-{re.escape(target_name)}-"
            rf"\d{{8}}-\d{{6}}(?:-attempt[1-9][0-9]*)?(?:-[0-9a-f]{{8}})?$"
        )
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
                candidates = []
                unlocatable = []
                for item in raw:
                    candidate = location_candidate(item)
                    if candidate:
                        candidates.append(candidate)
                    elif isinstance(item, dict):
                        unlocatable.append(unlocatable_candidate(item))
                if candidates or unlocatable:
                    return candidates, unlocatable

    return [], []


# How much of a file to hand over when the line is unknown. The verifier's contract keys on a
# resolvable PATH (SKILL.md "Verdict Determination": cite the nearest path that exists), so a
# file-level view keeps such a candidate verifiable rather than dropping it or inventing a line.
FILE_VIEW_LINES = 200


# `usable_line_number` is the shared line-sentinel rule (lib/line_numbers.py, agents-ghtz): it
# returns the 1-based line or None, never coercing an unknown location to line 0 or line 1
# (agents-fy26).
def load_file_context(target_dir: Path, rel_path: str, line_number: Optional[int]) -> Dict[str, Any]:
    """Read source file and extract rich window around candidate line."""
    filepath = resolve_within_target(target_dir, rel_path)
    if filepath is None:
        return {"error": f"Refusing to read path outside target directory: {rel_path}", "lines": []}
    if not filepath.exists():
        return {"error": f"File not found: {rel_path}", "lines": []}

    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return {"error": f"Error reading file {rel_path}: {e}", "lines": []}

    all_lines = content.splitlines()
    total_lines = len(all_lines)

    usable_line = usable_line_number(line_number)
    if usable_line is None:
        # UNKNOWN line: give a bounded file-level view and say so, rather than centring the
        # window on line 1 as if the scanner had named it.
        start_idx = 0
        end_idx = min(total_lines, FILE_VIEW_LINES)
    else:
        # Extract window of ~30 lines before and after
        start_idx = max(0, usable_line - 30)
        end_idx = min(total_lines, usable_line + 30)

    context_lines = []
    for idx in range(start_idx, end_idx):
        context_lines.append(f"{idx + 1:4d} | {all_lines[idx]}")

    # Check for defense primitives in file
    has_try_catch = bool(re.search(r"\btry\s*\{", content))
    has_auth_gate = bool(re.search(r"(?:authenticate|requireAuth|checkToken|verifySession|authHeader|bearerToken)", content, re.IGNORECASE))
    has_sanitizer = bool(re.search(r"(?:sanitize|escape|DOMPurify|validator|encodeURI|encodeURIComponent)", content, re.IGNORECASE))

    context: Dict[str, Any] = {
        "total_lines": total_lines,
        "window_start": start_idx + 1,
        "window_end": end_idx,
        "line_number_known": usable_line is not None,
        "context_snippet": "\n".join(context_lines),
        "file_has_try_catch": has_try_catch,
        "file_has_auth_gate": has_auth_gate,
        "file_has_sanitizer": has_sanitizer,
    }
    if usable_line is None:
        # Says what the window IS, so the file-level view is not read as a located finding.
        context["location_note"] = (
            "candidate carries no usable line number; this is file-level context and the "
            "exact line is unknown"
        )
        if total_lines > FILE_VIEW_LINES:
            context["truncated"] = True
    return context


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
    unlocatable: List[Dict[str, Any]] = []
    if args.findings:
        input_path = Path(args.findings)
        if input_path.exists():
            try:
                data = json.loads(input_path.read_text(encoding="utf-8"))
                raw = data.get("findings", data if isinstance(data, list) else [])
                findings = [c for c in (location_candidate(i) for i in raw) if c]
                # Kept, not dropped (agents-nhpb): an input file whose every candidate lacks a path
                # still has candidates in it.
                unlocatable = [unlocatable_candidate(i) for i in raw
                               if isinstance(i, dict) and not i.get("path")]
            except Exception as e:
                sys.stderr.write(f"Error reading findings from {input_path}: {e}\n")

    # `and not unlocatable`: an input file whose candidates ALL lack a path must not send us on to
    # the store, which would replace those candidates with a different source's and lose the count.
    if not findings and not unlocatable:
        findings, unlocatable = find_latest_findings(target_name, target_dir)

    # Carried INTO the bundle rather than discarded (agents-nhpb). The loop below classifies by
    # path, so these take the marked branch instead of being dropped.
    findings = findings + unlocatable
    if unlocatable:
        sys.stderr.write(
            f"{len(unlocatable)} candidate finding(s) carry no path and are kept as UNVERIFIABLE "
            f"(location_present=false); not dropped (agents-nhpb).\n"
        )
    sys.stderr.write(f"Preparing verification bundle for {len(findings)} candidate findings in {target_name}...\n")

    # 2. Enrich each finding with source code context
    verification_candidates: List[Dict[str, Any]] = []
    for f in findings:
        path = f.get("path")
        line_no = f.get("line_number")
        if not path:
            # KEPT and marked, not dropped (agents-nhpb): a scanner candidate is still a finding, and
            # omitting it would let the station report "nothing to verify" for something it declined
            # to look at. The verifier can only return `unverifiable` for these, because agents-0tl
            # rejects verified/disproved without a resolvable location - which is correct here.
            verification_candidates.append(unlocatable_candidate(f))
            continue

        file_ctx = load_file_context(target_dir, path, line_no)
        usable_line = usable_line_number(line_no)
        candidate = {
            "rule_id": f.get("rule_id", "generic-vuln"),
            "path": path,
            "line_number": usable_line,
            "snippet": f.get("snippet", ""),
            "source_context": file_ctx,
        }
        if usable_line is None:
            # The candidate STAYS, marked. Dropping it would turn a crash into a false clean,
            # which is the outcome this bead exists to prevent (agents-fy26); the path is the
            # location the verifier can still act on, and it asks for the line if it needs one.
            candidate["line_number_unknown"] = True
        if f.get("fingerprint"):
            candidate["fingerprint"] = f["fingerprint"]
        if f.get("candidate_id"):
            # Second drop point: the allowlist above is not enough, because this rebuild constructs a
            # fresh dict, so anything not named here is lost even when it survived the reduction.
            candidate["candidate_id"] = f["candidate_id"]
        verification_candidates.append(candidate)

    tm_summary = load_threat_model_summary(target_dir)

    result = {
        "target": target_name,
        "candidate_count": len(verification_candidates),
        # The subset the station could not look at, stated so "not looked at" cannot be read as
        # "looked at and clean" (agents-nhpb). Machine-readable, so no prose inference is needed.
        "unlocatable_count": sum(1 for c in verification_candidates
                                 if c.get("location_present") is False),
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
