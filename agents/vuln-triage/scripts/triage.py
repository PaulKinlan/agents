#!/usr/bin/env python3
"""Deterministic pre-pass for vuln-triage agent.

Clusters candidate and verified findings by file, proximity, and rule class,
and extracts target THREAT_MODEL.md context to prepare for root-cause synthesis.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

FACTORY_ROOT = Path(__file__).resolve().parent.parent.parent.parent

def load_threat_model(target_name: str, target_dir: Path, output_file: Optional[Path] = None) -> Tuple[str, str]:
    # 1. Local target THREAT_MODEL.md
    local_tm = target_dir / "THREAT_MODEL.md"
    if local_tm.exists():
        try:
            return local_tm.read_text(encoding="utf-8", errors="replace"), "THREAT_MODEL.md"
        except OSError:
            pass
    # 2. Docs THREAT_MODEL.md
    docs_tm = target_dir / "docs" / "THREAT_MODEL.md"
    if docs_tm.exists():
        try:
            return docs_tm.read_text(encoding="utf-8", errors="replace"), "docs/THREAT_MODEL.md"
        except OSError:
            pass
    # 3. Findings stored THREAT_MODEL.md
    store_tm = FACTORY_ROOT / "findings" / f"{target_name}-THREAT_MODEL.md"
    if store_tm.exists():
        try:
            text = store_tm.read_text(encoding="utf-8", errors="replace")
            # Inside the sandbox, findings/ is masked. Copy to run directory so the agent can read it!
            if output_file is not None:
                try:
                    (output_file.parent / "THREAT_MODEL.md").write_text(text, encoding="utf-8")
                except OSError:
                    pass
            return text, "THREAT_MODEL.md"
        except OSError:
            pass
    return "No THREAT_MODEL.md found. Treat all external inputs as untrusted.", ""

def gather_findings(target_name: str) -> List[Dict[str, Any]]:
    findings = []
    store_file = FACTORY_ROOT / "findings" / f"{target_name}.json"
    if store_file.exists():
        try:
            data = json.loads(store_file.read_text(encoding="utf-8"))
            for item in data.get("findings", {}).values():
                if item.get("state") in ("new", "regressed", "accepted"):
                    findings.append(item)
        except Exception:
            pass
    return findings

def _parse_line_number(val: Any) -> Optional[int]:
    """Returns integer line number if valid and non-negative, else None."""
    if isinstance(val, bool):
        return None
    if isinstance(val, int):
        return val if val >= 0 else None
    if isinstance(val, str):
        s = val.strip()
        if s.isascii() and s.isdigit():
            try:
                n = int(s)
                return n if n >= 0 else None
            except ValueError:
                return None
    return None


def cluster_deterministic(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Groups findings by file and proximity (lines within 15).

    Design choice for unknown-location findings (agents-ajt4):
    Each finding with an unknown or non-numeric line number (e.g. '?', None, or
    non-numeric string) is placed into its own distinct single-item cluster.
    Because unknown locations cannot have spatial proximity established either
    with numeric lines or with each other, they are never coerced to line 0 (which
    would falsely merge them with lines <= 15) or grouped together by proximity.
    """
    by_file: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        path = f.get("path", "unknown") or "unknown"
        by_file.setdefault(path, []).append(f)

    clusters = []
    cluster_id = 1

    for path in sorted(by_file.keys()):
        items = by_file[path]
        numeric_items: List[Tuple[int, Dict[str, Any]]] = []
        unknown_items: List[Dict[str, Any]] = []

        for item in items:
            line = _parse_line_number(item.get("line_number"))
            if line is not None:
                numeric_items.append((line, item))
            else:
                unknown_items.append(item)

        sorted_numeric = sorted(
            numeric_items,
            key=lambda x: (
                x[0],
                str(x[1].get("rule_id") or ""),
                str(x[1].get("fingerprint") or ""),
                str(x[1].get("title") or ""),
            )
        )

        current_cluster: List[Dict[str, Any]] = []
        last_line: Optional[int] = None

        for line, item in sorted_numeric:
            if current_cluster and last_line is not None and abs(line - last_line) <= 15:
                current_cluster.append(item)
                last_line = line
            else:
                if current_cluster:
                    clusters.append({
                        "cluster_id": f"C{cluster_id}",
                        "file": path,
                        "count": len(current_cluster),
                        "items": current_cluster
                    })
                    cluster_id += 1
                current_cluster = [item]
                last_line = line

        if current_cluster:
            clusters.append({
                "cluster_id": f"C{cluster_id}",
                "file": path,
                "count": len(current_cluster),
                "items": current_cluster
            })
            cluster_id += 1

        # Unknown-location findings are placed in separate single-item clusters
        # sorted deterministically to prevent cluster ID churn across runs.
        sorted_unknown = sorted(
            unknown_items,
            key=lambda x: (
                str(x.get("rule_id") or ""),
                str(x.get("fingerprint") or ""),
                str(x.get("title") or ""),
                str(x.get("line_number") or ""),
            )
        )

        for item in sorted_unknown:
            clusters.append({
                "cluster_id": f"C{cluster_id}",
                "file": path,
                "count": 1,
                "items": [item]
            })
            cluster_id += 1

    return clusters

def main():
    parser = argparse.ArgumentParser(description="Vuln Triage Pre-pass")
    parser.add_argument("--target", required=True, help="Path to target directory")
    parser.add_argument("--output", required=True, help="Output JSON path")
    args = parser.parse_args()

    target_path = Path(args.target).resolve()
    target_name = target_path.name
    output_path = Path(args.output).resolve() if args.output else None

    threat_model_text, tm_path = load_threat_model(target_name, target_path, output_file=output_path)
    active_findings = gather_findings(target_name)
    clusters = cluster_deterministic(active_findings)

    MAX_TM_SUMMARY_CHARS = 3000
    if len(threat_model_text) > MAX_TM_SUMMARY_CHARS:
        threat_model_summary = (
            f"[THREAT_MODEL.md summarised: showing first {MAX_TM_SUMMARY_CHARS} of {len(threat_model_text)} chars. "
            f"Full document available to read via file: {tm_path or 'THREAT_MODEL.md'}]\n"
            + threat_model_text[:MAX_TM_SUMMARY_CHARS]
            + f"\n\n... [TRUNCATED: remaining {len(threat_model_text) - MAX_TM_SUMMARY_CHARS} chars omitted. Read {tm_path or 'THREAT_MODEL.md'} with read tool.]"
        )
    else:
        threat_model_summary = threat_model_text

    payload = {
        "target": target_name,
        "total_active_findings": len(active_findings),
        "cluster_count": len(clusters),
        "threat_model_summary": threat_model_summary,
        "threat_model_file": tm_path or None,
        "clusters": clusters
    }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print(f"vuln-triage: {len(active_findings)} findings grouped into {len(clusters)} deterministic clusters.")

if __name__ == "__main__":
    main()
