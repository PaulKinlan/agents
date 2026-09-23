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
from typing import Any, Dict, List

FACTORY_ROOT = Path(__file__).resolve().parent.parent.parent.parent

def load_threat_model(target_name: str, target_dir: Path) -> str:
    # 1. Local target THREAT_MODEL.md
    local_tm = target_dir / "THREAT_MODEL.md"
    if local_tm.exists():
        return local_tm.read_text(encoding="utf-8")
    # 2. Findings stored THREAT_MODEL.md
    store_tm = FACTORY_ROOT / "findings" / f"{target_name}-THREAT_MODEL.md"
    if store_tm.exists():
        return store_tm.read_text(encoding="utf-8")
    return "No THREAT_MODEL.md found. Treat all external inputs as untrusted."

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

def cluster_deterministic(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Groups findings by file and proximity (lines within 15)."""
    by_file: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        path = f.get("path", "unknown")
        by_file.setdefault(path, []).append(f)

    clusters = []
    cluster_id = 1

    for path, items in by_file.items():
        sorted_items = sorted(items, key=lambda x: x.get("line_number") or 0)
        current_cluster = []
        last_line = None

        for item in sorted_items:
            line = item.get("line_number")
            if line is not None and last_line is not None and abs(line - last_line) <= 15:
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
                last_line = line if line is not None else 0

        if current_cluster:
            clusters.append({
                "cluster_id": f"C{cluster_id}",
                "file": path,
                "count": len(current_cluster),
                "items": current_cluster
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

    threat_model_text = load_threat_model(target_name, target_path)
    active_findings = gather_findings(target_name)
    clusters = cluster_deterministic(active_findings)

    payload = {
        "target": target_name,
        "total_active_findings": len(active_findings),
        "cluster_count": len(clusters),
        "threat_model_summary": threat_model_text[:3000],
        "clusters": clusters
    }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print(f"vuln-triage: {len(active_findings)} findings grouped into {len(clusters)} deterministic clusters.")

if __name__ == "__main__":
    main()
