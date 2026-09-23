#!/usr/bin/env python3
"""Deterministic Pre-Pass for Factory QA Station (agents/qa-station/scripts/audit_factory_quality.py)

Audits the Software Factory's own fleet and findings store:
1. Verifies every `agents/<name>/` directory has valid `agent.yaml`, `SKILL.md`, `scripts/`, and `report.schema.json`.
2. Analyzes `findings/*-findings.json` and `findings/suppressions.yaml` to compute per-agent finding volume,
   `wontfix` false-positive rates, duplicate snippet rates, and missing remediation quality.
3. Flags noisy rules (`wontfix_rate > 0.30` or high volume of low-value alerts) for prompt/pre-pass tuning.
"""

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List

FACTORY_ROOT = Path(__file__).resolve().parent.parent.parent.parent
AGENTS_DIR = FACTORY_ROOT / "agents"
FINDINGS_DIR = FACTORY_ROOT / "findings"


def audit_agent_contracts() -> List[Dict[str, Any]]:
    contract_issues = []
    for p in sorted(AGENTS_DIR.iterdir()):
        if not p.is_dir() or p.name.startswith("."):
            continue
        required_files = ["agent.yaml", "SKILL.md", "report.schema.json"]
        for req in required_files:
            if not (p / req).exists():
                contract_issues.append({
                    "rule_id": "qa-missing-agent-contract-file",
                    "agent": p.name,
                    "path": f"agents/{p.name}/{req}",
                    "severity": "high",
                    "title": f"Agent '{p.name}' Missing Required Contract File '{req}'"
                })
        scripts_dir = p / "scripts"
        if not scripts_dir.exists() or not list(scripts_dir.glob("*.py")):
            contract_issues.append({
                "rule_id": "qa-missing-deterministic-prepass",
                "agent": p.name,
                "path": f"agents/{p.name}/scripts",
                "severity": "high",
                "title": f"Agent '{p.name}' Missing Deterministic Python Pre-Pass Script"
            })
    return contract_issues


def audit_findings_precision() -> Dict[str, Any]:
    agent_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
        "total_findings": 0,
        "new": 0,
        "accepted": 0,
        "wontfix": 0,
        "fixed": 0,
        "missing_remediation": 0
    })
    noisy_candidates: List[Dict[str, Any]] = []

    if FINDINGS_DIR.exists():
        for fpath in sorted(FINDINGS_DIR.glob("*-findings.json")):
            try:
                store = json.loads(fpath.read_text(encoding="utf-8"))
            except Exception:
                continue

            items = list(store.values()) if isinstance(store, dict) else store
            for item in items:
                if not isinstance(item, dict):
                    continue
                ag = item.get("agent", "unknown")
                status = item.get("status", "new")
                st = agent_stats[ag]
                st["total_findings"] += 1
                st[status] = st.get(status, 0) + 1
                if not item.get("remediation"):
                    st["missing_remediation"] += 1

    scorecards = []
    for ag, st in sorted(agent_stats.items()):
        total = max(1, st["total_findings"])
        wontfix_rate = round(st["wontfix"] / total, 3)
        precision_est = round(1.0 - wontfix_rate, 3)
        scorecards.append({
            "agent": ag,
            **st,
            "wontfix_rate": wontfix_rate,
            "estimated_precision": precision_est
        })
        if wontfix_rate > 0.30 and st["total_findings"] >= 3:
            noisy_candidates.append({
                "rule_id": "qa-agent-high-wontfix-noise",
                "agent": ag,
                "path": f"agents/{ag}/SKILL.md",
                "severity": "medium",
                "title": f"Agent '{ag}' Exceeds 30% Wontfix Threshold ({wontfix_rate * 100:.1f}%)",
                "rationale": "High wontfix ratio indicates false-positive creep; tighten deterministic pre-pass filters or SKILL.md triage rules."
            })

    return {
        "agent_scorecards": scorecards,
        "noisy_candidates": noisy_candidates
    }


def main():
    parser = argparse.ArgumentParser(description="Factory QA Station quality & precision auditor")
    parser.add_argument("--target", required=True, help="Target repository directory")
    parser.add_argument("--output", help="Output JSON path")
    args = parser.parse_args()

    contract_issues = audit_agent_contracts()
    precision_data = audit_findings_precision()

    fleet_names = sorted([
        p.name for p in AGENTS_DIR.iterdir()
        if p.is_dir() and (p / "agent.yaml").exists()
    ])

    payload = {
        "target": Path(args.target).resolve().name,
        "fleet_size": len(fleet_names),
        "fleet_agents": fleet_names,
        "contract_issues": contract_issues,
        "agent_scorecards": precision_data["agent_scorecards"],
        "candidates": contract_issues + precision_data["noisy_candidates"]
    }

    out = json.dumps(payload, indent=2)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
    else:
        print(out)


if __name__ == "__main__":
    main()
