#!/usr/bin/env python3
"""Deterministic Pre-Pass for Factory QA Station (agents/qa-station/scripts/audit_factory_quality.py)

Audits the Software Factory's own fleet and findings store:
1. Verifies every `agents/<name>/` directory has valid `agent.yaml`, `SKILL.md`, `scripts/`, and `report.schema.json`, and that the manifest actually satisfies the documented anatomy contract (required fields and their declared value sets, SKILL.md discovery frontmatter) rather than merely existing (agents-40jyn).
2. Analyzes readable `findings/*.json` lifecycle stores to compute per-agent finding volume,
   `wontfix` false-positive rates and missing-remediation counts.
3. Flags agents with at least three findings and `wontfix_rate > 0.30` for prompt/pre-pass tuning.
"""

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional
import sys

FACTORY_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(FACTORY_ROOT) not in sys.path:
    sys.path.insert(0, str(FACTORY_ROOT))

from lib.candidate_identity import assign_candidate_ids, artefact_scheme_fields  # noqa: E402
from lib.embargo import is_false_positive  # noqa: E402
from lib.redaction import emit_station_result  # noqa: E402
from lib.yaml_mini import load_yaml, YamlParseError  # noqa: E402
AGENTS_DIR = FACTORY_ROOT / "agents"
FINDINGS_DIR = FACTORY_ROOT / "findings"
# agents-21lfh: states whose finding is still live work. wontfix is a human suppression, fixed is
# closed; neither has a next step left to describe.
LIVE_WORK_STATES = frozenset(("new", "accepted", "regressed"))

# The anatomy contract is more than file existence (agents-40jyn): AGENTS.md "Required
# agent.yaml fields" names five fields with closed value sets, and every SKILL.md carries a
# frontmatter block declaring `name` and `description` (how all three engines discover the
# skill). A manifest that parses to the wrong shape, or a skill whose discovery header is
# missing, passes the old existence check while violating the contract the fleet documents.
REQUIRED_YAML_FIELDS: Dict[str, Optional[frozenset]] = {
    "class": frozenset({"observer", "proposer", "optimizer"}),
    "containment": frozenset({"t0-readonly", "t1-fetch", "t2-local", "t3-sandbox"}),
    # `plane` and `triggers` may be a scalar or a list; every value must be in the set and
    # the field must not be empty.
    "plane": frozenset({"local", "ci", "both"}),
    "triggers": frozenset({"schedule", "manual", "git-hook", "repo-event", "webhook", "agent"}),
    # `blocking` is presence+boolean only (AGENTS.md: "true only if deterministic and
    # sub-5s"), so its allowed set is empty here and `_invalid_field_reason` handles it
    # before ever reading the set.
    "blocking": frozenset(),
}
REQUIRED_SKILL_FRONTMATTER = ("name", "description")


def _frontmatter_sections(skill_text: str) -> List[str]:
    """Required frontmatter sections MISSING from a SKILL.md's leading `---` block.

    A presence check, not a YAML parse: the question is whether the discovery header
    declares each required section with a non-empty value, answered line-wise so the
    pre-pass never writes a temp file. Lines after the closing `---` are body, not
    frontmatter, and indented `name:`/`description:` keys are not top-level declarations.
    """
    lines = skill_text.splitlines()
    if not lines or lines[0].strip() != "---":
        return list(REQUIRED_SKILL_FRONTMATTER)
    closing = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            closing = i
            break
    if closing is None:
        return list(REQUIRED_SKILL_FRONTMATTER)
    present = set()
    for line in lines[1:closing]:
        m = re.match(r"^(name|description):\s*(\S.*)$", line)
        if m:
            present.add(m.group(1))
    return [s for s in REQUIRED_SKILL_FRONTMATTER if s not in present]


def _invalid_field_reason(field: str, value: Any) -> Optional[str]:
    """Why `value` violates the declared contract for `field`, or None when it complies."""
    allowed = REQUIRED_YAML_FIELDS[field]
    if field == "blocking":
        if not isinstance(value, bool):
            return f"expected a boolean, got {value!r}"
        return None
    values = value if isinstance(value, list) else [value]
    if not values:
        return "must declare at least one value"
    bad = [v for v in values if not (isinstance(v, str) and v in allowed)]
    if bad:
        return f"expected one of {sorted(allowed)}, got {bad!r}"
    return None

VALID_STATES = frozenset(("new", "accepted", "wontfix", "fixed", "regressed"))


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
        manifest = p / "agent.yaml"
        if manifest.exists():
            try:
                config = load_yaml(manifest)
            except (YamlParseError, OSError) as exc:
                contract_issues.append({
                    "rule_id": "qa-agent-yaml-unparseable",
                    "agent": p.name,
                    "path": f"agents/{p.name}/agent.yaml",
                    "severity": "high",
                    "title": f"Agent '{p.name}' agent.yaml Does Not Parse: {exc}"
                })
            else:
                if not isinstance(config, dict):
                    contract_issues.append({
                        "rule_id": "qa-agent-yaml-unparseable",
                        "agent": p.name,
                        "path": f"agents/{p.name}/agent.yaml",
                        "severity": "high",
                        "title": f"Agent '{p.name}' agent.yaml Is Not A Mapping: {type(config).__name__}"
                    })
                else:
                    for field, allowed in REQUIRED_YAML_FIELDS.items():
                        if field not in config:
                            contract_issues.append({
                                "rule_id": "qa-missing-agent-yaml-field",
                                "agent": p.name,
                                "path": f"agents/{p.name}/agent.yaml",
                                "severity": "high",
                                "title": f"Agent '{p.name}' agent.yaml Missing Required Field '{field}'"
                            })
                            continue
                        reason = _invalid_field_reason(field, config[field])
                        if reason:
                            contract_issues.append({
                                "rule_id": "qa-invalid-agent-yaml-value",
                                "agent": p.name,
                                "path": f"agents/{p.name}/agent.yaml",
                                "severity": "high",
                                "title": f"Agent '{p.name}' agent.yaml Field '{field}' Invalid: {reason}"
                            })
        skill = p / "SKILL.md"
        if skill.exists():
            try:
                skill_text = skill.read_text(encoding="utf-8")
            except OSError:
                skill_text = ""
            missing_sections = _frontmatter_sections(skill_text)
            if missing_sections:
                contract_issues.append({
                    "rule_id": "qa-missing-skill-frontmatter",
                    "agent": p.name,
                    "path": f"agents/{p.name}/SKILL.md",
                    "severity": "high",
                    "title": (f"Agent '{p.name}' SKILL.md Frontmatter Missing Required "
                              f"Section(s): {', '.join(missing_sections)}")
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
    # agents-21lfh: the LIVE-WORK population the remediation-gap derivation reads - states whose
    # finding still asks a human for a next step, discounting dismissals (false_positive rows).
    live_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: {
        "live_total": 0,
        "live_missing_remediation": 0
    })
    noisy_candidates: List[Dict[str, Any]] = []
    stores_read: List[str] = []

    # The store is `findings/<target>.json` = {"target", "findings": {fingerprint: record}},
    # and a record's lifecycle is `state`. This used to glob `*-findings.json` (a name the
    # store never had) and read `status`, so it audited nothing and reported a clean fleet
    # (journal-wog). Any JSON file of the store's shape is read; anything else is skipped.
    if FINDINGS_DIR.exists():
        for fpath in sorted(FINDINGS_DIR.glob("*.json")):
            try:
                store = json.loads(fpath.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not (isinstance(store, dict) and isinstance(store.get("findings"), dict)):
                continue
            stores_read.append(fpath.name)
            invalid_states = 0
            for item in store["findings"].values():
                if not isinstance(item, dict):
                    continue
                # `state` is authoritative; support a legacy `status` only when state
                # is absent. Never treat a malformed value as new or use an untrusted
                # string as a scorecard key (or confuse a corrupted store with precision).
                status = item.get("state", item.get("status"))
                if not isinstance(status, str) or status not in VALID_STATES:
                    invalid_states += 1
                    continue
                ag = item.get("agent", "unknown")
                st = agent_stats[ag]
                st["total_findings"] += 1
                st[status] = st.get(status, 0) + 1
                has_remediation = bool(item.get("remediation"))
                if not has_remediation:
                    st["missing_remediation"] += 1
                # The gap derivation reads LIVE WORK only (agents-21lfh): a dismissal row has no next
                # step by design and a suppression was written by a human, so neither is an omission.
                if status in LIVE_WORK_STATES and not is_false_positive(item):
                    live = live_stats[ag]
                    live["live_total"] += 1
                    if not has_remediation:
                        live["live_missing_remediation"] += 1
            if invalid_states:
                noisy_candidates.append({
                    "rule_id": "qa-invalid-findings-state",
                    "agent": "qa-station",
                    "path": f"findings/{fpath.name}",
                    "severity": "medium",
                    "title": f"Findings store has {invalid_states} invalid lifecycle state(s)",
                    "rationale": ("Exclude malformed records from precision estimates and repair their "
                                  "state/status to one of new, accepted, wontfix, fixed, regressed "
                                  "after verifying the real disposition."),
                })

    scorecards = []
    for ag, st in sorted(agent_stats.items()):
        total = max(1, st["total_findings"])
        wontfix_rate = round(st["wontfix"] / total, 3)
        precision_est = round(1.0 - wontfix_rate, 3)
        # agents-e3jru: missing_remediation was counted but never DERIVED - the scorecard carried a raw
        # count the SKILL.md tells the model to review, with no rate and no candidate rule, so an agent
        # whose findings systematically lack a remediation never surfaced the way a high wontfix rate
        # does. Same shape, same thresholds: a rate over the same 30% line, on the same >=3 floor.
        # agents-21lfh: measured over LIVE WORK ONLY (states new/accepted/regressed whose row is not a
        # dismissal - is_false_positive, the same predicate the store and publication filter use). A
        # dismissed finding has no next step by design ('evidence, not work', agents-f8dj) and a
        # suppression comes from findings/suppressions.yaml, not from the model omitting anything, so
        # either population alone must not read as a remediation contract gap. The raw
        # missing_remediation counter above stays polarity- and state-blind by contract (agents-xoxum).
        live = live_stats.get(ag) or {}
        live_total = live.get("live_total", 0)
        live_missing = live.get("live_missing_remediation", 0)
        missing_remediation_rate = round(live_missing / live_total, 3) if live_total else 0.0
        scorecards.append({
            "agent": ag,
            **st,
            "wontfix_rate": wontfix_rate,
            "missing_remediation_rate": missing_remediation_rate,
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
        if missing_remediation_rate > 0.30 and live_total >= 3:
            noisy_candidates.append({
                "rule_id": "qa-agent-remediation-gap",
                "agent": ag,
                "path": f"agents/{ag}/SKILL.md",
                "severity": "medium",
                "title": (f"Agent '{ag}' omits remediation on {live_missing} of "
                          f"{live_total} live findings ({missing_remediation_rate * 100:.1f}%)"),
                "rationale": ("Findings without remediation hand a human a problem with no next step; "
                              "the SKILL.md output contract must require an actionable remediation per finding.")
            })

    if not agent_stats:
        # A line can create findings/<target>.json with an EMPTY findings map. The old
        # `not stores_read` check then treated that file as measurement evidence and
        # reported a clean fleet despite having zero lifecycle records (agents-2e8).
        # No observations are not a precision of 100%, regardless of file presence.
        noisy_candidates.append({
            "rule_id": "qa-no-findings-store",
            "agent": "qa-station",
            "path": "findings/",
            "severity": "info",
            "title": "No findings lifecycle records: agent precision was not measured",
            "rationale": (f"No valid findings/<target>.json lifecycle records under {FINDINGS_DIR} "
                          f"(stores read: {len(stores_read)}). A populated store from real "
                          "station runs and human disposition is needed before trusting a "
                          "qa-station precision verdict."),
        })

    return {
        "agent_scorecards": scorecards,
        "noisy_candidates": noisy_candidates,
        "stores_read": stores_read,
    }


def main():
    parser = argparse.ArgumentParser(description="Factory QA Station quality & precision auditor")
    parser.add_argument("--target", required=True, help="Target repository directory")
    parser.add_argument("--output", help="Output JSON path")
    args = parser.parse_args()

    # A missing target is an error, never a clean audit (journal-wog).
    target = Path(args.target).resolve()
    if not target.is_dir():
        import sys
        sys.stderr.write(f"Target does not exist or is not a directory: {target}\n")
        sys.exit(1)

    contract_issues = audit_agent_contracts()
    precision_data = audit_findings_precision()

    fleet_names = sorted([
        p.name for p in AGENTS_DIR.iterdir()
        if p.is_dir() and (p / "agent.yaml").exists()
    ])

    # The candidate set is an expression here, so it is named first: the helper needs the whole
    # list, and a spread would hide the fact that these candidates never got an identity.
    candidates = contract_issues + precision_data["noisy_candidates"]
    # Every candidate gets a deterministic identity at scan time (agents-rdyb), so a consumer can
    # COPY it rather than reconstruct identity from the model's label and prose.
    assign_candidate_ids(candidates)

    payload = {
        **artefact_scheme_fields(),
        "target": target.name,
        "stores_read": precision_data["stores_read"],
        "fleet_size": len(fleet_names),
        "fleet_agents": fleet_names,
        "contract_issues": contract_issues,
        "agent_scorecards": precision_data["agent_scorecards"],
        # The dispatcher presents only `candidates` and opt-in `context` to the model.
        # Without this context a clean scan exposes just [] and the model must guess
        # fleet size and lifecycle statistics from the SKILL.md example.
        "context": {
            "stores_read": precision_data["stores_read"],
            "fleet_size": len(fleet_names),
            "fleet_agents": fleet_names,
            "agent_scorecards": precision_data["agent_scorecards"],
        },
        "candidates": candidates
    }

    emit_station_result(payload, args.output)


if __name__ == "__main__":
    main()
