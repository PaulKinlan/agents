#!/usr/bin/env python3
"""Validate model reports against the agent's declared output schema (agents-1r5, SF-07).

Every agent ships report.schema.json and every agent.yaml names it under output.schema.
Until now nothing loaded it: model output went from a lenient JSON extraction straight
into the findings store, so an unvalidated (or absent) severity flowed into security
decisions and malformed reports produced findings with None fields that were then
formatted into delta reports and issue bodies.

The schemas across agents/ use a small JSON Schema subset — type, required, properties,
items, enum, minimum, maximum — and this project is stdlib-only, so validation lives
here as a deliberately small checker rather than a dependency. Unsupported keywords are
ignored on purpose: a validator that silently passes constructs it does not understand
is exactly the failure mode this module exists to remove, but the declared schemas are
surveyed and covered, and qa-station checks that every agent ships the file.
"""

import json
import re
from collections.abc import Mapping as MappingABC
from pathlib import Path
from typing import Any, Dict, List, Optional

from lib.findings import path_resolves_in_target

_TYPE_CHECKS = {
    # bool is a subclass of int in Python, but never in JSON Schema.
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}


def validate(instance: Any, schema: Any, path: str = "$") -> List[str]:
    """Check instance against the supported schema subset, returning violations.

    Each violation is a human-readable `path: reason` string; an empty list means the
    instance conforms. Unknown keywords are ignored rather than treated as failure.
    """
    errors: List[str] = []
    if not isinstance(schema, dict):
        return errors

    if "enum" in schema:
        allowed = schema["enum"]
        if isinstance(allowed, list) and instance not in allowed:
            errors.append(f"{path}: {instance!r} not in enum {allowed!r}")

    declared = schema.get("type")
    if declared is not None:
        types = declared if isinstance(declared, list) else [declared]
        checks = [_TYPE_CHECKS.get(t) for t in types]
        if any(c is None for c in checks):
            errors.append(f"{path}: unsupported type keyword {declared!r}")
        elif not any(c(instance) for c in checks if c):
            errors.append(
                f"{path}: expected type {declared!r}, got {type(instance).__name__}"
            )
            return errors  # deeper checks are meaningless against the wrong type

    if isinstance(instance, dict):
        required = schema.get("required", [])
        if isinstance(required, list):
            for name in required:
                if name not in instance:
                    errors.append(f"{path}: missing required property {name!r}")
        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            for name, subschema in properties.items():
                if name in instance:
                    errors.extend(validate(instance[name], subschema, f"{path}.{name}"))
    elif isinstance(instance, list):
        items = schema.get("items")
        if isinstance(items, dict):
            for index, item in enumerate(instance):
                errors.extend(validate(item, items, f"{path}[{index}]"))
    elif isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append(f"{path}: {instance!r} below minimum {schema['minimum']!r}")
        if "maximum" in schema and instance > schema["maximum"]:
            errors.append(f"{path}: {instance!r} above maximum {schema['maximum']!r}")

    return errors


def declared_schema(agent_dir: Path, agent_cfg: MappingABC) -> Optional[Dict[str, Any]]:
    """Load the schema agent.yaml declares under output.schema, or None if undeclared.

    A declared schema that is missing or unparseable is a broken contract: raise so the
    caller fails closed rather than silently skipping the one check this module exists for.
    """
    output = agent_cfg.get("output")
    name = output.get("schema") if isinstance(output, MappingABC) else None
    if not name or not isinstance(name, str):
        return None
    path = agent_dir / name
    if not path.exists():
        raise FileNotFoundError(f"{agent_dir.name} declares output.schema {name!r} but {path} does not exist")
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(schema, dict):
        raise ValueError(f"{path} is not a JSON Schema object")
    return schema


def unlocatable_verdicts(report: Any, target_dir: Optional[Path] = None) -> List[str]:
    """A verifier must not adjudicate a record it cannot locate (agents-0tl).

    `vuln-verify` returns `verifications[]` entries carrying a `path` and a `verdict`. Nothing
    used to stop a model returning `verdict: "disproved"` with `confidence: "high"` for a
    record whose location was `unknown` - observed on the 2026-10-09 dogfood audit, where four
    such records were "disproved" with no location and one of them (the memory-profile
    findings/ exclusion) turned out to be real and is now fixed. A verifier that cannot point
    at the code cannot disprove a claim about it, and it cannot verify one either: the only
    honest verdict for an unlocatable record is `unverifiable`, which asks for the location
    instead of inventing a conclusion.

    Returns a violation per offending entry (empty when the report is fine). A record is
    locatable when its `path` names an existing entry inside `target_dir`; when no target is
    supplied only an explicitly missing/placeholder path is treated as unlocatable.
    """
    violations: List[str] = []
    if not isinstance(report, dict):
        return violations
    verifications = report.get("verifications")
    if not isinstance(verifications, list):
        return violations
    for i, entry in enumerate(verifications):
        if not isinstance(entry, dict):
            continue
        verdict = entry.get("verdict")
        if verdict not in ("verified", "disproved"):
            continue
        raw_path = entry.get("path")
        placeholder = (not isinstance(raw_path, str) or not raw_path.strip()
                       or raw_path.strip().lower() in ("unknown", "unclassified"))
        # With no target to resolve against, only an explicitly missing/placeholder path is
        # treated as unlocatable: the rule is about refusing to adjudicate a record that has no
        # location, not about rejecting a path string we merely cannot check.
        unresolvable = placeholder or (target_dir is not None
                                       and not path_resolves_in_target(raw_path, target_dir))
        if unresolvable:
            violations.append(
                f"$.verifications[{i}].verdict: {verdict!r} is not available for a record with "
                f"no resolvable location (path={raw_path!r}); the only honest verdict is "
                f"'unverifiable' - cite a location inside the target or ask for one"
            )
    return violations


# ---------------------------------------------------------------------------------------------
# Concurrency recommendation guard (agents-vorw / hub fleet-4inv)
#
# Concurrency recommendations (e.g. replacing loops with Promise.all / asyncio.gather)
# must either name the backend and cite evidence that it tolerates overlap, or carry
# their reentrancy precondition ("IF this runtime is reentrant..."). Unchecked concurrency
# recommendations on non-reentrant runtimes (like ONNX Runtime Web wasm with its module-level
# _OrtRun mutex, WebGPU compute passes, or transactional handles) crash the application.
# ---------------------------------------------------------------------------------------------

_EXECUTION_CONCURRENCY_PATTERN = re.compile(
    r"\b(?:Promise\.(?:all|allSettled|race)|asyncio\.gather)\b"
    r"|(?:run|execute|call|dispatch|await|start)\b[^.;\n]*?\b(?:concurrently|in\s+parallel|simultaneously|at\s+the\s+same\s+time)\b"
    r"|\b(?:concurrent|parallel|simultaneous)\s+(?:execution|calls?|invocations?|passes|runs?|tasks?|inferences?|computations?|operations?)\b"
    r"|\bparallel(?:ize|izing|ization)\b"
    r"|\b(?:worker\s+pool|thread\s+pool|web\s+worker|worker_threads)\b",
    re.IGNORECASE
)

# Exclude non-execution asset downloads / stylesheet preloading
_ASSET_CONCURRENCY_EXCLUSIONS = re.compile(
    r"\b(?:<link\b|@import|stylesheet|preload|prefetch|html\s+parsing|download\s+styles?|fetchpriority)\b",
    re.IGNORECASE
)

# Named backend evidence: must name a specific known-reentrant backend/API and cite overlap support
_NAMED_BACKEND_PATTERN = re.compile(
    r"\b(?:node(?:\.js)?|fetch|http|network|read-only\s+i/o|fs(?:\.promises)?|libuv|threadpool|stateless\s+api)\b",
    re.IGNORECASE
)

_CONDITIONAL_REENTRANCY_PATTERN = re.compile(
    r"\b(?:precondition:?\s*verify\s+backend\s+reentrancy|if\s+[^.;\n]{1,80}?\b(?:is\s+reentrant|is\s+thread[- ]safe|supports?\s+concurrency|supports?\s+concurrent|tolerates?\s+overlap))\b",
    re.IGNORECASE
)

_SERIAL_FALLBACK_PATTERN = re.compile(
    r"\b(?:otherwise|else)\s+(?:preserve|keep|maintain|run|use)?\s*(?:documented\s+)?(?:serial(?:ly)?|sequentially)\b"
    r"|\b(?:preserve|keep|maintain)\s+(?:documented\s+)?(?:serial|sequential)\b",
    re.IGNORECASE
)

_POSITIVE_EVIDENCE_PATTERN = re.compile(
    r"\b(?:is\s+(?:proven\s+)?reentrant|is\s+known\s+to\s+be\s+reentrant|is\s+thread[- ]safe|supports?\s+(?:concurrent|concurrency|overlap)|tolerates?\s+overlap)\b",
    re.IGNORECASE
)

_NEGATION_PATTERN = re.compile(
    r"\b(?:not|no|never|does\s+not|doesn't|cannot|can't|unsupported|non-reentrant|lacks?)\b",
    re.IGNORECASE
)


def is_concurrency_recommendation(finding: Dict[str, Any]) -> bool:
    """Return True if a finding proposes concurrent / parallel / overlapping execution."""
    if not isinstance(finding, dict):
        return False
    rule_id = str(finding.get("rule_id", "")).strip().lower()
    if rule_id == "sequential-await-waterfall":
        return True
    if rule_id == "render-blocking-head-asset":
        return False

    remediation = str(finding.get("remediation", ""))
    diff = str(finding.get("proposed_fix_diff", ""))
    # If remediation or fix diff specifically recommends execution concurrency, it is an execution concurrency finding
    if _EXECUTION_CONCURRENCY_PATTERN.search(remediation) or _EXECUTION_CONCURRENCY_PATTERN.search(diff):
        return True

    # Otherwise check title and description, excluding pure asset/stylesheet loading
    if _ASSET_CONCURRENCY_EXCLUSIONS.search(remediation) and not _EXECUTION_CONCURRENCY_PATTERN.search(remediation):
        return False

    text = " ".join([str(finding.get("title", "")), str(finding.get("description", ""))])
    return bool(_EXECUTION_CONCURRENCY_PATTERN.search(text))


def has_reentrancy_precondition(finding: Dict[str, Any]) -> bool:
    """Return True if the remediation is properly conditional with a serial fallback
    or names a specific backend with cited evidence that it tolerates overlap.

    Negative statements, bare assertions ('backend is reentrant' without naming the backend),
    or conditional suggestions without a serial fallback do NOT qualify as a preconditioned
    recommendation (agents-vorw / hub fleet-4inv).
    """
    if not isinstance(finding, dict):
        return False
    remediation = str(finding.get("remediation", "")).strip()
    if not remediation:
        return False

    has_negation = bool(_NEGATION_PATTERN.search(remediation))

    # Case 1: Conditional advice with explicit serial fallback
    has_condition = bool(_CONDITIONAL_REENTRANCY_PATTERN.search(remediation))
    has_fallback = bool(_SERIAL_FALLBACK_PATTERN.search(remediation))
    if has_condition and has_fallback:
        return True

    # Case 2: Named backend citing proven evidence of overlap tolerance
    # Must name the specific backend, cite positive evidence, have no negation, and not be hypothetical
    if not has_negation and not re.search(r"\b(?:if|whether|assuming)\b", remediation, re.IGNORECASE):
        if _NAMED_BACKEND_PATTERN.search(remediation) and _POSITIVE_EVIDENCE_PATTERN.search(remediation):
            return True

    return False


def guard_concurrency_finding(finding: Dict[str, Any], index: int) -> Optional[str]:
    """Ensure a concurrency recommendation carries its reentrancy precondition.

    If the finding recommends concurrency without citing backend evidence or stating
    a reentrancy precondition, wrap/prepend the remediation and description with the
    explicit precondition so applying it will not crash on non-reentrant runtimes
    (agents-vorw / hub fleet-4inv).
    """
    if not is_concurrency_recommendation(finding) or has_reentrancy_precondition(finding):
        return None

    remediation = str(finding.get("remediation", "")).strip()
    if remediation:
        finding["remediation"] = (
            "Precondition: Verify backend reentrancy before applying. "
            f"IF the underlying runtime/backend is reentrant and thread-safe (e.g. does not use a non-reentrant mutex or shared state like ONNX Runtime _OrtRun or WebGPU queues), {remediation}; otherwise preserve serial execution."
        )
    else:
        finding["remediation"] = (
            "Precondition: Verify backend reentrancy before applying. "
            "IF the underlying runtime/backend is reentrant and thread-safe (e.g. does not use a non-reentrant mutex or shared state like ONNX Runtime _OrtRun or WebGPU queues), consider parallel execution; otherwise preserve serial execution."
        )

    desc = str(finding.get("description", "")).strip()
    if desc and "[Precondition Note:" not in desc:
        finding["description"] = (
            desc + "\n[Precondition Note: Concurrency advice requires verified backend reentrancy; if the runtime is non-reentrant, serial execution must be preserved.]"
        )
    return f"findings[{index}]: enforced reentrancy precondition on concurrency recommendation"


def unpreconditioned_concurrency_findings(report: Any) -> List[str]:
    """Check if any finding makes an unchecked concurrency recommendation without a precondition."""
    violations: List[str] = []
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        return violations
    for i, item in enumerate(report["findings"]):
        if not isinstance(item, dict):
            continue
        if is_concurrency_recommendation(item) and not has_reentrancy_precondition(item):
            violations.append(
                f"$.findings[{i}]: concurrency recommendation (rule {item.get('rule_id', 'unknown')!r}) "
                "must cite backend evidence that it tolerates overlap or state its reentrancy precondition "
                "('IF this runtime is reentrant...')"
            )
    return violations


def validate_agent_report(agent_dir: Path, agent_cfg: MappingABC, report: Any,
                          target_dir: Optional[Path] = None) -> Optional[List[str]]:
    """Validate a model report against the agent's declared schema.

    Returns a list of violations (empty when the report conforms), or None when the agent
    declares no output schema and there is nothing to check against. A declared schema that
    cannot be loaded is returned as a violation so the dispatcher fails closed.

    Cross-field rules the schema cannot express are applied on top:
    - a verdict about a location must have a location (agents-0tl)
    - a concurrency recommendation must carry its reentrancy precondition or cite backend evidence (agents-vorw)
    """
    try:
        schema = declared_schema(agent_dir, agent_cfg)
    except (FileNotFoundError, ValueError) as exc:
        return [f"$: {exc}"]
    if schema is None:
        return None
    return (
        validate(report, schema)
        + unlocatable_verdicts(report, target_dir)
        + unpreconditioned_concurrency_findings(report)
    )


# ---------------------------------------------------------------------------------------------
# Field-name normalisation (fleet-9wyi)
#
# A model that returns a complete analysis under `"id": "TM-1"` instead of `"rule_id"` has not
# produced unusable output; it has used a synonym. Rejecting the whole report for that turned a
# 23KB threat model into "no verdict" and halted the line. Before validation, each finding's
# well-known synonyms are mapped onto the canonical names the findings store reads. Only a
# canonical field that is *absent* is filled, only from an alias that is not itself a declared
# property, and every mapping is reported. The schema still decides: a report that is still
# non-conformant after this is rejected exactly as before.
# ---------------------------------------------------------------------------------------------

FINDING_FIELD_ALIASES = {
    "rule_id": ("id", "rule", "ruleId", "rule_name", "check_id", "finding_id", "threat_id", "type"),
    "path": ("file", "file_path", "filepath", "filename", "location", "affected_file"),
    "line_number": ("line", "lineNumber", "line_no", "lineno", "start_line"),
    "title": ("name", "headline", "summary"),
    "description": ("details", "detail", "explanation", "rationale", "impact", "body"),
    "remediation": ("recommendation", "mitigation", "fix", "suggested_fix", "remedy"),
    "snippet": ("code", "evidence", "excerpt", "code_snippet"),
    "severity": ("risk", "level", "risk_level"),
}

SEVERITY_SYNONYMS = {
    "moderate": "medium", "med": "medium", "informational": "info", "information": "info",
    "none": "info", "crit": "critical", "important": "high", "minor": "low",
}

# `<path>:<line>[:<col>]`, parsed from the numeric suffix so the path may contain spaces and
# a Windows drive-letter colon (`src/my file.ts:12`, `C:\\src\\x.ts:12:5`). The path part must
# be non-empty and not itself end in a colon; the shortest such path wins, so `x.ts:12:5` is
# line 12, column 5.
_LOCATION = re.compile(r"^(?P<path>.*?[^:\s]):(?P<line>\d+)(?::(?P<col>\d+))?$")


def _finding_item_schema(schema: Any) -> Dict[str, Any]:
    if not isinstance(schema, dict):
        return {}
    findings = schema.get("properties", {}).get("findings", {})
    items = findings.get("items", {}) if isinstance(findings, dict) else {}
    return items if isinstance(items, dict) else {}


def normalize_report(report: Any, schema: Optional[Dict[str, Any]] = None) -> List[str]:
    """Map known field-name synonyms in `report["findings"]` onto canonical names, in place.

    Returns human-readable notes ("findings[0]: id -> rule_id"). Also: a `path:line` location
    is split, a digit-string line becomes an integer, and a severity is lower-cased and mapped
    from common synonyms (moderate -> medium). Anything else is left for the schema to judge.
    """
    notes: List[str] = []
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        return notes
    item_schema = _finding_item_schema(schema)
    declared = set(item_schema.get("properties", {}) or {})
    enum = (item_schema.get("properties", {}).get("severity", {}) or {}).get("enum")

    for index, item in enumerate(report["findings"]):
        if not isinstance(item, dict):
            continue
        for canonical, aliases in FINDING_FIELD_ALIASES.items():
            if canonical in item:
                continue
            for alias in aliases:
                if alias in item and alias not in declared and item[alias] not in (None, ""):
                    value = item[alias]
                    if canonical == "path" and isinstance(value, str):
                        match = _LOCATION.match(value.strip())
                        if match:
                            value = match.group("path")
                            item.setdefault("line_number", int(match.group("line")))
                    item[canonical] = value
                    notes.append(f"findings[{index}]: {alias} -> {canonical}")
                    break
        line = item.get("line_number")
        if isinstance(line, str) and line.strip().isdigit():
            item["line_number"] = int(line.strip())
        severity = item.get("severity")
        if isinstance(severity, str):
            lowered = severity.strip().lower()
            lowered = SEVERITY_SYNONYMS.get(lowered, lowered)
            if lowered != severity and (not isinstance(enum, list) or lowered in enum):
                item["severity"] = lowered
                notes.append(f"findings[{index}]: severity {severity!r} -> {lowered!r}")
        guard_note = guard_concurrency_finding(item, index)
        if guard_note:
            notes.append(guard_note)
    return notes


def normalize_agent_report(agent_dir: Path, agent_cfg: MappingABC, report: Any) -> List[str]:
    """`normalize_report` against the agent's declared schema (or none). Never raises."""
    try:
        schema = declared_schema(agent_dir, agent_cfg)
    except (FileNotFoundError, ValueError):
        schema = None
    return normalize_report(report, schema)
