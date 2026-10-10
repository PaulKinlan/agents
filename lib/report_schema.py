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
from typing import Any, Dict, List, Optional, Set

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
    r"\b(?:Promise\.(?:all|allSettled|race|any)|asyncio\.gather)\b"
    r"|(?:run|execute|call|dispatch|await|start|issue|send|use|overlap)\b[^.;\n]*?\b(?:concurrently|in\s+parallel|simultaneously|at\s+the\s+same\s+time|overlap(?:ping)?)\b"
    r"|\b(?:concurrent|parallel|simultaneous|overlapping)\s+(?:execution|calls?|invocations?|passes|runs?|tasks?|inferences?|computations?|operations?|requests?|fetches|queries)\b"
    r"|\bparallel(?:ize|izing|ization)\b"
    r"|\b(?:overlap|overlapping)\s+(?:[^.;\n]{0,40}?\s+)?(?:calls?|invocations?|passes|runs?|tasks?|inferences?|computations?|operations?|requests?|fetches|queries|execution)\b"
    r"|\b(?:pool\s+of\s+workers?|worker\s+pools?|thread\s+pools?|web\s+workers?|worker_threads)\b"
    r"|\b(?:pool\.(?:map|dispatch|exec|run|submit|queue)|pLimit|p-limit)\b",
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

_STRUCTURED_PRECONDITION_PATTERN = re.compile(
    r"\b(?:precondition:?\s*verify\s+backend\s+reentrancy[^\n]*?\b)?if\s+[^\n]{1,120}?\b(?:is\s+(?:proven\s+)?reentrant|is\s+thread[- ]safe|supports?\s+(?:concurrent|concurrency)|tolerates?\s+overlap)\b"
    r"[^\n]{1,160}?\b(?:Promise\.(?:all|allSettled|race|any)|asyncio\.gather|concurrent|parallel|concurrency)\b"
    r"[^\n]{0,100}?\b(?:otherwise|else)\s+(?:preserve|keep|maintain|run|use|default\s+to)?\s*(?:documented\s+)?(?:serial(?:ly)?|sequential(?:ly)?)\b",
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


_STOP_CONCURRENCY_PATTERN = re.compile(
    r"\b(?:stop|avoid|discontinue|eliminate|prevent|cease|replac(?:e|ing)|remov(?:e|ing)|switch(?:ing)?\s+from|do\s+not|don't|never)\s+"
    r"(?:(?:use|using|the|a)\s+)?"
    r"(?:(?:run|running|execute|executing|dispatch|dispatching|call|calling|process|processing)\s+(?:(?!(?:serially|sequential|in\s+series|but)\b)[a-zA-Z0-9_.-]+\s+){0,3}(?:in\s+parallel|concurrently|simultaneously)|"
    r"Promise\.(?:all|allSettled|race|any)|asyncio\.gather|concurrency|parallel(?:ism|iz(?:e|ing|ation))?|overlap(?:ping)?|(?:a\s+)?worker\s+pools?|(?:a\s+)?pool\s+of\s+workers?|thread\s+pools?)\b",
    re.IGNORECASE
)

_ADVOCATES_SERIAL_PATTERN = re.compile(
    r"\b(?:restore|prefer|keep|enforce|switch\s+to|use|run|execute|process|dispatch|await|setup|set\s+up)\s+"
    r"(?:(?!(?:concurrent|parallel|simultaneous|overlap|promise|gather|but)\b)[a-zA-Z0-9_.-]+\s+){0,3}"
    r"(?:serial(?:ly)?|sequential(?:ly)?|in\s+series|one\s+(?:by|at\s+a)\s+time)\b",
    re.IGNORECASE
)


def is_concurrency_recommendation(finding: Dict[str, Any]) -> bool:
    """Return True if a finding proposes concurrent / parallel / overlapping execution."""
    if not isinstance(finding, dict):
        return False
    rule_id = str(finding.get("rule_id", "")).strip().lower()
    if rule_id == "sequential-await-waterfall":
        return True

    remediation = str(finding.get("remediation", ""))
    diff = str(finding.get("proposed_fix_diff", ""))
    added_diff = ""
    removed_diff = ""
    if diff:
        added_diff = "\n".join(
            line[1:] for line in diff.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        )
        removed_diff = "\n".join(
            line[1:] for line in diff.splitlines()
            if line.startswith("-") and not line.startswith("---")
        )

    # 1. If added diff lines specifically introduce concurrency, it is a concurrency recommendation
    if _EXECUTION_CONCURRENCY_PATTERN.search(added_diff):
        return True

    # 2. Check for affirmative concurrency recommendation in remediation (Reviewer P1).
    # Strip negative cessation clauses (e.g. "stop using Promise.all") and serial advocacy clauses
    # (e.g. "run tasks sequentially") to check if any remaining text advocates concurrency.
    stripped_remediation = _STOP_CONCURRENCY_PATTERN.sub(" ", remediation)
    stripped_remediation = _ADVOCATES_SERIAL_PATTERN.sub(" ", stripped_remediation)
    has_remaining_concurrency = bool(_EXECUTION_CONCURRENCY_PATTERN.search(stripped_remediation))
    if has_remaining_concurrency:
        return True

    # 3. Only after confirming there is NO affirmative concurrency recommendation in added diff
    # or remediation, check for serial restoration exemptions:
    # - If diff removes concurrency to restore serial execution, exempt it.
    if _EXECUTION_CONCURRENCY_PATTERN.search(removed_diff):
        return False
    # - If remediation directs serial execution or cessation of concurrency, exempt it.
    has_serial_direction = bool(_STOP_CONCURRENCY_PATTERN.search(remediation) or _ADVOCATES_SERIAL_PATTERN.search(remediation))
    if has_serial_direction:
        return False

    # Pure asset loading rules are excluded unless they explicitly recommended execution concurrency above.
    if rule_id == "render-blocking-head-asset":
        return False
    if _ASSET_CONCURRENCY_EXCLUSIONS.search(remediation):
        return False

    # Fallback to title/description only for affirmative recommendations, not hazard/vulnerability warnings (Reviewer P2)
    text = " ".join([str(finding.get("title", "")), str(finding.get("description", ""))])
    if re.search(r"\b(?:unsafe|hazard|race\s+condition|risk|conflict|corrupt|deadlock|defect|flaw)\b", text, re.IGNORECASE):
        return False
    return bool(_EXECUTION_CONCURRENCY_PATTERN.search(text))


# Domains and primitives where concurrency is often non-reentrant or stateful
_NON_REENTRANT_SUSPECT_PATTERN = re.compile(
    r"\b(?:onnx|sessions?|models?|inferences?|forward\s+passes?|wasm|webassembly|gpus?|webgpu|webgl|transactions?|mutex(?:es)?|locks?|db|databases?|sqlite)\b",
    re.IGNORECASE
)

_RECOGNIZED_STATELESS_CALLS = {
    "fetch",
    "window.fetch",
    "globalthis.fetch",
    "axios",
    "axios.get",
    "fs.promises.readfile",
    "fspromises.readfile",
    "fs.readfile",
    "readfile",
    "read_file",
    "https.get",
    "http.get",
    "download",
}

_BACKEND_OP_FAMILIES = {
    "fetch": re.compile(r"\b(?:fetch|http|network|stateless\s+api)\b", re.IGNORECASE),
    "window.fetch": re.compile(r"\b(?:fetch|http|network|stateless\s+api)\b", re.IGNORECASE),
    "globalthis.fetch": re.compile(r"\b(?:fetch|http|network|stateless\s+api)\b", re.IGNORECASE),
    "axios": re.compile(r"\b(?:axios|http|network|stateless\s+api)\b", re.IGNORECASE),
    "axios.get": re.compile(r"\b(?:axios|http|network|stateless\s+api)\b", re.IGNORECASE),
    "https.get": re.compile(r"\b(?:https?|network|http)\b", re.IGNORECASE),
    "http.get": re.compile(r"\b(?:https?|network|http)\b", re.IGNORECASE),
    "download": re.compile(r"\b(?:download|network|http)\b", re.IGNORECASE),
    "readfile": re.compile(r"\b(?:fs(?:\.promises)?|read-only\s+i/o|readfile)\b", re.IGNORECASE),
    "read_file": re.compile(r"\b(?:fs(?:\.promises)?|read-only\s+i/o|readfile)\b", re.IGNORECASE),
    "fs.readfile": re.compile(r"\b(?:fs(?:\.promises)?|read-only\s+i/o|readfile)\b", re.IGNORECASE),
    "fs.promises.readfile": re.compile(r"\b(?:fs(?:\.promises)?|read-only\s+i/o|readfile)\b", re.IGNORECASE),
    "fspromises.readfile": re.compile(r"\b(?:fs(?:\.promises)?|read-only\s+i/o|readfile)\b", re.IGNORECASE),
}


_API_DIRECT_PATTERNS = {
    "fetch": re.compile(r"\b(?:fetch|window\.fetch|globalthis\.fetch)\b(?:\s+backend|\s+runtime|\s+library)?\s+(?:is\s+(?:proven\s+)?reentrant|is\s+thread[- ]safe|supports?\s+(?:concurrent|concurrency|overlap)|tolerates?\s+overlap)\b", re.IGNORECASE),
    "window.fetch": re.compile(r"\b(?:fetch|window\.fetch|globalthis\.fetch)\b(?:\s+backend|\s+runtime|\s+library)?\s+(?:is\s+(?:proven\s+)?reentrant|is\s+thread[- ]safe|supports?\s+(?:concurrent|concurrency|overlap)|tolerates?\s+overlap)\b", re.IGNORECASE),
    "globalthis.fetch": re.compile(r"\b(?:fetch|window\.fetch|globalthis\.fetch)\b(?:\s+backend|\s+runtime|\s+library)?\s+(?:is\s+(?:proven\s+)?reentrant|is\s+thread[- ]safe|supports?\s+(?:concurrent|concurrency|overlap)|tolerates?\s+overlap)\b", re.IGNORECASE),
    "axios": re.compile(r"\baxios\b(?:\s+backend|\s+runtime|\s+library)?\s+(?:is\s+(?:proven\s+)?reentrant|is\s+thread[- ]safe|supports?\s+(?:concurrent|concurrency|overlap)|tolerates?\s+overlap)\b", re.IGNORECASE),
    "axios.get": re.compile(r"\baxios(?:\.get)?\b(?:\s+backend|\s+runtime|\s+library)?\s+(?:is\s+(?:proven\s+)?reentrant|is\s+thread[- ]safe|supports?\s+(?:concurrent|concurrency|overlap)|tolerates?\s+overlap)\b", re.IGNORECASE),
    "https.get": re.compile(r"\bhttps?\b(?:\s+backend|\s+runtime|\s+library)?\s+(?:is\s+(?:proven\s+)?reentrant|is\s+thread[- ]safe|supports?\s+(?:concurrent|concurrency|overlap)|tolerates?\s+overlap)\b", re.IGNORECASE),
    "http.get": re.compile(r"\bhttps?\b(?:\s+backend|\s+runtime|\s+library)?\s+(?:is\s+(?:proven\s+)?reentrant|is\s+thread[- ]safe|supports?\s+(?:concurrent|concurrency|overlap)|tolerates?\s+overlap)\b", re.IGNORECASE),
    "download": re.compile(r"\bdownload\b(?:\s+backend|\s+runtime|\s+library)?\s+(?:is\s+(?:proven\s+)?reentrant|is\s+thread[- ]safe|supports?\s+(?:concurrent|concurrency|overlap)|tolerates?\s+overlap)\b", re.IGNORECASE),
    "readfile": re.compile(r"\b(?:fs(?:\.promises)?|read-only\s+i/o|readfile)\b(?:\s+backend|\s+runtime|\s+library)?\s+(?:is\s+(?:proven\s+)?reentrant|is\s+thread[- ]safe|supports?\s+(?:concurrent|concurrency|overlap)|tolerates?\s+overlap)\b", re.IGNORECASE),
    "read_file": re.compile(r"\b(?:fs(?:\.promises)?|read-only\s+i/o|readfile)\b(?:\s+backend|\s+runtime|\s+library)?\s+(?:is\s+(?:proven\s+)?reentrant|is\s+thread[- ]safe|supports?\s+(?:concurrent|concurrency|overlap)|tolerates?\s+overlap)\b", re.IGNORECASE),
    "fs.readfile": re.compile(r"\b(?:fs(?:\.promises)?|read-only\s+i/o|readfile)\b(?:\s+backend|\s+runtime|\s+library)?\s+(?:is\s+(?:proven\s+)?reentrant|is\s+thread[- ]safe|supports?\s+(?:concurrent|concurrency|overlap)|tolerates?\s+overlap)\b", re.IGNORECASE),
    "fs.promises.readfile": re.compile(r"\b(?:fs(?:\.promises)?|read-only\s+i/o|readfile)\b(?:\s+backend|\s+runtime|\s+library)?\s+(?:is\s+(?:proven\s+)?reentrant|is\s+thread[- ]safe|supports?\s+(?:concurrent|concurrency|overlap)|tolerates?\s+overlap)\b", re.IGNORECASE),
    "fspromises.readfile": re.compile(r"\b(?:fs(?:\.promises)?|read-only\s+i/o|readfile)\b(?:\s+backend|\s+runtime|\s+library)?\s+(?:is\s+(?:proven\s+)?reentrant|is\s+thread[- ]safe|supports?\s+(?:concurrent|concurrency|overlap)|tolerates?\s+overlap)\b", re.IGNORECASE),
}


def _is_stateless_call(call: str) -> bool:
    """Check if an invoked identifier is an exact recognized stateless I/O API."""
    c = call.lower().replace("?.", ".").strip()
    return c in _RECOGNIZED_STATELESS_CALLS


_CONCURRENCY_WRAPPERS = {
    "promise.all", "all", "promise.allsettled", "allsettled", "promise.race", "race",
    "promise.any", "any", "asyncio.gather", "gather", "map", "foreach", "for_each"
}


def _is_concurrency_wrapper(call: str) -> bool:
    """Check if an invoked identifier is an iteration / concurrency wrapper (map, Promise.all)."""
    c = call.lower().replace("?.", ".").strip()
    return c in _CONCURRENCY_WRAPPERS or ("." in c and c.split(".")[-1] in _CONCURRENCY_WRAPPERS)


_STRING_OR_COMMENT_PATTERN = re.compile(
    r'(\"(?:\\.|[^"\\])*\"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`)'
    r'|(/\*[\s\S]*?\*/|//[^\n]*)'
)


def _strip_comments_safely(code: str) -> str:
    """Strip // and /* */ comments without truncating string literals containing '//'."""
    if not code:
        return ""

    def _repl(m: re.Match) -> str:
        if m.group(1):
            return m.group(1)
        return " "

    return _STRING_OR_COMMENT_PATTERN.sub(_repl, code)


_COMPUTED_OR_INDIRECT_CALL = re.compile(r"\]\s*(?:\?\.)?\s*\(|\)\s*(?:\?\.)?\s*\(")


def _extract_invoked_calls(code: str) -> Optional[Set[str]]:
    """Extract function/method identifiers invoked in executable code (ignoring comments).

    Returns None if the code contains un-inspectable call syntax (e.g. computed
    invocation like obj[fn]() or chained calls like getFn()()), indicating that
    the caller must fail closed.
    """
    if not code:
        return set()
    clean = _strip_comments_safely(code)
    # Fail closed on computed invocations or chained invocation syntax
    if _COMPUTED_OR_INDIRECT_CALL.search(clean):
        return None

    calls: Set[str] = set()
    for m in re.finditer(r"\b([A-Za-z0-9_$.]+(?:\?\.[A-Za-z0-9_$]+)*)\s*(?:\?\.)?\s*\(", clean):
        func = m.group(1).lower()
        calls.add(func)
    # Also extract callback arguments like map(readFile) or map(fetch)
    for m in re.finditer(r"\bmap\s*(?:\?\.)?\s*\(\s*([A-Za-z0-9_$.]+(?:\?\.[A-Za-z0-9_$]+)*)\s*\)", clean):
        cb = m.group(1).lower()
        calls.add(cb)
    return calls


def _extract_awaited_calls(code: str) -> Optional[Set[str]]:
    """Extract function/method identifiers directly awaited in executable code (ignoring comments).

    Returns None if the code contains un-inspectable call syntax.
    """
    if not code:
        return set()
    clean = _strip_comments_safely(code)
    if _COMPUTED_OR_INDIRECT_CALL.search(clean):
        return None

    calls: Set[str] = set()
    for m in re.finditer(r"\bawait\s+([A-Za-z0-9_$.]+(?:\?\.[A-Za-z0-9_$]+)*)\s*(?:\?\.)?\s*\(", clean):
        func = m.group(1).lower()
        calls.add(func)
    return calls


def has_proven_backend_evidence(finding: Dict[str, Any]) -> bool:
    """Return True only if finding cites proven positive evidence tied to the operation being patched.

    If the finding involves non-reentrant domains (model inference, WASM, sessions, GPU, mutexes,
    database transactions) or the awaited operation and proposed patch do not match the evidenced
    stateless backend, it cannot qualify as proven evidence, and automated patches must be
    withheld (agents-vorw / hub fleet-4inv).
    """
    if not isinstance(finding, dict):
        return False

    remediation = str(finding.get("remediation", "")).strip()
    if not remediation:
        return False

    # Any mention of non-reentrant or stateful domains disqualifies unconditional evidence
    full_context = " ".join([
        str(finding.get("title", "")),
        str(finding.get("description", "")),
        remediation,
        str(finding.get("snippet", "")),
    ])
    if _NON_REENTRANT_SUSPECT_PATTERN.search(full_context):
        return False

    has_negation = bool(_NEGATION_PATTERN.search(remediation))
    if has_negation or re.search(r"\b(?:if|whether|assuming)\b", remediation, re.IGNORECASE):
        return False

    # Remediation must name a reentrant backend and cite evidence
    if not (_NAMED_BACKEND_PATTERN.search(remediation) and _POSITIVE_EVIDENCE_PATTERN.search(remediation)):
        return False

    # Every awaited operation in the snippet must be an inherently stateless I/O call
    # matching the evidenced backend family (Reviewer P1).
    # An empty snippet lacks operation evidence and cannot prove backend reentrancy safety.
    snippet = str(finding.get("snippet", "")).strip()
    if not snippet:
        return False
    awaited_calls = _extract_awaited_calls(snippet)
    if awaited_calls is None or not awaited_calls or any(not _is_stateless_call(c) for c in awaited_calls):
        return False

    # Each awaited operation must have its own positive evidence clause in remediation.
    # The evidence clause must directly cite the specific awaited API (Reviewer P1).
    clauses = [c.strip() for c in re.split(r"(?:\.\s+|;\s*|\n+)", remediation) if c.strip()]
    for call in awaited_calls:
        direct_pat = _API_DIRECT_PATTERNS.get(call)
        if not direct_pat:
            return False
        has_clause_evidence = False
        for clause in clauses:
            if _NEGATION_PATTERN.search(clause) or re.search(r"\b(?:if|whether|assuming)\b", clause, re.IGNORECASE):
                continue
            if direct_pat.search(clause):
                has_clause_evidence = True
                break
        if not has_clause_evidence:
            return False

    # If proposed_fix_diff is present, every parallelized call inside it must also be stateless I/O
    diff = str(finding.get("proposed_fix_diff", ""))
    if diff:
        added_lines = "\n".join(line[1:] for line in diff.splitlines() if line.startswith("+") and not line.startswith("+++"))
        extracted = _extract_invoked_calls(added_lines)
        if extracted is None:
            return False
        diff_calls = {c for c in extracted if not _is_concurrency_wrapper(c)}
        if not diff_calls or any(not _is_stateless_call(c) for c in diff_calls):
            return False

    return True


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

    # Case 1: Structured conditional advice with serial fallback on non-reentrant branch (Reviewer P1).
    # The condition must govern every concurrency recommendation in remediation (no unconditioned prefix/suffix),
    # and the fallback branch must preserve serial execution without advocating concurrency.
    match = _STRUCTURED_PRECONDITION_PATTERN.search(remediation)
    if match:
        prefix = remediation[:match.start()]
        suffix = remediation[match.end():]
        if not _EXECUTION_CONCURRENCY_PATTERN.search(prefix) and not _EXECUTION_CONCURRENCY_PATTERN.search(suffix):
            otherwise_parts = re.split(r"\b(?:otherwise|else)\b", match.group(0), flags=re.IGNORECASE)
            if len(otherwise_parts) >= 2:
                fallback_branch = otherwise_parts[-1]
                if not _EXECUTION_CONCURRENCY_PATTERN.search(fallback_branch):
                    return True

    # Case 2: Named backend citing proven evidence of overlap tolerance
    if has_proven_backend_evidence(finding):
        return True

    return False


def guard_concurrency_finding(finding: Dict[str, Any], index: int) -> Optional[str]:
    """Ensure a concurrency recommendation carries its reentrancy precondition
    and withholds automated code patches.

    1. If the remediation does not carry an explicit reentrancy precondition with serial fallback
       (or proven backend evidence), wrap it with the explicit precondition.
    2. ALWAYS withhold proposed_fix_diff: automated tools (like pr-fixer) must never blindly
       apply concurrency patches (Promise.all / asyncio.gather) without verified runtime
       reentrancy and binding proof in the target codebase (agents-vorw / hub fleet-4inv).
    """
    if not is_concurrency_recommendation(finding):
        return None

    modified = False

    # 1. Enforce precondition on remediation if not already preconditioned
    if not has_reentrancy_precondition(finding):
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
        modified = True

    # 2. ALWAYS withhold proposed_fix_diff for concurrency recommendations
    if "proposed_fix_diff" in finding:
        diff = finding.pop("proposed_fix_diff", None)
        if diff:
            if "(Code patch withheld" not in finding.get("remediation", ""):
                finding["remediation"] = (
                    finding.get("remediation", "").rstrip()
                    + " (Code patch withheld; automated concurrency patches must not be applied without manual verification of runtime reentrancy)."
                )
            modified = True

    if modified:
        return f"findings[{index}]: enforced reentrancy precondition on concurrency recommendation"
    return None


def unpreconditioned_concurrency_findings(report: Any) -> List[str]:
    """Check if any finding makes an unchecked concurrency recommendation without a precondition
    or provides an unverified proposed_fix_diff."""
    violations: List[str] = []
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        return violations
    for i, item in enumerate(report["findings"]):
        if not isinstance(item, dict):
            continue
        if is_concurrency_recommendation(item):
            if not has_reentrancy_precondition(item):
                violations.append(
                    f"$.findings[{i}]: concurrency recommendation (rule {item.get('rule_id', 'unknown')!r}) "
                    "must cite backend evidence that it tolerates overlap or state its reentrancy precondition "
                    "('IF this runtime is reentrant... otherwise preserve serial execution')"
                )
            if item.get("proposed_fix_diff"):
                violations.append(
                    f"$.findings[{i}]: proposed_fix_diff for concurrency recommendation must be withheld "
                    "until runtime reentrancy and bindings are verified"
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
