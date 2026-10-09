#!/usr/bin/env python3
"""Finding severity, visibility normalization and legacy fail-closed embargo.

`reported_severity` preserves the triaged label; `effective_severity` treats unknown labels
and credential/vulnerability-agent identity as critical for routing. `embargo_reason` withholds
high/critical when visibility is missing or invalid: the synced beads tracker is a shared
surface, so missing visibility must not silently file a high/critical bead. `dispatch_to_sink`
(lib/findings.py) and the beads adapter (lib/sinks/beads.py) apply the embargo; public GitHub issues
are no longer a finding sink (agents-eyo) — public input is triaged separately, and `promote_issue` is the
explicit, human-approved issue -> bead link. `lib/redaction.py` masks published values; raw
evidence stays in the local store/artifacts.
"""

import re
from typing import Any, Dict, Optional

try:  # imported as lib.embargo, or run with lib/ on sys.path
    from lib.redaction import CREDENTIAL_AGENTS
except ImportError:  # pragma: no cover - the CLI's sys.path fallback covers this layout
    from redaction import CREDENTIAL_AGENTS

# Agents whose findings are security-sensitive by construction: a credential scanner's candidate
# *is* a credential, and a vulnerability agent's candidate *is* an attack surface. The triage
# model can mislabel, omit or understate a severity — identity cannot. Any finding from one of
# these is critical for routing, whatever the model's label says (SF-03).
IDENTITY_CRITICAL_AGENTS = CREDENTIAL_AGENTS | frozenset({
    "vuln-discovery",
    "vuln-verify",
    "vuln-triage",
    "threat-model",
})

# The accepted severity vocabulary. Anything outside it is not a severity.
VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")

# Legacy fail-closed bands when visibility is missing or invalid. A target explicitly
# declaring visibility: public authorises publication of these bands too (agents-559).
EMBARGOED_SEVERITIES = frozenset({"critical", "high"})

# The evidence trail a human reads: never subject to this routing decision. Values in it are
# still rendered through lib/redaction.py before any surface publishes it (see the factory
# action's step summary). Any other sink, including one added later, is a publication.
PRIVATE_SINKS = frozenset({"file"})

# normalize_visibility is for the run banner and unsandboxed trusted-target checks in
# factory. It does NOT prove an explicit public declaration: publication checks the raw
# manifest value separately. Missing/invalid values remain conservative (SF-09).
VALID_VISIBILITIES = ("public", "private")


def normalize_visibility(value: Any) -> str:
    """Coerce visibility for reporting; do not use this as publication authority."""
    if isinstance(value, str) and value.strip().lower() in VALID_VISIBILITIES:
        return value.strip().lower()
    return "public"


def normalize_severity(value: Any) -> str:
    """Coerce a model-supplied severity to the enum, failing closed.

    Missing, non-text and unrecognised values become `critical`, never `medium`.
    """
    if isinstance(value, str):
        severity = value.strip().lower()
        if severity in VALID_SEVERITIES:
            return severity
    return "critical"


# A severity label that is missing or outside the vocabulary is *reported* as this. It is not a
# routing value: the embargo below still treats it as critical (fail closed). Reporting it as
# critical made every unlabelled finding read CRITICAL in the store and the delta report while
# the line's andon counted only the model's genuine criticals (journal-1kg, journal-y5m).
UNCLASSIFIED = "unclassified"

# Triage verdicts that mean "this candidate is not a real issue". A finding the triage itself
# declares a false positive must never be counted, badged or published as a live finding
# (journal-35w, journal-aaj).
_FALSE_POSITIVE_VERDICTS = frozenset({
    "false_positive", "false-positive", "false positive", "fp", "not_an_issue",
    "not-an-issue", "benign", "not_exploitable", "not-exploitable",
})
_VERDICT_FIELDS = ("verdict", "triage_verdict", "triage", "disposition", "classification", "status")
_FP_TITLE = re.compile(r"(?<!not a )(?<!not )(?<!no )\bfalse[- ]positive\b", re.IGNORECASE)

# Obvious dummy/placeholder credential markers (agents-3r7). A candidate whose snippet or raw
# match carries one of these is a test fixture or example, not a live credential: every marker
# is a word or sequence a real key never contains (a real key is random base-58/62, never
# "placeholder", "do-not-leak", a sequential digit run, or the alphabet in order). They are
# deliberately narrow so real-key detection is never weakened — a genuine leaked key that
# happens to sit in a test file still matches none of them.
_DUMMY_CREDENTIAL_MARKERS = (
    re.compile(r"placeholder", re.IGNORECASE),
    re.compile(r"do[ _-]?not[ _-]?leak", re.IGNORECASE),
    re.compile(r"dont[ _-]?leak", re.IGNORECASE),
    re.compile(r"not[ _-]?real", re.IGNORECASE),
    re.compile(r"secret[ _-]?token", re.IGNORECASE),
    re.compile(r"your[ _-]?api[ _-]?key", re.IGNORECASE),
    re.compile(r"\bsk-test-", re.IGNORECASE),
    re.compile(r"(?:0123456789|1234567890|9876543210)"),
    re.compile(r"abcdefghijklmnop", re.IGNORECASE),
)

# Refusal and containment guard patterns (agents-5gg). A code block or snippet that raises an error
# or explicitly refuses an insecure operation (e.g. `raise ContainmentError(...)`) is an
# enforcement guard preventing an insecure mode, not an unguarded invocation.
_REFUSAL_GUARD_PATTERNS = (
    re.compile(r"\braise\s+(?:ContainmentError|StationError|PermissionError|SecurityError)\b"),
    re.compile(r"""(?:refusing\s+on\s+target|credentials?\s+(?:are|is)\s+never\s+brokered)""", re.IGNORECASE),
    re.compile(r"""(?:if|elif)\s+.*(?:not\s+\(?trusted|normalize_visibility).*:\s*raise\b"""),
)

_ACCEPTED_RISK_TITLE = re.compile(
    r"\b(?:accepted\s+(?:residual\s+)?risk|intentional\s+exclusion|by[- ]design)\b",
    re.IGNORECASE,
)


def is_refusal_guard_snippet(snippet: Any) -> bool:
    """True when snippet represents a refusal, denial, or containment enforcement guard (agents-5gg).

    A guard that checks preconditions and raises an error or refuses execution
    is an enforcement mechanism preventing an insecure mode, not an unguarded invocation.
    """
    if not isinstance(snippet, str):
        return False
    text = snippet.strip()
    if not text:
        return False
    return any(p.search(text) for p in _REFUSAL_GUARD_PATTERNS)


def match_unbrokered_claude_invocation(code: str) -> bool:
    """Rule for unbrokered claude engine credentials (agents-5gg).

    Requires positive evidence of an actual unguarded claude invocation.
    Denial and refusal paths (e.g. raising ContainmentError, checking trusted+private)
    must NOT trigger this rule.
    """
    if not isinstance(code, str):
        return False
    # Denial and refusal branches must NOT fire (negative case)
    if is_refusal_guard_snippet(code):
        return False
    if "raise ContainmentError" in code or "refusing" in code:
        return False
    # Positive case: invocation of claude without the trusted-private containment guard
    claude_invocation = bool(re.search(
        r"""(?:engine\s*==\s*['"]claude['"]|['"]claude['"]\s*in\s*engine|adapters/claude\.sh)""",
        code
    ))
    has_guard = bool(re.search(r"""(?:trusted.*private|normalize_visibility)""", code))
    return claude_invocation and not has_guard


def is_self_referential_artifact(path: Any, snippet: Any = "") -> bool:
    """True when path or snippet references the threat-model station's own output artifact (agents-5gg).

    The threat-model station writes `findings/<target>-THREAT_MODEL.md` as an intended local
    evidence store; flagging its creation or existence is self-referential noise.
    """
    path_str = str(path or "")
    if re.search(r"""(?:^|[/\\])findings[/\\][^/\\]+-THREAT_MODEL\.md$""", path_str):
        return True
    snippet_str = str(snippet or "")
    if re.search(r"""findings[/\\][^/\\]+-THREAT_MODEL\.md""", snippet_str):
        return True
    if "tm_findings_file.write_text" in snippet_str:
        return True
    return False


def _dummy_credential_marker(finding: Dict[str, Any]) -> bool:
    """True when the finding's raw matched value reads as an obvious dummy credential.

    Only the scanner's raw match (the exact matched token) is inspected, never the surrounding
    code line: the markers can otherwise match a variable name (``secret_token``), a comment
    (``// do not leak``) or a type annotation (``<Token>``) on a line whose key is real
    (agents-3r7 review). A finding with no raw match therefore never fires this deterministic
    path — the model's own false-positive verdict still does for ordinary agents.
    """
    value = finding.get("raw_match")
    if not isinstance(value, str):
        return False
    text = value.strip()
    return bool(text) and any(marker.search(text) for marker in _DUMMY_CREDENTIAL_MARKERS)


def _is_identity_critical(finding: Dict[str, Any]) -> bool:
    agent = finding.get("agent")
    return isinstance(agent, str) and agent.strip() in IDENTITY_CRITICAL_AGENTS


def is_false_positive(finding: Dict[str, Any]) -> bool:
    """Whether `finding` is a false positive for REPORTING (store, badge, delta section).

    The deterministic dummy marker always counts; so does the triage's own verdict and a title
    that names a false positive. This is the human-readable truth, NOT the routing decision:
    `effective_severity` still routes an identity-critical agent's real key as critical even
    when the model calls it a false positive (SF-03, agents-3r7).
    """
    if not isinstance(finding, dict):
        return False
    if _dummy_credential_marker(finding):
        return True
    # agents-5gg: refusal/denial guards and self-referential station artifacts are false positives
    if is_refusal_guard_snippet(finding.get("snippet")):
        return True
    if is_self_referential_artifact(finding.get("path"), finding.get("snippet")):
        return True
    title = finding.get("title")
    if isinstance(title, str) and (_FP_TITLE.search(title) or _ACCEPTED_RISK_TITLE.search(title)):
        return True
    flag = finding.get("false_positive")
    if flag is True or (isinstance(flag, str) and flag.strip().lower() in ("true", "yes")):
        return True
    for field in _VERDICT_FIELDS:
        value = finding.get(field)
        if isinstance(value, str) and value.strip().lower() in _FALSE_POSITIVE_VERDICTS:
            return True
    return False


def reported_severity(finding: Dict[str, Any]) -> str:
    """The severity a human reads and every count uses: the triaged label, never inflated.

    One source for the findings store, the delta report and the line's andon/scorecard
    (journal-y5m). A missing or unrecognised label is `unclassified` — not critical, because
    an unanalysed finding is not evidence of a critical one — and a triaged false positive is
    `info`. Publication routing does NOT use this: see `effective_severity`.
    """
    if is_false_positive(finding):
        return "info"
    value = finding.get("severity") if isinstance(finding, dict) else None
    if isinstance(value, str) and value.strip().lower() in VALID_SEVERITIES:
        return value.strip().lower()
    return UNCLASSIFIED


def effective_severity(finding: Dict[str, Any]) -> str:
    """The severity this finding is treated as having at a publication boundary (routing only).

    This is deliberately NOT what the store, the report badge or the andon count: it is the
    fail-closed routing value. Displaying it made identity-critical agents' info-level and
    false-positive verdicts read CRITICAL (journal-1kg, journal-aaj).

    A deterministic dummy credential (a placeholder body, not a key at all) routes `info`.
    Otherwise a security-sensitive agent is critical on identity — a model that labels a real
    leaked key `low`, `info`, or even `false positive` cannot authorise its publication
    (SF-03, agents-3r7). Ordinary agents keep their normalised label; their triaged false
    positives route `info`.
    """
    if _dummy_credential_marker(finding):
        return "info"
    if _is_identity_critical(finding):
        return "critical"
    if is_false_positive(finding):
        return "info"
    return normalize_severity(finding.get("severity"))


def embargo_reason(finding: Dict[str, Any], sink: str, visibility: Any = None) -> Optional[str]:
    """Why this finding must not go to `sink`, or None when it may.

    Fail-closed by default: `file` is local evidence. An explicitly declared `public`
    authorises public disclosure of every genuine finding, including high/critical, per
    the project's public-issue policy. An explicitly declared `private` is still subject
    to the issue publisher's separate public-repository check. Missing/invalid visibility
    never silently authorises high/critical disclosure (SF-09).
    """
    if sink in PRIVATE_SINKS:
        return None
    if visibility in VALID_VISIBILITIES:
        return None
    severity = effective_severity(finding)
    if severity in EMBARGOED_SEVERITIES:
        return f"{severity} severity is embargoed from the {sink} tracker on a public target"
    return None
