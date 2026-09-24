#!/usr/bin/env python3
"""Structural redaction for everything the factory publishes.

A finding's `snippet` is whatever the deterministic scanner matched — for `secret-scan`
that is the credential itself. Those values leave this machine in three directions:
the local delta report (which the composite action appends to a public step summary),
tracker sinks (beads / GitHub Issues), and scanner stdout.

The rule here is structural, never a prompt. Non-negotiable #2: a model is not a
containment boundary, so nothing relies on the triage model choosing not to repeat what
it was shown. Two layers:

1. `CREDENTIAL_AGENTS` are agents whose candidates are credentials by construction.
   Their snippets never leave as text at all — replaced wholesale with a location, so an
   unrecognised credential format cannot slip through either.
2. Every other published string is passed through `mask_text`, which masks anything
   shaped like a credential a model may have echoed into a title, description or
   remediation.

Raw values stay in the local, gitignored run artifacts and findings store: a human has to
be able to see what leaked in order to rotate it. Redaction applies at the publish
boundary, not at ingestion, so fingerprints and the lifecycle stay stable.
"""

import re
from typing import Any, Dict, List

# Agents whose candidate snippets are credentials by construction (see agents/*/SKILL.md).
CREDENTIAL_AGENTS = frozenset({"secret-scan"})

# Second, independent trigger: the scanner rule that matched. Either signal can be absent,
# so a finding is treated as credential-bearing when either one fires. Over-dropping a
# snippet is the safe failure — the rule, location, description and remediation still ship.
CREDENTIAL_RULE_HINTS = ("key", "secret", "token", "credential", "password", "private")

# Kept aligned with the scanner's own suite in agents/secret-scan/scripts/scan.py, so the
# factory masks exactly the shapes it claims to detect. Add a pattern in both places.
PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}")),
    ("github-pat", re.compile(r"ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}")),
    ("slack-token", re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*")),
    ("generic-api-key", re.compile(r"""(?i)(?:api_key|apikey|secret|token|password)\s*[:=]\s*['"][a-zA-Z0-9_\-]{20,80}['"]""")),
    ("jwt-token", re.compile(r"ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
]

# A value does not only leak through the assignment the scanner matched: a triage model that has
# been shown a candidate can quote the value on its own in prose ('the key is sk-…'), which the
# assignment-shaped patterns above do not see. These match vendor prefixes anywhere in a string,
# and PEM blocks whole rather than only their header.
BARE_PATTERNS = [
    ("openai-key", re.compile(r"sk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{16,}")),
    ("stripe-key", re.compile(r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("google-oauth", re.compile(r"ya29\.[0-9A-Za-z_-]{20,}")),
    ("gitlab-pat", re.compile(r"glpat-[A-Za-z0-9_-]{20,}")),
    ("npm-token", re.compile(r"npm_[A-Za-z0-9]{36}")),
]

# Whole-block shapes must run before any pattern that matches only their header, or the header is
# replaced first and the body can no longer be recognised (agents-tcd re-review).
BLOCK_PATTERNS = [
    ("pem-block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
]

ALL_PATTERNS = BLOCK_PATTERNS + BARE_PATTERNS + PATTERNS

# Derived text for a credential finding: scanner-controlled facts only. The triage model's own
# words are never published for these, because they cannot be checked for an echo of a value
# whose shape is unknown. The local run artifact keeps the model's notes for the responder.
WITHHELD_NOTE = (
    "Published summaries withhold the matched value and the triage notes for credential "
    "findings; both remain in the local run artifact and findings store."
)
GENERIC_REMEDIATION = "Rotate the credential, remove it from source, and re-run the scan."

# Every field that is *rendered* into a published surface. Identity fields are in here on purpose:
# `path`, `rule_id` and `severity` reach this layer as model-returned strings — process_run does not
# bind them to scanner output — so a value can be smuggled through any of them, and the re-review
# proved it for `path` and `rule_id`. `state` and `change` are absent deliberately: they are
# store-controlled enums that dispatch filters on, not text that arrives with a finding.
RENDERED_TEXT_FIELDS = (
    "agent", "title", "description", "remediation", "snippet",
    "path", "rule_id", "severity", "suppression_reason", "line_number",
)

# Fields on a scanner candidate that hold the matched value.
CANDIDATE_MATCH_FIELDS = ("snippet", "raw_match")


# Identity fields (`agent`, `rule_id`, `path`) are rendered, and they reach this layer as
# strings the triage model returned — process_run does not bind them to scanner output — so a value
# can be smuggled through them. They are the only fields where the *shape* of a legitimate value is
# known, so they get a shape check as well as masking: a long opaque run is not a rule id or a
# path segment, and the field falls back to a placeholder rather than publishing it. Fail-closed,
# and cosmetic only — the raw value is still in the local run artifact.
IDENTITY_SHAPES = {
    "agent": (re.compile(r"[A-Za-z0-9_.-]{1,64}"), "unknown-agent"),
    "rule": (re.compile(r"[A-Za-z0-9_.:-]{1,64}"), "unclassified"),
    "path": (re.compile(r"[A-Za-z0-9_. /-]{1,200}"), "unknown"),
}
OPAQUE_RUN = re.compile(r"[A-Za-z0-9]{20,}")


def sanitise_identity(value: Any, kind: str) -> Any:
    """Return `value` if it looks like the identity field it claims to be, else a placeholder."""
    if not isinstance(value, str) or not value.strip():
        return value
    pattern, placeholder = IDENTITY_SHAPES[kind]
    if pattern.fullmatch(value) and not OPAQUE_RUN.search(value):
        return value
    return placeholder


def mask_text(value: Any) -> Any:
    """Mask anything credential-shaped in `value`. Non-strings pass through untouched."""
    if not isinstance(value, str):
        return value
    masked = value
    for name, pattern in ALL_PATTERNS:
        masked = pattern.sub(f"[redacted:{name}]", masked)
    return masked


def matched_literals(finding: Dict[str, Any]) -> set:
    """The values this finding's scanner actually matched.

    A model shown a candidate can quote the value on its own in prose ('the key is zkq…'), which
    no pattern sees because the assignment context is gone. So collect the value the scanner
    handed us, and — when a credential pattern matched somewhere in the same text — every
    token-shaped run in it, which is what a bare echo of that value looks like.
    """
    literals = set()
    texts = []
    for field in ("snippet", "raw_match"):
        value = finding.get(field)
        if isinstance(value, str) and value.strip():
            texts.append(value)
            if field == "raw_match":
                literals.add(value.strip())

    pattern_matched = False
    for value in texts:
        for _, pattern in ALL_PATTERNS:
            for match in pattern.findall(value):
                pattern_matched = True
                matched = match if isinstance(match, str) else "".join(match)
                literals.add(matched)
                # The value inside an assignment is a separate literal from the assignment.
                literals.update(re.findall(r"""['"]([^\s'"]{8,})['"]""", matched))

    if pattern_matched:
        for value in texts:
            literals.update(re.findall(r"[A-Za-z0-9_\-/+=]{16,}", value))
    else:
        # No known pattern matched, so this came from a scanner whose rules we do not share
        # (gitleaks). Its candidates hand us the value itself, so a short whitespace-free
        # snippet is the literal to mask wherever it is echoed.
        snippet = (finding.get("snippet") or "").strip()
        if 8 <= len(snippet) <= 200 and not re.search(r"\s", snippet):
            literals.add(snippet)

    return {literal for literal in literals if isinstance(literal, str) and len(literal) >= 8}


def mask_literals(value: Any, literals: set) -> Any:
    if not isinstance(value, str):
        return value
    masked = value
    for literal in sorted(literals, key=len, reverse=True):
        if literal in masked:
            masked = masked.replace(literal, "[redacted:value]")
    return masked


def is_credential_finding(finding: Dict[str, Any]) -> bool:
    """True when this finding's matched text is a credential by construction."""
    if str(finding.get("agent") or "") in CREDENTIAL_AGENTS:
        return True
    rule_id = str(finding.get("rule_id") or "").lower()
    return any(hint in rule_id for hint in CREDENTIAL_RULE_HINTS)


def redact_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Return a publishable copy of `finding` with credential-bearing text removed.

    A copy, because the caller persists delivery receipts and keeps the raw local record.

    Every rendered field is masked, identity fields included, and a credential finding
    (by agent or by rule id) publishes **derived text only**: its rule, location, severity
    and fingerprint. The triage model's own words are never published for those, because
    prose cannot be checked for an echo of a value whose shape is unknown; the value and
    the notes stay in the local run artifact for whoever has to rotate the credential.
    """
    published = dict(finding)
    agent = str(finding.get("agent") or "")
    literals = matched_literals(finding)
    credential = is_credential_finding(finding)

    # Untrusted text goes through both layers: known shapes, and the literal the scanner
    # matched wherever a model has re-quoted it. Non-strings (line numbers) pass through.
    for field in RENDERED_TEXT_FIELDS:
        if field in published:
            published[field] = mask_literals(mask_text(published[field]), literals)

    # Shape-check the fields whose legitimate form is known. After masking, so a recognised
    # shape is reported as masked rather than dropped.
    for field, kind in (("agent", "agent"), ("rule_id", "rule"), ("path", "path")):
        if field in published:
            published[field] = sanitise_identity(published[field], kind)

    # Derived text is built from the *masked* values, so it cannot reintroduce anything.
    location = f"{published.get('path')}:{published.get('line_number', '?')}"
    rule = published.get("rule_id") or "credential"

    if credential:
        published["snippet"] = f"[redacted:{agent or 'credential'} match at {location}]"
        published["title"] = f"{rule} match at {location}"
        published["description"] = (
            f"The deterministic scanner matched `{rule}` at `{location}`. {WITHHELD_NOTE}"
        )
        published["remediation"] = GENERIC_REMEDIATION

    if "raw_match" in published:
        published["raw_match"] = (
            "[redacted]" if credential else mask_literals(published["raw_match"], literals)
        )

    return published


def redact_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [redact_finding(f) for f in findings]


def stdout_safe_report(report: Any) -> Any:
    """Return a publishable copy of a scanner candidate report.

    Candidate match fields are dropped wholesale rather than pattern-masked: this output
    goes to a terminal or a CI log, which has no way to be un-published. The raw values
    remain in the file written by `--output`, which is the local record.
    """
    if isinstance(report, list):
        return [stdout_safe_report(item) for item in report]
    if not isinstance(report, dict):
        return report

    safe: Dict[str, Any] = {}
    for key, value in report.items():
        if key == "candidates" and isinstance(value, list):
            safe[key] = [stdout_safe_report(c) for c in value]
        elif key in CANDIDATE_MATCH_FIELDS:
            safe[key] = "[redacted]"
        elif isinstance(value, str):
            safe[key] = mask_text(value)
        else:
            safe[key] = value
    return safe
