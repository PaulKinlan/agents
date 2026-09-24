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

# Fields whose text is copied from model output or scanner output and can therefore carry
# a credential. Identity and bookkeeping fields are deliberately absent.
PUBLISHED_TEXT_FIELDS = ("title", "description", "remediation", "snippet", "path")

# Fields on a scanner candidate that hold the matched value.
CANDIDATE_MATCH_FIELDS = ("snippet", "raw_match")


def mask_text(value: Any) -> Any:
    """Mask anything credential-shaped in `value`. Non-strings pass through untouched."""
    if not isinstance(value, str):
        return value
    masked = value
    for name, pattern in PATTERNS:
        masked = pattern.sub(f"[redacted:{name}]", masked)
    return masked


def is_credential_finding(finding: Dict[str, Any]) -> bool:
    """True when this finding's matched text is a credential by construction."""
    if str(finding.get("agent") or "") in CREDENTIAL_AGENTS:
        return True
    rule_id = str(finding.get("rule_id") or "").lower()
    return any(hint in rule_id for hint in CREDENTIAL_RULE_HINTS)


def redact_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Return a publishable copy of `finding` with credential-bearing text masked.

    A copy, because the caller persists delivery receipts and keeps the raw local record.
    """
    published = dict(finding)
    agent = str(finding.get("agent") or "")

    if is_credential_finding(finding):
        # Default-deny: the whole value goes, not just recognised patterns.
        published["snippet"] = (
            f"[redacted:{agent or 'credential'} match at {mask_text(finding.get('path'))}:"
            f"{finding.get('line_number', '?')}]"
        )
    else:
        published["snippet"] = mask_text(finding.get("snippet"))

    for field in PUBLISHED_TEXT_FIELDS:
        if field == "snippet" or field not in published:
            continue
        published[field] = mask_text(published[field])

    if "raw_match" in published:
        published["raw_match"] = (
            "[redacted]" if is_credential_finding(finding) else mask_text(published["raw_match"])
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
