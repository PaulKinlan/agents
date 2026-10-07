#!/usr/bin/env python3
"""Publication embargo: may this finding leave the machine at all?

`lib/redaction.py` removes the *value* from text that is published. This module makes the
separate, earlier decision: whether a finding is routed to a tracker. Every tracker sink is
reached through `findings.dispatch_to_sink`, which calls `embargo_reason` once per run, so a
new sink cannot silently omit the check (agents-681).

The decision never treats a model's self-report as authority (agents-94f):

- A missing, non-text or unrecognised severity fails closed to `critical`. The old default
  was `medium` — exactly the band the public sinks publish, so an absent field authorised
  publication.
- `CREDENTIAL_AGENTS` are credential-class by construction: a scanner candidate *is* a
  credential whatever the triage model called it, so they are critical on identity, a
  deterministic fact. The same identity rule covers the vulnerability agents (vuln-discovery,
  vuln-verify, vuln-triage, threat-model): their candidates are attack surfaces, and a model
  that understates one does not authorise its publication.

The embargo is a routing decision, not deletion. The raw value and the model's own notes stay
in the local run artifact and findings store, where a human needs them to rotate the secret.
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

# Targets declare their repository visibility in targets/*.yaml. The disclosure rule is about
# *public* trackers, so visibility is the first input to the routing decision: a public target
# gets the severity embargo, a private target's own tracker is not a public disclosure.
# Anything else — missing, misspelled, unknown — fails closed to public (SF-09, agents-5rx).
VALID_VISIBILITIES = ("public", "private")


def normalize_visibility(value: Any) -> str:
    """Coerce a target's declared visibility, failing closed to public."""
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


def is_false_positive(finding: Dict[str, Any]) -> bool:
    """Whether the triage that produced `finding` declared it a false positive.

    Explicit fields win (`false_positive: true`, or a verdict-like field naming one); failing
    that, a title that says the item *is* a false positive ("... is a false positive (comment,
    not a network call)") counts, while "not a false positive" does not.
    """
    if not isinstance(finding, dict):
        return False
    flag = finding.get("false_positive")
    if flag is True or (isinstance(flag, str) and flag.strip().lower() in ("true", "yes")):
        return True
    for field in _VERDICT_FIELDS:
        value = finding.get(field)
        if isinstance(value, str) and value.strip().lower() in _FALSE_POSITIVE_VERDICTS:
            return True
    title = finding.get("title")
    return isinstance(title, str) and bool(_FP_TITLE.search(title))


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

    Security-sensitive agents are critical on identity, so a model that labels a leaked key —
    or an understated vulnerability — `low` cannot authorise its publication.
    """
    agent = finding.get("agent")
    if isinstance(agent, str) and agent.strip() in IDENTITY_CRITICAL_AGENTS:
        return "critical"
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
