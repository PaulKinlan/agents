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

# Bands that must never reach a public tracker (AGENTS.md disclosure rule).
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


def effective_severity(finding: Dict[str, Any]) -> str:
    """The severity this finding is treated as having at a publication boundary.

    Security-sensitive agents are critical on identity, so a model that labels a leaked key —
    or an understated vulnerability — `low` cannot authorise its publication.
    """
    agent = finding.get("agent")
    if isinstance(agent, str) and agent.strip() in IDENTITY_CRITICAL_AGENTS:
        return "critical"
    return normalize_severity(finding.get("severity"))


def embargo_reason(finding: Dict[str, Any], sink: str, visibility: Any = "public") -> Optional[str]:
    """Why this finding must not go to `sink`, or None when it may.

    Fail-closed by default: `file` is the local evidence trail and is never embargoed; every
    other sink — known, or one added later — is treated as a publication boundary. Visibility
    is read first: only a target that explicitly declares `private` may publish the embargoed
    bands to its own tracker. A missing or unrecognised value is treated as public (SF-09).
    """
    if sink in PRIVATE_SINKS:
        return None
    if normalize_visibility(visibility) == "private":
        return None
    severity = effective_severity(finding)
    if severity in EMBARGOED_SEVERITIES:
        return f"{severity} severity is embargoed from the {sink} tracker on a public target"
    return None
