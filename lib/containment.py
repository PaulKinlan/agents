#!/usr/bin/env python3
"""Containment: agent.yaml's `containment`, `capabilities` and `budget`, read and enforced.

Until this module nothing read those fields (audit SF-02, bead agents-pnu). The banner printed
`Containment: t0-readonly` while the engine ran with its full default tool set, as the
operator. A printed tier that nothing enforces is worse than no tier: it reads as an assurance.

What this module does:

* **Validates the declaration and fails closed.** An unknown tier, an unknown capability or
  budget key, a non-boolean capability, a malformed budget, or a capability above its tier's
  ceiling (docs/PLAN.md section 5) refuses the run. A declared field that nothing reads is the
  defect this bead is about, so an unread field is refused rather than ignored.
* **Refuses t3-sandbox.** No sandboxed runner exists, so there is nothing to run it in.
* **Grants the model session only what is enforceable today**: the `read-only` tool policy.
  The dispatcher hands it to the engine adapter, which turns it into the engine's own flags —
  a tool allowlist, and no project hooks, extensions, settings or MCP servers. The boundary is
  the harness's tool registry, never prompt text (non-negotiable #2).
* **Says plainly what is not enforced.** There is no OS sandbox: the engine process and the
  deterministic pre-pass run as the operator, with the operator's filesystem and network.

The tier is a ceiling on what an agent may declare. It is not a grant. Write, network and
browser are declared by some agents and granted to none, each for a stated reason
(WITHHELD_REASONS); lifting one needs the mechanism named in its reason, not a manifest edit.
"""

import math
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

# docs/PLAN.md section 5. The ceiling is what an agent at that tier may *declare*.
#   t0-readonly  no network, read-only checkout
#   t1-fetch     allowlisted network (registries, the tracker API), read-only
#   t2-local     localhost only, writable worktree. `network` here means off-host network,
#                so it stays False; a browser against a local preview is what t2 allows.
TIER_CEILINGS: Dict[str, Dict[str, bool]] = {
    "t0-readonly": {"write": False, "network": False, "browser": False},
    "t1-fetch": {"write": False, "network": True, "browser": False},
    "t2-local": {"write": True, "network": False, "browser": True},
}
REFUSED_TIERS = {
    "t3-sandbox": "t3-sandbox needs a gVisor/container runner with egress locked to the model "
                  "API and manual approval per run (docs/PLAN.md section 5); none exists, so "
                  "there is nothing to run it in",
}
# AGENTS.md: "Default to t0-readonly." An absent tier gets the strictest ceiling.
DEFAULT_TIER = "t0-readonly"

CAPABILITY_FLAGS = ("write", "network", "browser")
CAPABILITY_KEYS = frozenset(CAPABILITY_FLAGS + ("requires",))
BUDGET_KEYS = frozenset({"max_minutes", "max_usd"})

# Tool policies the factory can grant a model session, and which adapter enforces which.
# lib/adapters/<engine>.sh reads FACTORY_TOOL_POLICY and refuses anything it cannot enforce;
# tests/test_containment.py asserts the adapters and this table agree.
READ_ONLY = "read-only"
GRANTABLE_POLICIES = (READ_ONLY,)
ENGINE_TOOL_POLICIES: Dict[str, frozenset] = {
    "pi": frozenset({READ_ONLY}),
    "claude": frozenset({READ_ONLY}),
    # `agentapi new-conversation` takes a prompt and nothing else: no tool controls.
    "antigravity": frozenset(),
}

# How each adapter enforces read-only, and what that leaves open. Stated in the banner and in
# policy.json so the operator reads the enforcement, not an adjective.
ENGINE_ENFORCEMENT = {
    "pi": "pi --tools read,grep,find,ls --no-extensions --no-approve",
    "claude": "claude --restricted --tools Read,Grep,Glob --strict-mcp-config",
}
ENGINE_READ_SCOPE = {
    "pi": "NOT confined: pi's read tool reaches any file the operator can read",
    "claude": "confined to the target directory (claude --restricted)",
}

WITHHELD_REASONS = {
    "write": "no disposable worktree yet: the engine runs in the target's own checkout, so "
             "proposers return patches in their report instead of editing files",
    "network": "no egress allowlist yet, so a network tool cannot be held to the tier's hosts",
    "browser": "a browser is an unscoped network client and cannot yet be held to localhost",
}
SANDBOX_GAP = ("NOT enforced: the engine process and the pre-pass run as the operator, with "
               "the operator's filesystem and network")


class ContainmentError(RuntimeError):
    """The run is refused: a declaration the factory cannot honour, or an engine that cannot
    enforce the granted tool policy. Raised before any station work, so nothing is recorded as
    a clean scan. A RuntimeError, so `factory line` scores the station ERROR (agents-p2c)."""


@dataclass(frozen=True)
class Policy:
    agent: str
    tier: str
    tier_declared: bool
    declared: Dict[str, bool]
    requires: Tuple[str, ...]
    tool_policy: str
    withheld: Dict[str, str]
    max_minutes: Optional[float]
    max_usd: Optional[float]


def _positive_number(agent: str, field: str, value: Any) -> Optional[float]:
    """A declared budget value: absent is None; anything else must be a finite number > 0.

    Numeric strings are accepted because lib/budget.py accepts them; everything it would
    silently replace with its default is refused here, because a malformed declaration that
    runs under a different budget is a declaration nothing honoured.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        raise ContainmentError(f"{agent}: budget.{field} must be a number, not a boolean")
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ContainmentError(f"{agent}: budget.{field} must be a number, got {value!r}") from None
    if not math.isfinite(number) or number <= 0:
        raise ContainmentError(f"{agent}: budget.{field} must be a finite number above 0, got {value!r}")
    return number


def load_policy(agent: str, agent_cfg: Mapping[str, Any]) -> Policy:
    """Validate agent.yaml's containment fields and compute the session grant. Fails closed."""
    if not isinstance(agent_cfg, Mapping):
        raise ContainmentError(f"{agent}: agent.yaml is not a mapping")

    tier_value = agent_cfg.get("containment")
    tier_declared = tier_value is not None
    tier = DEFAULT_TIER if tier_value is None else tier_value
    if not isinstance(tier, str):
        raise ContainmentError(f"{agent}: containment must be a tier name, got {tier!r}")
    if tier in REFUSED_TIERS:
        raise ContainmentError(f"{agent}: {REFUSED_TIERS[tier]}")
    if tier not in TIER_CEILINGS:
        known = ", ".join(sorted(TIER_CEILINGS) + sorted(REFUSED_TIERS))
        raise ContainmentError(f"{agent}: unknown containment tier {tier!r} (known: {known})")
    ceiling = TIER_CEILINGS[tier]

    caps = agent_cfg.get("capabilities")
    caps = {} if caps is None else caps
    if not isinstance(caps, Mapping):
        raise ContainmentError(f"{agent}: capabilities must be a mapping")
    unknown = sorted(set(caps) - CAPABILITY_KEYS)
    if unknown:
        raise ContainmentError(
            f"{agent}: unknown capability {', '.join(unknown)} — nothing would enforce it "
            f"(known: {', '.join(sorted(CAPABILITY_KEYS))})")
    declared: Dict[str, bool] = {}
    for flag in CAPABILITY_FLAGS:
        value = caps.get(flag, False)
        if not isinstance(value, bool):
            raise ContainmentError(
                f"{agent}: capabilities.{flag} must be true or false, got {value!r}")
        if value and not ceiling[flag]:
            raise ContainmentError(
                f"{agent}: capabilities.{flag} exceeds the {tier} ceiling (docs/PLAN.md "
                f"section 5): declare a tier that allows it, or drop the capability")
        declared[flag] = value
    requires = caps.get("requires", [])
    requires = [] if requires is None else requires
    if not isinstance(requires, list) or not all(isinstance(r, str) and r for r in requires):
        raise ContainmentError(f"{agent}: capabilities.requires must be a list of tool names")

    budget = agent_cfg.get("budget")
    budget = {} if budget is None else budget
    if not isinstance(budget, Mapping):
        raise ContainmentError(f"{agent}: budget must be a mapping")
    unknown = sorted(set(budget) - BUDGET_KEYS)
    if unknown:
        raise ContainmentError(
            f"{agent}: unknown budget key {', '.join(unknown)} — nothing would enforce it "
            f"(known: {', '.join(sorted(BUDGET_KEYS))})")
    max_minutes = _positive_number(agent, "max_minutes", budget.get("max_minutes"))
    max_usd = _positive_number(agent, "max_usd", budget.get("max_usd"))

    # The grant. Nothing beyond read-only is enforceable yet, so every declared write,
    # network or browser capability is withheld, with the reason and the missing mechanism.
    withheld = {flag: WITHHELD_REASONS[flag] for flag in CAPABILITY_FLAGS if declared[flag]}
    return Policy(agent=agent, tier=tier, tier_declared=tier_declared, declared=declared,
                  requires=tuple(requires), tool_policy=READ_ONLY, withheld=withheld,
                  max_minutes=max_minutes, max_usd=max_usd)


def check_engine(policy: Policy, engine: str) -> None:
    """Refuse an engine whose adapter cannot enforce the policy's tool policy."""
    supported = ENGINE_TOOL_POLICIES.get(engine)
    capable = sorted(e for e, policies in ENGINE_TOOL_POLICIES.items() if policy.tool_policy in policies)
    alternatives = " or ".join(f"--engine {e}" for e in capable) or "no engine"
    if supported is None:
        raise ContainmentError(
            f"engine '{engine}' has no adapter known to enforce a tool policy; use {alternatives}")
    if policy.tool_policy not in supported:
        raise ContainmentError(
            f"engine '{engine}' cannot enforce the '{policy.tool_policy}' tool policy for "
            f"{policy.agent} — its adapter has no tool controls; use {alternatives}")


def banner_lines(policy: Policy, engine: str) -> List[str]:
    """The run banner's containment block: declared, enforced, withheld, not enforced."""
    tier_note = "declared" if policy.tier_declared else "not declared; strictest tier assumed"
    lines = [
        f"  Containment: {policy.tier} ({tier_note}) — a ceiling on capabilities, validated",
        f"  Tool policy: {policy.tool_policy}, enforced by the {engine} adapter: "
        f"{ENGINE_ENFORCEMENT.get(engine, 'unknown')}",
        f"  Read scope:  {ENGINE_READ_SCOPE.get(engine, 'unknown')}",
    ]
    for flag, reason in policy.withheld.items():
        lines.append(f"  Withheld:    {flag} — {reason}")
    lines.append(f"  Sandbox:     {SANDBOX_GAP}")
    return lines


def budget_note(policy: Policy) -> str:
    """Suffix for the Budget line. max_minutes is enforced by lib/budget.py; max_usd is not."""
    if policy.max_usd is None:
        return ""
    return f"; ${policy.max_usd:.2f} declared, NOT enforced"


def policy_record(policy: Policy, engine: str) -> Dict[str, Any]:
    """The machine-readable account written to the run directory as policy.json."""
    not_enforced = ["os-sandbox"]
    if engine == "pi":
        not_enforced.append("read-scope")
    if policy.max_usd is not None:
        not_enforced.append("budget.max_usd")
    return {
        "agent": policy.agent,
        "engine": engine,
        "declared": {
            "containment": policy.tier,
            "containment_declared": policy.tier_declared,
            "capabilities": dict(policy.declared),
            "requires": list(policy.requires),
            "budget": {"max_minutes": policy.max_minutes, "max_usd": policy.max_usd},
        },
        "granted": {
            "tool_policy": policy.tool_policy,
            "enforced_by": ENGINE_ENFORCEMENT.get(engine),
            "read_scope": ENGINE_READ_SCOPE.get(engine),
        },
        "withheld": dict(policy.withheld),
        "not_enforced": not_enforced,
    }
