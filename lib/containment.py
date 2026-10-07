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
* **Says plainly what is enforced and what is not.** On Linux hosts with bubblewrap the
  engine session and the pre-pass run inside an OS sandbox (lib/sandbox.py, agents-9n7);
  elsewhere they run as the operator and the banner and policy.json say NOT confined.
  Network egress is never filtered yet.

The tier is a ceiling on what an agent may declare. It is not a grant. Write, network and
browser are declared by some agents and granted to none, each for a stated reason
(WITHHELD_REASONS); lifting one needs the mechanism named in its reason, not a manifest edit.
"""

import math
from dataclasses import dataclass, replace
from typing import Any, Dict, List, Mapping, Optional, Tuple

from lib.child_env import NETWORK_CREDENTIAL_REQUIREMENTS

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
# A write grant runs the engine in a disposable per-session git worktree (agents-6ce): the
# model may edit files, but only inside the throwaway worktree — the target checkout is bound
# read-only, so "propose, don't apply" holds and the collected session diff IS the proposal.
WORKTREE_WRITE = "worktree-write"
GRANTABLE_POLICIES = (READ_ONLY, WORKTREE_WRITE)
ENGINE_TOOL_POLICIES: Dict[str, frozenset] = {
    "pi": frozenset({READ_ONLY, WORKTREE_WRITE}),
    "claude": frozenset({READ_ONLY, WORKTREE_WRITE}),
    "deepseek": frozenset({READ_ONLY}),
    # `agentapi new-conversation` takes a prompt and nothing else: no tool controls.
    "antigravity": frozenset(),
}

# How each adapter enforces each grantable policy, and what that leaves open. Stated in the
# banner and in policy.json so the operator reads the enforcement, not an adjective.
ENGINE_ENFORCEMENT: Dict[str, Dict[str, str]] = {
    "pi": {
        READ_ONLY: "pi --tools read,grep,find,ls --no-extensions --no-approve",
        WORKTREE_WRITE: ("pi --tools read,grep,find,ls,edit,write --no-extensions --no-approve "
                         "in a disposable worktree (target bound read-only)"),
    },
    "claude": {
        READ_ONLY: "claude --restricted --tools Read,Grep,Glob --strict-mcp-config",
        WORKTREE_WRITE: ("claude --restricted --tools Read,Grep,Glob,Edit,Write "
                         "--strict-mcp-config in a disposable worktree"),
    },
    "deepseek": {READ_ONLY: "deepseek-api read-only payload triage"},
}
ENGINE_READ_SCOPE = {
    "pi": "NOT confined: pi's read tool reaches any file the operator can read",
    "claude": "confined to the target directory (claude --restricted)",
    "deepseek": "confined to scanner context and payload",
}


def enforcement_for(engine: str, tool_policy: str) -> str:
    """The adapter's enforcement string for a granted policy (banner + policy.json)."""
    return ENGINE_ENFORCEMENT.get(engine, {}).get(tool_policy, "unknown")


WITHHELD_REASONS = {
    # write is grantable via the disposable worktree (agents-6ce), so load_policy no longer
    # withholds a declared write at a tier that allows it. This generic reason remains for the
    # run-time downgrade path (run_agent supplies the specific reason, e.g. a non-git target).
    "write": "the engine runs in the target's own checkout, so proposers return patches in "
             "their report instead of editing files",
    "network": "no egress allowlist yet, so a network tool cannot be held to the tier's hosts",
    "browser": "a browser is an unscoped network client and cannot yet be held to localhost",
}
SANDBOX_GAP = ("NOT enforced: the engine process and the pre-pass run as the operator, with "
               "the operator's filesystem and network")
SANDBOX_PARTIAL_NOTE = ("; the engine adapter is not verified under the sandbox, so the "
                        "engine session itself is NOT confined")

# Adapters with a per-run cost flag. claude -p takes --max-budget-usd; pi (0.87.1) and
# agentapi have no equivalent (agents-js7), so a declared cap there is reported, not enforced.
USD_CAPABLE_ENGINES = frozenset({"claude"})


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


def downgrade_write_to_read_only(policy: "Policy", reason: str) -> "Policy":
    """A copy of `policy` with a granted worktree-write downgraded to read-only and `write`
    re-withheld for a target-specific reason. Used when a declared write cannot be honoured at
    run time (agents-6ce) — e.g. the target is not a git repository, so no disposable worktree
    can be created. The banner and policy.json then report read-only with write withheld,
    honestly, instead of claiming a write grant the run will not deliver."""
    if policy.tool_policy != WORKTREE_WRITE:
        return policy
    return replace(policy, tool_policy=READ_ONLY,
                   withheld={**policy.withheld, "write": reason})


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
    # A requirement that brings the pre-pass a network credential is network use, whatever the
    # flag says (lib/child_env.py). Without this, a t0 manifest could list gh and its pre-pass
    # would receive a GitHub token (agents-05h, found by review on PR #22).
    for tool in requires:
        if tool in NETWORK_CREDENTIAL_REQUIREMENTS and not declared["network"]:
            raise ContainmentError(
                f"{agent}: capabilities.requires [{tool}] brings the pre-pass a network "
                f"credential, so it needs capabilities.network: true at a tier that allows it")

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

    # The grant. Write is now grantable via a disposable per-session git worktree
    # (agents-6ce): an agent that declares write within a tier that allows it (t2-local) runs
    # its engine in a throwaway worktree, so edits never touch the target checkout — the
    # collected session diff is the proposal. The grant is conditional on the target being a
    # git repo; run_agent resolves that and downgrades to read-only (re-withholding write)
    # when it is not, so the banner and policy.json stay honest. Network and browser stay
    # withheld: no egress allowlist / localhost-only browser exists yet.
    write_granted = declared["write"]  # a declared write already passed the ceiling check
    tool_policy = WORKTREE_WRITE if write_granted else READ_ONLY
    withheld: Dict[str, str] = {}
    for flag in CAPABILITY_FLAGS:
        if declared[flag] and not (flag == "write" and write_granted):
            withheld[flag] = WITHHELD_REASONS[flag]
    return Policy(agent=agent, tier=tier, tier_declared=tier_declared, declared=declared,
                  requires=tuple(requires), tool_policy=tool_policy, withheld=withheld,
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


def banner_lines(policy: Policy, engine: str, sandbox: Optional[Dict[str, Any]] = None) -> List[str]:
    """The run banner's containment block: declared, enforced, withheld, not enforced.

    `sandbox` is lib/sandbox.py's sandbox_record(): None on hosts without a sandbox (the
    gap text stays, honestly), or the record of what the OS sandbox actually covers.
    """
    tier_note = "declared" if policy.tier_declared else "not declared; strictest tier assumed"
    engine_sandboxed = bool(sandbox and sandbox.get("engine_sandboxed"))
    read_scope = ((sandbox or {}).get("engine_read_scope")
                  or ENGINE_READ_SCOPE.get(engine, "unknown"))
    lines = [
        f"  Containment: {policy.tier} ({tier_note}) — a ceiling on capabilities, validated",
        f"  Tool policy: {policy.tool_policy}, enforced by the {engine} adapter: "
        f"{enforcement_for(engine, policy.tool_policy)}",
        f"  Read scope:  {read_scope}",
    ]
    for flag, reason in policy.withheld.items():
        lines.append(f"  Withheld:    {flag} — {reason}")
    if sandbox is None:
        lines.append(f"  Sandbox:     {SANDBOX_GAP}")
    else:
        tool = sandbox.get("tool", "os-sandbox")
        coverage = ("engine and pre-pass" if engine_sandboxed
                    else f"pre-pass only{SANDBOX_PARTIAL_NOTE}")
        egress = ("network egress NOT filtered"
                  if not sandbox.get("network_egress_filtered") else "egress filtered")
        lines.append(f"  Sandbox:     enforced ({tool}): {coverage} — target read-only, "
                     f"everything else invisible, $HOME hidden (auth via env only), "
                     f"private PID namespace (host /proc invisible); {egress}")
    return lines


def budget_note(policy: Policy, engine: str) -> str:
    """Suffix for the Budget line. max_minutes is enforced by lib/budget.py; max_usd only
    where the engine adapter has a per-run cost flag (agents-js7)."""
    if policy.max_usd is None:
        return ""
    if engine in USD_CAPABLE_ENGINES:
        return f"; ${policy.max_usd:.2f} enforced by the {engine} adapter (--max-budget-usd)"
    return (f"; ${policy.max_usd:.2f} declared, NOT enforced "
            f"(the {engine} adapter has no per-run budget flag)")


def policy_record(policy: Policy, engine: str,
                  sandbox: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The machine-readable account written to the run directory as policy.json.

    `sandbox` is lib/sandbox.py's sandbox_record(); the not_enforced list only drops an
    entry when the sandbox actually covers it, and gains `network-egress` because the
    sandbox does not filter egress (agents-9n7).
    """
    engine_sandboxed = bool(sandbox and sandbox.get("engine_sandboxed"))
    not_enforced = [] if engine_sandboxed else ["os-sandbox"]
    if engine == "pi" and not engine_sandboxed:
        not_enforced.append("read-scope")
    if sandbox is not None:
        if not sandbox.get("network_egress_filtered"):
            not_enforced.append("network-egress")
        # bun/pi needs a real procfs, so the engine's own /proc/self/environ is readable by
        # its own read tool: the engine's API keys (the child_env allowlist, nothing else)
        # are in reach of a prompt-injected session. Published output is redacted
        # (lib/redaction.py); a credential-broker proxy is the follow-up (agents-9n7).
        not_enforced.append("env-credentials")
    if policy.max_usd is not None and engine not in USD_CAPABLE_ENGINES:
        not_enforced.append("budget.max_usd")
    granted = {
        "tool_policy": policy.tool_policy,
        "enforced_by": enforcement_for(engine, policy.tool_policy),
        "read_scope": ((sandbox or {}).get("engine_read_scope")
                       or ENGINE_READ_SCOPE.get(engine)),
    }
    if sandbox is not None:
        granted["os_sandbox"] = dict(sandbox)
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
        "granted": granted,
        "withheld": dict(policy.withheld),
        "not_enforced": not_enforced,
    }
