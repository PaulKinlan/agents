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
from urllib.parse import urlsplit

from lib.child_env import (BROKER_PROVIDERS, ENGINE_CREDENTIALS,
                           NETWORK_CREDENTIAL_REQUIREMENTS)

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
# This table says NOTHING about OS sandboxing: a WORKTREE_WRITE row means only that the
# adapter implements the policy's flags. The sandbox-verified set is lib/sandbox.py
# SANDBOXED_ENGINES, and the runtime delivers a write grant solely when the run is
# engine_sandboxed — factory downgrades it to read-only otherwise.
READ_ONLY = "read-only"
# A write grant runs the engine in a disposable per-session git worktree (agents-6ce): the
# model may edit files, but only inside the throwaway worktree — the target checkout is bound
# read-only, so "propose, don't apply" holds and the collected session diff IS the proposal.
WORKTREE_WRITE = "worktree-write"
GRANTABLE_POLICIES = (READ_ONLY, WORKTREE_WRITE)
# The only classes an agent manifest may declare (agents-7ik): the write grant is gated on
# == proposer and an unknown class must refuse loudly, not silently downgrade.
VALID_CLASSES = ("observer", "proposer", "optimizer")
ENGINE_TOOL_POLICIES: Dict[str, frozenset] = {
    "pi": frozenset({READ_ONLY, WORKTREE_WRITE}),
    # claude's adapter carries the worktree-write policy in this table, but claude is NOT
    # OS-sandbox-verified (not in lib/sandbox.py SANDBOXED_ENGINES — its session auth needs
    # $HOME, which the sandbox hides), so the write grant is never delivered to it: the
    # factory dispatcher downgrades a claude worktree-write to read-only on every host
    # BEFORE invoking the adapter, and the adapter REFUSES a direct worktree-write
    # invocation outright (exit 3 — agents-dpbc review P1: a silent exit-0 downgrade would
    # leave a direct caller believing its writes happened). The row stays because
    # check_engine runs before that downgrade — without it a claude write-agent would be
    # refused outright instead of downgraded honestly.
    "claude": frozenset({READ_ONLY, WORKTREE_WRITE}),
    "deepseek": frozenset({READ_ONLY}),
    # `agentapi new-conversation` takes a prompt and nothing else: no tool controls.
    "antigravity": frozenset(),
}
# Engines whose table row carries the worktree-write policy but which are NOT
# OS-sandbox-verified, so the runtime never delivers the grant to them and their adapters
# refuse a direct invocation of it. Named here so the table cannot be read as a
# verification claim (agents-dpbc); tests/test_containment.py pins that a WORKTREE_WRITE
# row above implies membership in lib/sandbox.py
# SANDBOXED_ENGINES or in this set, so the next engine added to the wrong column fails
# the test unless its author names it unverified here, in code.
WORKTREE_WRITE_UNVERIFIED_ENGINES = frozenset({"claude"})

# How each adapter enforces each grantable policy, and what that leaves open. Stated in the
# banner and in policy.json so the operator reads the enforcement, not an adjective.
ENGINE_ENFORCEMENT: Dict[str, Dict[str, str]] = {
    "pi": {
        READ_ONLY: "pi --tools read,grep,find,ls --no-extensions --no-approve",
        WORKTREE_WRITE: ("pi --tools read,grep,find,ls,edit,write --no-extensions --no-approve "
                         "in a disposable worktree (target bound read-only); delivered ONLY "
                         "inside the dispatcher's OS sandbox — run_agent grants it solely when "
                         "the run is engine_sandboxed and wraps the adapter in sandbox_command, "
                         "and downgrades to read-only otherwise. The adapter ACCEPTS the "
                         "dispatcher's grant and verifies nothing itself (agents-dpbc, fourth "
                         "ruling: an adapter cannot verify its own kernel boundary — the "
                         "round-3 uid_map/mount checks were spoofable with unprivileged "
                         "namespaces), so a direct adapter invocation carrying this policy is "
                         "UNSANDBOXED — misuse, not a supported caller"),
    },
    "claude": {
        READ_ONLY: "claude --restricted --tools Read,Grep,Glob --strict-mcp-config",
        # Never delivered: claude is not sandbox-verified, so the dispatcher downgrades a
        # claude worktree-write grant to read-only before the adapter is invoked, and the
        # adapter REFUSES a direct worktree-write invocation (exit 3) rather than silently
        # downgrading it (agents-dpbc review P1) — no caller reaches claude with Edit,Write,
        # and no caller is left believing writes happened that did not.
        WORKTREE_WRITE: ("never delivered: downgraded to read-only by the dispatcher before "
                         "the adapter is invoked, and refused (exit 3) by the adapter on a "
                         "direct invocation (claude is not sandbox-verified)"),
    },
    "deepseek": {READ_ONLY: "deepseek-api read-only payload triage"},
}
# Read-scope claims for engines the OS sandbox does NOT cover. Only pi is in
# SANDBOXED_ENGINES (lib/sandbox.py): claude/antigravity/deepseek run with no kernel boundary,
# so each of these must name its real boundary (a tool flag, a refusal, or a payload-only
# design) and say plainly that it is NOT kernel-confined (agents-nq7). claude needs $HOME for
# session auth (the sandbox hides it), and its --restricted/permission mode are tool flags,
# not a kernel boundary. antigravity enforces no tool policy and is refused before it can run.
# deepseek is payload-only, so it has no filesystem read scope to confine at all.
ENGINE_READ_SCOPE = {
    "pi": "NOT confined: pi's read tool reaches any file the operator can read",
    "claude": "NOT kernel-confined: only claude's --restricted tool flags confine its file "
              "tools to the working directory (claude is not in SANDBOXED_ENGINES — its "
              "session auth needs $HOME, which the sandbox hides), so the target is not "
              "sandboxed read-only and $HOME is not hidden",
    "antigravity": "NOT kernel-confined: the antigravity adapter enforces no tool policy and "
                   "is refused before it can run",
    "deepseek": "NOT kernel-confined: deepseek is payload-only (the adapter passes only the "
                "scanner context and payload, no file tools), so it has no filesystem read scope",
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
    # network is grantable via the egress-allowlist proxy (agents-2x6): a sandboxed run
    # under --unshare-net has no route off its netns and its only egress is the per-run
    # allowlist, so a declared network at t1-fetch is honoured. This reason names the
    # mechanism and is used by the run-time fallback (downgrade_network_to_withheld):
    # no OS sandbox on the host, an engine adapter not verified to run under it, or a
    # model provider the credential broker cannot cover keeps the engine session on the
    # shared host network, and then a network tool could not be held to the tier's hosts
    # (the pre-pass may still be egress-isolated; this text is about the engine session).
    "network": "the egress-allowlist proxy is not active for this engine's run (no OS "
               "sandbox on this host, the engine adapter is not verified to run under it, "
               "or a model provider the credential broker cannot cover), so a network "
               "tool cannot be held to the tier's hosts",
    "browser": "a browser is an unscoped network client and cannot yet be held to localhost",
}

# An optimizer's model session stays read-only even when it declares write (agents-6ce): its
# output is a set of structured steps that its driver applies in its own isolated worktree
# (run_hillclimb's measure-change-remeasure loop), not a file patch, so a session worktree
# would be discarded and could displace the structured-steps contract.
OPTIMIZER_WRITE_WITHHELD = (
    "an optimizer returns structured steps that its driver applies in its own isolated "
    "worktree (measure-change-remeasure), so its model session stays read-only")
SANDBOX_GAP = ("NOT enforced: the engine process and the pre-pass run as the operator, with "
               "the operator's filesystem and network")
SANDBOX_PARTIAL_NOTE = ("; the engine adapter is not verified under the sandbox, so the "
                        "engine session itself is NOT confined")

# A declared `requires` tool -> the egress hosts its deterministic pre-pass fetches from
# (agents-2x6). The per-run allowlist handed to the egress proxy is derived from the agent's
# OWN manifest, never a global host list: a tool that is not declared adds nothing, and an
# unknown tool adds nothing (its pre-pass then has no egress under --unshare-net — exactly
# the allowlist discipline the t1-fetch tier promises). git is deliberately absent: audited,
# every git-requiring pre-pass runs local history (git log/diff) against the bound checkout
# and does no network fetch. The model API is not here either — it goes through the
# credential broker, not the egress proxy.
REQUIRE_EGRESS_HOSTS: Dict[str, Tuple[str, ...]] = {
    "gh": ("api.github.com",),
    "npm": ("registry.npmjs.org",),
    "npx": ("registry.npmjs.org",),
}


def egress_allowlist(requires: Tuple[str, ...]) -> Tuple[str, ...]:
    """The per-run egress allowlist implied by an agent's capabilities.requires
    (agents-2x6): the union of the hosts each declared tool's pre-pass fetches from, in
    declaration order, de-duplicated. Empty for an agent that declares no network tools —
    under --unshare-net its sandbox then has no egress at all, which is the t0 promise."""
    hosts: List[str] = []
    for tool in requires:
        for host in REQUIRE_EGRESS_HOSTS.get(tool, ()):
            if host not in hosts:
                hosts.append(host)
    return tuple(hosts)

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


def downgrade_network_to_withheld(policy: "Policy") -> "Policy":
    """A copy of `policy` with a declared network re-withheld (agents-2x6). load_policy
    grants a declared network optimistically — the egress-allowlist proxy can hold it to
    the tier's hosts — but the grant is only honourable on a run that actually isolates the
    network namespace. run_agent calls this when it cannot: a host with no OS sandbox, or a
    model provider the credential broker cannot cover (so --unshare-net would break the
    engine's own model calls). The banner and policy.json then report network withheld,
    honestly, instead of claiming an allowlist this run is not enforcing."""
    if not policy.declared.get("network") or "network" in policy.withheld:
        return policy
    return replace(policy,
                   withheld={**policy.withheld, "network": WITHHELD_REASONS["network"]})


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

    # The grant. Write is grantable via a disposable per-session git worktree (agents-6ce),
    # but only for an agent whose class is `proposer` — one whose output IS a file patch
    # (pr-fixer, docs-write, perf-review). Such an agent runs its engine in a throwaway
    # worktree, so edits never touch the target checkout and the collected session diff is the
    # proposal. The gate is fail-closed on the class (review P2, agents-6ce): ONLY `proposer`
    # is granted, so an optimizer (perf-hillclimb — it returns structured steps its driver
    # applies in its own worktree, so its session stays read-only), an observer, or any
    # unknown/mis-typed class that declares write is NOT. The grant is further conditional, at
    # run time, on the target being a git repo AND the run being engine_sandboxed; run_agent
    # downgrades to read-only (re-withholding write) when either fails, so the banner and
    # policy.json stay honest. Network is grantable via the egress-allowlist proxy
    # (agents-2x6) and is likewise conditional at run time: run_agent re-withholds it
    # (downgrade_network_to_withheld) when this run cannot isolate the netns — no OS sandbox,
    # or a model provider the credential broker cannot cover. Browser stays withheld: no
    # localhost-only browser mechanism exists yet.
    # agents-7ik: the class is not free-form. An unknown or mis-typed class used to slip
    # through silently (the write gate was already fail-closed on == proposer, but a typo'd
    # class quietly ran read-only with no hint); now it refuses like an unknown tier or
    # capability, and a MISSING class defaults to observer — the strictest of the three.
    agent_class = agent_cfg.get("class", "observer")
    if agent_class not in VALID_CLASSES:
        raise ContainmentError(
            f"{agent}: unknown agent class {agent_class!r} — nothing would gate its grant "
            f"correctly (known: {', '.join(VALID_CLASSES)}; omit `class` for observer)")
    write_granted = declared["write"] and agent_class == "proposer"
    tool_policy = WORKTREE_WRITE if write_granted else READ_ONLY
    withheld: Dict[str, str] = {}
    for flag in CAPABILITY_FLAGS:
        if not declared[flag]:
            continue
        if flag == "write" and write_granted:
            continue  # granted via the disposable worktree, not withheld
        if flag == "network":
            continue  # granted via the egress-allowlist proxy; runtime downgrade if inactive
        withheld[flag] = (OPTIMIZER_WRITE_WITHHELD
                          if flag == "write" and agent_class == "optimizer"
                          else WITHHELD_REASONS[flag])
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


def banner_lines(policy: Policy, engine: str, sandbox: Optional[Dict[str, Any]] = None,
                 unsandboxed_note: Optional[str] = None) -> List[str]:
    """The run banner's containment block: declared, enforced, withheld, not enforced.

    `sandbox` is lib/sandbox.py's sandbox_record(): None on hosts without a sandbox (the
    gap text stays, honestly), or the record of what the OS sandbox actually covers. That
    record is only ever produced for a wrap sandbox_command() has already exercised (agents-kwi),
    so "Sandbox: enforced" is never printed for a wrap that could not start its child.
    `unsandboxed_note` (agents-bp0) names the explicit FACTORY_ALLOW_UNSANDBOXED opt-in on
    a trusted target — a deliberate exception the operator attested to, so it is printed
    prominently instead of the generic gap text.
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
        lines.append(f"  Sandbox:     NOT enforced — {unsandboxed_note}"
                     if unsandboxed_note else f"  Sandbox:     {SANDBOX_GAP}")
    else:
        tool = sandbox.get("tool", "os-sandbox")
        coverage = ("engine and pre-pass" if engine_sandboxed
                    else f"pre-pass only{SANDBOX_PARTIAL_NOTE}")
        egress = ("network egress NOT filtered"
                  if not sandbox.get("network_egress_filtered") else "egress filtered")
        lines.append(f"  Sandbox:     enforced ({tool}): {coverage} — target read-only, "
                     f"factory repo and system dirs read-only, $HOME hidden (auth via env only), "
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


def _broker_covers_engine_env(engine: str, brokered_providers: Tuple[str, ...],
                              engine_env: Optional[Mapping[str, str]],
                              expected_placeholder: Optional[str] = None) -> bool:
    """Report broker enforcement only when no real engine credential survives the swap.

    Provider labels are not proof by themselves: the broker must have started, the
    adapter must have received its placeholder and loopback URL, and *every* model
    credential exposed by child_environment must be removed or replaced. URL userinfo in
    inherited proxy settings also remains a credential in the child's environment.
    `expected_placeholder` must be the running broker's per-run secret (agents-28nn
    round 7): the env holding ANY other value — including the retired static
    placeholder constant — is not evidence of a broker that will answer.
    """
    if not brokered_providers or engine_env is None or not expected_placeholder:
        return False
    covered = set()
    for provider in brokered_providers:
        spec = BROKER_PROVIDERS.get(provider)
        if spec is None:
            return False
        placeholder_var, base_var, secret_vars = spec
        try:
            base = urlsplit(engine_env.get(base_var, ""))
            if (engine_env.get(placeholder_var) != expected_placeholder
                    or base.scheme != "http" or base.hostname != "127.0.0.1"
                    or not base.port or base.path != f"/proxy/{provider}"):
                return False
        except ValueError:  # malformed URL/port is not evidence of a working broker
            return False
        covered.update(secret_vars)
    for var in ENGINE_CREDENTIALS.get(engine, ()):
        value = engine_env.get(var)
        if value and (var not in covered or value != expected_placeholder):
            return False
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        try:
            if urlsplit(engine_env.get(var, "")).username is not None:
                return False
        except ValueError:
            return False
    return True


def policy_record(policy: Policy, engine: str,
                  sandbox: Optional[Dict[str, Any]] = None,
                  unsandboxed_note: Optional[str] = None,
                  brokered_providers: Tuple[str, ...] = (),
                  engine_env: Optional[Mapping[str, str]] = None,
                  expected_placeholder: Optional[str] = None) -> Dict[str, Any]:
    """The machine-readable account written to the run directory as policy.json.

    `sandbox` is lib/sandbox.py's sandbox_record(), produced only for an exercised wrap
    (agents-kwi). The credential residual only drops after a broker actually starts and
    the engine env is verified to contain placeholders rather than real keys (agents-2dj)
    — on EITHER sandbox state, because the broker is no longer sandbox-gated (agents-28nn
    round 6). The dispatcher writes a conservative record before its pre-pass, then
    replaces it after a successful broker swap and restores those captured bytes after
    the session.
    """
    engine_sandboxed = bool(sandbox and sandbox.get("engine_sandboxed"))
    not_enforced = [] if engine_sandboxed else ["os-sandbox"]
    if engine == "pi" and not engine_sandboxed:
        not_enforced.append("read-scope")
    # bun/pi can read its own /proc/self/environ. The residual drops only when a running
    # broker swapped every real credential for a placeholder — verified against the
    # ACTUAL engine env by _broker_covers_engine_env, which is direct evidence on any
    # path (agents-28nn round 6: an unsandboxed brokered engine's record must be able to
    # say so). A sandboxed pre-pass alone is not sufficient (e.g. claude).
    brokered_env = _broker_covers_engine_env(engine, brokered_providers, engine_env,
                                             expected_placeholder)
    if sandbox is not None:
        if not sandbox.get("network_egress_filtered"):
            not_enforced.append("network-egress")
        if not brokered_env:
            not_enforced.append("env-credentials")
    elif brokered_providers and not brokered_env:
        # No sandbox record exists on a sandbox-less host; a broker that was started but
        # did NOT take (a real credential survived the swap) is still recorded honestly.
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
    if brokered_env:
        granted["credential_broker"] = {"providers": sorted(brokered_providers),
                                        "enforced": "engine env contains placeholders only"}
    record = {
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
    # agents-bp0: an unsandboxed opt-in run records the attestation it ran under, so the
    # machine-readable account says WHY the engine is unconfined — a deliberate exception
    # on a trusted target, not a silent fallback. os-sandbox/read-scope stay in
    # not_enforced either way; this field never upgrades them.
    if unsandboxed_note:
        record["unsandboxed_opt_in"] = unsandboxed_note
    # agents-5d9: record the child-transport trust assumption that was previously invisible.
    # The operator's CA bundle is never forwarded (children use the system trust store), and
    # the operator's proxy reaches only unsandboxed children (sandboxed children get the
    # in-sandbox relay / broker set by the dispatcher).
    record["network_transport"] = {
        "ca_bundle": "operator CA bundle not forwarded; child uses the system trust store",
        "proxy": "operator proxy env forwarded only to unsandboxed children "
                  "(sandboxed children use the in-sandbox relay/broker)",
    }
    return record
