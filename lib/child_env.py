"""Allowlisted child process environments (agents-5d9, agents-8h4).

Subprocesses spawned by the factory must run under a known, bounded set of environment
variables so ambient host secrets (e.g. AWS tokens, SSH keys, personal tokens) are never
inherited by child processes.

The factory spawns several distinct classes of children:
- The model engine itself (pi, claude, deepseek, etc.), via lib/adapters/*.sh
- The pre-pass scanner (station script), via its python entrypoint
- The git/gh sinks, which need network and authentication
- Isolated commands, which need nothing

Each caller specifies what capability the child legitimately needs:
- `engine`: which model engine is running (pi gets PI_* and MODEL_* vars; others get none)
- `github`: True if the child legitimately needs GH_TOKEN (issue-triage, github sink)
- `target_env`: optional mapping of extra env vars declared by the target config
- `trusted_tools`: True if the child resolves trusted tools itself via lib.tool_pins
- `broker_urls`: optional mapping {provider: localhost_url} to inject broker base URLs
- `proxied`: True only for unsandboxed children needing operator proxy variables
"""

import os
from collections.abc import Mapping as MappingABC
from typing import Dict, Mapping, Optional

from lib.credential_broker import BROKER_ENV_CONFIGS, PLACEHOLDER_KEY
from lib.tool_pins import HOST_PINS_ENV, UNPINNED_ALLOW_ENV

# Paths, locale, temp and user identity. Proxy and CA-bundle vars are deliberately NOT here
# (agents-5d9): proxies are forwarded only for unsandboxed children that legitimately need
# the operator's network route (see `proxied`), and CA bundles are kept off children unless
# explicitly configured.
BASE_ALLOW = (
    "PATH",
    "HOME",
    "TMPDIR",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "USER",
    "LOGNAME",
    "SHELL",
    "TERM",
    "COLORTERM",
)

PROXY_VARS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
)

# Engine-specific credential variables.
# A sandboxed engine's credentials are replaced by the broker (see `apply_broker_urls`);
# an unsandboxed engine gets its own credentials if present in parent. Any other engine's
# engine gets none (fail closed).
#
# Trust boundary for UNBROKERED engines (tm-unbrokered-engine-credentials, agents-5d9): a
# sandboxed engine's keys are replaced by the broker (placeholder + loopback URL), so nothing
# real crosses into the sandbox. An UNSANDBOXED engine (claude, or a host without bubblewrap)
# runs as the operator on a trusted+private target and gets its own real key BY DESIGN — that
# key is the engine's credential needed for its model call, and policy.json already records
# `env-credentials` in not_enforced for it. Documented behaviour, not a leak.
ENGINE_CREDENTIALS = {
    "pi": (
        "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY",
        "DEEPSEEK_API_KEY", "OPENROUTER_API_KEY", "KIMI_API_KEY", "ZAI_API_KEY",
        "QWEN_API_KEY",
        "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
    ),
    "claude": (
        "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
    ),
    "deepseek": (
        "DEEPSEEK_API_KEY",
    ),
    "antigravity": (
        "GEMINI_API_KEY", "GOOGLE_API_KEY",
    ),
}

# The subset of PROVIDERS that CredentialBroker can broker (all of them).
BROKER_PROVIDERS = BROKER_ENV_CONFIGS

PI_ALLOW = (
    "PI_AUTO_APPROVE",
    "PI_TOOLS",
    "PI_NO_EXTENSIONS",
    "PI_NO_PROMPT_TEMPLATES",
    "PI_MODEL",
    "PI_CODING_AGENT_DIR",
    "FACTORY_MODEL",
)

GITHUB_VARS = (
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GH_ENTERPRISE_TOKEN",
)


def declares_requirement(agent_cfg: Mapping, capability: str) -> bool:
    """True if agent_cfg declares a requires: list containing `capability`."""
    cap_section = agent_cfg.get("capabilities")
    if not isinstance(cap_section, MappingABC):
        return False
    requires = cap_section.get("requires")
    if not isinstance(requires, list):
        return False
    return capability in requires


def prepass_environment(agent_cfg: Mapping, parent: Optional[Mapping[str, str]] = None,
                        proxied: bool = False) -> Dict[str, str]:
    """The scrubbed environment for a deterministic pre-pass scanner.

    It gets a GitHub token only when the agent declares it needs `gh` (issue-triage), never
    just because the operator's shell had one. `proxied` forwards the operator's proxy vars
    only for an UNSANDBOXED pre-pass (agents-5d9); a sandboxed pre-pass gets the relay set
    by the dispatcher instead. `trusted_tools=True` because (agents-28nn round 4, agents-01qd,
    agents-qbl8) the pre-pass scripts resolve their own trusted tools through `resolve_tool` —
    including when unsandboxed, where no bind boundary authenticates anything, forwarding
    FACTORY_TOOL_PINS and FACTORY_ALLOW_UNPINNED_TOOLS.
    """
    return child_environment(github=declares_requirement(agent_cfg, "gh"), parent=parent,
                             proxied=proxied, trusted_tools=True)


def apply_broker_urls(env: Dict[str, str], broker_urls: Mapping[str, str]) -> Dict[str, str]:
    """Swap brokered providers' real key vars in `env` for a placeholder + the broker base URL.

    Mutates and returns `env`. For each provider in `broker_urls` that BROKER_ENV_CONFIGS maps,
    every var that could carry a real secret is dropped and the engine gets PLACEHOLDER_KEY
    under the var it reads plus the base-URL var pointed at the dispatcher's broker, so a
    sandboxed engine's /proc/self/environ holds no credential shape while model calls still
    authenticate (the broker injects the real key host-side).
    
    If the broker advertised a URL for a provider that we cannot broker (unmapped), we FAIL CLOSED
    by raising ContainmentError, because continuing would leave the raw key in the environment.
    """
    from lib.containment import ContainmentError
    for provider, base_url in broker_urls.items():
        spec = BROKER_ENV_CONFIGS.get(provider)
        if not spec:
            raise ContainmentError(
                f"broker advertised unmapped provider {provider!r}; cannot broker credentials safely")
        placeholder_var, base_url_var, secret_vars = spec
        for var in secret_vars:
            env.pop(var, None)  # no real credential crosses into the sandboxed env
        env[placeholder_var] = PLACEHOLDER_KEY
        env[base_url_var] = base_url
    return env


def child_environment(
    *,
    engine: Optional[str] = None,
    github: bool = False,
    parent: Optional[Mapping[str, str]] = None,
    broker_urls: Optional[Mapping[str, str]] = None,
    trusted_tools: bool = False,
    sink_options: Optional[Mapping[str, object]] = None,
    proxied: bool = False,
) -> Dict[str, str]:
    """Construct a scrubbed, allowlisted environment mapping for a child process.

    `trusted_tools` is for the children that resolve a trusted tool THEMSELVES — the findings
    dispatch and promotion run `lib/sinks/*`, which call `lib.tool_pins.resolve_tool` for
    `gh`/`bd`, and (agents-28nn round 4, agents-01qd) the pre-pass scripts, which now resolve their own
    git/gh/gitleaks/npm through `resolve_tool` rather than trusting PATH order (a station
    script's own trusted-tool launch is a census kind of its own). On a pinned host the pins
    live behind `FACTORY_TOOL_PINS`, and without that variable such a child cannot verify
    the tool it is about to execute and fails closed, with strictly less information than
    the parent that already verified the same file (agents-dpt). The same child also needs
    the parent's `FACTORY_ALLOW_UNPINNED_TOOLS` dev/test opt-in (agents-7ua): it is a
    run-scoped widening the parent already applied when it resolved the tool, and without
    it the child's own `resolve_tool` fails closed even though the parent just resolved the
    same binary. Children that never resolve a trusted tool (engine sessions) get nothing
    extra. For the SANDBOXED pre-pass the forwarded pins path would be hidden by the wrap,
    so the dispatcher overwrites it with the effective pins written OUTSIDE the run
    directory and bound into the wrap read-only (factory, lib.tool_pins.write_effective_pins
    — agents-28nn round 5: a file the pin resolver trusts must not be a file the pinned
    process can rewrite).

    `proxied` (agents-5d9) forwards the operator's proxy vars (PROXY_VARS) — only for an
    unsandboxed child that must reach the network the way the operator's shell does. It is
    ignored for children that have no network capability.

    `broker_urls` (agents-8h4) maps a provider name to the base URL of a dispatcher-run
    credential broker. For each such provider the real key vars are dropped and the engine gets
    a non-secret placeholder + the base URL, so a sandboxed engine's /proc/self/environ holds no
    credential shape while model calls still authenticate (the broker injects the real key on the
    host side). Providers absent from broker_urls are untouched.
    """
    source = os.environ if parent is None else parent
    env = {name: source[name] for name in BASE_ALLOW if name in source}

    if proxied:
        for name in PROXY_VARS:
            if name in source:
                env[name] = source[name]

    if engine and engine in ENGINE_CREDENTIALS:
        for name in ENGINE_CREDENTIALS[engine]:
            if name in source:
                env[name] = source[name]

    if engine == "pi":
        for name in PI_ALLOW:
            if name in source:
                env[name] = source[name]

    if github:
        for name in GITHUB_VARS:
            if name in source:
                env[name] = source[name]

    if trusted_tools:
        for name in (HOST_PINS_ENV, UNPINNED_ALLOW_ENV):
            value = source.get(name)
            if value is not None:
                env[name] = value

    if sink_options:
        env_extra = sink_options.get("env")
        if isinstance(env_extra, MappingABC):
            for k, v in env_extra.items():
                if isinstance(k, str) and isinstance(v, str):
                    env[k] = v

    # Preserve any existing FACTORY_* configuration variables already in the parent env
    for name, value in source.items():
        if name.startswith("FACTORY_") and name not in env:
            env[name] = value

    if broker_urls:
        apply_broker_urls(env, broker_urls)
    return env
