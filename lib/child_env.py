#!/usr/bin/env python3
"""Explicit child environments: add what a child needs, never subtract from the parent.

Non-negotiable #4: an agent's environment holds no credentials it was not given for this run.
The audit's SF-04 finding is that subtraction cannot be complete — claude.sh unset two
precedence variables and four more survived (agents-e3u). Every agent child now gets an
environment built by addition:

* a base allowlist of paths, locale, temp and user identity (no secrets, no SSH agent);
* the operator's proxy vars only when the child is unsandboxed (``proxied`` flag), never its
  CA bundle;
* the model-auth variables of the engine being dispatched, and nothing else;
* a GitHub token for an explicit public-issue promotion (`factory promote`, which reuses the
  `github-issues` sink name), or for a pre-pass whose agent declares `requires: [gh]`
  (issue-triage) — the only children that talk to GitHub on the run's behalf.

Cloud credentials, the SSH agent, unrelated project tokens and everything else the operator's
shell happened to hold are never added. An unknown engine gets no credentials at all: a new
adapter must be named here before it can see a key, which is the fail-closed direction.
"""

import os
from collections.abc import Mapping as MappingABC
from typing import Dict, Mapping, Optional

from lib.credential_broker import BROKER_ENV_CONFIGS, PLACEHOLDER_KEY
from lib.tool_pins import HOST_PINS_ENV, UNPINNED_ALLOW_ENV

# Paths, locale, temp and user identity. Proxy and CA-bundle vars are deliberately NOT here
# (agents-5d9): a poisoned operator env could redirect a child's traffic or point its TLS at
# an attacker CA. Proxy vars are forwarded only via the explicit `proxied` flag (unsandboxed
# children, PROXY_VARS below); the operator's CA bundle is never forwarded — every child uses
# the system trust store (/etc, ro-bound into the sandbox) as its trust assumption.
BASE_ALLOW = (
    "PATH", "HOME", "TMPDIR", "TMP", "TEMP",
    "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_MESSAGES",
    "TERM", "TZ", "USER", "LOGNAME",
    "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR",
)

# Operator proxy/routing vars, forwarded ONLY when `proxied=True` — an unsandboxed child that
# must reach the network the way the operator's shell does (e.g. an unsandboxed engine's model
# call on a corporate network). Sandboxed children never inherit these: their egress is the
# in-sandbox relay + allowlist proxy (pre-pass) or the credential broker (engine), set by the
# dispatcher. A poisoned operator proxy must not redirect a sandboxed child (agents-5d9).
PROXY_VARS = (
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY",
    "http_proxy", "https_proxy", "no_proxy", "all_proxy",
)

# The model-auth variables each engine adapter may see. These are the engine's own credentials,
# not the operator's: extend the tuple when a provider is wired up, and note that an unlisted
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
        "DEEPSEEK_API_KEY", "OPENROUTER_API_KEY",
        # Keyless BYOK providers (agents-3y2): pi reads <NAME>_API_KEY/<NAME>_BASE_URL,
        # and the managed endpoints inject auth server-side, so a placeholder key + the
        # broker's base URL is all a sandboxed pi needs for these.
        "KIMI_API_KEY", "ZAI_API_KEY", "QWEN_API_KEY",
    ),
    # Kept aligned with lib/adapters/claude.sh's SESSION_OVERRIDE_VARS plus the session token
    # the adapter deliberately preserves; tests/test_child_env.py asserts the relationship.
    "deepseek": (
        "DEEPSEEK_API_KEY", "deepseek_api_key", "DEEPSEEK_BASE_URL", "DEEPSEEK_MODEL",
    ),
    "claude": (
        "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
        "ANTHROPIC_BASE_URL", "ANTHROPIC_BEDROCK_BASE_URL", "ANTHROPIC_CUSTOM_HEADERS",
        "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_GATEWAY",
        "AWS_BEARER_TOKEN_BEDROCK",
    ),
    "antigravity": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
}

# The findings dispatch is a child of the run, and the only one allowed to talk to GitHub.
GITHUB_TOKEN_VARS = ("GH_TOKEN", "GITHUB_TOKEN")

# Backwards-compatible alias: agents-2x6's factory/egress code and its tests reference
# child_env.BROKER_PROVIDERS, while 62u made credential_broker.BROKER_ENV_CONFIGS the canonical
# table. Both names MUST be the same mapping object, or a provider could be brokered off one
# table while being unknown to the other.
BROKER_PROVIDERS = BROKER_ENV_CONFIGS
# Requirements that bring the pre-pass a network credential. lib/containment.py refuses any of
# these unless the agent declares capabilities.network, so a credential never reaches a tier
# whose ceiling forbids network (agents-05h). tests/test_containment.py holds this list and
# prepass_environment() in agreement: add an entry here when a requirement starts to grant one.
NETWORK_CREDENTIAL_REQUIREMENTS = ("gh",)


def declares_requirement(agent_cfg: Mapping, tool: str) -> bool:
    """Whether agent.yaml's capabilities.requires names `tool`."""
    capabilities = agent_cfg.get("capabilities") if isinstance(agent_cfg, MappingABC) else None
    requires = capabilities.get("requires") if isinstance(capabilities, MappingABC) else None
    return isinstance(requires, (list, tuple)) and tool in requires


def prepass_environment(agent_cfg: Mapping, parent: Optional[Mapping[str, str]] = None,
                        proxied: bool = False) -> Dict[str, str]:
    """The deterministic pre-pass env: trusted factory code, but still an added allowlist.

    It gets a GitHub token only when the agent declares it needs `gh` (issue-triage), never
    just because the operator's shell had one. `proxied` forwards the operator's proxy vars
    only for an UNSANDBOXED pre-pass (agents-5d9); a sandboxed pre-pass gets the relay set
    by the dispatcher instead.
    """
    return child_environment(github=declares_requirement(agent_cfg, "gh"), parent=parent,
                             proxied=proxied)


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
            raise ContainmentError(f"fail closed: broker provided URL for unmapped provider {provider!r}")
        placeholder_var, base_url_var, secret_vars = spec
        for var in secret_vars:
            env.pop(var, None)  # no real credential crosses into the sandboxed env
        env[placeholder_var] = PLACEHOLDER_KEY
        env[base_url_var] = base_url
    return env


def child_environment(
    engine: Optional[str] = None,
    sink: Optional[str] = None,
    github: bool = False,
    parent: Optional[Mapping[str, str]] = None,
    broker_urls: Optional[Mapping[str, str]] = None,
    trusted_tools: bool = False,
    sink_options: Optional[Mapping[str, object]] = None,
    proxied: bool = False,
) -> Dict[str, str]:
    """Build the environment for one child process by addition.

    `engine` selects the model-auth class; `github` adds a GitHub token (a pre-pass that
    declares `gh`); `sink` adds credentials declared by its configured adapters.
    `parent` defaults to os.environ and is only read, never mutated.

    `trusted_tools` is for the children that resolve a trusted tool THEMSELVES — the findings
    dispatch and promotion run `lib/sinks/*`, which call `lib.tool_pins.resolve_tool` for
    `gh`/`bd`. On a pinned host the pins live behind `FACTORY_TOOL_PINS`, and without that
    variable such a child cannot verify the tool it is about to execute and fails closed, with
    strictly less information than the parent that already verified the same file (agents-dpt).
    The same child also needs the parent's `FACTORY_ALLOW_UNPINNED_TOOLS` dev/test opt-in
    (agents-7ua): it is a run-scoped widening the parent already applied when it resolved the
    tool, and without it the child's own `resolve_tool` fails closed even though the parent just
    resolved the same binary. Children that never resolve a trusted tool (engine sessions,
    pre-passes) get nothing extra.

    `proxied` (agents-5d9) forwards the operator's proxy vars (PROXY_VARS) — only for an
    unsandboxed child that must reach the network the way the operator's shell does. It is
    False by default, so a sandboxed child never inherits a possibly-poisoned operator proxy.
    The operator's CA bundle is never forwarded: every child uses the system trust store.

    `broker_urls` (agents-8h4) maps a provider name to the base URL of a dispatcher-run
    credential broker. For each such provider the real key vars are dropped and the engine gets
    a non-secret placeholder + the base URL, so a sandboxed engine's /proc/self/environ holds no
    credential shape while model calls still authenticate (the broker injects the real key on the
    host side). Providers absent from broker_urls are untouched.
    """
    source = os.environ if parent is None else parent
    env = {name: source[name] for name in BASE_ALLOW if name in source}
    if proxied:
        env.update({name: source[name] for name in PROXY_VARS if name in source})

    if trusted_tools:
        if source.get(HOST_PINS_ENV):
            env[HOST_PINS_ENV] = str(source[HOST_PINS_ENV])
        # agents-7ua: the unpinned-tools opt-in is the same run-scoped decision as the pins
        # file above — forward it so the sink/promotion child resolves the tool under the same
        # rule the parent just used, never a stricter one that makes it fail closed spuriously.
        if source.get(UNPINNED_ALLOW_ENV):
            env[UNPINNED_ALLOW_ENV] = str(source[UNPINNED_ALLOW_ENV])

    names = list(ENGINE_CREDENTIALS.get(engine or "", ()))
    # Explicit promotion grants a GitHub token; legacy both/all aliases only select beads.
    if github:
        names.extend(GITHUB_TOKEN_VARS)
    if sink:
        # Each sink adapter names what its delivery needs (github-issues: a GitHub token;
        # command: the manifest's `sink_env` list). This module never names a tracker
        # (fleet-km8); the set for the built-in sinks is unchanged.
        from lib.sinks import credential_env
        names.extend(credential_env(sink, sink_options))
    for name in names:
        value = source.get(name)
        if value:
            env[name] = value

    if broker_urls:
        apply_broker_urls(env, broker_urls)
    return env
