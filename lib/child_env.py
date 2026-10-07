#!/usr/bin/env python3
"""Explicit child environments: add what a child needs, never subtract from the parent.

Non-negotiable #4: an agent's environment holds no credentials it was not given for this run.
The audit's SF-04 finding is that subtraction cannot be complete — claude.sh unset two
precedence variables and four more survived (agents-e3u). Every agent child now gets an
environment built by addition:

* a base allowlist of paths, locale, temp and transport settings (no secrets, no SSH agent);
* the model-auth variables of the engine being dispatched, and nothing else;
* a GitHub token for a `github-issues` findings dispatch, or for a pre-pass whose agent
  declares `requires: [gh]` (issue-triage) — the only children that talk to GitHub on the
  run's behalf.

Cloud credentials, the SSH agent, unrelated project tokens and everything else the operator's
shell happened to hold are never added. An unknown engine gets no credentials at all: a new
adapter must be named here before it can see a key, which is the fail-closed direction.
"""

import os
from collections.abc import Mapping as MappingABC
from typing import Dict, Mapping, Optional

from lib.credential_broker import BROKER_ENV_CONFIGS, PLACEHOLDER_KEY

# Paths, locale, temp and transport. Transport settings (proxies, CA bundles) are routing
# configuration rather than identity; dropping them silently breaks every engine on a
# corporate network, and the operator supplied them for this purpose.
BASE_ALLOW = (
    "PATH", "HOME", "TMPDIR", "TMP", "TEMP",
    "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_MESSAGES",
    "TERM", "TZ", "USER", "LOGNAME",
    "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY",
    "http_proxy", "https_proxy", "no_proxy", "all_proxy",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
)

# The model-auth variables each engine adapter may see. These are the engine's own credentials,
# not the operator's: extend the tuple when a provider is wired up, and note that an unlisted
# engine gets none (fail closed).
ENGINE_CREDENTIALS = {
    "pi": (
        "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY",
        "DEEPSEEK_API_KEY", "OPENROUTER_API_KEY",
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


def prepass_environment(agent_cfg: Mapping, parent: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
    """The deterministic pre-pass env: trusted factory code, but still an added allowlist.

    It gets a GitHub token only when the agent declares it needs `gh` (issue-triage), never
    just because the operator's shell had one.
    """
    return child_environment(github=declares_requirement(agent_cfg, "gh"), parent=parent)


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
) -> Dict[str, str]:
    """Build the environment for one child process by addition.

    `engine` selects the model-auth class; `sink`/`github` add a GitHub token for the children
    that legitimately talk to GitHub. `parent` defaults to os.environ and is only read, never
    mutated.

    `broker_urls` (agents-8h4) maps a provider name to the base URL of a dispatcher-run
    credential broker. For each such provider the real key vars are dropped and the engine gets
    a non-secret placeholder + the base URL, so a sandboxed engine's /proc/self/environ holds no
    credential shape while model calls still authenticate (the broker injects the real key on the
    host side). Providers absent from broker_urls are untouched.
    """
    source = os.environ if parent is None else parent
    env = {name: source[name] for name in BASE_ALLOW if name in source}

    names = list(ENGINE_CREDENTIALS.get(engine or "", ()))
    if github or (sink and any(s.strip() in ("github-issues", "both", "all") for s in sink.split(","))):
        names.extend(GITHUB_TOKEN_VARS)
    for name in names:
        value = source.get(name)
        if value:
            env[name] = value

    if broker_urls:
        apply_broker_urls(env, broker_urls)
    return env
