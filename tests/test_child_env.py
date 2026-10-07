#!/usr/bin/env python3
"""Child environments are built by addition (SF-04).

Subtraction can never be complete: the claude adapter unset two precedence variables and four
more survived (agents-e3u). These tests pin the addition — a base allowlist, the dispatching
engine's own model-auth variables, and a GitHub token only for the findings dispatch that
talks to GitHub.
"""

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.child_env import (  # noqa: E402
    BASE_ALLOW,
    BROKER_PROVIDERS,
    ENGINE_CREDENTIALS,
    GITHUB_TOKEN_VARS,
    child_environment,
    declares_requirement,
    prepass_environment,
)
from lib.credential_broker import PLACEHOLDER_KEY  # noqa: E402

SECRETS = {
    "GITHUB_TOKEN": "ghs_ci_token",
    "GH_TOKEN": "ghs_ci_token",
    "AWS_SECRET_ACCESS_KEY": "aws-secret",
    "AWS_ACCESS_KEY_ID": "aws-id",
    "SSH_AUTH_SOCK": "/tmp/ssh.sock",
    "PROJECT_UNRELATED_TOKEN": "unrelated",
    "MY_SECRET": "another",
}


def parent_env(**overrides):
    env = {
        "PATH": "/usr/bin", "HOME": "/home/operator", "LANG": "en_GB.UTF-8",
        "ANTHROPIC_API_KEY": "sk-ant", "GEMINI_API_KEY": "gem", "OPENAI_API_KEY": "op",
    }
    env.update(SECRETS)
    env.update(overrides)
    return env


class TestChildEnvironment(unittest.TestCase):
    def test_base_allowlist_carries_no_credentials(self):
        env = child_environment(parent=parent_env())
        self.assertEqual(env["PATH"], "/usr/bin")
        self.assertEqual(env["HOME"], "/home/operator")
        self.assertEqual(env["LANG"], "en_GB.UTF-8")
        for name in list(SECRETS) + ["ANTHROPIC_API_KEY", "GEMINI_API_KEY"]:
            with self.subTest(name=name):
                self.assertNotIn(name, env)

    def test_engine_gets_only_its_own_model_auth(self):
        pi = child_environment(engine="pi", parent=parent_env())
        self.assertEqual(pi["ANTHROPIC_API_KEY"], "sk-ant")
        self.assertEqual(pi["GEMINI_API_KEY"], "gem")
        self.assertNotIn("GITHUB_TOKEN", pi)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", pi)
        self.assertNotIn("SSH_AUTH_SOCK", pi)

        claude = child_environment(engine="claude", parent=parent_env())
        self.assertEqual(claude["ANTHROPIC_API_KEY"], "sk-ant")
        self.assertNotIn("GEMINI_API_KEY", claude)
        self.assertNotIn("GITHUB_TOKEN", claude)

        deepseek = child_environment(engine="deepseek", parent=parent_env(DEEPSEEK_API_KEY="ds-key"))
        self.assertEqual(deepseek["DEEPSEEK_API_KEY"], "ds-key")
        self.assertNotIn("ANTHROPIC_API_KEY", deepseek)
        self.assertNotIn("GITHUB_TOKEN", deepseek)

    def test_unknown_engine_fails_closed(self):
        env = child_environment(engine="brand-new-engine", parent=parent_env())
        self.assertNotIn("ANTHROPIC_API_KEY", env)
        self.assertNotIn("GEMINI_API_KEY", env)
        self.assertEqual(env["PATH"], "/usr/bin")

    def test_github_sink_gets_a_token_and_nothing_else(self):
        for sink in ("github-issues", "github-issues,beads", "both"):
            with self.subTest(sink=sink):
                env = child_environment(sink=sink, parent=parent_env())
                self.assertEqual(env["GH_TOKEN"], "ghs_ci_token")
                self.assertEqual(env["GITHUB_TOKEN"], "ghs_ci_token")
                self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)
                self.assertNotIn("ANTHROPIC_API_KEY", env)

    def test_other_sinks_get_no_github_token(self):
        for sink in ("file", "beads", None):
            with self.subTest(sink=sink):
                env = child_environment(sink=sink, parent=parent_env())
                for name in GITHUB_TOKEN_VARS:
                    self.assertNotIn(name, env)

    def test_github_flag_adds_tokens(self):
        env = child_environment(github=True, parent=parent_env())
        self.assertEqual(env["GH_TOKEN"], "ghs_ci_token")
        self.assertNotIn("ANTHROPIC_API_KEY", env)

    def test_declares_requirement_reads_the_agent_yaml_shape(self):
        self.assertTrue(declares_requirement({"capabilities": {"requires": ["gh"]}}, "gh"))
        self.assertFalse(declares_requirement({"capabilities": {"requires": ["git"]}}, "gh"))
        for malformed in ({}, {"capabilities": None}, {"capabilities": "gh"},
                          {"capabilities": {"requires": "gh"}}):
            with self.subTest(cfg=malformed):
                self.assertFalse(declares_requirement(malformed, "gh"))

    def test_prepass_gets_github_only_when_declared(self):
        declaring = prepass_environment({"capabilities": {"requires": ["gh"]}},
                                        parent=parent_env())
        self.assertEqual(declaring["GH_TOKEN"], "ghs_ci_token")
        self.assertNotIn("ANTHROPIC_API_KEY", declaring)

        plain = prepass_environment({"capabilities": {"requires": ["git"]}},
                                    parent=parent_env())
        self.assertNotIn("GH_TOKEN", plain)

    def test_absent_variables_are_not_invented(self):
        self.assertEqual(child_environment(parent={"PATH": "/bin"}), {"PATH": "/bin"})

    def test_parent_mapping_is_read_only(self):
        source = parent_env()
        before = dict(source)
        child_environment(engine="pi", sink="github-issues", parent=source)
        self.assertEqual(source, before)

    def test_claude_allowlist_covers_the_adapter_overrides(self):
        """The allowlist forwards everything claude.sh may want to unset (agents-e3u)."""
        adapter = (ROOT / "lib" / "adapters" / "claude.sh").read_text(encoding="utf-8")
        block = re.search(r"SESSION_OVERRIDE_VARS=\((.*?)\)", adapter, re.DOTALL).group(1)
        overrides = {line.strip() for line in block.splitlines() if line.strip()}
        self.assertTrue(overrides <= set(ENGINE_CREDENTIALS["claude"]),
                        f"missing from ENGINE_CREDENTIALS['claude']: "
                        f"{sorted(overrides - set(ENGINE_CREDENTIALS['claude']))}")
        self.assertIn("CLAUDE_CODE_OAUTH_TOKEN", ENGINE_CREDENTIALS["claude"])

    def test_base_allowlist_names_carry_no_secrets(self):
        """No credential-shaped name sneaks into the base list."""
        for name in BASE_ALLOW:
            with self.subTest(name=name):
                self.assertNotIn("TOKEN", name.upper())
                self.assertNotIn("SECRET", name.upper())
                self.assertNotIn("KEY", name.upper())


class TestCredentialBrokering(unittest.TestCase):
    """agents-8h4: a brokered provider's real key never enters the sandboxed env; the engine
    gets a non-secret placeholder + the broker base URL instead."""

    def test_brokered_anthropic_gets_a_placeholder_and_base_url_not_the_real_key(self):
        url = "http://127.0.0.1:9999/proxy/anthropic"
        env = child_environment(engine="pi", parent=parent_env(),
                                broker_urls={"anthropic": url})
        self.assertEqual(env["ANTHROPIC_API_KEY"], PLACEHOLDER_KEY)
        self.assertEqual(env["ANTHROPIC_BASE_URL"], url)
        self.assertNotIn("sk-ant", env.values())  # the real key is gone

    def test_every_secret_var_of_a_brokered_provider_is_stripped(self):
        parent = parent_env(ANTHROPIC_AUTH_TOKEN="auth-tok", CLAUDE_CODE_OAUTH_TOKEN="oauth-tok")
        env = child_environment(engine="claude", parent=parent,
                                broker_urls={"anthropic": "http://127.0.0.1:1/proxy/anthropic"})
        self.assertNotIn("ANTHROPIC_AUTH_TOKEN", env)
        self.assertNotIn("CLAUDE_CODE_OAUTH_TOKEN", env)
        self.assertEqual(env["ANTHROPIC_API_KEY"], PLACEHOLDER_KEY)

    def test_unbrokered_providers_keep_their_real_keys(self):
        env = child_environment(engine="pi", parent=parent_env(),
                                broker_urls={"anthropic": "http://127.0.0.1:1/proxy/anthropic"})
        self.assertEqual(env["OPENAI_API_KEY"], "op")   # not brokered -> untouched
        self.assertEqual(env["GEMINI_API_KEY"], "gem")

    def test_openai_and_google_brokering(self):
        env = child_environment(engine="pi", parent=parent_env(), broker_urls={
            "openai": "http://127.0.0.1:1/proxy/openai",
            "google": "http://127.0.0.1:1/proxy/google",
        })
        self.assertEqual(env["OPENAI_API_KEY"], PLACEHOLDER_KEY)
        self.assertEqual(env["OPENAI_BASE_URL"], "http://127.0.0.1:1/proxy/openai")
        self.assertEqual(env["GEMINI_API_KEY"], PLACEHOLDER_KEY)
        self.assertEqual(env["GOOGLE_GEMINI_BASE_URL"], "http://127.0.0.1:1/proxy/google")
        self.assertNotIn("op", env.values())
        self.assertNotIn("gem", env.values())

    def test_no_broker_urls_leaves_the_env_unchanged(self):
        with_broker = child_environment(engine="pi", parent=parent_env())
        self.assertEqual(with_broker["ANTHROPIC_API_KEY"], "sk-ant")  # real key, as today
        self.assertNotIn("ANTHROPIC_BASE_URL", with_broker)

    def test_an_unmapped_provider_is_ignored(self):
        # A provider absent from BROKER_PROVIDERS is skipped: apply_broker_urls sets no base
        # URL and strips no key for it, and unrelated providers are untouched. (deepseek and
        # openrouter were the old unmapped example; agents-2x6 mapped them, so the still-
        # unmapped bedrock stands in.)
        env = child_environment(engine="pi", parent=parent_env(),
                                broker_urls={"bedrock": "http://127.0.0.1:1/proxy/bedrock"})
        self.assertEqual(env["ANTHROPIC_API_KEY"], "sk-ant")  # real key, not brokered
        self.assertNotIn("ANTHROPIC_BASE_URL", env)

    def test_deepseek_and_openrouter_are_brokered(self):
        # agents-2x6: under --unshare-net a sandboxed engine cannot dial a provider directly,
        # so every provider pi can use must be brokerable. deepseek and openrouter joined
        # BROKER_PROVIDERS; like anthropic/openai/google their key becomes the placeholder and
        # they get a base URL, so no real credential crosses into the sandboxed environ.
        env = child_environment(engine="pi", parent=parent_env(
            DEEPSEEK_API_KEY="ds-key", OPENROUTER_API_KEY="or-key"), broker_urls={
            "deepseek": "http://127.0.0.1:1/proxy/deepseek",
            "openrouter": "http://127.0.0.1:1/proxy/openrouter",
        })
        self.assertEqual(env["DEEPSEEK_API_KEY"], PLACEHOLDER_KEY)
        self.assertEqual(env["DEEPSEEK_BASE_URL"], "http://127.0.0.1:1/proxy/deepseek")
        self.assertEqual(env["OPENROUTER_API_KEY"], PLACEHOLDER_KEY)
        self.assertEqual(env["OPENROUTER_BASE_URL"], "http://127.0.0.1:1/proxy/openrouter")
        self.assertNotIn("ds-key", env.values())
        self.assertNotIn("or-key", env.values())

    def test_the_placeholder_is_not_credential_shaped(self):
        # The whole point: the value in the sandboxed environ must not look like a key, so a
        # prompt-injected engine reading /proc/self/environ finds nothing worth exfiltrating.
        self.assertFalse(re.search(r"^(sk-|AIza|ghp_|ghs_|xox)", PLACEHOLDER_KEY))
        self.assertNotIn("KEY", PLACEHOLDER_KEY.upper().replace("-", "").replace("_", ""))

    def test_broker_provider_table_is_consistent_with_the_broker(self):
        # child_env's BROKER_PROVIDERS and credential_broker's PROVIDERS must name the same
        # providers, or a base URL would be set for a provider the broker cannot route.
        from lib.credential_broker import PROVIDERS as BROKER_SIDE
        self.assertEqual(set(BROKER_PROVIDERS), set(BROKER_SIDE))


if __name__ == "__main__":
    unittest.main()
