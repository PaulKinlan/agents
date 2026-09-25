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
    ENGINE_CREDENTIALS,
    GITHUB_TOKEN_VARS,
    child_environment,
    declares_requirement,
    prepass_environment,
)

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

    def test_unknown_engine_fails_closed(self):
        env = child_environment(engine="brand-new-engine", parent=parent_env())
        self.assertNotIn("ANTHROPIC_API_KEY", env)
        self.assertNotIn("GEMINI_API_KEY", env)
        self.assertEqual(env["PATH"], "/usr/bin")

    def test_github_sink_gets_a_token_and_nothing_else(self):
        env = child_environment(sink="github-issues", parent=parent_env())
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


if __name__ == "__main__":
    unittest.main()
