#!/usr/bin/env python3
"""Child environments are built by addition (SF-04).

Subtraction can never be complete: the claude adapter unset two precedence variables and four
more survived (agents-e3u). These tests pin the addition — a base allowlist, the dispatching
engine's own model-auth variables, and a GitHub token only for the findings dispatch that
talks to GitHub.
"""

import hashlib
import os
os.environ.setdefault("FACTORY_ALLOW_UNPINNED_TOOLS", "1")  # dev/test opt-in for unpinned tools
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
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
    survey_egress_credentials,
)
from lib.credential_broker import PLACEHOLDER_PREFIX, BROKER_ENV_CONFIGS  # noqa: E402
from lib.containment import ContainmentError

# The placeholder is a PER-RUN secret (agents-28nn round 7): child_environment must be
# handed the running broker's value via broker_placeholder and swaps it in verbatim.
# These tests pass an explicit stand-in; the broker's own generation and per-run
# uniqueness are pinned in tests/test_credential_broker.py.
TEST_PLACEHOLDER = PLACEHOLDER_PREFIX + "test-run-secret"

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
                # agents-3cm4/agents-vsqa: assert key presence only, never dump env dict
                self.assertFalse(name in env)

    def test_engine_gets_only_its_own_model_auth(self):
        pi = child_environment(engine="pi", parent=parent_env())
        self.assertEqual(pi["ANTHROPIC_API_KEY"], "sk-ant")
        self.assertEqual(pi["GEMINI_API_KEY"], "gem")
        self.assertFalse("GITHUB_TOKEN" in pi)
        self.assertFalse("AWS_SECRET_ACCESS_KEY" in pi)
        self.assertFalse("SSH_AUTH_SOCK" in pi)

        claude = child_environment(engine="claude", parent=parent_env())
        self.assertEqual(claude["ANTHROPIC_API_KEY"], "sk-ant")
        self.assertFalse("GEMINI_API_KEY" in claude)
        self.assertFalse("GITHUB_TOKEN" in claude)

        deepseek = child_environment(engine="deepseek", parent=parent_env(
            DEEPSEEK_API_KEY="ds-key",
            FACTORY_DEFAULT_DEEPSEEK_BASE_URL="http://127.0.0.1:9",
        ))
        self.assertEqual(deepseek["DEEPSEEK_API_KEY"], "ds-key")
        self.assertEqual(deepseek["FACTORY_DEFAULT_DEEPSEEK_BASE_URL"], "http://127.0.0.1:9")
        self.assertFalse("ANTHROPIC_API_KEY" in deepseek)
        self.assertFalse("GITHUB_TOKEN" in deepseek)

    def test_unknown_engine_fails_closed(self):
        env = child_environment(engine="brand-new-engine", parent=parent_env())
        self.assertFalse("ANTHROPIC_API_KEY" in env)
        self.assertFalse("GEMINI_API_KEY" in env)
        self.assertEqual(env["PATH"], "/usr/bin")

    def test_github_sink_gets_a_token_and_nothing_else(self):
        for sink in ("github-issues", "github-issues,beads"):
            with self.subTest(sink=sink):
                env = child_environment(sink=sink, parent=parent_env())
                self.assertEqual(env["GH_TOKEN"], "ghs_ci_token")
                self.assertEqual(env["GITHUB_TOKEN"], "ghs_ci_token")
                self.assertFalse("AWS_SECRET_ACCESS_KEY" in env)
                self.assertFalse("ANTHROPIC_API_KEY" in env)

    def test_beads_alias_sinks_get_no_github_token(self):
        """agents-eyo: `both`/`all` are now aliases for beads and grant no GitHub token."""
        for sink in ("beads", "both", "all"):
            with self.subTest(sink=sink):
                env = child_environment(sink=sink, parent=parent_env())
                for name in GITHUB_TOKEN_VARS:
                    self.assertFalse(name in env)

    def test_other_sinks_get_no_github_token(self):
        for sink in ("file", "beads", None):
            with self.subTest(sink=sink):
                env = child_environment(sink=sink, parent=parent_env())
                for name in GITHUB_TOKEN_VARS:
                    self.assertFalse(name in env)

    def test_github_flag_adds_tokens(self):
        env = child_environment(github=True, parent=parent_env())
        self.assertEqual(env["GH_TOKEN"], "ghs_ci_token")
        self.assertFalse("ANTHROPIC_API_KEY" in env)

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
        self.assertFalse("ANTHROPIC_API_KEY" in declaring)

        plain = prepass_environment({"capabilities": {"requires": ["git"]}},
                                    parent=parent_env())
        self.assertFalse("GH_TOKEN" in plain)

    def test_a_failing_child_env_assertion_never_dumps_the_dict_or_tokens(self):
        """agents-97nq: this guard must FAIL if the assertions it guards are reverted.

        The first version typed a copy of the fixed pattern into its own body - it built a local
        ``poisoned_env`` and then asserted ``assertFalse("AWS_SECRET_ACCESS_KEY" in poisoned_env)``
        - so it proved nothing about the file it lives in. MEASURED by the reviewer: reverting the
        ~20 real assertions here to the leaking ``assertNotIn(k, env)`` form, which prints the whole
        environment dictionary, secrets and tokens included, when it fails, left the suite GREEN
        (Ran 36 tests ... OK). A guard that cannot fail on the defect it names is a false green.

        This version CALLS THE REAL TEST METHODS, the same shape as the sibling guard in
        tests/test_hermetic_env.py:31-54: a builder leaking one synthetic secret and one synthetic
        token is injected, each real test method is run against it, and every failure message is
        checked. In the fixed form the message is unittest's bare "False is not true"; in the
        leaking form it is "'AWS_SECRET_ACCESS_KEY' unexpectedly found in {...}" carrying the
        synthetic credential, so the revert turns this test RED.
        """
        leaking = dict(child_environment(sink="github-issues", parent=parent_env()),
                       AWS_SECRET_ACCESS_KEY="synthetic-secret-leak-marker",
                       ANTHROPIC_API_KEY="synthetic-anthropic-leak-marker")
        for method in ("test_github_sink_gets_a_token_and_nothing_else",
                       "test_unknown_engine_fails_closed"):
            with self.subTest(method=method):
                case = self.__class__(method)
                with mock.patch("tests.test_child_env.child_environment",
                                lambda **kwargs: dict(leaking)):
                    with self.assertRaises(AssertionError) as ctx:
                        getattr(case, method)()
                err_msg = str(ctx.exception)
                self.assertNotIn("synthetic-secret-leak-marker", err_msg,
                                 "leaked poisoned secret value in traceback")
                self.assertNotIn("synthetic-anthropic-leak-marker", err_msg,
                                 "leaked poisoned anthropic value in traceback")
                self.assertNotIn("ghs_ci_token", err_msg, "leaked child token value in traceback")

    def test_absent_variables_are_not_invented(self):
        self.assertEqual(child_environment(parent={"PATH": "/bin"}), {"PATH": "/bin"})

    def test_findings_child_resolves_a_pinned_tool_with_the_host_pins_file(self):
        """agents-dpt: the findings/promotion child must see the pins its parent verified.

        `lib/sinks/*` resolve `gh`/`bd` themselves. A pinned host keeps the pins behind
        FACTORY_TOOL_PINS, so a child without that variable cannot verify the tool it is about
        to run and fails closed — with less information than the parent that just verified the
        same file. `trusted_tools=True` is only for those children.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            fake_bd = tmp / "bd"
            fake_bd.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fake_bd.chmod(0o755)
            pins = tmp / "tools.pins.yaml"
            pins.write_text(f"bd:\n  path: {fake_bd}\n  sha256: "
                            f"{hashlib.sha256(fake_bd.read_bytes()).hexdigest()}\n",
                            encoding="utf-8")
            parent = {"PATH": tmpdir, "HOME": str(tmp), "FACTORY_TOOL_PINS": str(pins)}
            probe = ("import sys; sys.path.insert(0, %r); "
                     "from lib.tool_pins import resolve_tool, ToolPinError\n"
                     "try: print('RESOLVED', resolve_tool('bd'))\n"
                     "except ToolPinError as e: print('FAILED', e)\n") % str(ROOT)

            def resolve(pins_in_child):
                # The snapshot is the DISPATCHER's argument (agents-oq3j); the parent's own
                # FACTORY_TOOL_PINS is deliberately present and must not be what the child uses.
                env = child_environment(parent=parent, trusted_tools=pins_in_child,
                                        verified_pins=str(pins) if pins_in_child else None)
                out = subprocess.run([sys.executable, "-c", probe], env=env, text=True,
                                     capture_output=True, cwd=str(ROOT), timeout=60)
                return out.stdout.strip()

            self.assertEqual(resolve(True), f"RESOLVED {fake_bd}")
            self.assertTrue(resolve(False).startswith("FAILED"),
                            "without the flag the child must fail closed, not guess")
            # agents-3cm4 + agents-oq3j: check key presence only, never dump the child environment
            # dict. NEITHER pins name may appear without an explicit handoff, even though the parent
            # here carries the legacy one: the value is SET by the dispatcher, never inherited.
            for env in (child_environment(parent=parent),
                        child_environment(engine="pi", parent=parent),
                        child_environment(parent=parent, trusted_tools=True)):
                self.assertFalse("FACTORY_TOOL_PINS" in env)
                self.assertFalse("FACTORY_VERIFIED_TOOL_PINS" in env)

    def test_the_pins_handoff_is_set_by_the_dispatcher_and_never_inherited(self):
        """agents-oq3j, the property in the strongest available form: a pins file crosses to a child
        because the DISPATCHER put it in the environment it constructed, not because the child
        inherited a name. Both directions are asserted, because only the pair rules out each other's
        failure mode - a value that is not inherited cannot be conjured by the parent, and a value
        that was not handed over cannot be smuggled in by it.
        """
        handed = child_environment(parent={"HOME": "/tmp"}, trusted_tools=True,
                                   verified_pins="/somewhere/tool-pins.effective.yaml")
        self.assertEqual(handed["FACTORY_VERIFIED_TOOL_PINS"],
                         "/somewhere/tool-pins.effective.yaml")
        self.assertNotIn("FACTORY_TOOL_PINS", handed)

        hostile_parent = {"HOME": "/tmp",
                          "FACTORY_VERIFIED_TOOL_PINS": "/attacker/pins.yaml",
                          "FACTORY_TOOL_PINS": "/attacker/pins.yaml"}
        for env in (child_environment(parent=hostile_parent, trusted_tools=True),
                    child_environment(parent=hostile_parent, trusted_tools=True,
                                      verified_pins="/real/pins.yaml")):
            self.assertNotEqual(env.get("FACTORY_VERIFIED_TOOL_PINS"), "/attacker/pins.yaml",
                                "an inherited pins name must never substitute for the dispatcher's")
            self.assertNotIn("FACTORY_TOOL_PINS", env)

    def test_a_prepass_child_gets_the_same_handoff_as_a_sink_child(self):
        handed = prepass_environment({"name": "secret-scan"}, parent={"HOME": "/tmp"},
                                     verified_pins="/somewhere/tool-pins.effective.yaml")
        self.assertEqual(handed["FACTORY_VERIFIED_TOOL_PINS"],
                         "/somewhere/tool-pins.effective.yaml")
        self.assertNotIn("FACTORY_TOOL_PINS", handed)

    def test_findings_child_resolves_an_unpinned_tool_with_the_parent_opt_in(self):
        """agents-7ua: the sink child must inherit the parent's unpinned-tools opt-in.

        `FACTORY_ALLOW_UNPINNED_TOOLS=1` is a run-scoped widening the parent already applied
        when it resolved the tool. The findings/promotion child resolves the same tool itself,
        so without that variable its own `resolve_tool` fails closed even though the parent
        just resolved the same binary — the web-uplift halt. `trusted_tools=True` forwards it
        exactly like `FACTORY_TOOL_PINS`.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            fake_bd = tmp / "bd"
            fake_bd.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fake_bd.chmod(0o755)
            # No pins file: bd is UNPINNED, so only the explicit opt-in lets it resolve.
            parent = {"PATH": tmpdir, "HOME": str(tmp),
                      "FACTORY_ALLOW_UNPINNED_TOOLS": "1"}
            probe = ("import sys; sys.path.insert(0, %r); "
                     "from lib.tool_pins import resolve_tool, ToolPinError\n"
                     "try: print('RESOLVED', resolve_tool('bd'))\n"
                     "except ToolPinError as e: print('FAILED', e)\n") % str(ROOT)

            def resolve(child):
                env = child_environment(parent=parent, trusted_tools=child)
                out = subprocess.run([sys.executable, "-c", probe], env=env, text=True,
                                     capture_output=True, cwd=str(ROOT), timeout=60)
                return env, out.stdout.strip()

            with_optin, out = resolve(True)
            self.assertEqual(with_optin["FACTORY_ALLOW_UNPINNED_TOOLS"], "1")
            self.assertEqual(out, f"RESOLVED {fake_bd}")

            # The opt-in is only for the children that resolve a trusted tool themselves.
            without, out = resolve(False)
            self.assertFalse("FACTORY_ALLOW_UNPINNED_TOOLS" in without)
            self.assertTrue(out.startswith("FAILED"))

            self.assertFalse("FACTORY_ALLOW_UNPINNED_TOOLS" in child_environment(parent=parent))
            self.assertFalse("FACTORY_ALLOW_UNPINNED_TOOLS" in child_environment(engine="pi", parent=parent))

    def test_findings_child_opt_in_never_leaks_secrets(self):
        """agents-7ua: forwarding the unpinned opt-in must not widen the secret boundary."""
        parent = parent_env(FACTORY_ALLOW_UNPINNED_TOOLS="1")
        env = child_environment(sink="beads", trusted_tools=True, parent=parent)
        self.assertEqual(env["FACTORY_ALLOW_UNPINNED_TOOLS"], "1")
        for name in list(SECRETS) + ["ANTHROPIC_API_KEY", "GEMINI_API_KEY"]:
            with self.subTest(name=name):
                self.assertFalse(name in env)

    def test_proxy_and_ca_vars_not_forwarded_by_default(self):
        # agents-5d9: a poisoned operator proxy/CA must not reach a child by default.
        parent = parent_env(HTTP_PROXY="http://attacker:8080",
                            HTTPS_PROXY="http://attacker:8080",
                            ALL_PROXY="socks5://attacker:1080",
                            NO_PROXY="",
                            SSL_CERT_FILE="/home/operator/.certs/attacker-ca.pem",
                            NODE_EXTRA_CA_CERTS="/home/operator/.certs/attacker-ca.pem")
        env = child_environment(parent=parent)
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                     "http_proxy", "https_proxy", "all_proxy", "no_proxy",
                     "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS",
                     "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
            with self.subTest(name=name):
                self.assertFalse(name in env)

    def test_proxy_vars_forwarded_only_when_proxied(self):
        # agents-5d9: an UNSANDBOXED child (proxied=True) inherits the operator's proxy.
        parent = parent_env(HTTP_PROXY="http://corp-proxy:3128",
                            HTTPS_PROXY="http://corp-proxy:3128",
                            NO_PROXY="localhost,127.0.0.1")
        self.assertFalse("HTTP_PROXY" in child_environment(parent=parent))
        proxied = child_environment(parent=parent, proxied=True)
        self.assertEqual(proxied["HTTP_PROXY"], "http://corp-proxy:3128")
        self.assertEqual(proxied["HTTPS_PROXY"], "http://corp-proxy:3128")
        self.assertEqual(proxied["NO_PROXY"], "localhost,127.0.0.1")

    def test_ca_bundle_never_forwarded_even_when_proxied(self):
        # agents-5d9: the operator's CA bundle is a TLS trust decision, never inherited —
        # the child uses the system trust store regardless of `proxied`.
        parent = parent_env(SSL_CERT_FILE="/etc/ssl/operator-ca.pem",
                            NODE_EXTRA_CA_CERTS="/etc/ssl/operator-ca.pem")
        for env in (child_environment(parent=parent),
                    child_environment(parent=parent, proxied=True)):
            with self.subTest(env=env):
                self.assertFalse("SSL_CERT_FILE" in env)
                self.assertFalse("NODE_EXTRA_CA_CERTS" in env)

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
                                broker_urls={"anthropic": url},
                                broker_placeholder=TEST_PLACEHOLDER)
        self.assertEqual(env["ANTHROPIC_API_KEY"], TEST_PLACEHOLDER)
        self.assertEqual(env["ANTHROPIC_BASE_URL"], url)
        self.assertFalse("sk-ant" in env.values())  # the real key is gone

    def test_every_secret_var_of_a_brokered_provider_is_stripped(self):
        parent = parent_env(ANTHROPIC_AUTH_TOKEN="auth-tok", CLAUDE_CODE_OAUTH_TOKEN="oauth-tok")
        env = child_environment(engine="claude", parent=parent,
                                broker_urls={"anthropic": "http://127.0.0.1:1/proxy/anthropic"},
                                broker_placeholder=TEST_PLACEHOLDER)
        self.assertFalse("ANTHROPIC_AUTH_TOKEN" in env)
        self.assertFalse("CLAUDE_CODE_OAUTH_TOKEN" in env)
        self.assertEqual(env["ANTHROPIC_API_KEY"], TEST_PLACEHOLDER)

    def test_unbrokered_providers_keep_their_real_keys(self):
        env = child_environment(engine="pi", parent=parent_env(),
                                broker_urls={"anthropic": "http://127.0.0.1:1/proxy/anthropic"},
                                broker_placeholder=TEST_PLACEHOLDER)
        self.assertEqual(env["OPENAI_API_KEY"], "op")   # not brokered -> untouched
        self.assertEqual(env["GEMINI_API_KEY"], "gem")

    def test_openai_and_google_brokering(self):
        env = child_environment(engine="pi", parent=parent_env(), broker_urls={
            "openai": "http://127.0.0.1:1/proxy/openai",
            "google": "http://127.0.0.1:1/proxy/google",
        }, broker_placeholder=TEST_PLACEHOLDER)
        self.assertEqual(env["OPENAI_API_KEY"], TEST_PLACEHOLDER)
        self.assertEqual(env["OPENAI_BASE_URL"], "http://127.0.0.1:1/proxy/openai")
        self.assertEqual(env["GEMINI_API_KEY"], TEST_PLACEHOLDER)
        self.assertEqual(env["GOOGLE_GEMINI_BASE_URL"], "http://127.0.0.1:1/proxy/google")
        self.assertFalse("op" in env.values())
        self.assertFalse("gem" in env.values())

    def test_no_broker_urls_leaves_the_env_unchanged(self):
        with_broker = child_environment(engine="pi", parent=parent_env())
        self.assertEqual(with_broker["ANTHROPIC_API_KEY"], "sk-ant")  # real key, as today
        self.assertFalse("ANTHROPIC_BASE_URL" in with_broker)

    def test_an_unmapped_provider_fails_closed(self):
        # A provider the broker advertised but child_env doesn't map must FAIL CLOSED,
        # otherwise its real key would survive in the sandboxed environment.
        with self.assertRaisesRegex(ContainmentError, "fail closed: broker provided URL for unmapped provider 'unmapped'"):
            child_environment(engine="pi", parent=parent_env(UNMAPPED_API_KEY="key"),
                              broker_urls={"unmapped": "http://127.0.0.1:1/proxy/unmapped"},
                              broker_placeholder=TEST_PLACEHOLDER)

    def test_deepseek_and_openrouter_are_brokered(self):
        # agents-2x6: under --unshare-net a sandboxed engine cannot dial a provider directly,
        # so every provider pi can use must be brokerable. deepseek and openrouter joined
        # BROKER_PROVIDERS; like anthropic/openai/google their key becomes the placeholder and
        # they get a base URL, so no real credential crosses into the sandboxed environ.
        env = child_environment(engine="pi", parent=parent_env(
            DEEPSEEK_API_KEY="ds-key", OPENROUTER_API_KEY="or-key"), broker_urls={
            "deepseek": "http://127.0.0.1:1/proxy/deepseek",
            "openrouter": "http://127.0.0.1:1/proxy/openrouter",
        }, broker_placeholder=TEST_PLACEHOLDER)
        self.assertEqual(env["DEEPSEEK_API_KEY"], TEST_PLACEHOLDER)
        self.assertEqual(env["DEEPSEEK_BASE_URL"], "http://127.0.0.1:1/proxy/deepseek")
        self.assertEqual(env["OPENROUTER_API_KEY"], TEST_PLACEHOLDER)
        self.assertEqual(env["OPENROUTER_BASE_URL"], "http://127.0.0.1:1/proxy/openrouter")
        self.assertFalse("ds-key" in env.values())
        self.assertFalse("or-key" in env.values())

    def test_brokering_fails_closed_without_the_running_brokers_placeholder(self):
        # agents-28nn round 7: the broker refuses any request that does not present the
        # run's per-run secret, so a swap that cannot name it would hand the engine an
        # env whose model calls can never authenticate. Fail closed at the swap.
        with self.assertRaisesRegex(ContainmentError, "per-run placeholder"):
            child_environment(engine="pi", parent=parent_env(),
                              broker_urls={"anthropic": "http://127.0.0.1:1/proxy/anthropic"})

    def test_the_placeholder_is_not_credential_shaped(self):
        # The whole point: the value in the sandboxed environ must not look like a key, so a
        # prompt-injected engine reading /proc/self/environ finds nothing worth exfiltrating.
        # The prefix is the constant part (the per-run random suffix is generated by the
        # broker; its uniqueness is pinned in tests/test_credential_broker.py).
        self.assertFalse(re.search(r"^(sk-|AIza|ghp_|ghs_|xox)", PLACEHOLDER_PREFIX))
        self.assertNotIn("KEY", PLACEHOLDER_PREFIX.upper().replace("-", "").replace("_", ""))

    def test_broker_provider_table_is_consistent_with_the_broker(self):
        # child_env's BROKER_ENV_CONFIGS and credential_broker's PROVIDERS must name the same
        # providers, or a base URL would be set for a provider the broker cannot route.
        from lib.credential_broker import PROVIDERS as BROKER_SIDE
        self.assertEqual(set(BROKER_ENV_CONFIGS), set(BROKER_SIDE))

    def test_pi_credentials_are_covered_by_broker_secret_vars(self):
        # Every credential passed to pi must have a broker entry so a real key
        # never silently leaks into a sandboxed env without being brokered (agents-8k9).
        self.assertTrue(set(ENGINE_CREDENTIALS["pi"]) <= {var for _, _, sv in BROKER_ENV_CONFIGS.values() for var in sv})


class TestSurveyEgressCredentials(unittest.TestCase):
    """agents-8xei: survey_egress_credentials performs an active key and model survey
    to determine whether egress filtering can be enabled without breaking model calls."""

    def test_pi_with_brokerable_model_and_brokerable_creds_passes(self):
        active, reason = survey_egress_credentials("pi", model="deepseek/deepseek-flash",
                                                   parent={"DEEPSEEK_API_KEY": "sk-test"})
        self.assertTrue(active)
        self.assertIsNone(reason)

    def test_pi_with_unbrokerable_model_fails_survey(self):
        active, reason = survey_egress_credentials("pi", model="mistral/mistral-large")
        self.assertFalse(active)
        self.assertIn("mistral", str(reason))

    def test_pi_with_unbrokerable_ollama_fails_survey(self):
        active, reason = survey_egress_credentials("pi", model="ollama/llama3")
        self.assertFalse(active)
        self.assertIn("ollama", str(reason))

    def test_unsandboxed_engine_fails_survey(self):
        active, reason = survey_egress_credentials("claude", parent={"ANTHROPIC_API_KEY": "sk-ant"})
        self.assertFalse(active)
        self.assertIn("claude", str(reason))

    def test_engine_with_unbrokerable_credentials_fails_survey(self):
        active, reason = survey_egress_credentials("claude", parent={"CLAUDE_CODE_USE_BEDROCK": "1"})
        self.assertFalse(active)


if __name__ == "__main__":
    unittest.main()
