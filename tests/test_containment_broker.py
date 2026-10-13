"""Containment: the credential broker's placeholders and keyless provider wiring.

Split out of tests/test_containment.py (agents-ryw9); TestDispatcher keeps the
policy/admission subset. The harness stays in tests/containment_harness.py, and the
header below is copied verbatim from the family modules agents-3iog split.
"""

import hashlib
import http.server
import importlib.machinery
import importlib.util
import json
import os
os.environ.setdefault("FACTORY_ALLOW_UNPINNED_TOOLS", "1")  # agents-7bj: tests use unpinned stub tools
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.containment import (  # noqa: E402
    ENGINE_READ_SCOPE, ENGINE_TOOL_POLICIES, GRANTABLE_POLICIES, READ_ONLY, WORKTREE_WRITE,
    WORKTREE_WRITE_UNVERIFIED_ENGINES, ContainmentError, banner_lines,
    budget_note, check_engine, downgrade_network_to_withheld, egress_allowlist, load_policy,
    policy_record,
)
from lib.sandbox import SANDBOXED_ENGINES, sandbox_available, sandbox_command  # noqa: E402
from lib.credential_broker import PLACEHOLDER_PREFIX  # noqa: E402
from lib.child_env import child_environment  # noqa: E402
from lib import egress_proxy  # noqa: E402
from lib import containment as containment_module  # noqa: E402
from lib import sandbox as sandbox_module  # noqa: E402
from lib.egress_proxy import EgressProxy  # noqa: E402

# Whether THIS host can run bubblewrap. The confinement acceptance test needs it; the
# fail-closed and opt-in tests simulate its absence with a broken bwrap on PATH, so they run
# anywhere (review P0, agents-9n7).
_BWRAP = sandbox_available()

_loader = importlib.machinery.SourceFileLoader("factory_cli_pnu", str(ROOT / "factory"))
_spec = importlib.util.spec_from_loader("factory_cli_pnu", _loader)
factory_cli = importlib.util.module_from_spec(_spec)
_loader.exec_module(factory_cli)

STUB_REPORT = "echo '{\"summary\":\"stub\",\"scanned_files\":0,\"findings\":[]}'\n"


def manifest(**overrides):
    cfg = {
        "name": "probe",
        "containment": "t0-readonly",
        "capabilities": {"write": False, "network": False, "browser": False, "requires": []},
        "budget": {"max_minutes": 5},
    }
    cfg.update(overrides)
    return cfg

from tests import containment_harness as harness

# TestDispatcher's tests read TestAdapters.ENGINE_BINARY. Import the MODULE, not the name:
# a class imported into this namespace would be collected by discovery here as well, which is
# the duplicate-run shape this split exists to remove (agents-3iog).
from tests import test_containment_adapters as adapters

class TestBrokerCredentials(harness.ContainmentHarness):
    """The credential broker's placeholders and keyless provider wiring."""


    def test_an_unknown_agent_class_refuses_before_any_run(self):
        """An unknown class fails closed on every host, including without bubblewrap."""
        self.agent("name: probe\nclass: writer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        res = self.factory("pi")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("unknown agent class", res.stderr + res.stdout)
        self.assertEqual(self.run_dirs(), [], "a refused run must leave no run directory")


    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_a_missing_agent_class_defaults_to_observer(self):
        """A missing class runs as an observer when the OS sandbox is runnable."""
        self.agent("name: probe\ncontainment: t0-readonly\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.stub_line("POLICY:"), READ_ONLY)


    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_a_sandboxed_engine_gets_a_broker_placeholder_not_the_real_key(self):
        """agents-8h4 acceptance: a sandboxed engine must not carry the operator's real API key.
        With a real key in the dispatcher's environment, run_agent starts the localhost
        credential broker and hands the engine a PLACEHOLDER + the broker base URL instead, so
        the engine's own /proc/self/environ — the leak vector THREAT_MODEL §6.1 names — holds no
        credential shape, while the broker (host side) still injects the real key upstream. This
        proves the key is stripped inside the REAL bwrap sandbox and that the engine can reach
        the broker through the sandbox's shared host network. Gated on bwrap: brokering applies
        only to an engine_sandboxed run."""
        real_key = "sk-ant-REALKEY-do-not-leak"
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "echo \"ENVKEY:${ANTHROPIC_API_KEY:-unset}\"\n"
            "echo \"ENVBASE:${ANTHROPIC_BASE_URL:-unset}\"\n"
            # The leak vector: grep the engine's OWN /proc/self/environ for the real key.
            "if tr '\\0' '\\n' < /proc/self/environ | grep -qF '" + real_key + "'; then\n"
            "  echo PROCENV:LEAKED\n"
            "else\n"
            "  echo PROCENV:CLEAN\n"
            "fi\n"
            # Reach the broker over loopback. agents-28nn round 7 (the verdict's P0): the
            # listener now AUTHENTICATES — an unauthenticated local call is refused 403
            # before any upstream hop, and only the run's per-run placeholder (which the
            # engine carries as ANTHROPIC_API_KEY) is served; the root path then 404s
            # before any upstream hop, so this still needs no real provider network.
            "PORT=${ANTHROPIC_BASE_URL#http://127.0.0.1:}; PORT=${PORT%%/*}\n"
            "if exec 3<>/dev/tcp/127.0.0.1/$PORT 2>/dev/null; then\n"
            "  printf 'GET / HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\nConnection: close\\r\\n\\r\\n' >&3\n"
            "  read -r LINE <&3 && echo \"NOAUTHLINE:$LINE\"\n"
            "  exec 3>&-\n"
            "else\n"
            "  echo NOAUTHLINE:UNREACHABLE\n"
            "fi\n"
            "if exec 3<>/dev/tcp/127.0.0.1/$PORT 2>/dev/null; then\n"
            "  printf \"GET / HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\nx-api-key: ${ANTHROPIC_API_KEY}\\r\\nConnection: close\\r\\n\\r\\n\" >&3\n"
            "  read -r LINE <&3 && echo \"BROKERLINE:$LINE\"\n"
            "  exec 3>&-\n"
            "else\n"
            "  echo BROKERLINE:UNREACHABLE\n"
            "fi\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        # A read-only observer: brokering applies to any sandboxed engine, no write grant needed.
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "capabilities: {}\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi", {"ANTHROPIC_API_KEY": real_key,
                                  "FACTORY_MODEL": "anthropic/claude-3-5-sonnet"})
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        # The engine's environ holds the run's per-run placeholder, never the real key.
        self.assertTrue(self.stub_line("ENVKEY:").startswith(PLACEHOLDER_PREFIX),
                        f"the engine must carry a per-run placeholder, got {self.stub_line('ENVKEY:')!r}")
        self.assertEqual(self.stub_line("PROCENV:"), "CLEAN",
                         "the real key must not appear in the sandboxed engine's /proc/self/environ")
        base = self.stub_line("ENVBASE:")
        self.assertTrue(base.startswith("http://127.0.0.1:") and base.endswith("/proxy/anthropic"),
                        f"the engine must be pointed at the localhost broker, got {base!r}")
        # agents-28nn round 7 (the verdict's P0): an UNAUTHENTICATED local call is refused
        # (403 before any upstream hop) ...
        self.assertIn("403", self.stub_line("NOAUTHLINE:"),
                      "the broker must refuse a request that does not present the run's secret")
        # ... and the engine, holding the placeholder, reaches the broker through the
        # sandbox network: a 404 on the root path proves the listener answered (no upstream
        # hop involved).
        self.assertIn("404", self.stub_line("BROKERLINE:"),
                      "the sandboxed engine must reach the broker over loopback")
        record = json.loads((self.run_dirs()[0] / "policy.json").read_text(encoding="utf-8"))
        self.assertTrue(record["granted"]["os_sandbox"]["engine_sandboxed"])
        self.assertNotIn("env-credentials", record["not_enforced"],
                         "the actual brokered engine env must update the trusted record")
        # agents-3z8: policy.json lists ONLY the run's effective model provider (anthropic),
        # not an unrestricted fail-open list of all host credentials.
        self.assertEqual(record["granted"]["credential_broker"]["providers"],
                         ["anthropic"])
        self.assertNotIn(real_key, json.dumps(record))


    def test_an_unsandboxed_engine_gets_a_broker_placeholder_not_the_raw_key(self):
        """agents-28nn round 6, review P1 — the WORST of the inverted-polarity shapes:
        the credential broker used to start ONLY if engine_sandboxed(engine), so the
        LESS-confined unsandboxed path handed the engine the RAW API KEY where the
        confined path hands a placeholder. THE LESS-CONFINED PATH MUST NOT RECEIVE MORE
        THAN THE MORE-CONFINED PATH (the rule on lib/sandbox.py's engine_sandboxed).

        Forces the unsandboxed path on a sandboxed host (a pins file with NO bwrap entry
        fails the probe closed; FACTORY_ALLOW_UNSANDBOXED=1 + a trusted private target
        permits the run) with a real key in the dispatcher's environment, and asserts the
        engine's environ holds the PLACEHOLDER + the broker's loopback URL and NEVER the
        raw key, that the broker answers on loopback, and that policy.json records the
        broker's enforcement rather than the env-credentials residual. The "Sandbox: NOT
        enforced" banner assertion proves the test exercised the path it claims to cover.

        MUTATION PROOF (performed, not asserted): re-gating the broker on
        engine_sandboxed(engine) turns this red — ENVKEY is the raw key, PROCENV leaks,
        and policy.json gains no credential_broker grant.
        """
        real_key = "sk-ant-REALKEY-do-not-leak-unsandboxed"
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "echo \"ENVKEY:${ANTHROPIC_API_KEY:-unset}\"\n"
            "echo \"ENVBASE:${ANTHROPIC_BASE_URL:-unset}\"\n"
            # The leak vector: grep the engine's OWN /proc/self/environ for the real key.
            "if tr '\\0' '\\n' < /proc/self/environ | grep -qF '" + real_key + "'; then\n"
            "  echo PROCENV:LEAKED\n"
            "else\n"
            "  echo PROCENV:CLEAN\n"
            "fi\n"
            # Reach the broker over loopback. agents-28nn round 7 (the verdict's P0): the
            # listener now AUTHENTICATES — an unauthenticated local call is refused 403
            # before any upstream hop, and only the run's per-run placeholder (which the
            # engine carries as ANTHROPIC_API_KEY) is served; the root path then 404s
            # before any upstream hop, so this still needs no real provider network.
            "PORT=${ANTHROPIC_BASE_URL#http://127.0.0.1:}; PORT=${PORT%%/*}\n"
            "if exec 3<>/dev/tcp/127.0.0.1/$PORT 2>/dev/null; then\n"
            "  printf 'GET / HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\nConnection: close\\r\\n\\r\\n' >&3\n"
            "  read -r LINE <&3 && echo \"NOAUTHLINE:$LINE\"\n"
            "  exec 3>&-\n"
            "else\n"
            "  echo NOAUTHLINE:UNREACHABLE\n"
            "fi\n"
            "if exec 3<>/dev/tcp/127.0.0.1/$PORT 2>/dev/null; then\n"
            "  printf \"GET / HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\nx-api-key: ${ANTHROPIC_API_KEY}\\r\\nConnection: close\\r\\n\\r\\n\" >&3\n"
            "  read -r LINE <&3 && echo \"BROKERLINE:$LINE\"\n"
            "  exec 3>&-\n"
            "else\n"
            "  echo BROKERLINE:UNREACHABLE\n"
            "fi\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "capabilities: {}\nbudget: {max_minutes: 1}\n")
        self.trusted_target("trusted")
        # Pin the stub engine by path + content; OMIT bwrap so the probe fails closed and
        # the trusted-target opt-in takes the UNSANDBOXED path on this sandboxed host.
        digest = hashlib.sha256(stub.read_bytes()).hexdigest()
        pins = self.root / "tools.pins.yaml"
        pins.write_text(f"pi:\n  path: {stub}\n  sha256: {digest}\n", encoding="utf-8")
        res = self.factory("pi", {"ANTHROPIC_API_KEY": real_key,
                                  "FACTORY_MODEL": "anthropic/claude-3-5-sonnet",
                                  "FACTORY_ALLOW_UNSANDBOXED": "1",
                                  "FACTORY_ALLOW_UNPINNED_TOOLS": "0",
                                  "FACTORY_TOOL_PINS": str(pins)},
                           target_arg="trusted")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("Sandbox:     NOT enforced", res.stdout,
                      "the test must EXERCISE the unsandboxed path: " + res.stdout)
        # The engine's environ holds the run's per-run placeholder, never the real key — the same
        # guarantee the sandboxed path delivers (the less-confined path must not receive
        # more).
        self.assertTrue(self.stub_line("ENVKEY:").startswith(PLACEHOLDER_PREFIX),
                        f"the engine must carry a per-run placeholder, got {self.stub_line('ENVKEY:')!r}")
        self.assertEqual(self.stub_line("PROCENV:"), "CLEAN",
                         "the real key must not appear in the unsandboxed engine's "
                         "/proc/self/environ")
        base = self.stub_line("ENVBASE:")
        self.assertTrue(base.startswith("http://127.0.0.1:") and base.endswith("/proxy/anthropic"),
                        f"the engine must be pointed at the localhost broker, got {base!r}")
        # agents-28nn round 7 (the verdict's P0, the CONSTRUCTED surface): on this path the
        # broker's loopback is the HOST's — an unauthenticated local call must be refused
        # (403 before any upstream hop) ...
        self.assertIn("403", self.stub_line("NOAUTHLINE:"),
                      "on the unsandboxed path the broker sits on the host's shared loopback; "
                      "a request without the run's secret must be refused")
        # ... while the engine, holding the run's placeholder, is served.
        self.assertIn("404", self.stub_line("BROKERLINE:"),
                      "the unsandboxed engine must reach the broker over loopback")
        record = json.loads((self.run_dirs()[0] / "policy.json").read_text(encoding="utf-8"))
        self.assertNotIn("env-credentials", record["not_enforced"],
                         "the brokered engine env must update the record on this path too")
        self.assertEqual(record["granted"]["credential_broker"]["providers"],
                         ["anthropic"])
        self.assertIn("os-sandbox", record["not_enforced"],
                      "the sandbox is genuinely absent — the record must keep saying so")
        self.assertNotIn(real_key, json.dumps(record))


    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_default_pi_run_brokers_only_effective_model_provider(self):
        """agents-3z8: a default pi run's policy.json lists ONLY the effective model's provider
        (deepseek), not an unrestricted allowlist of all host credentials."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "capabilities: {}\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi", {
            "ANTHROPIC_API_KEY": "sk-ant-secret",
            "OPENAI_API_KEY": "sk-openai-secret",
            "GEMINI_API_KEY": "gem-secret",
        })
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        record = json.loads((self.run_dirs()[0] / "policy.json").read_text(encoding="utf-8"))
        self.assertTrue(record["granted"]["os_sandbox"]["engine_sandboxed"])
        # Only deepseek (the DEFAULT_PI_MODEL provider) must be brokered, never all host credentials!
        self.assertEqual(record["granted"]["credential_broker"]["providers"], ["deepseek"])


    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_sandboxed_engine_cross_provider_request_returns_403(self):
        """agents-3z8 [P2]: a sandboxed engine attempting cross-provider egress through
        the credential broker receives HTTP 403 Forbidden inside real bubblewrap sandbox."""
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "PORT=${ANTHROPIC_BASE_URL#http://127.0.0.1:}; PORT=${PORT%%/*}\n"
            "if exec 3<>/dev/tcp/127.0.0.1/$PORT 2>/dev/null; then\n"
            "  printf 'POST /proxy/openai/v1/chat/completions HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\nContent-Length: 2\\r\\n\\r\\n{}' >&3\n"
            "  read -r STATUS_LINE <&3\n"
            "  echo \"RESP_STATUS:$STATUS_LINE\"\n"
            "  exec 3>&-\n"
            "else\n"
            "  echo RESP_STATUS:UNREACHABLE\n"
            "fi\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "capabilities: {}\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi", {
            "ANTHROPIC_API_KEY": "sk-ant-test",
            "OPENAI_API_KEY": "sk-openai-secret",
            "FACTORY_MODEL": "anthropic/claude-3-5-sonnet",
        })
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        resp_line = self.stub_line("RESP_STATUS:")
        self.assertIn("403", resp_line,
                      f"cross-provider broker request inside sandbox must be 403 Forbidden, got {resp_line!r}")


    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_a_sandboxed_pi_engine_gets_the_keyless_broker_provider_config(self):
        """agents-854: pi ignores *_BASE_URL env, so the keyless broker routing must reach it as
        a models.json in its (redirected) agent directory, bound writable into the sandbox. The
        dispatcher wires PI_CODING_AGENT_DIR + FACTORY_MODEL and writes the provider override."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "capabilities: {}\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        # The adapter names the keyless model explicitly (not pi's Anthropic default).
        argv = self.stub_line("ARGV:").split()
        self.assertIn("--model", argv)
        self.assertEqual(argv[argv.index("--model") + 1], "deepseek/deepseek-flash")
        # The agent directory is redirected to a per-run config dir…
        agent_dir = self.stub_line("AGENTDIR:")
        self.assertTrue(agent_dir.startswith("/tmp/factory-pi-"), agent_dir)
        # …which holds the broker-routed provider override, readable inside the sandbox.
        models = self.stub_line("MODELSJSON:")
        self.assertIn("proxy/deepseek", models)
        self.assertIn(f'"apiKey": "{PLACEHOLDER_PREFIX}', models)
        self.assertIn("openai-completions", models)


    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_the_keyless_pi_wiring_is_provider_agnostic(self):
        """agents-854/agents-0ld: the keyless wiring is not deepseek-specific. Selecting a
        different keyless provider (kimi, an Anthropic-style managed endpoint) must wire THAT
        provider's broker route, api type AND model ids, so `--model kimi/k3` resolves even
        though pi's bundled registry has no provider named `kimi` (it is `kimi-coding`)."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "capabilities: {}\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi", {"FACTORY_MODEL": "kimi/k3"})
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        argv = self.stub_line("ARGV:").split()
        self.assertEqual(argv[argv.index("--model") + 1], "kimi/k3")
        models = self.stub_line("MODELSJSON:")
        self.assertIn("proxy/kimi", models)
        self.assertIn("anthropic-messages", models)
        self.assertNotIn("deepseek", models)
        self.assertIn('"models"', models)
        self.assertIn('"k3"', models)
        self.assertIn('"k3-256k"', models)
        self.assertIn('"kimi-for-coding"', models)

if __name__ == "__main__":
    unittest.main()
