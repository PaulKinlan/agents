"""Containment: the engine credential path (agents-28nn round 5).

Split from tests/test_containment.py (agents-3iog). This is the consumer of the
checked-in attack payload tests/fixtures/fake_engine.sh, so the `tests/fixtures/*`
fast-gate arm names THIS file: 4 tests, not 58 (it no longer re-runs the
harness's 54 tests, agents-3iog).
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

class TestEngineCredentialPinning(harness.ContainmentHarness):
    """agents-28nn round 5, review P0 — the DEMONSTRATED credential exfiltration.

    The adapter is the LAST GRANTER BEFORE THE KEY: it hands the run's model credentials
    to whatever binary it executes, so an unpinned engine is an EXFILTRATION PATH, not
    merely an unverified binary. The round-4 reviewer proved it by construction: a fake
    `pi` planted first on PATH, run via `factory run --engine pi` under the trusted-target
    FACTORY_ALLOW_UNSANDBOXED opt-in with ANTHROPIC_API_KEY set, EXECUTED and dumped the
    environment — key included — into model_output.txt.

    The attack payload is CHECKED IN as tests/fixtures/fake_engine.sh, so these tests
    contain the attack rather than describing one, and the assertion sits at the point the
    secret should never arrive — what the fake RECEIVED — not at an exit code (a fake that
    dumps the environment and then fails would pass a nonzero-exit assertion while the
    leak stands). agents-28nn round 6 (review P2) made the assertion SOUND: it cannot sit
    on the file's EXISTENCE, because the adapter's shell redirection (`> "$OUTPUT_FILE"`,
    lib/adapters/pi.sh) creates model_output.txt BEFORE the engine executes — a missing
    or failing engine still leaves the file, so existence is not execution. The assertion
    is on the file's CONTENT:

    * the attack arm asserts no run artefact's content carries the dump marker or the
      secret — the fake never executed and the credential never moved;
    * the control arm pins the SAME payload and asserts the run succeeds AND the dump
      PROVES DELIVERY — the credential-bearing environment reached the executed engine.
      Since round 6 the broker runs on the unsandboxed path too (THE LESS-CONFINED PATH
      MUST NOT RECEIVE MORE THAN THE MORE-CONFINED PATH), so what the pinned engine
      receives is the broker PLACEHOLDER + loopback base URL (credential ACCESS, live end
      to end), and the raw key must NOT appear. Only the pin gates execution.

    MUTATION PROOF, both directions (performed, not asserted): dropping the engine
    binaries from TRUSTED_TOOLS turns the attack arm red (the fake resolves, executes and
    its dump's CONTENT carries the marker); dropping the dispatcher's FACTORY_ENGINE_BIN
    wiring turns the control arm red (the adapter refuses, nothing is delivered).
    """

    SECRET = "sk-ant-EXFIL-CANARY-28nn"
    FIXTURE = ROOT / "tests" / "fixtures" / "fake_engine.sh"

    def _plant_fake_engine(self, name="pi"):
        """Install the checked-in attack payload as an engine namesake FIRST on PATH."""
        evil = self.root / "evilbin"
        evil.mkdir(exist_ok=True)
        fake = evil / name
        shutil.copyfile(self.FIXTURE, fake)
        fake.chmod(0o755)
        return evil, fake

    def _attack_env(self, evil, extra=None):
        env = {"PATH": f"{evil}{os.pathsep}{self.bin}{os.pathsep}/usr/bin:/bin",
               "FACTORY_ALLOW_UNSANDBOXED": "1",
               # The dev/test opt-in must NOT rescue resolution: this is the pinned-host
               # posture the attack ran under.
               "FACTORY_ALLOW_UNPINNED_TOOLS": "0",
               "ANTHROPIC_API_KEY": self.SECRET}
        env.update(extra or {})
        return env

    def _model_outputs(self):
        """The model_output.txt files that exist. EXISTENCE IS NOT EXECUTION (agents-28nn
        round 6, review P2): the adapter's shell redirection creates the file BEFORE the
        engine executes, so a missing or failing engine still leaves one — assert on
        CONTENT, never on the file being there."""
        return [run / "model_output.txt" for run in self.run_dirs()
                if (run / "model_output.txt").exists()]

    def _assert_no_dump_received_the_secret(self):
        """The sound leak assertion: no run artefact's CONTENT carries the fake's dump
        marker or the secret — whatever files exist."""
        for output in self._model_outputs():
            content = output.read_text(encoding="utf-8", errors="replace")
            self.assertNotIn("FAKE ENGINE ENVIRONMENT DUMP", content,
                             f"the fake engine EXECUTED and dumped the environment: {output}")
            self.assertNotIn(self.SECRET, content,
                             f"the credential reached a run artefact: {output}")

    def test_a_path_planted_fake_engine_never_receives_the_credential(self):
        """The constructed attack, retained: an UNPINNED namesake first on PATH must be
        refused BEFORE it executes — the assertion is that the credential never reaches
        it, not that the run exits nonzero."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        self.trusted_target("trusted")
        evil, _fake = self._plant_fake_engine()
        res = self.factory("pi", self._attack_env(evil), target_arg="trusted")
        self.assertNotEqual(res.returncode, 0,
                            "an unpinned engine must refuse the run, not exit clean")
        self.assertIn("not pinned", res.stderr,
                      "the refusal must name the pin cause, not some other gate: "
                      + res.stderr)
        self._assert_no_dump_received_the_secret()

    def test_a_pinned_engine_is_delivered_the_credential(self):
        """The control: the SAME payload, pinned by its sha256, runs and its environment
        dump PROVES DELIVERY — since round 6 the broker runs on the unsandboxed path too,
        so the executed engine receives the broker PLACEHOLDER + loopback base URL
        (credential access, live end to end) and NEVER the raw key. This is also the
        mutation trap for the delivery half: remove the dispatcher's FACTORY_ENGINE_BIN
        wiring and the adapter refuses, the dump never appears, and this test goes red."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        self.trusted_target("trusted")
        evil, fake = self._plant_fake_engine()
        digest = hashlib.sha256(fake.read_bytes()).hexdigest()
        pins = self.root / "tools.pins.yaml"
        pins.write_text(f"pi:\n  sha256: {digest}\n", encoding="utf-8")
        res = self.factory("pi", self._attack_env(
            evil, {"FACTORY_TOOL_PINS": str(pins)}), target_arg="trusted")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        outputs = self._model_outputs()
        self.assertEqual(len(outputs), 1)
        dump = outputs[0].read_text(encoding="utf-8")
        self.assertIn("FAKE ENGINE ENVIRONMENT DUMP", dump,
                      "the pinned payload must have EXECUTED and dumped its environment")
        self.assertIn(PLACEHOLDER_PREFIX, dump,
                      "the pinned engine must have RECEIVED the brokered credential shape — "
                      "otherwise the attack arm proves nothing about delivery")
        self.assertIn("http://127.0.0.1:", dump,
                      "the broker's loopback base URL must reach the engine — the credential "
                      "path is live, so only the pin gates execution")
        self.assertNotIn(self.SECRET, dump,
                         "the raw key must NOT reach the engine env on ANY path "
                         "(agents-28nn round 6: the broker is not sandbox-gated)")

    def test_an_unpinned_claude_is_refused_before_it_can_receive_the_key(self):
        """Same granter, never-sandboxed engine (agents-ejm): claude's credentials reach
        the adapter UNBROKERED by design, so the pin is the whole boundary."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        self.trusted_target("trusted")
        evil, _fake = self._plant_fake_engine("claude")
        res = self.factory("claude", self._attack_env(evil), target_arg="trusted")
        self.assertNotEqual(res.returncode, 0,
                            "an unpinned engine must refuse the run, not exit clean")
        self.assertIn("not pinned", res.stderr)
        self._assert_no_dump_received_the_secret()

    def test_deepseek_engine_has_no_binary_and_never_executes_planted_cli(self):
        """agents-mhv7 (review P1/P2): deepseek is purely payload-only Python HTTP station code
        and has no CLI arm — planting a fake deepseek or fake python3 on PATH never executes
        either binary and never leaks DEEPSEEK_API_KEY."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        self.trusted_target("trusted")
        evil, _fake_ds = self._plant_fake_engine("deepseek")
        _evil, _fake_py = self._plant_fake_engine("python3")

        captured = {"called": False}

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                captured["called"] = True
                reply = json.dumps({"choices": [{"message": {"content":
                    json.dumps({"summary": "stub", "findings": []})}}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(reply)))
                self.end_headers()
                self.wfile.write(reply)

            def log_message(self, *args):  # noqa: N802
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        threading.Thread(target=server.serve_forever, daemon=True).start()

        res = self.factory(
            "deepseek",
            self._attack_env(
                evil,
                {
                    "DEEPSEEK_API_KEY": self.SECRET,
                    "DEEPSEEK_BASE_URL": f"http://127.0.0.1:{server.server_address[1]}",
                }
            ),
            target_arg="trusted"
        )
        # Verify the adapter actually ran and issued the API request to our local stub
        self.assertTrue(captured["called"],
                        "the deepseek adapter was not exercised / did not issue HTTP request!")
        self._assert_no_dump_received_the_secret()

if __name__ == "__main__":
    unittest.main()
