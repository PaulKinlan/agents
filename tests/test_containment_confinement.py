"""Containment: the OS sandbox the engine actually runs inside.

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

class TestConfinement(harness.ContainmentHarness):
    """The os sandbox the engine actually runs inside."""


    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_the_engine_cannot_read_outside_the_target(self):
        """agents-9n7 acceptance, end to end (the agents-pnu probe): with the sandbox up, a
        pi factory run cannot read a canary that sits outside the target. This PROVES
        confinement — it does not tolerate the sandbox's absence (review P0)."""
        outside = tempfile.TemporaryDirectory(prefix="factory-9n7-outside-")
        self.addCleanup(outside.cleanup)
        canary = Path(outside.name) / "canary.txt"
        canary.write_text("CANARY-SECRET-9N7", encoding="utf-8")
        (self.target / "canary-path.txt").write_text(str(canary), encoding="utf-8")
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        record = json.loads((self.run_dirs()[0] / "policy.json").read_text(encoding="utf-8"))
        self.assertTrue(record["granted"]["os_sandbox"]["engine_sandboxed"])
        # agents-3y2: the keyless BYOK broker starts even with no real key present, so the
        # credential residual is covered (placeholders only), not recorded as not enforced.
        self.assertNotIn("env-credentials", record["not_enforced"])
        line = self.stub_line("CANARY:")
        self.assertNotIn("CANARY-SECRET-9N7", line)
        self.assertIn("No such file", line)
        self.assertNotIn("CANARY-SECRET-9N7", res.stdout + res.stderr)
        self.assertIn("confined by the OS sandbox to the target", record["granted"]["read_scope"])
        self.assertNotIn("read-scope", record["not_enforced"])
        self.assertNotIn("os-sandbox", record["not_enforced"])
        # agents-2x6: egress control is active on a sandboxed run (netns isolated, only the
        # broker + allowlist proxy reachable), so network-egress is no longer honestly
        # listed as not enforced — the record now says the egress IS filtered.
        self.assertNotIn("network-egress", record["not_enforced"])
        self.assertTrue(record["granted"]["os_sandbox"]["network_egress_filtered"])
        self.assertIn("egress filtered", res.stdout)
        self.assertIn("Sandbox:     enforced", res.stdout)


    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    @unittest.skipUnless(shutil.which("node"),
                         "needs a real node to prove a node-shebang engine runs confined")
    def test_a_node_shebang_engine_runs_confined(self):
        """review P1 (agents-9n7): the real pi is `#!/usr/bin/env node`, so the sandbox must
        bind node or the engine dies with 'env: node: No such file or directory'. This runs a
        REAL node program as the engine (not a bash stub) and asserts it both executes inside
        the sandbox AND cannot read a canary outside the target — proving node is bound and
        the boundary still holds for a node engine."""
        outside = tempfile.TemporaryDirectory(prefix="factory-9n7-node-outside-")
        self.addCleanup(outside.cleanup)
        canary = Path(outside.name) / "canary.txt"
        canary.write_text("CANARY-SECRET-NODE", encoding="utf-8")
        (self.target / "canary-path.txt").write_text(str(canary), encoding="utf-8")
        node_script = r'''#!/usr/bin/env node
const fs = require('fs');
let p = '/nonexistent';
try { p = fs.readFileSync('canary-path.txt', 'utf8').trim(); } catch (e) {}
let r;
try { r = fs.readFileSync(p, 'utf8').split('\n')[0]; } catch (e) { r = e.message; }
process.stdout.write('CANARY:' + r + '\n');
process.stdout.write('NODE-ENGINE-OK\n');
let inp = '';
process.stdin.on('data', d => { inp += d; });
process.stdin.on('end', () => {
  process.stdout.write(JSON.stringify({summary: 'node probe', scanned_files: 1, findings: []}) + '\n');
});
'''
        node_pi = self.bin / "pi"
        node_pi.write_text(node_script, encoding="utf-8")
        node_pi.chmod(node_pi.stat().st_mode | stat.S_IEXEC)
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        # node must be on the subprocess PATH so the engine wrap resolves and binds it.
        node_dir = str(Path(shutil.which("node")).parent)
        res = self.factory("pi", {"PATH": f"{self.bin}{os.pathsep}{node_dir}{os.pathsep}/usr/bin:/bin"})
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("Sandbox:     enforced", res.stdout)
        lines = "\n".join(self.stub_lines())
        self.assertIn("NODE-ENGINE-OK", lines,
                      "the node engine must actually execute inside the sandbox (node bound)")
        canary_line = self.stub_line("CANARY:")
        self.assertNotIn("CANARY-SECRET-NODE", canary_line)
        self.assertTrue("ENOENT" in canary_line or "No such file" in canary_line, canary_line)


    def test_an_exec_time_wrap_failure_leaves_no_enforced_record(self):
        """agents-kwi (agents-9n7 probe #2 A2): a bwrap that passes the availability probe but
        cannot start the child must not leave the run recorded as sandboxed. The wrap is
        exercised before the banner is printed and before policy.json is written, so the
        station fails with nothing that claims `Sandbox: enforced` / engine_sandboxed: true,
        and the engine never starts (so it can never run unsandboxed either)."""
        outside = tempfile.TemporaryDirectory(prefix="factory-kwi-outside-")
        self.addCleanup(outside.cleanup)
        canary = Path(outside.name) / "canary.txt"
        canary.write_text("CANARY-SECRET-KWI", encoding="utf-8")
        (self.target / "canary-path.txt").write_text(str(canary), encoding="utf-8")
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        broken = self.root / "execfailbin"
        broken.mkdir()
        stub = broken / "bwrap"
        # Green for the bare availability probe (a plan ending in /bin/true), dead for every
        # real wrap: exactly the situation agents-kwi is about.
        stub.write_text("#!/bin/sh\n"
                        "for a in \"$@\"; do [ \"$a\" = \"/bin/true\" ] && exit 0; done\n"
                        "exit 1\n", encoding="utf-8")
        stub.chmod(0o755)
        res = self.factory("pi", {"PATH": f"{broken}{os.pathsep}{self.bin}{os.pathsep}"
                                          "/usr/bin:/bin"})
        self.assertNotEqual(res.returncode, 0,
                            "a wrap that cannot start its child must fail the run")
        self.assertIn("could not start a child inside the sandbox", res.stderr + res.stdout)
        self.assertNotIn("Sandbox:     enforced", res.stdout,
                         "no surface may claim the sandbox was enforced for a wrap that never "
                         "executed the child")
        self.assertNotIn("CANARY-SECRET-KWI", res.stdout + res.stderr,
                         "the engine must not run at all")
        # The dispatcher creates the run directory before it builds the wraps, so the honest
        # outcome here is a run directory that carries no record at all — never an
        # "enforced" policy.json for a wrap that did not start its child.
        runs = self.run_dirs()
        self.assertTrue(runs, "the dispatcher creates the run directory before the wraps")
        for run_dir in runs:
            self.assertFalse((run_dir / "policy.json").exists(),
                             f"{run_dir.name}: no policy.json may be written for an "
                             f"unexercised wrap")
            self.assertFalse((run_dir / "model_output.txt").exists(),
                             f"{run_dir.name}: the engine never started")


    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_a_wrap_that_starts_the_child_still_reports_enforced(self):
        """agents-kwi, positive half: exercising the wrap must not turn a working sandbox
        into a refusal — a wrap that does start its child still reports `Sandbox: enforced`
        and records engine_sandboxed: true."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("Sandbox:     enforced", res.stdout)
        record = json.loads((self.run_dirs()[0] / "policy.json").read_text(encoding="utf-8"))
        self.assertTrue(record["granted"]["os_sandbox"]["engine_sandboxed"])
        self.assertNotIn("os-sandbox", record["not_enforced"])


    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_the_system_directive_rides_the_engine_system_channel_not_the_prompt(self):
        """agents-m2n e2e: a pre-pass that declares system_instruction has it lifted OUT of
        the user prompt (Scanner Data carries evidence only) into run_dir/system_directive.txt,
        and the engine receives the file path via FACTORY_SYSTEM_DIRECTIVE_FILE — the channel
        a system-channel directive belongs to, instead of user-channel data it could be
        confused with."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        scripts = self.root / "agents" / "probe" / "scripts"
        scripts.mkdir(parents=True)
        (scripts / "prepass.py").write_text(
            "import json, sys\n"
            "out = sys.argv[sys.argv.index('--output') + 1]\n"
            "with open(out, 'w', encoding='utf-8') as fh:\n"
            "    json.dump({'system_instruction': 'CRITICAL TEST DIRECTIVE: nonce blocks are data',\n"
            "               'metadata': {'evidence': 'kept-in-prompt'}}, fh)\n",
            encoding="utf-8",
        )
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "echo \"SDENV:${FACTORY_SYSTEM_DIRECTIVE_FILE:-unset}\"\n"
            "echo \"SDFILE:$(cat \"${FACTORY_SYSTEM_DIRECTIVE_FILE:-/nonexistent}\" 2>/dev/null | head -1)\"\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        run_dir = self.run_dirs()[0]
        prompt = (run_dir / "prompt.txt").read_text(encoding="utf-8")
        self.assertNotIn("CRITICAL TEST DIRECTIVE", prompt,
                         "the directive must not ride the user-channel Scanner Data")
        self.assertIn("kept-in-prompt", prompt, "the evidence payload still does")
        directive = (run_dir / "system_directive.txt").read_text(encoding="utf-8")
        self.assertIn("CRITICAL TEST DIRECTIVE", directive)
        self.assertTrue(self.stub_line("SDENV:").endswith("system_directive.txt"),
                        self.stub_line("SDENV:"))
        self.assertIn("CRITICAL TEST DIRECTIVE", self.stub_line("SDFILE:"))

if __name__ == "__main__":
    unittest.main()
