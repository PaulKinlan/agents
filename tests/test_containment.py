"""Containment: the dispatcher.

TestDispatcher is the base configuration every containment assertion runs
against; the harness it uses lives in tests/containment_harness.py, and the
other concerns were split out beside this file (agents-3iog):
declarations/manifests, adapters, engine credential pinning, prepass pins,
egress end to end.
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

class TestDispatcher(harness.ContainmentHarness):
    """The real `factory run` CLI, from a sandbox copy, against a stub `pi`.

    The stub reports through its stdout, which the adapter captures into the run
    directory's model_output.txt — the only place an engine can write, because the OS
    sandbox (agents-9n7) makes the factory root read-only and the run directory writable.
    extract_json_from_output tolerates the marker lines around the JSON report.
    """








    def test_an_engine_that_cannot_enforce_is_refused_before_any_work(self):
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        res = self.factory("antigravity")
        self.assertEqual(res.returncode, 3, res.stdout + res.stderr)
        self.assertIn("cannot enforce", res.stderr)
        self.assertEqual(self.run_dirs(), [], "a refused run must leave no run directory")

    def test_a_declaration_above_its_ceiling_is_refused_before_any_work(self):
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi")
        self.assertEqual(res.returncode, 3, res.stdout + res.stderr)
        self.assertIn("exceeds the t0-readonly ceiling", res.stderr)
        self.assertEqual(self.run_dirs(), [], "the engine must not start")

    def test_the_policy_is_set_explicitly_enforced_and_recorded(self):
        """A FACTORY_TOOL_POLICY in the caller's environment never reaches the adapter."""
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        self.trusted_target("trusted")
        res = self.factory("pi", {"FACTORY_TOOL_POLICY": "unrestricted",
                                  "FACTORY_ALLOW_UNSANDBOXED": "1"}, target_arg="trusted")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.stub_line("POLICY:"), READ_ONLY)
        argv = self.stub_line("ARGV:").split()
        self.assertEqual(argv[argv.index("--tools") + 1], "read,grep,find,ls")
        self.assertIn("Withheld:    write", res.stdout)
        self.assertIn("[pi adapter] Tool policy: read-only", res.stdout)
        runs = self.run_dirs()
        self.assertEqual(len(runs), 1)
        record = json.loads((runs[0] / "policy.json").read_text(encoding="utf-8"))
        self.assertEqual(record["granted"]["tool_policy"], READ_ONLY)
        self.assertEqual(record["declared"]["containment"], "t2-local")
        self.assertEqual(set(record["withheld"]), {"write"})

    def test_a_declared_usd_cap_reaches_the_adapter_only_from_the_dispatcher(self):
        """agents-js7: the declared cap is set explicitly on the adapter environment; an
        ambient FACTORY_MAX_BUDGET_USD in the operator's shell never reaches the adapter."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1, max_usd: 0.5}\n")
        self.trusted_target("trusted")
        res = self.factory("pi", {"FACTORY_MAX_BUDGET_USD": "999",
                                  "FACTORY_ALLOW_UNSANDBOXED": "1"}, target_arg="trusted")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.stub_line("BUDGET:"), "0.5", "the declared cap, not the ambient one")
        self.assertIn("NOT enforced (the pi adapter has no per-run budget flag)", res.stdout)
        record = json.loads((self.run_dirs()[0] / "policy.json").read_text(encoding="utf-8"))
        self.assertIn("budget.max_usd", record["not_enforced"])

    def test_an_unpinned_run_is_auditable_in_policy_json_and_banner(self):
        """agents-onf6: an unpinned-tools run must record the waiver in the run banner
        and in policy.json (in not_enforced and unpinned_tools_opt_in) so it is auditable."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\nbudget: {max_minutes: 1}\n")
        self.trusted_target("trusted")
        res = self.factory("pi", {"FACTORY_ALLOW_UNPINNED_TOOLS": "1",
                                  "FACTORY_ALLOW_UNSANDBOXED": "1"}, target_arg="trusted")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("Tool pins:   NOT enforced — explicit FACTORY_ALLOW_UNPINNED_TOOLS=1", res.stdout)
        record = json.loads((self.run_dirs()[0] / "policy.json").read_text(encoding="utf-8"))
        self.assertIn("trusted-tool-pins", record["not_enforced"])
        self.assertIn("unpinned_tools_opt_in", record)
        self.assertIn("FACTORY_ALLOW_UNPINNED_TOOLS=1", record["unpinned_tools_opt_in"])

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

    def test_same_second_collision_is_allocated_exclusively(self):
        """agents-esx: force the exact old run id twice. Without the exclusive mkdir
        fallback this would reuse the first run dir, even if two real subprocesses
        happened to land on different seconds in the integration test below."""
        with mock.patch.object(factory_cli, "FACTORY_ROOT", self.root), \
             mock.patch.object(factory_cli, "token_hex", return_value="a1b2c3d4"):
            first = factory_cli.create_run_dir("probe", "target", "20261007-123456")
            (first / "model_output.txt").write_text("first output", encoding="utf-8")
            second = factory_cli.create_run_dir("probe", "target", "20261007-123456")
        self.assertNotEqual(first, second)
        self.assertEqual(second.name, "probe-target-20261007-123456-a1b2c3d4")
        self.assertEqual((first / "model_output.txt").read_text(encoding="utf-8"), "first output")
        self.assertEqual(second.stat().st_mode & 0o777, 0o700)

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_two_runs_never_share_a_run_directory(self):
        """agents-m2n review P2 (same class as agents-30q): run ids resolve to the second,
        and two runs in one second must still get distinct, exclusively-created run
        directories — the egress sockets, prompt, policy.json and session.patch all live
        there."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        for _ in range(2):
            res = self.factory("pi")
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        runs = self.run_dirs()
        self.assertEqual(len(runs), 2, "both runs must complete")
        self.assertEqual(len({r.name for r in runs}), 2,
                         "consecutive runs must never share a run directory")

    def test_a_pi_run_is_refused_when_the_sandbox_cannot_run(self):
        """review P0 (agents-9n7): pi's read scope is confined ONLY by the OS sandbox. If
        bubblewrap cannot run on the host, the dispatcher must REFUSE — never silently fall
        back to an unsandboxed run where a prompt-injected model reads any file the operator
        can. A broken bwrap on PATH simulates a host where the real probe fails."""
        outside = tempfile.TemporaryDirectory(prefix="factory-9n7-outside-")
        self.addCleanup(outside.cleanup)
        canary = Path(outside.name) / "canary.txt"
        canary.write_text("CANARY-SECRET-9N7", encoding="utf-8")
        (self.target / "canary-path.txt").write_text(str(canary), encoding="utf-8")
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        broken = self.root / "brokenbin"
        broken.mkdir()
        stub = broken / "bwrap"
        stub.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        stub.chmod(0o755)
        res = self.factory("pi", {"PATH": f"{broken}{os.pathsep}{self.bin}{os.pathsep}/usr/bin:/bin"})
        self.assertNotEqual(res.returncode, 0, "an unsandboxed pi run must be refused")
        self.assertIn("OS filesystem sandbox", res.stderr + res.stdout)
        self.assertEqual(self.run_dirs(), [], "a refused run must leave no run directory")

    def test_unsandboxed_run_requires_an_explicit_opt_in(self):
        """agents-bp0 acceptance: the ambient FACTORY_ALLOW_UNSANDBOXED opt-in alone must
        NOT unlock an unsandboxed run. The attestation lives in the TARGET's own manifest
        (targets/<name>.yaml `trusted: true` + `visibility: private`), because anything
        able to set an environment variable — a compromised schedule entry, a malicious CI
        step, a wrapper script, a command a doc tells a developer to run — must not be able
        to make the operator's filesystem the read scope. A raw --target path carries no
        manifest at all, so it refuses exactly like the no-opt-in case above."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        broken = self.root / "brokenbin"
        broken.mkdir()
        stub = broken / "bwrap"
        stub.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        stub.chmod(0o755)
        res = self.factory("pi", {"PATH": f"{broken}{os.pathsep}{self.bin}{os.pathsep}/usr/bin:/bin",
                                  "FACTORY_ALLOW_UNSANDBOXED": "1"})
        self.assertNotEqual(res.returncode, 0, "an untrusted target must refuse the opt-in")
        self.assertIn("trusted attestation", res.stderr + res.stdout)
        self.assertEqual(self.run_dirs(), [], "a refused run must leave no run directory")

    def test_a_trusted_but_public_target_still_refuses_the_opt_in(self):
        """agents-bp0: `trusted: true` is necessary but not sufficient — a target whose
        visibility is public (or undeclared, which normalizes to public) never qualifies:
        THREAT_MODEL.md section 7's precondition is a trusted AND non-public target."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        broken = self.root / "brokenbin"
        broken.mkdir()
        stub = broken / "bwrap"
        stub.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        stub.chmod(0o755)
        env = {"PATH": f"{broken}{os.pathsep}{self.bin}{os.pathsep}/usr/bin:/bin",
               "FACTORY_ALLOW_UNSANDBOXED": "1",
               "FACTORY_ALLOW_UNPINNED_TOOLS": "1"}
        for name, visibility in (("pub", "public"), ("unsetvis", None)):
            with self.subTest(target=name):
                self.trusted_target(name, visibility=visibility)
                res = self.factory("pi", env, target_arg=name)
                self.assertNotEqual(res.returncode, 0,
                                    f"{name} must refuse the opt-in")
                self.assertIn("trusted attestation", res.stderr + res.stdout)
                self.assertEqual(self.run_dirs(), [], "a refused run must leave no run directory")

    def test_an_absolute_target_path_never_loads_a_planted_manifest(self):
        """review P1 (agents-bp0): pathlib's absolute-join DISCARD made
        FACTORY_ROOT/'targets'/f'{target_arg}.yaml' load a manifest from ANYWHERE, so an
        argv+env-controlling adversary could plant trusted:true + visibility:private +
        path:<operator home> beside any directory and get an attested unsandboxed run
        from `--target <dir>`. Only a bare name may load a manifest; an absolute path is
        a raw target and must refuse the opt-in exactly like any other untrusted one."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        broken = self.root / "brokenbin"
        broken.mkdir()
        stub = broken / "bwrap"
        stub.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        stub.chmod(0o755)
        # The planted manifest sits beside the target directory: with the absolute-join
        # bug, --target <self.root>/target resolved to it and the run would be attested.
        (self.root / "target.yaml").write_text(
            f"name: planted\npath: {self.root}\nvisibility: private\ntrusted: true\n",
            encoding="utf-8")
        res = self.factory("pi", {"PATH": f"{broken}{os.pathsep}{self.bin}{os.pathsep}/usr/bin:/bin",
                                  "FACTORY_ALLOW_UNSANDBOXED": "1"})
        self.assertNotEqual(res.returncode, 0,
                            "an absolute --target must not load a planted manifest")
        self.assertIn("trusted attestation", res.stderr + res.stdout)
        self.assertEqual(self.run_dirs(), [], "a refused run must leave no run directory")

    def test_the_opt_in_runs_only_for_a_trusted_private_target(self):
        """The only unsandboxed path is the explicit FACTORY_ALLOW_UNSANDBOXED opt-in for a
        TRUSTED target (THREAT_MODEL.md section 7) — a real precondition since agents-bp0,
        not just an honour-system docstring. It must run and say NOT enforced with the
        opt-in named prominently, proving the refusals above are the default and this is a
        deliberate, attested exception rather than a silent fallback."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        broken = self.root / "brokenbin"
        broken.mkdir()
        stub = broken / "bwrap"
        stub.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        stub.chmod(0o755)
        self.trusted_target("trusted")
        res = self.factory("pi", {"PATH": f"{broken}{os.pathsep}{self.bin}{os.pathsep}/usr/bin:/bin",
                                  "FACTORY_ALLOW_UNSANDBOXED": "1"}, target_arg="trusted")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("Sandbox:     NOT enforced — explicit FACTORY_ALLOW_UNSANDBOXED opt-in "
                      "on trusted target 'trusted'", res.stdout)
        self.assertIn("run as the operator", res.stdout)
        record = json.loads((self.run_dirs()[0] / "policy.json").read_text(encoding="utf-8"))
        self.assertIn("os-sandbox", record["not_enforced"])
        self.assertIn("read-scope", record["not_enforced"])
        self.assertIn("explicit FACTORY_ALLOW_UNSANDBOXED opt-in on trusted target 'trusted'",
                      record["unsandboxed_opt_in"])

    # --- agents-6ce: the disposable per-session worktree -------------------------------





    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_a_write_agent_edits_a_disposable_worktree_and_leaves_the_target_untouched(self):
        """agents-6ce acceptance: a granted write runs in a disposable git worktree. The engine
        edits files there, the dispatcher collects the session diff as the proposal, the
        worktree is discarded, and the target checkout is never modified. Gated on bwrap: since
        review P1-2 pi gets worktree-write ONLY when engine_sandboxed, so this mechanism is
        reachable only under a real OS sandbox; on a bwrap-less host it downgrades to read-only
        (test_an_unsandboxed_pi_write_agent_downgrades_to_read_only)."""
        self._git_init_target()
        self._editing_stub()
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        before = self._target_fingerprint()
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        # The grant is worktree-write and the engine ran inside the worktree, not the target.
        self.assertEqual(self.stub_line("POLICY:"), WORKTREE_WRITE)
        self.assertIn("Tool policy: worktree-write", res.stdout)
        self.assertTrue(self.stub_line("CWD:").endswith("/worktree"), self.stub_line("CWD:"))
        # The session diff was collected as the proposal (both the edit and the new file).
        run_dir = self.run_dirs()[0]
        patch = run_dir / "session.patch"
        self.assertTrue(patch.exists(), "session.patch must be collected")
        patch_text = patch.read_text(encoding="utf-8")
        self.assertIn("proposed fix", patch_text)
        self.assertIn("proposed.txt", patch_text)
        # No worktree leaked, and the target checkout is byte-identical (coord hard
        # requirement: prove a write run never touched the operator's checkout).
        self._assert_no_leaked_worktree()
        self.assertEqual(self._target_fingerprint(), before,
                         "the target checkout must be byte-identical after a write run")
        status = subprocess.run(["git", "-C", str(self.target), "status", "--porcelain"],
                                capture_output=True, text=True, check=True)
        self.assertEqual(status.stdout.strip(), "",
                         "the target must be clean, got: " + status.stdout)

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_the_worktree_is_writable_inside_the_sandbox(self):
        """End-to-end: under the enforced OS sandbox the worktree (under the read-write-bound
        run directory) is writable, so the engine's edits are collected and the target stays
        read-only and unmodified. No FACTORY_ALLOW_UNSANDBOXED here — the sandbox is enforced."""
        self._git_init_target()
        self._editing_stub()
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        before = self._target_fingerprint()
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("Sandbox:     enforced", res.stdout)
        self.assertEqual(self.stub_line("POLICY:"), WORKTREE_WRITE)
        patch = self.run_dirs()[0] / "session.patch"
        self.assertTrue(patch.exists(), "the sandboxed engine's edits must be collected")
        self.assertIn("proposed fix", patch.read_text(encoding="utf-8"))
        self._assert_no_leaked_worktree()
        self.assertEqual(self._target_fingerprint(), before,
                         "the target checkout must be byte-identical after a sandboxed write run")
        status = subprocess.run(["git", "-C", str(self.target), "status", "--porcelain"],
                                capture_output=True, text=True, check=True)
        self.assertEqual(status.stdout.strip(), "",
                         "the target must be clean, got: " + status.stdout)

    def test_a_write_agent_on_a_non_git_target_downgrades_to_read_only(self):
        """agents-6ce: the worktree grant needs a git repo. A non-git target downgrades to
        read-only and re-withholds write with the specific reason, so the banner and policy
        stay honest and no worktree/session.patch is produced."""
        # self.target is a plain directory (not git) from setUp; the trusted manifest
        # points at it, so the run proceeds on any host (review P2: the old raw-path +
        # opt-in form only worked where bubblewrap exists).
        self.trusted_target("trusted")
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi", {"FACTORY_ALLOW_UNSANDBOXED": "1"}, target_arg="trusted")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.stub_line("POLICY:"), READ_ONLY)
        self.assertIn("Tool policy: read-only", res.stdout)
        self.assertIn("not a git repository", res.stdout)
        run_dir = self.run_dirs()[0]
        self.assertFalse((run_dir / "worktree").exists())
        self.assertFalse((run_dir / "session.patch").exists())
        record = json.loads((run_dir / "policy.json").read_text(encoding="utf-8"))
        self.assertEqual(record["granted"]["tool_policy"], READ_ONLY)
        self.assertIn("write", record["withheld"])

    def test_an_unsandboxed_pi_write_agent_downgrades_to_read_only(self):
        """Review P1-2 (agents-6ce): the OS sandbox is the ONLY boundary that ro-binds the
        target — pi's tools are not path-confined by its flags. On a bwrap-less host (a broken
        bwrap on PATH simulates it) under the explicit FACTORY_ALLOW_UNSANDBOXED opt-in, a pi
        write agent must NOT get worktree-write: that would hand a prompt-injected session an
        unconfined write primitive over the operator's tree. It downgrades to read-only (the
        pre-6ce behaviour for this mode); no worktree or session.patch is produced."""
        self._git_init_target()
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        broken = self.root / "brokenbin"
        broken.mkdir()
        bwrap = broken / "bwrap"
        bwrap.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        bwrap.chmod(0o755)
        self.trusted_target("trusted")
        res = self.factory("pi", {"PATH": f"{broken}{os.pathsep}{self.bin}{os.pathsep}/usr/bin:/bin",
                                  "FACTORY_ALLOW_UNSANDBOXED": "1"}, target_arg="trusted")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.stub_line("POLICY:"), READ_ONLY)
        self.assertIn("Tool policy: read-only", res.stdout)
        self.assertIn("will not run inside the OS sandbox", res.stdout)
        run_dir = self.run_dirs()[0]
        self.assertFalse((run_dir / "worktree").exists())
        self.assertFalse((run_dir / "session.patch").exists())
        record = json.loads((run_dir / "policy.json").read_text(encoding="utf-8"))
        self.assertEqual(record["granted"]["tool_policy"], READ_ONLY)
        self.assertIn("write", record["withheld"])

    def test_a_claude_write_agent_downgrades_to_read_only(self):
        """Review P1-2 (agents-6ce): claude is NOT in SANDBOXED_ENGINES (its adapter is not
        sandbox-verified), so engine_sandboxed('claude') is False on EVERY host — claude never
        gets the OS sandbox that ro-binds the target. Its --restricted is claude's own
        confinement, not a kernel boundary, so a claude write agent downgrades to read-only
        anywhere. No broken bwrap needed here: claude is never engine_sandboxed. agents-ejm:
        claude also needs the trusted-private target attestation, so this runs against one."""
        self._git_init_target()
        self.trusted_target("trusted")
        stub = self.bin / "claude"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "echo \"POLICY:${FACTORY_TOOL_POLICY:-unset}\"\n"
            "echo \"CWD:$(pwd)\"\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        # ANTHROPIC_API_KEY satisfies claude.sh's deterministic auth gate (a presence check);
        # the stub never calls the real API.
        res = self.factory("claude", {"ANTHROPIC_API_KEY": "sk-ant-test-not-real"},
                          target_arg="trusted")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.stub_line("POLICY:"), READ_ONLY)
        self.assertIn("will not run inside the OS sandbox", res.stdout)
        run_dir = self.run_dirs()[0]
        self.assertFalse((run_dir / "worktree").exists())
        self.assertFalse((run_dir / "session.patch").exists())
        record = json.loads((run_dir / "policy.json").read_text(encoding="utf-8"))
        self.assertEqual(record["granted"]["tool_policy"], READ_ONLY)
        self.assertIn("write", record["withheld"])

    def test_a_write_grant_reaches_the_engine_only_inside_the_sandbox_wrap(self):
        """agents-dpbc, the guard REPINNED TO THE COMPOSITION (fourth ruling): the
        worktree-write guarantee is run_agent + sandbox_command, not any adapter, so the
        property pinned here is the composition's real contract — a dispatcher-driven run
        reaches the engine with write flags ONLY when sandbox_command wraps it. For EVERY
        engine whose ENGINE_TOOL_POLICIES row carries WORKTREE_WRITE (the iteration source
        the third verdict confirmed sound; new write-capable engines enter automatically
        via the table), drive a real factory write-agent run on a host where the wrap
        cannot be built — a broken bwrap on PATH simulates the bwrap-less host, so this
        runs anywhere — under the trusted-target opt-in. The dispatcher must downgrade
        BEFORE the adapter env is set: the engine's stub reports POLICY read-only with
        the read-only tool flags (delivery of the DOWNGRADE asserted, not just exit 0),
        the downgrade reason names the missing sandbox wrap (not some other gate), no
        worktree or session.patch is produced, and policy.json records write withheld.
        MUTATION THAT FAILS THIS GUARD: removing run_agent's `not engine_sandboxed`
        downgrade arm hands the engine worktree-write on the no-wrap host and the stub
        reports POLICY worktree-write with edit,write in argv. The wrap side — the grant
        really is delivered inside the sandbox — is pinned by the bwrap-gated
        test_a_write_agent_edits_a_disposable_worktree_and_leaves_the_target_untouched,
        which asserts a collected session.patch and a byte-identical target and must not
        be replaced by a green adapter-only substitute on a host without bwrap. The
        adapter side of the contract is pinned separately: claude refuses a direct
        worktree-write (test_claude_never_honours_worktree_write_until_sandbox_verified)
        and pi accepts it as unsandboxed misuse
        (test_a_direct_pi_worktree_write_invocation_is_unsandboxed_misuse)."""
        write_capable = sorted(e for e, policies in ENGINE_TOOL_POLICIES.items()
                               if WORKTREE_WRITE in policies)
        self.assertIn("pi", write_capable,
                      "guard vacuous: the sandboxed write engine must be iterated")
        self._git_init_target()
        self.trusted_target("trusted")
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        broken = self.root / "brokenbin"
        broken.mkdir()
        bwrap = broken / "bwrap"
        bwrap.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        bwrap.chmod(0o755)
        for engine in write_capable:
            with self.subTest(engine=engine):
                if engine != "pi":  # the setUp stub covers pi
                    stub = self.bin / adapters.TestAdapters.ENGINE_BINARY.get(engine, engine)
                    stub.write_text(
                        "#!/usr/bin/env bash\n"
                        "echo \"ARGV:$*\"\n"
                        "echo \"POLICY:${FACTORY_TOOL_POLICY:-unset}\"\n"
                        "cat >/dev/null\n" + STUB_REPORT,
                        encoding="utf-8",
                    )
                    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
                shutil.rmtree(self.root / "runs", ignore_errors=True)
                res = self.factory(
                    engine,
                    {"PATH": f"{broken}{os.pathsep}{self.bin}{os.pathsep}/usr/bin:/bin",
                     "FACTORY_ALLOW_UNSANDBOXED": "1",
                     # Satisfies claude.sh's deterministic auth gate (a presence check);
                     # the stub never calls the real API.
                     "ANTHROPIC_API_KEY": "sk-ant-test-not-real"},
                    target_arg="trusted")
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                self.assertEqual(
                    self.stub_line("POLICY:"), READ_ONLY,
                    "the composition must downgrade before the adapter env is set: "
                    "write flags may reach the engine only inside the sandbox wrap")
                self.assertIn(
                    "will not run inside the OS sandbox", res.stdout,
                    "the downgrade reason must be the missing sandbox wrap, not another "
                    "gate (a non-git-target downgrade would pass for the wrong reason)")
                argv = self.stub_line("ARGV:").split()
                tools = argv[argv.index("--tools") + 1]
                self.assertNotIn("write", tools.lower(),
                                 f"{engine} received write flags outside the wrap: "
                                 f"--tools {tools}")
                run_dir = self.run_dirs()[0]
                self.assertFalse((run_dir / "worktree").exists())
                self.assertFalse((run_dir / "session.patch").exists())
                record = json.loads((run_dir / "policy.json").read_text(encoding="utf-8"))
                self.assertEqual(record["granted"]["tool_policy"], READ_ONLY)
                self.assertIn("write", record["withheld"])

    def test_a_claude_run_against_a_public_target_is_refused(self):
        """agents-ejm: claude runs without the OS sandbox (--restricted only, not a kernel
        boundary) and with unbrokered credentials, so it is refused against any target whose
        manifest does not declare the trusted-private attestation — a raw --target path carries
        no manifest at all and refuses, fail-closed, before any run directory exists."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        # The stub is never reached — the refusal is before the adapter — but it proves a
        # reverted check would run claude to a clean exit 0, not an adapter-not-found failure.
        stub = self.bin / "claude"
        stub.write_text("#!/usr/bin/env bash\ncat >/dev/null\n" + STUB_REPORT, encoding="utf-8")
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        res = self.factory("claude", {"ANTHROPIC_API_KEY": "sk-ant-test-not-real"})
        self.assertEqual(res.returncode, 3, res.stdout + res.stderr)
        self.assertIn("claude", res.stderr)
        self.assertIn("trusted: true", res.stderr)
        self.assertEqual(self.run_dirs(), [], "a refused claude run must leave no run directory")

    def test_a_claude_run_against_a_public_named_target_is_refused(self):
        """agents-ejm: the attestation is the manifest's `trusted: true` + `visibility: private`,
        so a NAMED target that declares visibility: public (even with a trusted field absent)
        refuses a claude run — the public sink is exactly what a no-kernel-boundary engine must
        not reach."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        stub = self.bin / "claude"
        stub.write_text("#!/usr/bin/env bash\ncat >/dev/null\n" + STUB_REPORT, encoding="utf-8")
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        (self.root / "targets").mkdir(exist_ok=True)
        (self.root / "targets" / "public.yaml").write_text(
            f"name: public\npath: {self.target}\nvisibility: public\n", encoding="utf-8")
        res = self.factory("claude", {"ANTHROPIC_API_KEY": "sk-ant-test-not-real"},
                          target_arg="public")
        self.assertEqual(res.returncode, 3, res.stdout + res.stderr)
        self.assertIn("trusted: true", res.stderr)
        self.assertEqual(self.run_dirs(), [], "a refused claude run must leave no run directory")

    def test_a_claude_read_only_run_against_a_trusted_private_target_proceeds(self):
        """agents-ejm positive control: a claude run against a manifest declaring trusted: true +
        visibility: private is allowed (read-only, unsandboxed) — the restriction must not
        over-block the one target class claude is permitted on."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        self.trusted_target("trusted")
        stub = self.bin / "claude"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "echo \"POLICY:${FACTORY_TOOL_POLICY:-unset}\"\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        res = self.factory("claude", {"ANTHROPIC_API_KEY": "sk-ant-test-not-real"},
                          target_arg="trusted")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.stub_line("POLICY:"), READ_ONLY)
        record = json.loads((self.run_dirs()[0] / "policy.json").read_text(encoding="utf-8"))
        self.assertEqual(record["granted"]["tool_policy"], READ_ONLY)
        self.assertIn("os-sandbox", record["not_enforced"])

    def test_collect_session_diff_raises_on_a_stale_index_lock(self):
        """Review P1-1 (agents-6ce): if a crashed run left a stale index.lock, `git add -A`
        exits non-zero (128) while the following `git diff --cached` returns an empty rc0 diff.
        _collect_session_diff must RAISE, not return None — returning None would print 'no file
        edits (empty proposal)' and exit 0, silently discarding the engine's proposal. Uses a
        real linked worktree (round 2) so the .git marker and admin gitdir match production."""
        target = self.root / "lock-target"
        target.mkdir()
        subprocess.run(["git", "init", "-q", str(target)], check=True, capture_output=True)
        (target / "f.txt").write_text("one\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(target), "add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(target), "-c", "user.email=f@t", "-c", "user.name=f",
                        "commit", "-qm", "init"], check=True, capture_output=True)
        wt = self.root / "lock-wt"
        gitdir = factory_cli._create_session_worktree(target, wt)
        # The session "edited" a file, then a crashed run left a stale lock in the admin gitdir.
        (wt / "f.txt").write_text("one\ntwo\n", encoding="utf-8")
        lock = gitdir / "index.lock"
        lock.write_text("", encoding="utf-8")
        run_dir = self.root / "lock-run"
        run_dir.mkdir()
        try:
            with self.assertRaises(factory_cli.StationError):
                factory_cli._collect_session_diff(wt, run_dir, gitdir)
            self.assertFalse((run_dir / "session.patch").exists(),
                             "a failed stage must not produce a patch")
        finally:
            lock.unlink(missing_ok=True)

    def test_second_collection_write_failure_keeps_the_first_patch_intact(self):
        """agents-nei P1-2 (round 4): each kept win re-collects session.patch in place, so a
        failure during a LATER collection's write (disk full) could truncate the earlier good
        patch and strand an already-durable KEPT row. The write must go to a sibling temp file
        and be atomically os.replace()'d only after it completes."""
        target = self.root / "atomic-target"
        target.mkdir()
        subprocess.run(["git", "init", "-q", str(target)], check=True, capture_output=True)
        (target / "f.txt").write_text("one\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(target), "add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(target), "-c", "user.email=f@t", "-c", "user.name=f",
                        "commit", "-qm", "init"], check=True, capture_output=True)
        wt = self.root / "atomic-wt"
        gitdir = factory_cli._create_session_worktree(target, wt)
        run_dir = self.root / "atomic-run"
        run_dir.mkdir()

        # First collection succeeds and writes the first accumulated proposal.
        (wt / "f.txt").write_text("one\ntwo\n", encoding="utf-8")
        factory_cli._collect_session_diff(wt, run_dir, gitdir)
        patch_file = run_dir / "session.patch"
        first_patch = patch_file.read_bytes()
        self.assertIn(b"two", first_patch)
        self.assertNotIn(b"three", first_patch)

        # A second accumulated edit is re-collected, but its write fails (disk full) only
        # AFTER the target file has been truncated and a partial prefix written — the exact
        # failure the temp-file+replace path must survive. The earlier patch must remain
        # byte-for-byte intact (a), so the already-durable KEPT row's proposal still matches
        # what is on disk (b), and the failed temp file must be cleaned up.
        (wt / "f.txt").write_text("one\ntwo\nthree\n", encoding="utf-8")

        def write_prefix_then_fail(path, data, encoding="utf-8"):
            # In-place implementations truncate the write target and write a prefix before the
            # error. Here the prefix lands in whatever file _collect_session_diff is writing;
            # the assertions below prove that file is a throwaway temp, not session.patch.
            path.write_bytes(data[:12].encode(encoding))
            raise OSError("disk full")

        with mock.patch.object(Path, "write_text", write_prefix_then_fail):
            with self.assertRaises(OSError):
                factory_cli._collect_session_diff(wt, run_dir, gitdir)

        self.assertEqual(patch_file.read_bytes(), first_patch)  # (a) byte-for-byte intact
        self.assertIn(b"two", patch_file.read_bytes())          # (b) kept proposal still on disk
        self.assertNotIn(b"three", patch_file.read_bytes())
        self.assertFalse((run_dir / "session.patch.tmp").exists(),
                         "a failed write must not leak the temp file")

    def test_a_non_utf8_worktree_marker_fails_closed(self):
        """agents-7ik (4): a binary .git marker raises UnicodeDecodeError (a ValueError,
        not an OSError) — it must surface as a clean StationError, never an unhandled
        traceback. Fail-closed: host-side git is refused against the marker."""
        target = self.root / "bin-target"
        target.mkdir()
        subprocess.run(["git", "init", "-q", str(target)], check=True, capture_output=True)
        (target / "f.txt").write_text("one\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(target), "add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(target), "-c", "user.email=f@t", "-c", "user.name=f",
                        "commit", "-qm", "init"], check=True, capture_output=True)
        wt = self.root / "bin-wt"
        gitdir = factory_cli._create_session_worktree(target, wt)
        (wt / ".git").write_bytes(b"\xff\xfe\x00not-a-gitdir-pointer")
        with self.assertRaises(factory_cli.StationError) as ctx:
            factory_cli._validate_worktree_marker(wt, gitdir)
        self.assertIn("not UTF-8", str(ctx.exception))
        factory_cli._remove_session_worktree(target, wt)

    def test_a_redirected_worktree_git_marker_is_refused_not_followed(self):
        """Review P1-1 round 2 (agents-6ce): the worktree's .git marker is a FILE inside the
        writable run_dir, so a write-enabled model can replace `gitdir: <target>/.git/worktrees/
        <name>` with `gitdir: <target>/.git`. An unpinned host-side `git add -A` would then run
        against the operator's real repo and STAGE THE OPERATOR'S uncommitted target edits.
        _collect_session_diff must validate the marker against the admin gitdir captured at
        creation and REFUSE; its --git-dir/--work-tree pinning is the second layer that makes
        the redirect ineffective regardless. The operator's target index must be untouched."""
        target = self.root / "redirect-target"
        target.mkdir()
        subprocess.run(["git", "init", "-q", str(target)], check=True, capture_output=True)
        (target / "committed.txt").write_text("base\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(target), "add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(target), "-c", "user.email=f@t", "-c", "user.name=f",
                        "commit", "-qm", "init"], check=True, capture_output=True)
        # An operator edit sitting UNSTAGED in the target's own checkout — exactly what the
        # attack would stage into the target's index if host-side git followed the marker.
        (target / "committed.txt").write_text("base\nOPERATOR UNCOMMITTED WORK\n", encoding="utf-8")
        index_before = (target / ".git" / "index").read_bytes()

        wt = self.root / "redirect-wt"
        gitdir = factory_cli._create_session_worktree(target, wt)
        # The model edits its worktree, then repoints the .git marker at the target's real .git.
        (wt / "committed.txt").write_text("base\nmodel edit\n", encoding="utf-8")
        (wt / ".git").write_text(f"gitdir: {target / '.git'}\n", encoding="utf-8")

        run_dir = self.root / "redirect-run"
        run_dir.mkdir()
        try:
            with self.assertRaises(factory_cli.StationError):
                factory_cli._collect_session_diff(wt, run_dir, gitdir)
            self.assertFalse((run_dir / "session.patch").exists(),
                             "a refused marker redirect must not produce a patch")
            self.assertEqual((target / ".git" / "index").read_bytes(), index_before,
                             "the redirected marker must never stage the operator's target index")
        finally:
            factory_cli._remove_session_worktree(target, wt)

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_the_worktree_is_removed_even_when_the_engine_fails(self):
        """agents-6ce hard requirement: no leaked worktrees. An engine that edits the worktree
        and then FAILS must still have its disposable worktree discarded by the finally block,
        and the target checkout must stay byte-identical. Gated on bwrap and asserting the
        worktree-write policy + a /worktree cwd FIRST (review P1-2 round 2): without a real OS
        sandbox the run downgrades to read-only, no worktree is created, and the cleanup
        assertions below would pass vacuously — proving nothing about worktree cleanup."""
        self._git_init_target()
        # A stub that records its policy/cwd, edits a file inside the worktree, then fails
        # (non-zero, no report). The adapter propagates the failure (pi.sh: `pi ... || exit 1`),
        # so run_agent raises StationError only AFTER the finally has removed the worktree.
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "echo \"POLICY:${FACTORY_TOOL_POLICY:-unset}\"\n"
            "echo \"CWD:$(pwd)\"\n"
            "printf '// edited then crashed\\n' >> fixme.txt\n"
            "cat >/dev/null\n"
            "exit 7\n",
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        before = self._target_fingerprint()
        res = self.factory("pi")
        self.assertNotEqual(res.returncode, 0, "a failed engine must fail the run")
        # Prove the worktree path was actually taken (review P1-2 round 2): the grant was
        # worktree-write and the engine ran inside the disposable worktree, not the target.
        # Without this the cleanup assertions below could pass on a downgraded read-only run.
        self.assertEqual(self.stub_line("POLICY:"), WORKTREE_WRITE)
        self.assertTrue(self.stub_line("CWD:").endswith("/worktree"), self.stub_line("CWD:"))
        # No worktree leaked despite the failure, and the target is byte-identical.
        self._assert_no_leaked_worktree()
        self.assertEqual(self._target_fingerprint(), before,
                         "the target checkout must be byte-identical even when the engine fails")
        # agents-7ik (d): a failed session's partial edits are NOT collected as a proposal.
        self.assertIn("discarding its partial edits", res.stdout)
        self.assertFalse((self.run_dirs()[0] / "session.patch").exists(),
                         "a failed session must not leave a proposal patch")

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_the_session_patch_carries_a_base_commit_and_applies_cleanly(self):
        """agents-7ik (b): session.patch begins with a `base-commit:` trailer naming the
        base HEAD, so a proposal can never be applied blind against a moved HEAD — and
        git apply skips the trailer (verified here by applying the whole marked patch to a
        fresh clone of the same base)."""
        self._git_init_target()
        self._editing_stub()
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        run_dir = self.run_dirs()[0]
        patch_text = (run_dir / "session.patch").read_text(encoding="utf-8")
        head = subprocess.run(["git", "-C", str(self.target), "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
        self.assertTrue(patch_text.startswith(f"base-commit: {head}\n"),
                        patch_text[:120])
        clone = self.root / "apply-clone"
        subprocess.run(["git", "clone", "-q", str(self.target), str(clone)],
                       check=True, capture_output=True)
        applied = subprocess.run(["git", "-C", str(clone), "apply",
                                  str(run_dir / "session.patch")],
                                 capture_output=True, text=True)
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.assertTrue((clone / "proposed.txt").exists(),
                        "the proposal's new file must apply")

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_a_tampered_candidates_json_fails_closed(self):
        """agents-5bn: candidates.json is the scanner's ground truth (agents-nha) that binds
        the model's rule_id/path at findings dispatch, which runs AFTER the session. The run
        dir is rw-bound inside the sandbox, so a write-granted session can overwrite it. The
        dispatcher snapshots the trusted bytes before the session and must REFUSE the dispatch
        (station failure) when the session changed them — never book findings against forged
        ground truth."""
        self._git_init_target()
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        scripts = self.root / "agents" / "probe" / "scripts"
        scripts.mkdir(parents=True)
        (scripts / "prepass.py").write_text(
            "import json, sys\n"
            "out = sys.argv[sys.argv.index('--output') + 1]\n"
            "with open(out, 'w', encoding='utf-8') as fh:\n"
            "    json.dump({'candidates': [{'rule_id': 'vuln-x', 'path': 'fixme.txt',\n"
            "                              'line_number': 1, 'snippet': 'original line'}]}, fh)\n",
            encoding="utf-8",
        )
        # A write-granted session that overwrites the scanner ground truth from inside its
        # worktree (the run dir is the worktree's parent): ../candidates.json.
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "printf 'FORGED' > ../candidates.json\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        res = self.factory("pi")
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertIn("candidates.json changed during the engine session", res.stderr)

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_an_untampered_write_session_with_candidates_dispatches(self):
        """agents-5bn positive control: a write-granted session that leaves candidates.json
        alone still dispatches normally — the snapshot verification must not false-positive on
        the honest path (a pre-pass that produces candidates, then a normal editing session)."""
        self._git_init_target()
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        scripts = self.root / "agents" / "probe" / "scripts"
        scripts.mkdir(parents=True)
        (scripts / "prepass.py").write_text(
            "import json, sys\n"
            "out = sys.argv[sys.argv.index('--output') + 1]\n"
            "with open(out, 'w', encoding='utf-8') as fh:\n"
            "    json.dump({'candidates': [{'rule_id': 'vuln-x', 'path': 'fixme.txt',\n"
            "                              'line_number': 1, 'snippet': 'original line'}]}, fh)\n",
            encoding="utf-8",
        )
        self._editing_stub()
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        run_dir = self.run_dirs()[0]
        patch = run_dir / "session.patch"
        self.assertTrue(patch.exists(), "the honest editing session must still collect a patch")
        self.assertIn("proposed fix", patch.read_text(encoding="utf-8"))

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_a_preplaced_session_patch_is_discarded_when_no_edits_are_made(self):
        """agents-5bn: a write-granted session runs with the run dir rw-bound, so it can write
        run_dir/session.patch directly and be credited with a proposal it never made in the
        worktree. When the session makes no trackable edits, _collect_session_diff returns None
        and the dispatcher must discard any session.patch left in the run dir — only a collected
        patch is a real proposal."""
        self._git_init_target()
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "printf 'forged proposal' > ../session.patch\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertFalse((self.run_dirs()[0] / "session.patch").exists(),
                         "a forged pre-placed session.patch must not survive a no-edit session")

    def test_a_planted_session_patch_tmp_symlink_is_not_followed(self):
        """agents-5bn: the run dir is rw-bound inside the sandbox, so a write-granted session
        could plant a symlink at session.patch.tmp pointing at an arbitrary operator-writable
        host file; host-side collection writing the temp file must not follow it. Unlink the name
        before writing so the planted target is never overwritten."""
        target = self.root / "symlink-target"
        target.mkdir()
        subprocess.run(["git", "init", "-q", str(target)], check=True, capture_output=True)
        (target / "f.txt").write_text("one\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(target), "add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(target), "-c", "user.email=f@t", "-c", "user.name=f",
                        "commit", "-qm", "init"], check=True, capture_output=True)
        wt = self.root / "symlink-wt"
        gitdir = factory_cli._create_session_worktree(target, wt)
        (wt / "f.txt").write_text("one\ntwo\n", encoding="utf-8")
        run_dir = self.root / "symlink-run"
        run_dir.mkdir()
        canary = self.root / "canary.txt"
        canary.write_text("DO NOT OVERWRITE", encoding="utf-8")
        # A planted symlink at the temp-file path, as a write-granted session could leave.
        (run_dir / "session.patch.tmp").symlink_to(canary)
        try:
            patch_file = factory_cli._collect_session_diff(wt, run_dir, gitdir)
            self.assertIsNotNone(patch_file)
            self.assertEqual(canary.read_text(encoding="utf-8"), "DO NOT OVERWRITE",
                             "the planted symlink must never redirect the temp write at its target")
            self.assertIn("two", (run_dir / "session.patch").read_text(encoding="utf-8"))
        finally:
            factory_cli._remove_session_worktree(target, wt)

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_a_forged_candidates_json_without_a_prepass_fails_closed(self):
        """agents-5bn: even a write-granted agent with no deterministic pre-pass must not be
        able to mint its own candidates.json — it has no trusted origin. The dispatcher refuses
        findings dispatch when candidates.json exists but no pre-pass produced it."""
        self._git_init_target()
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "printf '{\"candidates\":[{\"rule_id\":\"forged\",\"path\":\"forged.py\"}]}'"
            " > ../candidates.json\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        res = self.factory("pi")
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertIn("candidates.json appeared during the engine session", res.stderr)

    def test_write_run_artifact_does_not_follow_a_planted_symlink(self):
        """agents-5bn P0: a write-granted session can plant a symlink at any run-dir path; the
        helper must unlink it first so the write never follows it to an arbitrary host file."""
        run_dir = self.root / "symlink-artifact-run"
        run_dir.mkdir()
        canary = self.root / "authorized_keys"
        canary.write_text("SSH CANARY", encoding="utf-8")
        target = run_dir / "report.json"
        target.symlink_to(canary)
        factory_cli._write_run_artifact(target, '{"summary": "clean"}')
        self.assertEqual(canary.read_text(encoding="utf-8"), "SSH CANARY",
                         "the write must not follow the planted symlink")
        self.assertEqual(target.read_text(encoding="utf-8"), '{"summary": "clean"}',
                         "the artifact must be a fresh regular file")

    def test_write_run_artifact_fails_closed_on_a_planted_directory(self):
        """agents-5bn P0: a session could plant a directory at an artifact path; unlink on a
        directory raises, so the write fails closed rather than erroring into a bad state."""
        run_dir = self.root / "symlink-dir-run"
        run_dir.mkdir()
        target = run_dir / "report.json"
        target.mkdir()
        with self.assertRaises(factory_cli.StationError):
            factory_cli._write_run_artifact(target, "x")

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_a_planted_report_json_symlink_is_not_followed(self):
        """agents-5bn P0 end-to-end: a write-granted session plants a symlink at
        run_dir/report.json pointing at a host canary; the post-session report.json write must
        unlink it first, so the canary is untouched and the real report is written."""
        self._git_init_target()
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        canary = self.root / "authorized_keys"
        canary.write_text("SSH CANARY", encoding="utf-8")
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            f"ln -s {canary} ../report.json\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(canary.read_text(encoding="utf-8"), "SSH CANARY",
                         "the post-session report.json write must not follow the planted symlink")
        report = json.loads((self.run_dirs()[0] / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(report.get("summary"), "stub", "the real report.json must be written")

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_staging_writes_no_content_blobs_into_the_shared_object_store(self):
        """agents-7ik (c): intent-to-add staging must not litter the target's shared
        .git/objects with unreferenced content blobs (a plain `git add -A` wrote one per
        new/modified file every run). At most the canonical empty blob (size 0) may
        appear, once; never the session's content."""
        self._git_init_target()
        self._editing_stub()
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        objects = self.target / ".git" / "objects"
        before = {p for p in objects.rglob("*") if p.is_file()}
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        after = {p for p in objects.rglob("*") if p.is_file()}
        new_objects = after - before
        self.assertLessEqual(len(new_objects), 1,
                             f"staging wrote {len(new_objects)} objects: {new_objects}")
        for obj in new_objects:
            sha = f"{obj.parent.name}{obj.name}"
            size = subprocess.run(["git", "-C", str(self.target), "cat-file", "-s", sha],
                                  capture_output=True, text=True, check=True).stdout.strip()
            self.assertEqual(size, "0", "the only allowed new object is the empty blob")

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_gitignored_edits_are_reported_honestly(self):
        """agents-7ik (a): a session whose only edits land in gitignored paths must not
        be reported as 'no file edits' — the files exist on disk — but as ignored edits,
        honestly not representable as a patch proposal."""
        self._git_init_target()
        (self.target / ".gitignore").write_text("ignored/\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.target), "add", ".gitignore"], check=True,
                       capture_output=True)
        subprocess.run(["git", "-C", str(self.target), "-c", "user.email=factory@test",
                        "-c", "user.name=factory", "commit", "-qm", "gitignore"],
                       check=True, capture_output=True)
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "mkdir -p ignored && printf 'junk\\n' > ignored/x.txt\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("gitignored files", res.stdout)
        self.assertIn("not representable as a patch proposal", res.stdout)
        self.assertNotIn("no file edits", res.stdout)
        self.assertFalse((self.run_dirs()[0] / "session.patch").exists())

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_a_session_cannot_tamper_with_its_own_policy_record(self):
        """agents-7ik (2): run_dir is the read-write bind, so a granted-write session can
        reach its own policy.json — but whatever it writes there does not survive it: the
        dispatcher rewrites the record from its captured bytes after the session closes."""
        self._git_init_target()
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "echo \"POLICY:${FACTORY_TOOL_POLICY:-unset}\"\n"
            # The tamper: overwrite the containment record mid-session.
            "printf '%s' '{\"tampered\": true, \"granted\": {\"tool_policy\": \"unrestricted\"}}' "
            "> ../policy.json\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.stub_line("POLICY:"), WORKTREE_WRITE,
                         "sanity: this really was a granted-write session")
        record = json.loads((self.run_dirs()[0] / "policy.json").read_text(encoding="utf-8"))
        self.assertNotIn("tampered", record)
        self.assertEqual(record["granted"]["tool_policy"], WORKTREE_WRITE,
                         "the post-session rewrite must restore the dispatcher's record")

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

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_a_sandboxed_engine_has_no_route_off_its_netns(self):
        """agents-2x6 acceptance: with egress control active the engine runs under
        --unshare-net, so a dial off the sandbox must genuinely fail at the kernel, not by
        convention. The allowlisted path — the credential broker through the net_forward
        relay — is proven end to end by the 8h4 acceptance test above, which now runs through
        that relay (the engine dials 127.0.0.1:8384 and the broker answers). This is the
        complement: everything ELSE is unreachable, and no resolver is available either."""
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "python3 - <<'PYEOF'\n"
            "import socket\n"
            "try:\n"
            "    socket.create_connection(('93.184.216.34', 443), timeout=3).close()\n"
            "    print('DIRECT:REACHED')\n"
            "except OSError:\n"
            "    print('DIRECT:UNREACHABLE')\n"
            "try:\n"
            "    socket.gethostbyname('api.github.com')\n"
            "    print('DNS:RESOLVED')\n"
            "except OSError:\n"
            "    print('DNS:BLOCKED')\n"
            "PYEOF\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "capabilities: {}\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.stub_line("DIRECT:"), "UNREACHABLE",
                         "under --unshare-net a dial off the netns must fail at the kernel")
        self.assertEqual(self.stub_line("DNS:"), "BLOCKED",
                         "no resolver may be reachable from the isolated netns")

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_the_prepass_egress_is_held_to_its_own_allowlist(self):
        """agents-2x6 acceptance: the pre-pass runs under --unshare-net with the egress
        proxy as its only route off the netns (HTTP_PROXY points at the in-sandbox relay),
        and the allowlist is derived from the agent's OWN requires — here [gh] →
        api.github.com — so a fetch of any other host is refused by the proxy itself (403).
        The refusal is decided before any upstream dial, so this needs no live network."""
        self.agent("name: probe\nclass: observer\ncontainment: t1-fetch\n"
                   "capabilities:\n  network: true\n  requires: [gh]\n"
                   "budget: {max_minutes: 1}\n")
        scripts = self.root / "agents" / "probe" / "scripts"
        scripts.mkdir(parents=True)
        (scripts / "prepass.py").write_text(
            "import json, os, sys, urllib.error, urllib.request\n"
            "out = sys.argv[sys.argv.index('--output') + 1]\n"
            "try:\n"
            "    urllib.request.urlopen('http://registry.npmjs.org/-/ping', timeout=5)\n"
            "    verdict = 'reached'\n"
            "except urllib.error.HTTPError as e:\n"
            "    verdict = f'http-{e.code}'\n"
            "except OSError as e:\n"
            "    verdict = f'os-{type(e).__name__}'\n"
            "with open(out, 'w', encoding='utf-8') as fh:\n"
            "    json.dump({'egress': verdict, 'proxy': os.environ.get('HTTP_PROXY')}, fh)\n",
            encoding="utf-8",
        )
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        payload = json.loads((self.run_dirs()[0] / "candidates.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["proxy"], "http://127.0.0.1:8385",
                         "the pre-pass must be pointed at the in-sandbox egress proxy")
        self.assertEqual(payload["egress"], "http-403",
                         "a host outside the agent's own requires allowlist must be refused")

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_unbrokerable_model_downgrades_network_and_reports_egress_unfiltered(self):
        """agents-8xei: when a run requests an unbrokerable model (e.g. mistral/mistral-large),
        the key survey recognizes the model provider cannot be brokered under --unshare-net,
        downgrades network to withheld, and honestly reports network-egress as not enforced."""
        self.agent("name: probe\nclass: observer\ncontainment: t1-fetch\n"
                   "capabilities:\n  network: true\n"
                   "budget: {max_minutes: 1}\n")
        res = self.factory("pi", {"FACTORY_MODEL": "mistral/mistral-large"})
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        record = json.loads((self.run_dirs()[0] / "policy.json").read_text(encoding="utf-8"))
        self.assertIn("network-egress", record["not_enforced"])
        self.assertFalse(record["granted"]["os_sandbox"]["network_egress_filtered"])
        self.assertIn("network egress NOT filtered", res.stdout)
        self.assertIn("Withheld:    network", res.stdout)

if __name__ == "__main__":
    unittest.main()
