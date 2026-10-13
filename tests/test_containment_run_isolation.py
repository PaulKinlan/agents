"""Containment: run-directory exclusivity, the unsandboxed opt-in, and target trust.

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

class TestRunIsolation(harness.ContainmentHarness):
    """Run-directory exclusivity, the unsandboxed opt-in, and target trust."""


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

if __name__ == "__main__":
    unittest.main()
