"""Containment: the worktree write grant, and every path that must downgrade it.

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

class TestWriteGrants(harness.ContainmentHarness):
    """The worktree write grant, and every path that must downgrade it."""


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

if __name__ == "__main__":
    unittest.main()
