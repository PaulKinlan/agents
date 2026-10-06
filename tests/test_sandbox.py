#!/usr/bin/env python3
"""The OS sandbox confines the engine's filesystem to the target (agents-9n7).

Two layers:

1. Unit: sandbox_command() builds a bwrap argv that is an allowlist — target ro, run dir
   rw, factory root ro with runs/ masked, home roots tmpfs'd, a private PID namespace with
   a real procfs, and no bind of anything else on the host.
2. Live (skipped where bubblewrap cannot run): the agents-pnu probe, reproduced — a canary
   file outside the target is unreadable from inside the sandbox, a file inside the target
   is readable, the run directory is writable, the operator's home is invisible, and host
   processes are invisible.

The dispatcher-level guarantee (banner + policy.json say what was enforced) lives in
tests/test_containment.py, which holds the stub-engine harness.
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.sandbox import (  # noqa: E402
    SANDBOXED_ENGINES, SandboxError, engine_sandboxed, sandbox_available, sandbox_command,
    sandbox_record,
)

LIVE = sandbox_available()


def _pairs(argv, flag):
    """The (source, dest) pairs of every `flag` mount in a bwrap argv."""
    out = []
    for i, item in enumerate(argv):
        if item == flag:
            out.append((argv[i + 1], argv[i + 2]))
    return out


class TestSandboxCommandShape(unittest.TestCase):
    """What the bwrap argv must contain, checked without running bwrap."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="factory-9n7-shape-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.factory = self.root / "factory-root"
        (self.factory / "runs" / "old").mkdir(parents=True)
        self.target = self.root / "target"
        self.target.mkdir()
        self.run_dir = self.factory / "runs" / "run1"
        self.run_dir.mkdir(parents=True)

    def build(self, env=None, inner=("/bin/true",)):
        return sandbox_command(
            list(inner), target_dir=self.target, factory_root=self.factory,
            run_dir=self.run_dir, env=env if env is not None else {"PATH": "/usr/bin:/bin"},
        )

    def test_target_is_bound_read_only_and_run_dir_writable(self):
        argv = self.build()
        ro = dict(_pairs(argv, "--ro-bind"))
        rw = dict(_pairs(argv, "--bind"))
        self.assertEqual(ro.get(os.path.realpath(self.target)), os.path.realpath(self.target))
        self.assertEqual(rw.get(os.path.realpath(self.run_dir)), os.path.realpath(self.run_dir))
        self.assertNotIn(os.path.realpath(self.run_dir), ro)

    def test_factory_root_is_read_only_and_other_runs_are_masked(self):
        argv = self.build()
        ro = dict(_pairs(argv, "--ro-bind"))
        self.assertEqual(ro.get(os.path.realpath(self.factory)), os.path.realpath(self.factory))
        tmpfs = [argv[i + 1] for i, a in enumerate(argv) if a == "--tmpfs"]
        self.assertIn(str(self.factory / "runs"), tmpfs,
                      "other runs' raw scanner artifacts must not be readable")

    def test_home_roots_are_tmpfs_never_binds(self):
        argv = self.build(env={"PATH": "/usr/bin:/bin", "HOME": "/home/someuser"})
        tmpfs = [argv[i + 1] for i, a in enumerate(argv) if a == "--tmpfs"]
        self.assertIn("/home/someuser", tmpfs)
        if os.path.isdir("/home"):
            self.assertIn("/home", tmpfs)
        if os.path.isdir("/root"):
            self.assertIn("/root", tmpfs)
        for source, _dest in _pairs(argv, "--ro-bind") + _pairs(argv, "--bind"):
            self.assertFalse(source == "/home" or source.startswith("/home/"),
                             f"home content must never be bound: {source}")
            self.assertFalse(source == "/root" or source.startswith("/root/"),
                             f"home content must never be bound: {source}")

    def test_private_pid_namespace_with_a_real_procfs(self):
        argv = self.build()
        self.assertIn("--unshare-pid", argv)
        self.assertIn("--proc", argv)
        self.assertEqual(argv[argv.index("--proc") + 1], "/proc")

    def test_the_child_dies_with_its_parent_in_a_new_session(self):
        argv = self.build()
        self.assertIn("--die-with-parent", argv)
        self.assertIn("--new-session", argv)

    def test_nothing_outside_the_allowlist_is_bound(self):
        """Every ro/rw bind source is the factory root, the target, the run dir, a system
        directory, or an executable tree from the child's PATH — nothing else."""
        path_dirs = []
        with tempfile.TemporaryDirectory(prefix="factory-9n7-bin-") as bindir:
            path_dirs.append(bindir)
            argv = self.build(env={"PATH": f"{bindir}:/usr/bin:/bin", "HOME": "/nonexistent"})
        allowed_prefixes = tuple(
            os.path.realpath(p) for p in
            [self.factory, self.target, self.run_dir, "/usr", "/etc", *path_dirs])
        for source, _dest in _pairs(argv, "--ro-bind") + _pairs(argv, "--bind"):
            self.assertTrue(
                any(source == a or source.startswith(a + os.sep) for a in allowed_prefixes)
                or source in ("/bin", "/sbin", "/lib", "/lib64"),
                f"unexpected bind source: {source}")

    def test_path_directories_under_hidden_roots_are_rebound(self):
        with tempfile.TemporaryDirectory(prefix="factory-9n7-tools-") as tools:
            argv = self.build(env={"PATH": f"{tools}:/usr/bin", "HOME": "/nonexistent"})
        sources = [s for s, _d in _pairs(argv, "--ro-bind")]
        self.assertIn(os.path.realpath(tools), sources,
                      "executables the child's PATH needs must be reachable inside")

    def test_an_empty_command_is_refused(self):
        with self.assertRaises(SandboxError):
            sandbox_command([], target_dir=self.target, factory_root=self.factory,
                            run_dir=self.run_dir)


class TestSandboxRecord(unittest.TestCase):
    def test_no_sandbox_host_records_none(self):
        if LIVE:
            self.skipTest("host has a sandbox; the None path is unit-covered by the code")
        self.assertIsNone(sandbox_record("pi"))

    @unittest.skipUnless(LIVE, "needs bubblewrap")
    def test_a_verified_engine_is_sandboxed_and_says_confined(self):
        for engine in SANDBOXED_ENGINES:
            record = sandbox_record(engine)
            self.assertTrue(record["engine_sandboxed"])
            self.assertTrue(record["prepass_sandboxed"])
            self.assertIn("confined to the target", record["engine_read_scope"])
            self.assertFalse(record["network_egress_filtered"])
            self.assertTrue(engine_sandboxed(engine))

    @unittest.skipUnless(LIVE, "needs bubblewrap")
    def test_an_unverified_engine_is_not_sandboxed_and_the_record_says_so(self):
        record = sandbox_record("antigravity")
        self.assertFalse(record["engine_sandboxed"])
        self.assertIsNone(record["engine_read_scope"])
        self.assertFalse(engine_sandboxed("antigravity"))


@unittest.skipUnless(LIVE, "needs a host where bubblewrap actually runs")
class TestSandboxLive(unittest.TestCase):
    """The agents-pnu probe, reproduced under the real wrapper."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="factory-9n7-live-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.factory = self.root / "factory-root"
        (self.factory / "runs" / "run1").mkdir(parents=True)
        self.target = self.root / "target"
        self.target.mkdir()
        (self.target / "inside.txt").write_text("TARGET FILE OK\n", encoding="utf-8")
        self.outside = self.root / "outside"
        self.outside.mkdir()
        (self.outside / "canary.txt").write_text("CANARY agents-pnu\n", encoding="utf-8")
        self.run_dir = self.factory / "runs" / "run1"
        self.env = {"PATH": "/usr/bin:/bin",
                    "HOME": str(self.root / "sandbox-home"),
                    "ANTHROPIC_API_KEY": "sk-test-placeholder"}
        (self.root / "sandbox-home").mkdir()

    def run_inside(self, script):
        cmd = sandbox_command(["/bin/sh", "-c", script], target_dir=self.target,
                              factory_root=self.factory, run_dir=self.run_dir, env=self.env)
        return subprocess.run(cmd, capture_output=True, text=True, env=self.env,
                              timeout=120, stdin=subprocess.DEVNULL)

    def test_the_canary_outside_the_target_is_unreadable(self):
        res = self.run_inside(
            f"cat {self.outside}/canary.txt; cat {self.target}/../outside/canary.txt")
        self.assertNotIn("CANARY", res.stdout)
        self.assertIn("No such file", res.stderr + res.stdout)

    def test_the_target_is_readable_and_read_only(self):
        res = self.run_inside(
            f"cat {self.target}/inside.txt; touch {self.target}/x 2>&1 | head -1")
        self.assertIn("TARGET FILE OK", res.stdout)
        self.assertIn("Read-only file system", res.stdout)

    def test_the_run_directory_is_writable(self):
        res = self.run_inside(f"touch {self.run_dir}/out.txt && echo RUN_WRITE_OK")
        self.assertIn("RUN_WRITE_OK", res.stdout)
        self.assertTrue((self.run_dir / "out.txt").exists())

    def test_other_runs_are_invisible(self):
        other = self.factory / "runs" / "run0"
        other.mkdir()
        (other / "secret.json").write_text('{"raw": "another run"}', encoding="utf-8")
        res = self.run_inside(f"cat {other}/secret.json 2>&1; ls {self.factory}/runs")
        self.assertNotIn("another run", res.stdout)

    def test_the_operator_home_is_invisible(self):
        (self.root / "sandbox-home" / ".secret").write_text("HOME SECRET", encoding="utf-8")
        real_home = Path.home()
        res = self.run_inside(f"cat $HOME/.secret 2>&1; ls -A {real_home} 2>&1")
        self.assertNotIn("HOME SECRET", res.stdout)
        self.assertIn("No such file", res.stdout)
        if str(real_home).startswith(("/home", "/root")):
            # The home root exists inside but is an empty tmpfs: no operator content.
            listing = [line for line in res.stdout.splitlines()
                       if line and "No such file" not in line and "cannot access" not in line]
            self.assertEqual(listing, [], f"operator home content leaked: {listing}")

    def test_real_operator_home_content_is_unreachable(self):
        """The actual home of the user running the test (e.g. ~/.pi/auth.json, ~/.ssh) is
        not reachable, unless it is a PATH tree the child legitimately needs."""
        real_home = Path.home()
        if not str(real_home).startswith(("/home", "/root")):
            self.skipTest("test needs a home under a hidden root")
        candidates = sorted(p.name for p in real_home.iterdir())
        self.assertTrue(candidates, "expected some real home content to probe")
        script = "; ".join(f"ls -A {real_home / name} 2>/dev/null || "
                           f"cat {real_home / name} 2>/dev/null" for name in candidates[:20])
        res = self.run_inside(f"{script}; echo PROBE_DONE")
        self.assertIn("PROBE_DONE", res.stdout)
        self.assertEqual(res.stdout.replace("PROBE_DONE", "").strip(), "",
                         "operator home content leaked into the sandbox")

    def test_host_processes_are_invisible(self):
        """Private PID namespace: the sandbox sees only its own process tree, so no host
        process's /proc/<pid>/environ is reachable."""
        host_pids = {p for p in os.listdir("/proc") if p.isdigit()}
        res = self.run_inside("ls /proc | grep '^[0-9]'")
        visible = set(res.stdout.split())
        self.assertTrue(visible, "the sandbox must see its own processes")
        self.assertTrue(len(visible) < 12, f"too many PIDs visible: {sorted(visible)}")
        outside_only = host_pids - {"1"} - visible
        self.assertTrue(outside_only, "test needs host PIDs the sandbox should not see")
        probe = self.run_inside(
            "for p in " + " ".join(sorted(outside_only)[:20]) +
            "; do cat /proc/$p/environ >/dev/null 2>&1 && echo LEAK $p; done; echo PROBE_DONE")
        self.assertIn("PROBE_DONE", probe.stdout)
        self.assertNotIn("LEAK", probe.stdout)

    def test_env_credentials_are_the_only_secret_in_reach(self):
        """Documented residual (policy.json not_enforced: env-credentials): the engine's
        own /proc/self/environ is readable by its own read tool because bun/pi needs a real
        procfs. This test pins the residual to exactly the child_env allowlist: the key the
        dispatcher passed is there, and nothing from the operator's shell environment is —
        bwrap is given the child env, and the dispatcher (run_station_command) never passes
        the operator's env."""
        os.environ["OPERATOR_SIDE_SECRET"] = "must-not-appear"
        self.addCleanup(os.environ.pop, "OPERATOR_SIDE_SECRET", None)
        cmd = sandbox_command(["/bin/sh", "-c", "tr '\\0' '\\n' < /proc/self/environ"],
                              target_dir=self.target, factory_root=self.factory,
                              run_dir=self.run_dir, env=self.env)
        res = subprocess.run(cmd, capture_output=True, text=True, env=self.env,
                             timeout=120, stdin=subprocess.DEVNULL)
        self.assertIn("sk-test-placeholder", res.stdout,
                      "the engine's own key must reach it (env is the only channel)")
        self.assertNotIn("must-not-appear", res.stdout,
                         "the operator's shell env must never reach the sandbox child")


if __name__ == "__main__":
    unittest.main()
