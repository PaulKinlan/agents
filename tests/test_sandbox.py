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
os.environ.setdefault("FACTORY_ALLOW_UNPINNED_TOOLS", "1")  # agents-7bj: tests use unpinned stub tools
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.sandbox import (  # noqa: E402
    SANDBOXED_ENGINES, SandboxError, engine_sandboxed, sandbox_available, sandbox_command,
    sandbox_record,
)
from lib import sandbox as sandbox_module  # noqa: E402

LIVE = sandbox_available()


def _pairs(argv, flag):
    """The (source, dest) pairs of every `flag` mount in a bwrap argv."""
    out = []
    for i, item in enumerate(argv):
        if item == flag:
            out.append((argv[i + 1], argv[i + 2]))
    return out


@unittest.skipUnless(LIVE, "sandbox_command() exercises every wrap, so these need a real bwrap")
class TestSandboxCommandShape(unittest.TestCase):
    """What the bwrap argv must contain. sandbox_command() now exercises every wrap it builds
    (agents-kwi), so each of these runs a real exercise rather than only building argv — and
    needs a functional bubblewrap, hence the LIVE gate."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="factory-9n7-shape-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.factory = self.root / "factory-root"
        (self.factory / "runs" / "old").mkdir(parents=True)
        # sandbox_command() exercises every wrap it builds (agents-kwi), and an egress wrap
        # runs lib/net_forward.py from the factory root: the fake root must carry it.
        (self.factory / "lib").mkdir()
        shutil.copyfile(ROOT / "lib" / "net_forward.py",
                        self.factory / "lib" / "net_forward.py")
        self.target = self.root / "target"
        self.target.mkdir()
        self.run_dir = self.factory / "runs" / "run1"
        self.run_dir.mkdir(parents=True)

    def build(self, env=None, inner=("/bin/true",), executables=(), egress_forwards=None,
              rw_binds=()):
        return sandbox_command(
            list(inner), target_dir=self.target, factory_root=self.factory,
            run_dir=self.run_dir, env=env if env is not None else {"PATH": "/usr/bin:/bin"},
            executables=executables, egress_forwards=egress_forwards, rw_binds=rw_binds,
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

    def test_no_egress_forwards_keeps_the_host_network(self):
        # The default (agents-2x6 off, or an unbrokerable-provider fallback): the host
        # network stays shared and the inner command runs directly, unwrapped.
        argv = self.build()
        self.assertNotIn("--unshare-net", argv)
        self.assertEqual(argv[-1], "/bin/true")

    def test_egress_forwards_isolates_net_and_wraps_in_net_forward(self):
        # agents-2x6: egress control isolates the netns (a direct connect() off-box fails
        # ENETUNREACH) and wraps inner behind net_forward, which relays the child's loopback
        # ports to the host-side broker/proxy UNIX sockets — the only egress path.
        argv = self.build(inner=("/bin/echo", "hi"),
                          egress_forwards=[(8384, "/run/x/broker.sock"),
                                           (8385, "/run/x/proxy.sock")])
        self.assertIn("--unshare-net", argv)
        self.assertTrue(any(a.endswith(os.path.join("lib", "net_forward.py")) for a in argv),
                        "net_forward.py is not the wrapper")
        self.assertIn("--forward", argv)
        self.assertIn("8384=/run/x/broker.sock", argv)
        self.assertIn("8385=/run/x/proxy.sock", argv)
        # The original inner command survives verbatim after net_forward's own `--`.
        last_sep = len(argv) - 1 - argv[::-1].index("--")
        self.assertEqual(argv[last_sep + 1:], ["/bin/echo", "hi"])

    def test_an_egress_socket_path_over_the_sun_path_limit_is_refused(self):
        # agents-x8l: AF_UNIX sun_path holds at most 107 bytes. Refuse a path that can never
        # bind loudly, rather than let bind() fail with ENAMETOOLONG deep in the server thread.
        with self.assertRaises(SandboxError) as cm:
            self.build(egress_forwards=[(8384, "/" * 108)])
        self.assertIn("sun_path", str(cm.exception))
        self.assertIn("107", str(cm.exception))

    def test_egress_sockets_outside_run_dir_get_their_parent_bound(self):
        # agents-x8l: the egress sockets live in a short per-run dir under /tmp (run_dir can
        # exceed AF_UNIX's sun_path limit). sandbox_command must rw-bind that dir so the
        # in-sandbox net_forward relay reaches the host-side listener.
        sock_dir = Path(tempfile.mkdtemp(prefix="factory-sock-test-", dir="/tmp"))
        self.addCleanup(shutil.rmtree, sock_dir, True)
        argv = self.build(egress_forwards=[(8384, str(sock_dir / "broker.sock"))])
        rw = dict(_pairs(argv, "--bind"))
        self.assertEqual(rw.get(os.path.realpath(sock_dir)), os.path.realpath(sock_dir),
                         "the socket's parent dir must be rw-bound into the sandbox")

    def test_rw_binds_are_bound_writable(self):
        # agents-854: pi's agent dir (PI_CODING_AGENT_DIR) must be writable inside the sandbox
        # (pi opens its auth.json credential store read-write even when auth comes from env),
        # so extra config directories are rw-bound, not read-only.
        cfg_dir = Path(tempfile.mkdtemp(prefix="factory-pi-test-", dir="/tmp"))
        self.addCleanup(shutil.rmtree, cfg_dir, True)
        argv = self.build(rw_binds=[str(cfg_dir)])
        rw = dict(_pairs(argv, "--bind"))
        self.assertEqual(rw.get(os.path.realpath(cfg_dir)), os.path.realpath(cfg_dir),
                         "the config dir must be rw-bound into the sandbox")

    def test_nothing_outside_the_allowlist_is_bound(self):
        """Every ro/rw bind source is the factory root, the target, the run dir, a system
        directory, or a resolved allowlisted executable tree — nothing else."""
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

    def test_only_allowlisted_executables_are_bound_never_whole_path_dirs(self):
        """review P1 (agents-9n7): a directory on the inherited PATH is never bound whole.
        Only the resolved executables named in the allowlist are bound (plus a dedicated
        package dir named after the tool), so a canary an attacker drops into a PATH
        directory stays invisible to the engine. The tools dir lives outside the factory
        root so the factory bind cannot mask the assertion."""
        with tempfile.TemporaryDirectory(prefix="factory-9n7-tools-") as tools:
            tool = Path(tools) / "mytool"
            tool.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
            tool.chmod(0o755)
            (Path(tools) / "canary.txt").write_text("SECRET", encoding="utf-8")
            argv = self.build(env={"PATH": f"{tools}:/usr/bin", "HOME": "/nonexistent"},
                              executables=("mytool",))
            bound = {s for s, _d in _pairs(argv, "--ro-bind") + _pairs(argv, "--bind")}
            # the allowlisted tool is reachable...
            self.assertIn(os.path.realpath(tool), bound)
            # ...but the flat directory is NOT bound whole, so the canary is not exposed.
            self.assertNotIn(os.path.realpath(tools), bound)
            for source in bound:
                self.assertFalse(source.endswith("canary.txt"),
                                 f"a PATH directory's non-executable content must not be "
                                 f"bound: {source}")

    def test_an_unallowlisted_program_on_path_is_not_bound(self):
        """A program on PATH that the caller did not allowlist contributes no bind at all —
        the sandbox binds by name, not by directory (review P1, agents-9n7)."""
        with tempfile.TemporaryDirectory(prefix="factory-9n7-extra-") as extra:
            rogue = Path(extra) / "rogue"
            rogue.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
            rogue.chmod(0o755)
            argv = self.build(env={"PATH": f"{extra}:/usr/bin", "HOME": "/nonexistent"},
                              executables=("mytool",))  # mytool, not rogue
            bound = {s for s, _d in _pairs(argv, "--ro-bind") + _pairs(argv, "--bind")}
            self.assertNotIn(os.path.realpath(rogue), bound)
            self.assertNotIn(os.path.realpath(extra), bound)

    def test_an_empty_command_is_refused(self):
        with self.assertRaises(SandboxError):
            sandbox_command([], target_dir=self.target, factory_root=self.factory,
                            run_dir=self.run_dir)


class TestWrapVerification(unittest.TestCase):
    """agents-kwi: "bwrap is available" is not "this run's child started inside the sandbox".

    sandbox_available()'s probe is a minimal plan (no target/factory/run mounts, no PID
    namespace); a wrap built for a real run can still fail at exec after it passes. Every
    sandbox_command() therefore exercises the plan it just built, with a sentinel child, and
    raises instead of returning a wrap that never started a child — so a station fails before
    any banner or policy.json can call the run sandboxed.

    Documented residual (review P2, agents-kwi, no code): the exercise checks that the inner
    program resolves and is executable inside the wrap, but not that a *script* inner's shebang
    interpreter is bound there. Not reachable today — the inner is the adapter, invoked through
    an interpreter the plan already binds.
    """

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="factory-kwi-wrap-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.factory = self.root / "factory-root"
        (self.factory / "runs").mkdir(parents=True)
        self.target = self.root / "target"
        self.target.mkdir()
        self.run_dir = self.factory / "runs" / "run1"
        self.run_dir.mkdir(parents=True)
        self.real_path = os.environ.get("PATH", "")
        self.addCleanup(os.environ.__setitem__, "PATH", self.real_path)
        # The probe result is process-cached: every fake-bwrap test must re-probe.
        self.addCleanup(setattr, sandbox_module, "_probe_result", None)

    def use_fake_bwrap(self, body, name="fakebin"):
        """Put a fake bwrap on PATH (the path sandbox_command resolves) and return the child
        environment PATH that goes with it."""
        fake_bin = self.root / name
        fake_bin.mkdir()
        stub = fake_bin / "bwrap"
        stub.write_text(body, encoding="utf-8")
        stub.chmod(0o755)
        path = f"{fake_bin}{os.pathsep}{self.real_path}"
        os.environ["PATH"] = path
        sandbox_module._probe_result = None
        return path

    def build(self, path, inner=("/bin/true",)):
        return sandbox_command(list(inner), target_dir=self.target,
                               factory_root=self.factory, run_dir=self.run_dir,
                               env={"PATH": path, "HOME": str(self.root / "home")})

    def test_a_bwrap_that_fails_at_exec_after_a_green_probe_is_refused(self):
        """The agents-kwi reproduction: a bwrap that answers the availability probe (it is
        handed a bare plan ending in /bin/true) but exits non-zero for every real wrap. The
        inner is deliberately NOT /bin/true, so the fake cannot answer the exercised wrap with
        the probe's own exit-0 clause — this pins bwrap's non-zero exit, not the
        rc-0-without-a-token path (`..._exits_zero_without_running_the_child...` below)."""
        path = self.use_fake_bwrap(
            '#!/bin/sh\n'
            'for a in "$@"; do [ "$a" = "/bin/true" ] && exit 0; done\n'
            'exit 1\n')
        self.assertTrue(sandbox_available(), "the probe alone reports the host as sandboxable")
        with self.assertRaises(SandboxError) as raised:
            self.build(path, inner=("/bin/echo", "x"))
        self.assertIn("exited 1", str(raised.exception))
        self.assertEqual(list(self.run_dir.iterdir()), [],
                         "no verification artifact may be left behind")

    def test_a_bwrap_that_exits_zero_without_running_the_child_is_refused(self):
        """Exit status alone is not proof: a bwrap that returns 0 without launching the child
        never writes the sentinel's token, so the wrap is refused rather than recorded."""
        path = self.use_fake_bwrap('#!/bin/sh\nexit 0\n', name="zero-bin")
        with self.assertRaises(SandboxError) as raised:
            self.build(path)
        self.assertIn("could not start a child", str(raised.exception))
        self.assertEqual(list(self.run_dir.iterdir()), [])

    def test_a_wrap_that_cannot_exec_the_inner_program_is_refused(self):
        """The verification is not only about bwrap's exit status: the program the wrap will
        actually exec must be runnable inside the plan. With a real bwrap but an inner that
        does not exist inside the sandbox, sandbox_command refuses."""
        if not LIVE:
            self.skipTest("needs a real bubblewrap to reach the inner-program check")
        with self.assertRaises(SandboxError) as raised:
            sandbox_command([str(self.root / "missing-adapter")], target_dir=self.target,
                            factory_root=self.factory, run_dir=self.run_dir,
                            env={"PATH": "/usr/bin:/bin", "HOME": str(self.root / "home")})
        self.assertIn("cannot execute", str(raised.exception))

    @unittest.skipUnless(LIVE, "needs bubblewrap")
    def test_a_wrap_that_starts_its_child_is_returned_unchanged(self):
        """The positive half: on a host where the wrap really starts its child, the argv the
        station runs is the one built, and the exercise leaves no artifact."""
        argv = self.build("/usr/bin:/bin")
        self.assertEqual(argv[0], shutil.which("bwrap"))
        self.assertEqual(argv[-1], "/bin/true")
        self.assertEqual(list(self.run_dir.iterdir()), [])


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
            self.assertIn("confined by the OS sandbox to the target", record["engine_read_scope"])
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
        process's /proc/<pid>/environ is reachable.

        agents-76v: the old numeric-range probe was a false-positive machine — every probed
        pid was read by a spawned `cat` whose own namespace-LOCAL pid could equal the host
        pid being probed, so `cat` read its OWN environ and reported a LEAK (observed on
        plain main). The probe is now ONE sentinel process started OUTSIDE the sandbox —
        long-lived, carrying a marker in its environ — read by a single grep that requires
        the MARKER, not merely 'some environ readable': even if the prober's own local pid
        collided with the sentinel's host pid, its environ cannot contain the host-side
        marker, so a self-read stays harmless. The host-side sanity read first proves the
        sentinel's environ is genuinely readable from the host pid namespace — so on a
        genuinely SHARED namespace the same read inside the sandbox would find the marker
        and this test fails, exactly as it must."""
        # 76v review P1/P2: the sentinel outlives every probe the test can make (run_inside
        # has a 120s timeout, wrap verification 60s; 600s dwarfs both), it is asserted ALIVE
        # immediately before the in-sandbox probe (expiry fails the test loudly instead of
        # false-passing on an empty /proc entry), and cleanup terminates + REAPS it so no
        # zombie or orphan sleep is left behind.
        sentinel = subprocess.Popen(
            ["sleep", "600"],
            env={**os.environ, "FACTORY_76V_SENTINEL": "host-side-secret-marker"},
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)

        def _reap_sentinel():
            sentinel.terminate()
            try:
                sentinel.wait(timeout=10)
            except subprocess.TimeoutExpired:
                sentinel.kill()
                sentinel.wait(timeout=10)

        self.addCleanup(_reap_sentinel)
        # Host-side sanity: the sentinel's environ exists and carries the marker — readable
        # from the host pid namespace, which is precisely what a shared-ns sandbox would see.
        # Bounded poll for execve to populate /proc/<pid>/environ (agents-h4q, agents-76v):
        # immediately after fork() before execve() finishes, /proc/<pid>/environ can return
        # transient empty bytes (b'').
        host_side = b""
        deadline = time.monotonic() + 5.0
        environ_path = Path(f"/proc/{sentinel.pid}/environ")
        while time.monotonic() < deadline:
            try:
                host_side = environ_path.read_bytes()
                if host_side:
                    break
            except (FileNotFoundError, ProcessLookupError):
                pass
            time.sleep(0.01)
        self.assertIn(b"FACTORY_76V_SENTINEL=host-side-secret-marker", host_side,
                      "host-side sentinel environ must be non-empty and carry the marker")
        res = self.run_inside("ls /proc | grep '^[0-9]'")
        visible = set(res.stdout.split())
        self.assertTrue(visible, "the sandbox must see its own processes")
        self.assertTrue(len(visible) < 12, f"too many PIDs visible: {sorted(visible)}")
        self.assertIsNone(sentinel.poll(),
                          "the sentinel expired before the in-sandbox probe - the test "
                          "cannot tell a leak from an empty /proc entry, so fail loudly")
        probe = self.run_inside(
            f"grep -aq FACTORY_76V_SENTINEL /proc/{sentinel.pid}/environ 2>/dev/null "
            f"&& echo LEAK; echo PROBE_DONE")
        self.assertIn("PROBE_DONE", probe.stdout)
        self.assertNotIn("LEAK", probe.stdout,
                         "a host process's environ (the sentinel's) leaked into the sandbox")

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


class WrapperRuntimeBindTests(unittest.TestCase):
    """agents-wza: a wrapper launcher (pi) execs a runtime in a different tree than its own;
    the binder must mount that runtime's package at the path the launcher references — even
    through a symlink — or the module fails to resolve once $HOME is hidden."""

    def test_wrapper_runtime_paths_extracts_existing_absolute_paths(self):
        from lib.sandbox import _wrapper_runtime_paths
        tmp = Path(tempfile.mkdtemp(prefix="wza-runtime-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        bundle = tmp / "bundle" / "cli.js"
        bundle.parent.mkdir(parents=True)
        bundle.write_text("// stub\n", encoding="utf-8")
        launcher = tmp / "pi"
        launcher.write_text(f"#!/bin/sh\nexec /usr/bin/node {bundle} \"$@\"\n", encoding="utf-8")
        self.assertIn(str(bundle), _wrapper_runtime_paths(launcher))

    def test_wrapper_runtime_paths_skips_non_scripts_and_missing_paths(self):
        from lib.sandbox import _wrapper_runtime_paths
        tmp = Path(tempfile.mkdtemp(prefix="wza-skip-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        not_a_script = tmp / "pi"
        not_a_script.write_text("exec /does/not/exist/cli.js \"$@\"\n", encoding="utf-8")
        self.assertEqual(_wrapper_runtime_paths(not_a_script), [])

    def test_executable_binds_mounts_a_symlinked_runtime_at_the_launch_path(self):
        from lib.sandbox import _BindPlan, _executable_binds
        tmp = Path(tempfile.mkdtemp(prefix="wza-bind-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        # A "real" package tree at a resolved location ...
        real_pkg = tmp / "real" / "pi-coding-agent"
        (real_pkg / "dist" / "bundle").mkdir(parents=True)
        (real_pkg / "package.json").write_text("{}\n", encoding="utf-8")
        (real_pkg / "dist" / "bundle" / "cli.js").write_text("// stub\n", encoding="utf-8")
        # ... symlinked at the path a launcher hardcodes.
        link = tmp / "linked" / "pi-coding-agent"
        link.parent.mkdir()
        link.symlink_to(real_pkg)
        # A flat launcher (name != dir, not under a structural dir) binds only its own file,
        # so the runtime bind below is what must bring the package in.
        launcher = tmp / "pi"
        launcher.write_text(
            f"#!/bin/sh\nexec /usr/bin/node {link / 'dist' / 'bundle' / 'cli.js'} \"$@\"\n",
            encoding="utf-8")
        launcher.chmod(launcher.stat().st_mode | 0o111)
        plan = _BindPlan()
        _executable_binds(plan, ("pi",), str(tmp), str(tmp))
        # The resolved content is mounted AT the symlink path the launcher references.
        self.assertTrue(plan.visible(str(link)),
                        "the symlinked runtime must be visible at its launch path")
        pairs = _pairs(plan.argv, "--ro-bind")
        self.assertIn((os.path.realpath(str(link)), str(link)), pairs,
                      "the real package must be mounted AT the symlink path, not at its "
                      "resolved location")


class ToolPinBindTests(unittest.TestCase):
    """agents-7bj P2-6: the sandbox binder authenticates a pinned trusted tool's content
    before binding it, failing the wrap closed on a hash mismatch (never binding an
    unverified binary)."""

    def _bind(self, name, content):
        from unittest import mock
        import lib.tool_pins as tool_pins
        from lib.sandbox import _BindPlan, _executable_binds
        tmp = Path(tempfile.mkdtemp(prefix="binds-pin-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        # agents-3g6: a host-local FACTORY_TOOL_PINS file overlays the repo tools.yaml in
        # load_tool_pins(), so its `path` pin would not match this fake binary and the test
        # would fail for reasons unrelated to what it asserts. Isolate these fixtures from
        # the host env so they test the repo-pin path deterministically.
        host_pins = os.environ.pop("FACTORY_TOOL_PINS", None)
        if host_pins is not None:
            self.addCleanup(os.environ.__setitem__, "FACTORY_TOOL_PINS", host_pins)
        fake = tmp / name
        fake.write_text(content, encoding="utf-8")
        fake.chmod(fake.stat().st_mode | 0o111)
        return mock, tool_pins, _BindPlan, _executable_binds, tmp, fake

    def test_executable_binds_fails_closed_on_hash_mismatch(self):
        mock, tool_pins, _BindPlan, _executable_binds, tmp, fake = \
            self._bind("node", "#!/bin/sh\necho rogue\n")
        cfg = tmp / "tools.yaml"
        cfg.write_text("node:\n  sha256: " + "0" * 64 + "\n", encoding="utf-8")
        with mock.patch.object(tool_pins, "CONFIG_PATH", cfg):
            with self.assertRaises(tool_pins.ToolPinError):
                _executable_binds(_BindPlan(), ("node",), str(tmp), "/tmp")

    def test_executable_binds_binds_a_hash_matching_pinned_tool(self):
        mock, tool_pins, _BindPlan, _executable_binds, tmp, fake = \
            self._bind("node", "#!/bin/sh\necho ok\n")
        cfg = tmp / "tools.yaml"
        cfg.write_text("node:\n  sha256: " + tool_pins.sha256_file(fake) + "\n", encoding="utf-8")
        with mock.patch.object(tool_pins, "CONFIG_PATH", cfg):
            plan = _BindPlan()
            _executable_binds(plan, ("node",), str(tmp), "/tmp")
            self.assertTrue(plan.visible(str(fake.resolve())))


if __name__ == "__main__":
    unittest.main()
