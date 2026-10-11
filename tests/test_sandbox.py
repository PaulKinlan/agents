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

import errno
import os
os.environ.setdefault("FACTORY_ALLOW_UNPINNED_TOOLS", "1")  # agents-7bj: tests use unpinned stub tools
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.sandbox import (  # noqa: E402
    SANDBOXED_ENGINES, SandboxError, engine_sandboxed, sandbox_available, sandbox_command,
    sandbox_record, sandbox_unavailable_reason,
)
from lib import sandbox as sandbox_module  # noqa: E402

# --- hermetic test environment (agents-21ap) -------------------------------------------------
# The pin machinery under test resolves tools through FACTORY_TOOL_PINS when the OPERATOR'S
# shell exports it (~/.fleet/local.conf does on this VM), so without this scrub these tests
# observed the host rather than the tree: on 2026-10-11 a re-provision generated the host pins
# file and the full suite went red on EVERY tree, including landed main - these three accounting for 14 of the 43 failures, the rest in seven sibling modules fixed under the same bead - each
# with `trusted tool 'pi' resolved to /tmp/.../bin/pi, not the configured path
# /usr/local/bin/pi`. The tests were right - they plant a fake `pi` and assert the pin refuses
# it - and the environment was not hermetic. See tests/hermetic_env.py.
from tests import hermetic_env  # noqa: E402


def setUpModule():
    hermetic_env.isolate_operator_config()


def tearDownModule():
    hermetic_env.restore_operator_config()


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
        # agents-r2ne census: net_forward.py is the egress-wrap runtime of a FAKE FACTORY ROOT,
        # not a station script's dependency - tests/sandbox_fixtures.py does not apply here.
        (self.factory / "lib").mkdir()
        shutil.copyfile(ROOT / "lib" / "net_forward.py",
                        self.factory / "lib" / "net_forward.py")
        self.target = self.root / "target"
        self.target.mkdir()
        self.run_dir = self.factory / "runs" / "run1"
        self.run_dir.mkdir(parents=True)

    def build(self, env=None, inner=("/bin/true",), executables=(), egress_forwards=None,
              rw_binds=(), mask_findings=False):
        return sandbox_command(
            list(inner), target_dir=self.target, factory_root=self.factory,
            run_dir=self.run_dir, env=env if env is not None else {"PATH": "/usr/bin:/bin"},
            executables=executables, egress_forwards=egress_forwards, rw_binds=rw_binds,
            mask_findings=mask_findings,
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

    def test_findings_are_masked_only_when_requested(self):
        """agents-4zg: the engine's sandbox masks the findings store (cross-target credentials),
        while the pre-pass (trusted deterministic code) keeps it for bundle/pr-fixer/qa-station."""
        (self.factory / "findings").mkdir()
        masked = self.build(mask_findings=True)
        tmpfs = [masked[i + 1] for i, a in enumerate(masked) if a == "--tmpfs"]
        self.assertIn(str(self.factory / "findings"), tmpfs,
                      "the engine's sandbox must mask the findings store")
        default = self.build()
        tmpfs_default = [default[i + 1] for i, a in enumerate(default) if a == "--tmpfs"]
        self.assertNotIn(str(self.factory / "findings"), tmpfs_default,
                         "the pre-pass sandbox keeps the findings store by default")

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


@unittest.skipUnless(LIVE, "the pin boundary is exercised against a real, functional bwrap")
class TestBwrapPinBoundary(unittest.TestCase):
    """agents-28nn: the child's-write proof CANNOT catch a fake bwrap — the run directory is
    bound at the SAME host path inside and outside the wrap, so a PATH-planted fake that
    shifts to `--` and execs the child natively satisfies the proof (the token write, the
    exit status, the confined-looking argv; established by execution). The boundary
    assertion is therefore on the deliverer, not on anything the deliverer executes: bwrap
    is a pinned trusted tool, resolved and hash-verified BEFORE it runs, and an
    unauthenticated bwrap is refused without being executed.

    These tests remove FACTORY_ALLOW_UNPINNED_TOOLS (the module-level dev/test opt-in the
    other suites use) because the properties they pin are exactly what the opt-in waives.
    """

    FAKE = ('#!/bin/sh\n'
            # Log every invocation: refusal must PRECEDE any execution of the untrusted
            # binary, so the log existing at all fails the refusal tests.
            'echo ran >> "$FAKE_BWRAP_LOG"\n'
            'while [ $# -gt 0 ] && [ "$1" != "--" ]; do shift; done\n'
            '[ "$1" = "--" ] && shift\n'
            'exec "$@"\n')

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="factory-28nn-pin-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.factory = self.root / "factory-root"
        (self.factory / "runs").mkdir(parents=True)
        self.target = self.root / "target"
        self.target.mkdir()
        self.run_dir = self.factory / "runs" / "run1"
        self.run_dir.mkdir(parents=True)
        # Resolve the REAL bwrap before any PATH tampering, and pin it by content.
        self.real_bwrap = os.path.realpath(shutil.which("bwrap"))
        from lib.tool_pins import sha256_file
        self.real_sha = sha256_file(Path(self.real_bwrap))
        self.pins = self.root / "tools.pins.yaml"
        # The proof-satisfying fake, planted in its own directory.
        self.fake_dir = self.root / "fakebin"
        self.fake_dir.mkdir()
        self.fake_log = self.root / "fake-bwrap-ran"
        stub = self.fake_dir / "bwrap"
        stub.write_text(self.FAKE, encoding="utf-8")
        stub.chmod(0o755)
        # Environment: deterministic pins file, NO dev/test opt-in, PATH under control.
        self._saved = {k: os.environ.get(k)
                       for k in ("PATH", "FACTORY_TOOL_PINS", "FACTORY_ALLOW_UNPINNED_TOOLS")}
        self.addCleanup(self._restore_env)
        os.environ["FACTORY_TOOL_PINS"] = str(self.pins)
        os.environ.pop("FACTORY_ALLOW_UNPINNED_TOOLS", None)
        os.environ["FAKE_BWRAP_LOG"] = str(self.fake_log)
        self.addCleanup(os.environ.pop, "FAKE_BWRAP_LOG", None)
        # The probe result is process-cached: every test here re-probes.
        sandbox_module._probe_result = None
        self.addCleanup(setattr, sandbox_module, "_probe_result", None)

    def _restore_env(self):
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _plant_fake_first_on_path(self):
        os.environ["PATH"] = f"{self.fake_dir}{os.pathsep}{self._saved['PATH']}"

    def _write_pins(self, body):
        self.pins.write_text(body, encoding="utf-8")
        sandbox_module._probe_result = None

    def test_a_path_planted_fake_bwrap_that_would_satisfy_the_proof_is_refused(self):
        """THE FILED HOLE, CLOSED: a fake bwrap that execs the child natively satisfies the
        child's-write proof, so it must be stopped at RESOLUTION. With only the real
        bwrap's content pinned (no `path` pin, so resolution still follows PATH order),
        the planted fake is resolved, fails the hash check, and is refused — never
        executed. sandbox_available() reports the host as unable to sandbox (the factory
        then refuses or honestly downgrades) and sandbox_command() fails closed."""
        self._write_pins(f"bwrap:\n  sha256: {self.real_sha}\n")
        self._plant_fake_first_on_path()
        self.assertFalse(sandbox_available(),
                         "an unauthenticated bwrap must read as 'cannot sandbox', never as "
                         "'sandboxed' — the overclaim is the hole")
        with self.assertRaises(SandboxError) as raised:
            sandbox_command(["/bin/true"], target_dir=self.target, factory_root=self.factory,
                            run_dir=self.run_dir, env=dict(os.environ))
        self.assertIn("bwrap", str(raised.exception))
        self.assertFalse(self.fake_log.exists(),
                         "the unauthenticated bwrap must be refused BEFORE it executes")
        self.assertEqual(list(self.run_dir.iterdir()), [],
                         "no verification artifact may be left behind")

    def test_a_full_pin_bypasses_the_planted_fake_and_the_wrap_still_confines(self):
        """The positive direction: with `path` + `sha256` pinned, the configured path wins
        over PATH order, so the planted fake is not even resolved; the REAL bwrap builds
        the wrap, and the wrap still does what the pin vouches for — a write to the
        'read-only' target fails inside it."""
        self._write_pins(f"bwrap:\n  path: {self.real_bwrap}\n  sha256: {self.real_sha}\n")
        self._plant_fake_first_on_path()
        self.assertTrue(sandbox_available())
        argv = sandbox_command(
            ["/bin/sh", "-c", f"echo x > {self.target}/marker"],
            target_dir=self.target, factory_root=self.factory, run_dir=self.run_dir,
            env=dict(os.environ))
        self.assertEqual(argv[0], self.real_bwrap,
                         "the pinned path must win over the PATH-planted fake")
        res = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
        self.assertNotEqual(res.returncode, 0, "the ro-bound target must reject the write")
        self.assertFalse((self.target / "marker").exists(),
                         "the authenticated wrap still confines the child")
        self.assertFalse(self.fake_log.exists(),
                         "the PATH-planted fake must not execute even on the success path")

    def test_a_pin_mismatch_refuses_even_the_real_bwrap(self):
        """Fail closed the other way: a bwrap whose content does not match its pin — a
        swapped or rebuilt binary at the pinned location — is refused exactly like the
        planted fake, and is never executed."""
        self._write_pins(f"bwrap:\n  path: {self.real_bwrap}\n  sha256: {'0' * 64}\n")
        self.assertFalse(sandbox_available())
        with self.assertRaises(SandboxError):
            sandbox_command(["/bin/true"], target_dir=self.target, factory_root=self.factory,
                            run_dir=self.run_dir, env=dict(os.environ))

    def test_no_bwrap_pin_at_all_fails_closed(self):
        """The fail-closed composition end to end: NO bwrap pin configured anywhere (empty
        pins file, no dev opt-in) and the fake planted on PATH. Refusal here is what
        bwrap's TRUSTED_TOOLS membership buys — dropping the membership (not just the
        wiring) must fail this test."""
        self._write_pins("")  # no bwrap entry anywhere
        self._plant_fake_first_on_path()
        self.assertFalse(sandbox_available(),
                         "an unpinned bwrap must fail closed, never resolve by PATH order")
        with self.assertRaises(SandboxError):
            sandbox_command(["/bin/true"], target_dir=self.target, factory_root=self.factory,
                            run_dir=self.run_dir, env=dict(os.environ))
        self.assertFalse(self.fake_log.exists())


@unittest.skipUnless(LIVE, "the ro-bind boundary needs a real bwrap wrap")
class TestEffectivePinsBoundary(unittest.TestCase):
    """agents-28nn round 5, review P0 — the TOCTOU on the effective pins.

    PROJECT RULE: A FILE THE PIN RESOLVER TRUSTS MUST NOT BE A FILE THE PINNED PROCESS CAN
    REWRITE — trust is not a property of WHAT is read, it is a property of WHO CAN WRITE
    WHAT IS READ. The dispatcher used to write the merged tool-pins.effective.yaml into
    the run directory, which the wrap binds READ-WRITE at the same host path; the round-4
    reviewer CONSTRUCTED the hole by having a station script write a fake git hash to the
    path named by FACTORY_TOOL_PINS before calling resolve_tool("git"), which validated
    the injected hash. The fix keeps the pins OUTSIDE every rw-bound tree and binds the
    file into the wrap READ-ONLY (sandbox_command's ro_binds — the existing bind
    machinery, reused).

    These tests ARE the constructed case, run against a real wrap: a child that rewrites
    the file it was handed. The boundary arm (ro_binds) must leave resolve_tool validating
    the REAL git; the control arm (the old shape — the pins file rw-bound inside the run
    directory) must show the SAME child succeeding, so the boundary arm's refusal is the
    bind's doing, not a broken harness. MUTATION PROOF, both directions (performed, not
    asserted): dropping the dispatcher's ro_binds wiring makes the file rw inside the wrap
    and the boundary arm goes red (OVERWRITE-SUCCEEDED, the fake resolves); restoring it
    turns it green.
    """

    # The child: plant a fake git in the (rw-bound) run dir, FORGE a pins file vouching
    # for it at the FACTORY_TOOL_PINS path it was handed, then resolve — exactly the
    # reviewer's construction.
    ATTACK_CHILD = r"""
import hashlib, os, sys
from pathlib import Path
sys.path.insert(0, {factory!r})
pins = Path(os.environ["FACTORY_TOOL_PINS"])
fake = Path({run_dir!r}) / "git"
fake.write_text("#!/bin/sh\necho PWNED\n")
fake.chmod(0o755)
forged = "git:\n  path: %s\n  sha256: %s\n" % (
    fake, hashlib.sha256(fake.read_bytes()).hexdigest())
try:
    pins.write_text(forged)
    print("OVERWRITE-SUCCEEDED")
except OSError as e:
    print("OVERWRITE-REFUSED:%s" % e.errno)
from lib.tool_pins import resolve_tool, ToolPinError
try:
    print("RESOLVED:%s" % resolve_tool("git"))
except ToolPinError as e:
    print("REFUSED:%s" % e)
"""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="factory-28nn-toctou-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.factory = self.root / "factory-root"
        (self.factory / "runs").mkdir(parents=True)
        self.target = self.root / "target"
        self.target.mkdir()
        self.run_dir = self.factory / "runs" / "run1"
        self.run_dir.mkdir(parents=True)
        # The REAL git, pinned by path + content — what the host verified and wrote as
        # the child's effective pins.
        self.real_git = os.path.realpath(shutil.which("git"))
        from lib.tool_pins import sha256_file
        self.real_sha = sha256_file(Path(self.real_git))
        # The child imports lib.tool_pins from the REAL factory root (ro-bound by every
        # wrap at its host path), not the scratch factory dir the wrap masks runs/ under.
        self.child = self.run_dir / "attack_child.py"
        self.child.write_text(
            self.ATTACK_CHILD.format(factory=str(ROOT), run_dir=str(self.run_dir)),
            encoding="utf-8")

    def _run_child(self, pins_path: Path, ro_binds=()):
        pins_path.write_text(
            f"git:\n  path: {self.real_git}\n  sha256: {self.real_sha}\n",
            encoding="utf-8")
        env = {"PATH": "/usr/bin:/bin",
               # The properties pinned here are exactly what the dev/test opt-in waives.
               "FACTORY_TOOL_PINS": str(pins_path)}
        argv = sandbox_command(
            [sys.executable, str(self.child)],
            target_dir=self.target, factory_root=self.factory, run_dir=self.run_dir,
            env=env,
            # ROOT (the real repo, under tmpfs-hidden /home) is bound read-only so the
            # child can import lib.tool_pins — the same visibility the real pre-pass
            # gets from factory_root.
            ro_binds=[str(p) for p in ro_binds] + [str(ROOT)])
        # The env must ride the EXEC, not only the wrap build: bwrap inherits the
        # process environment, so omitting env= here would hand the child the OPERATOR's
        # FACTORY_TOOL_PINS instead of the file under test.
        return subprocess.run(argv, capture_output=True, text=True, timeout=60, env=env)

    def test_a_child_cannot_rewrite_the_read_only_pins_it_is_handed(self):
        """THE FILED HOLE, CLOSED: the pins file lives OUTSIDE the rw-bound run dir and is
        bound read-only, so the forged write fails EROFS and resolve_tool keeps
        validating the REAL git — the injected hash never enters what the resolver
        trusts."""
        pins = self.root / "factory-pins-test" / "tool-pins.effective.yaml"
        pins.parent.mkdir()
        original = f"git:\n  path: {self.real_git}\n  sha256: {self.real_sha}\n"
        res = self._run_child(pins, ro_binds=[pins])
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn(f"OVERWRITE-REFUSED:{errno.EROFS}", res.stdout,
                      "the read-only bind must refuse the forged write with EROFS "
                      "specifically — an ENOENT would mean the file never reached the "
                      "child and the test proves nothing: " + res.stdout)
        self.assertNotIn("OVERWRITE-SUCCEEDED", res.stdout)
        self.assertIn(f"RESOLVED:{self.real_git}", res.stdout,
                      "resolve_tool must keep validating what the host verified: "
                      + res.stdout)
        self.assertEqual(pins.read_text(encoding="utf-8"), original,
                         "the pins the host wrote must be byte-identical afterwards")
        # The fake git was planted but is never what the resolver returns.
        self.assertNotIn(str(self.run_dir / "git"), res.stdout.split("RESOLVED:")[-1])

    def test_control_the_run_dir_shape_rewrites_the_pins_and_validates_the_fake(self):
        """The constructed attack against the OLD shape (pins rw-bound inside the run dir,
        no ro-bind): the same child OVERWRITES the file it was handed and resolve_tool
        validates the injected hash. This is the mutation trap for the fix: reintroduce
        the old shape and the boundary test above goes red exactly this way."""
        pins = self.run_dir / "tool-pins.effective.yaml"
        res = self._run_child(pins)  # no ro_binds — the pre-fix shape
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("OVERWRITE-SUCCEEDED", res.stdout,
                      "the old shape must still be attackable, or the boundary test "
                      "proves nothing: " + res.stdout)
        self.assertIn(f"RESOLVED:{self.run_dir / 'git'}", res.stdout,
                      "the forged pin must be VALIDATED against the rewritten file — the "
                      "attack the rule now forbids: " + res.stdout)


class TestPinFailureDegradation(unittest.TestCase):
    """agents-28nn round 2, review P2: EVERY failure of the pin machinery must degrade the
    probe to 'cannot sandbox' — the honest refusal/downgrade path — instead of crashing
    the factory with a raw OSError. Before the fix, an UNREADABLE pins file (chmod 000)
    raised PermissionError out of _parse_pins_file, and _probe() caught only ToolPinError,
    so the whole factory crashed rather than degrading. The fix makes the pin machinery's
    failures all surface as ToolPinError, and the probe records WHY so the refusal names
    the cause (a quiet downgrade that looks like an ordinary bwrap-less host is a trap).

    The mutations that prove these tests guard the behaviour: reverting _parse_pins_file
    to let OSError escape makes the first two tests raise PermissionError/
    IsADirectoryError instead of observing the degradation; removing the probe's reason
    recording makes the reason assertions fail.
    """

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="factory-28nn-degrade-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.factory = self.root / "factory-root"
        (self.factory / "runs").mkdir(parents=True)
        self.target = self.root / "target"
        self.target.mkdir()
        self.run_dir = self.factory / "runs" / "run1"
        self.run_dir.mkdir(parents=True)
        self._saved = {k: os.environ.get(k)
                       for k in ("FACTORY_TOOL_PINS", "FACTORY_ALLOW_UNPINNED_TOOLS")}
        self.addCleanup(self._restore_env)
        os.environ.pop("FACTORY_ALLOW_UNPINNED_TOOLS", None)
        sandbox_module._probe_result = None
        self.addCleanup(setattr, sandbox_module, "_probe_result", None)

    def _restore_env(self):
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _assert_degrades_honestly(self):
        """The probe returns False (no exception), names WHY, and the wrap build fails
        closed with SandboxError naming bwrap — the same path as a missing pin."""
        self.assertFalse(sandbox_available(),
                         "a pins-file failure must degrade to 'cannot sandbox', never raise")
        reason = sandbox_unavailable_reason()
        self.assertIsNotNone(reason, "a refused/downgraded run must NAME the cause")
        self.assertIn("bwrap", reason)
        with self.assertRaises(SandboxError) as raised:
            sandbox_command(["/bin/true"], target_dir=self.target, factory_root=self.factory,
                            run_dir=self.run_dir, env=dict(os.environ))
        self.assertIn("bwrap", str(raised.exception))

    @unittest.skipIf(os.geteuid() == 0, "root ignores file permission bits")
    def test_an_unreadable_pins_file_degrades_instead_of_crashing(self):
        """The reviewer's P2 by construction: chmod 000 the host pins file."""
        pins = self.root / "tools.pins.yaml"
        pins.write_text("bwrap:\n  sha256: " + "0" * 64 + "\n", encoding="utf-8")
        pins.chmod(0o000)
        self.addCleanup(pins.chmod, 0o644)
        os.environ["FACTORY_TOOL_PINS"] = str(pins)
        self._assert_degrades_honestly()

    def test_a_directory_where_the_pins_file_is_expected_degrades(self):
        """The other unreadable shape: FACTORY_TOOL_PINS names a directory."""
        os.environ["FACTORY_TOOL_PINS"] = str(self.root / "pins.d")
        (self.root / "pins.d").mkdir()
        self._assert_degrades_honestly()

    def test_an_empty_pins_file_fails_closed_and_degrades(self):
        """An empty pins file is zero pins: unpinned bwrap fails closed, and the probe
        degrades with the 'not pinned' cause named."""
        pins = self.root / "tools.pins.yaml"
        pins.write_text("", encoding="utf-8")
        os.environ["FACTORY_TOOL_PINS"] = str(pins)
        self.assertFalse(sandbox_available())
        reason = sandbox_unavailable_reason()
        self.assertIsNotNone(reason)
        self.assertIn("not pinned", reason)

    def test_a_fifo_where_the_pins_file_is_expected_degrades(self):
        """agents-28nn round 3: a FIFO as FACTORY_TOOL_PINS. Without the bounded read the
        probe BLOCKS on the FIFO (or reads attacker-supplied bytes through it); with it
        the refusal precedes any read and the degradation names the FIFO. The writer
        keeps the mutation direction bounded: with the refusal removed the read gets
        content and the probe degrades for the WRONG reason (a hash mismatch), which the
        reason assertion below rejects."""
        fifo = self.root / "tools.fifo"
        os.mkfifo(fifo)

        def writer():
            # O_NONBLOCK with retries: with the fix no reader ever opens the FIFO (every
            # attempt fails ENXIO and the thread exits); under the mutation the reader is
            # blocked in open() waiting for exactly this writer, so one attempt lands. A
            # single non-blocking open would race the reader's scheduling.
            fd = None
            for _ in range(30):
                try:
                    fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
                    break
                except OSError:
                    time.sleep(0.1)
            if fd is None:
                return  # the fixed reader never opens the FIFO: ENXIO is expected
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write("bwrap:\n  sha256: " + "0" * 64 + "\n")
            except OSError:
                pass

        feeder = threading.Thread(target=writer, daemon=True)
        feeder.start()
        try:
            os.environ["FACTORY_TOOL_PINS"] = str(fifo)
            self._assert_degrades_honestly()
            self.assertIn("FIFO", sandbox_unavailable_reason())
        finally:
            feeder.join(timeout=5)
        self.assertFalse(feeder.is_alive(),
                         "the probe must REFUSE the FIFO, never block on it")

    def test_a_device_file_where_the_pins_file_is_expected_degrades(self):
        """The unbounded-read sibling (/dev/null stands in for /dev/urandom, which must
        never be read to exhaustion — that read IS the crash being fixed)."""
        os.environ["FACTORY_TOOL_PINS"] = "/dev/null"
        self._assert_degrades_honestly()
        self.assertIn("character device", sandbox_unavailable_reason())


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
            self.assertIn("factory repository (with runs/ and findings/ masked)", record["engine_read_scope"])
            self.assertIn("ambient $HOME", record["engine_read_scope"])
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

    def test_a_findings_overlapping_target_cannot_re_expose_the_store(self):
        """agents-4zg round 4: a raw --target <factory>/findings must not overmount the mask.
        The mask is applied after every other bind (mask last wins), so the store stays hidden
        even when the target's own read-only bind would otherwise re-expose it."""
        findings = self.factory / "findings"
        findings.mkdir()
        secret = "ghp_" + "A" * 36
        (findings / "target-b.json").write_text(
            '{"target":"target-b","findings":{"fp":{"raw_match":"' + secret + '"}}}',
            encoding="utf-8")
        # The raw target IS the findings store: its ro-bind overlaps the mask.
        cmd = sandbox_command(["/bin/cat", str(findings / "target-b.json")],
                              target_dir=findings, factory_root=self.factory,
                              run_dir=self.run_dir, env=self.env, mask_findings=True)
        res = subprocess.run(cmd, capture_output=True, text=True, env=self.env,
                             timeout=120, stdin=subprocess.DEVNULL)
        self.assertNotIn("A" * 36, res.stdout, "the store was re-exposed through the target bind")
        self.assertIn("No such file", res.stderr + res.stdout)

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
