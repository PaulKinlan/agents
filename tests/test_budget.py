#!/usr/bin/env python3
"""Station budgets and the dispatcher's subprocess timeouts (SF-06).

`budget.max_minutes` is a hard station deadline, expiry is a station failure, and no
subprocess call in the dispatcher runs unbounded. These tests cover the policy, the real
timeout path (including the process-group kill), and the repo-wide invariant.
"""

import ast
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.budget import (  # noqa: E402
    DEFAULT_MAX_MINUTES,
    StationBudget,
    StationTimeout,
    budget_for,
    run_station_command,
)


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class TestStationBudget(unittest.TestCase):
    def test_declared_minutes_are_honoured(self):
        self.assertEqual(StationBudget(5).minutes, 5)
        self.assertEqual(StationBudget(12).max_seconds, 720)
        self.assertEqual(StationBudget("7.5").minutes, 7.5)

    def test_missing_or_invalid_budgets_fail_closed_to_the_default(self):
        for bad in (None, "", "fast", 0, -3, True, False, float("nan"), float("inf"), {"m": 1}):
            with self.subTest(value=bad):
                self.assertEqual(StationBudget(bad).minutes, DEFAULT_MAX_MINUTES)

    def test_budget_expires_on_the_clock(self):
        clock = FakeClock()
        budget = StationBudget(1, label="secret-scan", clock=clock)
        self.assertEqual(budget.timeout_for("engine"), 60)
        clock.now = 60
        with self.assertRaises(StationTimeout):
            _ = budget.remaining_seconds
        with self.assertRaises(StationTimeout) as ctx:
            budget.timeout_for("engine")
        self.assertIn("secret-scan", str(ctx.exception))
        self.assertIn("before engine", str(ctx.exception))

    def test_budget_for_reads_an_agent_yaml_mapping(self):
        self.assertEqual(budget_for({"budget": {"max_minutes": 15}}).minutes, 15)
        self.assertEqual(budget_for({"budget": {"max_minutes": "15"}}).minutes, 15)
        self.assertEqual(budget_for({}).minutes, DEFAULT_MAX_MINUTES)
        self.assertEqual(budget_for({"budget": "5"}).minutes, DEFAULT_MAX_MINUTES)

    def test_budget_for_explicit_override_and_env_var(self):
        import os
        # Explicit override takes top precedence
        self.assertEqual(budget_for({"budget": {"max_minutes": 5}}, override_minutes=25).minutes, 25)
        self.assertEqual(budget_for({}, override_minutes="12.5").minutes, 12.5)

        # FACTORY_BUDGET_MINUTES overrides agent.yaml when override_minutes is not set
        orig = os.environ.get("FACTORY_BUDGET_MINUTES")
        try:
            os.environ["FACTORY_BUDGET_MINUTES"] = "30"
            self.assertEqual(budget_for({"budget": {"max_minutes": 5}}).minutes, 30)
            # Explicit override still beats env var
            self.assertEqual(budget_for({"budget": {"max_minutes": 5}}, override_minutes=10).minutes, 10)
        finally:
            if orig is not None:
                os.environ["FACTORY_BUDGET_MINUTES"] = orig
            else:
                os.environ.pop("FACTORY_BUDGET_MINUTES", None)


class TestRunStationCommand(unittest.TestCase):
    def test_a_fast_command_is_returned_unchanged(self):
        budget = StationBudget(1)
        res = run_station_command(
            [sys.executable, "-c", "print('ok')"], budget, "echo",
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(res.returncode, 0)
        self.assertEqual(res.stdout.strip(), "ok")

    def test_check_semantics_are_preserved(self):
        budget = StationBudget(1)
        failed = [sys.executable, "-c", "import sys; sys.exit(3)"]
        with self.assertRaises(subprocess.CalledProcessError):
            run_station_command(failed, budget, "fail", check=True, capture_output=True, text=True)
        res = run_station_command(failed, budget, "fail", check=False, capture_output=True, text=True)
        self.assertEqual(res.returncode, 3)

    def test_on_spawn_fires_with_the_live_child(self):
        # agents-28nn round 8: the dispatcher binds the credential broker's peer gate to
        # the engine session's pid through this hook, so it must fire with the live
        # Popen — the child running, its pid allocated — BEFORE communicate() blocks.
        budget = StationBudget(1)
        seen = []
        res = run_station_command(
            [sys.executable, "-c", "pass"], budget, "spawn",
            on_spawn=lambda proc: seen.append((proc.pid, proc.poll() is None)),
        )
        self.assertEqual(res.returncode, 0)
        self.assertEqual(len(seen), 1)
        self.assertTrue(seen[0][1], "on_spawn fired before the child was running")
        self.assertGreater(seen[0][0], 0)

    def test_a_raising_on_spawn_cannot_orphan_the_child(self):
        """agents-8z4z: THE SPAWN-RAISES PATH, DRIVEN RATHER THAN READ.

        The hook is what binds the credential broker's peer gate to the engine session's pid
        (factory:1835); if it raises, its job is NOT done, so the child is still running with
        live model credentials in its environment and nobody to reap it. RED-FIRST against the
        pre-fix module: on_spawn was called outside every cleanup path (audit finding
        lib/budget.py:136), so this child survived the raise and the assertion below failed.
        """
        import os

        budget = StationBudget(1)
        pids = []

        def hook(proc):
            pids.append(proc.pid)
            raise RuntimeError("broker registration failed")

        with self.assertRaises(RuntimeError):
            run_station_command(
                [sys.executable, "-c", "import time; time.sleep(60)"], budget, "spawn",
                on_spawn=hook, capture_output=True, text=True, check=False,
            )

        self.assertEqual(len(pids), 1, "the hook must have been handed the live child")
        with self.assertRaises(ProcessLookupError,
                               msg=f"pid {pids[0]} outlived a failing on_spawn - orphaned"):
            os.kill(pids[0], 0)

    def test_a_raising_on_spawn_kills_the_whole_process_group(self):
        """The containment property, not just the direct child: the session started for the
        station dies with the hook's failure, so a descendant the adapter spawned cannot keep
        working (and holding credentials) after the hook refused to narrow the peer gate.
        Same shape as test_expiry_kills_the_whole_process_group, with on_spawn raising in
        place of the budget expiring."""
        child_code = (
            "import sys, time\n"
            "while True:\n"
            "    with open(sys.argv[1], 'a') as fh:\n"
            "        fh.write('.')\n"
            "    time.sleep(0.05)\n"
        )
        parent_code = (
            "import subprocess, sys, time\n"
            "subprocess.Popen([sys.executable, sys.argv[1], sys.argv[2]])\n"
            "time.sleep(60)\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            child = root / "child.py"
            child.write_text(child_code, encoding="utf-8")
            parent = root / "parent.py"
            parent.write_text(parent_code, encoding="utf-8")
            heartbeat = root / "heartbeat"

            budget = StationBudget(1, label="hook")

            def hook(proc):
                # DETERMINISM, NOT DECORATION: on_spawn runs BEFORE communicate() blocks, so
                # the hook waits for the descendant it is about to fail over to actually
                # start. Without that wait the raise (and, with the fix, the kill) completes
                # before the grandchild exists, and the assertion below would fail on the
                # grandchild never having STARTED rather than on it surviving - a race that
                # read as a test bug in both directions.
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline and not heartbeat.exists():
                    time.sleep(0.02)
                raise RuntimeError("broker registration failed")

            with self.assertRaises(RuntimeError):
                run_station_command(
                    [sys.executable, str(parent), str(child), str(heartbeat)],
                    budget, "spawn", capture_output=True, text=True, check=False,
                    on_spawn=hook,
                )

            self.assertTrue(heartbeat.exists(), "the grandchild never started")
            size_after_kill = heartbeat.stat().st_size
            time.sleep(0.5)
            self.assertEqual(heartbeat.stat().st_size, size_after_kill,
                             "a descendant of the spawned session outlived the failing hook")

    def test_a_failing_group_kill_still_contains_the_child(self):
        """agents-dhk8: the DOUBLE FAULT - the hook raises AND the reap fails with it.

        The 8z4z guarantee above ("a hook that raises cannot orphan the child") holds only
        while the kill itself succeeds, and that is the half nobody had driven. Measured
        RED-FIRST against the pre-fix module: with the group kill raising, the caller saw the
        reap's OSError INSTEAD of the hook's RuntimeError - the hook's own failure silently
        misattributed - and the child SURVIVED, which is exactly the orphan the hook's
        exception was supposed to prevent. A double fault is not a licence to lose the first
        fault: the hook's error is what a reader needs, and the reap's belongs in its chain.

        The liveness assertion is on the Popen rather than os.kill(pid, 0), because a ZOMBIE
        still answers signal 0: the reap raised before its wait(), so the killed child is
        unreaped and an os.kill probe reports a dead process as alive (this test caught its
        own author with exactly that). poll() both reports SIGKILL and reaps, after which
        the pid is genuinely gone.
        """
        import os

        pids = []
        popen = []

        def hook(proc):
            pids.append(proc.pid)
            popen.append(proc)
            raise RuntimeError("broker registration failed")

        def broken_group_kill(proc):
            raise OSError("killpg failed")

        with mock.patch("lib.budget._kill_process_group", broken_group_kill):
            with self.assertRaises(RuntimeError) as ctx:
                run_station_command(
                    [sys.executable, "-c", "import time; time.sleep(60)"], StationBudget(1),
                    "spawn", on_spawn=hook, capture_output=True, text=True, check=False,
                )

        self.assertIn("broker registration failed", str(ctx.exception),
                      "the hook's own failure must be the exception reported")
        self.assertIn("killpg failed", str(ctx.exception.__context__),
                      "the reap's failure must stay in the chain, not replace the cause")
        self.assertEqual(len(pids), 1, "the hook must have been handed the live child")
        self.assertEqual(popen[0].poll(), -signal.SIGKILL,
                         "the child outlived a failing hook AND a failed reap")
        with self.assertRaises(ProcessLookupError, msg="the killed child was left unreaped"):
            os.kill(pids[0], 0)

    def test_the_reap_is_bounded_when_an_escaped_descendant_holds_the_pipes(self):
        """agents-dhk8: A DESCENDANT THAT ESCAPED THE GROUP MAKES THE DRAIN UNFINISHABLE.

        A descendant in its own session keeps our stdout write end open, so no communicate()
        can see EOF - the case _kill_and_reap's own comment names. The escape hatch for it
        was a bare proc.communicate() with no bound, and the measured cost was the
        descendant's LIFETIME: 25.1 s against a descendant that slept 25 s, so a station
        would wait for as long as that descendant lived (the reaper allows 120 min) while
        this module's own docstring promises no subprocess call in the dispatcher is
        unbounded. The assertion below is about the SHAPE - we returned while the pipe holder
        was still alive - so GROUP_EXIT_WAIT_SECONDS is patched down; the module's real bound
        is 5 s per wait, and waiting it out twice in every run would buy nothing here.
        """
        import os

        parent_code = (
            "import subprocess, sys, time\n"
            "proc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(6)'],\n"
            "                        start_new_session=True, stdout=sys.stdout)\n"
            "open(sys.argv[1], 'w').write(str(proc.pid))\n"
            "time.sleep(60)\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            parent = root / "parent.py"
            parent.write_text(parent_code, encoding="utf-8")
            pidfile = root / "descendant.pid"

            def hook(proc):
                # The descendant must exist before the hook fails, or the pipes would be held
                # by nobody and the drain would finish instantly (see the 8z4z test above).
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline and not pidfile.exists():
                    time.sleep(0.02)
                raise RuntimeError("broker registration failed")

            started = time.monotonic()
            with mock.patch("lib.budget.GROUP_EXIT_WAIT_SECONDS", 0.5):
                with self.assertRaises(RuntimeError):
                    run_station_command(
                        [sys.executable, str(parent), str(pidfile)],
                        StationBudget(1), "spawn", on_spawn=hook,
                        capture_output=True, text=True, check=False,
                    )
            elapsed = time.monotonic() - started
            self.assertTrue(pidfile.exists(), "the escaped descendant never started")
            descendant = int(pidfile.read_text())
            try:
                self.assertLess(elapsed, 4.5,
                                "the reap waited out a process outside its own group")
                try:
                    os.kill(descendant, 0)
                except ProcessLookupError:
                    self.fail("the reap waited for the escaped pipe holder instead of "
                              "bounding the drain and returning")
            finally:
                try:
                    os.kill(descendant, 9)
                except ProcessLookupError:
                    pass

    def test_expiry_raises_station_timeout(self):
        budget = StationBudget(0.01, label="hung")  # 0.6 s
        started = time.monotonic()
        with self.assertRaises(StationTimeout) as ctx:
            run_station_command(
                [sys.executable, "-c", "import time; time.sleep(30)"], budget, "engine",
                capture_output=True, text=True, check=False,
            )
        self.assertLess(time.monotonic() - started, 10)
        self.assertIn("hung", str(ctx.exception))
        self.assertIn("process group killed", str(ctx.exception))

    def test_expiry_kills_the_whole_process_group(self):
        """The engine dies with the adapter shell, not as an orphan holding the slot."""
        child_code = (
            "import sys, time\n"
            "while True:\n"
            "    with open(sys.argv[1], 'a') as fh:\n"
            "        fh.write('.')\n"
            "    time.sleep(0.05)\n"
        )
        parent_code = (
            "import subprocess, sys, time\n"
            "subprocess.Popen([sys.executable, sys.argv[1], sys.argv[2]])\n"
            "time.sleep(60)\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            child = root / "child.py"
            child.write_text(child_code, encoding="utf-8")
            parent = root / "parent.py"
            parent.write_text(parent_code, encoding="utf-8")
            heartbeat = root / "heartbeat"

            budget = StationBudget(0.03, label="hung")  # 1.8 s
            with self.assertRaises(StationTimeout):
                run_station_command(
                    [sys.executable, str(parent), str(child), str(heartbeat)],
                    budget, "engine", capture_output=True, text=True, check=False,
                )

            self.assertTrue(heartbeat.exists(), "the grandchild never started")
            size_after_kill = heartbeat.stat().st_size
            time.sleep(0.5)
            self.assertEqual(heartbeat.stat().st_size, size_after_kill,
                             "the grandchild outlived the process-group kill")


class TestKillGroupOnExit(unittest.TestCase):
    """PR #29 review r4200705643: a command that returns must not leave its group running."""

    def test_descendants_die_when_the_command_returns(self):
        import os
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = Path(tmp) / "pid"
            cmd = ["sh", "-c", f"sleep 60 >/dev/null 2>&1 & echo $! > {pidfile}; exit 0"]
            budget = StationBudget(1, label="t")
            run_station_command(cmd, budget, "step", capture_output=True, text=True,
                                kill_group_on_exit=True)
            pid = int(pidfile.read_text())
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
            # Without the flag, the existing behaviour is unchanged.
            run_station_command(cmd, budget, "step", capture_output=True, text=True)
            pid = int(pidfile.read_text())
            os.kill(pid, 0)  # still alive
            os.kill(pid, 9)


class TestNoUnboundedSubprocess(unittest.TestCase):
    """Guard rail for SF-06: a subprocess call must carry a timeout or use a wrapper."""

    def test_every_dispatcher_subprocess_call_is_bounded(self):
        paths = [ROOT / "factory"] + sorted((ROOT / "lib").rglob("*.py"))
        offenders = []
        for path in paths:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                if not isinstance(func, ast.Attribute) or not isinstance(func.value, ast.Name):
                    continue
                if func.attr == "communicate":
                    # agents-dhk8: THE HOLE THIS GUARD RAIL HAD. It checked the calls that
                    # CREATE a subprocess and none of the calls that WAIT on one, which is
                    # where an unbounded wait actually happens: `proc.communicate()` with no
                    # timeout in lib/budget.py passed this test for as long as the escape
                    # hatch existed, while being able to block for the LIFETIME of a process
                    # outside our group (measured: 25.1 s against a descendant that slept
                    # 25 s). communicate() is Popen-specific, so a rule for it cannot
                    # misfire. `wait` is deliberately NOT covered: Event.wait and thread
                    # waits share the name, and a rule flagging them would turn other lanes'
                    # branches red for a false positive - lib/net_forward.py's child.wait is
                    # the documented exception, bounded transitively by the station's group
                    # kill. That residual is named here rather than left to be rediscovered.
                    if not any(kw.arg == "timeout" for kw in node.keywords):
                        offenders.append(
                            f"{path.relative_to(ROOT)}:{node.lineno}: .communicate() without timeout="
                        )
                    continue
                if func.value.id != "subprocess":
                    continue
                where = f"{path.relative_to(ROOT)}:{node.lineno}"
                if func.attr in ("run", "call", "check_call", "check_output"):
                    if not any(kw.arg == "timeout" for kw in node.keywords):
                        offenders.append(f"{where}: subprocess.{func.attr} without timeout=")
                if func.attr == "Popen" and path.name not in ("budget.py", "net_forward.py"):
                    offenders.append(f"{where}: subprocess.Popen outside lib/budget.py")
        # lib/net_forward.py (agents-2x6) is the deliberate exception: it IS the in-sandbox
        # relay/supervisor — it runs inside the bubblewrap invocation, where
        # lib/budget.py's host-side machinery cannot reach it. Its child is bounded
        # transitively instead: the enclosing run_station_command kills the whole process
        # group at the station budget, and net_forward forwards signals and propagates the
        # child's exit code (tests/test_factory_core.py
        # TestDispatcherBudget.test_hung_engine_is_killed_at_the_station_budget rides this
        # exact path).
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
