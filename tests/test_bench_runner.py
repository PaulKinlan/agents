#!/usr/bin/env python3
"""lib/bench/runner.py runs the operator's bench command without a shell (agents-ywe, SF-05).

The hill-climb path edits files and re-measures them, so its subprocess is the wrong place
for shell=True: the command is operator-supplied today, but if a target config or a model
proposal ever feeds it, a shell turns that into arbitrary code execution with no further
code change. These tests pin the safe shape: argv in, direct exec, timeout enforced.
"""

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

FACTORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(FACTORY_ROOT))

import lib.bench.runner as bench_runner  # noqa: E402
from lib.bench.runner import measure_target  # noqa: E402
from lib.tool_pins import sha256_file  # noqa: E402


class TestBenchCmd(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="factory-bench-")
        self.addCleanup(temporary.cleanup)
        self.tree = Path(temporary.name)

    def test_bench_cmd_runs_and_times(self):
        """A real argv command is executed and its median timing recorded."""
        metrics = measure_target(self.tree, [sys.executable, "-c", "pass"])

        self.assertIsNotNone(metrics["custom_bench_ms"])

    def test_shell_metacharacters_are_not_interpreted(self):
        """$(...) reaches the executable as a literal argument: there is no shell to expand it."""
        marker = self.tree / "pwned"

        metrics = measure_target(self.tree, ["echo", f"$(touch {marker})"])

        self.assertIsNotNone(metrics["custom_bench_ms"])  # the command itself ran
        self.assertFalse(marker.exists())

    def test_cli_never_invokes_a_shell(self):
        """The bead's attack shape through the real CLI: `--bench-cmd 'echo $(touch ...)'`
        creates the file under shell=True, and must not under direct exec."""
        marker = self.tree / "pwned-cli"
        out = self.tree / "out.json"

        subprocess.run(
            [sys.executable, str(FACTORY_ROOT / "lib" / "bench" / "runner.py"),
             "--target", str(self.tree), "--bench-cmd", f"echo $(touch {marker})",
             "--output", str(out)],
            capture_output=True, text=True, timeout=120, check=True,
        )

        self.assertFalse(marker.exists())
        payload = json.loads(out.read_text())
        self.assertIsNotNone(payload["current_metrics"]["custom_bench_ms"])

    def test_bench_cmd_timeout_is_enforced(self):
        """A hung bench contributes no timing and returns promptly, per SF-06's fixed cap."""
        original = bench_runner.BENCH_TIMEOUT_SECONDS
        bench_runner.BENCH_TIMEOUT_SECONDS = 0.5
        try:
            start = time.monotonic()
            metrics = measure_target(
                self.tree, [sys.executable, "-c", "import time; time.sleep(60)"]
            )
            elapsed = time.monotonic() - start
        finally:
            bench_runner.BENCH_TIMEOUT_SECONDS = original

        self.assertIsNone(metrics["custom_bench_ms"])
        self.assertLess(elapsed, 30)  # 3 iterations x 0.5s, not 3 x 60s

    def test_failing_bench_cmd_records_no_timing(self):
        """A non-zero exit is a failed sample, not a measurement."""
        metrics = measure_target(self.tree, [sys.executable, "-c", "import sys; sys.exit(1)"])

        self.assertIsNone(metrics["custom_bench_ms"])

    def test_missing_executable_records_no_timing(self):
        """A typo'd binary surfaces on stderr and yields no timing, rather than crashing
        the whole measurement (shell=True used to hide it as exit 127)."""
        metrics = measure_target(self.tree, ["definitely-not-a-real-binary-ywe"])

        self.assertIsNone(metrics["custom_bench_ms"])


class TestBenchCmdPinBoundary(unittest.TestCase):
    """agents-28nn round 3, review P1 — the second runtime-constructed site with the
    command sink's shape: --bench-cmd is shlex.split of operator input and its argv[0]
    used to execute from PATH order with the pin machinery never consulted, so
    `--bench-cmd "git ..."` ran whichever git PATH ordered first. pin_trusted_argv now
    routes a trusted argv[0] through resolve_tool; a tool it cannot authenticate runs
    NOTHING — the measurement degrades to static metrics with the cause named on stderr.

    The behaviour-mutation proof: reverting lib/bench/runner.py to execute bench_cmd as
    given makes all three tests fail — the planted fake runs (its log appears) and a
    timing is recorded for it.
    """

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="factory-bench-pin-")
        self.addCleanup(temporary.cleanup)
        self.tree = Path(temporary.name)
        self.real_git = shutil.which("git")
        if self.real_git is None:
            self.skipTest("git is not installed on this host")
        self.fakebin = self.tree / "fakebin"
        self.fakebin.mkdir()
        self.fake_log = self.tree / "fake-git-ran"
        fake_git = self.fakebin / "git"
        fake_git.write_text(f'#!/bin/sh\necho ran >> "{self.fake_log}"\nexit 0\n',
                            encoding="utf-8")
        fake_git.chmod(0o755)
        self.pins = self.tree / "tools.pins.yaml"

    def measure(self, pins_text):
        self.pins.write_text(pins_text, encoding="utf-8")
        env = {"PATH": f"{self.fakebin}{os.pathsep}{os.environ.get('PATH', '')}",
               "FACTORY_TOOL_PINS": str(self.pins),
               # The dev/test opt-in this repo's suites sometimes set must NOT leak in:
               # these properties pin exactly what it waives.
               "FACTORY_ALLOW_UNPINNED_TOOLS": ""}
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, env), contextlib.redirect_stderr(stderr):
            metrics = measure_target(self.tree, ["git", "--version"])
        return metrics, stderr.getvalue()

    def test_a_configured_trusted_tool_cannot_reach_a_path_planted_fake(self):
        """THE HOLE, CLOSED: a sha256-only pin (resolution follows PATH order, so the fake
        IS the resolved candidate) fails the hash check — no timing is recorded, the
        cause is named on stderr, and the fake never ran."""
        metrics, stderr = self.measure(
            f"git:\n  sha256: {sha256_file(Path(self.real_git))}\n")
        self.assertIsNone(metrics["custom_bench_ms"])
        self.assertIn("cannot be authenticated", stderr)
        self.assertFalse(self.fake_log.exists(),
                         "the unauthenticated configured git must be refused BEFORE it executes")

    def test_a_full_pin_runs_the_configured_real_git_not_the_path_order_winner(self):
        """The positive direction: with path+sha256 pinned, the real git runs even when a
        fake wins PATH order — resolution follows the pin, not the PATH."""
        metrics, _stderr = self.measure(
            f"git:\n  path: {self.real_git}\n  sha256: {sha256_file(Path(self.real_git))}\n")
        self.assertIsNotNone(metrics["custom_bench_ms"],
                             "the pinned real git ran and was timed")
        self.assertFalse(self.fake_log.exists(), "the PATH-order winner must not run")

    def test_an_unpinned_configured_trusted_tool_runs_nothing_and_says_why(self):
        """Fail closed AND named: no pin anywhere, no opt-in — nothing runs and stderr
        records the cause rather than reading like a missing binary."""
        metrics, stderr = self.measure("")
        self.assertIsNone(metrics["custom_bench_ms"])
        self.assertIn("not pinned", stderr)
        self.assertFalse(self.fake_log.exists())


if __name__ == "__main__":
    unittest.main()
