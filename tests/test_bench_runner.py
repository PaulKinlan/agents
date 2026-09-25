#!/usr/bin/env python3
"""lib/bench/runner.py runs the operator's bench command without a shell (agents-ywe, SF-05).

The hill-climb path edits files and re-measures them, so its subprocess is the wrong place
for shell=True: the command is operator-supplied today, but if a target config or a model
proposal ever feeds it, a shell turns that into arbitrary code execution with no further
code change. These tests pin the safe shape: argv in, direct exec, timeout enforced.
"""

import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

FACTORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(FACTORY_ROOT))

import lib.bench.runner as bench_runner  # noqa: E402
from lib.bench.runner import measure_target  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
