#!/usr/bin/env python3
"""A station that fails closed must not kill the line (agents-p2c).

run_agent calls sys.exit(1) when an adapter produces no model output. SystemExit is not an
Exception, so run_line's station loop used to abort the whole process mid-line: no scorecard, no
per-station summary, and no halt_on_failure path. These tests drive the real line runner and the
real CLI and assert the Andon semantics survive.
"""

import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

loader = importlib.machinery.SourceFileLoader("factory_cli_p2c", str(ROOT / "factory"))
spec = importlib.util.spec_from_loader("factory_cli_p2c", loader)
factory_cli = importlib.util.module_from_spec(spec)
loader.exec_module(factory_cli)

LIB_MODULES = ("findings.py", "redaction.py", "embargo.py", "budget.py", "child_env.py",
               "report_schema.py")


class LineSandbox:
    def __init__(self, root: Path, halt: bool, stations) -> None:
        self.root = root
        self.target = root / "target"
        self.bin = root / "bin"
        self.marker = root / "okprobe-ran"
        self._build(halt, stations)

    def _agent(self, name: str) -> None:
        directory = self.root / "agents" / name
        directory.mkdir(parents=True)
        (directory / "agent.yaml").write_text(
            f"name: {name}\n"
            "class: observer\n"
            "containment: t0-readonly\n"
            "short_circuit_empty: false\n"
            "budget: {max_minutes: 1}\n",
            encoding="utf-8",
        )

    def _build(self, halt: bool, stations) -> None:
        self._agent("okprobe")
        self._agent("failprobe")
        (self.root / "lines").mkdir()
        station_lines = "".join(f"  - {station}\n" for station in stations)
        (self.root / "lines" / "testline.yaml").write_text(
            "name: testline\n"
            f"andon_halt_on_failure: {'true' if halt else 'false'}\n"
            "stations:\n"
            f"{station_lines}",
            encoding="utf-8",
        )

        (self.root / "lib" / "adapters").mkdir(parents=True)
        for engine in ("pi", "antigravity"):
            adapter = self.root / "lib" / "adapters" / f"{engine}.sh"
            shutil.copyfile(ROOT / "lib" / "adapters" / f"{engine}.sh", adapter)
            adapter.chmod(adapter.stat().st_mode | stat.S_IEXEC)
        for module in LIB_MODULES:
            shutil.copyfile(ROOT / "lib" / module, self.root / "lib" / module)

        report = self.root / "report-src.json"
        report.write_text(json.dumps({"summary": "stub", "scanned_files": 1, "findings": []}),
                          encoding="utf-8")
        self.bin.mkdir()
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            f"touch '{self.marker}'\n"
            f"cat '{report}'\n",
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)

        self.target.mkdir()

    def run(self, engine: str = "pi"):
        env = {
            "PATH": f"{self.bin}{os.pathsep}/usr/bin:/bin",
            "ANTHROPIC_API_KEY": "stub-key",
        }
        stdout = io.StringIO()
        with mock.patch.object(factory_cli, "FACTORY_ROOT", self.root), \
             mock.patch.dict(os.environ, env), \
             contextlib.redirect_stdout(stdout):
            result = factory_cli.run_line("testline", str(self.target), engine_arg=engine)
        return result, stdout.getvalue()

    def run_cli(self, engine: str = "pi"):
        env = dict(os.environ)
        env["PATH"] = f"{self.bin}{os.pathsep}/usr/bin:/bin"
        env["ANTHROPIC_API_KEY"] = "stub-key"
        return subprocess.run(
            [sys.executable, str(self.root / "factory"), "line", "testline",
             "--target", str(self.target), "--engine", engine, "--sink", "file"],
            cwd=str(self.root), env=env, capture_output=True, text=True, timeout=120,
        )


class TestLineAndon(unittest.TestCase):
    def _sandbox(self, tmpdir: str, halt: bool, stations) -> LineSandbox:
        sandbox = LineSandbox(Path(tmpdir), halt=halt, stations=stations)
        shutil.copyfile(ROOT / "factory", sandbox.root / "factory")
        (sandbox.root / "factory").chmod(0o755)
        return sandbox

    def test_a_station_system_exit_records_error_and_halts(self):
        """The bead's case: a fail-closed station aborted the process before the scorecard."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = self._sandbox(tmpdir, halt=True, stations=["missing-agent", "okprobe"])
            result, output = sandbox.run()

            self.assertFalse(result, "a halted line must report failure to its caller")
            self.assertIn("FACTORY LINE SCORECARD", output)
            self.assertIn("HALTED", output)
            self.assertIn("missing-agent", output)
            self.assertIn("ERROR", output)
            self.assertFalse(sandbox.marker.exists(),
                             "a station after a halted failure must not run")

    def test_halt_on_failure_false_continues_and_keeps_the_scorecard(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = self._sandbox(tmpdir, halt=False, stations=["missing-agent", "okprobe"])
            result, output = sandbox.run()

            self.assertTrue(result, "a completed line must report success")
            self.assertIn("FACTORY LINE SCORECARD", output)
            self.assertIn("COMPLETE", output)
            self.assertIn("ERROR", output)
            self.assertTrue(sandbox.marker.exists(), "downstream stations must run when not halting")

    def test_a_fail_closed_adapter_is_a_station_failure_not_an_abort(self):
        """The exact repro: antigravity with no agentapi exits 1 from the adapter."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = self._sandbox(tmpdir, halt=True, stations=["failprobe"])
            result, output = sandbox.run(engine="antigravity")

            self.assertFalse(result)
            self.assertIn("FACTORY LINE SCORECARD", output)
            self.assertIn("failprobe", output)
            self.assertIn("ERROR", output)

    def test_the_cli_exits_non_zero_when_the_line_halts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = self._sandbox(tmpdir, halt=True, stations=["missing-agent", "okprobe"])
            res = sandbox.run_cli()

            self.assertEqual(res.returncode, 1)
            self.assertIn("FACTORY LINE SCORECARD", res.stdout)
            self.assertIn("ERROR", res.stdout)


if __name__ == "__main__":
    unittest.main()
