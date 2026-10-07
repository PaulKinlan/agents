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
               "credential_broker.py", "net_forward.py", "egress_proxy.py",
               "report_schema.py", "containment.py", "sandbox.py")


class _Marker:
    """Proof the okprobe station's engine ran. The stub echoes the marker into its stdout,
    which the adapter captures into the run directory's model_output.txt — the OS sandbox
    (agents-9n7) leaves the engine nothing else writable."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def exists(self) -> bool:
        runs = self.root / "runs"
        if not runs.exists():
            return False
        return any("OKPROBE-RAN" in (run / "model_output.txt").read_text(encoding="utf-8")
                   for run in runs.glob("okprobe-*")
                   if (run / "model_output.txt").exists())


class LineSandbox:
    def __init__(self, root: Path, halt: bool, stations) -> None:
        self.root = root
        self.target = root / "target"
        self.bin = root / "bin"
        self._build(halt, stations)

    @property
    def marker(self):
        return _Marker(self.root)

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
            "echo OKPROBE-RAN\n"
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

            # Every station after the failure ran, but one produced no verdict: the line is
            # INCOMPLETE and reports failure rather than success (fleet-ddd, journal-idy).
            self.assertFalse(result, "a line with a no-verdict station must not report success")
            self.assertIn("FACTORY LINE SCORECARD", output)
            self.assertIn("INCOMPLETE", output)
            self.assertIn("ERROR", output)
            self.assertTrue(sandbox.marker.exists(), "downstream stations must run when not halting")

    def test_a_fail_closed_adapter_is_a_station_failure_not_an_abort(self):
        """The bead's repro: an adapter exits 1 without producing model output, so run_agent
        calls sys.exit(1). This used antigravity with no agentapi; since agents-pnu the
        dispatcher refuses antigravity before its adapter runs (next test), so a stub adapter
        that fails closed the same way keeps the SystemExit path covered."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = self._sandbox(tmpdir, halt=True, stations=["failprobe"])
            adapter = sandbox.root / "lib" / "adapters" / "pi.sh"
            adapter.write_text("#!/usr/bin/env bash\necho 'adapter failed closed' >&2\nexit 1\n",
                               encoding="utf-8")
            result, output = sandbox.run(engine="pi")

            self.assertFalse(result)
            self.assertIn("FACTORY LINE SCORECARD", output)
            self.assertIn("failprobe", output)
            self.assertIn("exited with code 1", output)
            self.assertIn("ERROR", output)

    def test_a_containment_refusal_is_a_station_failure_not_an_abort(self):
        """An engine that cannot enforce the tool policy is refused (agents-pnu), and the line
        still scores the station and halts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = self._sandbox(tmpdir, halt=True, stations=["failprobe", "okprobe"])
            result, output = sandbox.run(engine="antigravity")

            self.assertFalse(result)
            self.assertIn("FACTORY LINE SCORECARD", output)
            self.assertIn("HALTED", output)
            self.assertIn("cannot enforce", output)
            self.assertIn("ERROR", output)

    def test_the_cli_exits_non_zero_when_the_line_halts(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = self._sandbox(tmpdir, halt=True, stations=["missing-agent", "okprobe"])
            res = sandbox.run_cli()

            self.assertEqual(res.returncode, 1)
            self.assertIn("FACTORY LINE SCORECARD", res.stdout)
            self.assertIn("ERROR", res.stdout)

    # --- agents-noo: a no-verdict (unparseable/schema-invalid) station is a PLUMBING failure ---
    # It must degrade-and-continue (line INCOMPLETE), NOT halt and skip every downstream station.
    # A GENUINE failure (engine/pre-pass) still halts. run_line branches on the NoVerdictError
    # TYPE, and gives it exactly one bounded repair-retry first.

    def test_unparseable_output_degrades_and_continues_not_halts(self):
        """agents-noo core: a station whose model output is unparseable (a PLUMBING failure, not a
        genuine engine failure) must NOT halt the line, even with andon_halt_on_failure=true.
        run_agent raises NoVerdictError, run_line repair-retries once (still unparseable), then
        degrades the station to ERROR and CONTINUES. Before this fix the line halted here and
        skipped every downstream station. This is end-to-end (the real run_agent parses the real
        stub output), so it also proves the no-verdict path raises NoVerdictError, not StationError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = self._sandbox(tmpdir, halt=True, stations=["garbage", "okprobe"])
            (sandbox.root / "agents" / "garbage").mkdir(parents=True)
            (sandbox.root / "agents" / "garbage" / "agent.yaml").write_text(
                "name: garbage\nclass: observer\ncontainment: t0-readonly\n"
                "short_circuit_empty: false\nbudget: {max_minutes: 1}\n", encoding="utf-8")
            # Prose, not a JSON report. The OKPROBE-RAN line keeps _Marker's proof that the
            # downstream station actually ran (the line continued past the no-verdict).
            stub = sandbox.bin / "pi"
            stub.write_text(
                "#!/usr/bin/env bash\n"
                "echo OKPROBE-RAN\n"
                "echo 'This station produced prose only. There is no JSON object here at all.'\n",
                encoding="utf-8")
            stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
            result, output = sandbox.run()

            self.assertFalse(result, "a line with a no-verdict station must report failure (INCOMPLETE)")
            self.assertIn("INCOMPLETE", output)
            self.assertNotIn("HALTED", output)
            self.assertNotIn("SKIPPED", output)
            self.assertIn("garbage", output)
            self.assertIn("ERROR", output)
            self.assertIn("repair-retry", output)
            self.assertTrue(sandbox.marker.exists(),
                            "the downstream station must RUN: the line continued past the no-verdict")

    def test_a_genuine_engine_failure_still_halts_the_line(self):
        """agents-noo guard: NoVerdictError degrades, but a GENUINE StationError (a failed engine,
        not merely unparseable output) must still halt the line and skip downstream stations. This
        proves the NoVerdictError subclass did not silently turn genuine failures into
        degrade-and-continue, and that genuine failures are NOT repair-retried."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = self._sandbox(tmpdir, halt=True, stations=["genuine", "okprobe"])

            def fake_run_agent(agent_name, *a, **k):
                raise factory_cli.StationError(f"{agent_name}: engine 'pi' exited 1; genuine failure")

            with mock.patch.object(factory_cli, "run_agent", side_effect=fake_run_agent):
                result, output = sandbox.run()

            self.assertFalse(result)
            self.assertIn("HALTED", output)
            self.assertIn("genuine", output)
            self.assertIn("ERROR", output)
            self.assertIn("okprobe", output)
            self.assertIn("SKIPPED", output)
            self.assertNotIn("repair-retry", output)
            self.assertFalse(sandbox.marker.exists(),
                             "a halted line must not run the downstream station")

    def test_the_repair_retry_recovers_a_station_whose_first_output_was_unparseable(self):
        """agents-noo: the ONE bounded repair-retry is real — a station that produces no verdict on
        the first attempt but a valid report on the retry PASSES, and the line completes. Proves the
        retry can recover a transient bad-output station instead of degrading it, and that it is
        bounded (exactly one retry)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = self._sandbox(tmpdir, halt=True, stations=["flaky", "okprobe"])
            valid = {"report": {"summary": "ok", "findings": [], "scanned_files": 1},
                     "fragment": None, "run_dir": tmpdir}
            calls = {"flaky": 0}

            def fake_run_agent(agent_name, *a, **k):
                if agent_name == "flaky":
                    calls["flaky"] += 1
                    if calls["flaky"] == 1:
                        raise factory_cli.NoVerdictError("flaky: unparseable output; no verdict")
                return valid

            with mock.patch.object(factory_cli, "run_agent", side_effect=fake_run_agent):
                result, output = sandbox.run()

            self.assertTrue(result, "a line whose stations all reached a verdict must report success")
            self.assertIn("COMPLETE", output)
            self.assertNotIn("INCOMPLETE", output)
            self.assertNotIn("HALTED", output)
            self.assertIn("repair-retry", output)
            self.assertEqual(calls["flaky"], 2, "flaky must be retried exactly once (bounded)")
            self.assertIn("flaky", output)
            self.assertIn("okprobe", output)
            self.assertIn("PASS", output)


if __name__ == "__main__":
    unittest.main()
