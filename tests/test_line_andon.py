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
os.environ.setdefault("FACTORY_ALLOW_UNPINNED_TOOLS", "1")  # agents-7bj: tests use unpinned stub tools
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lib.credential_broker import PLACEHOLDER_PREFIX
from lib.sandbox import sandbox_available

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

loader = importlib.machinery.SourceFileLoader("factory_cli_p2c", str(ROOT / "factory"))
spec = importlib.util.spec_from_loader("factory_cli_p2c", loader)
factory_cli = importlib.util.module_from_spec(spec)
loader.exec_module(factory_cli)

LIB_MODULES = ("findings.py", "redaction.py", "embargo.py", "budget.py", "child_env.py",
               "credential_broker.py", "net_forward.py", "egress_proxy.py",
               "report_schema.py", "containment.py", "sandbox.py", "retention.py",
               "tool_pins.py", "line_numbers.py", "candidate_batching.py")


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
    def __init__(self, root: Path, halt: bool, stations, andon_stations=None) -> None:
        self.root = root
        self.target = root / "target"
        self.bin = root / "bin"
        self._build(halt, stations, andon_stations)

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

    def _build(self, halt: bool, stations, andon_stations=None) -> None:
        self._agent("okprobe")
        self._agent("failprobe")
        (self.root / "lines").mkdir()
        station_lines = "".join(f"  - {station}\n" for station in stations)
        andon_line = f"andon_stations: {json.dumps(andon_stations)}\n" if andon_stations is not None else ""
        (self.root / "lines" / "testline.yaml").write_text(
            "name: testline\n"
            f"andon_halt_on_failure: {'true' if halt else 'false'}\n"
            f"{andon_line}"
            "stations:\n"
            f"{station_lines}",
            encoding="utf-8",
        )

        (self.root / "lib" / "adapters").mkdir(parents=True)
        # agents-r2ne census: a FACTORY-runtime tree, not a station-script fixture - the copy set
        # is the factory dispatcher's own runtime (shell adapters, the lib/sinks package
        # directory, budget.py and friends), which tests/sandbox_fixtures.py:copy_station_script
        # deliberately does not derive (it follows ONE station script's Python import closure).
        # Different case; not routed through it.
        for engine in ("pi", "antigravity"):
            adapter = self.root / "lib" / "adapters" / f"{engine}.sh"
            shutil.copyfile(ROOT / "lib" / "adapters" / f"{engine}.sh", adapter)
            adapter.chmod(adapter.stat().st_mode | stat.S_IEXEC)
        # Contract (agents-v52t): the dispatcher runtime, staged by name; lib/sinks as a package tree.
        STAGED_RUNTIME = ("dispatcher", "named", ("sinks",))
        for module in LIB_MODULES:
            shutil.copyfile(ROOT / "lib" / module, self.root / "lib" / module)
        # Sink adapters (fleet-km8): findings.py delegates delivery to lib/sinks.
        shutil.copytree(ROOT / "lib" / "sinks", self.root / "lib" / "sinks", dirs_exist_ok=True)
        shutil.copyfile(ROOT / "lib" / "budget.py", self.root / "lib" / "budget.py")

        report = self.root / "report-src.json"
        report.write_text(json.dumps({"summary": "stub", "scanned_files": 1, "findings": []}),
                          encoding="utf-8")
        self.bin.mkdir()
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "cat >/dev/null\n"  # the adapter uses pipefail; a non-reading stub can SIGPIPE printf
            "echo OKPROBE-RAN\n"
            f"cat '{report}'\n",
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)

        self.target.mkdir()

    def run(self, engine: str = "pi", env_overrides=None):
        env = {
            "PATH": f"{self.bin}{os.pathsep}/usr/bin:/bin",
            "ANTHROPIC_API_KEY": "stub-key",
        }
        if env_overrides:
            env.update(env_overrides)
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
    def _sandbox(self, tmpdir: str, halt: bool, stations, andon_stations=None) -> LineSandbox:
        sandbox = LineSandbox(Path(tmpdir), halt=halt, stations=stations, andon_stations=andon_stations)
        # agents-r2ne census: copies the factory BINARY (a non-station artefact), not station
        # code - the shared station-script builder does not apply.
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

    @unittest.skipUnless(sandbox_available(), "needs a host where bubblewrap actually runs")
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

    @unittest.skipUnless(sandbox_available(), "needs a host where bubblewrap actually runs")
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

    @unittest.skipUnless(sandbox_available(), "needs a host where bubblewrap actually runs")
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
            # The same pi stub serves BOTH stations. Match the actual --skill agent path:
            # garbage is always unparseable, while the downstream okprobe must produce a
            # VALID report. Previously both emitted prose; okprobe then repair-retried and
            # could turn this test into a genuine adapter failure/HALTED flake.
            report = sandbox.root / "report-src.json"
            stub = sandbox.bin / "pi"
            stub.write_text(
                "#!/usr/bin/env bash\n"
                "cat >/dev/null\n"
                "agent=''\n"
                "while [ \"$#\" -gt 0 ]; do\n"
                "  if [ \"$1\" = --skill ]; then agent=${2##*/}; break; fi\n"
                "  shift\n"
                "done\n"
                "case \"$agent\" in\n"
                "  garbage) echo 'This station produced prose only. There is no JSON object here at all.' ;;\n"
                f"  okprobe) echo OKPROBE-RAN; cat '{report}' ;;\n"
                "  *) echo 'unexpected test agent' >&2; exit 97 ;;\n"
                "esac\n",
                encoding="utf-8")
            stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
            # A large prompt makes a non-reading canned-output stub SIGPIPE the
            # adapter's writer under pipefail; this direct process-boundary guard
            # fails reliably if the stdin drain above is removed (agents-lx4/ub9).
            drain = subprocess.run(
                ["bash", "-o", "pipefail", "-c",
                 'python3 -c \'import sys; sys.stdout.write("x"*200000)\' | "$1" --skill "$2"',
                 "bash", str(stub), str(sandbox.root / "agents" / "garbage")],
                capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual(drain.returncode, 0, drain.stderr)
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
            downstream = list((sandbox.root / "runs").glob("okprobe-*/report.json"))
            self.assertEqual(len(downstream), 1, "okprobe must succeed on its FIRST attempt")
            self.assertEqual(json.loads(downstream[0].read_text())["summary"], "stub")
            garbage_runs = list((sandbox.root / "runs").glob("garbage-*"))
            self.assertEqual(len(garbage_runs), 2, "only garbage gets the bounded repair-retry")

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

    @unittest.skipUnless(sandbox_available(), "needs a host where bubblewrap actually runs")
    def test_the_repair_retry_recovers_via_a_real_adapter_and_preserves_the_first_output(self):
        """agents-30q (1)+(2): with the REAL adapter and a REAL flaky engine — first call emits
        garbage and exits zero (a no-verdict), second call emits the valid report — the repair
        retry recovers the line. Each attempt must land in its OWN run directory: the rejected
        first output stays beside the retry's, never overwritten, and the retry's directory is
        visibly attempt-numbered."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = self._sandbox(tmpdir, halt=True, stations=["flaky", "okprobe"])
            sandbox._agent("flaky")
            report = sandbox.root / "report-src.json"
            stub = sandbox.bin / "pi"
            stub.write_text(
                "#!/usr/bin/env bash\n"
                # Only flaky is prompt-dependent. The shared stub also serves okprobe;
                # that downstream station must return its report on the FIRST attempt.
                # Read ALL stdin first: grep -q on a pipe can return early and SIGPIPE
                # the adapter's printf under pipefail even when the engine exits zero.
                "prompt=$(cat)\n"
                "agent=''\n"
                "while [ \"$#\" -gt 0 ]; do\n"
                "  if [ \"$1\" = --skill ]; then agent=${2##*/}; break; fi\n"
                "  shift\n"
                "done\n"
                "if [ \"$agent\" = okprobe ]; then\n"
                "  echo OKPROBE-RAN\n"
                f"  cat '{report}'\n"
                "elif [ \"$agent\" = flaky ] && grep -q 'NO VERDICT' <<<\"$prompt\"; then\n"
                "  echo FLAKY-RETRY-RECOVERED\n"
                f"  cat '{report}'\n"
                "elif [ \"$agent\" = flaky ]; then\n"
                "  echo 'FIRST ATTEMPT GARBAGE - no JSON here'\n"
                "else\n"
                "  echo 'unexpected test agent' >&2; exit 97\n"
                "fi\n",
                encoding="utf-8",
            )
            stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
            result, output = sandbox.run()

            self.assertTrue(result, "garbage-then-valid must recover via the repair-retry")
            self.assertIn("COMPLETE", output)
            self.assertIn("repair-retry", output)
            runs = sorted((sandbox.root / "runs").glob("flaky-*"))
            self.assertEqual(len(runs), 2, f"exactly one retry - one run dir per attempt: {[r.name for r in runs]}")
            first = next(r for r in runs if "-attempt2" not in r.name)
            second = next(r for r in runs if "-attempt2" in r.name)
            self.assertIn("FIRST ATTEMPT GARBAGE", (first / "model_output.txt").read_text(encoding="utf-8"),
                          "the rejected first output must be preserved for human recovery")
            second_output = (second / "model_output.txt").read_text(encoding="utf-8")
            self.assertIn("FLAKY-RETRY-RECOVERED", second_output)
            self.assertIn("\"summary\"", second_output, "the retry's output is the valid report")
            self.assertEqual(len(list((sandbox.root / "runs").glob("okprobe-*"))), 1,
                             "the downstream station must not need a repair-retry")

    @unittest.skipUnless(sandbox_available(), "needs a host where bubblewrap actually runs")
    def test_a_genuine_engine_failure_halts_via_a_real_adapter_with_one_invocation(self):
        """agents-30q (2): the real-adapter counterpart of the mocked halt test — a stub pi
        that exits NON-ZERO is a genuine engine failure, so the line halts, downstream stations
        are skipped, and there is NO repair-retry (the engine count proves it: exactly 1)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = self._sandbox(tmpdir, halt=True, stations=["genuine", "okprobe"])
            sandbox._agent("genuine")
            stub = sandbox.bin / "pi"
            stub.write_text(
                "#!/usr/bin/env bash\n"
                "cat >/dev/null\n"
                "echo 'engine exploded' >&2\n"
                "exit 7\n",
                encoding="utf-8",
            )
            stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
            result, output = sandbox.run()

            self.assertFalse(result)
            self.assertIn("HALTED", output)
            self.assertNotIn("repair-retry", output,
                             "a genuine failure must not be retried")
            self.assertEqual(len(list((sandbox.root / "runs").glob("genuine-*"))), 1,
                             "exactly one engine invocation — no retry on genuine failure")
            self.assertFalse(sandbox.marker.exists(), "the halted line must skip downstream stations")

    @unittest.skipUnless(sandbox_available(),
                         "the broker only engages for a sandboxed engine (bubblewrap host)")
    def test_the_credential_broker_lifecycle_spans_each_attempt_cleanly(self):
        """agents-30q (3): the credential broker is started and stopped per ATTEMPT — across
        a repair-retry there are two full start/stop cycles. Both attempts' engines see the
        placeholder + brokered base URL (never the operator's key), and after the line ends no
        broker socket path survives either attempt. The relay's child-facing port is in
        the sandbox's private netns, not the host namespace."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = self._sandbox(tmpdir, halt=True, stations=["flaky", "okprobe"])
            sandbox._agent("flaky")
            report = sandbox.root / "report-src.json"
            stub = sandbox.bin / "pi"
            stub.write_text(
                "#!/usr/bin/env bash\n"
                "echo \"KEY:${ANTHROPIC_API_KEY}\"\n"
                "echo \"BASE:${ANTHROPIC_BASE_URL:-unset}\"\n"
                "prompt=$(cat)\n"
                "agent=''\n"
                "while [ \"$#\" -gt 0 ]; do\n"
                "  if [ \"$1\" = --skill ]; then agent=${2##*/}; break; fi\n"
                "  shift\n"
                "done\n"
                "if [ \"$agent\" = okprobe ]; then\n"
                f"  cat '{report}'\n"
                "elif [ \"$agent\" = flaky ] && grep -q 'NO VERDICT' <<<\"$prompt\"; then\n"
                f"  cat '{report}'\n"
                "elif [ \"$agent\" = flaky ]; then\n"
                "  echo 'FIRST ATTEMPT GARBAGE - no JSON here'\n"
                "else\n"
                "  echo 'unexpected test agent' >&2; exit 97\n"
                "fi\n",
                encoding="utf-8",
            )
            stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
            result, output = sandbox.run(env_overrides={"FACTORY_MODEL": "anthropic/claude-3-5-sonnet"})

            self.assertTrue(result, "sanity: the retry must recover the line")
            runs = sorted((sandbox.root / "runs").glob("flaky-*"))
            self.assertEqual(len(runs), 2)
            self.assertEqual(len(list((sandbox.root / "runs").glob("okprobe-*"))), 1,
                             "only the flaky station should retry")
            for run in runs:
                text = (run / "model_output.txt").read_text(encoding="utf-8")
                self.assertIn(f"KEY:{PLACEHOLDER_PREFIX}", text,
                              f"attempt {run.name} must see the brokered placeholder, not the real key")
                self.assertNotIn("stub-key", text)
                base = next(line for line in text.splitlines() if line.startswith("BASE:"))
                self.assertTrue(base.startswith("BASE:http://127.0.0.1:"),
                                f"attempt {run.name} must reach the broker via localhost: {base}")
                self.assertFalse((run / "egress-broker.sock").exists(),
                                 f"attempt {run.name} must not leave its broker socket behind")
            # Each per-attempt broker UNIX socket is gone. Do not claim that binding
            # 127.0.0.1:8384 on the HOST proves the relay's child-facing port is free:
            # the relay listened in a separate --unshare-net namespace.

    def test_non_gated_station_timeout_degrades_and_continues_not_halts(self):
        """agents-7ms: a station timeout in a non-gate station must NOT halt the line and skip
        downstream stations. It records TIMEOUT, marks the line INCOMPLETE (fails), and downstream
        stations continue running."""
        from lib.budget import StationTimeout

        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = self._sandbox(tmpdir, halt=True, stations=["timeoutprobe", "okprobe"],
                                    andon_stations=["secret-scan", "vuln-triage"])

            def fake_run_agent(agent_name, *a, **k):
                if agent_name == "timeoutprobe":
                    raise StationTimeout("timeoutprobe: engine 'pi' exceeded 5 min budget; killed")
                return {"report": {"summary": "ok", "findings": [], "scanned_files": 1},
                        "fragment": None, "run_dir": tmpdir}

            with mock.patch.object(factory_cli, "run_agent", side_effect=fake_run_agent):
                result, output = sandbox.run()

            self.assertFalse(result, "a line with a timed-out station must report failure (INCOMPLETE)")
            self.assertIn("INCOMPLETE", output)
            self.assertNotIn("HALTED", output)
            self.assertNotIn("SKIPPED", output)
            self.assertIn("timeoutprobe", output)
            self.assertIn("TIMEOUT", output)
            self.assertIn("TIMED OUT", output)
            self.assertIn("okprobe", output)
            self.assertIn("PASS", output)

    def test_gated_station_timeout_halts_the_line(self):
        """agents-7ms: a station timeout in an explicit Andon gate station MUST halt the line."""
        from lib.budget import StationTimeout

        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = self._sandbox(tmpdir, halt=True, stations=["gatetimeout", "okprobe"],
                                    andon_stations=["gatetimeout"])

            def fake_run_agent(agent_name, *a, **k):
                if agent_name == "gatetimeout":
                    raise StationTimeout("gatetimeout: engine 'pi' exceeded budget; killed")
                return {"report": {"summary": "ok", "findings": [], "scanned_files": 1},
                        "fragment": None, "run_dir": tmpdir}

            with mock.patch.object(factory_cli, "run_agent", side_effect=fake_run_agent):
                result, output = sandbox.run()

            self.assertFalse(result, "a halted line must report failure")
            self.assertIn("HALTED", output)
            self.assertIn("gatetimeout", output)
            self.assertIn("TIMEOUT", output)
            self.assertIn("okprobe", output)
            self.assertIn("SKIPPED", output)

    def test_vuln_discovery_budget_is_at_least_twenty_minutes(self):
        """agents-7ms: vuln-discovery agent.yaml budget.max_minutes must be >= 20."""
        agent_yaml = ROOT / "agents" / "vuln-discovery" / "agent.yaml"
        cfg = factory_cli.load_yaml_simple(agent_yaml)
        max_minutes = cfg.get("budget", {}).get("max_minutes")
        self.assertIsNotNone(max_minutes)
        self.assertGreaterEqual(float(max_minutes), 20.0)

    @unittest.skipUnless(sandbox_available(), "needs a host where bubblewrap actually runs")
    def test_silent_station_is_retried_once_and_recovers_via_real_adapter(self):
        """agents-h8i4: a station that produces no verdict and no output (silent station)
        is retried ONCE. If the retry produces a valid report, the line completes as COMPLETE.
        The first attempt preserves its explicit reason and report in its own run dir."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = self._sandbox(tmpdir, halt=True, stations=["silentprobe", "okprobe"])
            sandbox._agent("silentprobe")
            report = sandbox.root / "report-src.json"
            stub = sandbox.bin / "pi"
            stub.write_text(
                "#!/usr/bin/env bash\n"
                "prompt=$(cat)\n"
                "agent=''\n"
                "while [ \"$#\" -gt 0 ]; do\n"
                "  if [ \"$1\" = --skill ]; then agent=${2##*/}; break; fi\n"
                "  shift\n"
                "done\n"
                "if [ \"$agent\" = okprobe ]; then\n"
                f"  cat '{report}'\n"
                "elif [ \"$agent\" = silentprobe ] && grep -q 'NO OUTPUT' <<<\"$prompt\"; then\n"
                f"  cat '{report}'\n"
                "elif [ \"$agent\" = silentprobe ]; then\n"
                "  # First attempt: exit 1, write 0 bytes to stdout and 0 bytes to stderr (silent station)\n"
                "  exit 1\n"
                "else\n"
                "  echo 'unexpected agent' >&2; exit 97\n"
                "fi\n",
                encoding="utf-8",
            )
            stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
            result, output = sandbox.run()

            self.assertTrue(result, "silent-then-valid must recover via the retry")
            self.assertIn("COMPLETE", output)
            self.assertIn("repair-retry", output)
            runs = sorted((sandbox.root / "runs").glob("silentprobe-*"))
            self.assertEqual(len(runs), 2, f"exactly one retry: {[r.name for r in runs]}")
            first = next(r for r in runs if "-attempt2" not in r.name)
            second = next(r for r in runs if "-attempt2" in r.name)
            self.assertTrue((first / "failure_reason.txt").exists(),
                            "the failed first attempt must leave an explicit reason in its run dir")
            first_reason = (first / "failure_reason.txt").read_text(encoding="utf-8")
            self.assertIn("silent station", first_reason)
            self.assertTrue((first / "report.json").exists())
            first_report = json.loads((first / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(first_report["status"], "ERROR")
            self.assertEqual(first_report["verdict"], "error")
            self.assertIn("silent station", first_report["summary"])

            second_report = json.loads((second / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(second_report["summary"], "stub")

    @unittest.skipUnless(sandbox_available(), "needs a host where bubblewrap actually runs")
    def test_silent_station_failing_after_retry_leaves_reason_in_run_dir_and_line_continues(self):
        """agents-h8i4: a station that remains silent after retry leaves an explicit reason
        in both run dirs, degrades to ERROR, and allows the line to continue as INCOMPLETE
        so downstream stations (okprobe) are not skipped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = self._sandbox(tmpdir, halt=True, stations=["persistentsilent", "okprobe"])
            sandbox._agent("persistentsilent")
            report = sandbox.root / "report-src.json"
            stub = sandbox.bin / "pi"
            stub.write_text(
                "#!/usr/bin/env bash\n"
                "prompt=$(cat)\n"
                "agent=''\n"
                "while [ \"$#\" -gt 0 ]; do\n"
                "  if [ \"$1\" = --skill ]; then agent=${2##*/}; break; fi\n"
                "  shift\n"
                "done\n"
                "if [ \"$agent\" = okprobe ]; then\n"
                "  echo OKPROBE-RAN\n"
                f"  cat '{report}'\n"
                "elif [ \"$agent\" = persistentsilent ]; then\n"
                "  # Both attempts silent: exit 1, 0 bytes stdout, 0 bytes stderr\n"
                "  exit 1\n"
                "else\n"
                "  echo 'unexpected agent' >&2; exit 97\n"
                "fi\n",
                encoding="utf-8",
            )
            stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
            result, output = sandbox.run()

            self.assertFalse(result, "a line with a silent station that fails retry is INCOMPLETE")
            self.assertIn("INCOMPLETE", output)
            self.assertNotIn("HALTED", output)
            self.assertIn("persistentsilent", output)
            self.assertIn("okprobe", output)
            self.assertIn("PASS", output)
            self.assertTrue(sandbox.marker.exists(), "okprobe downstream ran")

            runs = sorted((sandbox.root / "runs").glob("persistentsilent-*"))
            self.assertEqual(len(runs), 2, f"attempt 1 and attempt 2 run dirs: {[r.name for r in runs]}")
            for r in runs:
                self.assertTrue((r / "failure_reason.txt").exists(),
                                f"{r.name} must leave failure_reason.txt")
                self.assertTrue((r / "report.json").exists(),
                                f"{r.name} must leave report.json")
                reason = (r / "failure_reason.txt").read_text(encoding="utf-8")
                self.assertIn("silent station", reason)
                rep = json.loads((r / "report.json").read_text(encoding="utf-8"))
                self.assertEqual(rep["status"], "ERROR")
                self.assertEqual(rep["verdict"], "error")

    @unittest.skipUnless(sandbox_available(), "needs a host where bubblewrap actually runs")
    def test_missing_output_file_without_stderr_is_retried_as_silent_station(self):
        """agents-h8i4 (review finding P1): when model_output.txt is completely missing
        and stderr has no diagnostics, it must route through silent retry rather than sys.exit(1)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = self._sandbox(tmpdir, halt=True, stations=["missingfileprobe", "okprobe"])
            sandbox._agent("missingfileprobe")
            adapter = sandbox.root / "lib" / "adapters" / "pi.sh"
            adapter.write_text(
                "#!/usr/bin/env bash\n"
                "prompt=$(cat)\n"
                "run_dir=\"$4\"\n"
                "if grep -q 'NO OUTPUT' <<<\"$prompt\"; then\n"
                "  echo '{\"summary\": \"recovered\", \"findings\": [], \"scanned_files\": 1}' > \"$run_dir/model_output.txt\"\n"
                "  exit 0\n"
                "elif [ \"$1\" = okprobe ]; then\n"
                "  echo '{\"summary\": \"ok\", \"findings\": [], \"scanned_files\": 1}' > \"$run_dir/model_output.txt\"\n"
                "  exit 0\n"
                "else\n"
                "  # Attempt 1: no model_output.txt, no stderr output at all\n"
                "  rm -f \"$run_dir/model_output.txt\"\n"
                "  exit 1\n"
                "fi\n",
                encoding="utf-8",
            )
            adapter.chmod(adapter.stat().st_mode | stat.S_IEXEC)
            result, output = sandbox.run(engine="pi")

            self.assertTrue(result, "missing output file without stderr must recover via silent retry")
            self.assertIn("COMPLETE", output)
            self.assertIn("repair-retry", output)
            runs = sorted((sandbox.root / "runs").glob("missingfileprobe-*"))
            self.assertEqual(len(runs), 2, f"exactly one retry: {[r.name for r in runs]}")
            first = next(r for r in runs if "-attempt2" not in r.name)
            self.assertTrue((first / "failure_reason.txt").exists())
            self.assertIn("silent station", (first / "failure_reason.txt").read_text(encoding="utf-8"))

    @unittest.skipUnless(sandbox_available(), "needs a host where bubblewrap actually runs")
    def test_empty_output_with_stderr_rc_0_is_retried_and_line_continues(self):
        """agents-2wgg: when an engine exits 0, model_output.txt exists but is empty, and
        model_stderr.txt has diagnostic output, it must be treated as a plumbing failure
        (SilentStationError / NoVerdictError): repair-retried once, degrades to ERROR and
        continues as INCOMPLETE without halting the line, and downstream stations run.
        This exercises the REAL adapter (lib/adapters/pi.sh) with a stub engine."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = self._sandbox(tmpdir, halt=True, stations=["emptydiag", "okprobe"])
            sandbox._agent("emptydiag")
            report = sandbox.root / "report-src.json"
            stub = sandbox.bin / "pi"
            stub.write_text(
                "#!/usr/bin/env bash\n"
                "prompt=$(cat)\n"
                "agent=''\n"
                "while [ \"$#\" -gt 0 ]; do\n"
                "  if [ \"$1\" = --skill ]; then agent=${2##*/}; break; fi\n"
                "  shift\n"
                "done\n"
                "if [ \"$agent\" = okprobe ]; then\n"
                "  echo OKPROBE-RAN\n"
                f"  cat '{report}'\n"
                "elif [ \"$agent\" = emptydiag ]; then\n"
                "  echo 'engine diagnostic: warning notice' >&2\n"
                "  exit 0\n"
                "else\n"
                "  echo 'unexpected agent' >&2; exit 97\n"
                "fi\n",
                encoding="utf-8",
            )
            stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
            result, output = sandbox.run()

            self.assertFalse(result, "a line with an empty-output station is INCOMPLETE")
            self.assertIn("INCOMPLETE", output)
            self.assertNotIn("HALTED", output)
            self.assertNotIn("SKIPPED", output)
            self.assertIn("emptydiag", output)
            self.assertIn("okprobe", output)
            self.assertIn("PASS", output)
            self.assertTrue(sandbox.marker.exists(), "okprobe downstream must run")

            runs = sorted((sandbox.root / "runs").glob("emptydiag-*"))
            self.assertEqual(len(runs), 2, f"attempt 1 and attempt 2 run dirs: {[r.name for r in runs]}")
            for r in runs:
                self.assertTrue((r / "failure_reason.txt").exists(),
                                f"{r.name} must leave failure_reason.txt")
                self.assertTrue((r / "report.json").exists(),
                                f"{r.name} must leave report.json")
                reason = (r / "failure_reason.txt").read_text(encoding="utf-8")
                self.assertIn("exited 0 but produced no verdict or output", reason)
                rep = json.loads((r / "report.json").read_text(encoding="utf-8"))
                self.assertEqual(rep["status"], "ERROR")
                self.assertEqual(rep["verdict"], "error")
                # agents-lbgso: a failed attempt must leave enough behind to diagnose it. Measured on
                # this tree before writing these: a silent engine exits 2 (never 0), and each attempt
                # keeps prompt.txt (what was asked), model_output.txt (the model's raw stdout channel,
                # empty here because the engine wrote nothing), model_stderr.txt and the reason. The
                # premise that prompted the bead - "exits 0 with an empty model_output.txt" - is stale;
                # what was unpinned is that the ASK and the ENGINE's own words survive the failure.
                self.assertTrue((r / "prompt.txt").exists(), f"{r.name} must keep the prompt it sent")
                self.assertGreater((r / "prompt.txt").stat().st_size, 0, f"{r.name}: empty prompt.txt")
                self.assertTrue((r / "model_output.txt").exists(),
                                f"{r.name} must keep the raw stdout channel even when empty")
                self.assertEqual((r / "model_output.txt").stat().st_size, 0,
                                 "the silent engine wrote nothing, so the artifact is empty - and kept")
                self.assertIn("engine diagnostic: warning notice",
                              (r / "model_stderr.txt").read_text(encoding="utf-8"),
                              f"{r.name}: the engine's own stderr must be preserved")
                self.assertIn("engine diagnostic: warning notice", reason,
                              "and quoted in the reason, so the failure reads without opening files")


if __name__ == "__main__":
    unittest.main()
