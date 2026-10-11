#!/usr/bin/env python3
"""Tests for adapter authentication / environment failure reporting (agents-zrn).

When an engine adapter fails because it cannot authenticate (e.g. pi exit 1 'No API key found
for the selected model', claude exit 1 'no Claude credentials', deepseek 'DEEPSEEK_API_KEY is not configured'):
1. The station reports a distinct NAMED environment failure (AdapterAuthError / EnvironmentFailureError),
   not a generic 'no verdict' StationError.
2. In single-station runs, report.json and the delta report record ENV_FAILURE, findings are UNKNOWN (—),
   and the report never says 'Clean Delta' or 0 findings.
3. In line runs, the station is recorded on the scorecard as ENV_FAILURE with '-' findings and '-' criticals.
   If andon_halt_on_failure is true, the line halts; if false, it continues as INCOMPLETE.
"""

import contextlib
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

import importlib.machinery
import importlib.util

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# agents-28nn round 5: run_agent pin-verifies the engine binary before the adapter may
# execute it; these tests drive run_agent in-process with stub adapters, so they run
# under the same documented dev/test opt-in the other in-process harnesses use.
os.environ.setdefault("FACTORY_ALLOW_UNPINNED_TOOLS", "1")

loader = importlib.machinery.SourceFileLoader("factory_cli_auth", str(ROOT / "factory"))
spec = importlib.util.spec_from_loader("factory_cli_auth", loader)
factory_module = importlib.util.module_from_spec(spec)
loader.exec_module(factory_module)

AdapterAuthError = factory_module.AdapterAuthError
EnvironmentFailureError = factory_module.EnvironmentFailureError
detect_adapter_auth_failure = factory_module.detect_adapter_auth_failure
run_agent = factory_module.run_agent
run_line = factory_module.run_line
from lib.sandbox import sandbox_available


class TestAdapterAuthFailureDetection(unittest.TestCase):
    def test_pi_auth_failure_detected(self):
        output = "No API key found for the selected model.\nUse /login to log into a provider via OAuth or API key."
        reason = detect_adapter_auth_failure(output, "")
        self.assertIsNotNone(reason)
        self.assertIn("No API key found for the selected model", reason)

    def test_pi_provider_specific_auth_failure_detected(self):
        output = "No API key found for antigravity.\nUse /login to log into a provider via OAuth or API key."
        reason = detect_adapter_auth_failure(output, "")
        self.assertIsNotNone(reason)
        self.assertEqual(reason, "No API key found for antigravity")

    def test_pi_token_shaped_provider_not_leaked(self):
        """Reviewer finding P1: token-shaped string after 'No API key found for' must never be
        echoed into the reason code."""
        output = "No API key found for sk-ant-secret-token-1234567890\n"
        reason = detect_adapter_auth_failure(output, "")
        self.assertIsNotNone(reason)
        self.assertEqual(reason, "No API key found for the selected model")
        self.assertNotIn("sk-ant", reason)
        self.assertNotIn("secret", reason)
        self.assertNotIn("1234567890", reason)

    def test_claude_credentials_failure_detected(self):
        stderr = "[claude adapter] Error: no Claude credentials. Run 'claude login' for session auth"
        reason = detect_adapter_auth_failure("", stderr)
        self.assertIsNotNone(reason)
        self.assertIn("No Claude credentials", reason)

    def test_deepseek_key_failure_detected(self):
        stderr = "[deepseek adapter] Error: DEEPSEEK_API_KEY is not configured.\n"
        reason = detect_adapter_auth_failure("", stderr)
        self.assertIsNotNone(reason)
        self.assertIn("DEEPSEEK_API_KEY is not configured", reason)

    def test_http_401_detected_and_sanitized(self):
        stderr = "HTTP Error 401: Unauthorized; Authorization: Bearer sk-ant-secret-1234567890\n"
        reason = detect_adapter_auth_failure("", stderr)
        self.assertIsNotNone(reason)
        self.assertEqual(reason, "Model API returned HTTP 401 Unauthorized")
        self.assertNotIn("Bearer", reason)
        self.assertNotIn("secret", reason)

    def test_non_auth_failure_not_detected(self):
        output = "SyntaxError: Unexpected token in JSON at position 0\n"
        stderr = "fatal: segmentation fault\n"
        reason = detect_adapter_auth_failure(output, stderr)
        self.assertIsNone(reason)

    def test_finding_mentioning_unauthorized_does_not_trigger_auth_failure(self):
        """Reviewer finding P2: a non-auth failure mentioning 'unauthorized access' in findings
        or code discussion must not be misclassified as adapter auth failure."""
        output = '{"findings": [{"title": "Unauthorized access to /admin endpoint"}]}\n'
        stderr = "fatal: process killed by SIGTERM\n"
        reason = detect_adapter_auth_failure(output, stderr)
        self.assertIsNone(reason)


class TestSingleStationAdapterAuthFailure(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.root = Path(self.tmp)
        self.target = self.root / "target"
        self.target.mkdir()

        # Build mock agent
        self.agent_dir = self.root / "agents" / "a11y-test"
        self.agent_dir.mkdir(parents=True)
        (self.agent_dir / "agent.yaml").write_text(
            "name: a11y-test\n"
            "class: observer\n"
            "containment: t0-readonly\n"
            "short_circuit_empty: false\n"
            "budget: {max_minutes: 1}\n",
            encoding="utf-8",
        )
        (self.agent_dir / "report.schema.json").write_text(
            json.dumps({"type": "object", "required": ["summary", "findings"],
                        "properties": {"summary": {"type": "string"}, "findings": {"type": "array"}}}),
            encoding="utf-8",
        )

        # Mock adapters
        (self.root / "lib" / "adapters").mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_pi_adapter_auth_failure_raises_adapter_auth_error_and_writes_reports(self):
        """When pi adapter fails with 'No API key found', run_agent raises AdapterAuthError,
        writes report.json with status ENV_FAILURE and verdict environment_failure, and writes
        an ENVIRONMENT FAILURE delta report with UNKNOWN findings."""
        (self.root / "targets").mkdir(exist_ok=True)
        (self.root / "targets" / "target.yaml").write_text(
            f"name: target\npath: {self.target}\ntrusted: true\nvisibility: private\n",
            encoding="utf-8",
        )
        adapter = self.root / "lib" / "adapters" / "pi.sh"
        adapter.write_text(
            "#!/usr/bin/env bash\n"
            "RUN_DIR=\"$4\"\n"
            "mkdir -p \"$RUN_DIR\"\n"
            "echo 'No API key found for the selected model.' > \"$RUN_DIR/model_output.txt\"\n"
            "echo 'Use /login to log into a provider via OAuth or API key.' >> \"$RUN_DIR/model_output.txt\"\n"
            "exit 1\n",
            encoding="utf-8",
        )
        adapter.chmod(adapter.stat().st_mode | stat.S_IEXEC)

        stderr_buf = io.StringIO()
        with mock.patch.object(factory_module, "FACTORY_ROOT", self.root), \
             mock.patch.object(factory_module, "sandbox_available", return_value=True), \
             mock.patch.object(factory_module, "sandbox_command", side_effect=lambda cmd, **kw: cmd), \
             contextlib.redirect_stderr(stderr_buf):
            with self.assertRaises(AdapterAuthError) as ctx:
                run_agent("a11y-test", "target", engine_arg="pi", explicit_sink="file")

        err = ctx.exception
        self.assertIsInstance(err, EnvironmentFailureError)
        self.assertEqual(err.agent, "a11y-test")
        self.assertEqual(err.engine, "pi")
        self.assertIn("No API key found for the selected model", err.reason)
        self.assertIn("[environment failure]", stderr_buf.getvalue())

        # Check run_dir / report.json
        runs = list((self.root / "runs").glob("a11y-test-*"))
        self.assertEqual(len(runs), 1)
        report_json = json.loads((runs[0] / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(report_json["status"], "ENV_FAILURE")
        self.assertEqual(report_json["verdict"], "environment_failure")
        self.assertIn("No API key found", report_json["summary"])

        # Check findings delta report
        delta_md = (self.root / "findings" / f"{self.target.name}-a11y-test-delta.md").read_text(encoding="utf-8")
        self.assertIn("ENVIRONMENT FAILURE", delta_md)
        self.assertIn("UNKNOWN", delta_md)
        self.assertIn("not zero", delta_md)
        self.assertNotIn("Clean Delta", delta_md)
        self.assertIn("| — | — | — | — | — | — |", delta_md)

    def test_claude_adapter_auth_failure_detected_from_stderr(self):
        """When claude adapter fails closed with 'no Claude credentials' on stderr before
        creating model_output.txt, run_agent detects it as AdapterAuthError rather than dying
        with SystemExit(1)."""
        # Set target as trusted private so claude is not refused upfront by agents-ejm
        (self.root / "targets").mkdir(exist_ok=True)
        (self.root / "targets" / "target.yaml").write_text(
            f"name: target\npath: {self.target}\ntrusted: true\nvisibility: private\n",
            encoding="utf-8",
        )
        adapter = self.root / "lib" / "adapters" / "claude.sh"
        adapter.write_text(
            "#!/usr/bin/env bash\n"
            "echo \"[claude adapter] Error: no Claude credentials. Run 'claude login'\" >&2\n"
            "exit 1\n",
            encoding="utf-8",
        )
        adapter.chmod(adapter.stat().st_mode | stat.S_IEXEC)

        stderr_buf = io.StringIO()
        with mock.patch.object(factory_module, "FACTORY_ROOT", self.root), \
             mock.patch.object(factory_module, "sandbox_available", return_value=False), \
             contextlib.redirect_stderr(stderr_buf):
            with self.assertRaises(AdapterAuthError) as ctx:
                run_agent("a11y-test", "target", engine_arg="claude", explicit_sink="file")

        err = ctx.exception
        self.assertEqual(err.engine, "claude")
        self.assertIn("No Claude credentials", err.reason)
        self.assertIn("[environment failure]", stderr_buf.getvalue())


class TestLineAdapterAuthFailure(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.root = Path(self.tmp)
        self.target = self.root / "target"
        self.target.mkdir()

        # Build mock agents
        for name in ("a11y-test", "next-station"):
            agent_dir = self.root / "agents" / name
            agent_dir.mkdir(parents=True)
            (agent_dir / "agent.yaml").write_text(
                f"name: {name}\nclass: observer\ncontainment: t0-readonly\nshort_circuit_empty: false\nbudget: {{max_minutes: 1}}\n",
                encoding="utf-8",
            )
            (agent_dir / "report.schema.json").write_text(
                json.dumps({"type": "object", "required": ["summary", "findings"],
                            "properties": {"summary": {"type": "string"}, "findings": {"type": "array"}}}),
                encoding="utf-8",
            )

        (self.root / "lib" / "adapters").mkdir(parents=True)
        # agents-r2ne census: a FACTORY-runtime tree, not a station-script fixture - this copies
        # the factory dispatcher's own runtime (every lib/*.py by GLOB, plus the lib/sinks
        # package directory), not a station script's dependencies, so
        # tests/sandbox_fixtures.py:copy_station_script does not apply. Different case.
        for mod in (ROOT / "lib").glob("*.py"):
            shutil.copyfile(mod, self.root / "lib" / mod.name)
        # Sink adapters (fleet-km8): findings.py delegates delivery to lib/sinks.
        shutil.copytree(ROOT / "lib" / "sinks", self.root / "lib" / "sinks", dirs_exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _setup_line(self, halt_on_failure: bool):
        (self.root / "lines").mkdir(exist_ok=True)
        (self.root / "lines" / "testline.yaml").write_text(
            "name: testline\n"
            f"andon_halt_on_failure: {'true' if halt_on_failure else 'false'}\n"
            "stations:\n"
            "  - a11y-test\n"
            "  - next-station\n",
            encoding="utf-8",
        )

    def test_line_halt_on_failure_false_records_env_failure_and_continues(self):
        """When andon_halt_on_failure is false, an adapter auth failure marks the station as
        ENV_FAILURE with '-' findings, continues remaining stations, reports line INCOMPLETE,
        and includes an ENVIRONMENT FAILURE callout in the line delta report."""
        self._setup_line(halt_on_failure=False)

        # Pi adapter fails for a11y-test, succeeds for next-station
        adapter = self.root / "lib" / "adapters" / "pi.sh"
        adapter.write_text(
            "#!/usr/bin/env bash\n"
            "AGENT=\"$1\"\n"
            "RUN_DIR=\"$4\"\n"
            "mkdir -p \"$RUN_DIR\"\n"
            "if [ \"$AGENT\" = \"a11y-test\" ]; then\n"
            "  echo 'No API key found for the selected model.' > \"$RUN_DIR/model_output.txt\"\n"
            "  exit 1\n"
            "else\n"
            "  echo '{\"summary\": \"ok\", \"findings\": []}' > \"$RUN_DIR/model_output.txt\"\n"
            "  exit 0\n"
            "fi\n",
            encoding="utf-8",
        )
        adapter.chmod(adapter.stat().st_mode | stat.S_IEXEC)

        stdout_buf = io.StringIO()
        with mock.patch.object(factory_module, "FACTORY_ROOT", self.root), \
             mock.patch.object(factory_module, "sandbox_available", return_value=True), \
             mock.patch.object(factory_module, "sandbox_command", side_effect=lambda cmd, **kw: cmd), \
             contextlib.redirect_stdout(stdout_buf):
            result = run_line("testline", str(self.target), engine_arg="pi", explicit_sink="file")

        output = stdout_buf.getvalue()
        # Line must report failure overall
        self.assertFalse(result)
        # Scorecard must show INCOMPLETE
        self.assertIn("INCOMPLETE", output)
        # a11y-test must be recorded as ENV_FAILURE
        self.assertIn("ENV_FAILURE", output)
        self.assertIn("a11y-test", output)
        # next-station must have run and passed
        self.assertIn("next-station", output)
        self.assertIn("PASS", output)
        self.assertIn("encountered ENVIRONMENT FAILURE (adapter auth): a11y-test", output)

        # Check line delta report
        line_delta_file = self.root / "findings" / f"{self.target.name}-delta.md"
        self.assertTrue(line_delta_file.exists())
        line_delta = line_delta_file.read_text(encoding="utf-8")
        self.assertIn("ENVIRONMENT FAILURE", line_delta)
        self.assertIn("`a11y-test`", line_delta)
        self.assertIn("UNKNOWN (not zero)", line_delta)
        self.assertNotIn("Clean Delta", line_delta)
        # Headline table must be unknown, not zeroes (reviewer finding P1)
        self.assertIn("| — | — | — | — | — | — |", line_delta)
        self.assertIn("| `a11y-test` | ENV_FAILURE | — | — |", line_delta)

        # Check line machine json
        line_json = json.loads((self.root / "findings" / f"{self.target.name}-line.json").read_text(encoding="utf-8"))
        self.assertFalse(line_json["complete"])
        stations = {s["station"]: s for s in line_json["stations"]}
        self.assertEqual(stations["a11y-test"]["status"], "ENV_FAILURE")
        self.assertIsNone(stations["a11y-test"]["findings_count"])

    def test_cli_run_adapter_auth_failure_exits_2_with_environment_failure_stderr(self):
        """When factory run encounters an adapter auth failure, it outputs [environment failure]
        and exits 2 (not generic no-verdict station failure).
        
        Uses a trusted, private target manifest so the documented unsandboxed opt-in applies
        cleanly even on hosts without working bubblewrap (agents-6qf, coord review finding)."""
        (self.root / "targets").mkdir(exist_ok=True)
        (self.root / "targets" / "target.yaml").write_text(
            f"name: target\npath: {self.target}\ntrusted: true\nvisibility: private\n",
            encoding="utf-8",
        )
        factory_script = self.root / "factory"
        # agents-r2ne census: copies the factory BINARY (a non-station artefact), not station
        # code - the shared station-script builder does not apply.
        shutil.copyfile(ROOT / "factory", factory_script)
        factory_script.chmod(0o755)

        adapter = self.root / "lib" / "adapters" / "pi.sh"
        adapter.write_text(
            "#!/usr/bin/env bash\n"
            "RUN_DIR=\"$4\"\n"
            "mkdir -p \"$RUN_DIR\"\n"
            "echo 'No API key found for the selected model.' > \"$RUN_DIR/model_output.txt\"\n"
            "exit 1\n",
            encoding="utf-8",
        )
        adapter.chmod(adapter.stat().st_mode | stat.S_IEXEC)

        res = subprocess.run(
            [sys.executable, str(factory_script), "run", "a11y-test",
             "--target", "target", "--engine", "pi", "--sink", "file"],
            cwd=str(self.root),
            env=dict(os.environ, FACTORY_ALLOW_UNSANDBOXED="1", ANTHROPIC_API_KEY="dummy"),
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(res.returncode, 2, f"STDOUT: {res.stdout}\nSTDERR: {res.stderr}")
        self.assertIn("[environment failure]", res.stderr)
        self.assertIn("No API key found for the selected model", res.stderr)
        self.assertNotIn("no verdict", res.stderr)

    def test_line_halt_on_failure_true_halts_and_skips_downstream(self):
        """When andon_halt_on_failure is true, an adapter auth failure pulls the Andon cord,
        halts the line, and marks downstream stations as SKIPPED."""
        self._setup_line(halt_on_failure=True)

        adapter = self.root / "lib" / "adapters" / "pi.sh"
        adapter.write_text(
            "#!/usr/bin/env bash\n"
            "RUN_DIR=\"$4\"\n"
            "mkdir -p \"$RUN_DIR\"\n"
            "echo 'No API key found for the selected model.' > \"$RUN_DIR/model_output.txt\"\n"
            "exit 1\n",
            encoding="utf-8",
        )
        adapter.chmod(adapter.stat().st_mode | stat.S_IEXEC)

        stdout_buf = io.StringIO()
        with mock.patch.object(factory_module, "FACTORY_ROOT", self.root), \
             mock.patch.object(factory_module, "sandbox_available", return_value=True), \
             mock.patch.object(factory_module, "sandbox_command", side_effect=lambda cmd, **kw: cmd), \
             contextlib.redirect_stdout(stdout_buf):
            result = run_line("testline", str(self.target), engine_arg="pi", explicit_sink="file")

        output = stdout_buf.getvalue()
        self.assertFalse(result)
        self.assertIn("HALTED", output)
        self.assertIn("ENV_FAILURE", output)
        self.assertIn("SKIPPED", output)
        self.assertIn("next-station", output)


if __name__ == "__main__":
    unittest.main()
