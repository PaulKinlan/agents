#!/usr/bin/env python3
"""Unit tests for the Software Factory core library (findings store, YAML parser, containment)."""

import importlib.machinery
import importlib.util
import os
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from lib.findings import FindingsStore, compute_fingerprint, normalize_text

FACTORY_ROOT = Path(__file__).resolve().parent.parent
loader = importlib.machinery.SourceFileLoader("factory_cli", str(FACTORY_ROOT / "factory"))
spec = importlib.util.spec_from_loader("factory_cli", loader)
factory_cli = importlib.util.module_from_spec(spec)
loader.exec_module(factory_cli)


class TestSoftwareFactoryCore(unittest.TestCase):
    def test_fingerprint_line_number_independence(self):
        """Fingerprints must be identical across line shifts and whitespace reformatting."""
        fp1 = compute_fingerprint("secret-scan", "generic-key", "./src/config.js", "const key = 'abc';")
        fp2 = compute_fingerprint("secret-scan", "generic-key", "src/config.js", "  const   key = 'abc'; \n")
        self.assertEqual(fp1, fp2)

    def test_findings_lifecycle_transitions(self):
        """Verify new -> unchanged -> fixed -> regressed state machine transitions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = FindingsStore("test-target", findings_dir=Path(tmpdir))
            sample = [{
                "rule_id": "xss-sink",
                "path": "app.js",
                "line_number": 10,
                "snippet": "el.innerHTML = user;",
                "severity": "high",
                "title": "DOM XSS"
            }]

            # Run 1: new
            _, stats1, _ = store.process_run("vuln-discovery", sample)
            self.assertEqual(stats1["new"], 1)

            # Run 2: unchanged (even if line_number changes)
            sample[0]["line_number"] = 42
            _, stats2, _ = store.process_run("vuln-discovery", sample)
            self.assertEqual(stats2["unchanged"], 1)
            self.assertEqual(stats2["new"], 0)

            # Run 3: empty findings -> fixed
            _, stats3, fixed = store.process_run("vuln-discovery", [])
            self.assertEqual(stats3["fixed"], 1)
            self.assertEqual(len(fixed), 1)

            # Run 4: reappears -> regressed
            _, stats4, _ = store.process_run("vuln-discovery", sample)
            self.assertEqual(stats4["regressed"], 1)

    def test_indentation_aware_yaml_parser(self):
        """Verify nested maps (schedule:, budget:) and lists parse properly."""
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tf:
            tf.write(
                "name: fauxmium\n"
                "visibility: public\n"
                "agents:\n"
                "  - secret-scan\n"
                "  - test-gap\n"
                "schedule:\n"
                "  secret-scan:\n"
                "    interval: 86400\n"
                "    hour: 7\n"
            )
            tf_path = Path(tf.name)

        try:
            parsed = factory_cli.load_yaml_simple(tf_path)
            self.assertEqual(parsed["name"], "fauxmium")
            self.assertEqual(parsed["agents"], ["secret-scan", "test-gap"])
            self.assertIsInstance(parsed["schedule"], dict)
            self.assertEqual(parsed["schedule"]["secret-scan"]["interval"], 86400)
            self.assertEqual(parsed["schedule"]["secret-scan"]["hour"], 7)
        finally:
            tf_path.unlink(missing_ok=True)


class TestDispatcherBudget(unittest.TestCase):
    """budget.max_minutes is enforced by the dispatcher, not decorative (SF-06)."""

    def test_hung_engine_is_killed_at_the_station_budget(self):
        """A hung engine dies at the declared budget and the station fails.

        Without enforcement this test would sit for the stub's full 60 s and then report a
        clean zero-finding run — the failure mode the audit observed with a stale auth key.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = Path(tmpdir)
            (sandbox / "agents" / "hung").mkdir(parents=True)
            (sandbox / "agents" / "hung" / "agent.yaml").write_text(
                "name: hung\n"
                "class: observer\n"
                "containment: t0-readonly\n"
                "short_circuit_empty: false\n"
                "budget: {max_minutes: 0.05}\n",  # 3 s
                encoding="utf-8",
            )
            (sandbox / "lib" / "adapters").mkdir(parents=True)
            adapter = sandbox / "lib" / "adapters" / "pi.sh"
            shutil.copyfile(FACTORY_ROOT / "lib" / "adapters" / "pi.sh", adapter)
            adapter.chmod(adapter.stat().st_mode | stat.S_IEXEC)
            target = sandbox / "target"
            target.mkdir()
            bindir = sandbox / "bin"
            bindir.mkdir()
            stub = bindir / "pi"
            stub.write_text("#!/usr/bin/env bash\nsleep 60\n", encoding="utf-8")
            stub.chmod(stub.stat().st_mode | stat.S_IEXEC)

            env = dict(os.environ)
            env["PATH"] = f"{bindir}{os.pathsep}{env['PATH']}"
            started = time.monotonic()
            with mock.patch.object(factory_cli, "FACTORY_ROOT", sandbox), \
                 mock.patch.dict(os.environ, env, clear=True):
                with self.assertRaises(factory_cli.StationTimeout) as ctx:
                    factory_cli.run_agent("hung", str(target), engine_arg="pi")
            elapsed = time.monotonic() - started
            self.assertIn("engine 'pi'", str(ctx.exception))
            self.assertIn("station budget", str(ctx.exception))
            self.assertLess(elapsed, 15, "the hung engine was not stopped at its budget")


class TestEngineAdapterAuth(unittest.TestCase):
    """Engine adapters must dispatch on the caller's existing session auth, and must never
    report a run that did not happen. Adapters are exercised against a stub engine binary,
    so these are deterministic — no model call, no API key."""

    def _stub_engine(self, tmp: Path) -> Path:
        """A fake `claude` that records the environment it was launched with."""
        bindir = tmp / "bin"
        bindir.mkdir(exist_ok=True)
        stub = bindir / "claude"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "printf '%s\\n' \"$*\" > \"$FAKE_PROMPT_LOG\"\n"
            "env > \"$FAKE_ENV_LOG\"\n"
            "echo '{\"summary\":\"stub\",\"scanned_files\":0,\"findings\":[]}'\n"
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        return bindir

    def _run_claude_adapter(self, tmp: Path, env_overrides: dict):
        adapter = FACTORY_ROOT / "lib" / "adapters" / "claude.sh"
        run_dir = tmp / "run"
        target = tmp / "target"
        target.mkdir(exist_ok=True)
        env = dict(os.environ)
        env["HOME"] = str(tmp / "home")
        env["FAKE_PROMPT_LOG"] = str(tmp / "prompt.log")
        env["FAKE_ENV_LOG"] = str(tmp / "child-env.log")
        env.update(env_overrides)
        return subprocess.run(
            ["bash", str(adapter), "probe", str(target), str(tmp), "prompt", str(run_dir)],
            capture_output=True, text=True, env=env, timeout=60,
        ), run_dir

    def test_claude_prefers_session_and_scrubs_ambient_api_key(self):
        """A login on disk must win over a stale API key in the caller's environment."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            creds = tmp / "home" / ".claude" / ".credentials.json"
            creds.parent.mkdir(parents=True)
            creds.write_text("{\"stub\":true}")
            bindir = self._stub_engine(tmp)

            res, run_dir = self._run_claude_adapter(tmp, {
                "PATH": f"{bindir}:{os.environ['PATH']}",
                "ANTHROPIC_API_KEY": "sk-ant-stale-key",
            })

            self.assertEqual(res.returncode, 0, res.stderr)
            child_env = (tmp / "child-env.log").read_text()
            self.assertNotIn("ANTHROPIC_API_KEY=", child_env)
            self.assertTrue((run_dir / "model_output.txt").exists())

    def test_claude_keeps_api_key_without_a_session(self):
        """The CI plane authenticates by injected API key and has no login on disk."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            bindir = self._stub_engine(tmp)

            res, _ = self._run_claude_adapter(tmp, {
                "PATH": f"{bindir}:{os.environ['PATH']}",
                "ANTHROPIC_API_KEY": "sk-ant-ci-key",
            })

            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("ANTHROPIC_API_KEY=sk-ant-ci-key", (tmp / "child-env.log").read_text())

    def test_claude_fails_fast_with_no_credentials_at_all(self):
        """No login and no key is an error before any engine invocation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            bindir = self._stub_engine(tmp)

            res, run_dir = self._run_claude_adapter(tmp, {
                "PATH": f"{bindir}:{os.environ['PATH']}",
                "ANTHROPIC_API_KEY": "",
                "ANTHROPIC_AUTH_TOKEN": "",
            })

            self.assertEqual(res.returncode, 1)
            self.assertIn("no Claude credentials", res.stderr)
            self.assertFalse((tmp / "child-env.log").exists(), "engine must not be invoked")
            self.assertFalse((run_dir / "model_output.txt").exists())

    @unittest.skipIf(shutil.which("agentapi"), "agentapi installed; missing-binary path not reachable")
    def test_antigravity_fails_loudly_when_agentapi_is_missing(self):
        """A missing engine must abort the run, never write a placeholder the dispatcher
        would then store as a clean, zero-finding report."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            run_dir = tmp / "run"
            adapter = FACTORY_ROOT / "lib" / "adapters" / "antigravity.sh"
            env = dict(os.environ)
            env["PATH"] = "/usr/bin:/bin"

            res = subprocess.run(
                ["bash", str(adapter), "probe", str(tmp), str(tmp), "prompt", str(run_dir)],
                capture_output=True, text=True, env=env, timeout=60,
            )

            self.assertEqual(res.returncode, 1)
            self.assertIn("agentapi", res.stderr)
            self.assertFalse((run_dir / "model_output.txt").exists())


if __name__ == "__main__":
    unittest.main()
