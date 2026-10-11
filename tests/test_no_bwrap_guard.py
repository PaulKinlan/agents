#!/usr/bin/env python3
"""A local-green host must also exercise the no-bubblewrap CI contract (agents-6qf)."""

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

# --- hermetic test environment (agents-21ap) -------------------------------------------------
# The pin machinery resolves tools through FACTORY_TOOL_PINS when the OPERATOR'S shell exports
# it (~/.fleet/local.conf does on this VM). Without this scrub the suite observed the host
# rather than the tree: a re-provision generated the host pins file at 02:19:46Z and these
# suites went red on EVERY tree, including landed main, with `trusted tool 'pi' resolved to
# /tmp/.../bin/pi, not the configured path /usr/local/bin/pi`. The tests were right; the
# environment was not hermetic. See tests/hermetic_env.py.
from tests import hermetic_env  # noqa: E402


def setUpModule():
    hermetic_env.isolate_operator_config()


def tearDownModule():
    hermetic_env.restore_operator_config()


ROOT = Path(__file__).resolve().parent.parent


class TestNoBubblewrapGuard(unittest.TestCase):
    def test_refusal_runs_while_successful_engine_tests_honestly_skip(self):
        """A failing bwrap executable must never turn refusal into an opt-in or a skip.

        Spawn a fresh interpreter so sandbox_available() cannot reuse a cached probe from
        this process. The budget test needs a real sandbox and must skip; the explicit
        no-sandbox refusal test must RUN and pass. This guard runs on both local bwrap
        hosts and GitHub runners, where user namespaces may be disabled.
        """
        with tempfile.TemporaryDirectory(prefix="factory-no-bwrap-guard-") as tmp:
            stub = Path(tmp) / "bwrap"
            stub.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            stub.chmod(0o755)
            env = os.environ.copy()
            env["PATH"] = f"{tmp}{os.pathsep}{env.get('PATH', '')}"
            env.pop("FACTORY_ALLOW_UNSANDBOXED", None)
            program = textwrap.dedent("""
                import json
                import unittest
                from lib.sandbox import sandbox_available

                ids = (
                    'tests.test_containment.TestDispatcher.test_a_pi_run_is_refused_when_the_sandbox_cannot_run',
                    'tests.test_factory_core.TestDispatcherBudget.test_hung_engine_is_killed_at_the_station_budget',
                )
                result = unittest.TestResult()
                unittest.TestLoader().loadTestsFromNames(ids).run(result)
                print(json.dumps({
                    'sandbox_available': sandbox_available(),
                    'ran': result.testsRun,
                    'skipped': [t.id() for t, _ in result.skipped],
                    'failures': len(result.failures),
                    'errors': len(result.errors),
                }))
            """)
            proc = subprocess.run([sys.executable, "-c", program], cwd=ROOT, env=env,
                                  capture_output=True, text=True, timeout=60)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            result = json.loads(proc.stdout.splitlines()[-1])
            self.assertFalse(result["sandbox_available"], "the stub must defeat the real probe")
            self.assertEqual(result["ran"], 2)
            self.assertEqual(result["failures"], 0, proc.stdout + proc.stderr)
            self.assertEqual(result["errors"], 0, proc.stdout + proc.stderr)
            self.assertEqual(result["skipped"], [
                "tests.test_factory_core.TestDispatcherBudget."
                "test_hung_engine_is_killed_at_the_station_budget"
            ], "only the successful engine run may skip; refusal must execute")


if __name__ == "__main__":
    unittest.main()
