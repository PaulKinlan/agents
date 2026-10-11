#!/usr/bin/env python3
"""Acceptance test for centralized hermetic test environment declaration (agents-v1a2).

Proves that test execution is hermetic at the gate and package level:
any test module (including newly added modules that do not define setUpModule/tearDownModule)
executes in an environment free from ambient operator host pins files.
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from lib.tool_pins import resolve_tool

ROOT = Path(__file__).resolve().parent.parent


class TestHermeticEnvironmentDeclaration(unittest.TestCase):
    def test_package_init_isolates_operator_config(self):
        """tests/__init__.py must ensure FACTORY_TOOL_PINS is unset and FACTORY_ALLOW_UNPINNED_TOOLS=1."""
        self.assertNotIn("FACTORY_TOOL_PINS", os.environ,
                         "tests/__init__.py must scrub ambient FACTORY_TOOL_PINS")
        self.assertEqual(os.environ.get("FACTORY_ALLOW_UNPINNED_TOOLS"), "1",
                         "tests/__init__.py must establish dev/test opt-in")

    def test_unscrubbed_module_resolves_synthetic_tool_under_host_pins(self):
        """Acceptance test (agents-v1a2 requirement 2):
        A test module that does NOT scrub or define setUpModule/tearDownModule must still
        pass and resolve synthetic tools on PATH, even when FACTORY_TOOL_PINS is exported
        in the parent process environment pointing to an active host pins file.
        """
        host_pins = Path.home() / ".config" / "factory" / "tools.pins.yaml"
        if not host_pins.exists():
            self.skipTest(f"Host pins file {host_pins} not present on this VM")

        with tempfile.TemporaryDirectory(prefix="unscrubbed-test-") as tmp:
            fakebin = Path(tmp) / "bin"
            fakebin.mkdir()
            fakepi = fakebin / "pi"
            fakepi.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fakepi.chmod(0o755)

            # Test code does NOT import hermetic_env and does NOT define setUpModule
            test_script = (
                "import os, unittest\n"
                "from pathlib import Path\n"
                "from lib.tool_pins import resolve_tool\n"
                "class TestSynthetic(unittest.TestCase):\n"
                "    def test_resolve(self):\n"
                f"        os.environ['PATH'] = '{fakebin}:' + os.environ['PATH']\n"
                "        resolved = resolve_tool('pi')\n"
                f"        self.assertEqual(str(resolved), '{fakepi}')\n"
            )
            test_file = ROOT / "tests" / "test__hermetic_sentinel_tmp.py"
            test_file.write_text(test_script, encoding="utf-8")
            try:
                env = dict(os.environ)
                # Export the operator host pins file to simulate ambient environment
                env["FACTORY_TOOL_PINS"] = str(host_pins)
                env.pop("FACTORY_ALLOW_UNPINNED_TOOLS", None)

                # Run through the tests package via unittest
                res = subprocess.run([sys.executable, "-m", "unittest", "tests.test__hermetic_sentinel_tmp"],
                                     cwd=ROOT, env=env, capture_output=True, text=True)
                self.assertEqual(res.returncode, 0,
                                 f"Unscrubbed module failed under host pins:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")
            finally:
                test_file.unlink(missing_ok=True)

    def test_package_aware_discovery_under_ambient_host_pins(self):
        """Full gate package-aware discovery (`-s tests -t .`) runs hermetically under host pins."""
        host_pins = Path.home() / ".config" / "factory" / "tools.pins.yaml"
        if not host_pins.exists():
            self.skipTest(f"Host pins file {host_pins} not present on this VM")

        env = dict(os.environ)
        env["FACTORY_TOOL_PINS"] = str(host_pins)
        env.pop("FACTORY_ALLOW_UNPINNED_TOOLS", None)

        res = subprocess.run([sys.executable, "-m", "unittest", "discover",
                              "-s", "tests", "-t", ".", "-p", "test_sandbox.py"],
                             cwd=ROOT, env=env, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0,
                         f"Package-aware discovery failed under ambient host pins:\nSTDERR:\n{res.stderr}")

    def test_full_gate_invocation_with_env_scrub_under_ambient_host_pins(self):
        """Full-gate command declared for check.conf (`env -u FACTORY_TOOL_PINS FACTORY_ALLOW_UNPINNED_TOOLS=1 ...`)
        succeeds even under discover -s tests without package awareness."""
        host_pins = Path.home() / ".config" / "factory" / "tools.pins.yaml"
        if not host_pins.exists():
            self.skipTest(f"Host pins file {host_pins} not present on this VM")

        env = dict(os.environ)
        env["FACTORY_TOOL_PINS"] = str(host_pins)
        env.pop("FACTORY_ALLOW_UNPINNED_TOOLS", None)

        full_gate_cmd = (
            f"env -u FACTORY_TOOL_PINS FACTORY_ALLOW_UNPINNED_TOOLS=1 "
            f"{sys.executable} -m unittest discover -s tests -p test_sandbox.py"
        )
        res = subprocess.run(["bash", "-c", full_gate_cmd],
                             cwd=ROOT, env=env, capture_output=True, text=True)
        self.assertEqual(res.returncode, 0,
                         f"Full-gate command failed under ambient host pins:\nSTDERR:\n{res.stderr}")

    def test_fast_gate_runner_unsets_host_pins_for_child_suites(self):
        """tools/fast-gate.sh must unset FACTORY_TOOL_PINS and export FACTORY_ALLOW_UNPINNED_TOOLS=1
        for all invoked child test subprocesses (review finding P2)."""
        probe = ROOT / "tests" / "test__probe_fast_gate_env_tmp.py"
        probe.write_text(
            "import os, unittest\n"
            "class TestEnv(unittest.TestCase):\n"
            "    def test_runner_environment(self):\n"
            "        self.assertNotIn('FACTORY_TOOL_PINS', os.environ)\n"
            "        self.assertEqual(os.environ.get('FACTORY_ALLOW_UNPINNED_TOOLS'), '1')\n",
            encoding="utf-8"
        )
        try:
            env = dict(os.environ)
            env["FACTORY_TOOL_PINS"] = "/tmp/host-pins-probe.yaml"
            env.pop("FACTORY_ALLOW_UNPINNED_TOOLS", None)
            env["GIT_CHANGED"] = "tests/test__probe_fast_gate_env_tmp.py"

            res = subprocess.run(["bash", "tools/fast-gate.sh"],
                                 cwd=ROOT, env=env, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0,
                             f"fast-gate.sh failed to execute child suite:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")
            self.assertIn("tests/test__probe_fast_gate_env_tmp.py", res.stdout)
        finally:
            probe.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
