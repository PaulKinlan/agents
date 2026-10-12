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
        # agents-3cm4: assert on key presence only; never assertNotIn(k, os.environ)
        # which dumps the entire host environment and ambient credentials on failure.
        self.assertFalse("FACTORY_TOOL_PINS" in os.environ,
                         "tests/__init__.py must scrub ambient FACTORY_TOOL_PINS")
        self.assertEqual(os.environ.get("FACTORY_ALLOW_UNPINNED_TOOLS"), "1",
                         "tests/__init__.py must establish dev/test opt-in")

    def test_the_fast_gate_does_not_scrub_its_callers_environment(self):
        """agents-u4k7: hermeticity must come from THIS declaration, not from the gate's shell.

        The gate used to run ``unset FACTORY_TOOL_PINS`` plus ``export
        FACTORY_ALLOW_UNPINNED_TOOLS=1`` before unittest. That made a green fast gate evidence
        about the CALLER's shell rather than about this declaration - MEASURED: with the scrub in
        place, making this package's declaration inert left ``tests/test_sandbox.py`` at "Ran 64
        tests ... OK" (rc=0), so the gate could not report that the declaration was broken.
        The deployed full gate (``python3 -m unittest discover -s tests -t . -v``) scrubs nothing
        and relies on this declaration, so the fast gate must match it or the two gates are
        evidence about different environments.

        Both halves are asserted: the scrub statements are ABSENT from the gate, and the gate
        STATES the environment policy in its output - checked through the real script with
        FAST_GATE_DRY_RUN, which exits before running any suite, so this costs no test time.
        """
        gate_path = ROOT / "tools" / "fast-gate.sh"
        gate = gate_path.read_text()
        # COMMENTS MAY QUOTE THE OLD LINES; the assertion is about EXECUTABLE code, because a
        # note explaining why the scrub was removed must be able to name the scrub it removed.
        code = "\n".join(
            line for line in gate.splitlines() if not line.lstrip().startswith("#"))
        self.assertNotIn("unset FACTORY_TOOL_PINS", code,
                         "the fast gate must not scrub the caller's FACTORY_TOOL_PINS")
        self.assertNotIn("export FACTORY_ALLOW_UNPINNED_TOOLS", code,
                         "the fast gate must not export the dev/test opt-in")
        res = subprocess.run(
            ["bash", str(gate_path)], cwd=str(ROOT),
            env={**os.environ, "FAST_GATE_DRY_RUN": "1",
                 "GIT_CHANGED": "tests/test_hermetic_env.py"},
            capture_output=True, text=True, timeout=120)
        # STDERR, AND THAT IS THE POINT (caught by tests/test_fast_gate_mapping.py, which is in
        # this gate's own arm): the gate's STDOUT is a machine-readable contract - the dry run IS
        # the suite list, asserted EMPTY for an ignored path or an empty delta (agents-9nir). My
        # first version printed this on stdout and made that suite fail with 7 failures.
        self.assertIn("environment: the caller's, unmodified", res.stderr,
                      f"the gate must say which environment its verdict is about: {res.stderr!r}")
        self.assertIn("isolate_operator_config", res.stderr,
                      "the gate must name the declaration that supplies hermeticity")
        self.assertEqual(res.stdout.strip(), "tests/test_hermetic_env.py",
                         "stdout stays the machine-readable suite list")
        self.assertEqual(res.returncode, 0, res.stderr)

    def test_assertion_failure_does_not_leak_ambient_environment_values(self):
        """agents-3cm4: when hermetic assertions fail, they must assert on key presence only
        and never format the surrounding environment dictionary or ambient secrets into the message."""
        fake_secret = "npm_test_secret_token_never_leak_xyz"
        test_case = TestHermeticEnvironmentDeclaration()
        prev_pins = os.environ.get("FACTORY_TOOL_PINS")
        prev_npm = os.environ.get("NPM_TOKEN")
        try:
            os.environ["FACTORY_TOOL_PINS"] = "/tmp/bad-pins.yaml"
            os.environ["NPM_TOKEN"] = fake_secret
            with self.assertRaises(AssertionError) as ctx:
                test_case.test_package_init_isolates_operator_config()
            err_msg = str(ctx.exception)
            self.assertNotIn(fake_secret, err_msg, "assertion message leaked ambient credential value!")
            self.assertNotIn("NPM_TOKEN", err_msg, "assertion message leaked ambient environment keys!")
            self.assertIn("FACTORY_TOOL_PINS", err_msg, "assertion message must name the offending key")
        finally:
            if prev_pins is None:
                os.environ.pop("FACTORY_TOOL_PINS", None)
            else:
                os.environ["FACTORY_TOOL_PINS"] = prev_pins
            if prev_npm is None:
                os.environ.pop("NPM_TOKEN", None)
            else:
                os.environ["NPM_TOKEN"] = prev_npm

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
            "        self.assertFalse('FACTORY_TOOL_PINS' in os.environ, 'ambient FACTORY_TOOL_PINS must be scrubbed')\n"
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
