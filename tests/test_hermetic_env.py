#!/usr/bin/env python3
"""Acceptance test for centralized hermetic test environment declaration (agents-v1a2).

Proves that test execution is hermetic at the gate and package level:
any test module (including newly added modules that do not define setUpModule/tearDownModule)
executes in an environment free from ambient operator host pins files.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from lib.tool_pins import resolve_tool

ROOT = Path(__file__).resolve().parent.parent


def _isolated_test_package(test_dir):
    """Run the actual package declaration without planting a suite in the checkout.

    A test killed before finally cannot clean up a file under ROOT/tests; keeping the
    package and its probes in a temporary tree makes that interruption harmless to git.
    """
    test_dir.mkdir(parents=True)
    for name in ("__init__.py", "hermetic_env.py"):
        shutil.copy2(ROOT / "tests" / name, test_dir / name)


def _ambient_pins_probe(isolated):
    """Use a real pin-sensitive child, not the host's file or a passing unrelated suite."""
    tests = isolated / "tests"
    _isolated_test_package(tests)
    fakebin = isolated / "bin"
    fakebin.mkdir()
    fakepi = fakebin / "pi"
    fakepi.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fakepi.chmod(0o755)
    pins = isolated / "synthetic-tools.pins.yaml"
    pins.write_text("pi:\n  sha256: " + "0" * 64 + "\n", encoding="utf-8")
    # The ambient-name fallback is reached only after configure_host_pins(None).
    # Without that call, even an existing FACTORY_TOOL_PINS is ignored by fresh
    # unittest children; the former test_sandbox.py discovery was not discriminating.
    (tests / "test__ambient_pins_probe_tmp.py").write_text(
        "import os, unittest\n"
        "from lib.tool_pins import configure_host_pins, resolve_tool\n"
        "configure_host_pins(None)\n"
        "class TestAmbientPin(unittest.TestCase):\n"
        "    def test_resolve(self):\n"
        "        resolved = resolve_tool('pi')\n"
        "        self.assertFalse('FACTORY_TOOL_PINS' in os.environ)\n"
        "        self.assertEqual(os.environ.get('FACTORY_ALLOW_UNPINNED_TOOLS'), '1')\n"
        f"        self.assertEqual(str(resolved), {str(fakepi)!r})\n",
        encoding="utf-8",
    )
    env = dict(os.environ)
    env["FACTORY_TOOL_PINS"] = str(pins)
    env.pop("FACTORY_ALLOW_UNPINNED_TOOLS", None)
    env["PATH"] = f"{fakebin}{os.pathsep}{env.get('PATH', '')}"
    env["PYTHONPATH"] = os.pathsep.join((str(isolated), str(ROOT), env.get("PYTHONPATH", "")))
    env["HOME"] = str(isolated)  # Do not consult another host pin through the default home.
    return tests, env


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
        # agents-h17y / agents-i2sx: this test is about the gate NOT scrubbing its caller's
        # environment, and the dry-run stdout is only the PROBE that makes the run observable - so
        # the expectation states the CONTRACT rather than freezing one filename. Arms legitimately
        # widen the resolution (this one gained the completeness guard), and such a widening must
        # not break an assertion about the environment. The resolution must therefore be a non-empty,
        # sorted, unique list of test module paths that names the file which changed.
        # The EXACT list is pinned where exactness IS the contract, in tests/test_fast_gate_mapping.py.
        resolved = res.stdout.strip().splitlines()
        self.assertTrue(resolved, "the dry run must print the resolution, not nothing at all")
        for line in resolved:
            self.assertRegex(line, r"^tests/[A-Za-z0-9_/]+\.py$",
                             "stdout is the machine-readable suite list: one module path per line, no prose")
        self.assertEqual(sorted(set(resolved)), resolved,
                         "the resolution is sorted and free of duplicates")
        self.assertIn("tests/test_hermetic_env.py", resolved,
                      "the file that changed must appear in its own arm's resolution")
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
        in the parent environment pointing to a synthetic ambient pins path. No real
        host pins or credentials are needed for this test.
        """
        with tempfile.TemporaryDirectory(prefix="unscrubbed-test-") as tmp:
            isolated = Path(tmp)
            _isolated_test_package(isolated / "tests")
            fakebin = isolated / "bin"
            fakebin.mkdir()
            fakepi = fakebin / "pi"
            fakepi.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fakepi.chmod(0o755)

            # Test code does NOT import hermetic_env and does NOT define setUpModule.
            # Its temporary tests package runs a copy of the REAL package declaration.
            test_script = (
                "import os, unittest\n"
                "from lib.tool_pins import resolve_tool\n"
                "class TestSynthetic(unittest.TestCase):\n"
                "    def test_resolve(self):\n"
                "        self.assertFalse('FACTORY_TOOL_PINS' in os.environ)\n"
                "        self.assertEqual(os.environ.get('FACTORY_ALLOW_UNPINNED_TOOLS'), '1')\n"
                "        resolved = resolve_tool('pi')\n"
                f"        self.assertEqual(str(resolved), {str(fakepi)!r})\n"
            )
            (isolated / "tests" / "test__hermetic_sentinel_tmp.py").write_text(test_script, encoding="utf-8")
            env = dict(os.environ)
            # A synthetic ambient pin tests the declaration on hosts with no real pins, too.
            env["FACTORY_TOOL_PINS"] = str(isolated / "ambient-tools.pins.yaml")
            env.pop("FACTORY_ALLOW_UNPINNED_TOOLS", None)
            env["PATH"] = f"{fakebin}{os.pathsep}{env.get('PATH', '')}"
            env["PYTHONPATH"] = os.pathsep.join((str(isolated), str(ROOT), env.get("PYTHONPATH", "")))

            res = subprocess.run([sys.executable, "-m", "unittest", "tests.test__hermetic_sentinel_tmp"],
                                 cwd=isolated, env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(res.returncode, 0,
                             f"Synthetic module failed under ambient pins:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")

    def test_package_aware_discovery_under_ambient_host_pins(self):
        """The real package-aware command scrubs a synthetic, mismatched ambient pin."""
        with tempfile.TemporaryDirectory(prefix="ambient-pins-discovery-") as tmp:
            isolated = Path(tmp)
            tests, env = _ambient_pins_probe(isolated)
            command = [sys.executable, "-m", "unittest", "discover",
                       "-s", "tests", "-t", ".", "-p", "test__ambient_pins_probe_tmp.py"]
            res = subprocess.run(command, cwd=isolated, env=env, capture_output=True,
                                 text=True, timeout=30)
            self.assertEqual(res.returncode, 0,
                             f"Package-aware discovery failed under synthetic ambient pins:\nSTDERR:\n{res.stderr}")
            # Prove it was the package declaration, not a tool that ignored the pin.
            (tests / "__init__.py").write_text("# inert declaration\n", encoding="utf-8")
            broken = subprocess.run(command, cwd=isolated, env=env, capture_output=True,
                                    text=True, timeout=30)
            self.assertNotEqual(broken.returncode, 0, "an inert package must expose the ambient pin")
            self.assertIn("not the configured pin", broken.stderr)

    def test_full_gate_invocation_with_env_scrub_under_ambient_host_pins(self):
        """The real package-blind full-gate command scrubs a synthetic ambient pin."""
        with tempfile.TemporaryDirectory(prefix="ambient-pins-full-gate-") as tmp:
            isolated = Path(tmp)
            _, env = _ambient_pins_probe(isolated)
            command = [sys.executable, "-m", "unittest", "discover",
                       "-s", "tests", "-p", "test__ambient_pins_probe_tmp.py"]
            scrubbed = subprocess.run(["env", "-u", "FACTORY_TOOL_PINS",
                                     "FACTORY_ALLOW_UNPINNED_TOOLS=1", *command],
                                    cwd=isolated, env=env, capture_output=True, text=True, timeout=30)
            self.assertEqual(scrubbed.returncode, 0,
                             f"Full-gate command failed under synthetic ambient pins:\nSTDERR:\n{scrubbed.stderr}")
            # Without the full gate's env -u, the package-blind invocation sees the
            # mismatched ambient content pin even though the opt-out is set.
            broken = subprocess.run(["env", "FACTORY_ALLOW_UNPINNED_TOOLS=1", *command],
                                    cwd=isolated, env=env, capture_output=True, text=True, timeout=30)
            self.assertNotEqual(broken.returncode, 0, "removing env -u must expose the ambient pin")
            self.assertIn("not the configured pin", broken.stderr)

    def test_fast_gate_runner_unsets_host_pins_for_child_suites(self):
        """The real gate preserves ambient pins; its child test PACKAGE must scrub them.

        Run the gate and arm registry in a temporary tree, with only the package
        declaration and a testable child; the always-on suites are stubs because
        this checks environment plumbing, not their separate coverage contracts.
        An inert package must make the same gate RED: the gate cannot hide a
        broken declaration by scrubbing the caller's environment itself.
        """
        with tempfile.TemporaryDirectory(prefix="fast-gate-child-env-") as tmp:
            isolated = Path(tmp)
            tools = isolated / "tools"
            tools.mkdir()
            shutil.copy2(ROOT / "tools" / "fast-gate.sh", tools / "fast-gate.sh")
            shutil.copytree(ROOT / "tools" / "fast-gate-arms.d", tools / "fast-gate-arms.d")
            tests = isolated / "tests"
            _isolated_test_package(tests)
            probe_name = "tests/test__probe_fast_gate_env_tmp.py"
            (isolated / probe_name).write_text(
                "import os, unittest\n"
                "class TestEnv(unittest.TestCase):\n"
                "    def test_runner_environment(self):\n"
                "        self.assertFalse('FACTORY_TOOL_PINS' in os.environ, 'ambient FACTORY_TOOL_PINS must be scrubbed')\n"
                "        self.assertEqual(os.environ.get('FACTORY_ALLOW_UNPINNED_TOOLS'), '1')\n",
                encoding="utf-8"
            )
            env = dict(os.environ)
            env["FACTORY_TOOL_PINS"] = str(isolated / "ambient-tools.pins.yaml")
            env.pop("FACTORY_ALLOW_UNPINNED_TOOLS", None)
            env.pop("FAST_GATE_DRY_RUN", None)
            env["FLEET_CHECKS_DIR"] = str(isolated / "checks")
            env["GIT_CHANGED"] = probe_name

            # Ask the REAL copied gate which suites it will execute, then stub only
            # suites absent from this tiny fixture. A new always-on tier or arm mapping
            # must not require updating an unrelated environment-plumbing test.
            dry_run = subprocess.run(["bash", "tools/fast-gate.sh"], cwd=isolated,
                                     env={**env, "FAST_GATE_DRY_RUN": "1"},
                                     capture_output=True, text=True, timeout=30)
            self.assertEqual(dry_run.returncode, 0, dry_run.stderr)
            resolved = dry_run.stdout.strip().splitlines()
            self.assertIn(probe_name, resolved, "the real gate must select the environment probe")
            self.assertEqual(sorted(set(resolved)), resolved, "the gate must return distinct, sorted suites")
            for name in resolved:
                self.assertRegex(name, r"^tests/(?:[A-Za-z0-9_]+/)*test_[A-Za-z0-9_]+\.py$",
                                 "only test modules inside the isolated tree may be stubbed")
                stub = isolated / name
                if stub.is_file():
                    continue  # Never overwrite a real suite, especially the environment probe.
                parent = stub.parent
                while parent != tests:
                    parent.mkdir(parents=True, exist_ok=True)
                    (parent / "__init__.py").touch(exist_ok=True)
                    parent = parent.parent
                stub.write_text("import unittest\nclass Stub(unittest.TestCase):\n    def test_stub(self): pass\n",
                                encoding="utf-8")

            res = subprocess.run(["bash", "tools/fast-gate.sh"], cwd=isolated, env=env,
                                 capture_output=True, text=True, timeout=30)
            self.assertEqual(res.returncode, 0,
                             f"fast-gate.sh failed to execute child suite:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")
            passed = [line.removeprefix("fast-gate: passed: ").split()
                      for line in res.stdout.splitlines() if line.startswith("fast-gate: passed: ")]
            self.assertEqual(passed, [resolved], "the real runner must report every resolved suite as passed")

            # Mutation control: if the package stops scrubbing, the gate itself
            # must not make the test green. No real source or host config is edited.
            (tests / "__init__.py").write_text("# inert test declaration\n", encoding="utf-8")
            broken = subprocess.run(["bash", "tools/fast-gate.sh"], cwd=isolated, env=env,
                                    capture_output=True, text=True, timeout=30)
            self.assertNotEqual(broken.returncode, 0,
                                "an inert test declaration must fail through the unmodified gate")
            self.assertIn("FACTORY_TOOL_PINS", broken.stdout + broken.stderr)


if __name__ == "__main__":
    unittest.main()
