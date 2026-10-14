"""Drive the real full-gate entrypoint against isolated, tiny unittest packages."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class TestFullGateSharding(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=self.root, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=self.root, check=True)
        (self.root / "tools").mkdir()
        (self.root / "tests").mkdir()
        (self.root / "checks").mkdir()
        (self.root / "tests" / "__init__.py").write_text("")
        shutil.copy2(ROOT / "tools" / "full-gate.sh", self.root / "tools" / "full-gate.sh")
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)

    def module(self, name, body):
        p = self.root / "tests" / f"test_{name}.py"
        p.write_text(
            "import os, time, unittest\nclass Case(unittest.TestCase):\n" + body,
            encoding="utf-8")
        subprocess.run(["git", "add", str(p)], cwd=self.root, check=True)

    def run_gate(self, *args, **settings):
        env = dict(os.environ, FLEET_CHECKS_DIR=str(self.root / "checks"),
                   FULL_GATE_SHARDS="2", FULL_GATE_BUDGET_S="20")
        # The nested gate must not inherit the PARENT gate's shard-child marker: with it set, the
        # child behaves as a shard, skips the serial-only test this case constructs deliberately,
        # and exits 0 - which is exactly the assertion below failing for the wrong reason.
        env.pop("FULL_GATE_SHARD_CHILD", None)
        env.update(settings)
        return subprocess.run(["bash", str(self.root / "tools" / "full-gate.sh"), *args],
                              cwd=self.root, env=env, capture_output=True, text=True,
                              timeout=25, check=False)

    def test_exact_union_and_measured_cost_cache(self):
        self.module("a", " def test_one(self): time.sleep(.05)\n")
        self.module("b", " def test_two(self): self.assertTrue(True)\n")
        res = self.run_gate()
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("executed ids=2 expected=2 missing=0 extra=0 duplicate=0", res.stdout)
        self.assertIn("full-gate: passed", res.stdout)
        costs = json.loads((self.root / "checks" / "full-gate-module-costs.json").read_text())
        self.assertEqual(set(costs["seconds"]), {"tests.test_a", "tests.test_b"})
        self.assertGreater(costs["seconds"]["tests.test_a"], 0)
        self.assertEqual(len(list((self.root / "checks").glob("*.summary.txt"))), 1)
        self.assertIn("full-gate run: tree=", next((self.root / "checks").glob("*.summary.txt")).read_text())

    def test_docstring_and_plain_test_ids_are_both_counted(self):
        self.module("described", ' def test_described(self):\n  """A description printed on the next line."""\n  pass\n'
                                 ' def test_plain(self): pass\n')
        res = self.run_gate()
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("executed ids=2 expected=2 missing=0 extra=0 duplicate=0", res.stdout)
        self.assertIn("tests.test_described.Case.test_described", res.stdout)
        self.assertIn("module=tests.test_described", res.stdout)

    def test_serial_default_pattern_includes_test_without_underscore(self):
        p = self.root / "tests" / "testextra.py"
        p.write_text(
            "import unittest\nclass Case(unittest.TestCase):\n"
            " def test_extra(self): pass\n", encoding="utf-8")
        subprocess.run(["git", "add", str(p)], cwd=self.root, check=True)
        res = self.run_gate()
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("executed ids=1 expected=1", res.stdout)
        self.assertIn("module=tests.testextra", res.stdout)

    def test_failing_module_is_named_and_fails_the_gate(self):
        self.module("a", " def test_ok(self): pass\n")
        self.module("bad", " def test_bad(self): self.fail('injected red')\n")
        res = self.run_gate()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("failing modules: tests.test_bad", res.stdout)
        self.assertIn("injected red", res.stdout)
        self.assertIn("executed ids=2 expected=2", res.stdout)

    def test_silent_child_omission_refuses_even_with_zero_exit(self):
        """A nested run that exits 0 because it swallowed a module must be refused, and say why.

        The DIAGNOSIS is asserted before the exit status (agents-ou2p): when the nested gate wrongly
        exits 0 it is this case's id-set check that knows the difference, and asserting the return
        code first made the failure read 'AssertionError: 0 == 0' - which names neither the
        condition that failed nor the likely cause.
        """
        self.module("a", " def test_one(self): pass\n"
                         " if os.getenv('FULL_GATE_SHARD_CHILD') != '1':\n"
                         "  def test_only_in_serial(self): pass\n")
        res = self.run_gate()
        self.assertIn(
            "ID SET MISMATCH", res.stdout,
            "no id-set mismatch in the gate output - the nested run most likely inherited the "
            "shard marker and never ran the serial-only test:\n" + res.stdout + res.stderr)
        self.assertIn("tests.test_a.Case.test_only_in_serial", res.stdout, res.stdout + res.stderr)
        self.assertIn("failing modules: tests.test_a", res.stdout, res.stdout + res.stderr)
        self.assertNotEqual(
            res.returncode, 0,
            "the nested gate exited 0 despite reporting the id-set mismatch and the failing "
            "module above, so the refusal under test is missing:\n" + res.stdout + res.stderr)

    def test_nested_gate_ignores_outer_shard_marker_for_serial_discovery(self):
        self.module("nested", " def test_one(self): pass\n"
                              " if os.getenv('FULL_GATE_SHARD_CHILD') != '1':\n"
                              "  def test_only_in_serial(self): pass\n")
        res = self.run_gate(FULL_GATE_SHARD_CHILD="1")
        self.assertNotEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("executed ids=1 expected=2 missing=1", res.stdout)
        self.assertIn("ID SET MISMATCH", res.stdout)
        self.assertIn("tests.test_nested.Case.test_only_in_serial", res.stdout)

    def test_module_import_failure_is_not_mistaken_for_zero_tests(self):
        p = self.root / "tests" / "test_bad.py"
        p.write_text("raise RuntimeError('injected import failure')\n")
        subprocess.run(["git", "add", str(p)], cwd=self.root, check=True)
        res = self.run_gate()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("serial discovery failed", res.stdout)
        self.assertIn("injected import failure", res.stdout)

    def test_untracked_debris_is_not_absorbed_by_full_gate(self):
        """A check must read git's objects rather than the filesystem (agents-jcd2).

        Untracked test debris in tests/ left by an interrupted run must not be absorbed
        or executed by serial discovery in the full gate.
        """
        self.module("tracked", " def test_ok(self): pass\n")
        debris = self.root / "tests" / "test_zz_debris_probe_tmp.py"
        debris.write_text(
            "import unittest\nclass Case(unittest.TestCase):\n def test_debris(self): pass\n",
            encoding="utf-8")
        res = self.run_gate()
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("executed ids=1 expected=1 missing=0 extra=0 duplicate=0", res.stdout)
        self.assertNotIn("test_zz_debris_probe_tmp", res.stdout)

    def test_over_budget_is_not_a_pass(self):
        self.module("slow", " def test_one(self): time.sleep(1.1)\n")
        res = self.run_gate(FULL_GATE_BUDGET_S="1")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("OVER BUDGET", res.stdout)
        self.assertIn("full-gate: failed", res.stdout)

    def test_invalid_cost_cache_cannot_make_a_false_green(self):
        self.module("a", " def test_one(self): pass\n")
        (self.root / "checks" / "full-gate-module-costs.json").write_text("not json")
        res = self.run_gate()
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("executed ids=1 expected=1", res.stdout)

    def test_unknown_filter_argument_cannot_narrow_the_full_gate(self):
        self.module("a", " def test_one(self): pass\n")
        res = self.run_gate("-p", "test_a.py")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("unsupported full-gate arguments", res.stdout)
        self.assertNotIn("module=tests.test_a", res.stdout)

    def test_invalid_parallelism_refuses_before_running_tests(self):
        self.module("a", " def test_one(self): pass\n")
        res = self.run_gate(FULL_GATE_SHARDS="0")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("FULL_GATE_SHARDS must be a positive integer", res.stdout)


if __name__ == "__main__":
    unittest.main()
