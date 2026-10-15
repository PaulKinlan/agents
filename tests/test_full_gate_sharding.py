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
        """RE-PINNED BY agents-vuvrm, deliberately and loudly: this case's subject is still
        'an over-budget run is not a pass', and its two load-bearing assertions are UNCHANGED -
        the exit status is non-zero, and the gate still says OVER BUDGET. What changed is the
        RENDERING it used to pin: 'full-gate: failed'. That reading is the defect agents-vuvrm
        fixes, because an over-budget run with expected==executed and zero failures is a
        machine-state fact, not a content regression, and calling it 'failed' sends the reader to
        look for an assertion that does not exist. A complete run over the wall is now its own
        state with its own exit code (3), so the second assertion is inverted rather than dropped.
        """
        self.module("slow", " def test_one(self): time.sleep(1.1)\n")
        res = self.run_gate(FULL_GATE_BUDGET_S="1")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("OVER BUDGET", res.stdout)
        self.assertIn("executed ids=1 expected=1 missing=0 extra=0 duplicate=0", res.stdout)
        self.assertNotIn(
            "full-gate: failed", res.stdout,
            "a complete run over the wall was reported as a content FAILURE:\n" + res.stdout + res.stderr)
        self.assertEqual(
            res.returncode, 3,
            "a complete green run over the wall must be its own outcome, not failure (1):\n"
            + res.stdout + res.stderr)

    def test_a_complete_run_over_the_wall_is_not_a_content_failure(self):
        """agents-vuvrm acceptance 2, from the merger's attempt 2 while landing agents-nfpqn.

        Attempt 2 on the same tree reported 'executed ids=1880 expected=1880 missing=0 extra=0
        duplicate=0' with 'OVER BUDGET 350.483s > 300s' and exit 1 - and NO failing-modules line,
        because nothing failed: all 1880 ids ran, zero assertion failures, and the module attempt 1
        had killed at its 240s bound ran and passed. SO A COMPLETE GREEN RUN OVER THE WALL WAS
        INDISTINGUISHABLE FROM A CONTENT REGRESSION, and the right next action differs: park and
        wait, versus fix something. This pins that an over-the-wall run which is complete is
        reported as the wall, with its accounting beside it and no failure claimed.
        """
        self.module("slow", " def test_one(self): time.sleep(1.1)\n")
        res = self.run_gate(FULL_GATE_BUDGET_S="1")
        self.assertIn("executed ids=1 expected=1 missing=0 extra=0 duplicate=0", res.stdout)
        self.assertIn("OVER BUDGET", res.stdout)
        self.assertIn("COMPLETE", res.stdout, res.stdout + res.stderr)
        self.assertNotIn("failing modules", res.stdout, res.stdout + res.stderr)
        self.assertNotIn("ID SET MISMATCH", res.stdout, res.stdout + res.stderr)
        self.assertNotIn(
            "full-gate: failed", res.stdout,
            "a complete run over the wall was reported as a content failure:\n" + res.stdout + res.stderr)
        self.assertEqual(
            res.returncode, 3,
            "complete-but-over-wall is its own state: failed=1, unknown=2, over budget=3:\n"
            + res.stdout + res.stderr)

    def test_killed_module_is_unknown_and_not_a_failing_module(self):
        """A module killed at its own bound is not evidence about the tree (agents-vuvrm).

        The defect this pins: rc=124 with ids=0 was reported as a FAILING module whose ids were
        MISSING, so a per-module timeout reddened the gate and read as though the suite had
        asserted something and lost. The measured facts come from the merger's full gate on tree
        c5d3dbb3 - ZERO assertion failures in the whole log, 'ID SET MISMATCH missing=[101 ids]',
        and the one line that explains it: 'module=tests.test_fast_gate_mapping wall=240.015s
        rc=124 ids=0'. The same module alone on the same tree was rc=0, OK, 201s.

        Killed and failed must be DISTINGUISHABLE, in the scorecard and in the id-set accounting:
        a suite that never ran cannot be reported as having failed, and cannot be reported as
        having passed either.
        """
        # Two ids, so a pre-fix run contributes both of them to `missing` rather than one.
        self.module("hangs", " def test_slow(self): time.sleep(5)\n"
                             " def test_never_reached(self): pass\n")
        res = self.run_gate(FULL_GATE_MODULE_TIMEOUT_S="1")
        self.assertIn("unknown modules", res.stdout, res.stdout + res.stderr)
        self.assertIn("tests.test_hangs", res.stdout)
        self.assertNotIn(
            "failing modules: tests.test_hangs", res.stdout,
            "a module killed at its bound was reported as FAILING - that is the defect:\n"
            + res.stdout + res.stderr)
        self.assertNotIn(
            "ID SET MISMATCH", res.stdout,
            "the killed module's own ids were counted as MISSING, which is the second half of the "
            "defect - a suite that never ran is not evidence:\n" + res.stdout + res.stderr)
        self.assertIn("missing=0", res.stdout, res.stdout + res.stderr)
        self.assertNotIn(
            "full-gate: passed", res.stdout,
            "the gate claimed a PASS while a module never reached a verdict, so the tree was not "
            "fully verified:\n" + res.stdout + res.stderr)
        self.assertEqual(
            res.returncode, 2,
            "killed must be its own outcome, distinct from failed (1) and passed (0):\n"
            + res.stdout + res.stderr)

    def test_a_killed_module_does_not_mask_a_genuinely_failing_one(self):
        """The distinction must survive the mixture: a real failure still fails, and is named."""
        self.module("hangs", " def test_slow(self): time.sleep(5)\n")
        self.module("broken", " def test_bad(self): self.assertTrue(False, 'real failure')\n")
        res = self.run_gate(FULL_GATE_MODULE_TIMEOUT_S="1")
        self.assertIn("failing modules: tests.test_broken", res.stdout, res.stdout + res.stderr)
        self.assertIn("unknown modules", res.stdout, res.stdout + res.stderr)
        self.assertNotIn("failing modules: tests.test_hangs", res.stdout, res.stdout + res.stderr)
        self.assertEqual(
            res.returncode, 1,
            "a genuine assertion failure must still fail the gate, even beside a killed module:\n"
            + res.stdout + res.stderr)


    def test_signal_killed_modules_are_unknown_like_the_bound(self):
        """agents-2xq02, found by rev-vuvrm on b6cd3f23: the same costume, through the other door.

        tools/full-gate.sh first accepted only the SHELL spelling of a killed child (128+N). But
        run_module drives a module through subprocess.run WITHOUT a shell, where a signal-killed
        child comes back as the NEGATIVE SIGNAL NUMBER - measured on this VM: SIGKILL -> -9,
        SIGTERM -> -15, while the per-module bound is 124 synthesised by Python's own
        TimeoutExpired path. `rc in {124, 137, 143}` was therefore FALSE for a signal kill, so it
        was added to `failed`, its ids were reported as MISSING, and the gate exited 1 - exactly
        the reading the bead exists to remove. All three spellings must reach the SAME state, with
        the same id accounting, so this drives every mechanism rather than the one that was
        demonstrated.

        (The harness's module preamble imports os, so the deaths use raw signal numbers: 9 is
        SIGKILL and 15 is SIGTERM. A module is its own subprocess, so killing it here kills the
        child, not the gate.)
        """
        self.module("killed", " def test_sigkill(self): os.kill(os.getpid(), 9)\n")
        self.module("termed", " def test_sigterm(self): os.kill(os.getpid(), 15)\n")
        self.module("hangs", " def test_slow(self): time.sleep(5)\n")
        res = self.run_gate(FULL_GATE_MODULE_TIMEOUT_S="1")
        for module in ("tests.test_killed", "tests.test_termed", "tests.test_hangs"):
            self.assertIn(module, res.stdout, res.stdout + res.stderr)
        self.assertIn("unknown modules", res.stdout, res.stdout + res.stderr)
        self.assertNotIn(
            "failing modules", res.stdout,
            "a signal-killed module was reported as FAILING - that is agents-2xq02:\n"
            + res.stdout + res.stderr)
        self.assertNotIn(
            "ID SET MISMATCH", res.stdout,
            "a signal-killed module's ids were counted as MISSING, which is the same costume:\n"
            + res.stdout + res.stderr)
        self.assertIn(
            "executed ids=0 expected=0 missing=0 extra=0 duplicate=0", res.stdout,
            "the three killed modules' ids must be excluded from BOTH sides, leaving an empty and "
            "therefore consistent accounting:\n" + res.stdout + res.stderr)
        self.assertNotIn("full-gate: failed", res.stdout, res.stdout + res.stderr)
        self.assertEqual(
            res.returncode, 2,
            "all three kill spellings must report unknown (2), not a content failure (1):\n"
            + res.stdout + res.stderr)

    def test_a_signal_kill_does_not_mask_a_genuinely_failing_module(self):
        """The precedence must keep holding through the newly covered path, not just the bound."""
        self.module("killed", " def test_sigkill(self): os.kill(os.getpid(), 9)\n")
        self.module("broken", " def test_bad(self): self.assertTrue(False, 'real failure')\n")
        res = self.run_gate()
        self.assertIn("failing modules: tests.test_broken", res.stdout, res.stdout + res.stderr)
        self.assertIn("unknown modules", res.stdout, res.stdout + res.stderr)
        self.assertNotIn("failing modules: tests.test_killed", res.stdout, res.stdout + res.stderr)
        self.assertEqual(
            res.returncode, 1,
            "a content failure must still dominate a SIGKILLed module (agents-2xq02):\n"
            + res.stdout + res.stderr)


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

    def test_a_run_merges_its_costs_instead_of_deleting_another_trees_entries(self):
        """agents-2e2ca: save_costs REPLACED the table, so a stray entry could delete 101 modules."""
        self.module("here", " def test_one(self): pass\n")
        table = self.root / "checks" / "full-gate-module-costs.json"
        table.write_text(json.dumps({"seconds": {"tests.test_elsewhere": 42.0,
                                                  "test_oom_two": 0.2}}), encoding="utf-8")
        res = self.run_gate()
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        document = json.loads(table.read_text(encoding="utf-8"))
        # THE CONTROL, without which "the table is intact" is satisfiable by a merge that records
        # nothing at all: this run must have recorded its own cost.
        self.assertIn("tests.test_here", document["seconds"])
        # and the other tree's entries survive - including the one no module here answers to, which
        # is the exact shape that destroyed the real table on 2026-10-15.
        self.assertEqual(document["seconds"]["tests.test_elsewhere"], 42.0)
        self.assertEqual(document["seconds"]["test_oom_two"], 0.2)
        # a table now says which tree it was measured on, so a foreign one is detectable
        self.assertEqual(document["identity"]["tree"],
                         subprocess.run(["git", "rev-parse", "HEAD^{tree}"], cwd=self.root,
                                        capture_output=True, text=True, check=True).stdout.strip())

    def test_the_fallback_to_test_count_is_visible_rather_than_silent(self):
        """agents-2e2ca: the silent fallback is why a replaced table sharded on test count."""
        self.module("a", " def test_one(self): pass\n")
        first = self.run_gate()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertIn("cost fallback", first.stderr)
        self.assertIn("ordering those by test COUNT", first.stderr)
        # once the table carries this fixture's module the fallback is gone, so the line is about
        # the missing entry and not something the gate prints unconditionally.
        second = self.run_gate()
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertNotIn("cost fallback", second.stderr)


if __name__ == "__main__":
    unittest.main()
