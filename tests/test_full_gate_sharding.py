"""Drive the real full-gate entrypoint against isolated, tiny unittest packages."""

import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]


def measured_start_seconds(samples=3):
    """What one `python -m unittest` start costs on THIS host, right now.

    A fixture's per-module wall is a bound on the WHOLE module process, interpreter start
    included, so any case that wants a CONTENT failure inside a wall is racing the start.
    On 2026-10-23 that race was lost on this VM (agents-nxzkw): the synthetic ``broken``
    module was killed at wall=1.101s rc=124 ids=0 under the full gate's own parallelism,
    so it was classified ``unknown`` and the masking cases (agents-mzqfs) reported a red
    gate for two cleared, reviewed beads - on a delta that touches neither sharding nor
    this fixture. A constant is only safe on an idle host, so measure instead of assume.

    Three samples, worst case: a single start can be lucky, and the wall has to survive the
    unlucky one.
    """
    worst = 0.0
    for _ in range(samples):
        began = time.monotonic()
        subprocess.run([sys.executable, "-u", "-c", "import unittest"],
                       capture_output=True, check=False)
        worst = max(worst, time.monotonic() - began)
    return worst


_MEASURED_WALL = {}


def kill_wall_seconds():
    """The per-module wall for the KILL fixtures: several interpreter starts wide, min 5s.

    THE NUMBERS ARE MEASURED, NOT CHOSEN. ``FULL_GATE_MODULE_TIMEOUT_S`` bounds the WHOLE
    module process - interpreter start included - so a case that wants a CONTENT failure
    inside a wall is racing the start. On 2026-10-23 this VM lost that race at wall=1s: the
    merger's full gate reported ``module=tests.test_broken wall=1.101s rc=124 ids=0``, i.e. a
    module start costs about a second here under the gate's own parallelism, so the 'broken'
    module was KILLED before it could assert, arrived as ``unknown``, and the masking cases
    (agents-mzqfs) reddened a gate for two already-cleared, reviewed beads. The delta touched
    neither sharding nor this fixture (agents-nxzkw).

    3x the measured start, floor 5s: on a quiet host the measurement is ~0.3s and the floor
    applies; under the contention the merger measured it is ~1.1s and the floor still applies
    with a ~4.5x margin; only a host worse than any measurement here escalates the wall. The
    floor is also what keeps the fixture cheap: 5s, not minutes -- this module is in the full
    gate once per landing (tests/fast_gate_allowlists.d has it only for tools/full-gate.sh).
    """
    if "wall" not in _MEASURED_WALL:
        _MEASURED_WALL["start"] = measured_start_seconds()
        _MEASURED_WALL["wall"] = max(5, math.ceil(_MEASURED_WALL["start"] * 3))
    return _MEASURED_WALL["wall"]


def wall_note(wall):
    """Appended to a masking case's failure message, so a future red gate NAMES this race.

    Without it a wall that has slipped back under a module start reads exactly like a real
    precedence bug in tools/full-gate.sh - and on 2026-10-23 that misreading cost a full gate
    and two cleared beads (agents-nxzkw).
    """
    start = _MEASURED_WALL.get("start", 0.0)
    return (f"\n[fixture] per-module wall={wall}s; a `python -m unittest` start measured "
            f"{start:.3f}s on this host. If those two are CLOSE, the 'broken' module was killed "
            "before it could assert: that is this fixture racing the wall (agents-nxzkw), not a "
            "defect in the gate's precedence.")


def hang_body(wall):
    """A module the per-module bound must kill: it sleeps past the wall, then passes.

    Sleeping just past the wall (rather than forever, and rather than a multiple of it) keeps
    the fixture cheap and a BROKEN kill path legible: if the bound stops firing the module
    completes and the case fails on its own 'unknown modules' assertion with the gate output
    attached, instead of hanging the harness until it times out.
    """
    return f" def test_slow(self): time.sleep({wall + 5})\n"


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
        # A nested gate given an explicit per-module wall may legitimately run for a wall plus
        # the sleeping fixture's own sleep, so the harness timeout is derived from that wall too
        # - otherwise raising the wall to make the fixtures deterministic would make THIS harness
        # the thing that times out.
        wall = settings.get("FULL_GATE_MODULE_TIMEOUT_S")
        # The nested gate must not inherit the PARENT gate's shard-child marker: with it set, the
        # child behaves as a shard, skips the serial-only test this case constructs deliberately,
        # and exits 0 - which is exactly the assertion below failing for the wrong reason.
        env.pop("FULL_GATE_SHARD_CHILD", None)
        env.update(settings)
        return subprocess.run(["bash", str(self.root / "tools" / "full-gate.sh"), *args],
                              cwd=self.root, env=env, capture_output=True, text=True,
                              timeout=max(25, 2 * int(wall) + 15) if wall else 25, check=False)

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
        wall = kill_wall_seconds()
        self.module("hangs", hang_body(wall) + " def test_never_reached(self): pass\n")
        res = self.run_gate(FULL_GATE_MODULE_TIMEOUT_S=str(wall))
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
        """The distinction must survive the mixture: a real failure still fails, and is named.

        The wall here is MEASURED, not the 1s this case first used (agents-nxzkw). A 1s wall
        bounds the whole module process, interpreter start included, and a python start on this
        VM measured 1.1s under the full gate's own parallelism - so the ``broken`` module was
        killed before it could assert, arrived as ``unknown``, and this case reported a red gate
        for the wrong reason. See ``kill_wall_seconds``.
        """
        wall = kill_wall_seconds()
        self.module("hangs", hang_body(wall))
        self.module("broken", " def test_bad(self): self.assertTrue(False, 'real failure')\n")
        res = self.run_gate(FULL_GATE_MODULE_TIMEOUT_S=str(wall))
        self.assertIn("failing modules: tests.test_broken", res.stdout,
                      res.stdout + res.stderr + wall_note(wall))
        self.assertIn("unknown modules", res.stdout, res.stdout + res.stderr)
        self.assertNotIn("failing modules: tests.test_hangs", res.stdout, res.stdout + res.stderr)
        self.assertEqual(
            res.returncode, 1,
            "a genuine assertion failure must still fail the gate, even beside a killed module:\n"
            + res.stdout + res.stderr)


    def test_an_over_wall_run_beside_a_content_failure_still_fails(self):
        """agents-vuvrm case B, measured there but deliberately NOT pinned (agents-mzqfs).

        The disclosure this pins was honest coverage, not a gap: agents-vuvrm landed case A (a kill
        beside a content failure) as a test, and left cases B and C measured-but-unpinned because
        pinning them needs a commit, which would have changed the tree under review and voided the
        receipt. This is that commit, on a successor branch.

        THE RISK THIS GUARDS: a change that makes the WALL non-fatal can hide a real failure if it
        swallows the content-failure path. Precedence is the property, not each state alone - exit 1
        must win, and the failing module must still be named.
        """
        self.module("slow", " def test_slow(self): time.sleep(1.1)\n")
        self.module("broken", " def test_bad(self): self.assertTrue(False, 'real failure')\n")
        res = self.run_gate(FULL_GATE_BUDGET_S="1")
        self.assertIn("executed ids=2 expected=2 missing=0 extra=0 duplicate=0", res.stdout,
                      res.stdout + res.stderr)
        self.assertIn("failing modules: tests.test_broken", res.stdout, res.stdout + res.stderr)
        self.assertIn("OVER BUDGET", res.stdout, res.stdout + res.stderr)
        self.assertIn(
            "full-gate: failed", res.stdout,
            "a content failure beside an over-wall run must still report failure:\n" + res.stdout + res.stderr)
        self.assertNotIn(
            "full-gate: over budget", res.stdout,
            "the wall was reported as its own state while a module genuinely FAILED, so the content "
            "failure was swallowed:\n" + res.stdout + res.stderr)
        self.assertEqual(
            res.returncode, 1,
            "the content failure must dominate the wall (failed=1, unknown=2, over budget=3):\n"
            + res.stdout + res.stderr)

    def test_a_kill_beside_a_content_failure_and_the_wall_still_fails(self):
        """agents-vuvrm case C, the three-way mixture, measured but not pinned (agents-mzqfs).

        This is the strongest of the three: a killed module, an over-wall run AND a genuine content
        failure in one gate. Content must win (exit 1) and be named, the kill must still be reported
        as unknown rather than as a failure, and the killed module's ids must stay excluded from BOTH
        sides of the id-set check - so 'executed ids=1 expected=1 missing=0' is the accounting that
        proves the kill neither reddens via missing ids nor hides the real failure.
        """
        wall = kill_wall_seconds()
        self.module("hangs", hang_body(wall))
        self.module("broken", " def test_bad(self): self.assertTrue(False, 'real failure')\n")
        res = self.run_gate(FULL_GATE_MODULE_TIMEOUT_S=str(wall), FULL_GATE_BUDGET_S="1")
        self.assertIn(
            "executed ids=1 expected=1 missing=0 extra=0 duplicate=0", res.stdout,
            "the killed module's ids must be excluded from BOTH sides even beside a real failure, "
            "leaving only the failing module's id counted:\n" + res.stdout + res.stderr)
        self.assertIn("failing modules: tests.test_broken", res.stdout,
                      res.stdout + res.stderr + wall_note(wall))
        self.assertIn("unknown modules", res.stdout, res.stdout + res.stderr)
        self.assertIn("OVER BUDGET", res.stdout, res.stdout + res.stderr)
        self.assertNotIn(
            "failing modules: tests.test_hangs", res.stdout,
            "the killed module was reported as FAILING while a real failure sat beside it:\n"
            + res.stdout + res.stderr)
        self.assertNotIn("ID SET MISMATCH", res.stdout, res.stdout + res.stderr)
        self.assertEqual(
            res.returncode, 1,
            "content failure must dominate BOTH the kill and the wall:\n" + res.stdout + res.stderr)


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
        wall = kill_wall_seconds()
        self.module("hangs", hang_body(wall))
        res = self.run_gate(FULL_GATE_MODULE_TIMEOUT_S=str(wall))
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
        # a table now says which tree it was measured on, so a foreign one is detectable. The
        # fixture has no commit, so the sha and tree are empty by design (the gate's own header
        # uses `|| echo unknown` for exactly this reason); the module count is the measured fact.
        self.assertIn("identity", document)
        self.assertEqual(document["identity"]["modules"], 1)

    def test_the_fallback_to_test_count_is_visible_rather_than_silent(self):
        """agents-2e2ca: the silent fallback is why a replaced table sharded on test count."""
        self.module("a", " def test_one(self): pass\n")
        first = self.run_gate()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        # ON STDOUT, NOT STDERR, AND THAT IS MEASURED RATHER THAN ASSUMED: the gate wraps its
        # python in `2>&1 | tee`, so a line written to sys.stderr arrives on the caller's stdout,
        # and res.stderr is empty. Asserting on stderr was the first version of this test.
        self.assertIn("cost fallback", first.stdout)
        self.assertIn("ordering those by test COUNT", first.stdout)
        # once the table carries this fixture's module the fallback is gone, so the line is about
        # the missing entry and not something the gate prints unconditionally.
        second = self.run_gate()
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertNotIn("cost fallback", second.stdout)

    def test_concurrent_save_costs_calls_preserve_both_measurements(self):
        """agents-2c06k: concurrent save_costs calls must not overwrite each other via stale snapshots."""
        import ast, concurrent.futures
        src = (self.root / "tools" / "full-gate.sh").read_text(encoding="utf-8")
        py_lines = []
        in_py = False
        for line in src.splitlines():
            if not in_py and "<<'PY'" in line:
                in_py = True
                continue
            if in_py and line == "PY":
                break
            if in_py:
                py_lines.append(line)
        tree = ast.parse("\n".join(py_lines))
        nodes = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
        nodes.extend([n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "save_costs"])
        mod = ast.Module(body=nodes, type_ignores=[])
        ast.fix_missing_locations(mod)
        ns = {}
        exec(compile(mod, "full-gate.sh", "exec"), ns)
        save_costs = ns["save_costs"]

        table = self.root / "checks" / "full-gate-module-costs.json"
        table.write_text(json.dumps({"seconds": {}}), encoding="utf-8")
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(save_costs, table, {f"tests.test_{i}": float(i)}) for i in range(1, 11)]
            for f in futures:
                f.result()
        data = json.loads(table.read_text(encoding="utf-8"))["seconds"]
        for i in range(1, 11):
            self.assertIn(f"tests.test_{i}", data)
            self.assertEqual(data[f"tests.test_{i}"], float(i))

    def test_partial_run_does_not_overwrite_full_gate_module_costs(self):
        """agents-ia6mp: a partial/fixture run must not overwrite existing full-gate costs for overlapping modules."""
        import ast
        src = (self.root / "tools" / "full-gate.sh").read_text(encoding="utf-8")
        py_lines = []
        in_py = False
        for line in src.splitlines():
            if not in_py and "<<'PY'" in line:
                in_py = True
                continue
            if in_py and line == "PY":
                break
            if in_py:
                py_lines.append(line)
        tree = ast.parse("\n".join(py_lines))
        nodes = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
        nodes.extend([n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in ("save_costs", "costs_at")])
        mod = ast.Module(body=nodes, type_ignores=[])
        ast.fix_missing_locations(mod)
        ns = {}
        exec(compile(mod, "full-gate.sh", "exec"), ns)
        save_costs = ns["save_costs"]
        costs_at = ns["costs_at"]

        table = self.root / "checks" / "full-gate-module-costs.json"
        # 1. Full-gate baseline measurement with 2 modules and valid 40-char git tree sha
        save_costs(table, {"tests.test_heavy": 140.0, "tests.test_light": 1.0},
                   {"tree": "a" * 40, "remote": "origin", "modules": 2},
                   expected_keys=["tests.test_heavy", "tests.test_light"])
        # 2. Foreign/partial run measuring only 1 module with a stub timing
        save_costs(table, {"tests.test_heavy": 0.2},
                   {"tree": "b" * 40, "remote": "origin", "modules": 1},
                   expected_keys=["tests.test_heavy", "tests.test_light"])
        # 3. Full-gate sharding query must still preserve the full-gate baseline cost
        costs = costs_at(table, {"tests.test_heavy": ["heavy"], "tests.test_light": ["light"]})
        self.assertEqual(costs["tests.test_heavy"], 140.0)
        self.assertEqual(costs["tests.test_light"], 1.0)
        # And identity retains full suite provenance
        data = json.loads(table.read_text(encoding="utf-8"))
        self.assertEqual(data["identity"]["tree"], "a" * 40)
        self.assertEqual(data["identity"]["remote"], "origin")
        self.assertEqual(data["identity"]["modules"], 2)

    def test_equal_count_fixture_run_does_not_overwrite_baseline_costs(self):
        """agents-tktak: foreign mock fixtures cannot overwrite existing baseline costs."""
        import ast
        src = (self.root / "tools" / "full-gate.sh").read_text(encoding="utf-8")
        py_lines = []
        in_py = False
        for line in src.splitlines():
            if not in_py and "<<'PY'" in line:
                in_py = True
                continue
            if in_py and line == "PY":
                break
            if in_py:
                py_lines.append(line)
        tree = ast.parse("\n".join(py_lines))
        nodes = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
        nodes.extend([n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in ("save_costs", "costs_at")])
        mod = ast.Module(body=nodes, type_ignores=[])
        ast.fix_missing_locations(mod)
        ns = {}
        exec(compile(mod, "full-gate.sh", "exec"), ns)
        save_costs = ns["save_costs"]
        costs_at = ns["costs_at"]

        table = self.root / "checks" / "full-gate-module-costs.json"
        # 1. Baseline measurement with 2 modules and valid 40-char git tree sha
        save_costs(table, {"tests.test_heavy": 140.0, "tests.test_light": 1.0},
                   {"tree": "a" * 40, "remote": "origin", "modules": 2},
                   expected_keys=["tests.test_heavy", "tests.test_light"])
        # 2. Foreign mock fixture run with tree="fixture" and no matching remote
        save_costs(table, {"tests.test_heavy": 0.2, "tests.test_fixture": 0.1},
                   {"tree": "fixture", "remote": "", "modules": 2},
                   expected_keys=["tests.test_heavy", "tests.test_fixture"])
        # 3. Baseline cost must be preserved, foreign run rejected without pollution, and real identity retained
        costs = costs_at(table, {"tests.test_heavy": ["heavy"], "tests.test_light": ["light"]})
        self.assertEqual(costs["tests.test_heavy"], 140.0)
        self.assertEqual(costs["tests.test_light"], 1.0)
        data = json.loads(table.read_text(encoding="utf-8"))
        self.assertEqual(data["seconds"]["tests.test_heavy"], 140.0)
        self.assertEqual(data["seconds"]["tests.test_light"], 1.0)
        self.assertNotIn("tests.test_fixture", data["seconds"])
        self.assertEqual(data["identity"]["tree"], "a" * 40)
        self.assertEqual(data["identity"]["remote"], "origin")

        # 4. A full repository run on a new commit tree with matching remote updates costs and provenance
        save_costs(table, {"tests.test_heavy": 135.0, "tests.test_light": 0.9, "tests.test_new": 0.5},
                   {"tree": "b" * 40, "remote": "origin", "modules": 3},
                   expected_keys=["tests.test_heavy", "tests.test_light", "tests.test_new"])
        data2 = json.loads(table.read_text(encoding="utf-8"))
        self.assertEqual(data2["seconds"]["tests.test_heavy"], 135.0)
        self.assertEqual(data2["seconds"]["tests.test_light"], 0.9)
        self.assertEqual(data2["seconds"]["tests.test_new"], 0.5)
        self.assertEqual(data2["identity"]["tree"], "b" * 40)
        self.assertEqual(data2["identity"]["remote"], "origin")


if __name__ == "__main__":
    unittest.main()
