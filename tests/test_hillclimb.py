#!/usr/bin/env python3
"""run_hillclimb --apply must never mutate the operator's checkout (agents-nei).

The perf hill-climber's --apply path edits files and re-measures them. Before agents-nei it
fell back to writing the operator's real checkout on a non-git target or a failed
`git worktree add`, and it advanced `current_val` while discarding the worktree (or reverting
the file), so a KEPT ledger row could fire on a value not on disk. These tests drive the real
`run_hillclimb` (only the model call `run_agent` is stubbed — it is not the thing under test):

- a non-git target, or a worktree-add failure, BLOCKS the run and leaves the target untouched;
- a KEPT win persists in the worktree before `current_val` advances (the next identical step
  sees the edited file and is reverted, never re-applied to the operator's checkout);
- a failed/aborted step (unmatched snippet, or a step that worsens the metric) does not
  advance state and leaves the target untouched.
"""

import importlib.machinery
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

FACTORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(FACTORY_ROOT))

import lib.bench.runner as bench_runner  # noqa: E402

_loader = importlib.machinery.SourceFileLoader("factory_cli_hc", str(FACTORY_ROOT / "factory"))
_spec = importlib.util.spec_from_loader("factory_cli_hc", _loader)
factory_cli = importlib.util.module_from_spec(_spec)
_loader.exec_module(factory_cli)

BLOCKING_HTML = '<html><head><script src="app.js"></script></head><body></body></html>\n'


class HillClimbApplyIsolationTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="factory-hc-")
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)
        # Route both the factory's run artifacts and the bench ledger into the temp tree so
        # the tests never write the real repo's runs/ or findings/.
        self._findings_patch = mock.patch.object(bench_runner, "FINDINGS_DIR", self.tmp / "findings")
        self._root_patch = mock.patch.object(factory_cli, "FACTORY_ROOT", self.tmp / "factory-root")
        self._findings_patch.start()
        self._root_patch.start()
        self.addCleanup(self._findings_patch.stop)
        self.addCleanup(self._root_patch.stop)

    def _git_target(self, files):
        target = self.tmp / "target"
        target.mkdir()
        for rel, content in files.items():
            p = target / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=target, check=True)
        subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=target, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=target, check=True)
        subprocess.run(["git", "add", "-A"], cwd=target, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=target, check=True)
        return target

    def _ledger(self):
        return bench_runner.read_ledger("target")

    def _run(self, target, steps, iterations=1, goal_value=0):
        with mock.patch.object(factory_cli, "run_agent",
                               return_value={"report": {"hillclimb_steps": steps},
                                             "run_dir": self.tmp / "run"}):
            return factory_cli.run_hillclimb(
                str(target), goal_metric="perf_hazard_score", goal_value=goal_value,
                iterations=iterations, apply_edits=True, engine_arg="pi")

    def test_apply_on_non_git_target_is_blocked_and_target_unchanged(self):
        target = self.tmp / "target"
        target.mkdir()
        index = target / "index.html"
        original = BLOCKING_HTML
        index.write_text(original, encoding="utf-8")

        result = factory_cli.run_hillclimb(
            str(target), goal_metric="perf_hazard_score", goal_value=0,
            iterations=1, apply_edits=True, engine_arg="pi")

        self.assertFalse(result)
        self.assertEqual(index.read_text(), original)  # the operator's checkout is untouched
        ledger = self._ledger()
        self.assertEqual(ledger[-1]["outcome"], "BLOCKED")

    def test_worktree_add_failure_is_blocked_and_target_unchanged(self):
        target = self._git_target({"index.html": BLOCKING_HTML})
        index = target / "index.html"
        original = index.read_text()

        with mock.patch.object(factory_cli, "_create_session_worktree",
                               side_effect=factory_cli.StationError("concurrent worktree add")):
            result = factory_cli.run_hillclimb(
                str(target), goal_metric="perf_hazard_score", goal_value=0,
                iterations=1, apply_edits=True, engine_arg="pi")

        self.assertFalse(result)
        self.assertEqual(index.read_text(), original)
        self.assertEqual(self._ledger()[-1]["outcome"], "BLOCKED")

    def test_kept_win_persists_in_worktree_before_state_advances(self):
        # Two render-blocking scripts -> perf_hazard_score 30; one defer win -> 15 (not goal 0),
        # so a second iteration runs and must see the persisted first edit.
        html = ('<html><head>'
                '<script src="a.js"></script>'
                '<script src="b.js"></script>'
                '</head><body></body></html>\n')
        target = self._git_target({"index.html": html})
        index = target / "index.html"
        original = index.read_text()
        step = {
            "hypothesis": "defer a.js",
            "target_file": "index.html",
            "search_snippet": '<script src="a.js"></script>',
            "replace_snippet": '<script src="a.js" defer></script>',
        }

        result = self._run(target, [step], iterations=2)

        self.assertTrue(result)
        self.assertEqual(index.read_text(), original)  # operator's checkout never written
        ledger = self._ledger()
        self.assertEqual([e["outcome"] for e in ledger], ["KEPT", "REVERTED"])
        kept, reverted = ledger
        self.assertEqual(kept["baseline_value"], 30)
        self.assertEqual(kept["candidate_value"], 15)  # persisted win advanced the state
        self.assertEqual(reverted["baseline_value"], 15)  # advanced, then held
        self.assertEqual(reverted["candidate_value"], 15)
        self.assertEqual(reverted["reason"], "search_snippet did not match exact file contents")
        # The kept edit is the durable proposal (patch), never the operator's checkout.
        patches = list((self.tmp / "factory-root" / "runs").rglob("session.patch"))
        self.assertEqual(len(patches), 1)
        self.assertIn("defer", patches[0].read_text())

    def test_unmatched_search_snippet_does_not_advance_state(self):
        target = self._git_target({"index.html": BLOCKING_HTML})
        index = target / "index.html"
        original = index.read_text()
        step = {
            "hypothesis": "defer a missing script",
            "target_file": "index.html",
            "search_snippet": '<script src="missing.js"></script>',
            "replace_snippet": '<script src="missing.js" defer></script>',
        }

        result = self._run(target, [step])

        self.assertTrue(result)
        self.assertEqual(index.read_text(), original)
        ledger = self._ledger()
        self.assertEqual(len(ledger), 1)
        self.assertEqual(ledger[0]["outcome"], "REVERTED")
        self.assertEqual(ledger[0]["baseline_value"], 15)  # one blocking script
        self.assertEqual(ledger[0]["candidate_value"], 15)  # no advance

    def test_a_worse_step_is_reverted_and_does_not_advance_state(self):
        target = self._git_target({
            "index.html": BLOCKING_HTML,
            "app.js": "console.log('hello');\n",
        })
        index = target / "index.html"
        app = target / "app.js"
        original_html = index.read_text()
        original_js = app.read_text()
        step = {
            "hypothesis": "add layout thrash (worse)",
            "target_file": "app.js",
            "search_snippet": "console.log('hello');",
            "replace_snippet": "console.log('hello');\ngetBoundingClientRect();",
        }

        result = self._run(target, [step])

        self.assertTrue(result)
        self.assertEqual(index.read_text(), original_html)
        self.assertEqual(app.read_text(), original_js)
        ledger = self._ledger()
        self.assertEqual(len(ledger), 1)
        self.assertEqual(ledger[0]["outcome"], "REVERTED")
        self.assertEqual(ledger[0]["baseline_value"], 15)
        self.assertEqual(ledger[0]["candidate_value"], 25)  # 15 + 10 layout-thrash
        # No kept edits -> no proposal patch is produced.
        self.assertEqual(list((self.tmp / "factory-root" / "runs").rglob("session.patch")), [])

    def test_proposal_only_mode_records_and_does_not_touch_target(self):
        target = self._git_target({"index.html": BLOCKING_HTML})
        index = target / "index.html"
        original = index.read_text()
        step = {
            "hypothesis": "defer app.js",
            "target_file": "index.html",
            "search_snippet": '<script src="app.js"></script>',
            "replace_snippet": '<script src="app.js" defer></script>',
        }
        with mock.patch.object(factory_cli, "run_agent",
                               return_value={"report": {"hillclimb_steps": [step]},
                                             "run_dir": self.tmp / "run"}):
            result = factory_cli.run_hillclimb(
                str(target), goal_metric="perf_hazard_score", goal_value=0,
                iterations=1, apply_edits=False, engine_arg="pi")

        self.assertTrue(result)
        self.assertEqual(index.read_text(), original)
        ledger = self._ledger()
        self.assertEqual(len(ledger), 1)
        self.assertEqual(ledger[0]["outcome"], "PROPOSED")


if __name__ == "__main__":
    unittest.main()
