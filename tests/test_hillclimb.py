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
import io
import json
import shutil
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

# The real perf-hillclimb pre-pass, loaded in-process so a test can drive it against the
# disposable worktree while the patched FINDINGS_DIR keeps ledger I/O inside the tmp tree.
_measure_script = FACTORY_ROOT / "agents" / "perf-hillclimb" / "scripts" / "measure_and_context.py"
_measure_loader = importlib.machinery.SourceFileLoader("measure_and_context_hc", str(_measure_script))
_measure_spec = importlib.util.spec_from_loader("measure_and_context_hc", _measure_loader)
measure_and_context = importlib.util.module_from_spec(_measure_spec)
_measure_loader.exec_module(measure_and_context)

BLOCKING_HTML = '<html><head><script src="app.js"></script></head><body></body></html>\n'


class HillClimbApplyIsolationTest(unittest.TestCase):
    def run(self, result=None):
        """Buffer stdout during test execution so deliberate mock banners and blocked messages
        do not leak into gate logs on passing runs (agents-janc). If the test fails, replay the
        captured buffer to sys.stderr so genuine diagnostics from the code under test survive
        the failure (agents-lq6y). If the underlying runner raises before assigning a result,
        the original exception propagates unmasked (agents-ekbx)."""
        orig_stdout = sys.stdout
        self._stdout_capture = io.StringIO()
        sys.stdout = self._stdout_capture
        res = None
        try:
            res = super().run(result)
        finally:
            sys.stdout = orig_stdout
            actual_result = result if result is not None else res
            if actual_result is not None and any(
                test == self for test, _ in getattr(actual_result, "failures", []) + getattr(actual_result, "errors", [])
            ):
                val = self._stdout_capture.getvalue()
                if val:
                    sys.stderr.write(f"\n--- Captured stdout for {self.id()} ---\n{val}\n")
        return res

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

    def _run_prepass(self, read_dir, out_path):
        """Drive the REAL perf-hillclimb pre-pass against the given tree, in-process, so the
        patched FINDINGS_DIR keeps ledger I/O inside the tmp tree."""
        with mock.patch.object(sys, "argv", ["measure_and_context.py", "--target", str(read_dir),
                                             "--target-name", "target", "--output", str(out_path)]):
            measure_and_context.main()
        return json.loads(out_path.read_text(encoding="utf-8"))

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

    def test_dirty_checkout_is_blocked_and_never_mutated(self):
        # P1-1: the baseline is measured on the operator's checkout, but the disposable
        # worktree starts at HEAD. A dirty checkout would disagree with the worktree and could
        # mint a phantom KEPT win, so --apply must refuse it before any edit or worktree.
        target = self._git_target({"index.html": BLOCKING_HTML})
        index = target / "index.html"
        # Add a second render-blocking script WITHOUT committing it: the operator's checkout
        # now measures 30 while the worktree would start at HEAD (15).
        index.write_text(
            '<html><head>'
            '<script src="app.js"></script>'
            '<script src="extra.js"></script>'
            '</head><body></body></html>\n', encoding="utf-8")
        dirty = index.read_text()

        result = factory_cli.run_hillclimb(
            str(target), goal_metric="perf_hazard_score", goal_value=0,
            iterations=1, apply_edits=True, engine_arg="pi")

        self.assertFalse(result)
        self.assertEqual(index.read_text(), dirty)  # the operator's dirty checkout is untouched
        ledger = self._ledger()
        self.assertEqual(ledger[-1]["outcome"], "BLOCKED")
        self.assertIn("uncommitted changes", ledger[-1]["reason"])
        # Nothing was staged or committed by the factory, and no proposal/worktree was made.
        self.assertEqual(list((self.tmp / "factory-root" / "runs").glob("hillclimb-*")), [])

    def test_ignored_measured_asset_is_refused_not_a_phantom_win(self):
        # P1-2: git status --porcelain misses ignored files, while measure_target still walks
        # an ignored assets/slow.html (a blocking script) in the operator's checkout. That file
        # is absent from the HEAD worktree, so a checkout-measured baseline would disagree with
        # the worktree and could mint a phantom KEPT win. --apply must refuse the mismatch.
        target = self._git_target({
            "index.html": BLOCKING_HTML,
            ".gitignore": "assets/slow.html\n",
        })
        slow = target / "assets" / "slow.html"
        slow.parent.mkdir(parents=True, exist_ok=True)
        slow.write_text(BLOCKING_HTML, encoding="utf-8")
        index = target / "index.html"
        original = index.read_text()

        result = factory_cli.run_hillclimb(
            str(target), goal_metric="perf_hazard_score", goal_value=0,
            iterations=1, apply_edits=True, engine_arg="pi")

        self.assertFalse(result)
        self.assertEqual(index.read_text(), original)  # the operator's checkout is untouched
        self.assertEqual(slow.read_text(), BLOCKING_HTML)
        ledger = self._ledger()
        self.assertEqual(ledger[-1]["outcome"], "BLOCKED")
        self.assertIn("ignored measured asset", ledger[-1]["reason"])
        # No worktree/proposal was made for the refused run.
        self.assertEqual(list((self.tmp / "factory-root" / "runs").glob("hillclimb-*")), [])

    def test_ignored_measured_asset_with_newline_in_name_is_refused(self):
        # P1-1 (round 4): git ls-files quotes a path containing a newline, so parsing its
        # newline-delimited output as literal paths leaves a trailing quote (suffix not .html)
        # and the ignored assets/slow<NL>.html slips past the refusal — while measure_target
        # still walks it. NUL-delimited parsing must catch it and refuse the run.
        target = self._git_target({
            "index.html": BLOCKING_HTML,
            ".gitignore": "assets/slow*.html\n",
        })
        slow = target / "assets" / "slow\n.html"
        slow.parent.mkdir(parents=True, exist_ok=True)
        slow.write_text(BLOCKING_HTML, encoding="utf-8")
        index = target / "index.html"
        original = index.read_text()

        result = factory_cli.run_hillclimb(
            str(target), goal_metric="perf_hazard_score", goal_value=0,
            iterations=1, apply_edits=True, engine_arg="pi")

        self.assertFalse(result)
        self.assertEqual(index.read_text(), original)
        self.assertEqual(slow.read_text(), BLOCKING_HTML)
        ledger = self._ledger()
        self.assertEqual(ledger[-1]["outcome"], "BLOCKED")
        self.assertIn("ignored measured asset", ledger[-1]["reason"])
        self.assertEqual(list((self.tmp / "factory-root" / "runs").glob("hillclimb-*")), [])

    def test_collection_failure_leaves_no_durable_kept_row(self):
        # P1-3: a KEPT row must never outlive its proposal. If the proposal cannot be collected
        # (git add --intent-to-add nonzero), the run must fail BEFORE the KEPT row is durable.
        target = self._git_target({
            "index.html": ('<html><head>'
                           '<script src="a.js"></script>'
                           '<script src="b.js"></script>'
                           '</head><body></body></html>\n')
        })
        index = target / "index.html"
        original = index.read_text()
        step = {
            "hypothesis": "defer a.js",
            "target_file": "index.html",
            "search_snippet": '<script src="a.js"></script>',
            "replace_snippet": '<script src="a.js" defer></script>',
        }
        with mock.patch.object(factory_cli, "run_agent",
                               return_value={"report": {"hillclimb_steps": [step]},
                                             "run_dir": self.tmp / "run"}):
            with mock.patch.object(factory_cli, "_collect_session_diff",
                                   side_effect=factory_cli.StationError(
                                       "git add --intent-to-add failed (index lock)")):
                with self.assertRaises(factory_cli.StationError):
                    factory_cli.run_hillclimb(
                        str(target), goal_metric="perf_hazard_score", goal_value=0,
                        iterations=1, apply_edits=True, engine_arg="pi")

        self.assertEqual(index.read_text(), original)
        self.assertEqual(self._ledger(), [])  # no durable KEPT row survives the failed collection
        self.assertEqual(list((self.tmp / "factory-root" / "runs").rglob("session.patch")), [])

    def test_later_iteration_failure_still_collects_kept_proposal(self):
        # P1-2: iteration 1 keeps a win, iteration 2's run_agent raises. The verified edit must
        # still be collected as a proposal before the worktree is discarded — otherwise the
        # ledger keeps a KEPT row with no surviving proposal.
        target = self._git_target({
            "index.html": ('<html><head>'
                           '<script src="a.js"></script>'
                           '<script src="b.js"></script>'
                           '</head><body></body></html>\n')
        })
        index = target / "index.html"
        original = index.read_text()
        step = {
            "hypothesis": "defer a.js",
            "target_file": "index.html",
            "search_snippet": '<script src="a.js"></script>',
            "replace_snippet": '<script src="a.js" defer></script>',
        }
        with mock.patch.object(factory_cli, "run_agent",
                               side_effect=[
                                   {"report": {"hillclimb_steps": [step]},
                                    "run_dir": self.tmp / "run1"},
                                   factory_cli.StationError("iteration 2 failed"),
                               ]):
            with self.assertRaises(factory_cli.StationError):
                factory_cli.run_hillclimb(
                    str(target), goal_metric="perf_hazard_score", goal_value=0,
                    iterations=2, apply_edits=True, engine_arg="pi")

        self.assertEqual(index.read_text(), original)
        self.assertEqual([e["outcome"] for e in self._ledger()], ["KEPT"])
        patches = list((self.tmp / "factory-root" / "runs").rglob("session.patch"))
        self.assertEqual(len(patches), 1)
        self.assertIn("defer", patches[0].read_text())

    def test_worktree_creation_failure_after_add_is_cleaned_up(self):
        # P2-1: _create_session_worktree can raise AFTER `git worktree add` succeeded, leaving
        # a registered admin worktree. The caller must run the cleanup helper on that path too.
        target = self._git_target({"index.html": BLOCKING_HTML})
        index = target / "index.html"
        original = index.read_text()

        def create_then_fail(target_dir, worktree_dir):
            # The worktree is really registered (so the bug would leak it), then rev-parse
            # fails and the helper raises.
            subprocess.run(["git", "worktree", "add", "--detach", str(worktree_dir)],
                           cwd=target_dir, check=True, capture_output=True, text=True)
            raise factory_cli.StationError("rev-parse failed after worktree add")

        with mock.patch.object(factory_cli, "_create_session_worktree",
                               side_effect=create_then_fail):
            result = factory_cli.run_hillclimb(
                str(target), goal_metric="perf_hazard_score", goal_value=0,
                iterations=1, apply_edits=True, engine_arg="pi")

        self.assertFalse(result)
        self.assertEqual(index.read_text(), original)
        self.assertEqual(self._ledger()[-1]["outcome"], "BLOCKED")
        # No leftover worktree registration under the operator's .git, and the run dir is gone.
        worktrees = target / ".git" / "worktrees"
        self.assertEqual(list(worktrees.glob("*")) if worktrees.exists() else [], [])
        self.assertEqual(list((self.tmp / "factory-root" / "runs").glob("hillclimb-*")), [])

    def test_second_iteration_reads_accumulated_worktree(self):
        # P2-2: a later proposal must be generated against the accumulated worktree (which
        # carries the prior kept edit), never the operator's unchanged checkout. Drive the REAL
        # perf-hillclimb pre-pass on each iteration's read dir so the assertion is the measured
        # hazard score, not just run_agent's argument.
        target = self._git_target({
            "index.html": ('<html><head>'
                           '<script src="a.js"></script>'
                           '<script src="b.js"></script>'
                           '</head><body></body></html>\n')
        })
        index = target / "index.html"
        original = index.read_text()
        step_a = {
            "hypothesis": "defer a.js",
            "target_file": "index.html",
            "search_snippet": '<script src="a.js"></script>',
            "replace_snippet": '<script src="a.js" defer></script>',
        }
        step_b = {
            "hypothesis": "defer b.js",
            "target_file": "index.html",
            "search_snippet": '<script src="b.js"></script>',
            "replace_snippet": '<script src="b.js" defer></script>',
        }
        measured_scores = []

        def run_agent_side_effect(agent_name, target_arg, *args, **kwargs):
            read_dir = kwargs["read_target_dir"]
            out = self.tmp / f"prepass-{len(measured_scores)}.json"
            payload = self._run_prepass(read_dir, out)
            measured_scores.append(payload["baseline_metrics"]["perf_hazard_score"])
            steps = [step_a] if len(measured_scores) == 1 else [step_b]
            return {"report": {"hillclimb_steps": steps},
                    "run_dir": self.tmp / f"run{len(measured_scores)}"}

        with mock.patch.object(factory_cli, "run_agent", side_effect=run_agent_side_effect):
            result = factory_cli.run_hillclimb(
                str(target), goal_metric="perf_hazard_score", goal_value=0,
                iterations=2, apply_edits=True, engine_arg="pi")

        self.assertTrue(result)
        self.assertEqual(index.read_text(), original)
        self.assertEqual([e["outcome"] for e in self._ledger()], ["KEPT", "KEPT"])
        # The REAL pre-pass measured 30 on the HEAD worktree, then 15 after the first kept
        # edit — proving it read the accumulated worktree, not the operator's checkout (which
        # still measures 30 because it was never modified).
        self.assertEqual(measured_scores, [30, 15])
        patch = list((self.tmp / "factory-root" / "runs").rglob("session.patch"))[0].read_text()
        self.assertIn('src="a.js" defer', patch)
        self.assertIn('src="b.js" defer', patch)

    def test_create_session_worktree_prunes_stale_registration_and_retries(self):
        """P3 fix (agents-janc): stale worktree registration triggers git worktree prune and succeeds."""
        target = self._git_target({"index.html": BLOCKING_HTML})
        wt_dir = self.tmp / "disposable_worktree_stale"

        # Create a worktree, then rm -rf the directory to leave a stale admin registration
        subprocess.run(["git", "worktree", "add", "--detach", str(wt_dir)], cwd=target, check=True, capture_output=True)
        shutil.rmtree(wt_dir)

        # _create_session_worktree must prune the stale entry and succeed on retry
        admin_gitdir = factory_cli._create_session_worktree(target, wt_dir)
        self.assertTrue(wt_dir.exists())
        self.assertTrue(admin_gitdir.exists())
        factory_cli._remove_session_worktree(target, wt_dir)

    def test_create_session_worktree_retries_on_transient_lock(self):
        """P3 fix (agents-janc): transient git lock contention retries with backoff and succeeds."""
        target = self._git_target({"index.html": BLOCKING_HTML})
        wt_dir = self.tmp / "disposable_worktree_lock"

        calls = 0
        real_run_git = factory_cli._run_git

        def fake_run_git(cmd, cwd=None):
            nonlocal calls
            if "worktree" in cmd and "add" in cmd:
                calls += 1
                if calls == 1:
                    # First attempt simulates transient lock collision
                    return subprocess.CompletedProcess(cmd, 128, "", "fatal: Unable to create '.git/index.lock': File exists.")
            return real_run_git(cmd, cwd)

        with mock.patch.object(factory_cli, "_run_git", side_effect=fake_run_git):
            with mock.patch("time.sleep") as mock_sleep:
                admin_gitdir = factory_cli._create_session_worktree(target, wt_dir)
                self.assertTrue(wt_dir.exists())
                self.assertTrue(admin_gitdir.exists())
                self.assertEqual(calls, 2)
                mock_sleep.assert_called_once()
        factory_cli._remove_session_worktree(target, wt_dir)

    def test_create_session_worktree_raises_loud_error_on_persistent_failure(self):
        """P3 fix (agents-janc): persistent failure raises StationError naming the exit code and stderr."""
        target = self._git_target({"index.html": BLOCKING_HTML})
        wt_dir = self.tmp / "disposable_worktree_fail"

        def fail_run_git(cmd, cwd=None):
            if "worktree" in cmd and "add" in cmd:
                return subprocess.CompletedProcess(cmd, 128, "", "fatal: corrupt git repository")
            return factory_cli._run_git(cmd, cwd)

        with mock.patch.object(factory_cli, "_run_git", side_effect=fail_run_git):
            with self.assertRaises(factory_cli.StationError) as ctx:
                factory_cli._create_session_worktree(target, wt_dir)
            self.assertIn("git worktree add exited 128: fatal: corrupt git repository", str(ctx.exception))


class TestHillClimbStdoutDiagnostics(unittest.TestCase):
    """agents-lq6y: verify that HillClimbApplyIsolationTest retains station diagnostics on failure
    while muffling deliberate banners on passing runs."""

    class _SamplePassingTest(HillClimbApplyIsolationTest):
        def test_passing_run(self):
            print("⛰️  CLASS C HILL-CLIMB OPTIMIZER STARTED (mock banner)")
            self.assertTrue(True)

    class _SampleFailingTest(HillClimbApplyIsolationTest):
        def test_failing_run(self):
            print("DIAGNOSTIC: station proposal failed syntax validation on index.html:42")
            self.fail("deliberate test failure for diagnostic verification")

    def test_passing_test_keeps_stdout_and_stderr_clean(self):
        out_sink, err_sink = io.StringIO(), io.StringIO()
        old_out, old_err = sys.stdout, sys.stderr
        try:
            sys.stdout, sys.stderr = out_sink, err_sink
            result = unittest.TestResult()
            self._SamplePassingTest("test_passing_run").run(result)
        finally:
            sys.stdout, sys.stderr = old_out, old_err

        self.assertTrue(result.wasSuccessful())
        self.assertEqual(out_sink.getvalue(), "", "Passing run must not leak banner to stdout")
        self.assertEqual(err_sink.getvalue(), "", "Passing run must not write to stderr")

    def test_failing_test_replays_station_diagnostics_to_stderr(self):
        out_sink, err_sink = io.StringIO(), io.StringIO()
        old_out, old_err = sys.stdout, sys.stderr
        try:
            sys.stdout, sys.stderr = out_sink, err_sink
            result = unittest.TestResult()
            self._SampleFailingTest("test_failing_run").run(result)
        finally:
            sys.stdout, sys.stderr = old_out, old_err

        self.assertFalse(result.wasSuccessful())
        self.assertEqual(out_sink.getvalue(), "")
        stderr_output = err_sink.getvalue()
        self.assertIn("DIAGNOSTIC: station proposal failed syntax validation on index.html:42", stderr_output)
        self.assertIn("--- Captured stdout for", stderr_output)

    def test_underlying_runner_exception_propagates_unmasked(self):
        """P3 fix (agents-ekbx): an exception raised by the underlying runner must propagate
        as itself rather than being masked by UnboundLocalError/NameError in finally."""
        class _RaisingRunnerTest(HillClimbApplyIsolationTest):
            def test_noop(self):
                pass

        orig_run = unittest.TestCase.run
        unittest.TestCase.run = lambda self, r=None: (_ for _ in ()).throw(KeyboardInterrupt())
        try:
            with self.assertRaises(KeyboardInterrupt):
                _RaisingRunnerTest("test_noop").run(None)
        finally:
            unittest.TestCase.run = orig_run


if __name__ == "__main__":
    unittest.main()
