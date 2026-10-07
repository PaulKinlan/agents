#!/usr/bin/env python3
"""Run-directory retention (agents-ped): secret-bearing artifacts stay bounded.

The factory writes raw scanner matches (candidates.json, prompt.txt) and model
output (model_output.txt, rejected_report.json) into per-run directories under
``runs/``. Those artifacts can embed matched secret values, so they must not
accumulate without bound. These tests pin the retention contract:

- the count bound keeps the newest N and prunes the rest;
- the in-progress run (excluded) is never pruned;
- the age/TTL bound is deterministic (explicit mtimes and an injected clock,
  never sleeps);
- the default configuration is bounded;
- pruning never follows a symlink out of ``runs/`` and tolerates unexpected
  contents (non-directory files, the hill-climb ``worktrees/`` staging dir);
- the ``factory`` ``create_run_dir`` hook actually applies the policy (so
  removing the hook fails the suite).
"""

import contextlib
import importlib.machinery
import importlib.util
import io
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.retention import (  # noqa: E402
    RETAIN_AGE_DAYS_DEFAULT,
    RETAIN_COUNT_DEFAULT,
    prune_run_dirs,
    retention_config,
    run_directories,
)

_SECONDS_PER_DAY = 86400


def make_dir(runs_dir: Path, name: str, mtime: float) -> Path:
    """Create a run directory (with a marker file) and pin its mtime."""
    path = runs_dir / name
    path.mkdir(parents=True)
    (path / "report.json").write_text("{}\n", encoding="utf-8")
    os.utime(path, (mtime, mtime))
    return path


class TestRetentionConfig(unittest.TestCase):
    def test_defaults_are_bounded(self):
        retain, age = retention_config({})
        self.assertGreater(retain, 0)
        self.assertGreater(age, 0)
        self.assertEqual(retain, RETAIN_COUNT_DEFAULT)
        self.assertEqual(age, RETAIN_AGE_DAYS_DEFAULT * _SECONDS_PER_DAY)

    def test_env_override(self):
        retain, age = retention_config({
            "FACTORY_RUN_RETENTION": "5",
            "FACTORY_RUN_RETENTION_AGE_DAYS": "7",
        })
        self.assertEqual(retain, 5)
        self.assertEqual(age, 7 * _SECONDS_PER_DAY)

    def test_unparseable_values_fall_back_to_defaults(self):
        retain, age = retention_config({
            "FACTORY_RUN_RETENTION": "many",
            "FACTORY_RUN_RETENTION_AGE_DAYS": "soon",
        })
        self.assertEqual(retain, RETAIN_COUNT_DEFAULT)
        self.assertEqual(age, RETAIN_AGE_DAYS_DEFAULT * _SECONDS_PER_DAY)


class TestCountBound(unittest.TestCase):
    def test_keeps_newest_n_and_prunes_the_rest(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            dirs = [make_dir(runs, f"run-{i:02d}", 1000 + i) for i in range(5)]

            pruned = prune_run_dirs(runs, now=2000, retain=2,
                                    max_age_seconds=float('inf'))

            self.assertEqual(set(pruned), {d.resolve() for d in dirs[:3]})
            for d in dirs[:3]:
                self.assertFalse(d.exists())
            for d in dirs[3:]:
                self.assertTrue(d.exists())

    def test_default_prune_is_bounded_by_retain_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            total = RETAIN_COUNT_DEFAULT + 3
            # Distinct, recent mtimes (all within the default TTL) so only the
            # count bound fires.
            dirs = [make_dir(runs, f"run-{i:03d}", time.time() - (total - i) * 10)
                    for i in range(total)]

            pruned = prune_run_dirs(runs)

            self.assertEqual(len(pruned), 3)
            survivors = [d for d in dirs if d.exists()]
            self.assertEqual(len(survivors), RETAIN_COUNT_DEFAULT)
            self.assertEqual(set(survivors), set(dirs[-RETAIN_COUNT_DEFAULT:]))


class TestAgeBound(unittest.TestCase):
    def test_ttl_prunes_older_than_the_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            old = make_dir(runs, "old-run", 1000)
            recent = make_dir(runs, "recent-run", 2000)

            # retain is huge so only the age bound can fire.
            pruned = prune_run_dirs(runs, now=2000, retain=10**9, max_age_seconds=500)

            self.assertEqual(pruned, [old.resolve()])
            self.assertFalse(old.exists())
            self.assertTrue(recent.exists())

    def test_ttl_is_deterministic_and_exact_at_the_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            at_boundary = make_dir(runs, "at-boundary", 1500)

            # age == max_age_seconds exactly: kept (prune only when strictly older).
            pruned = prune_run_dirs(runs, now=2000, retain=10**9, max_age_seconds=500)
            self.assertEqual(pruned, [])
            self.assertTrue(at_boundary.exists())


class TestInProgressSafety(unittest.TestCase):
    def test_excluded_run_is_never_pruned(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            in_progress = make_dir(runs, "in-progress", 1)  # ancient mtime
            old = make_dir(runs, "old", 2)

            pruned = prune_run_dirs(runs, now=1000, retain=0, max_age_seconds=1,
                                    exclude={in_progress})

            self.assertNotIn(in_progress.resolve(), pruned)
            self.assertTrue(in_progress.exists())
            self.assertIn(old.resolve(), pruned)
            self.assertFalse(old.exists())


class TestSymlinkAndUnexpectedContents(unittest.TestCase):
    def test_top_level_symlink_is_not_followed_or_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            runs = base / "runs"
            runs.mkdir()
            outside = base / "outside"
            outside.mkdir()
            (outside / "precious.txt").write_text("keep me\n", encoding="utf-8")

            link = runs / "run-link"
            link.symlink_to(outside, target_is_directory=True)
            old = make_dir(runs, "old-run", 1)

            pruned = prune_run_dirs(runs, now=1000, retain=0, max_age_seconds=1)

            self.assertFalse(old.exists())
            self.assertTrue(link.is_symlink())
            self.assertTrue((outside / "precious.txt").exists())
            self.assertNotIn(link.resolve(), pruned)
            self.assertNotIn(outside.resolve(), pruned)

    def test_non_directory_files_are_left_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            log = runs / "schedule-secret-scan.stdout.log"
            log.write_text("stdout\n", encoding="utf-8")
            old = make_dir(runs, "old-run", 1)

            pruned = prune_run_dirs(runs, now=1000, retain=0, max_age_seconds=1)

            self.assertFalse(old.exists())
            self.assertTrue(log.exists())
            self.assertEqual(pruned, [old.resolve()])

    def test_worktrees_staging_dir_is_not_a_run_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            worktrees = runs / "worktrees"
            worktrees.mkdir()
            old = make_dir(runs, "old-run", 1)

            pruned = prune_run_dirs(runs, now=1000, retain=0, max_age_seconds=1)

            self.assertTrue(worktrees.exists())
            self.assertFalse(old.exists())

    def test_a_run_dir_with_a_symlink_inside_is_removed_without_following_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            runs = base / "runs"
            runs.mkdir()
            outside = base / "outside"
            outside.mkdir()
            (outside / "precious.txt").write_text("keep me\n", encoding="utf-8")

            old = make_dir(runs, "old-run", 1)
            (old / "escape").symlink_to(outside, target_is_directory=True)

            pruned = prune_run_dirs(runs, now=1000, retain=0, max_age_seconds=1)

            self.assertFalse(old.exists())
            self.assertTrue((outside / "precious.txt").exists())
            self.assertEqual(pruned, [old.resolve()])

    def test_missing_runs_dir_is_a_no_op(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp) / "does-not-exist"
            self.assertEqual(prune_run_dirs(runs), [])
            self.assertEqual(list(run_directories(runs)), [])


class TestFactoryHook(unittest.TestCase):
    """The dispatcher actually applies retention on run creation (fail-on-revert)."""

    @classmethod
    def setUpClass(cls):
        loader = importlib.machinery.SourceFileLoader(
            "factory_cli_retention", str(ROOT / "factory"))
        spec = importlib.util.spec_from_loader("factory_cli_retention", loader)
        cls.factory_cli = importlib.util.module_from_spec(spec)
        loader.exec_module(cls.factory_cli)

    def test_create_run_dir_prunes_and_excludes_the_new_dir(self):
        factory_cli = self.factory_cli
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runs = root / "runs"
            runs.mkdir()
            # 25 pre-existing runs, distinct recent mtimes so only the count bound
            # (set to 3 below) fires.
            base = time.time() - 1000
            dirs = [make_dir(runs, f"old-{i:02d}", base + i * 10) for i in range(25)]

            with mock.patch.object(factory_cli, "FACTORY_ROOT", root), \
                 mock.patch.dict(os.environ, {"FACTORY_RUN_RETENTION": "3"}), \
                 contextlib.redirect_stdout(io.StringIO()):
                new_dir = factory_cli.create_run_dir("agent", "target", "20260101-000000")

            self.assertTrue(new_dir.exists())
            # The three newest pre-existing runs survive, plus the new run.
            remaining = sorted(d.name for d in runs.iterdir() if d.is_dir())
            self.assertEqual(
                remaining,
                sorted(["old-22", "old-23", "old-24", new_dir.name]),
            )


if __name__ == "__main__":
    unittest.main()
