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
- a fresh ``.active`` marker protects an in-progress run from being swept by a
  concurrent run, while a stale marker is eventually swept (bounded grace);
- the hill-climb ``runs/hillclimb-*/`` proposal dir is never pruned;
- the default configuration is bounded;
- pruning never follows a symlink out of ``runs/`` and tolerates unexpected
  contents (non-directory files);
- the ``factory`` ``create_run_dir`` hook actually applies the policy and marks the
  new run active (so removing the hook fails the suite);
- every directory a prune removes is recorded as a tombstone line in
  ``runs/pruned.jsonl`` and nothing else is (agents-dm8n): the set of directories
  that disappear equals the set of explanations written, so a bead citation to a
  pruned run directory resolves instead of dangling.
"""

import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.retention import (  # noqa: E402
    ACTIVE_GRACE_SECONDS_DEFAULT,
    ACTIVE_MARKER_NAME,
    FINDINGS_RETENTION_BYTES_DEFAULT,
    HILLCLIMB_RETENTION_AGE_DAYS_DEFAULT,
    PRUNE_LOG_NAME,
    RETAIN_AGE_DAYS_DEFAULT,
    RETAIN_COUNT_DEFAULT,
    active_grace_seconds,
    findings_retention_config,
    hillclimb_retention_ttl,
    prune_findings,
    prune_hillclimb_dirs,
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


def make_finding(findings_dir: Path, name: str, mtime: float, size: int = 100) -> Path:
    """Create a findings/ file of ``size`` bytes and pin its mtime."""
    path = findings_dir / name
    path.write_bytes(b"x" * size)
    os.utime(path, (mtime, mtime))
    return path


def make_hillclimb(runs_dir: Path, name: str, mtime: float) -> Path:
    """Create a hill-climb proposal directory and pin its mtime."""
    path = runs_dir / name
    path.mkdir(parents=True)
    (path / "session.patch").write_text("patch\n", encoding="utf-8")
    os.utime(path, (mtime, mtime))
    return path


def read_tombstones(runs_dir: Path) -> list:
    """Return the tombstone records in ``runs/pruned.jsonl`` (empty when absent)."""
    log = runs_dir / PRUNE_LOG_NAME
    if not log.exists():
        return []
    return [json.loads(line)
            for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]


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


class TestPruneTombstones(unittest.TestCase):
    """agents-dm8n: a pruned run directory resolves to an explanation, not a gap.

    The property, pinned at the boundary that delivers it (prune_run_dirs): the set
    of directories a prune makes disappear EQUALS the set of tombstone records it
    writes. A prune that deletes without recording fails the equality from one side;
    a prune that records without deleting fails it from the other. The ledger lives
    at ``runs/pruned.jsonl`` and is itself never swept.
    """

    def test_disappeared_directories_equal_tombstoned_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            now = 1_700_000_000.0
            dirs = [make_dir(runs, f"agent-target-202610{i:02d}-000000", now - 100 + i)
                    for i in range(6)]
            before = {d.name for d in runs.iterdir() if d.is_dir()}

            pruned = prune_run_dirs(runs, now=now, retain=2,
                                    max_age_seconds=float("inf"))

            after = {d.name for d in runs.iterdir() if d.is_dir()}
            disappeared = before - after
            self.assertEqual(disappeared, {d.name for d in pruned})
            tombstones = read_tombstones(runs)
            # THE property: everything that vanished has exactly one explanation,
            # and nothing that survived is claimed as pruned.
            self.assertEqual({t["name"] for t in tombstones}, disappeared)
            self.assertEqual(len(tombstones), len(disappeared))
            for tombstone in tombstones:
                self.assertEqual(tombstone["reason"], "count")
                self.assertEqual(tombstone["path"],
                                 str((runs / tombstone["name"]).resolve()))
                self.assertEqual(tombstone["pruned_at"],
                                 time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)))

    def test_age_bound_removals_carry_the_age_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            old = make_dir(runs, "agent-target-20260901-000000", 1000)
            make_dir(runs, "agent-target-20261010-000000", 2000)

            pruned = prune_run_dirs(runs, now=2000, retain=10**9, max_age_seconds=500)

            self.assertEqual(pruned, [old.resolve()])
            tombstones = read_tombstones(runs)
            self.assertEqual(len(tombstones), 1)
            self.assertEqual(tombstones[0]["name"], old.name)
            self.assertEqual(tombstones[0]["reason"], "age")

    def test_a_failed_removal_leaves_no_tombstone(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            now = 1_700_000_000.0
            dirs = [make_dir(runs, f"run-{i:02d}", now - 100 + i) for i in range(4)]
            failing = dirs[0].resolve()
            real_rmtree = shutil.rmtree

            def flaky_rmtree(path, *args, **kwargs):
                if Path(path) == failing:
                    raise OSError("simulated removal failure")
                return real_rmtree(path, *args, **kwargs)

            fake_shutil = mock.Mock(wraps=shutil)
            fake_shutil.rmtree = flaky_rmtree
            with mock.patch("lib.retention.shutil", fake_shutil), \
                 contextlib.redirect_stderr(io.StringIO()):
                pruned = prune_run_dirs(runs, now=now, retain=1,
                                        max_age_seconds=float("inf"))

            self.assertTrue(failing.exists())
            tombstones = read_tombstones(runs)
            # No tombstone may claim a removal that did not happen.
            self.assertEqual({t["name"] for t in tombstones},
                             {d.name for d in pruned})
            self.assertNotIn(failing.name, {t["name"] for t in tombstones})

    def test_tombstones_accumulate_across_prunes_and_the_log_is_never_swept(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            now = 1_700_000_000.0
            first = [make_dir(runs, f"first-{i}", now - 200 + i) for i in range(3)]
            prune_run_dirs(runs, now=now, retain=1, max_age_seconds=float("inf"))
            second = [make_dir(runs, f"second-{i}", now - 100 + i) for i in range(3)]
            prune_run_dirs(runs, now=now + 10, retain=1,
                           max_age_seconds=float("inf"))

            log = runs / PRUNE_LOG_NAME
            self.assertTrue(log.is_file())
            tombstoned = {t["name"] for t in read_tombstones(runs)}
            # Explanations from BOTH prunes survive: resolvability is durable, and
            # the ledger (a regular file, not a run directory) is never swept.
            self.assertTrue({d.name for d in first[:2]} <= tombstoned)
            self.assertTrue({d.name for d in second[:2]} <= tombstoned)
            self.assertEqual(first[2].name not in tombstoned, first[2].exists())
            self.assertIn(PRUNE_LOG_NAME, {p.name for p in runs.iterdir()})

    def test_a_prune_that_removes_nothing_writes_no_tombstone(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            make_dir(runs, "only-run", 1000)

            pruned = prune_run_dirs(runs, now=2000, retain=5,
                                    max_age_seconds=float("inf"))

            self.assertEqual(pruned, [])
            self.assertFalse((runs / PRUNE_LOG_NAME).exists())


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

    def test_hillclimb_proposal_dir_is_not_a_run_directory(self):
        # agents-ped P0: the hill-climb proposal dir uses the REAL name
        # runs/hillclimb-<target>-<run_id>, not a literal "worktrees" dir. Skipping only
        # the phantom name masked this and let the live proposal be swept mid-run.
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            proposal = runs / "hillclimb-fauxmium-20260101-000000"
            proposal.mkdir()
            old = make_dir(runs, "old-run", 1)

            pruned = prune_run_dirs(runs, now=1000, retain=0, max_age_seconds=1)

            self.assertTrue(proposal.exists())
            self.assertFalse(old.exists())
            self.assertEqual(pruned, [old.resolve()])

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


class TestActiveRunGuard(unittest.TestCase):
    def test_fresh_active_marker_protects_a_long_running_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            # The run dir itself is ancient (so the age bound alone would prune it),
            # but its marker is fresh: a concurrent run must not sweep it.
            active = make_dir(runs, "active-run", 1)
            marker = active / ACTIVE_MARKER_NAME
            marker.write_text("active\n", encoding="utf-8")
            os.utime(marker, (2000, 2000))
            os.utime(active, (1, 1))  # the run dir is ancient; only the marker is fresh
            old = make_dir(runs, "old-run", 2)

            pruned = prune_run_dirs(runs, now=2000, retain=0, max_age_seconds=1,
                                    active_grace=100)

            self.assertTrue(active.exists())
            self.assertFalse(old.exists())
            self.assertEqual(pruned, [old.resolve()])

    def test_stale_active_marker_is_swept(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            stale = make_dir(runs, "stale-run", 1)
            marker = stale / ACTIVE_MARKER_NAME
            marker.write_text("active\n", encoding="utf-8")
            os.utime(marker, (1000, 1000))  # 1000s older than `now`, beyond grace=100
            os.utime(stale, (1, 1))

            pruned = prune_run_dirs(runs, now=2000, retain=10**9, max_age_seconds=1,
                                    active_grace=100)

            self.assertFalse(stale.exists())
            self.assertEqual(pruned, [stale.resolve()])

    def test_non_regular_file_marker_does_not_count_as_active(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            fake = make_dir(runs, "fake-active", 1)
            (fake / ACTIVE_MARKER_NAME).mkdir()  # a directory is not a marker
            os.utime(fake, (1, 1))

            pruned = prune_run_dirs(runs, now=2000, retain=0, max_age_seconds=1,
                                    active_grace=100)

            self.assertFalse(fake.exists())
            self.assertEqual(pruned, [fake.resolve()])


class TestActiveGraceConfig(unittest.TestCase):
    def test_default_grace_is_bounded(self):
        self.assertGreater(ACTIVE_GRACE_SECONDS_DEFAULT, 0)
        self.assertEqual(active_grace_seconds({}), ACTIVE_GRACE_SECONDS_DEFAULT)

    def test_env_override(self):
        self.assertEqual(
            active_grace_seconds({"FACTORY_RUN_ACTIVE_GRACE_SECONDS": "123"}), 123)

    def test_unparseable_or_non_positive_falls_back_to_default(self):
        self.assertEqual(
            active_grace_seconds({"FACTORY_RUN_ACTIVE_GRACE_SECONDS": "soon"}),
            ACTIVE_GRACE_SECONDS_DEFAULT)
        self.assertEqual(
            active_grace_seconds({"FACTORY_RUN_ACTIVE_GRACE_SECONDS": "0"}),
            ACTIVE_GRACE_SECONDS_DEFAULT)


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
            # The freshly allocated run is marked active so a concurrent run cannot sweep
            # it (agents-ped P2).
            self.assertTrue((new_dir / ACTIVE_MARKER_NAME).exists())
            # The three newest pre-existing runs survive, plus the new run.
            remaining = sorted(d.name for d in runs.iterdir() if d.is_dir())
            self.assertEqual(
                remaining,
                sorted(["old-22", "old-23", "old-24", new_dir.name]),
            )
            # The production hook delivers the tombstones too (agents-dm8n): every
            # directory this prune removed resolves to an explanation.
            tombstoned = {t["name"] for t in read_tombstones(runs)}
            self.assertEqual(tombstoned, {f"old-{i:02d}" for i in range(22)})


class TestFindingsRetentionConfig(unittest.TestCase):
    def test_default_budget_is_bounded(self):
        self.assertGreater(FINDINGS_RETENTION_BYTES_DEFAULT, 0)
        self.assertEqual(findings_retention_config({}), FINDINGS_RETENTION_BYTES_DEFAULT)

    def test_env_override(self):
        self.assertEqual(
            findings_retention_config({"FACTORY_FINDINGS_RETENTION_BYTES": "2048"}), 2048)

    def test_unparseable_or_non_positive_falls_back_to_default(self):
        self.assertEqual(
            findings_retention_config({"FACTORY_FINDINGS_RETENTION_BYTES": "many"}),
            FINDINGS_RETENTION_BYTES_DEFAULT)
        self.assertEqual(
            findings_retention_config({"FACTORY_FINDINGS_RETENTION_BYTES": "0"}),
            FINDINGS_RETENTION_BYTES_DEFAULT)


class TestPruneFindings(unittest.TestCase):
    def test_prunes_oldest_derived_reports_beyond_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings = Path(tmp)
            old = make_finding(findings, "target-a-history.jsonl", 1000, size=1000)
            mid = make_finding(findings, "target-a-delta.md", 2000, size=1000)
            new = make_finding(findings, "target-b-delta.md", 3000, size=1000)

            # Total 3000, budget 2500: only the oldest is pruned.
            pruned = prune_findings(findings, budget_bytes=2500)

            self.assertEqual(pruned, [old.resolve()])
            self.assertFalse(old.exists())
            self.assertTrue(mid.exists())
            self.assertTrue(new.exists())

    def test_authoritative_store_lock_and_committed_config_are_never_pruned(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings = Path(tmp)
            protected = [
                make_finding(findings, "target.json", 1000, size=10),
                make_finding(findings, "target.json.lock", 1000, size=10),
                make_finding(findings, ".gitkeep", 1000, size=10),
                make_finding(findings, "suppressions.yaml", 1000, size=10),
            ]
            report = make_finding(findings, "target-delta.md", 2000, size=100)

            # Budget 0: everything prunable must go, the authoritative/committed files stay.
            pruned = prune_findings(findings, budget_bytes=0)

            self.assertEqual(pruned, [report.resolve()])
            self.assertFalse(report.exists())
            for path in protected:
                self.assertTrue(path.exists())

    def test_store_and_machine_reports_are_protected_while_ledgers_are_prunable(self):
        # .json files (the authoritative <target>.json store and the regenerable machine
        # reports <target>-line.json / <target>-bundle-baseline.json) are rewritten in
        # place, so they stay; only the append-only .jsonl ledger is pruned.
        with tempfile.TemporaryDirectory() as tmp:
            findings = Path(tmp)
            store = make_finding(findings, "target.json", 1000, size=10)
            line = make_finding(findings, "target-line.json", 1000, size=100)
            ledger = make_finding(findings, "target-hillclimb-ledger.jsonl", 1000, size=100)

            pruned = prune_findings(findings, budget_bytes=0)

            # .json (store and machine reports) are protected; the .jsonl ledger is pruned.
            self.assertEqual(pruned, [ledger.resolve()])
            self.assertFalse(ledger.exists())
            self.assertTrue(store.exists())
            self.assertTrue(line.exists())

    def test_symlinks_are_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            findings = base / "findings"
            findings.mkdir()
            outside = base / "outside.txt"
            outside.write_text("precious\n", encoding="utf-8")
            link = findings / "target-delta.md"
            link.symlink_to(outside)
            old = make_finding(findings, "target-history.jsonl", 1000, size=100)

            pruned = prune_findings(findings, budget_bytes=0)

            self.assertEqual(pruned, [old.resolve()])
            self.assertTrue(link.is_symlink())
            self.assertTrue(outside.exists())

    def test_excluded_file_is_never_pruned(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings = Path(tmp)
            keep = make_finding(findings, "keep-delta.md", 1000, size=100)
            old = make_finding(findings, "old-delta.md", 2000, size=100)

            pruned = prune_findings(findings, budget_bytes=0, exclude={keep})

            self.assertEqual(pruned, [old.resolve()])
            self.assertTrue(keep.exists())

    def test_under_budget_is_a_no_op(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings = Path(tmp)
            make_finding(findings, "a-delta.md", 1000, size=100)
            make_finding(findings, "b-history.jsonl", 2000, size=100)
            self.assertEqual(prune_findings(findings, budget_bytes=10**9), [])

    def test_missing_findings_dir_is_a_no_op(self):
        self.assertEqual(prune_findings(Path("/nonexistent/findings"), budget_bytes=0), [])


class TestHillclimbRetentionTTL(unittest.TestCase):
    def test_default_ttl_is_bounded(self):
        self.assertGreater(HILLCLIMB_RETENTION_AGE_DAYS_DEFAULT, 0)
        self.assertEqual(hillclimb_retention_ttl({}),
                         HILLCLIMB_RETENTION_AGE_DAYS_DEFAULT * _SECONDS_PER_DAY)

    def test_env_override(self):
        self.assertEqual(hillclimb_retention_ttl({"FACTORY_HILLCLIMB_RETENTION_AGE_DAYS": "3"}),
                         3 * _SECONDS_PER_DAY)

    def test_unparseable_or_non_positive_falls_back(self):
        self.assertEqual(hillclimb_retention_ttl({"FACTORY_HILLCLIMB_RETENTION_AGE_DAYS": "soon"}),
                         HILLCLIMB_RETENTION_AGE_DAYS_DEFAULT * _SECONDS_PER_DAY)
        self.assertEqual(hillclimb_retention_ttl({"FACTORY_HILLCLIMB_RETENTION_AGE_DAYS": "0"}),
                         HILLCLIMB_RETENTION_AGE_DAYS_DEFAULT * _SECONDS_PER_DAY)


class TestPruneHillclimbDirs(unittest.TestCase):
    def test_sweeps_stale_proposals_and_keeps_recent(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            stale = make_hillclimb(runs, "hillclimb-target-20260101-000000", 1000)
            recent = make_hillclimb(runs, "hillclimb-target-20260109-000000", 2000)

            pruned = prune_hillclimb_dirs(runs, now=2000, max_age_seconds=500)

            self.assertEqual(pruned, [stale.resolve()])
            self.assertFalse(stale.exists())
            self.assertTrue(recent.exists())

    def test_ttl_is_exact_at_the_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            at_boundary = make_hillclimb(runs, "hillclimb-target-x", 1500)

            pruned = prune_hillclimb_dirs(runs, now=2000, max_age_seconds=500)

            self.assertEqual(pruned, [])
            self.assertTrue(at_boundary.exists())

    def test_non_hillclimb_dirs_are_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            run_dir = make_dir(runs, "run-123", 1)

            pruned = prune_hillclimb_dirs(runs, now=2000, max_age_seconds=1)

            self.assertEqual(pruned, [])
            self.assertTrue(run_dir.exists())

    def test_excluded_proposal_is_never_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            keep = make_hillclimb(runs, "hillclimb-keep", 1000)

            pruned = prune_hillclimb_dirs(runs, now=2000, max_age_seconds=500, exclude={keep})

            self.assertEqual(pruned, [])
            self.assertTrue(keep.exists())


if __name__ == "__main__":
    unittest.main()
