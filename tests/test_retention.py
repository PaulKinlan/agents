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
- every removal under the runs root goes through ``remove_recorded`` and is
  tombstoned at FILE granularity in ``retention-ledger.jsonl`` BESIDE the runs
  root (agents-dm8n round 2): the set of FILES that disappear equals the set of
  files the ledger records, a PARTIAL removal (directory survives, contents
  destroyed) is recorded with ``outcome: "partial"`` instead of passing a
  directory-level check, and the ledger survives a human clearing ``runs/``;
- every deletion primitive in the shipped source is enumerated in the deletion
  inventory below (coord's third-deleter test): a deleter this suite does not
  know about fails the gate rather than slipping past the record.
- the record tells the truth about its own limits (agents-dm8n rounds 3-4): the
  discovery text states the ledger records only removals made through it and
  names NO machine (a container hostname reads as a stable identity while
  meaning none); the record reads as best-effort about the removal window (a
  file created during it cannot be listed); and symlinks are recorded with
  their targets, with outside-tree targets explicitly NOT covered.
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
    LEDGER_NAME,
    RETAIN_AGE_DAYS_DEFAULT,
    RETAIN_COUNT_DEFAULT,
    RUNS_POINTER_NAME,
    active_grace_seconds,
    findings_retention_config,
    hillclimb_retention_ttl,
    prune_findings,
    prune_hillclimb_dirs,
    prune_run_dirs,
    RECORD_SCOPE,
    remove_recorded,
    retention_config,
    retention_ledger_path,
    run_directories,
)

_SECONDS_PER_DAY = 86400


def make_runs(tmp: str) -> Path:
    """The runs root inside a tmp tree, so the ledger lands inside the tmp tree."""
    runs = Path(tmp) / "runs"
    runs.mkdir()
    return runs


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


def snapshot_files(root: Path) -> set:
    """Relative POSIX paths of every regular file and symlink under ``root``.

    The test-side snapshot is written independently of lib/retention's (os.walk
    here, same contract: never follow symlinks), so the property compares two
    implementations of "what is here" rather than one against itself.
    """
    seen = set()
    if not root.is_dir() or root.is_symlink():
        return seen
    for dirpath, dirnames, filenames in os.walk(root):
        base = Path(dirpath)
        for name in filenames:
            seen.add((base / name).relative_to(root).as_posix())
        for name in dirnames:
            if (base / name).is_symlink():
                seen.add((base / name).relative_to(root).as_posix())
    return seen


def read_tombstones(runs_dir: Path) -> list:
    """Return the tombstone records in the ledger BESIDE ``runs_dir`` (empty when absent)."""
    ledger = retention_ledger_path(runs_dir)
    if not ledger.exists():
        return []
    return [json.loads(line)
            for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()]


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
            runs = make_runs(tmp)
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
            runs = make_runs(tmp)
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
            runs = make_runs(tmp)
            old = make_dir(runs, "old-run", 1000)
            recent = make_dir(runs, "recent-run", 2000)

            # retain is huge so only the age bound can fire.
            pruned = prune_run_dirs(runs, now=2000, retain=10**9, max_age_seconds=500)

            self.assertEqual(pruned, [old.resolve()])
            self.assertFalse(old.exists())
            self.assertTrue(recent.exists())

    def test_ttl_is_deterministic_and_exact_at_the_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = make_runs(tmp)
            at_boundary = make_dir(runs, "at-boundary", 1500)

            # age == max_age_seconds exactly: kept (prune only when strictly older).
            pruned = prune_run_dirs(runs, now=2000, retain=10**9, max_age_seconds=500)
            self.assertEqual(pruned, [])
            self.assertTrue(at_boundary.exists())


class TestPruneTombstones(unittest.TestCase):
    """agents-dm8n: a pruned run directory resolves to an explanation, not a gap.

    The property, pinned at the boundary that delivers it (prune_run_dirs via the
    remove_recorded choke point): the set of directories a prune makes disappear
    EQUALS the set of directories tombstoned with ``outcome: "removed"``. A prune
    that deletes without recording fails the equality from one side; a prune that
    records without deleting fails it from the other (both demonstrated by
    mutating the behaviour; see the round-2 bead comment for the failure counts).
    The ledger lives BESIDE the runs root (``retention_ledger_path``), never
    inside it.
    """

    def test_disappeared_directories_equal_tombstoned_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = make_runs(tmp)
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
                self.assertEqual(tombstone["outcome"], "removed")
                self.assertEqual(tombstone["reason"], "count")
                self.assertEqual(tombstone["path"],
                                 str((runs / tombstone["name"]).resolve()))
                self.assertEqual(tombstone["pruned_at"],
                                 time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)))

    def test_age_bound_removals_carry_the_age_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = make_runs(tmp)
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
            runs = make_runs(tmp)
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
            # The simulated failure deletes NOTHING, so the tombstone ledger must
            # claim no loss for it (a record of a loss that did not happen would
            # satisfy the equality falsely from the other side).
            tombstones = read_tombstones(runs)
            self.assertEqual({t["name"] for t in tombstones},
                             {d.name for d in pruned})
            self.assertNotIn(failing.name, {t["name"] for t in tombstones})

    def test_a_removal_that_deletes_but_raises_is_still_recorded(self):
        # rmtree can remove the directory and STILL raise (e.g. a late error on a
        # parent handle). The record must follow the BEHAVIOUR - the directory is
        # gone - not the exception.
        with tempfile.TemporaryDirectory() as tmp:
            runs = make_runs(tmp)
            now = 1_700_000_000.0
            doomed = make_dir(runs, "doomed", now - 100)
            real_rmtree = shutil.rmtree

            def delete_then_raise(path, *args, **kwargs):
                real_rmtree(path, *args, **kwargs)
                raise OSError("simulated late failure after deletion")

            fake_shutil = mock.Mock(wraps=shutil)
            fake_shutil.rmtree = delete_then_raise
            with mock.patch("lib.retention.shutil", fake_shutil), \
                 contextlib.redirect_stderr(io.StringIO()):
                pruned = prune_run_dirs(runs, now=now, retain=10**9,
                                        max_age_seconds=50)

            self.assertFalse(doomed.exists())
            self.assertEqual(pruned, [doomed.resolve()])
            tombstones = read_tombstones(runs)
            self.assertEqual(len(tombstones), 1)
            self.assertEqual(tombstones[0]["name"], doomed.name)
            self.assertEqual(tombstones[0]["outcome"], "removed")
            self.assertEqual(tombstones[0]["files"], ["report.json"])

    def test_tombstones_accumulate_across_prunes_and_the_ledger_is_never_inside_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = make_runs(tmp)
            now = 1_700_000_000.0
            first = [make_dir(runs, f"first-{i}", now - 200 + i) for i in range(3)]
            prune_run_dirs(runs, now=now, retain=1, max_age_seconds=float("inf"))
            second = [make_dir(runs, f"second-{i}", now - 100 + i) for i in range(3)]
            prune_run_dirs(runs, now=now + 10, retain=1,
                           max_age_seconds=float("inf"))

            ledger = retention_ledger_path(runs)
            self.assertTrue(ledger.is_file())
            tombstoned = {t["name"] for t in read_tombstones(runs)}
            # Explanations from BOTH prunes survive: resolvability is durable.
            self.assertTrue({d.name for d in first[:2]} <= tombstoned)
            self.assertTrue({d.name for d in second[:2]} <= tombstoned)
            self.assertEqual(first[2].name not in tombstoned, first[2].exists())
            # The ledger is BESIDE the runs root, never inside it: nothing under
            # runs/ is the record, so no clear of the run root can take it.
            self.assertNotIn(LEDGER_NAME, {p.name for p in runs.iterdir()})
            self.assertEqual(ledger.parent, runs.parent)

    def test_a_prune_that_removes_nothing_writes_no_tombstone(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = make_runs(tmp)
            make_dir(runs, "only-run", 1000)

            pruned = prune_run_dirs(runs, now=2000, retain=5,
                                    max_age_seconds=float("inf"))

            self.assertEqual(pruned, [])
            self.assertFalse(retention_ledger_path(runs).exists())


class TestFileGranularityTombstones(unittest.TestCase):
    """agents-dm8n round 2, finding 1: the harm is "a cited FILE cannot be
    resolved", so the property is asserted in the harm's own terms - the set of
    FILES that disappear equals the set of files the ledger records - and a
    partial removal (the directory survives while its contents are destroyed)
    is recorded, not invisible.
    """

    def test_disappeared_files_equal_recorded_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = make_runs(tmp)
            now = 1_700_000_000.0
            doomed_age = make_dir(runs, "agent-target-20260901-000000", 1000)
            (doomed_age / "nested").mkdir()
            (doomed_age / "nested" / "evidence.txt").write_text("cited\n",
                                                                encoding="utf-8")
            doomed_count = [make_dir(runs, f"agent-target-2026101{i}-000000",
                                     now - 50 + i) for i in range(3)]
            for d in doomed_count:
                (d / "model_output.txt").write_text("output\n", encoding="utf-8")
            keep = make_dir(runs, "agent-target-20261010-900000", now)
            (keep / "model_output.txt").write_text("keep\n", encoding="utf-8")
            # Writing files bumps the directory mtime; re-pin AFTER populating so
            # the injected clock drives the age/count bounds deterministically.
            os.utime(doomed_age, (1000, 1000))
            for i, d in enumerate(doomed_count):
                os.utime(d, (now - 50 + i, now - 50 + i))
            os.utime(keep, (now, now))

            before = {d.name: snapshot_files(d)
                      for d in (doomed_age, *doomed_count, keep)}

            pruned = prune_run_dirs(runs, now=now, retain=1, max_age_seconds=5000)

            self.assertEqual(set(pruned),
                             {doomed_age.resolve()}
                             | {d.resolve() for d in doomed_count})
            # THE property, at file granularity, both directions at once: every
            # file that disappeared is recorded against exactly its directory,
            # and no recorded file still exists.
            tombstones = {t["name"]: t for t in read_tombstones(runs)}
            self.assertEqual(set(tombstones),
                             {doomed_age.name} | {d.name for d in doomed_count})
            for name, held in before.items():
                if name == keep.name:
                    continue
                self.assertEqual(tombstones[name]["files"], sorted(held),
                                 f"tombstone for {name} must list exactly the "
                                 "files the directory held")
                self.assertEqual(tombstones[name]["outcome"], "removed")
                for rel in held:
                    self.assertFalse((runs / name / rel).exists())
            # The survivor's files exist and appear in NO tombstone.
            self.assertNotIn(keep.name, tombstones)
            self.assertEqual(snapshot_files(keep), before[keep.name])
            recorded = {f for t in tombstones.values() for f in t["files"]}
            disappeared = {f for name, held in before.items() if name != keep.name
                           for f in held}
            self.assertEqual(recorded, disappeared)

    def test_partial_removal_is_recorded_in_the_harms_own_terms(self):
        # The reviewer's constructed attack (agents-dm8n round 2, finding 1): a
        # permission bound makes rmtree delete the directory's CONTENTS and then
        # fail, leaving the directory present. A directory-level equality holds
        # in exactly this case (nothing disappeared at directory granularity)
        # while the cited file is gone. The record must answer at file
        # granularity: the lost files are tombstoned with outcome "partial".
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            self.skipTest("root ignores the permission bound this attack relies on")
        with tempfile.TemporaryDirectory() as tmp:
            runs = make_runs(tmp)
            now = 1_700_000_000.0
            doomed = make_dir(runs, "agent-target-20261001-000000", 1000)
            (doomed / "evidence.txt").write_text("cited\n", encoding="utf-8")
            locked = doomed / "locked"
            locked.mkdir()
            (locked / "inner.txt").write_text("stuck\n", encoding="utf-8")
            # r-x: the walk can LIST the contents (so they are in the snapshot),
            # but unlink of inner.txt needs write on locked/ and is denied.
            locked.chmod(0o500)
            # Writing files bumped the directory mtime; re-pin so the age bound fires.
            os.utime(doomed, (1000, 1000))
            try:
                with contextlib.redirect_stderr(io.StringIO()):
                    pruned = prune_run_dirs(runs, now=now, retain=10**9,
                                            max_age_seconds=50)

                # The directory SURVIVED, so it is not returned as pruned and no
                # tombstone may claim it was removed...
                self.assertTrue(doomed.exists())
                self.assertEqual(pruned, [])
                # ...but the files that were destroyed are recorded, in the harm's
                # own terms: a bead citing runs/<dir>/evidence.txt resolves to
                # "lost in a partial removal at T", not to a silent gap.
                tombstones = read_tombstones(runs)
                self.assertEqual(len(tombstones), 1)
                tombstone = tombstones[0]
                self.assertEqual(tombstone["name"], doomed.name)
                self.assertEqual(tombstone["outcome"], "partial")
                self.assertEqual(tombstone["files"],
                                 ["evidence.txt", "report.json"])
                self.assertFalse((doomed / "evidence.txt").exists())
                self.assertFalse((doomed / "report.json").exists())
                self.assertTrue((doomed / "locked" / "inner.txt").exists())

                # The survivor is retried by a later prune (it still matches the
                # age bound); once the operator clears the permission bound the
                # removal completes and the REMAINING files are recorded too. The
                # failed rmtree bumped the directory mtime; re-pin it so the age
                # bound still fires against the injected clock.
                locked.chmod(0o700)
                os.utime(doomed, (1000, 1000))
                pruned = prune_run_dirs(runs, now=now + 10, retain=10**9,
                                        max_age_seconds=50)
                self.assertEqual(pruned, [doomed.resolve()])
                self.assertFalse(doomed.exists())
                final = read_tombstones(runs)[-1]
                self.assertEqual(final["outcome"], "removed")
                self.assertEqual(final["files"], ["locked/inner.txt"])
            finally:
                if locked.exists():
                    locked.chmod(0o700)

    def test_remove_recorded_refuses_a_symlink_and_a_missing_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = make_runs(tmp)
            outside = Path(tmp) / "outside"
            outside.mkdir()
            (outside / "precious.txt").write_text("keep me\n", encoding="utf-8")
            link = runs / "run-link"
            link.symlink_to(outside, target_is_directory=True)

            with contextlib.redirect_stderr(io.StringIO()):
                self.assertFalse(remove_recorded(link, reason="age"))
                self.assertFalse(remove_recorded(runs / "never-existed",
                                                 reason="age"))

            self.assertTrue((outside / "precious.txt").exists())
            self.assertTrue(link.is_symlink())
            self.assertFalse(retention_ledger_path(runs).exists())


class TestLedgerPlacement(unittest.TestCase):
    """agents-dm8n round 2, finding 3: the record must outlive the thing it
    explains - a tombstone answers a question a BEAD asks, and beads outlive the
    run root. The ledger therefore lives BESIDE the runs root, where neither the
    automatic prune nor a human clearing the run root can reach it; and a reader
    standing on a dead citation finds the way from the citation side via
    runs/README.md.
    """

    def test_the_ledger_survives_a_human_clear_of_the_run_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runs = root / "runs"
            runs.mkdir()
            now = 1_700_000_000.0
            dirs = [make_dir(runs, f"agent-target-2026100{i}-000000", now - 100 + i)
                    for i in range(3)]
            prune_run_dirs(runs, now=now, retain=1, max_age_seconds=float("inf"))

            ledger = retention_ledger_path(runs)
            self.assertEqual(ledger, root / LEDGER_NAME)
            self.assertTrue(ledger.is_file())
            tombstoned = {t["name"]: t for t in read_tombstones(runs)}
            self.assertEqual(set(tombstoned), {d.name for d in dirs[:2]})

            # The human prune: clear the run root to reclaim disk, pointer and all.
            for entry in runs.iterdir():
                if entry.is_dir() and not entry.is_symlink():
                    shutil.rmtree(entry)
                else:
                    entry.unlink()
            self.assertEqual(list(runs.iterdir()), [])

            # The record outlives the thing it explains.
            self.assertTrue(ledger.is_file())
            survivors = {t["name"]: t for t in read_tombstones(runs)}
            self.assertEqual(survivors, tombstoned)
            # And a dead citation still resolves: a bead citing
            # runs/<dir>/report.json finds the file named in the tombstone.
            for name, tombstone in survivors.items():
                self.assertIn("report.json", tombstone["files"])

    def test_the_pointer_stands_where_a_dead_citation_leads_and_is_never_swept(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = make_runs(tmp)
            now = 1_700_000_000.0
            for i in range(3):
                make_dir(runs, f"run-{i}", now - 100 + i)

            prune_run_dirs(runs, now=now, retain=1, max_age_seconds=float("inf"))

            # A reader who followed a bead citation into runs/ and found the path
            # dead is standing HERE: the pointer names the ledger and says how to
            # resolve the citation from it.
            pointer = runs / RUNS_POINTER_NAME
            self.assertTrue(pointer.is_file())
            text = pointer.read_text(encoding="utf-8")
            self.assertIn(LEDGER_NAME, text)
            self.assertIn("../" + LEDGER_NAME, text)

            # The pointer is a regular file, so the automatic prune can never
            # sweep it (run_directories yields directories only) - it survives
            # every subsequent prune untouched.
            first_bytes = pointer.read_bytes()
            for i in range(3):
                make_dir(runs, f"later-{i}", now - 50 + i)
            prune_run_dirs(runs, now=now + 10, retain=1,
                           max_age_seconds=float("inf"))
            self.assertTrue(pointer.is_file())
            self.assertEqual(pointer.read_bytes(), first_bytes)
            self.assertNotIn(pointer.name,
                             {d.name for d in run_directories(runs)})


class TestLedgerLocalityTruth(unittest.TestCase):
    """agents-dm8n round 3, finding 1 (P1), reshaped by round 4, finding 4
    (P2): a bead is SYNCED and readable from any VM, but the ledger records
    only removals made through it. Round 3 named the machine on every line
    (``host``), but inside an ephemeral container the hostname is a random ID
    that reads as a stable machine identity while meaning none - a claim
    STRONGER than the record can stand behind. So the record's honest noun is
    THIS LEDGER: it records only its own removals, and names no machine. These
    tests assert the TEXT (the failure was that a reader is misled, not that a
    mechanism is wrong) and that no tombstone carries a machine identity.
    """

    def test_the_pointer_states_the_ledger_records_only_its_own_removals(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = make_runs(tmp)
            now = 1_700_000_000.0
            make_dir(runs, "old", now - 100)
            make_dir(runs, "new", now)
            prune_run_dirs(runs, now=now, retain=1, max_age_seconds=float("inf"))

            text = (runs / RUNS_POINTER_NAME).read_text(encoding="utf-8")
            self.assertIn("records only removals made through it", text)
            self.assertIn("THIS LEDGER", text)
            self.assertIn("NOT that the run never existed", text)
            # The record names no machine: a `host` field would read as a
            # stable machine identity while meaning none in a container.
            self.assertNotIn("`host`", text)

    def test_the_readme_states_the_ledger_is_local_and_names_no_machine(self):
        # Normalize wrapping: the assertion is about what the TEXT says, not
        # where its lines break.
        content = " ".join(
            (ROOT / "README.md").read_text(encoding="utf-8").split())
        self.assertIn("only removals made through it", content)
        self.assertIn("not that the run never existed", content)
        self.assertIn("names no machine", content)

    def test_no_tombstone_carries_a_machine_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = make_runs(tmp)
            now = 1_700_000_000.0
            make_dir(runs, "old", now - 100)
            make_dir(runs, "new", now)
            prune_run_dirs(runs, now=now, retain=1, max_age_seconds=float("inf"))

            tombstones = read_tombstones(runs)
            self.assertEqual(len(tombstones), 1)
            # Round 3 asserted the opposite (host == socket.gethostname());
            # the mutation both ways is the point of this bead's history: a
            # record must not claim more than it knows, and a container
            # hostname is not a knowable machine identity.
            self.assertNotIn("host", tombstones[0])


class TestAbsentTombstoneTruth(unittest.TestCase):
    """agents-dm8n round 4, finding 5 (P2): "no tombstone in this ledger means
    it was not removed here" is TRUE but leaves a reader unable to distinguish
    three cases that read identically: never pruned at all, pruned through
    another ledger (ledgers are local and do not sync), or pruned before this
    ledger existed. A true statement that misleads for want of one more clause
    is fixed by SAYING SO - these tests pin the sentence.
    """

    def test_the_pointer_states_the_three_readings_of_an_absent_tombstone(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = make_runs(tmp)
            now = 1_700_000_000.0
            make_dir(runs, "old", now - 100)
            make_dir(runs, "new", now)
            prune_run_dirs(runs, now=now, retain=1, max_age_seconds=float("inf"))

            text = " ".join(
                (runs / RUNS_POINTER_NAME).read_text(encoding="utf-8").split())
            self.assertIn("three readings the record cannot distinguish", text)
            self.assertIn("never pruned at all", text)
            self.assertIn("pruned before this ledger existed", text)

    def test_the_readme_states_the_three_readings_of_an_absent_tombstone(self):
        content = " ".join(
            (ROOT / "README.md").read_text(encoding="utf-8").split())
        self.assertIn("three readings the record cannot distinguish", content)
        self.assertIn("never pruned at all", content)
        self.assertIn("pruned before this ledger existed", content)


class TestRemovalWindowClaim(unittest.TestCase):
    """agents-dm8n round 3, finding 2 (P2): a file created inside the directory
    AFTER the pre-removal snapshot and BEFORE the removal finishes is destroyed
    but appears in NEITHER snapshot - the tombstone cannot list it, and no
    snapshot ordering closes the window. So the record must READ as best-effort
    where it is best-effort: every line carries its scope, and the pointer and
    README state the window plainly. These tests pin what the record CLAIMS,
    not what it cannot know.
    """

    def test_every_tombstone_carries_its_scope_on_the_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = make_runs(tmp)
            now = 1_700_000_000.0
            make_dir(runs, "old", now - 100)
            make_dir(runs, "new", now)
            prune_run_dirs(runs, now=now, retain=1, max_age_seconds=float("inf"))

            tombstones = read_tombstones(runs)
            self.assertEqual(len(tombstones), 1)
            self.assertEqual(tombstones[0]["record_scope"], RECORD_SCOPE)
            self.assertIn("best-effort", RECORD_SCOPE)
            self.assertIn("removal window", RECORD_SCOPE)

    def test_the_pointer_and_readme_state_the_window(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = make_runs(tmp)
            now = 1_700_000_000.0
            make_dir(runs, "old", now - 100)
            make_dir(runs, "new", now)
            prune_run_dirs(runs, now=now, retain=1, max_age_seconds=float("inf"))
            pointer = (runs / RUNS_POINTER_NAME).read_text(encoding="utf-8")
        self.assertIn("DURING the removal window", pointer)
        self.assertIn("best-effort", pointer)
        content = " ".join(
            (ROOT / "README.md").read_text(encoding="utf-8").split())
        self.assertIn("during* the removal window", content)
        self.assertIn("best-effort", content)

    def test_a_file_created_during_the_window_is_destroyed_but_not_claimed(self):
        # The reviewer's construction, driven through the choke point: a file
        # that appears after the snapshot and before rmtree completes is
        # destroyed, listed NOWHERE - and the record must not claim it. The
        # property pinned is honest limitation, not completeness: the ledger
        # lists only what was observed, and the line carries the scope that
        # says why that is not a completeness claim.
        with tempfile.TemporaryDirectory() as tmp:
            runs = make_runs(tmp)
            doomed = make_dir(runs, "doomed", 1000)
            (doomed / "before.txt").write_text("seen\n", encoding="utf-8")

            real_rmtree = shutil.rmtree

            def create_during_removal(path):
                (Path(path) / "created-during-removal.txt").write_text(
                    "late\n", encoding="utf-8")
                real_rmtree(path)

            with mock.patch.object(shutil, "rmtree",
                                   side_effect=create_during_removal):
                self.assertTrue(remove_recorded(doomed, reason="age"))

            self.assertFalse(doomed.exists())
            tombstones = read_tombstones(runs)
            self.assertEqual(len(tombstones), 1)
            tombstone = tombstones[0]
            self.assertEqual(tombstone["files"], ["before.txt", "report.json"])
            self.assertNotIn("created-during-removal.txt", tombstone["files"])
            self.assertEqual(tombstone["record_scope"], RECORD_SCOPE)


class TestMovedFileClaim(unittest.TestCase):
    """agents-dm8n round 4, finding 3 (P2): disappeared = before - after lists
    a file renamed AFTER the before-snapshot and BEFORE rmtree as disappeared -
    "destroyed", the list implies, when it merely survived under another name.
    The honest answer is that the file left the snapshot by a route the record
    cannot see, so the record must SAY that listed is not destroyed. The
    construction is driven through the choke point; the property pinned is
    that the claim carries its own uncertainty, not that the list changes.
    """

    def test_a_renamed_file_is_listed_but_the_record_does_not_claim_destruction(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = make_runs(tmp)
            doomed = make_dir(runs, "doomed", 1000)
            (doomed / "moved.txt").write_text("here\n", encoding="utf-8")

            def rename_then_fail(path):
                # The reviewer's race: renamed after the before-snapshot,
                # before the removal, which then fails part way.
                (Path(path) / "moved.txt").rename(Path(path) / "survivor.txt")
                raise OSError("simulated partial removal")

            with mock.patch.object(shutil, "rmtree", side_effect=rename_then_fail):
                self.assertFalse(remove_recorded(doomed, reason="age"))

            # The file was NOT destroyed - it survived under another name.
            self.assertTrue((doomed / "survivor.txt").exists())
            tombstone = read_tombstones(runs)[0]
            self.assertEqual(tombstone["outcome"], "partial")
            # moved.txt IS listed - it left the snapshot - but the record's
            # scope must not let "listed" read as "destroyed".
            self.assertIn("moved.txt", tombstone["files"])
            self.assertNotIn("survivor.txt", tombstone["files"])
            self.assertIn("moved or renamed", tombstone["record_scope"])

    def test_the_pointer_and_readme_say_a_listed_file_may_have_moved(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = make_runs(tmp)
            now = 1_700_000_000.0
            make_dir(runs, "old", now - 100)
            make_dir(runs, "new", now)
            prune_run_dirs(runs, now=now, retain=1, max_age_seconds=float("inf"))
            pointer = " ".join(
                (runs / RUNS_POINTER_NAME).read_text(encoding="utf-8").split())
        self.assertIn("moved or renamed", pointer)
        self.assertIn("must never be read as", pointer)
        content = " ".join(
            (ROOT / "README.md").read_text(encoding="utf-8").split())
        self.assertIn("moved or renamed", content)
        self.assertIn("must never be read as", content)


class TestSymlinkTombstones(unittest.TestCase):
    """agents-dm8n round 3, finding 3 (P2): os.walk YIELDS a symlink to a
    directory but does not traverse it, so a run dir containing
    symdir -> /tmp/data recorded "symdir" while a bead citing
    runs/.../symdir/evidence.txt stayed unresolvable - and the file-granularity
    equality held perfectly. The record must say what it actually saw: the
    symlink AND its target, and whether the target's contents were covered.
    """

    def test_an_external_symlink_is_recorded_with_target_and_not_claimed_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            runs = make_runs(tmp)
            external = base / "external"
            external.mkdir()
            (external / "evidence.txt").write_text("cited\n", encoding="utf-8")
            doomed = make_dir(runs, "doomed", 1000)
            (doomed / "symdir").symlink_to(external, target_is_directory=True)

            self.assertTrue(remove_recorded(doomed, reason="age"))

            self.assertFalse(doomed.exists())
            # The target's contents were never in the removed tree: rmtree
            # unlinks the LINK, and the evidence survives the removal.
            self.assertTrue((external / "evidence.txt").exists())
            tombstones = read_tombstones(runs)
            self.assertEqual(len(tombstones), 1)
            tombstone = tombstones[0]
            # The link itself disappeared with the tree and stays in files...
            self.assertIn("symdir", tombstone["files"])
            # ...but a file reachable ONLY through the link is NOT claimed as
            # removed - "this evidence moved or was never in this tree"...
            self.assertNotIn("symdir/evidence.txt", tombstone["files"])
            # ...and the symlink record says so in terms: the target is named
            # and marked outside the tree, so its contents are not covered.
            self.assertEqual(tombstone["symlinks"], [
                {"path": "symdir", "target": str(external),
                 "outside_tree": True}])

    def test_a_symlink_into_the_tree_is_marked_covered_by_the_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = make_runs(tmp)
            doomed = make_dir(runs, "doomed", 1000)
            real = doomed / "real"
            real.mkdir()
            (real / "evidence.txt").write_text("cited\n", encoding="utf-8")
            (doomed / "alias").symlink_to(real, target_is_directory=True)

            self.assertTrue(remove_recorded(doomed, reason="age"))

            tombstone = read_tombstones(runs)[0]
            self.assertEqual(tombstone["symlinks"], [
                {"path": "alias", "target": str(real),
                 "outside_tree": False}])
            # The target is inside the tree: its files ARE in files under their
            # real paths, so the record covers them - "this evidence is gone".
            self.assertIn("real/evidence.txt", tombstone["files"])
            self.assertIn("alias", tombstone["files"])


class TestFailedApplyRemovalGoesThroughTheChokePoint(unittest.TestCase):
    """agents-dm8n round 2, finding 2: factory's failed --apply cleanup deletes
    runs/hillclimb-<target>-<run_id> OUTSIDE prune_run_dirs. The record must
    follow the behaviour: that removal routes through remove_recorded, the same
    choke point the prune uses. The end-to-end pin (a real failed --apply writes
    the tombstone) lives in tests/test_hillclimb.py; this is the static pin that
    the routing cannot be reverted without this suite failing.
    """

    def test_factory_routes_the_proposal_dir_removal_through_remove_recorded(self):
        source = (ROOT / "factory").read_text(encoding="utf-8")
        self.assertIn("remove_recorded(proposal_run_dir", source)
        self.assertNotIn("shutil.rmtree(proposal_run_dir", source)


# --- The deletion inventory (coord's third-deleter test, agents-dm8n round 2) ---
#
# The record cannot follow a deleter nobody enumerated, so EVERY deletion
# primitive in the shipped source is listed here with a disposition:
#   RECORDED - the deletion IS the recorded-removal choke point (remove_recorded
#              in lib/retention.py); the record and the behaviour are one path.
#   NAMED    - deliberately NOT recorded, with the reason on record (never a
#              judgement without the search behind it). A NAMED path under the
#              runs root names what it deletes and why a bead citation can never
#              point at it; a NAMED path outside the runs root says where it is.
# A deleter added anywhere in the shipped source without an inventory entry fails
# the suite and NAMES the site; an entry whose site is removed fails too, so the
# inventory cannot drift from the code in either direction.

_PY_DELETION_PATTERNS = ("shutil.rmtree(", "os.unlink(", "os.remove(",
                         ".unlink(", "rm -rf", "rm -fr")
_SH_DELETION_PATTERNS = ("rm -rf", "rm -fr")

_DELETION_INVENTORY = (
    # (relpath, line substring, expected count, disposition, reason)
    ("factory", "tmp_file.unlink(missing_ok=True)", 2, "NAMED",
     "session.patch.tmp, the atomic-replace sibling of the run's own session.patch in the "
     "keep-edit flow (agents-nei): a transient write artifact created and removed within one "
     "run, never settled evidence; whatever survives to a prune is covered by the run "
     "directory's file-granularity tombstone."),
    ("factory", "path.unlink(missing_ok=True)", 1, "NAMED",
     "_write_run_artifact: removes a symlink a session may have planted at an artifact path "
     "before rewriting it (agents-5bn) - it deletes a planted NAME and the artifact is "
     "rewritten immediately after, so no settled state is lost."),
    ("factory", "shutil.rmtree(worktree_dir, ignore_errors=True)", 1, "NAMED",
     "_remove_session_worktree: discards the disposable git worktree INSIDE a run/proposal "
     "dir (agents-6ce). It holds a checkout of the TARGET, not run evidence; the dm8n census "
     "(bd export, 243 issues) found no bead citing a worktree path."),
    ("factory", "shutil.rmtree(_TRANSIENT_DIRS.pop(), ignore_errors=True)", 1, "NAMED",
     "_cleanup_transient_dirs: per-run socket/config dirs under /tmp (factory-sock-*, "
     "factory-pi-*), outside the runs root (agents-x8l)."),
    ("factory", "shutil.rmtree(d, ignore_errors=True)", 1, "NAMED",
     "_sweep_stale_transient_dirs: the same /tmp transient dirs, orphaned by a hard kill "
     "(agents-uxs); outside the runs root."),
    ("factory", "shutil.rmtree(sock_dir, ignore_errors=True)", 2, "NAMED",
     "the per-run egress socket dir under /tmp (agents-x8l); outside the runs root."),
    ("factory", "shutil.rmtree(pi_config_dir, ignore_errors=True)", 2, "NAMED",
     "the per-run pi provider-config dir under /tmp (agents-854): holds no secrets; outside "
     "the runs root."),
    ("factory", '(run_dir / "session.patch").unlink(missing_ok=True)', 3, "NAMED",
     "the run's own session.patch during the keep/discard flow while the run is live and "
     "unsettled (agents-nei, agents-5bn): a discarded patch never became evidence and a kept "
     "one is rewritten by the same flow. A bead citing a patch discarded mid-run would "
     "dangle - named here as a known unrecorded path rather than claimed complete."),
    ("factory", '(run_dir / "session.patch.tmp").unlink(missing_ok=True)', 1, "NAMED",
     "clears a pre-placed session.patch.tmp name before the engine runs (agents-5bn "
     "symlink defense); a planted name, not evidence."),
    ("factory", "(run_dir / ACTIVE_MARKER_NAME).unlink(missing_ok=True)", 1, "NAMED",
     "the run's own .active liveness marker at successful completion (agents-ped): a "
     "prune-guard signal, never evidence."),
    ("factory", "gemini_skills_link.unlink()", 1, "NAMED",
     "factory install: replaces the ~/.gemini skills symlink; operator home, outside the "
     "runs root."),
    ("factory", "dest.unlink()", 1, "NAMED",
     "factory install: replaces per-skill symlinks under ~/.pi, ~/.claude and ~/.agents; "
     "outside the runs root."),
    ("lib/retention.py", "shutil.rmtree(directory)", 1, "RECORDED",
     "remove_recorded IS the recorded-removal choke point (agents-dm8n round 2): the "
     "deletion and its file-granularity tombstone are one code path, and every removal of a "
     "citation-bearing directory under the runs root goes through it."),
    ("lib/retention.py", "resolved.unlink()", 1, "NAMED",
     "prune_findings: findings/ report pruning under its own byte budget (agents-0ti). "
     "Findings files are not run evidence; the dm8n census found no bead citing them, and "
     "coord's scope for this bead excludes findings tombstoning."),
    ("lib/retention.py", "shutil.rmtree(entry)", 1, "NAMED",
     "prune_hillclimb_dirs: sweeps STALE runs/hillclimb-*/ proposal dirs (agents-0ti). The "
     "dm8n census (bd export, 243 issues) found no bead citing a hillclimb dir and coord's "
     "scope excludes hillclimb tombstoning - named here so the exclusion is a decision on "
     "record, not an oversight. If hillclimb dirs ever become citable evidence, this entry "
     "must become RECORDED."),
    ("lib/credential_broker.py", "os.unlink(unix_path)", 2, "NAMED",
     "the credential broker's UNIX socket files under the per-run /tmp dir (agents-x8l); "
     "outside the runs root."),
    ("lib/egress_proxy.py", "os.unlink(self.socket_path)", 2, "NAMED",
     "the egress proxy's UNIX socket file under the per-run /tmp dir (agents-x8l); outside "
     "the runs root."),
    ("lib/findings.py", "os.unlink(tmp_path)", 1, "NAMED",
     "the findings store's atomic-replace temp file; a write artifact, not evidence."),
    ("lib/findings.py", "fragment.unlink(missing_ok=True)", 1, "NAMED",
     "the findings fragment temp name before an atomic replace; a planted directory fails "
     "closed instead - no settled state is deleted."),
    ("lib/sandbox.py", "token_path.unlink()", 1, "NAMED",
     "the sandbox's per-invocation token file; outside the runs root."),
    ("lib/scheduler.py", "dest_path.unlink(missing_ok=True)", 1, "NAMED",
     "launchd plist replacement under ~/Library/LaunchAgents; outside the runs root."),
    ("lib/scheduler.py", "dest_service.unlink(missing_ok=True)", 1, "NAMED",
     "systemd unit replacement under ~/.config/systemd; outside the runs root."),
    ("lib/scheduler.py", "dest_timer.unlink(missing_ok=True)", 1, "NAMED",
     "systemd timer replacement under ~/.config/systemd; outside the runs root."),
    ("lib/scheduler.py", "dest_path.unlink()", 1, "NAMED",
     "launchd plist removal on schedule uninstall; outside the runs root."),
    ("lib/scheduler.py", "dest_service.unlink()", 1, "NAMED",
     "systemd unit removal on schedule uninstall; outside the runs root."),
    ("lib/scheduler.py", "dest_timer.unlink()", 1, "NAMED",
     "systemd timer removal on schedule uninstall; outside the runs root."),
    ("tools/stage_site.py", "shutil.rmtree(out)", 1, "NAMED",
     "replaces the staged Pages _site/ output directory; build output, outside the runs root."),
    ("agents/docs-write/scripts/prepare_docs_fixes.py", "os.unlink(drift_out)", 1, "NAMED",
     "docs-write's own temp output inside its tmp workspace; outside the runs root."),
    (".github/actions/factory/fetch_factory.sh", 'rm -rf "$DEST"', 1, "NAMED",
     "the CI action replacing its own checked-out DEST in the runner workspace; never the "
     "operator's factory tree."),
)


def _scanned_sources(root: Path):
    """Every shipped source file that could harbour a deleter (tests excluded)."""
    candidates = [root / "factory"]
    for sub in ("lib", "tools", "agents"):
        candidates += sorted((root / sub).rglob("*.py"))
    candidates += sorted(p for p in root.rglob("*.sh")
                         if "tests" not in p.relative_to(root).parts)
    github = root / ".github"
    candidates += sorted(github.rglob("*.yml")) + sorted(github.rglob("*.yaml"))
    skip = {".git", ".beads", "node_modules", "_site", "__pycache__"}
    for path in candidates:
        if any(part in skip for part in path.parts):
            continue
        yield path.relative_to(root).as_posix(), path


def _deletion_sites(root: Path) -> list:
    """(relpath, stripped line) for every deletion-primitive line in shipped source."""
    sites = []
    for rel, path in _scanned_sources(root):
        patterns = (_SH_DELETION_PATTERNS
                    if path.suffix in {".sh", ".yml", ".yaml"}
                    else _PY_DELETION_PATTERNS)
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if any(pattern in stripped for pattern in patterns):
                sites.append((rel, stripped))
    return sites


def _inventory_errors(sites: list) -> list:
    """Every way the deletion inventory can drift from the source, as failure lines."""
    errors = []
    used = [0] * len(_DELETION_INVENTORY)
    for rel, line in sites:
        matches = [i for i, (path, substring, _count, _disp, _reason)
                   in enumerate(_DELETION_INVENTORY)
                   if path == rel and substring in line]
        if not matches:
            errors.append(
                f"unenumerated deletion site: {rel}: {line} — route citation-bearing "
                "removals through lib.retention.remove_recorded, or add a NAMED "
                "inventory entry with the search behind it")
        for i in matches:
            used[i] += 1
    for i, (path, substring, expected, disposition, _reason) in enumerate(
            _DELETION_INVENTORY):
        if used[i] != expected:
            errors.append(
                f"stale inventory entry: {path} {substring!r} is {disposition} for "
                f"{expected} site(s) but matched {used[i]}")
        if disposition == "RECORDED" and path != "lib/retention.py":
            errors.append(
                f"RECORDED entry outside the choke-point module: {path} {substring!r}")
    return errors


class TestRunRootDeletionInventory(unittest.TestCase):
    """Coord's third-deleter test (agents-dm8n round 2): the fix must survive a
    deleter we have NOT found. The recording choke point cannot be bypassed
    silently because this inventory enumerates every deletion primitive in the
    shipped source; a new one fails the gate and is named, in the full gate
    always and in the fast gate for any factory or lib change (the factory arm
    maps here - see tools/fast-gate.sh).
    """

    def test_every_deletion_primitive_in_the_shipped_source_is_enumerated(self):
        self.assertEqual(_inventory_errors(_deletion_sites(ROOT)), [])

    def test_an_unenumerated_deleter_fails_the_inventory_and_is_named(self):
        sites = _deletion_sites(ROOT) + [
            ("factory", "shutil.rmtree(some_new_path, ignore_errors=True)")]
        errors = _inventory_errors(sites)
        self.assertEqual(len(errors), 1)
        self.assertIn("shutil.rmtree(some_new_path", errors[0])
        self.assertIn("factory", errors[0])

    def test_a_deleter_removed_without_updating_the_inventory_fails(self):
        sites = [(rel, line) for rel, line in _deletion_sites(ROOT)
                 if "session.patch.tmp" not in line]
        errors = _inventory_errors(sites)
        self.assertTrue(any("session.patch.tmp" in error for error in errors),
                        f"the stale entry must be named: {errors}")


class TestInProgressSafety(unittest.TestCase):
    def test_excluded_run_is_never_pruned(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = make_runs(tmp)
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
            runs = make_runs(tmp)
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
            runs = make_runs(tmp)
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
            # The symlink itself is recorded in the tombstone's file list: it was
            # part of what disappeared with the directory.
            tombstones = read_tombstones(runs)
            self.assertEqual(len(tombstones), 1)
            self.assertEqual(sorted(tombstones[0]["files"]),
                             ["escape", "report.json"])

    def test_missing_runs_dir_is_a_no_op(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp) / "does-not-exist"
            self.assertEqual(prune_run_dirs(runs), [])
            self.assertEqual(list(run_directories(runs)), [])


class TestActiveRunGuard(unittest.TestCase):
    def test_fresh_active_marker_protects_a_long_running_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = make_runs(tmp)
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
            runs = make_runs(tmp)
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
            runs = make_runs(tmp)
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
            # directory this prune removed resolves to an explanation, at file
            # granularity, in the ledger BESIDE the runs root.
            tombstoned = {t["name"]: t for t in read_tombstones(runs)}
            self.assertEqual(set(tombstoned), {f"old-{i:02d}" for i in range(22)})
            for tombstone in tombstoned.values():
                self.assertEqual(tombstone["outcome"], "removed")
                self.assertEqual(tombstone["files"], ["report.json"])
            self.assertEqual(retention_ledger_path(runs), root / LEDGER_NAME)


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
