#!/usr/bin/env python3
"""Focused tests for the findings store's durability and concurrency guarantees (agents-3ls).

Covers the two failure modes the bug described: a crash/truncated store being silently reset to
empty (which re-books every prior finding as new), and concurrent factory processes losing each
other's findings via last-writer-wins read-modify-write.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lib import findings
from lib.findings import FindingsStore, StoreFileError

FACTORY_ROOT = Path(__file__).resolve().parent.parent


# A standalone writer, run as a real subprocess so the flock is exercised across process
# boundaries (threads in one process would not model the scheduled-timer-vs-manual-vs-CI
# contention the bug describes). It rendezvous with its sibling before touching the store so
# the no-lock race is deterministic: each reads the store before either saves, and the last
# writer wins.
_WRITER = r"""
import sys
import time
from pathlib import Path

from lib.findings import FindingsStore

findings_dir = Path(sys.argv[1])
agent = sys.argv[2]
rule_id = sys.argv[3]
my_id = sys.argv[4]
sleep_s = float(sys.argv[5])
barrier = Path(sys.argv[6])

(barrier / f"ready-{my_id}").write_text("1", encoding="utf-8")
while not ((barrier / "ready-0").exists() and (barrier / "ready-1").exists()):
    time.sleep(0.01)

store = FindingsStore("concurrent", findings_dir=findings_dir)
time.sleep(sleep_s)  # widen the load->save window: without flock both writers sit inside it
store.process_run(agent, [{
    "rule_id": rule_id, "path": "p.js", "line_number": 1,
    "snippet": rule_id, "severity": "low", "title": rule_id,
}])
store.close()
"""


class TestStoreLoadCorruption(unittest.TestCase):
    def test_missing_store_loads_empty(self):
        """A genuinely absent store keeps the documented empty-start behaviour."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = FindingsStore("target", findings_dir=Path(tmpdir))
            self.assertEqual(store.data, {"target": "target", "findings": {}})
            store.close()

    def test_truncated_store_raises_instead_of_resetting(self):
        """A half-written store must not be silently reset to empty (duplicate re-booking)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            findings_dir = Path(tmpdir)
            (findings_dir / "target.json").write_text(
                '{"target": "target", "findings": {"abc', encoding="utf-8",
            )
            with self.assertRaises(StoreFileError):
                FindingsStore("target", findings_dir=findings_dir)

    def test_corrupt_store_raises_instead_of_resetting(self):
        """A store that is not valid JSON must not be silently reset to empty."""
        with tempfile.TemporaryDirectory() as tmpdir:
            findings_dir = Path(tmpdir)
            (findings_dir / "target.json").write_text("this is not json", encoding="utf-8")
            with self.assertRaises(StoreFileError):
                FindingsStore("target", findings_dir=findings_dir)

    def test_non_object_store_raises_instead_of_resetting(self):
        """A store that parses but is not the expected object shape must not be reset."""
        with tempfile.TemporaryDirectory() as tmpdir:
            findings_dir = Path(tmpdir)
            (findings_dir / "target.json").write_text("[]", encoding="utf-8")
            with self.assertRaises(StoreFileError):
                FindingsStore("target", findings_dir=findings_dir)


class TestFindingRecordShape(unittest.TestCase):
    def test_findings_do_not_track_github_lifecycle_events(self):
        """agents-eyo: findings no longer publish to public GitHub issues, so the per-finding
        lifecycle-event list is gone. `github_issue` stays: promote_issue links a public-input
        issue to a bead and reads that receipt."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with FindingsStore("file-only", findings_dir=Path(tmpdir)) as store:
                item = {"rule_id": "r", "path": "p.js", "line_number": 1,
                        "snippet": "s", "severity": "high", "title": "t"}
                for _ in range(3):
                    store.process_run("lint", [item])
                    store.process_run("lint", [])
                finding, = store.data["findings"].values()
                self.assertNotIn("github_pending_transitions", finding)
                self.assertIsNone(finding["github_issue"])


class TestAtomicSave(unittest.TestCase):
    def test_save_is_atomic_and_leaves_no_temp_files(self):
        """save() writes valid JSON and does not leave a half-written temp file behind."""
        with tempfile.TemporaryDirectory() as tmpdir:
            findings_dir = Path(tmpdir)
            store = FindingsStore("target", findings_dir=findings_dir)
            store.process_run("docs-drift", [{
                "rule_id": "r", "path": "p.js", "line_number": 1,
                "snippet": "s", "severity": "low", "title": "t",
            }])
            store.close()

            data = json.loads((findings_dir / "target.json").read_text(encoding="utf-8"))
            self.assertEqual(len(data["findings"]), 1)
            leftovers = list(findings_dir.glob("target.json.*.tmp"))
            self.assertEqual(leftovers, [])


class TestCliStoreCleanup(unittest.TestCase):
    def test_close_runs_when_candidate_loading_processing_or_save_fails(self):
        """A held flock cannot survive an exception on any CLI path (agents-559/3ls)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            raw = Path(tmpdir) / "input.json"
            raw.write_text('{"findings": []}', encoding="utf-8")
            candidates = Path(tmpdir) / "candidates.json"
            candidates.write_text('{}', encoding="utf-8")
            argv = ["--target", "fixture", "--agent", "lint", "--input", str(raw),
                    "--candidates", str(candidates), "--sink", "file"]
            for failure in ("candidate", "process", "save"):
                with self.subTest(failure=failure):
                    store = mock.Mock()
                    store.process_run.return_value = ([], {key: 0 for key in findings.DELTA_KEYS}, [])
                    if failure == "process":
                        store.process_run.side_effect = RuntimeError("process failed")
                    if failure == "save":
                        store.save.side_effect = RuntimeError("save failed")
                    with mock.patch.object(findings, "FindingsStore", return_value=store), \
                         mock.patch.object(findings, "load_candidate_index",
                                           side_effect=RuntimeError("candidate failed") if failure == "candidate" else None), \
                         mock.patch.object(findings, "dispatch_to_sink", return_value={}):
                        with self.assertRaisesRegex(RuntimeError, failure + " failed"):
                            findings.main(argv)
                    store.close.assert_called_once()


class TestConcurrentWriters(unittest.TestCase):
    def test_two_concurrent_writers_do_not_lose_findings(self):
        """Two processes mutating one store must both survive (flock serializes the window)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            findings_dir = Path(tmpdir) / "findings"
            findings_dir.mkdir()
            barrier = Path(tmpdir) / "barrier"
            barrier.mkdir()

            env = dict(os.environ)
            env["PYTHONPATH"] = str(FACTORY_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
            procs = []
            for index, (agent, rule) in enumerate([("writer-a", "rule-a"), ("writer-b", "rule-b")]):
                procs.append(subprocess.Popen(
                    [sys.executable, "-c", _WRITER, str(findings_dir), agent, rule,
                     str(index), "0.4", str(barrier)],
                    cwd=str(FACTORY_ROOT), env=env,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                ))
            try:
                for proc in procs:
                    out, err = proc.communicate(timeout=60)
                    self.assertEqual(proc.returncode, 0, f"writer failed:\n{out}\n{err}")
            finally:
                for proc in procs:
                    if proc.poll() is None:
                        proc.kill()

            store = FindingsStore("concurrent", findings_dir=findings_dir)
            try:
                findings = store.data["findings"]
                self.assertEqual(len(findings), 2)
                self.assertEqual({f["agent"] for f in findings.values()}, {"writer-a", "writer-b"})
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
