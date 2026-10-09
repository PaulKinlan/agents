#!/usr/bin/env python3
"""Focused tests for the findings store's durability and concurrency guarantees (agents-3ls).

Covers the two failure modes the bug described: a crash/truncated store being silently reset to
empty (which re-books every prior finding as new), and concurrent factory processes losing each
other's findings via last-writer-wins read-modify-write.
"""

import json
import os
os.environ.setdefault("FACTORY_ALLOW_UNPINNED_TOOLS", "1")  # agents-7bj: tests use unpinned stub tools
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lib import findings
from lib.findings import FindingsStore, StoreFileError, bind_severity

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


class TestSeverityBaselineClamp(unittest.TestCase):
    """agents-964: a candidate-bound finding is never reported BELOW the scanner's baseline."""

    def _candidate_index(self):
        return {
            "rule_ids": {"lcp-cls-unoptimized-media", "layout-thrashing-forced-reflow"},
            "paths": {"index.html", "src/a.js"},
            "snippets_at": {},
            "snippets_in": {},
            "severities": {
                ("lcp-cls-unoptimized-media", "index.html"): "medium",
                ("layout-thrashing-forced-reflow", "src/a.js"): "high",
            },
        }

    def test_bind_severity_clamps_to_the_exact_baseline(self):
        ci = self._candidate_index()
        # downgrade: low -> baseline
        self.assertEqual(bind_severity({"severity": "low"}, "lcp-cls-unoptimized-media", "index.html", ci), "medium")
        self.assertEqual(bind_severity({"severity": "low"}, "layout-thrashing-forced-reflow", "src/a.js", ci), "high")
        self.assertEqual(bind_severity({"severity": "medium"}, "layout-thrashing-forced-reflow", "src/a.js", ci), "high")
        # upgrade (including critical) is also clamped to the baseline — no drift either way
        self.assertEqual(bind_severity({"severity": "high"}, "lcp-cls-unoptimized-media", "index.html", ci), "medium")
        self.assertEqual(bind_severity({"severity": "critical"}, "layout-thrashing-forced-reflow", "src/a.js", ci), "high")

    def test_bind_severity_preserves_info_and_unbound(self):
        ci = self._candidate_index()
        # the one exception: a fixture/mock classified info (SKILL.md rule 2) is kept
        self.assertEqual(bind_severity({"severity": "info"}, "layout-thrashing-forced-reflow", "src/a.js", ci), "info")
        # unbound (no candidate) -> model's value passes through
        self.assertEqual(bind_severity({"severity": "low"}, "nope", "x.js", ci), "low")

    def test_process_run_stores_the_clamped_severity(self):
        ci = self._candidate_index()
        with tempfile.TemporaryDirectory() as d:
            store = FindingsStore("t", findings_dir=Path(d))
            try:
                processed, _, _ = store.process_run(
                    "perf-review",
                    [{"rule_id": "lcp-cls-unoptimized-media", "path": "index.html",
                      "line_number": 5, "snippet": "<img>", "severity": "low",
                      "title": "t", "description": "d"}],
                    candidate_index=ci,
                )
                self.assertEqual(processed[0]["severity"], "medium")
            finally:
                store.close()


class TestRawMatchBinding(unittest.TestCase):
    """The scanner's raw_match is indexed and bound for deterministic dummy detection (agents-3r7)."""

    def _index(self, candidates):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "candidates.json"
            path.write_text(json.dumps({"candidates": candidates}), encoding="utf-8")
            return findings.load_candidate_index(path)

    def test_raw_match_is_indexed_and_bound_by_location(self):
        ci = self._index([{
            "rule_id": "openai-key", "path": "tests/x.py", "line_number": 62,
            "snippet": 'output = "No API key found for sk-ant-secret-token-1234567890"',
            "raw_match": "sk-ant-secret-token-1234567890",
        }])
        item = {"rule_id": "openai-key", "path": "tests/x.py", "line_number": 62}
        self.assertEqual(
            findings.identity_raw_match(item, "openai-key", "tests/x.py", ci),
            "sk-ant-secret-token-1234567890")

    def test_raw_match_falls_back_when_line_number_drifts(self):
        ci = self._index([{
            "rule_id": "openai-key", "path": "tests/x.py", "line_number": 62,
            "snippet": 'key = "sk-test-placeholder"',
            "raw_match": "sk-test-placeholder",
        }])
        item = {"rule_id": "openai-key", "path": "tests/x.py", "line_number": 61}
        self.assertEqual(
            findings.identity_raw_match(item, "openai-key", "tests/x.py", ci),
            "sk-test-placeholder")

    def test_raw_match_is_none_without_a_scanner_candidate(self):
        # An empty candidate list means no deterministic pre-pass: the raw match is absent.
        ci = self._index([])
        item = {"rule_id": "openai-key", "path": "tests/x.py", "line_number": 62}
        self.assertIsNone(findings.identity_raw_match(item, "openai-key", "tests/x.py", ci))


if __name__ == "__main__":
    unittest.main()
