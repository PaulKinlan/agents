#!/usr/bin/env python3
"""Focused tests for the findings store's durability and concurrency guarantees (agents-3ls).

Covers the two failure modes the bug described: a crash/truncated store being silently reset to
empty (which re-books every prior finding as new), and concurrent factory processes losing each
other's findings via last-writer-wins read-modify-write.
"""

import gc
import hashlib
import io
import json
import os
os.environ.setdefault("FACTORY_ALLOW_UNPINNED_TOOLS", "1")  # agents-7bj: tests use unpinned stub tools
import subprocess
import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest import mock

from lib import findings
from lib.candidate_identity import assign_candidate_ids
from lib.findings import (FindingsStore, StoreFileError, bind_severity, CANDIDATE_PROMPT_SLICE,
                          candidate_coverage, read_candidate_count, read_candidate_locations,
                          read_candidate_paths, read_presented_candidate_ids,
                          repair_cited_candidate_id, repair_cited_candidate_ids,
                          station_has_verdict, station_is_incomplete)
from lib.redaction import redact_finding, redact_for_storage

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


class TestDurableVerificationDispositions(unittest.TestCase):
    """agents-b5ec7: verdict evidence survives the run directory without becoming a finding."""

    def test_verified_metadata_is_bounded_scrubbed_and_upserted(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            store = FindingsStore("target", findings_dir=directory)
            row = {"candidate_id": "c0", "rule_id": "r1", "path": "a.js",
                   "line_number": 7, "verdict": "disproved", "confidence": "high",
                   "disproving_factors": ["auth_gate"], "reasoning": "SECRET unrecognised model prose",
                   "extra": "do not persist me"}
            store.record_verifications("vuln-verify", [row])
            store.process_run("vuln-verify", [])
            stored = json.loads((directory / "target.json").read_text())
            self.assertEqual(stored["findings"], {})
            self.assertEqual(len(stored["verifications"]), 1)
            self.assertNotIn("SECRET", json.dumps(stored))
            self.assertNotIn("do not persist me", json.dumps(stored))
            recorded = next(iter(stored["verifications"].values()))
            self.assertEqual((recorded["verdict"], recorded["disproving_factors"]),
                             ("disproved", ["auth_gate"]))
            store.close()

            reopened = FindingsStore("target", findings_dir=directory)
            reopened.record_verifications("vuln-verify", [{**row, "verdict": "verified"}])
            reopened.process_run("vuln-verify", [])
            updated = json.loads((directory / "target.json").read_text())
            self.assertEqual(len(updated["verifications"]), 1,
                             "a changed verdict must update the candidate's one durable record")
            self.assertEqual(next(iter(updated["verifications"].values()))["verdict"], "verified")
            reopened.close()

    def test_protected_store_caps_verifications_without_fabricating_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = FindingsStore("target", findings_dir=Path(tmp))
            store.record_verifications("vuln-verify", [
                {"candidate_id": f"c{i}", "verdict": "disproved", "confidence": "low"}
                for i in range(505)])
            store.process_run("vuln-verify", [])
            data = json.loads((Path(tmp) / "target.json").read_text())
            self.assertEqual(len(data["verifications"]), 500)
            self.assertEqual(data["findings"], {})
            store.close()


class TestVerificationDispositionReports(unittest.TestCase):
    """agents-xwzct: show verifier work without relabeling dispositions as findings."""

    def test_all_disproved_cli_and_line_report_keep_counts_separate_from_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.mkdir()
            (target / "a.js").write_text("x = 1\n", encoding="utf-8")
            raw = root / "report.json"
            raw.write_text(json.dumps({"summary": "verified", "findings": [], "verifications": [
                {"candidate_id": f"c{i}", "rule_id": "r1", "path": "a.js",
                 "line_number": i + 1, "verdict": "disproved", "confidence": "high",
                 "reasoning": "SECRET unrecognised prose"} for i in range(3)]}), encoding="utf-8")
            fragment = root / "delta.json"
            with mock.patch.object(findings, "FACTORY_ROOT", root), \
                 mock.patch("sys.stdout", new_callable=io.StringIO) as output:
                findings.main(["--target", "target", "--agent", "vuln-verify",
                               "--input", str(raw), "--sink", "file", "--target-dir", str(target),
                               "--station-only", "--fragment", str(fragment)])
            station_delta = (root / "findings/target-vuln-verify-delta.md").read_text()
            summary = (root / "findings/target-vuln-verify-summary.md").read_text()
            self.assertIn("3 candidate disposition(s)", output.getvalue())
            self.assertIn("3 candidate disposition(s)", station_delta)
            self.assertIn("3 candidate disposition(s)", summary)
            self.assertIn("3 disproved", station_delta)
            self.assertIn("not false-positive findings", station_delta)
            self.assertIn("Clean Delta", station_delta)
            self.assertIn("| **0** | **0** | **0** | 0 | 0 | 0 |", station_delta)
            self.assertNotIn("SECRET", station_delta + summary + output.getvalue())
            stored = json.loads((root / "findings/target.json").read_text())
            self.assertEqual(stored["findings"], {})
            self.assertEqual(len(stored["verifications"]), 3)
            self.assertEqual(json.loads(fragment.read_text())["verification_counts"],
                             {"disproved": 3, "unverifiable": 0, "verified": 0})

            station = {"station": "vuln-verify", "status": "PASS", "findings_count": 0,
                       "criticals": 0, "candidates_presented": 3, "candidates_accounted": 3,
                       "candidate_identity": "identity-matched", "complete": True,
                       "fragment": str(fragment)}
            findings.write_line_report("target", "audit", [station], findings_dir=root / "findings")
            line_delta = (root / "findings/target-delta.md").read_text()
            self.assertIn("3 candidate disposition(s)", line_delta)
            self.assertIn("Clean Delta", line_delta)
            self.assertEqual(json.loads((root / "findings/target-line.json").read_text())[
                "verification_counts"]["disproved"], 3)

    def test_duplicate_candidate_counts_only_its_last_verdict(self):
        with tempfile.TemporaryDirectory() as tmp:
            with FindingsStore("target", findings_dir=Path(tmp)) as store:
                counts = store.record_verifications("vuln-verify", [
                    {"candidate_id": "c0", "verdict": "disproved"},
                    {"candidate_id": "c0", "verdict": "unverifiable"}])
                self.assertEqual(counts, {"disproved": 0, "unverifiable": 1, "verified": 0})

    def test_non_verifier_and_legacy_fragment_do_not_invent_disposition_counts(self):
        stats = {key: 0 for key in findings.DELTA_KEYS}
        report = findings._render_delta_report("target", [], stats, [], verification_counts=None)
        self.assertNotIn("candidate disposition(s)", report)
        self.assertNotIn("candidate disposition(s)", findings._render_delta_report(
            "target", [], stats, [], verification_counts={}))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fragment = root / "legacy.json"
            fragment.write_text(json.dumps({"stats": stats, "findings": [], "fixed": [],
                                            "sinks": {}}), encoding="utf-8")
            findings.write_line_report("target", "audit", [
                {"station": "legacy", "status": "PASS", "fragment": str(fragment)}],
                findings_dir=root)
            self.assertNotIn("verification_counts", json.loads((root / "target-line.json").read_text()))
            self.assertNotIn("candidate disposition(s)", (root / "target-delta.md").read_text())


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


class TestAbandonedStoreReleasesItsLock(unittest.TestCase):
    def test_a_store_that_is_never_closed_does_not_leak_its_lock_handle(self):
        """agents-b81j: "a caller that forgets close()" is the ORDINARY case for a library.

        Five test files forgot, and each leaked the store's lock handle (`target.json.lock`) to the
        file object's finalizer, which CPython reports as `ResourceWarning: unclosed file`. The
        store owns the handle, so it releases it at teardown without the caller's help. Load-
        bearing: with `close()` reached only from `__del__`, dropping that finalizer makes this
        fail instead of printing a warning nobody gates on. The error filter raises inside the file
        object's own finalizer, so the failure arrives as an UNRAISABLE exception - hence the hook,
        because an unraisable warning does not fail a test run by itself (a `-W error` discovery
        run of the leaking suite printed 12 of them and still exited 0).
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            findings_dir = Path(tmpdir)
            unraisable = []
            previous_hook = sys.unraisablehook
            sys.unraisablehook = unraisable.append
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("error", ResourceWarning)
                    store = FindingsStore("abandoned", findings_dir=findings_dir)
                    lock_file = store._lock_path
                    self.assertTrue(store._lock_acquired, "the store never took the lock")
                    del store  # the caller that forgets: no close(), no context manager
                    gc.collect()
            finally:
                sys.unraisablehook = previous_hook
            self.assertTrue(lock_file.exists(), "the abandoned store never opened its lock file")
            self.assertEqual(
                [u for u in unraisable if issubclass(u.exc_type, ResourceWarning)], [],
                "the abandoned store leaked its lock handle to the garbage collector",
            )
            # And the flock went with it: a second store on the same target acquires at once.
            replacement = FindingsStore("abandoned", findings_dir=findings_dir, lock_timeout=0)
            try:
                self.assertIn("findings", replacement.data)
            finally:
                replacement.close()


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


class TestCrossStationCandidateIdsStaySeparate(unittest.TestCase):
    """agents-g3vnf, MEASURED: two stations may share a candidate_id, and their rows must stay TWO.

    A `candidate_id` names a CANDIDATE, not a finding: lib/candidate_identity builds it from
    (rule_id, path, match_text, ordinal) with no station in the inputs, and ADR agents-ltuf goes
    further - vuln-triage COPIES the anchor row's persisted id on purpose. So a shared id across
    stations is the design, not a collision. A finding's identity is
    sha256(agent:rule_id:path:snippet) and the retire sweep is agent-scoped, so "collapsing" two
    stations' rows would corrupt every per-station delta and every per-station QA scorecard. This
    test is here because a bead asked for that collapse (agents-g3vnf) and the answer is no, with the
    behaviour measured rather than argued - the mutation that fails it is deduplicating on
    candidate_id.

    The second assertion is the falsified half of the same bead: the critical routing of the
    security-sensitive row is NOT caused by the shared id. It is the fail-closed policy for an
    unverifiable rule label (agents-94f), and a row carrying no candidate id at all routes the same
    way.
    """

    CANDIDATE_ID = "b937944bf90b5d3c"  # the id the nightly reported on both stations

    def _index(self, d):
        path = Path(d) / "candidates.json"
        path.write_text(json.dumps({"candidate_id_scheme": 1, "candidates": [{
            "rule_id": "qa-agent-high-wontfix-noise", "path": "agents/secret-scan/SKILL.md",
            "line_number": 52, "snippet": "wontfix_rate: 0.35",
            "raw_match": "wontfix_rate: 0.35", "candidate_id": self.CANDIDATE_ID,
        }]}), encoding="utf-8")
        return findings.load_candidate_index(path)

    def _item(self, rule_id):
        return {"rule_id": rule_id, "path": "agents/secret-scan/SKILL.md", "line_number": 52,
                "snippet": "wontfix_rate: 0.35", "severity": "medium", "title": "t",
                "description": "d", "anchor_candidate_id": self.CANDIDATE_ID}

    def test_two_stations_sharing_a_candidate_id_keep_two_rows_and_two_deltas(self):
        with tempfile.TemporaryDirectory() as d:
            store = FindingsStore("t", findings_dir=Path(d))
            try:
                index = self._index(d)
                qa, qa_stats, _ = store.process_run(
                    "qa-station", [self._item("qa-agent-high-wontfix-noise")], candidate_index=index)
                vt, vt_stats, _ = store.process_run(
                    "vuln-triage", [self._item("vuln-triage-shared-anchor")], candidate_index=index)

                # Two identities, both bound to the SAME emitted id, both new: the shared id does
                # not merge them - only the fingerprint decides identity, and `agent` is in it.
                self.assertNotEqual(qa[0]["fingerprint"], vt[0]["fingerprint"])
                self.assertEqual(qa[0]["candidate_id"], vt[0]["candidate_id"])
                self.assertEqual((qa_stats["new"], vt_stats["new"]), (1, 1))
                self.assertEqual(len(store.data["findings"]), 2)

                # And a second identical run books nothing new for either station: anchored rows
                # are stable, which is why the nightly's one-off wave was the ANNOUNCED re-key
                # (agents-pb02), not a recurring false-new.
                _, qa_again, _ = store.process_run(
                    "qa-station", [self._item("qa-agent-high-wontfix-noise")], candidate_index=index)
                _, vt_again, _ = store.process_run(
                    "vuln-triage", [self._item("vuln-triage-shared-anchor")], candidate_index=index)
                self.assertEqual((qa_again["new"], vt_again["new"]), (0, 0))
                self.assertEqual((qa_again["unchanged"], vt_again["unchanged"]), (1, 1))
            finally:
                store.close()

    def test_the_critical_routing_is_the_agent_class_not_the_shared_id(self):
        """The falsified causal claim: remove the id and the security row still routes critical."""
        with tempfile.TemporaryDirectory() as d:
            store = FindingsStore("t", findings_dir=Path(d))
            try:
                without_id = {k: v for k, v in self._item("vuln-triage-shared-anchor").items()
                              if k != "anchor_candidate_id"}
                processed, _, _ = store.process_run("vuln-triage", [without_id])
                self.assertIsNone(processed[0].get("candidate_id"))
                self.assertEqual(processed[0]["routing_severity"], "critical")
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


class TestStoreRedactsRawMaterialAtRest(unittest.TestCase):
    """agents-4zg: the store is read-only-bound into the sandboxed engine, so it must not
    hold raw credential material a run for target A could read about target B."""

    def test_credential_findings_are_redacted_in_the_store(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = FindingsStore("target-a", findings_dir=Path(tmpdir))
            secret = "ghp_" + "A" * 36  # a GitHub PAT shape
            item = {"rule_id": "github-pat", "path": "src/config.js", "line_number": 1,
                    "snippet": secret, "raw_match": secret, "severity": "critical",
                    "title": "GitHub PAT", "description": f"found {secret}",
                    "remediation": "rotate"}
            store.process_run("secret-scan", [item])
            _, stats, _ = store.process_run("secret-scan", [item])  # same raw input re-runs
            store.close()

            data = json.loads((Path(tmpdir) / "target-a.json").read_text(encoding="utf-8"))
            rec = next(iter(data["findings"].values()))
            for field in ("raw_match", "snippet", "title", "description", "remediation"):
                self.assertNotIn(secret, str(rec.get(field, "")), field)
            self.assertTrue(rec.get("fingerprint"), "fingerprint (lifecycle identity) must survive")
            # The lifecycle is stable despite the redaction: the raw-snippet fingerprint still
            # dedupes the second identical run as unchanged, not a new finding.
            self.assertEqual(stats["unchanged"], 1, stats)
            self.assertEqual(len(data["findings"]), 1)

    def test_non_credential_findings_keep_their_metadata(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = FindingsStore("target-b", findings_dir=Path(tmpdir))
            store.process_run("docs-drift", [{
                "rule_id": "missing-doc", "path": "README.md", "line_number": 3,
                "snippet": "TODO update", "severity": "low", "title": "Stale docs",
            }])
            store.close()
            data = json.loads((Path(tmpdir) / "target-b.json").read_text(encoding="utf-8"))
            rec = next(iter(data["findings"].values()))
            self.assertEqual(rec["title"], "Stale docs")  # non-credential prose survives

    def test_security_finding_prose_is_withheld_regardless_of_pattern(self):
        """A threat-model finding can quote a secret whose shape no pattern recognises
        (a DB URL with a password). At rest its prose and raw context are withheld wholesale,
        never merely pattern-masked."""
        url = "postgres://appuser:N7v8Q9r0S1t2U3v4W5x6@db.internal/app"
        with tempfile.TemporaryDirectory() as tmpdir:
            store = FindingsStore("target-c", findings_dir=Path(tmpdir))
            store.process_run("threat-model", [{
                "rule_id": "tm-db-auth-boundary", "path": "db/internal.py", "line_number": 3,
                "snippet": f"  conn = '{url}'", "raw_match": None, "severity": "high",
                "title": "DB auth boundary",
                "description": f"The app connects as {url} with no TLS.",
                "remediation": "Add TLS.",
            }])
            store.close()
            data = json.loads((Path(tmpdir) / "target-c.json").read_text(encoding="utf-8"))
            rec = next(iter(data["findings"].values()))
            for field in ("raw_match", "snippet", "title", "description", "remediation"):
                self.assertNotIn("N7v8Q9r0", str(rec.get(field, "")), field)

    def test_legacy_store_is_scrubbed_on_load(self):
        """A store written before the fix still exposes its old raw_match on disk. Loading it
        scrubs the in-memory records, and the next save() persists the redacted copy."""
        secret = "ghp_" + "A" * 36
        legacy = {
            "target": "target-legacy",
            "findings": {"fp1": {
                "fingerprint": "fp1", "agent": "secret-scan", "rule_id": "github-pat",
                "path": "x.js", "line_number": 1, "snippet": secret, "raw_match": secret,
                "severity": "critical", "title": "GitHub PAT",
                "description": f"found {secret}", "remediation": "rotate",
                "state": "new", "change": "new", "dispatched_sinks": [],
                "github_issue": None, "first_seen": "x", "last_seen": "x",
                "suppression_reason": None,
            }},
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            store_file = Path(tmpdir) / "target-legacy.json"
            store_file.write_text(json.dumps(legacy), encoding="utf-8")
            store = FindingsStore("target-legacy", findings_dir=Path(tmpdir))
            in_memory = next(iter(store.data["findings"].values()))
            self.assertNotIn("A" * 36, str(in_memory), "load must scrub in-memory records")
            store.save()
            store.close()
            on_disk = json.loads(store_file.read_text(encoding="utf-8"))
            rec = next(iter(on_disk["findings"].values()))
            self.assertNotIn("A" * 36, str(rec), "save must persist the redacted copy")

    def test_delivery_receipts_persist_without_raw_fields(self):
        """dispatch_to_sink mutates the returned finding's receipts; save() must persist those
        receipts while still dropping the raw text (nothing raw is written back)."""
        secret = "ghp_" + "A" * 36
        with tempfile.TemporaryDirectory() as tmpdir:
            store = FindingsStore("target-d", findings_dir=Path(tmpdir))
            processed, _, _ = store.process_run("secret-scan", [{
                "rule_id": "github-pat", "path": "src/x.js", "line_number": 1,
                "snippet": secret, "raw_match": secret, "severity": "critical",
                "title": "GitHub PAT", "description": f"found {secret}", "remediation": "rotate",
            }])
            # dispatch_to_sink mutates the returned record's delivery receipts in place.
            processed[0]["dispatched_sinks"].append("beads")
            processed[0]["github_issue"] = 12345
            store.save()
            store.close()
            on_disk = json.loads((Path(tmpdir) / "target-d.json").read_text(encoding="utf-8"))
            saved = next(iter(on_disk["findings"].values()))
            self.assertEqual(saved["dispatched_sinks"], ["beads"], "receipt must persist")
            self.assertEqual(saved["github_issue"], 12345, "github_issue must persist")
            self.assertNotIn("A" * 36, str(saved), "raw fields must stay redacted")


class TestIdentityAttribution(unittest.TestCase):
    """Every row records WHICH KEY produced its fingerprint (agents-x9my).

    A fingerprint is sha256(agent:rule id:path:snippet), and the snippet half falls back to the
    model's re-quoted prose whenever the scanner candidate cannot be bound. The cause is NOT the
    order the binder runs in - it is that the rule-keyed lookups need the model to echo the
    scanner's rule id, which it usually does not (28% of rows in the real store carry the blanked
    label "unclassified"). Re-wording the prose then books the SAME unchanged finding as both new
    and fixed in one run, which step 2 stopped by binding identity to the candidate at the finding's
    LOCATION when that location is unambiguous.

    Recording the key is what makes a "Fixed" line falsifiable: without it an operator cannot tell a
    real fix from a reword, which is why the teams reading these reports concluded that nothing may
    be closed on one.
    """

    def _index(self, candidates):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "candidates.json"
            path.write_text(json.dumps({"candidates": candidates}), encoding="utf-8")
            return findings.load_candidate_index(path)

    def _finding(self, **overrides):
        item = {"rule_id": "scanner-rule", "path": "a.py", "line_number": 2,
                "snippet": "model wording one", "severity": "low", "title": "t",
                "description": "d", "remediation": "r"}
        item.update(overrides)
        return item

    def _run(self, td, items, candidate_index):
        store = FindingsStore("target", findings_dir=Path(td))
        try:
            processed, stats, fixed = store.process_run(
                "vuln-discovery", items, candidate_index=candidate_index)
        finally:
            store.close()
        return processed, stats, fixed

    def test_the_source_names_the_exact_candidate_key(self):
        ci = self._index([{"rule_id": "scanner-rule", "path": "a.py", "line_number": 2,
                           "snippet": "scanner text"}])
        snippet, source = findings.identity_snippet_binding(
            self._finding(), "scanner-rule", "a.py", ci)
        self.assertEqual((snippet, source), ("scanner text", "candidate-exact"))

    def test_the_source_distinguishes_the_unique_and_similar_fallbacks(self):
        unique = self._index([{"rule_id": "scanner-rule", "path": "a.py", "line_number": 2,
                               "snippet": "only candidate"}])
        drifted = self._finding(line_number=99)
        self.assertEqual(
            findings.identity_snippet_binding(drifted, "scanner-rule", "a.py", unique),
            ("only candidate", "candidate-unique"))

        ambiguous = self._index([
            {"rule_id": "scanner-rule", "path": "a.py", "line_number": 2, "snippet": "alpha"},
            {"rule_id": "scanner-rule", "path": "a.py", "line_number": 40, "snippet": "beta gamma"},
        ])
        quoted = self._finding(line_number=99, snippet="the line reads beta gamma here")
        self.assertEqual(
            findings.identity_snippet_binding(quoted, "scanner-rule", "a.py", ambiguous),
            ("beta gamma", "candidate-similar-by-model-snippet"))

    def test_a_model_selected_candidate_is_named_as_such_and_not_graded_as_stable(self):
        """The name says the mechanism, and the delta repeats the grading (coord ruling).

        `candidate-similar-by-model-snippet` is the scanner's text chosen by the MODEL's wording, so
        re-wording can pick a different candidate. A reader must not have to know this module's
        vocabulary to know whether a Fixed line is evidence, so the unstable sources are marked in
        the rendered line itself.
        """
        self.assertNotIn("candidate-similar-by-model-snippet", findings.IDENTITY_STABLE_SOURCES)
        record = dict(self._finding(), identity_source="candidate-similar-by-model-snippet",
                      change="new", state="new", fingerprint="f" * 64)
        stable = dict(self._finding(), identity_source="candidate-exact",
                      change="new", state="new", fingerprint="g" * 64)
        stats = {key: 0 for key in findings.DELTA_KEYS}
        stats["new"] = 2
        report = findings._render_delta_report("target", [record, stable], stats, [])
        self.assertIn("`candidate-similar-by-model-snippet` (reword-unstable", report)
        self.assertIn("`candidate-exact`\n", report)
        self.assertNotIn("`candidate-exact` (reword-unstable", report)

    def test_an_untrusted_rule_id_binds_by_location(self):
        """Step 2: a label that bind nothing no longer drags identity back to the model's prose.

        The rule-keyed lookups need the model to echo the scanner's rule id. When it does not, the
        scanner candidate is still identifiable by LOCATION, and binding to it keeps identity off
        the model's wording - which is what makes the fingerprint survive re-wording.
        """
        ci = self._index([{"rule_id": "scanner-rule", "path": "a.py", "line_number": 2,
                           "snippet": "scanner text"}])
        with tempfile.TemporaryDirectory() as td:
            processed, _, _ = self._run(
                td, [self._finding(rule_id="model-invented-label")], ci)

            record = processed[0]
            self.assertEqual(record["rule_id"], "unclassified")
            self.assertEqual(record["identity_source"], "unmatched-rule-location-unique")
            self.assertEqual(record["snippet"], "model wording one")

    def test_an_untraceable_location_still_falls_back_to_prose(self):
        """The honest limit: with nothing unambiguous to bind to, identity IS the model's prose.

        Two candidates at one path, neither matching the line the model named, leave no candidate
        that can be shown to be the right one - so the row keeps the model's snippet and says so.
        Binding to one of them anyway would be a guess presented as provenance.
        """
        ci = self._index([
            {"rule_id": "scanner-rule", "path": "a.py", "line_number": 2, "snippet": "alpha"},
            {"rule_id": "scanner-rule", "path": "a.py", "line_number": 40, "snippet": "beta"},
        ])
        with tempfile.TemporaryDirectory() as td:
            record = self._run(td, [self._finding(rule_id="model-invented-label", line_number=99)],
                               ci)[0][0]
            self.assertEqual(record["identity_source"], "model-snippet")

    def test_the_location_fallback_is_refused_when_the_run_has_two_findings_at_that_path(self):
        """The run-level guard, and the reason it exists: a collapse LOSES a finding.

        Two rows sharing a path and a blanked rule label would be handed the same scanner snippet,
        get the same fingerprint, and one would be dropped as a duplicate of the other. Refusing
        the fallback keeps both, each on its own prose, which is the old behaviour applied only
        where it is needed.
        """
        ci = self._index([{"rule_id": "scanner-rule", "path": "a.py", "line_number": 2,
                           "snippet": "scanner text"}])
        with tempfile.TemporaryDirectory() as td:
            processed, _, _ = self._run(td, [
                self._finding(rule_id="invented-a", snippet="first claim about the sink"),
                self._finding(rule_id="invented-b", snippet="second claim about the sink"),
            ], ci)

            self.assertEqual(len(processed), 2, "both findings must survive")
            self.assertEqual([r["identity_source"] for r in processed],
                             ["model-snippet", "model-snippet"])
            self.assertNotEqual(processed[0]["fingerprint"], processed[1]["fingerprint"])

    def test_a_stable_location_beats_the_model_text_when_both_could_bind(self):
        """Preference order: prefer the binding the model's wording cannot change.

        With two candidates under one rule, the model's prose could pick either one - which is how
        a re-wording moved a fingerprint. Where the model's own line points at exactly one
        candidate, that is a sharper and stabler statement, so it wins over the text match.
        """
        ci = self._index([
            {"rule_id": "scanner-rule", "path": "a.py", "line_number": 2, "snippet": "alpha"},
            {"rule_id": "scanner-rule", "path": "a.py", "line_number": 40, "snippet": "beta gamma"},
        ])
        with tempfile.TemporaryDirectory() as td:
            record = self._run(td, [self._finding(rule_id="invented", line_number=2,
                                                  snippet="quotes beta gamma")], ci)[0][0]
            self.assertEqual(record["identity_source"], "unmatched-rule-location-unique")
            # The stored snippet stays the MODEL's text; what changed is which candidate the
            # fingerprint was computed from, so assert the fingerprint against "alpha".
            self.assertEqual(record["snippet"], "quotes beta gamma")
            self.assertEqual(
                record["fingerprint"],
                findings.compute_fingerprint(agent="vuln-discovery", rule_id="unclassified",
                                             path="a.py", snippet="alpha"))

    def test_a_trusted_rule_id_binds_and_is_recorded(self):
        ci = self._index([{"rule_id": "scanner-rule", "path": "a.py", "line_number": 2,
                           "snippet": "scanner text"}])
        with tempfile.TemporaryDirectory() as td:
            processed, _, _ = self._run(td, [self._finding()], ci)

            record = processed[0]
            self.assertEqual(record["rule_id"], "scanner-rule")
            self.assertEqual(record["identity_source"], "candidate-exact")
            self.assertEqual(record["snippet"], "model wording one")

    def test_no_candidate_index_is_recorded_distinctly(self):
        with tempfile.TemporaryDirectory() as td:
            processed, _, _ = self._run(td, [self._finding()], None)
            self.assertEqual(processed[0]["identity_source"], "no-candidate-index")

    def test_a_report_cannot_claim_an_identity_it_does_not_have(self):
        """identity_source is written from the binder's vocabulary, never read from the input."""
        with tempfile.TemporaryDirectory() as td:
            processed, _, _ = self._run(
                td, [self._finding(identity_source="candidate-exact")], None)
            self.assertEqual(processed[0]["identity_source"], "no-candidate-index")

    def test_the_delta_attributes_a_fixed_row_to_its_key(self):
        """A Fixed line that cannot be attributed is unfalsifiable, which is the whole complaint.

        The row has to disappear for real here: step 2 made re-wording stop producing a Fixed line
        at all, so a test that relied on the re-wording would now only be testing that the fix is in
        place (test_the_found_scenario_no_longer_costs_a_new_and_fixed_pair does that).
        """
        ci = self._index([{"rule_id": "scanner-rule", "path": "a.py", "line_number": 2,
                           "snippet": "scanner text"}])
        with tempfile.TemporaryDirectory() as td:
            self._run(td, [self._finding(rule_id="model-invented-label",
                                         snippet="wording one")], ci)
            processed, stats, fixed = self._run(
                td, [self._finding(rule_id="model-invented-label", path="other.py")], ci)

            self.assertEqual(len(fixed), 1)
            report = findings._render_delta_report("target", processed, stats, fixed)
            self.assertIn("## Resolved in this Run (Fixed)", report)
            self.assertIn("identity: `unmatched-rule-location-unique`", report)

    def test_the_found_scenario_no_longer_costs_a_new_and_fixed_pair(self):
        """THE acceptance case, reproduced as it was found (agents-x9my step 2).

        Same unchanged location, prose re-worded between runs, model rule label that binds nothing:
        one finding was booked New and the row before it Fixed, on a byte-identical file. The
        fingerprint must now be identical across the two runs and the second run must report
        `unchanged`, which is the exact assertion the reviewer and the hub asked for.
        """
        ci = self._index([{"rule_id": "scanner-rule", "path": "src/app.js", "line_number": 2,
                           "snippet": "document.write(userInput)"}])
        run1 = self._finding(rule_id="model-invented-label", path="src/app.js",
                             snippet="document.write(userInput) is a DOM sink")
        run2 = self._finding(rule_id="model-invented-label", path="src/app.js",
                             snippet="the DOM sink is document.write(userInput)")
        with tempfile.TemporaryDirectory() as td:
            first, s1, fixed1 = self._run(td, [run1], ci)
            second, s2, fixed2 = self._run(td, [run2], ci)

            self.assertEqual(first[0]["fingerprint"], second[0]["fingerprint"])
            self.assertEqual((s2["new"], s2["fixed"], s2["unchanged"]), (0, 0, 1), s2)
            self.assertEqual((s1["new"], len(fixed1), len(fixed2)), (1, 0, 0))

    def _store_with_older_scheme(self, td, agent: str, **finding):
        """A store as an older identity binding left it: no scheme stamp, prose-keyed row."""
        item = self._finding(**finding)
        old_fp = findings.compute_fingerprint(agent=agent, rule_id="unclassified",
                                             path=item["path"], snippet=item["snippet"])
        record = dict(item, fingerprint=old_fp, agent=agent, rule_id="unclassified",
                      state="new", change="unchanged", first_seen="2026-01-01T00:00:00+00:00",
                      last_seen="2026-01-01T00:00:00+00:00")
        store_file = Path(td) / "target.json"
        store_file.write_text(json.dumps({"target": "target", "findings": {old_fp: record}}),
                              encoding="utf-8")
        return old_fp

    def test_a_store_from_an_older_binding_announces_the_re_key_once(self):
        """The wave is BOOKKEEPING and the delta must say so, once, or triage reads it as findings.

        A store written before the identity binding changed holds its rows under keys derived from
        the model's wording. The run that re-keys them produces a new+fixed wave on an unchanged
        file, so the delta carries a banner naming it as a migration - and the store is stamped, so
        the NEXT run is an ordinary one and does not repeat it.
        """
        ci = self._index([{"rule_id": "scanner-rule", "path": "a.py", "line_number": 2,
                           "snippet": "scanner text"}])
        with tempfile.TemporaryDirectory() as td:
            self._store_with_older_scheme(td, "vuln-discovery",
                                          rule_id="model-invented-label", snippet="wording one")
            processed, stats, fixed = self._run(
                td, [self._finding(rule_id="model-invented-label", snippet="wording one")], ci)

            self.assertEqual(stats["migrated"], 1, stats)
            report = findings._render_delta_report("target", processed, stats, fixed)
            self.assertIn("Identity migration (one-time)", report)
            self.assertIn("BOOKKEEPING, not findings", report)
            self.assertIn("Do not triage", report)
            stored = json.loads((Path(td) / "target.json").read_text(encoding="utf-8"))
            self.assertEqual(stored["identity_scheme"], findings.IDENTITY_SCHEME)

            # The second run is ordinary: the stamp means there is nothing left to re-key.
            again, s2, _ = self._run(
                td, [self._finding(rule_id="model-invented-label", snippet="wording one")], ci)
            self.assertEqual(s2["migrated"], 0, s2)
            self.assertNotIn("Identity migration",
                             findings._render_delta_report("target", again, s2, []))

    def test_a_fresh_store_never_claims_a_migration(self):
        """Nothing was re-keyed, so nothing may be announced as re-keyed."""
        ci = self._index([{"rule_id": "scanner-rule", "path": "a.py", "line_number": 2,
                           "snippet": "scanner text"}])
        with tempfile.TemporaryDirectory() as td:
            processed, stats, fixed = self._run(
                td, [self._finding(rule_id="invented")], ci)
            self.assertEqual(stats["migrated"], 0, stats)
            self.assertNotIn("Identity migration",
                             findings._render_delta_report("target", processed, stats, fixed))

    def test_the_fresh_store_is_stamped_with_its_binding(self):
        """A store written by this code says so, which is what makes the next bump detectable."""
        with tempfile.TemporaryDirectory() as td:
            self._run(td, [self._finding()], None)
            stored = json.loads((Path(td) / "target.json").read_text(encoding="utf-8"))
            self.assertEqual(stored["identity_scheme"], findings.IDENTITY_SCHEME)

    def test_the_vocabulary_is_defined_once_and_graded_consistently(self):
        """The review's P0, and the class it belongs to: a second definition of a constant is
        invisible to every behavioural test, because the later one simply wins.

        IDENTITY_STABLE_SOURCES was assigned twice (the new tuple above the old one), so every row
        bound by `unmatched-rule-*` rendered as `(reword-unstable - not evidence on its own)` while
        the commit message said the opposite. Nothing in the suite could see it: the rendering test
        only checked `candidate-exact`, and the acceptance test checks fingerprints, not text. So
        this pins BOTH the shadowing and the per-source grading, over the whole closed vocabulary.
        """
        source = (Path(findings.__file__)).read_text(encoding="utf-8")
        for name in ("IDENTITY_SOURCES", "IDENTITY_STABLE_SOURCES", "IDENTITY_SCHEME"):
            assignments = [ln for ln in source.splitlines() if ln.startswith(f"{name} =")]
            self.assertEqual(len(assignments), 1,
                             f"{name} is assigned {len(assignments)} times: {assignments}")

        # Every source is graded by membership, and the two stable location sources really are
        # stable - the user-facing contract of step 2.
        self.assertTrue({"unmatched-rule-location-unique", "unmatched-rule-path-unique"}
                        <= set(findings.IDENTITY_STABLE_SOURCES))
        for src in findings.IDENTITY_SOURCES:
            graded = findings._identity_grade({"identity_source": src})
            if src in findings.IDENTITY_STABLE_SOURCES:
                self.assertEqual(graded, "", f"{src} is stable and must render unmarked")
            else:
                self.assertIn("reword-unstable", graded, f"{src} must be marked unstable")
        self.assertEqual(findings._identity_grade({"identity_source": None}), "")

    def test_a_genuine_fix_is_never_announced_as_a_migration(self):
        """The review's P1: the banner must not tell triage to ignore a real resolution.

        On a store from an older binding, EVERY retired row used to be counted as a re-key, so a row
        the scanner had identified being genuinely fixed produced 'Do not triage that wave'. Only
        rows whose stored identity was unstable are re-keys; a stable-identified row disappearing is
        an ordinary result.
        """
        ci = self._index([{"rule_id": "scanner-rule", "path": "a.py", "line_number": 2,
                           "snippet": "scanner text"}])
        with tempfile.TemporaryDirectory() as td:
            # A store from an older scheme holding a row the SCANNER identified (candidate-exact).
            item = self._finding()
            fp = findings.compute_fingerprint(agent="vuln-discovery", rule_id="scanner-rule",
                                             path="a.py", snippet="scanner text")
            record = dict(item, fingerprint=fp, agent="vuln-discovery", identity_source="candidate-exact",
                          state="new", change="unchanged", first_seen="2026-01-01T00:00:00+00:00",
                          last_seen="2026-01-01T00:00:00+00:00")
            (Path(td) / "target.json").write_text(
                json.dumps({"target": "target", "findings": {fp: record}}), encoding="utf-8")

            # The run reports NOTHING: the finding is genuinely fixed. Nothing was re-keyed.
            processed, stats, fixed = self._run(td, [], ci)
            self.assertEqual((stats["fixed"], stats["migrated"]), (1, 0), stats)
            self.assertNotIn("Identity migration",
                             findings._render_delta_report("target", processed, stats, fixed))

    def test_a_re_key_is_still_counted_when_the_run_also_has_a_genuine_fix(self):
        """The other half of the same rule, and the sharper one: precision must not lose the wave.

        Two rows are retired here. One was identified by the model's wording and reappears under a
        location key - a re-key, and the wave the banner exists for. The other was identified by the
        SCANNER and simply disappears - a genuine fix. The count must be 1, not 2, and the banner
        must still fire: narrowing the count is only correct if the real wave survives it.
        """
        ci = self._index([{"rule_id": "scanner-rule", "path": "a.py", "line_number": 2,
                           "snippet": "scanner text"}])
        agent = "vuln-discovery"
        with tempfile.TemporaryDirectory() as td:
            rekey_fp = findings.compute_fingerprint(agent=agent, rule_id="unclassified", path="a.py",
                                                   snippet="the wording the model used last time")
            genuine_fp = findings.compute_fingerprint(agent=agent, rule_id="scanner-rule",
                                                      path="older.py", snippet="scanner text")
            base = {"severity": "high", "title": "t", "description": "d", "remediation": "r",
                    "state": "new", "change": "unchanged",
                    "first_seen": "2026-01-01T00:00:00+00:00",
                    "last_seen": "2026-01-01T00:00:00+00:00"}
            rows = {
                rekey_fp: dict(base, fingerprint=rekey_fp, agent=agent, rule_id="unclassified",
                               path="a.py", line_number=2,
                               snippet="the wording the model used last time",
                               identity_source="model-snippet"),
                genuine_fp: dict(base, fingerprint=genuine_fp, agent=agent, rule_id="scanner-rule",
                                 path="older.py", line_number=9, snippet="scanner text",
                                 identity_source="candidate-exact"),
            }
            (Path(td) / "target.json").write_text(
                json.dumps({"target": "target", "findings": rows}), encoding="utf-8")

            processed, stats, fixed = self._run(
                td, [self._finding(rule_id="model-invented-label", snippet="wording this time")], ci)

            self.assertEqual((stats["new"], stats["fixed"], stats["migrated"]), (1, 2, 1), stats)
            self.assertEqual(stats["fixed_unanchored"], 1, "rekey row has model-snippet identity so it is unanchored")
            self.assertIn("Identity migration (one-time)",
                          findings._render_delta_report("target", processed, stats, fixed))
            self.assertIn("1 of 2 finding(s) that left the active set had no stable anchor",
                          findings._render_delta_report("target", processed, stats, fixed))

    def test_fixed_unanchored_counter_and_banner_both_directions(self):
        """Option C (agents-6r8y): fixed keeps total count; fixed_unanchored is a subset counter beside it.

        An anchored disappearance leaves fixed_unanchored at 0 and renders no banner.
        An unanchored disappearance increments fixed_unanchored and renders the one-sentence banner.
        """
        agent = "vuln-discovery"
        base = {"severity": "high", "title": "t", "description": "d", "remediation": "r",
                "state": "new", "change": "unchanged",
                "first_seen": "2026-01-01T00:00:00+00:00",
                "last_seen": "2026-01-01T00:00:00+00:00"}

        # Direction 1: Anchored disappearance only
        ci = self._index([{"rule_id": "scanner-rule", "path": "a.py", "line_number": 2,
                           "snippet": "scanner text"}])
        with tempfile.TemporaryDirectory() as td:
            fp = findings.compute_fingerprint(agent=agent, rule_id="scanner-rule",
                                              path="a.py", snippet="scanner text")
            row = {fp: dict(base, fingerprint=fp, agent=agent, rule_id="scanner-rule",
                            path="a.py", line_number=2, snippet="scanner text",
                            identity_source="candidate-exact")}
            (Path(td) / "target.json").write_text(
                json.dumps({"target": "target", "identity_scheme": findings.IDENTITY_SCHEME,
                            "findings": row}), encoding="utf-8")

            # Finding disappears
            processed, stats, fixed = self._run(td, [], ci)
            self.assertEqual(stats["fixed"], 1, "fixed must count the total disappearances")
            self.assertEqual(stats["fixed_unanchored"], 0, "anchored disappearance leaves counter at 0")
            report = findings._render_delta_report("target", processed, stats, fixed)
            self.assertNotIn("Unanchored disappearances", report)

        # Direction 2: Unanchored disappearance only
        with tempfile.TemporaryDirectory() as td:
            fp = findings.compute_fingerprint(agent=agent, rule_id="unclassified",
                                              path="b.py", snippet="model wording")
            row = {fp: dict(base, fingerprint=fp, agent=agent, rule_id="unclassified",
                            path="b.py", line_number=5, snippet="model wording",
                            identity_source="model-snippet")}
            (Path(td) / "target.json").write_text(
                json.dumps({"target": "target", "identity_scheme": findings.IDENTITY_SCHEME,
                            "findings": row}), encoding="utf-8")

            # Finding disappears
            processed, stats, fixed = self._run(td, [], None)
            self.assertEqual(stats["fixed"], 1, "fixed keeps current meaning as total")
            self.assertEqual(stats["fixed_unanchored"], 1, "unanchored disappearance increments subset counter")
            report = findings._render_delta_report("target", processed, stats, fixed)
            self.assertIn("Unanchored disappearances", report)
            self.assertIn("> **Unanchored disappearances**: 1 of 1 finding(s) that left the active set", report)

        # Direction 3: Mixed disappearances (2 unanchored, 1 anchored = 3 total)
        with tempfile.TemporaryDirectory() as td:
            fp_anchored = findings.compute_fingerprint(agent=agent, rule_id="scanner-rule",
                                                      path="a.py", snippet="scanner text")
            fp_unanchored1 = findings.compute_fingerprint(agent=agent, rule_id="unclassified",
                                                         path="b.py", snippet="wording 1")
            fp_unanchored2 = findings.compute_fingerprint(agent=agent, rule_id="unclassified",
                                                         path="c.py", snippet="wording 2")
            rows = {
                fp_anchored: dict(base, fingerprint=fp_anchored, agent=agent, rule_id="scanner-rule",
                                  path="a.py", line_number=2, snippet="scanner text",
                                  identity_source="candidate-exact"),
                fp_unanchored1: dict(base, fingerprint=fp_unanchored1, agent=agent, rule_id="unclassified",
                                     path="b.py", line_number=5, snippet="wording 1",
                                     identity_source="model-snippet"),
                fp_unanchored2: dict(base, fingerprint=fp_unanchored2, agent=agent, rule_id="unclassified",
                                     path="c.py", line_number=8, snippet="wording 2",
                                     identity_source="no-candidate-index"),
            }
            (Path(td) / "target.json").write_text(
                json.dumps({"target": "target", "identity_scheme": findings.IDENTITY_SCHEME,
                            "findings": rows}), encoding="utf-8")

            # All disappear
            processed, stats, fixed = self._run(td, [], ci)
            self.assertEqual(stats["fixed"], 3, "total fixed is 3")
            self.assertEqual(stats["fixed_unanchored"], 2, "unanchored subset counter is 2")
            report = findings._render_delta_report("target", processed, stats, fixed)
            self.assertIn("> **Unanchored disappearances**: 2 of 3 finding(s) that left the active set", report)

    def test_new_unanchored_counter_and_section_both_directions(self):
        """agents-l606: an unanchored appearance is COUNTED, and a location match is DISCLOSED, not decided.

        `new_unanchored` is a subset counter beside `new`, exactly as `fixed_unanchored` is beside
        `fixed`. A row that shares its exact line with one this run booked Fixed is reported as a
        possible re-key: that is what the same finding moving key looks like, and also what a new finding
        at a recycled line looks like, so the row KEEPS `new` and stays actionable. The counter is
        information, and nothing is reclassified - demoting on this hid findings (agents-wcki).
        """
        agent = "vuln-discovery"

        # Direction 1: an ANCHORED appearance is an ordinary new finding.
        ci = self._index([{"rule_id": "scanner-rule", "path": "a.py", "line_number": 2,
                           "snippet": "scanner text"}])
        with tempfile.TemporaryDirectory() as td:
            processed, stats, fixed = self._run(td, [self._finding()], ci)
            self.assertEqual(stats["new"], 1)
            self.assertEqual(stats["new_unanchored"], 0, "an anchored appearance leaves the counter at 0")
            self.assertEqual(stats["possible_rekey"], 0)
            report = findings._render_delta_report("target", processed, stats, fixed)
            self.assertIn("## Action Required: New & Regressed Findings", report)
            self.assertNotIn("Unanchored appearances", report)
            self.assertNotIn("Re-keyed", report)

        # Direction 2: an UNANCHORED appearance with NO retiring twin stays new, counted as a subset.
        # It must ALSO stay under Action Required: newness is unattributed, but the row is not
        # evidence-coloured as a re-key, and a critical row must not be muted by this bookkeeping.
        with tempfile.TemporaryDirectory() as td:
            processed, stats, fixed = self._run(td, [self._finding()], None)
            self.assertEqual(stats["new"], 1, "new still counts an unattributed appearance")
            self.assertEqual(stats["new_unanchored"], 1, "unanchored appearance increments the subset")
            self.assertEqual(stats["possible_rekey"], 0, "no retiring twin means no pair")
            report = findings._render_delta_report("target", processed, stats, fixed)
            self.assertIn("## Action Required: New & Regressed Findings", report)
            self.assertIn("> **Unanchored appearances**: 1 of 1 new finding(s) had no stable anchor",
                          report)
            self.assertNotIn("Re-keyed", report)

        # Direction 3: THE agents-l606 CASE - one finding re-keyed inside one run. The store holds a
        # row at a location under the model's old wording; this run reports the SAME location with
        # reworded prose and no candidate set, so the row MOVES KEY: the old row is booked Fixed and
        # the reworded row appears. Before this change the run booked that appearance as a NEW
        # finding beside the Fixed twin of itself.
        with tempfile.TemporaryDirectory() as td:
            old_fp = findings.compute_fingerprint(agent=agent, rule_id="unclassified",
                                                  path="tests/x.py", snippet="old wording")
            row = {old_fp: {"fingerprint": old_fp, "agent": agent, "rule_id": "unclassified",
                            "path": "tests/x.py", "line_number": 621, "snippet": "old wording",
                            "identity_source": "no-candidate-index", "severity": "info",
                            "title": "Mock credential in a test fixture", "description": "d",
                            "remediation": "r", "state": "new", "change": "unchanged",
                            "first_seen": "2026-01-01T00:00:00+00:00",
                            "last_seen": "2026-01-01T00:00:00+00:00"}}
            (Path(td) / "target.json").write_text(
                json.dumps({"target": "target", "identity_scheme": findings.IDENTITY_SCHEME,
                            "findings": row}), encoding="utf-8")
            reworded = self._finding(rule_id="unclassified", path="tests/x.py", line_number=621,
                                     snippet="reworded prose")

            processed, stats, fixed = self._run(td, [reworded], None)
            self.assertEqual(stats["possible_rekey"], 1,
                             "the pair is reported as a possible re-key")
            self.assertEqual(stats["new"], 1,
                             "but nothing is reclassified: a location cannot prove the two rows are one")
            self.assertEqual(stats["new_unanchored"], 1, "and the appearance is still unattributed")
            self.assertEqual(stats["fixed"], 1, "the row that left is booked Fixed")
            self.assertEqual(stats["fixed_unanchored"], 1, "and is counted as an unanchored loss")
            report = findings._render_delta_report("target", processed, stats, fixed)
            self.assertIn("## Action Required: New & Regressed Findings", report,
                          "the row stays actionable - guessing it away has hidden real findings before")
            self.assertIn("Possibly re-keyed, not reclassified", report,
                          "and the report says the pair may be one finding that moved key")
            self.assertIn("## Resolved in this Run (Fixed)", report)

        # Direction 1b (agents-yh0z): an UNKNOWN line is NOT an exact location. The factory's own
        # unknown marker is the string "?" (lib/line_numbers.UNKNOWN_LINE_MARKER, which the store also
        # writes when a scanned null line is persisted), and the vuln-triage schema permits a null line,
        # so two unnamed rows in ONE file compare EQUAL at (path, "?") having no line in common. The
        # counter says EXACT LOCATION, so unknown-line rows are not paired and the count is a floor.
        # The rows themselves are untouched: new, actionable and delivered like any other.
        with tempfile.TemporaryDirectory() as td:
            old_fp = findings.compute_fingerprint(agent="vuln-discovery", rule_id="unclassified",
                                                  path="package.json", snippet="old wording")
            (Path(td) / "target.json").write_text(
                json.dumps({"target": "target", "identity_scheme": findings.IDENTITY_SCHEME,
                            "findings": {old_fp: {
                                "fingerprint": old_fp, "agent": "vuln-discovery",
                                "rule_id": "unclassified", "path": "package.json",
                                "line_number": None, "snippet": "old wording",
                                "identity_source": "no-candidate-index", "severity": "info",
                                "title": "old row", "description": "d", "remediation": "r",
                                "state": "new", "change": "unchanged",
                                "first_seen": "2026-01-01T00:00:00+00:00",
                                "last_seen": "2026-01-01T00:00:00+00:00"}}}), encoding="utf-8")
            unnamed = self._finding(rule_id="unclassified", path="package.json",
                                    line_number="?", snippet="reworded prose")
            processed, stats, fixed = self._run(td, [unnamed], None)
            self.assertEqual(stats["possible_rekey"], 0,
                             "two unnamed rows are not at a shared exact location")
            self.assertEqual(stats["new"], 1, "so the appearance is an ordinary new finding")
            self.assertEqual(len(fixed), 1, "and the unnamed row that left is still booked Fixed")

    def test_a_recycled_location_is_reported_and_never_reclassified(self):
        """Three reproductions of harm turned into three refusals (agents-wcki/l3j1/hci2).

        A location is RECYCLED when one row retires there and something else appears there. A location
        cannot distinguish a re-key from a new finding, and every reclassification attempted was
        reproduced as a way to hide work - a critical row dropped out of Action Required, and a
        fail-closed tracker check was skipped. So the delta COUNTS the pair and changes nothing.
        """
        agent = "vuln-discovery"

        def retire_at(td, path, line, snippet="old wording", severity="info",
                      identity_source="no-candidate-index"):
            fp = findings.compute_fingerprint(agent=agent, rule_id="unclassified",
                                              path=path, snippet=snippet)
            row = {fp: {"fingerprint": fp, "agent": agent, "rule_id": "unclassified",
                        "path": path, "line_number": line, "snippet": snippet,
                        "identity_source": identity_source, "severity": severity,
                        "title": "old row", "description": "d", "remediation": "old fix",
                        "state": "new", "change": "unchanged",
                        "first_seen": "2026-01-01T00:00:00+00:00",
                        "last_seen": "2026-01-01T00:00:00+00:00"}}
            (Path(td) / "target.json").write_text(
                json.dumps({"target": "target", "identity_scheme": findings.IDENTITY_SCHEME,
                            "findings": row}), encoding="utf-8")

        # (a) A NEW CRITICAL at the retired location keeps every thing a reader acts on: it is not
        # reclassified, it stays under Action Required, and it stays deliverable.
        with tempfile.TemporaryDirectory() as td:
            retire_at(td, "src/api.py", 42)
            critical = self._finding(rule_id="unclassified", path="src/api.py", line_number=42,
                                     snippet="auth bypass", severity="critical")
            critical["severity"] = "critical"
            critical["remediation"] = "patch the auth check"
            processed, stats, fixed = self._run(td, [critical], None)
            self.assertEqual(stats["possible_rekey"], 1, "the ambiguity is counted")
            self.assertEqual(stats["new"], 1, "and nothing is taken out of `new`")
            self.assertEqual({f["change"] for f in processed}, {"new"})
            report = findings._render_delta_report("target", processed, stats, fixed)
            self.assertIn("## Action Required: New & Regressed Findings", report)
            self.assertIn("Possibly re-keyed, not reclassified", report,
                          "the report must disclose the pair rather than resolve it")
            self.assertIn("patch the auth check", report,
                          "the remediation must never be the thing that disappears")
            # NOT ASSERTED AS PUBLISHABLE, on purpose: a critical row is withheld from publication by
            # the EMBARGO, which is a separate and deliberate mechanism, so asserting it here would
            # pass or fail for a reason unrelated to this bead. What the delta controls is that it
            # changes NOTHING the publication path reads - which is the sink guard I removed after it
            # silently skipped a fail-closed tracker check (see
            # tests/test_sinks.py::test_unavailable_tracker_listing_does_not_emit_false_closed_notice,
            # whose rc=3 assertion is the end-to-end evidence for this).
            self.assertEqual({f["state"] for f in processed}, {"new"})
            self.assertEqual({f["change"] for f in processed}, {"new"},
                             "a disclosed pair must not be reclassified out of the publication path")

        # (b) TWO appearances at one retired location: counted ONCE, and neither is changed.
        with tempfile.TemporaryDirectory() as td:
            retire_at(td, "a.py", 10)
            two = [self._finding(rule_id="unclassified", path="a.py", line_number=10,
                                 snippet="reworded one"),
                   self._finding(rule_id="unclassified", path="a.py", line_number=10,
                                 snippet="reworded two")]
            processed, stats, fixed = self._run(td, two, None)
            self.assertEqual(stats["possible_rekey"], 1,
                             "one retiring row explains at most one appearance")
            self.assertEqual(stats["new"], 2, "and both rows stay new and visible")
            self.assertEqual(len(fixed), 1)

        # (c) AN ANCHORED TWIN IS EVIDENCE, NOT A MATCH (agents-wcki): a row that had a stable anchor
        # would have been recognised by that key in THIS run, so its disappearance means the scanner
        # stopped emitting it - not that the next finding at its line is the same one.
        with tempfile.TemporaryDirectory() as td:
            retire_at(td, "c.py", 9, identity_source="candidate-exact")
            fresh = self._finding(rule_id="unclassified", path="c.py", line_number=9,
                                  snippet="a genuinely new finding")
            processed, stats, fixed = self._run(td, [fresh], None)
            self.assertEqual(stats["possible_rekey"], 0, "an anchored twin is not a candidate pair")
            self.assertEqual(stats["new"], 1)

    def _check_process_run_shared_predicate(self, process_run_source: str):
        """Shared verification helper for drift and mutation checks."""
        self.assertIn("is_unanchored_finding(existing)", process_run_source,
                      "delta path must call is_unanchored_finding(existing)")
        self.assertIn("is_unanchored_finding(row)", process_run_source,
                      "migration path must call is_unanchored_finding(row)")
        self.assertNotIn("not in IDENTITY_STABLE_SOURCES", process_run_source,
                         "process_run must not contain inlined predicate copies")

    def test_the_predicate_for_unanchored_rows_is_factored_and_shared(self):
        """The drift check: both the delta and migration paths must use the factored predicate.

        Two spellings of one rule is the defect we spent today removing. Both call sites
        (delta retirement and migration re-key counting) must call is_unanchored_finding.
        """
        # 1. Behavior over closed vocabulary
        for src in findings.IDENTITY_SOURCES:
            unanchored = findings.is_unanchored_finding({"identity_source": src})
            if src in findings.IDENTITY_STABLE_SOURCES:
                self.assertFalse(unanchored, f"{src} is in IDENTITY_STABLE_SOURCES and must be anchored")
            else:
                self.assertTrue(unanchored, f"{src} is not in IDENTITY_STABLE_SOURCES and must be unanchored")
        self.assertTrue(findings.is_unanchored_finding({}))
        self.assertTrue(findings.is_unanchored_finding({"identity_source": None}))

        # 2. Structural assertion against FindingsStore.process_run and _identity_grade
        import inspect
        src = inspect.getsource(findings.FindingsStore.process_run)
        self._check_process_run_shared_predicate(src)

        # agents-l17v: _identity_grade delegates stability classification to is_unanchored_finding
        grade_src = inspect.getsource(findings._identity_grade)
        self.assertIn("is_unanchored_finding(f)", grade_src,
                      "_identity_grade must delegate stability classification to is_unanchored_finding")
        self.assertNotIn("not in IDENTITY_STABLE_SOURCES", grade_src,
                         "_identity_grade must not duplicate the IDENTITY_STABLE_SOURCES membership check")
        # And verify the deliberate difference on missing source (agents-l17v)
        self.assertTrue(findings.is_unanchored_finding({"identity_source": None}))
        self.assertEqual(findings._identity_grade({"identity_source": None}), "")
        for src in findings.IDENTITY_SOURCES:
            has_grade = bool(findings._identity_grade({"identity_source": src}))
            is_unanchored = findings.is_unanchored_finding({"identity_source": src})
            self.assertEqual(has_grade, is_unanchored, f"mismatch between grade and predicate for {src}")

    def test_inlining_the_unanchored_predicate_fails_the_drift_check(self):
        """Mutation test: inlining an inline copy of the predicate into process_run must fail the drift check."""
        import inspect
        real_src = inspect.getsource(findings.FindingsStore.process_run)
        mutated_src = real_src.replace(
            "is_unanchored_finding(existing)",
            'existing.get("identity_source") not in findings.IDENTITY_STABLE_SOURCES'
        )
        with self.assertRaises(AssertionError):
            self._check_process_run_shared_predicate(mutated_src)

    def test_the_emitted_candidate_id_is_copied_where_a_rule_bound_the_candidate(self):
        """agents-q0mt: identity is COPIED from the station's id, not re-derived from text.

        rdyb has the station assign the id from data it owns at scan time; consuming it here is what
        removes the reconstruction layer rather than making it safer.
        """
        ci = self._index([{"rule_id": "scanner-rule", "path": "a.py", "line_number": 2,
                           "snippet": "scanner text", "candidate_id": "c6cab6881fc8535e"}])
        self.assertEqual(
            findings.identity_snippet_binding(self._finding(), "scanner-rule", "a.py", ci),
            ("c6cab6881fc8535e", "candidate-id"))
        self.assertIn("candidate-id", findings.IDENTITY_STABLE_SOURCES)

    def test_reworded_prose_cannot_move_an_identity_that_came_from_the_candidate_id(self):
        ci = self._index([{"rule_id": "scanner-rule", "path": "a.py", "line_number": 2,
                           "snippet": "el.innerHTML = user;", "candidate_id": "abc123def456abcd"}])
        first = findings.identity_snippet_binding(
            self._finding(snippet="el.innerHTML = user"), "scanner-rule", "a.py", ci)
        second = findings.identity_snippet_binding(
            self._finding(snippet="the line assigns innerHTML here"), "scanner-rule", "a.py", ci)
        # Equality alone would pass if BOTH runs fell back to the same unstable key, so the
        # mechanism is asserted before the stability it is supposed to provide (review finding).
        self.assertEqual((first[0], first[1]), ("abc123def456abcd", "candidate-id"))
        self.assertEqual(first, second)

    def test_a_prose_selected_candidate_does_not_borrow_the_stable_name(self):
        """The id is used at the four STABLE steps only.

        At this step the SELECTION is the model's, so the name must keep saying so even though the
        chosen candidate carries an id - a stable-sounding label there would hide the mechanism.
        """
        ci = self._index([
            {"rule_id": "scanner-rule", "path": "a.py", "line_number": 2, "snippet": "alpha",
             "candidate_id": "aaaa"},
            {"rule_id": "scanner-rule", "path": "a.py", "line_number": 40, "snippet": "beta gamma",
             "candidate_id": "bbbb"},
        ])
        value, source = findings.identity_snippet_binding(
            self._finding(line_number=99, snippet="the line reads beta gamma here"),
            "scanner-rule", "a.py", ci)
        self.assertEqual((value, source), ("beta gamma", "candidate-similar-by-model-snippet"))
        self.assertNotIn(source, findings.IDENTITY_STABLE_SOURCES)

    def test_two_findings_at_one_path_now_bind_to_two_candidates(self):
        """The case agents-x9my step 2 had to REFUSE, resolved by the emitted id.

        Two rows in one file whose labels bind nothing: step 2's path-level guard refused the
        location fallback because both rows would have been handed the same snippet and collapsed
        into one. Different lines are different candidates, and each now says which one it is, so
        both survive with stable identities.
        """
        ci = self._index([
            {"rule_id": "r", "path": "a.js", "line_number": 1, "snippet": "same text",
             "candidate_id": "id-one"},
            {"rule_id": "r", "path": "a.js", "line_number": 2, "snippet": "same text",
             "candidate_id": "id-two"},
        ])
        with tempfile.TemporaryDirectory() as td:
            items = [self._finding(rule_id="invented", path="a.js", line_number=1, snippet="wording one"),
                     self._finding(rule_id="invented", path="a.js", line_number=2, snippet="wording two")]
            processed, _, _ = self._run(td, items, ci)
        self.assertEqual([r["identity_source"] for r in processed], ["candidate-id"] * 2)
        self.assertEqual(len({r["fingerprint"] for r in processed}), 2,
                         "the two rows must not collapse into one")

    def test_two_findings_at_the_same_line_still_refuse_the_id(self):
        """The matching negative: the sharper guard is per (path, line), not per path.

        If two rows in one run claim the SAME location, the candidate there is not theirs alone, so
        the id is not used - a shared id would give both rows one fingerprint and drop a finding,
        which is the outcome this guard exists to prevent.
        """
        ci = self._index([{"rule_id": "r", "path": "a.js", "line_number": 1, "snippet": "same",
                           "candidate_id": "shared"}])
        with tempfile.TemporaryDirectory() as td:
            items = [self._finding(rule_id="invented", path="a.js", line_number=1, snippet="wording one"),
                     self._finding(rule_id="invented", path="a.js", line_number=1, snippet="wording two")]
            processed, _, _ = self._run(td, items, ci)
        self.assertEqual([r["identity_source"] for r in processed], ["model-snippet"] * 2)
        self.assertEqual(len({r["fingerprint"] for r in processed}), 2,
                         "the two rows must not collapse into one")

    def test_the_acceptance_is_pinned_with_an_emitted_id_wave_once_and_then_gone(self):
        """agents-q0mt, condition 2: same unchanged location, prose re-worded, untrusted label.

        Two runs against one store. Because the station's emitted id is consumed, run 2 re-words the
        prose completely and identity does not move: identical fingerprint, nothing booked new or
        fixed. The migration wave is then observed EXACTLY once - on the run that crosses the scheme
        stamp - and gone on the next, which is the difference between an announcement and a mystery.

        The last assertion is the disclosure-surface claim, tested rather than asserted: identity
        goes into the fingerprint, so the raw id is never persisted and the record gains no field.
        That is why storing it belongs with agents-p8og and not here.
        """
        ci = self._index([{"rule_id": "doc-broken-link", "path": "docs/a.md", "line_number": 10,
                           "snippet": "see [x](../src/gone.py)",
                           "candidate_id": "313b2133ae08c979"}])
        with tempfile.TemporaryDirectory() as td:
            first, _, _ = self._run(td, [self._finding(
                rule_id="invented", path="docs/a.md", line_number=10, snippet="quote one")], ci)
            self.assertEqual(first[0]["identity_source"], "candidate-id")
            fp1 = first[0]["fingerprint"]

            second, stats2, _ = self._run(td, [self._finding(
                rule_id="invented", path="docs/a.md", line_number=10,
                snippet="a completely different re-quoting of the same line")], ci)
            self.assertEqual(second[0]["fingerprint"], fp1)
            self.assertEqual((stats2["new"], stats2["fixed"], stats2["unchanged"]), (0, 0, 1), stats2)

            # Downgrade the stored run to an older binding, so the next run must cross the stamp.
            store_file = Path(td) / "target.json"
            data = json.loads(store_file.read_text())
            for key, row in list(data["findings"].items()):
                row["fingerprint"] = "0" * 64
                row["identity_source"] = "model-snippet"
                # The store is keyed BY fingerprint, so the key has to move too - rewriting the
                # field alone leaves the row matching under its old key and nothing migrates.
                del data["findings"][key]
                data["findings"]["0" * 64] = row
            data["identity_scheme"] = findings.IDENTITY_SCHEME - 1
            store_file.write_text(json.dumps(data))
            # The history ledger would re-match the row by its old key, so it is dropped: an older
            # store is one whose rows are only in the store, which is how the migration case is
            # constructed for agents-x9my step 2 as well.
            (Path(td) / "target-history.jsonl").unlink(missing_ok=True)

            _, stats3, _ = self._run(td, [self._finding(
                rule_id="invented", path="docs/a.md", line_number=10, snippet="quote one")], ci)
            self.assertEqual(stats3["migrated"], 1, stats3)          # the wave, exactly once
            _, stats4, _ = self._run(td, [self._finding(
                rule_id="invented", path="docs/a.md", line_number=10, snippet="quote three")], ci)
            self.assertEqual(stats4["migrated"], 0, stats4)          # and gone
            # "gone" has to mean the store was STAMPED, not merely that this run had nothing to
            # retire: without the stamp every later run would re-announce the wave (review finding).
            self.assertEqual(json.loads(store_file.read_text()).get("identity_scheme"),
                             findings.IDENTITY_SCHEME)
            # agents-p8og REVERSED the first half of what this line asserted, deliberately and with
            # a ruling behind it: the id IS persisted now, so a second-order station can carry it.
            # What has to stay true is WHY the old assertion existed - identity is carried by the
            # FINGERPRINT, so persisting the id must not introduce a second, competing identity, nor
            # collapse two findings onto one. Asserted by matching fingerprints against the shared
            # id rather than by the id's absence, and the scheme stamp above still says no re-key.
            stored = json.loads(store_file.read_text())
            carried = [r for r in stored["findings"].values()
                       if r.get("candidate_id") == "313b2133ae08c979"]
            self.assertTrue(carried, "the id should be persisted for second-order stations")
            for row in carried:
                self.assertNotEqual(row["fingerprint"], row["candidate_id"],
                                    "the id must not BE the identity: the fingerprint carries it")
            self.assertEqual(len({r["fingerprint"] for r in carried}), len(carried),
                             "one candidate id must not collapse distinct findings onto one identity")

    def test_a_non_scalar_line_number_cannot_crash_the_run(self):
        """The redaction contract is fail-closed, not crash (agents-q0mt).

        Found by the FULL gate, not the fast one: a dict line_number is unhashable and identity
        binding uses the line as a dict key, so process_run exited 1 with TypeError: unhashable type
        instead of coercing. Every lookup must MISS for a non-scalar (see _hashable_line).
        """
        with tempfile.TemporaryDirectory() as td:
            processed, stats, _ = self._run(td, [self._finding(line_number={"line": 12})], None)
        self.assertEqual(len(processed), 1)
        self.assertEqual(processed[0]["identity_source"], "no-candidate-index")
        self.assertEqual(stats["new"], 1)

    def test_a_non_scalar_line_number_still_binds_by_rule_without_crashing(self):
        """The second guarded site: identity_snippet_binding hashes the line too.

        Guarding only the counting loop in process_run would have moved the crash one call later.
        A non-scalar line cannot match a location, but the rule-keyed binding is still available and
        must be used rather than lost.
        """
        ci = self._index([{"rule_id": "scanner-rule", "path": "a.py", "line_number": 2,
                           "snippet": "scanner text", "candidate_id": "c6cab6881fc8535e"}])
        with tempfile.TemporaryDirectory() as td:
            processed, _, _ = self._run(td, [self._finding(line_number=["nope"])], ci)
        self.assertEqual(processed[0]["identity_source"], "candidate-id")

    def test_the_record_persists_the_id_the_binder_used_without_changing_identity(self):
        """agents-p8og: the id is persisted for second-order stations, and identity does NOT move.

        The no-scheme-bump claim, evidenced rather than asserted: the fingerprint for the same
        inputs is byte-identical with the id persisted, because the id was ALREADY the identity
        payload. Persisting it adds a field; it re-keys nothing.
        """
        ci = self._index([{"rule_id": "scanner-rule", "path": "a.py", "line_number": 2,
                           "snippet": "scanner text", "candidate_id": "c6cab6881fc8535e"}])
        with tempfile.TemporaryDirectory() as td:
            processed, _, _ = self._run(td, [self._finding(
                rule_id="invented", path="a.py", line_number=2, snippet="re-worded freely")], ci)
        row = processed[0]
        self.assertEqual(row["candidate_id"], "c6cab6881fc8535e")
        self.assertEqual(row["identity_source"], "candidate-id")
        self.assertEqual(row["fingerprint"],
                         findings.compute_fingerprint("vuln-discovery", "unclassified", "a.py",
                                                      "c6cab6881fc8535e"))

    def test_the_record_persists_the_id_on_disk_and_through_a_reload(self):
        """The P1 a cross-family review caught in the first version of this branch.

        process_run returns the IN-MEMORY record while save() writes the at-rest copy, so an
        assertion on `processed[0]` proved nothing about persistence - which is exactly how the id
        came to be stripped on the way to disk with the suite still green. Assert what PERSISTS.
        """
        ci = self._index([{"rule_id": "scanner-rule", "path": "a.py", "line_number": 2,
                           "snippet": "scanner text", "candidate_id": "c6cab6881fc8535e"}])
        with tempfile.TemporaryDirectory() as td:
            store = FindingsStore("target", findings_dir=Path(td))
            store.process_run("vuln-discovery", [self._finding(
                rule_id="invented", path="a.py", line_number=2, snippet="re-worded freely")],
                candidate_index=ci)
            store.close()

            on_disk = json.loads((Path(td) / "target.json").read_text(encoding="utf-8"))
            written = next(iter(on_disk["findings"].values()))
            self.assertEqual(written["candidate_id"], "c6cab6881fc8535e",
                             "the id did not reach disk, so no second-order station can read it")
            self.assertEqual(written["fingerprint"],
                             findings.compute_fingerprint("vuln-discovery", "unclassified", "a.py",
                                                          "c6cab6881fc8535e"))

            # And it survives the load path, which scrubs records a second time on the way in.
            reopened = FindingsStore("target", findings_dir=Path(td))
            reloaded = next(iter(reopened.data["findings"].values()))
            reopened.close()
            self.assertEqual(reloaded["candidate_id"], "c6cab6881fc8535e")

    def test_the_storage_and_publication_boundaries_are_distinct(self):
        """Storage KEEPS the id; publication DROPS it. If these ever collapse into one function
        again, both halves break silently - once the store keeps nothing, once the confirmation
        oracle is published - and this is the test that says which is which."""
        row = dict(self._finding(), fingerprint="f" * 64, identity_source="candidate-id",
                   candidate_id="c6cab6881fc8535e", state="new", change="new")
        self.assertNotIn("candidate_id", redact_finding(row))
        self.assertEqual(redact_for_storage(row)["candidate_id"], "c6cab6881fc8535e")

    def test_a_finding_with_no_emitted_id_persists_none_rather_than_inventing_one(self):
        """An invented id would look like provenance, which is worse than an empty field."""
        ci = self._index([{"rule_id": "scanner-rule", "path": "a.py", "line_number": 2,
                           "snippet": "scanner text"}])
        with tempfile.TemporaryDirectory() as td:
            processed, _, _ = self._run(td, [self._finding()], ci)
        self.assertIsNone(processed[0]["candidate_id"])

    def test_a_secret_in_the_matched_text_cannot_be_recovered_from_the_stored_id(self):
        """agents-p8og condition 1: the persisted id must not become a vector for the matched text.

        The id is a TRUNCATED SHA-256 over rule id, path, matched text AND ordinal, NUL-separated, so
        it is not a function of the secret alone. Tested in the two ways that are actually testable:
        the raw secret never appears in the store, and the SAME secret at two locations produces two
        DIFFERENT ids - so a rainbow table built over candidate secrets is not enough to test a
        guess, without also guessing the rule, the path and the ordinal.
        """
        secret = "ghp_" + "A" * 36
        cands = [{"rule_id": "github-pat", "path": "a.py", "line_number": 1,
                  "snippet": secret, "raw_match": secret},
                 {"rule_id": "github-pat", "path": "b.py", "line_number": 1,
                  "snippet": secret, "raw_match": secret}]
        assign_candidate_ids(cands)
        ci = self._index(cands)
        with tempfile.TemporaryDirectory() as td:
            processed, _, _ = self._run(td, [
                self._finding(rule_id="invented", path="a.py", line_number=1, snippet="wording"),
                self._finding(rule_id="invented", path="b.py", line_number=1, snippet="wording"),
            ], ci)
            store_text = (Path(td) / "target.json").read_text(encoding="utf-8")
        ids = [r["candidate_id"] for r in processed]
        self.assertTrue(all(ids), "the ids were not persisted at all")
        self.assertNotEqual(ids[0], ids[1],
                            "one secret in two places gave one id - the id is a function of the "
                            "secret alone, so it is a confirmation oracle")
        self.assertNotIn(secret, store_text)
        # Not the digest of the secret by itself either: the scanner-owned context is an input.
        secret_only = hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]
        self.assertNotIn(secret_only, ids)

    def test_the_persisted_id_is_never_published(self):
        """A digest of the matched text is a confirmation oracle, so it is withheld from output.

        The id stays in the LOCAL store, where the second-order stations read it; it is not a
        publication channel. Same shape as model_rule_id's withholding branches.
        """
        from lib.redaction import redact_finding, redact_for_storage

        row = dict(self._finding(), fingerprint="f" * 64, identity_source="candidate-id",
                   candidate_id="c6cab6881fc8535e", state="new", change="new")
        self.assertNotIn("candidate_id", redact_finding(row))
    def test_persisting_the_id_does_not_bump_the_identity_scheme(self):
        """Coord's condition 3: if no migration is needed, say so explicitly - and pin it.

        3 is the value agents-q0mt landed. A future bump must consciously update this test, which is
        the point: a re-key wave is announced BEFORE it lands, never discovered afterwards.
        """
        self.assertEqual(findings.IDENTITY_SCHEME, 3)

    def test_every_source_in_the_vocabulary_is_reachable(self):
        """EXACT equality, not a subset check: a source that can never be emitted is a defect.

        The reviewer was right that the subset form proved nothing - it would pass if the binder
        returned one value or none. Every vocabulary entry is now constructed for real, which is
        why it also catches a name that is defined but unreachable.
        """
        single = self._index([{"rule_id": "scanner-rule", "path": "a.py", "line_number": 2,
                               "snippet": "scanner text"}])
        # A separate index, because an id takes precedence over the snippet at the same step: with
        # the id present the `candidate-exact` case below would no longer be reachable.
        single_with_id = self._index([{"rule_id": "scanner-rule", "path": "a.py", "line_number": 2,
                                       "snippet": "scanner text",
                                       "candidate_id": "c6cab6881fc8535e"}])
        ambiguous = self._index([
            {"rule_id": "scanner-rule", "path": "a.py", "line_number": 2, "snippet": "alpha"},
            {"rule_id": "scanner-rule", "path": "a.py", "line_number": 40, "snippet": "beta gamma"},
        ])
        echoed = self._index([
            {"rule_id": "scanner-rule", "path": "a.py", "line_number": 2, "candidate_id": "id-a"},
            {"rule_id": "scanner-rule", "path": "a.py", "line_number": 40, "candidate_id": "id-b"},
        ])
        observed = set()
        with tempfile.TemporaryDirectory() as td:
            cases = [
                (self._finding(), single),                                  # exact
                (self._finding(), single_with_id),                          # candidate-id
                (self._finding(line_number=99), single),                    # unique
                (self._finding(line_number=99, snippet="reads beta gamma"),
                 ambiguous),                                                # similar-by-model-snippet
                (self._finding(line_number=99, snippet="nothing like it"), ambiguous),  # model-snippet
                (self._finding(line_number=99, anchor_candidate_id="id-a"), echoed),  # id-by-model
                (self._finding(), None),                                    # no-candidate-index
                # The location fallbacks need a label that binds nothing, or the rule-keyed
                # lookups answer first and these are unreachable.
                (self._finding(rule_id="invented"), single),                 # location-unique
                (self._finding(rule_id="invented", line_number=99), single),  # path-unique
            ]
            for item, index in cases:
                observed.add(self._run(td, [item], index)[0][0]["identity_source"])
        self.assertEqual(observed, set(findings.IDENTITY_SOURCES), observed)


class TestModelSelectedAnchor(unittest.TestCase):
    """agents-hoxs: a model echo can select identity, but cannot claim stable provenance."""

    def index(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "candidates.json"
            path.write_text(json.dumps({"candidates": [
                {"candidate_id": "id-a", "rule_id": "scanner-rule", "path": "a.py", "line_number": 2},
                {"candidate_id": "id-b", "rule_id": "scanner-rule", "path": "a.py", "line_number": 40},
            ]}), encoding="utf-8")
            return findings.load_candidate_index(path)

    def item(self, **overrides):
        row = {"rule_id": "scanner-rule", "path": "a.py", "line_number": 99,
               "snippet": "first prose", "title": "cause", "description": "linked", "severity": "high"}
        row.update(overrides)
        return row

    def test_echo_binds_only_when_rule_and_location_miss_and_is_unstable(self):
        index = self.index()
        self.assertEqual(index["ids_set"], {"id-a", "id-b"})
        with tempfile.TemporaryDirectory() as td:
            store = FindingsStore("target", findings_dir=Path(td))
            try:
                first, first_stats, _ = store.process_run(
                    "vuln-triage", [self.item(anchor_candidate_id="id-a")], candidate_index=index)
                second, replay, _ = store.process_run(
                    "vuln-triage", [self.item(snippet="entirely different prose", anchor_candidate_id="id-a")],
                    candidate_index=index)
            finally:
                store.close()
            self.assertEqual(first[0]["identity_source"], "candidate-id-by-model")
            self.assertEqual(first[0]["fingerprint"], second[0]["fingerprint"])
            self.assertEqual((replay["new"], replay["fixed"], replay["unchanged"]), (0, 0, 1))
            self.assertEqual(first_stats["new_unanchored"], 1)
            self.assertIn("reword-unstable", findings._render_delta_report(
                "target", first, first_stats, []), "model-selected identity must be visibly graded")
        self.assertIn("candidate-id-by-model", findings.IDENTITY_SOURCES)
        self.assertNotIn("candidate-id-by-model", findings.IDENTITY_STABLE_SOURCES)
        self.assertEqual(findings.IDENTITY_SCHEME, 3)

    def test_echo_adoption_can_rekey_once_but_repeat_does_not(self):
        """Synthetic migration control, not the ADR's after-landing live-store measurement."""
        index = self.index()
        with tempfile.TemporaryDirectory() as td:
            store = FindingsStore("target", findings_dir=Path(td))
            try:
                store.process_run("vuln-triage", [self.item()], candidate_index=None)
                adopted, wave, _ = store.process_run(
                    "vuln-triage", [self.item(snippet="new prose", anchor_candidate_id="id-a")],
                    candidate_index=index)
                replayed, stable, _ = store.process_run(
                    "vuln-triage", [self.item(snippet="new prose", anchor_candidate_id="id-a")],
                    candidate_index=index)
            finally:
                store.close()
        self.assertEqual((wave["new"], wave["fixed"]), (1, 1))
        self.assertEqual((stable["new"], stable["fixed"]), (0, 0))
        self.assertEqual(adopted[0]["fingerprint"], replayed[0]["fingerprint"])
        self.assertEqual(adopted[0]["identity_source"], "candidate-id-by-model")

    def test_fact_binding_wins_and_a_known_disagreement_is_counted_and_disclosed(self):
        index = self.index()
        with tempfile.TemporaryDirectory() as td:
            store = FindingsStore("target", findings_dir=Path(td))
            try:
                rows, stats, _ = store.process_run(
                    "vuln-triage", [self.item(line_number=2, anchor_candidate_id="id-b")],
                    candidate_index=index)
            finally:
                store.close()
            self.assertEqual((rows[0]["candidate_id"], rows[0]["identity_source"]),
                             ("id-a", "candidate-id"))
            self.assertEqual((stats["anchor_disagreement"], stats["anchor_unknown"]), (1, 0))
            report = findings._render_delta_report("target", rows, stats, [])
            self.assertIn("anchor disagreement", report.lower())
            history = json.loads((Path(td) / "target-history.jsonl").read_text().splitlines()[-1])
            self.assertEqual(history["delta"]["anchor_disagreement"], 1)

    def test_unknown_echo_falls_back_is_counted_and_named_without_echoing_input(self):
        index = self.index()
        with tempfile.TemporaryDirectory() as td:
            store = FindingsStore("target", findings_dir=Path(td))
            try:
                rows, stats, _ = store.process_run(
                    "vuln-triage", [self.item(anchor_candidate_id="secret-model-text")],
                    candidate_index=index)
            finally:
                store.close()
            self.assertEqual(rows[0]["identity_source"], "model-snippet")
            self.assertIsNone(rows[0]["candidate_id"])
            self.assertEqual((stats["anchor_unknown"], stats["anchor_disagreement"]), (1, 0))
            report = findings._render_delta_report("target", rows, stats, [])
            self.assertIn("unknown anchor", report.lower())
            self.assertNotIn("secret-model-text", report)
            history = json.loads((Path(td) / "target-history.jsonl").read_text().splitlines()[-1])
            self.assertEqual(history["delta"]["anchor_unknown"], 1)

    def test_malformed_or_indexless_echo_is_named_unknown_without_binding(self):
        for echo, index in (({"invalid": "shape"}, self.index()), ("id-a", None)):
            with self.subTest(echo=echo, has_index=index is not None):
                with tempfile.TemporaryDirectory() as td:
                    store = FindingsStore("target", findings_dir=Path(td))
                    try:
                        rows, stats, _ = store.process_run(
                            "vuln-triage", [self.item(anchor_candidate_id=echo)],
                            candidate_index=index)
                    finally:
                        store.close()
                self.assertEqual(stats["anchor_unknown"], 1)
                self.assertEqual(rows[0]["identity_source"],
                                 "model-snippet" if index else "no-candidate-index")

    def test_line_report_keeps_echo_counters_and_names_both_outcomes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            station = root / "triage-fragment.json"
            station.write_text(json.dumps({"stats": {
                "anchor_unknown": 2, "anchor_disagreement": 1}}), encoding="utf-8")
            path = findings.write_line_report(
                "target", "audit", [{"station": "vuln-triage", "status": "PASS",
                                     "findings_count": 0, "criticals": 0,
                                     "fragment": str(station)}], findings_dir=root)
            machine = json.loads((root / "target-line.json").read_text(encoding="utf-8"))
            report = path.read_text(encoding="utf-8")
        self.assertEqual((machine["stats"]["anchor_unknown"],
                          machine["stats"]["anchor_disagreement"]), (2, 1))
        self.assertIn("2 unknown anchor id(s)", report)
        self.assertIn("1 anchor disagreement(s)", report)

    def test_model_selected_id_is_the_persisted_key_but_not_published(self):
        index = self.index()
        with tempfile.TemporaryDirectory() as td:
            store = FindingsStore("target", findings_dir=Path(td))
            try:
                rows, _, _ = store.process_run(
                    "vuln-triage", [self.item(anchor_candidate_id="id-b")], candidate_index=index)
            finally:
                store.close()
            self.assertEqual(rows[0]["candidate_id"], "id-b")
            stored = json.loads((Path(td) / "target.json").read_text(encoding="utf-8"))
            saved = next(iter(stored["findings"].values()))
            self.assertEqual(saved["candidate_id"], "id-b")
            self.assertEqual(saved["identity_source"], "candidate-id-by-model")
            from lib.redaction import redact_finding
            self.assertNotIn("candidate_id", redact_finding(rows[0]))


class TestCandidateCoverage(unittest.TestCase):
    """agents-xx9t: the completeness fact PASS now requires - candidates in versus accounted for."""

    def test_a_station_with_no_pre_pass_cannot_be_called_partial(self):
        """No candidates.json is not zero candidates: completeness is unknowable, so nothing changes."""
        self.assertIsNone(read_candidate_count(None))
        self.assertTrue(candidate_coverage(None, 0)["complete"])
        self.assertTrue(candidate_coverage(None, 7)["complete"])
        self.assertIsNone(candidate_coverage(None, 0)["candidates_presented"])

    def test_a_partial_identity_record_is_no_identity_at_all(self):
        """agents-ju56b: the batched dispatcher records `identity: partial` when some presented candidates
        carry no candidate_id (the retained vuln-verify bundle has ids on 2 of 5). Reading that partial list
        made a COMPLETE answer score 2/5 and go INCOMPLETE, a regression the unbatched run did not have.
        A partial record must fall back to count accounting - not to the payload slice, which holds the same
        partial ids."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            # A payload with ids on 2 of 5 rows, exactly like the real one.
            (run / "candidates.json").write_text(json.dumps({"candidates": [
                {"candidate_id": "50a8a7c8990e463f", "rule_id": "r", "path": "THREAT_MODEL.md"},
                {"candidate_id": "effe7026c6ffc948", "rule_id": "r", "path": "lib/budget.py"},
                {"rule_id": "r", "path": "a.py"}, {"rule_id": "r", "path": "b.py"},
                {"rule_id": "r", "path": "c.py"},
            ]}), encoding="utf-8")
            (run / "presented_candidates.json").write_text(json.dumps({
                "presented": 5, "batch_count": 3, "identity": "partial",
                "candidates_without_id": 3, "candidate_ids": None,
                "batches": [["50a8a7c8990e463f", "effe7026c6ffc948"], [], []],
            }), encoding="utf-8")
            self.assertIsNone(read_presented_candidate_ids(run),
                              "a partial record must not be returned as identity information")
            coverage = candidate_coverage(5, 5, presented_ids=read_presented_candidate_ids(run),
                                          cited_ids=[None] * 5)
            self.assertEqual(coverage["identity"], "count-only")
            self.assertTrue(coverage["complete"], f"a complete answer must not read partial: {coverage}")

    def test_a_mistranscribed_id_is_repaired_only_when_it_is_unambiguous(self):
        """agents-00sew: chrome-agent-platform-z427f's model reported 4e8820782eed4e17 as
        4e8820782eed17 - a DELETION of two hex characters, which is neither a prefix nor a substring,
        so the repair has to cover the near-match shape too. Everything below is measured, not assumed."""
        presented = ["4e8820782eed4e17", "05622f455345d483", "b7fddd5efdaeb0d3"]
        # the real failure: two characters deleted mid-id
        self.assertEqual(repair_cited_candidate_id("4e8820782eed17", presented)[0],
                         "4e8820782eed4e17")
        # a truncated tail and a copied fragment
        self.assertEqual(repair_cited_candidate_id("4e8820782eed4e1", presented), ("4e8820782eed4e17", "prefix"))
        self.assertEqual(repair_cited_candidate_id("8820782eed4e", presented), ("4e8820782eed4e17", "substring"))
        # nothing to do, too little to go on, and nothing near
        self.assertEqual(repair_cited_candidate_id("4e8820782eed4e17", presented), (None, "exact"))
        self.assertIsNone(repair_cited_candidate_id("4e88", presented)[0])
        self.assertIsNone(repair_cited_candidate_id("ffffffffffffffff", presented)[0])
        # AMBIGUITY IS NEVER RESOLVED BY PREFERENCE
        ambiguous, rule = repair_cited_candidate_id("4e8820782eed",
                                                    ["4e8820782eed4e17", "4e8820782eed9abc"])
        self.assertIsNone(ambiguous)
        self.assertIn("ambiguous", rule)

    def test_a_near_match_must_be_strictly_closest_not_merely_within_the_limit(self):
        """Measured while wiring the e2e: "cand-prf-003" is 1 edit from "cand-perf-003" and 2 from
        "cand-perf-004". Treating every within-limit candidate as equally ambiguous refused the repair
        this exists for; picking "the first within the limit" would bind by id ORDER. Both are pinned."""
        self.assertEqual(repair_cited_candidate_id("cand-prf-003",
                                                   ["cand-perf-003", "cand-perf-004"]),
                         ("cand-perf-003", "near"), "the closer match wins over a farther one")
        self.assertEqual(repair_cited_candidate_id("cand-prf-003",
                                                   ["cand-perf-004", "cand-perf-003"]),
                         ("cand-perf-003", "near"), "and the order they arrive in cannot matter")

    def test_a_true_tie_at_the_same_distance_is_refused(self):
        # Neither is a prefix or a substring of the cited id; both sit at exactly two edits.
        # Two substitutions each, neither a prefix nor a substring of the cited id: a genuine tie.
        cited = "abcdef1234567890"
        presented = ["abXXef1234567890", "abcdef12345678YY", "ffffffffffffffff"]
        repaired, rule = repair_cited_candidate_id(cited, presented)
        self.assertIsNone(repaired)
        self.assertIn("ambiguous", rule)

    def test_another_batchs_exact_id_is_never_repaired_onto_a_near_neighbour(self):
        """agents-fv5uk. Batch ids sit one edit apart, so an unguarded near rule silently re-attached a row
        naming batch 3's candidate to batch 2's - the reviewer's repro, before this guard."""
        own, sibling = ["cand-perf-003"], ["cand-perf-004"]
        self.assertEqual(repair_cited_candidate_id(sibling[0], own, foreign=sibling),
                         (None, "belongs to another batch"))
        # the SAME near match is still allowed when the cited id belongs to no other batch
        self.assertEqual(repair_cited_candidate_id("cand-prf-003", own + sibling),
                         ("cand-perf-003", "near"))

    def test_a_typo_of_a_sibling_batchs_id_is_never_repaired_locally(self):
        """agents-00sew round 2. The exact-match guard was not enough: "cand-perf-0o4" is a one-character
        typo of the SIBLING batch's "cand-perf-004" (1 edit) and two edits from the local "cand-perf-003", so
        a repair that only weighed local candidates bound the row to the wrong batch's neighbour. The match
        must be judged globally - and a citation whose LOCAL candidate really is closest must still repair,
        or the rule would be a blanket ban rather than a judgement."""
        self.assertEqual(repair_cited_candidate_id("cand-perf-0o4", ["cand-perf-003"],
                                                   foreign=["cand-perf-004"])[0], None,
                         "the sibling explains it better, so it must be rejected there")
        self.assertEqual(repair_cited_candidate_id("cand-perf-0o4", ["cand-perf-004"],
                                                   foreign=["cand-perf-003"]),
                         ("cand-perf-004", "near"), "local and closest = repaired")
        # a more specific sibling match also wins: prefix beats a near match on the local side
        self.assertIsNone(repair_cited_candidate_id("4e8820782eed4e", ["4e8820782eed4e17"],
                                                    foreign=["4e8820782eed4exx"])[0])

    def test_a_refused_citation_keeps_its_reason_and_names_the_nearest_candidate(self):
        """agents-afx5o: the refusal reason was computed and discarded, so a failed run said "no unique
        match" while holding the very ids it compared against - an operator could not tell a typo from a
        wrong-batch answer. The nearest candidate is named only when it is close enough to be plausible."""
        rows = [{"candidate_id": "4e8820782eed4e1xxx", "path": "a.py"},
                {"candidate_id": "4e8820782eed4e17", "path": "b.py"}]
        refusals = []
        applied = repair_cited_candidate_ids(rows, ["4e8820782eed4e17"], refusals=refusals)
        self.assertEqual(applied, [], "three edits is beyond the repair bound")
        self.assertEqual(refusals, [{"cited": "4e8820782eed4e1xxx", "path": "a.py",
                                     "reason": "no unique match (nearest candidate: "
                                               "4e8820782eed4e17 at 3 edits)"}])
        # an already-exact id is not a refusal, and a hopeless one does not name a 16-edit neighbour
        refusals.clear()
        repair_cited_candidate_ids([{"candidate_id": "4e8820782eed4e17"}], ["4e8820782eed4e17"],
                                   refusals=refusals)
        self.assertEqual(refusals, [])
        self.assertEqual(repair_cited_candidate_id("ffffffffffffffff", ["4e8820782eed4e17"]),
                         (None, "no unique match"))

    def test_repairs_are_recorded_and_make_a_complete_answer_accountable(self):
        presented = ["4e8820782eed4e17", "05622f455345d483"]
        rows = [{"candidate_id": "4e8820782eed17", "path": "a.py"},
                {"candidate_id": "05622f455345d483", "path": "b.py"}]
        repairs = repair_cited_candidate_ids(rows, presented)
        self.assertEqual([r["candidate_id"] for r in rows], presented, "rewritten in place")
        self.assertEqual(repairs, [{"cited": "4e8820782eed17", "repaired": "4e8820782eed4e17",
                                    "rule": "near", "path": "a.py"}])
        coverage = candidate_coverage(2, 2, presented_ids=presented,
                                      cited_ids=[r["candidate_id"] for r in rows])
        self.assertTrue(coverage["complete"], coverage)

    def test_an_empty_pre_pass_is_vacuously_complete(self):
        self.assertTrue(candidate_coverage(0, 0)["complete"])

    def test_a_partial_triage_is_not_complete_and_names_its_counts(self):
        got = candidate_coverage(49, 8)
        self.assertEqual((got["candidates_in"], got["candidates_presented"],
                          got["candidates_accounted"]), (49, 49, 8))
        self.assertFalse(got["complete"])
        self.assertIn("8 of the 49", got["reason"])

    def test_a_complete_triage_is_complete_including_its_dismissals(self):
        self.assertTrue(candidate_coverage(49, 49)["complete"])

    def test_the_bound_is_the_prompt_slice_not_the_raw_candidate_count(self):
        """A pre-pass that found more candidates than the prompt carries cannot make the run partial for
        the tail the model never received - that is the same defect mirrored."""
        got = candidate_coverage(389, CANDIDATE_PROMPT_SLICE)
        self.assertEqual(got["candidates_in"], 389)
        self.assertEqual(got["candidates_presented"], 50)
        self.assertTrue(got["complete"])
        self.assertFalse(candidate_coverage(389, CANDIDATE_PROMPT_SLICE - 1)["complete"])

    def test_one_candidate_short_of_the_slice_is_incomplete(self):
        self.assertFalse(candidate_coverage(1, 0)["complete"])
        self.assertTrue(candidate_coverage(1, 1)["complete"])

    def test_zero_of_n_shown_candidate_ids_fails_and_cites_accounts(self):
        """agents-11aq5: a station that cites 0 of N shown IDs must fail, and citing accounts."""
        ids = [f"cand-{i}" for i in range(50)]
        refused = candidate_coverage(50, 50, presented_ids=ids, cited_ids=[])
        self.assertFalse(refused["complete"])
        self.assertEqual(refused["candidates_accounted"], 0)
        self.assertEqual(refused["candidates_presented"], 50)
        self.assertEqual(refused["identity"], "identity-matched")
        self.assertIn("a partial triage is not a clean result", refused["reason"])
        self.assertEqual(
            refused["reason"],
            "cited 0 of the 50 candidate id(s) shown (50 found by the pre-pass): a partial triage is not a clean "
            "result; every row - confirmed or dismissed - must carry the candidate_id of the pre-pass candidate "
            "it answers"
        )

        accounted = candidate_coverage(50, 50, presented_ids=ids, cited_ids=ids)
        self.assertTrue(accounted["complete"])
        self.assertEqual(accounted["candidates_accounted"], 50)
        self.assertEqual(accounted["reason"], "")


class TestADuplicatedCitationIsNamedAndRepairedByPath(unittest.TestCase):
    """agents-amgst, measured on nightly 2026-10-23 (run dir modern-web-...-20261023-032632).

    Six modern-web dismissal rows, one per page, but the `docs/index.html` row cited `docs/help.html`'s
    candidate_id. Coverage intersected DISTINCT ids, so six rows accounted for five candidates and
    `b1cea3c268d41ac2` was cited by nobody - while `repair_cited_candidate_id` answered `(None, 'exact')`
    for both duplicate rows, so the row was invisible to repair AND to refusal and the operator saw only
    "cited 5 of the 6". One low-severity dismissal therefore made the whole night's findings UNKNOWN.
    """

    CANDIDATES = [
        ("d21fff3b2fa42e68", "docs/help.html"),
        ("b1cea3c268d41ac2", "docs/index.html"),
        ("51f53868c774953d", "docs/install.html"),
        ("c49da5acae4731ad", "docs/lines.html"),
        ("5eced7ca1f833236", "docs/stations.html"),
        ("21a8f812d9cebe04", "docs/use.html"),
    ]
    PRESENTED = [cid for cid, _ in CANDIDATES]
    PATHS = dict(CANDIDATES)

    def rows(self):
        """The measured report, exactly: the index.html row carries help.html's id."""
        return [
            {"candidate_id": "d21fff3b2fa42e68", "path": "docs/help.html"},
            {"candidate_id": "d21fff3b2fa42e68", "path": "docs/index.html"},
            {"candidate_id": "51f53868c774953d", "path": "docs/install.html"},
            {"candidate_id": "c49da5acae4731ad", "path": "docs/lines.html"},
            {"candidate_id": "5eced7ca1f833236", "path": "docs/stations.html"},
            {"candidate_id": "21a8f812d9cebe04", "path": "docs/use.html"},
        ]

    def test_the_shortfall_names_the_duplicate_and_the_unanswered_candidate(self):
        """The operator-facing reason must point at both, because "cited 5 of the 6" points at neither."""
        rows = self.rows()
        coverage = candidate_coverage(6, len(rows), presented_ids=self.PRESENTED,
                                      cited_ids=[row["candidate_id"] for row in rows])
        self.assertFalse(coverage["complete"])
        self.assertEqual(coverage["candidates_accounted"], 5)
        self.assertIn("cited 5 of the 6", coverage["reason"])
        self.assertIn("d21fff3b2fa42e68 cited by 2 rows", coverage["reason"])
        self.assertIn("presented id(s) no row cited: b1cea3c268d41ac2", coverage["reason"])
        self.assertEqual(coverage["duplicate_cited_ids"],
                         [{"candidate_id": "d21fff3b2fa42e68", "citations": 2}])
        self.assertEqual(coverage["uncited_candidate_ids"], ["b1cea3c268d41ac2"])

    def test_the_duplicated_row_is_re_bound_by_its_own_path_and_the_run_accounts(self):
        rows = self.rows()
        repairs = repair_cited_candidate_ids(rows, self.PRESENTED, candidate_paths=self.PATHS)
        self.assertEqual(repairs, [{"cited": "d21fff3b2fa42e68",
                                    "repaired": "b1cea3c268d41ac2",
                                    "rule": "path", "path": "docs/index.html"}],
                         "only the row whose own path names the uncited candidate may be rewritten")
        self.assertEqual([row["candidate_id"] for row in rows],
                         [cid for cid, _ in self.CANDIDATES])
        coverage = candidate_coverage(6, len(rows), presented_ids=self.PRESENTED,
                                      cited_ids=[row["candidate_id"] for row in rows])
        self.assertTrue(coverage["complete"], coverage)
        self.assertEqual((coverage["duplicate_cited_ids"], coverage["uncited_candidate_ids"]),
                         ([], []))

    def test_without_path_evidence_nothing_is_re_written_or_invented(self):
        rows = self.rows()
        self.assertEqual(repair_cited_candidate_ids(rows, self.PRESENTED), [],
                         "no candidate paths = no evidence, so the citation stays as written")
        self.assertEqual(rows[1]["candidate_id"], "d21fff3b2fa42e68")

    def test_the_candidate_paths_are_read_from_the_run_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            (run / "candidates.json").write_text(json.dumps({"candidates": [
                {"candidate_id": "d21fff3b2fa42e68", "path": "./docs/help.html"},
                {"candidate_id": "b1cea3c268d41ac2", "path": "docs/index.html"},
                {"candidate_id": "no-path-here"},
            ]}), encoding="utf-8")
            self.assertEqual(findings.read_candidate_paths(run), {
                "d21fff3b2fa42e68": "docs/help.html", "b1cea3c268d41ac2": "docs/index.html"},
                "a candidate with no path is not path evidence")
            self.assertEqual(findings.read_candidate_paths(None), {})
            (run / "candidates.json").write_text("not json", encoding="utf-8")
            self.assertEqual(findings.read_candidate_paths(run), {})


class TestThePathRepairRefusesRatherThanGuesses(unittest.TestCase):
    """The four conditions that must ALL hold before a duplicated citation is re-bound (agents-amgst)."""

    def test_an_ambiguous_path_is_left_alone_and_recorded_as_a_refusal(self):
        paths = {"cand-a": "src/x.js", "cand-b": "src/x.js", "cand-c": "src/y.js"}
        rows = [{"candidate_id": "cand-a", "path": "src/x.js"},
                {"candidate_id": "cand-a", "path": "src/x.js"}]
        refusals = []
        self.assertEqual(repair_cited_candidate_ids(rows, list(paths), candidate_paths=paths,
                                                   refusals=refusals), [])
        self.assertEqual([row["candidate_id"] for row in rows], ["cand-a", "cand-a"])
        self.assertEqual(len(refusals), 1, refusals)
        self.assertEqual(refusals[0]["cited"], "cand-a")
        self.assertIn("duplicated citation: 2 row(s) cite it", refusals[0]["reason"])
        self.assertIn("2 presented candidate id(s) stay unaccounted", refusals[0]["reason"])

    def test_two_candidates_in_one_file_are_ambiguous_even_when_one_is_uncited(self):
        """The MULTIPLICITY guard, on a run where it is the deciding check (agents-ifb3t).

        The test above refuses because `matches[0]` is already cited, so it would still pass with the
        `len(matches) != 1` half of the condition deleted - measured: the mutant
        `if not matches or matches[0] not in still_uncited:` bound this row and left the whole suite green.
        Two candidates in ONE file is the ordinary shape (one page, several findings), so the run that
        matters is the one where the ambiguous match is ALSO the still-uncited candidate: here `cand-p1-a`
        is cited by nobody and the duplicated `cand-p1-b` has no business inheriting its verdict.
        """
        paths = {"cand-p1-a": "src/x.js", "cand-p1-b": "src/x.js"}
        rows = [{"candidate_id": "cand-p1-b", "path": "src/x.js"},
                {"candidate_id": "cand-p1-b", "path": "src/x.js"}]
        refusals = []
        repairs = repair_cited_candidate_ids(rows, list(paths), candidate_paths=paths,
                                             refusals=refusals)
        self.assertEqual(repairs, [],
                         "one file, two candidates: the row cannot say which one it meant")
        self.assertEqual([row["candidate_id"] for row in rows], ["cand-p1-b", "cand-p1-b"])
        self.assertEqual(len(refusals), 1, refusals)
        self.assertEqual(refusals[0]["cited"], "cand-p1-b")
        self.assertIn("row path(s) do not name exactly one still-uncited presented candidate",
                      refusals[0]["reason"])
        self.assertIn("1 presented candidate id(s) stay unaccounted (cand-p1-a)",
                      refusals[0]["reason"])
        coverage = candidate_coverage(2, len(rows), presented_ids=list(paths),
                                      cited_ids=[row["candidate_id"] for row in rows])
        self.assertFalse(coverage["complete"], "an unresolved duplicate is still a shortfall")
        self.assertEqual(coverage["uncited_candidate_ids"], ["cand-p1-a"])

    def test_a_path_whose_only_candidate_is_already_cited_is_not_stolen(self):
        paths = {"cand-a": "p1", "cand-b": "p2", "cand-c": "p3"}
        rows = [{"candidate_id": "cand-a", "path": "p1"},
                {"candidate_id": "cand-a", "path": "p2"},   # p2 -> cand-b, but cand-b is cited
                {"candidate_id": "cand-b", "path": "p3"}]
        self.assertEqual(repair_cited_candidate_ids(rows, list(paths), candidate_paths=paths), [])
        self.assertEqual([row["candidate_id"] for row in rows],
                         ["cand-a", "cand-a", "cand-b"],
                         "a citation is never moved off a candidate another row already names")

    def test_an_intentional_duplicate_that_costs_no_coverage_is_untouched_and_unreported(self):
        """Two rows may legitimately answer one candidate; a duplicate only matters when it leaves a
        presented candidate uncited, so a complete run gets neither a rewrite nor a refusal."""
        paths = {"cand-a": "p1", "cand-b": "p2"}
        rows = [{"candidate_id": "cand-a", "path": "p1"},
                {"candidate_id": "cand-a", "path": "p1"},
                {"candidate_id": "cand-b", "path": "p2"}]
        refusals = []
        self.assertEqual(repair_cited_candidate_ids(rows, list(paths), candidate_paths=paths,
                                                   refusals=refusals), [])
        self.assertEqual(refusals, [])

    def test_every_resolvable_duplicate_row_is_re_bound_to_its_own_candidate(self):
        """Three rows quoting one id whose paths name three DIFFERENT candidates: all three are re-bound,
        and the id they all quoted becomes the unanswered one - visible in coverage, never silently lost.
        A row whose own path names the candidate it already cites is the one left alone (the measured
        2026-10-23 shape), so nothing is re-bound off a candidate another row legitimately answers."""
        paths = {"cand-a": "p1", "cand-b": "p2", "cand-c": "p3", "cand-d": "p4"}
        rows = [{"candidate_id": "cand-a", "path": "p2"},
                {"candidate_id": "cand-a", "path": "p3"},
                {"candidate_id": "cand-a", "path": "p4"}]
        repairs = repair_cited_candidate_ids(rows, list(paths), candidate_paths=paths)
        self.assertEqual([row["candidate_id"] for row in rows],
                         ["cand-b", "cand-c", "cand-d"])
        self.assertEqual([record["rule"] for record in repairs], ["path", "path", "path"])
        coverage = candidate_coverage(4, 3, presented_ids=list(paths),
                                      cited_ids=[row["candidate_id"] for row in rows])
        self.assertFalse(coverage["complete"], "cand-a is still unanswered")
        self.assertEqual(coverage["uncited_candidate_ids"], ["cand-a"])
        self.assertEqual(coverage["duplicate_cited_ids"], [])

        # the row that keeps its citation is the one whose own path names it
        rows = [{"candidate_id": "cand-a", "path": "p1"},
                {"candidate_id": "cand-a", "path": "p2"}]
        repair_cited_candidate_ids(rows, list(paths), candidate_paths=paths)
        self.assertEqual([row["candidate_id"] for row in rows], ["cand-a", "cand-b"])


class TestARowThatOmitsItsCandidateIdIsBoundByItsLocation(unittest.TestCase):
    """agents-op02b: the qrcode nightly's vuln-discovery rows named a candidate by path and carried no id.

    Measured shape: seven findings with `path`/`line_number` describing real pre-pass candidates and no
    `candidate_id` key at all. Every id-text rule skips such a row, so the station read "cited 0 of 7" and
    the run was INCOMPLETE while the answer to each candidate was sitting in the row itself. """

    LOCATIONS = {
        "cand-1": {"path": "src/a.ts", "line": 10},
        "cand-2": {"path": "src/a.ts", "line": 20},
        "cand-3": {"path": "src/b.ts", "line": 5},
    }
    PRESENTED = ["cand-1", "cand-2", "cand-3"]

    def cited(self, rows):
        return [row.get("candidate_id") for row in rows]

    def repair(self, rows, presented=None, locations=None, foreign=()):
        refusals = []
        repairs = repair_cited_candidate_ids(
            rows, self.PRESENTED if presented is None else presented, foreign=foreign,
            refusals=refusals,
            candidate_locations=self.LOCATIONS if locations is None else locations)
        return repairs, refusals

    def test_the_nightly_shape_now_accounts_for_every_candidate_it_was_shown(self):
        rows = [{"path": "src/a.ts", "line_number": 10},
                {"path": "src/a.ts", "line_number": 20},
                {"path": "src/b.ts", "line_number": 5}]
        repairs, refusals = self.repair(rows)
        self.assertEqual(self.cited(rows), self.PRESENTED, "each row keeps its own candidate")
        self.assertEqual(refusals, [])
        self.assertEqual([record["rule"] for record in repairs], ["path+line"] * 3)
        self.assertEqual([record["cited"] for record in repairs], [None] * 3,
                         "a repaired row had no id to quote, and the record must say so")
        coverage = candidate_coverage(3, len(rows), presented_ids=self.PRESENTED,
                                      cited_ids=self.cited(rows))
        self.assertTrue(coverage["complete"], coverage)
        self.assertEqual(coverage["rows_without_candidate_id"], 0)

    def test_a_unique_path_is_enough_when_the_row_names_no_line(self):
        rows = [{"path": "./src/b.ts"}]
        repairs, refusals = self.repair(rows)
        self.assertEqual(self.cited(rows), ["cand-3"], "a leading ./ is the same file")
        self.assertEqual(repairs[0]["rule"], "path")
        self.assertEqual(refusals, [])

    def test_a_line_that_matches_nothing_falls_back_to_the_only_candidate_in_that_file(self):
        rows = [{"path": "src/b.ts", "line_number": 99}]
        self.repair(rows)
        self.assertEqual(self.cited(rows), ["cand-3"],
                         "a unique path is a unique candidate; a model-written line cannot veto it")

    def test_a_shared_path_with_no_line_is_refused_rather_than_guessed(self):
        rows = [{"path": "src/a.ts"}]
        repairs, refusals = self.repair(rows)
        self.assertEqual(repairs, [])
        self.assertEqual(self.cited(rows), [None])
        self.assertEqual(len(refusals), 1, refusals)
        self.assertTrue(refusals[0]["missing"])
        self.assertIn("2 presented candidate(s) share its location", refusals[0]["reason"])
        self.assertIn("cand-1, cand-2", refusals[0]["reason"])

    def test_a_path_no_presented_candidate_has_is_refused(self):
        rows = [{"path": "src/elsewhere.ts", "line_number": 1}]
        repairs, refusals = self.repair(rows)
        self.assertEqual((repairs, self.cited(rows)), ([], [None]))
        self.assertIn("names none of the 3 presented candidate(s)", refusals[0]["reason"])

    def test_a_row_with_no_path_is_refused_and_named(self):
        rows = [{"title": "no location at all"}]
        repairs, refusals = self.repair(rows)
        self.assertEqual(repairs, [])
        self.assertIn("no path to match one on", refusals[0]["reason"])

    def test_a_candidate_another_row_already_cites_is_not_double_booked(self):
        rows = [{"candidate_id": "cand-2", "path": "src/a.ts", "line_number": 20},
                {"path": "src/a.ts", "line_number": 20}]
        repairs, refusals = self.repair(rows)
        self.assertEqual(repairs, [])
        self.assertEqual(self.cited(rows), ["cand-2", None])
        self.assertIn("already cited by another row", refusals[0]["reason"])

    def test_a_candidate_the_prompt_never_showed_blocks_a_better_looking_match(self):
        """agents-fv5uk one level over: if a record the model was NOT shown matches the location better
        (or equally well), the row may not be attached to a neighbour it merely shares a file with."""
        locations = dict(self.LOCATIONS)
        locations["cand-unshown"] = {"path": "src/a.ts", "line": 20}
        rows = [{"path": "src/a.ts", "line_number": 20}]
        repairs, refusals = self.repair(rows, locations=locations)
        self.assertEqual(repairs, [])
        self.assertEqual(self.cited(rows), [None])
        self.assertIn("NOT shown", refusals[0]["reason"])
        self.assertIn("cand-unshown", refusals[0]["reason"])

    def test_count_only_runs_neither_repair_nor_complain(self):
        # A pre-pass with no ids legitimately produces id-less rows: there is nothing to bind, and a
        # refusal per row would name the normal shape as a defect.
        rows = [{"path": "src/a.ts", "line_number": 10}]
        refusals = []
        self.assertEqual(repair_cited_candidate_ids(rows, [], refusals=refusals,
                                                    candidate_locations=self.LOCATIONS), [])
        self.assertEqual((self.cited(rows), refusals), ([None], []))

    def test_a_duplicated_citation_still_wins_over_a_missing_id_for_the_same_candidate(self):
        """The id rules run first, so a row that already cites a candidate is never re-bound by location -
        and a missing-id row is bound only onto what is left."""
        rows = [{"candidate_id": "cand-2", "path": "src/a.ts"},
                {"candidate_id": "cand-2", "path": "src/a.ts"},
                {"path": "src/b.ts", "line_number": 5}]
        self.repair(rows)
        self.assertEqual(self.cited(rows), ["cand-2", "cand-2", "cand-3"])

    def test_the_locations_are_read_from_the_run_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            (run / "candidates.json").write_text(json.dumps({"candidates": [
                {"candidate_id": "d21fff3b2fa42e68", "path": "./docs/help.html", "line_number": 12},
                {"candidate_id": "b1cea3c268d41ac2", "path": "docs/index.html",
                 "line_number": "7"},
                {"candidate_id": "no-path-here", "line_number": 3},
                {"rule_id": "r", "path": "docs/unidentified.html", "line_number": 4},
            ]}), encoding="utf-8")
            self.assertEqual(read_candidate_locations(run), {
                "d21fff3b2fa42e68": {"path": "docs/help.html", "line": 12},
                "b1cea3c268d41ac2": {"path": "docs/index.html", "line": 7}})
            self.assertEqual(read_candidate_paths(run), {
                "d21fff3b2fa42e68": "docs/help.html",
                "b1cea3c268d41ac2": "docs/index.html"},
                "the path-only reader is the same population, so the two cannot disagree")
            self.assertEqual(read_candidate_locations(Path(tmp) / "absent"), {})

    def test_the_location_reader_also_exposes_the_identity_a_shared_line_needs(self):
        """agents-k4pf1: two candidates can share a path AND a line, and then the rule/title is the only
        thing that tells them apart. Read through the comparison normalisation, and absent when the
        candidate carries neither - an absent key is not an empty value pretending to be one."""
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            (run / "candidates.json").write_text(json.dumps({"candidates": [
                {"candidate_id": "aaaa1111bbbb2222", "path": "assets/css/vendor.css",
                 "line_number": 1, "rule_id": "  Legacy-Reset ",
                 "title": "Vendor   reset contradicts native normalize"},
                {"candidate_id": "cccc3333dddd4444", "path": "assets/css/vendor.css",
                 "line_number": 1, "rule_id": "unused-vendor-prefix"},
            ]}), encoding="utf-8")
            self.assertEqual(read_candidate_locations(run), {
                "aaaa1111bbbb2222": {"path": "assets/css/vendor.css", "line": 1,
                                     "rule_id": "legacy-reset",
                                     "title": "vendor reset contradicts native normalize"},
                "cccc3333dddd4444": {"path": "assets/css/vendor.css", "line": 1,
                                     "rule_id": "unused-vendor-prefix"}})

    def test_the_repair_is_what_makes_a_partial_report_accountable_end_to_end(self):
        """The whole point: without the location repair this report is INCOMPLETE and names no cause; with
        it the rows account, and a row that could not be bound is reported as a row with no id."""
        presented = [f"cand-{i:02d}" for i in range(7)]
        locations = {cid: {"path": f"src/f{i}.ts", "line": i + 1}
                     for i, cid in enumerate(presented)}
        rows = [{"path": f"src/f{i}.ts", "line_number": i + 1} for i in range(6)]
        rows.append({"path": "src/f6.ts"})            # no line, unique path: still bindable
        before = candidate_coverage(7, len(rows), presented_ids=presented,
                                    cited_ids=[row.get("candidate_id") for row in rows])
        self.assertFalse(before["complete"])
        self.assertEqual(before["rows_without_candidate_id"], 7)
        self.assertIn("7 row(s) carried no candidate_id", before["reason"])
        refusals = []
        repair_cited_candidate_ids(rows, presented, refusals=refusals, candidate_locations=locations)
        self.assertEqual(refusals, [])
        after = candidate_coverage(7, len(rows), presented_ids=presented,
                                   cited_ids=[row.get("candidate_id") for row in rows])
        self.assertTrue(after["complete"], after)
        self.assertEqual(after["candidates_accounted"], 7)
        self.assertEqual(after["rows_without_candidate_id"], 0)


class TestASharedLocationIsNarrowedByTheRowsOwnRuleOrTitle(unittest.TestCase):
    """agents-k4pf1: two PRESENTED candidates on one line is not always an ambiguity.

    Measured shape: the modern-web nightly's pre-pass put two rule candidates on
    `assets/css/open-props-normalize.css:1`, so every row describing that line was refused as ambiguous and
    the station read 32/33 accounted - while each row's own `rule_id` named one of the two. A row's rule
    label is copied from the same pre-pass record the candidate came from, so it is evidence about which
    candidate the row answers, not a guess from its prose.
    """

    SHARED = {
        # The reported shape: same vendored line, two different rules.
        "aaaa1111bbbb2222": {"path": "assets/css/vendor.css", "line": 1,
                             "rule_id": "legacy-reset", "title": "Vendor reset contradicts native"},
        "cccc3333dddd4444": {"path": "assets/css/vendor.css", "line": 1,
                             "rule_id": "unused-vendor-prefix", "title": "Prefixed property, no modern form"},
        "eeee5555ffff6666": {"path": "index.html", "line": 7,
                             "rule_id": "legacy-viewport-media", "title": "Viewport media query"},
    }
    PRESENTED = ["aaaa1111bbbb2222", "cccc3333dddd4444", "eeee5555ffff6666"]

    def repair(self, rows, locations=None, presented=None):
        refusals = []
        repairs = repair_cited_candidate_ids(
            rows, self.PRESENTED if presented is None else presented, refusals=refusals,
            candidate_locations=self.SHARED if locations is None else locations)
        return repairs, refusals

    def cited(self, rows):
        return [row.get("candidate_id") for row in rows]

    def test_the_reported_shape_now_binds_on_the_rows_rule_id(self):
        rows = [{"path": "assets/css/vendor.css", "line_number": 1,
                 "rule_id": "unused-vendor-prefix"}]
        repairs, refusals = self.repair(rows)
        self.assertEqual(self.cited(rows), ["cccc3333dddd4444"])
        self.assertEqual(refusals, [])
        self.assertEqual(repairs[0]["rule"], "path+line+rule_id",
                         "the repair record must say WHICH evidence bound the row")

    def test_the_rule_is_compared_the_way_a_model_would_restate_it(self):
        rows = [{"path": "./assets/css/vendor.css", "line_number": 1,
                 "rule_id": " Legacy-Reset "}]
        self.repair(rows)
        self.assertEqual(self.cited(rows), ["aaaa1111bbbb2222"])

    def test_a_title_breaks_a_rule_tie(self):
        locations = dict(self.SHARED)
        locations["cccc3333dddd4444"] = dict(locations["cccc3333dddd4444"], rule_id="legacy-reset")
        rows = [{"path": "assets/css/vendor.css", "line_number": 1,
                 "rule_id": "legacy-reset", "title": "Prefixed property, no modern form"}]
        repairs, refusals = self.repair(rows, locations=locations)
        self.assertEqual((self.cited(rows), refusals), (["cccc3333dddd4444"], []))
        self.assertEqual(repairs[0]["rule"], "path+line+title",
                         "the rule both candidates carry is not the evidence that decided it, so it is not named")

    def test_a_rule_that_names_neither_candidate_still_refuses(self):
        """A model-written rule is not a licence to force a binding: a label belonging to neither candidate
        leaves the row as ambiguous as it was, and the refusal must say what was tried."""
        rows = [{"path": "assets/css/vendor.css", "line_number": 1, "rule_id": "not-a-rule"}]
        repairs, refusals = self.repair(rows)
        self.assertEqual((repairs, self.cited(rows)), ([], [None]))
        self.assertIn("2 presented candidate(s) share its location", refusals[0]["reason"])
        self.assertIn("its rule_id does not single one out", refusals[0]["reason"])

    def test_two_candidates_that_share_rule_and_title_are_still_refused(self):
        locations = dict(self.SHARED)
        locations["cccc3333dddd4444"] = dict(locations["aaaa1111bbbb2222"])
        rows = [{"path": "assets/css/vendor.css", "line_number": 1, "rule_id": "legacy-reset",
                 "title": "Vendor reset contradicts native"}]
        repairs, refusals = self.repair(rows, locations=locations)
        self.assertEqual((repairs, self.cited(rows)), ([], [None]))
        self.assertIn("its rule_id or title does not single one out", refusals[0]["reason"])

    def test_a_row_with_no_location_line_is_narrowed_the_same_way(self):
        rows = [{"path": "assets/css/vendor.css", "rule_id": "legacy-reset"}]
        repairs, refusals = self.repair(rows)
        self.assertEqual((self.cited(rows), refusals), (["aaaa1111bbbb2222"], []))
        self.assertEqual(repairs[0]["rule"], "path+rule_id")

    def test_an_unshown_candidate_with_a_different_rule_does_not_block_a_named_match(self):
        """The sibling guard must narrow WITH the row: a candidate that was never shown cannot be what a row
        naming this rule means when it carries a different rule, or the same ambiguity would reappear one
        population over and the line would stay unbindable."""
        locations = dict(self.SHARED)
        locations["9999888877776666"] = {"path": "assets/css/vendor.css", "line": 1,
                                         "rule_id": "another-rule", "title": "Another rule"}
        rows = [{"path": "assets/css/vendor.css", "line_number": 1,
                 "rule_id": "unused-vendor-prefix"}]
        repairs, refusals = self.repair(rows, locations=locations)
        self.assertEqual((self.cited(rows), refusals), (["cccc3333dddd4444"], []))
        self.assertEqual(repairs[0]["rule"], "path+line+rule_id")

    def test_an_unshown_candidate_with_the_same_rule_still_blocks(self):
        """The other half of the same rule: if the candidate the model never saw carries the SAME rule, the
        row could equally have been about it, and the repair must stay refused."""
        locations = dict(self.SHARED)
        locations["9999888877776666"] = {"path": "assets/css/vendor.css", "line": 1,
                                         "rule_id": "unused-vendor-prefix"}
        rows = [{"path": "assets/css/vendor.css", "line_number": 1,
                 "rule_id": "unused-vendor-prefix"}]
        repairs, refusals = self.repair(rows, locations=locations)
        self.assertEqual((repairs, self.cited(rows)), ([], [None]))
        self.assertIn("NOT shown", refusals[0]["reason"])
        self.assertIn("9999888877776666", refusals[0]["reason"])

    def test_the_narrowed_report_accounts_end_to_end(self):
        """What the operator sees: the station stops reading INCOMPLETE for a line the pre-pass recorded
        twice, and every shown candidate is accounted for."""
        rows = [{"path": "assets/css/vendor.css", "line_number": 1, "rule_id": "legacy-reset"},
                {"path": "assets/css/vendor.css", "line_number": 1,
                 "rule_id": "unused-vendor-prefix"},
                {"path": "index.html", "line_number": 7, "rule_id": "legacy-viewport-media"}]
        self.repair(rows)
        coverage = candidate_coverage(3, len(rows), presented_ids=self.PRESENTED,
                                      cited_ids=self.cited(rows))
        self.assertTrue(coverage["complete"], coverage)
        self.assertEqual(coverage["rows_without_candidate_id"], 0)


class TestCoverageDiagnosticsStayQuietWhenTheyWouldBeNoise(unittest.TestCase):
    def test_a_nothing_cited_report_does_not_list_forty_five_ids(self):
        ids = [f"cand-{i}" for i in range(45)]
        refused = candidate_coverage(45, 45, presented_ids=ids, cited_ids=[])
        self.assertFalse(refused["complete"])
        self.assertNotIn("presented id(s) no row cited", refused["reason"],
                         "\"cited 0\" is the whole finding; naming all 45 is a wall of ids")
        self.assertEqual(refused["duplicate_cited_ids"], [])
        self.assertEqual(refused["uncited_candidate_ids"], ids,
                         "the structured field still carries the full population")

    def test_a_large_shortfall_names_a_bounded_number_of_ids(self):
        ids = [f"cand-{i}" for i in range(45)]
        got = candidate_coverage(45, 45, presented_ids=ids, cited_ids=ids[:1])
        self.assertIn("presented id(s) no row cited: cand-1, cand-2, cand-3, cand-4, cand-5, +39 more",
                      got["reason"])

    def test_a_count_only_station_carries_no_identity_diagnostics(self):
        got = candidate_coverage(5, 2, presented_ids=[])
        self.assertEqual((got["duplicate_cited_ids"], got["uncited_candidate_ids"]), ([], []))
        self.assertNotIn("presented id(s)", got["reason"])


class TestStationPredicates(unittest.TestCase):
    """agents-kve2, agents-pim5: one predicate pair, and the two facts stay independent.

    The three surfaces that broke each re-derived "has a verdict" locally. These pin the shared answer,
    including the case a single fused predicate would get wrong: an ALERT with a partial triage HAS a
    verdict (the alarm) and IS incomplete (the caveat) at the same time.
    """

    def test_completeness_is_the_missing_key_tolerant_way_round(self):
        self.assertFalse(station_is_incomplete({"status": "PASS"}))
        self.assertFalse(station_is_incomplete({"status": "PASS", "complete": True}))
        self.assertTrue(station_is_incomplete({"status": "PASS", "complete": False}))
        self.assertTrue(station_is_incomplete({"status": "INCOMPLETE", "complete": False}))

    def test_an_incomplete_station_has_no_verdict(self):
        self.assertFalse(station_has_verdict({"status": "INCOMPLETE", "complete": False}))
        self.assertFalse(station_has_verdict({"status": "ERROR"}))
        self.assertFalse(station_has_verdict({"status": "TIMEOUT"}))
        self.assertFalse(station_has_verdict({"status": "ENV_FAILURE"}))
        self.assertFalse(station_has_verdict({"status": "SKIPPED"}))

    def test_the_alarm_keeps_its_verdict_and_keeps_its_caveat(self):
        partial_alert = {"status": "ALERT", "findings_count": 1, "criticals": 1, "complete": False}
        self.assertTrue(station_has_verdict(partial_alert))
        self.assertTrue(station_is_incomplete(partial_alert))

    def test_a_verdict_needs_counts_as_well_as_a_completed_status(self):
        """agents-ekwm: None is unknown, not zero - the union clause xx9t's lighter predicate lacked."""
        self.assertFalse(station_has_verdict({"status": "PASS", "findings_count": None,
                                              "criticals": None}))
        self.assertFalse(station_has_verdict({"status": "PASS", "findings_count": None,
                                              "criticals": 0}))
        self.assertFalse(station_has_verdict({"status": "PASS", "findings_count": 0}))
        self.assertTrue(station_has_verdict({"status": "PASS", "findings_count": 0, "criticals": 0}))
        self.assertFalse(station_has_verdict(None))
        self.assertFalse(station_has_verdict("PASS"))

    def test_a_clean_verdict_is_neither_partial_nor_verdictless(self):
        for status in ("PASS", "ALERT"):
            with self.subTest(status):
                self.assertTrue(station_has_verdict({"status": status, "findings_count": 0,
                                                       "criticals": 0}))
                self.assertFalse(station_is_incomplete({"status": status}))
class TestLineDeltaVerdictCounts(unittest.TestCase):
    """agents-ekwm: a missing station verdict is unknown, not a zero-count scan."""

    DASH_ROW = "| — | — | — | — | — | — |"
    ZERO_ROW = "| **0** | **0** | **0** | 0 | 0 | 0 |"

    def report(self, stations, stats=None):
        return findings._render_delta_report(
            "target", [], stats or {key: 0 for key in findings.DELTA_KEYS}, [],
            stations=stations, line_name="project-audit",
        )

    def top_row(self, report):
        rows = report.splitlines()
        header = "| New | Regressed | Fixed | Unchanged | Suppressed | False positive |"
        return rows[rows.index(header) + 2]

    def test_timeout_error_and_skipped_are_unknown_but_completed_zero_is_real(self):
        for status in ("TIMEOUT", "ERROR", "SKIPPED"):
            with self.subTest(status=status):
                station = {"station": "triage", "status": status,
                           "findings_count": None, "criticals": None}
                report = self.report([station])
                self.assertEqual(self.top_row(report), self.DASH_ROW,
                                 f"{status} without a verdict rendered as zero findings")
                self.assertIn(f"| `triage` | {status} | — | — |", report)
                self.assertIn("INCOMPLETE", report)
                self.assertNotIn("Clean Delta", report)
        completed = {"station": "quiet", "status": "PASS", "findings_count": 0, "criticals": 0}
        report = self.report([completed])
        self.assertEqual(self.top_row(report), self.ZERO_ROW,
                         "a completed zero-findings station must keep a real zero")
        self.assertIn("| `quiet` | PASS | 0 | 0 |", report)
        self.assertIn("Clean Delta", report)

    def test_partial_triage_top_row_is_unknown_but_clean_zero_and_alert_counts_survive(self):
        partial = {"station": "perf-review", "status": "INCOMPLETE", "complete": False,
                   "findings_count": 0, "criticals": 0, "candidates_presented": 49,
                   "candidates_accounted": 8, "candidate_identity": "identity-matched",
                   "note": "cited 8 of 49"}
        unknown = self.report([partial])
        self.assertEqual(self.top_row(unknown), self.DASH_ROW,
                         "8/49 cited is not evidence of a clean zero-finding line")
        self.assertIn("| `perf-review` | INCOMPLETE | — | — | cited 8 of 49 |", unknown)
        self.assertIn("did not account for the candidates they were shown", unknown)
        self.assertNotIn("Clean Delta", unknown)

        complete = {"station": "perf-review", "status": "PASS", "complete": True,
                    "findings_count": 0, "criticals": 0, "candidates_presented": 49,
                    "candidates_accounted": 49, "candidate_identity": "identity-matched"}
        clean = self.report([complete])
        self.assertEqual(self.top_row(clean), self.ZERO_ROW,
                         "49/49 clean must remain a genuine numeric zero")
        self.assertIn("| `perf-review` | PASS | 0 (49/49, identity-matched) | 0 |", clean)
        self.assertIn("Clean Delta", clean)

        alarm = {**partial, "status": "ALERT", "findings_count": 1, "criticals": 1}
        alerted = self.report([alarm])
        self.assertEqual(self.top_row(alerted), self.DASH_ROW)
        self.assertIn("| `perf-review` | ALERT | 1 (8/49, identity-matched) | 1 | cited 8 of 49 |", alerted,
                      "an incomplete aggregate must not erase a real station alarm")

    def test_partial_verdict_keeps_its_counts_but_aggregate_is_unknown(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            fragment = root / "completed-fragment.json"
            fragment.write_text(json.dumps({"stats": {"new": 2}}), encoding="utf-8")
            stations = [
                {"station": "completed", "status": "ALERT", "findings_count": 2,
                 "criticals": 0, "fragment": str(fragment)},
                {"station": "triage", "status": "TIMEOUT", "findings_count": None,
                 "criticals": None},
            ]
            path = findings.write_line_report("target", "project-audit", stations, findings_dir=root)
            report = path.read_text(encoding="utf-8")
            machine = json.loads((root / "target-line.json").read_text(encoding="utf-8"))
        self.assertEqual(self.top_row(report), self.DASH_ROW,
                         "a partial verdict cannot make the aggregate look complete")
        self.assertIn("| `completed` | ALERT | 2 | 0 |", report)
        self.assertEqual(machine["stats"]["new"], 2, "retain actual partial findings in the machine record")
        self.assertFalse(machine["complete"])

    def test_error_status_cannot_promote_stale_counts_to_a_verdict(self):
        station = {"station": "failed", "status": "ERROR", "findings_count": 3,
                   "criticals": 1}
        report = self.report([station])
        self.assertEqual(self.top_row(report), self.DASH_ROW,
                         "a failed station's stale count is not a completed verdict")
        self.assertIn("| `failed` | ERROR | — | — |", report)
        self.assertIn("INCOMPLETE", report)

    def test_pass_without_count_is_not_a_clean_zero(self):
        station = {"station": "missing", "status": "PASS", "findings_count": None,
                   "criticals": None}
        report = self.report([station])
        self.assertEqual(self.top_row(report), self.DASH_ROW,
                         "PASS with missing counts is not evidence of a zero-findings scan")
        self.assertIn("INCOMPLETE", report)

    # ---------------------------------------------------------------------------------------
    # agents-pxzb: the possible-re-key pairing is run-level, and the line is where the run is
    # visible. The counter's own sentence always said 'a row this run booked Fixed'.

    def _pxzb_row(self, agent, source, state="fixed", change="fixed", line=192, path="docs/css/factory.css"):
        return {"fingerprint": f"fp-{agent}-{source}", "agent": agent, "rule_id": "unclassified",
                "path": path, "line_number": line, "snippet": "prose", "identity_source": source,
                "severity": "medium", "title": "t", "description": "d", "remediation": "r",
                "state": state, "change": change, "false_positive": False}

    def _pxzb_line(self, root, stations_spec):
        """Build one fragment per station and ask write_line_report for the aggregate."""
        stations = []
        for name, (new_rows, fixed_rows, station_pairs) in stations_spec:
            frag = root / f"{name}.json"
            frag.write_text(json.dumps({
                "stats": {"new": len(new_rows), "fixed": len(fixed_rows),
                          "possible_rekey": station_pairs},
                "findings": new_rows, "fixed": fixed_rows, "sinks": {}}), encoding="utf-8")
            stations.append({"station": name, "status": "ALERT",
                             "findings_count": len(new_rows), "criticals": 0,
                             "fragment": str(frag)})
        findings.write_line_report("target", "factory", stations, findings_dir=root)
        return json.loads((root / "target-line.json").read_text(encoding="utf-8"))["stats"]

    def test_a_pair_split_across_two_stations_is_counted_at_the_line_level(self):
        """THE agents-pxzb DEFECT, with the nightly's own shape: a `new` row under one station and the
        Fixed twin of it booked by ANOTHER station. Both fragments report possible_rekey 0, so the summed
        aggregate was 0 and the pair was invisible for the whole run - the appearance stayed a New row
        every run with nothing saying its twin had retired elsewhere. Nothing is reclassified here either:
        the row keeps `new` and only the counter moves."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            stats = self._pxzb_line(root, [
                ("vuln-triage", ([self._pxzb_row("vuln-triage", "no-candidate-index", state="new",
                                                 change="new")], [], 0)),
                ("modern-web", ([], [self._pxzb_row("modern-web", "no-candidate-index")], 0)),
            ])
        self.assertEqual(stats["possible_rekey"], 1,
                         "the two halves are in different stations, so only the line can pair them")
        self.assertEqual((stats["new"], stats["fixed"]), (1, 1),
                         "and nothing is reclassified: the appearance is still counted as new")

    def test_a_same_station_pair_is_not_double_counted(self):
        """The other direction, and the one that would make the counter useless: a pair inside ONE
        station is already counted there, so the line must report 1 and not 2."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            stats = self._pxzb_line(root, [
                ("vuln-triage", ([self._pxzb_row("vuln-triage", "no-candidate-index", state="new",
                                                 change="new")],
                                 [self._pxzb_row("vuln-triage", "no-candidate-index")], 1)),
            ])
        self.assertEqual(stats["possible_rekey"], 1)

    def test_an_anchored_twin_is_still_refused_when_another_station_booked_it(self):
        """THE RULE IS DELIBERATELY NOT WIDENED, and this is the nightly's example, so the omission is
        pinned rather than left to be rediscovered: `docs/css/factory.css:192` is a `new` row under
        vuln-triage (`no-candidate-index`) whose Fixed twin modern-web booked with `candidate-id`, and
        `candidate-id` is in IDENTITY_STABLE_SOURCES - so both the station and the line refuse the pair.
        Soundness says a stable anchor WOULD have matched this run's rows, which is true only WITHIN a
        station: a station compares its own agent's rows, so an anchored twin booked elsewhere was never
        offered to this appearance. Widening that is a soundness decision (agents-wcki), not the scope
        fix above, so it is recorded here and left to the owner of that argument."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            stats = self._pxzb_line(root, [
                ("vuln-triage", ([self._pxzb_row("vuln-triage", "no-candidate-index", state="new",
                                                 change="new")], [], 0)),
                ("modern-web", ([], [self._pxzb_row("modern-web", "candidate-id")], 0)),
            ])
        self.assertEqual(stats["possible_rekey"], 0,
                         "an anchored twin is refused at run level too - see this test's docstring")

    def test_the_count_never_falls_below_the_summed_station_counters(self):
        """The fail-safe direction: if a fragment cannot supply the rows the run-level recomputation
        needs (an older shape, a trimmed fragment), the summed station value must SURVIVE rather than be
        replaced by a smaller number computed from rows that are not there."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            stats = self._pxzb_line(root, [
                ("quiet", ([], [], 2)),
            ])
        self.assertEqual(stats["possible_rekey"], 2)

    def test_two_appearances_at_one_recycled_line_consume_one_retiring_row(self):
        """One retiring row explains exactly ONE appearance (agents-l3j1), and the run-level pass has to
        keep that: without the consume, two appearances at a recycled line would both be counted against a
        single retired row."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            stats = self._pxzb_line(root, [
                ("vuln-triage", ([self._pxzb_row("vuln-triage", "no-candidate-index", state="new",
                                                 change="new"),
                                  self._pxzb_row("vuln-triage", "model-snippet", state="new",
                                                 change="new")], [], 0)),
                ("modern-web", ([], [self._pxzb_row("modern-web", "no-candidate-index")], 0)),
            ])
        self.assertEqual(stats["possible_rekey"], 1)


    def test_an_anchored_cross_station_pair_is_disclosed_and_nothing_is_reclassified(self):
        """agents-09wf / decision agents-u2xe option (a)+(c): the nightly's OWN example, now DISCLOSED.

        `docs/css/factory.css:192` is a `new` row under vuln-triage (`no-candidate-index`) whose Fixed
        twin modern-web booked with `candidate-id`. `test_an_anchored_twin_is_still_refused_when_another_
        station_booked_it` above pins that the pair is REFUSED - and it stays refused, which is why this
        test asserts `possible_rekey` is still 0: the two counters are DISJOINT by construction (the
        sibling counts both-prose-bound pairs, this one counts at-least-one-anchored pairs), so the old
        value cannot move. What changes is that the pair is no longer SILENTLY dropped: it appears in its
        own disclosed counter and its own banner, and both rows keep their states.

        The "unchanged on real data" premise is ATTRIBUTED, not re-derived here: over the 2026-10-14
        03:xx nightly's eleven station fragments the run-level count under the original rule equalled the
        summed station counters (2), with no cross-station same-location New/Fixed coincidence - measured
        on agents-pxzb by imp-dflt. This code does not depend on that measurement being right; it depends
        on it to say the DISCLOSED count is 0 on today's data.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            stats = self._pxzb_line(root, [
                ("vuln-triage", ([self._pxzb_row("vuln-triage", "no-candidate-index", state="new",
                                                 change="new")], [], 0)),
                ("modern-web", ([], [self._pxzb_row("modern-web", "candidate-id")], 0)),
            ])
            report = (root / "target-delta.md").read_text(encoding="utf-8")
        self.assertEqual(stats["possible_rekey_anchored"], 1,
                         "the anchored cross-station twin is disclosed instead of silently dropped")
        self.assertEqual(stats["possible_rekey"], 0,
                         "and the original counter is UNCHANGED - the pair is not reclassified into it")
        self.assertEqual((stats["new"], stats["fixed"]), (1, 1),
                         "nothing is reclassified: the appearance is still new and the twin still Fixed")
        self.assertIn("Advisory", report, "the disclosure reaches the report, not only the stats dict")
        self.assertIn("not reclassified", report)

    def test_a_station_local_anchored_pair_stays_refused_and_uncounted(self):
        """THE COUNTEREXAMPLE THAT MUST STILL FAIL, and the reason the counter is cross-station only.

        Inside ONE station the anchor IS comparable: `candidate-id` there means "the station assigned
        this identity to a candidate it presented", so "the anchor would have matched" is sound and the
        pair is genuinely not a re-key. That is the case the original refusal exists for, so it must be
        neither paired nor disclosed - if this goes green by accident, the change has drifted from the
        decision.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            stats = self._pxzb_line(root, [
                ("vuln-triage", ([self._pxzb_row("vuln-triage", "no-candidate-index", state="new",
                                                 change="new")],
                                 [self._pxzb_row("vuln-triage", "candidate-id")], 0)),
            ])
        self.assertEqual(stats["possible_rekey_anchored"], 0,
                         "a station-local anchored pair is not disclosed as a cross-station one")
        self.assertEqual(stats["possible_rekey"], 0, "and it is still not a prose-bound re-key either")

    def test_a_prose_bound_cross_station_pair_stays_in_the_original_counter_only(self):
        """The other disjointness direction: a cross-station pair with NO anchor on either side belongs
        to `possible_rekey` and must not also appear in the anchored counter - otherwise one pair would
        be reported twice and the two numbers would stop being additive."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            stats = self._pxzb_line(root, [
                ("vuln-triage", ([self._pxzb_row("vuln-triage", "no-candidate-index", state="new",
                                                 change="new")], [], 0)),
                ("modern-web", ([], [self._pxzb_row("modern-web", "model-snippet")], 0)),
            ])
        self.assertEqual(stats["possible_rekey"], 1, "both sides prose-bound is the original counter's case")
        self.assertEqual(stats["possible_rekey_anchored"], 0,
                         "and it is not double-counted into the anchored one")

    def test_an_unknown_agent_is_not_evidence_of_a_cross_station_pair(self):
        """A FLOOR rather than a guess (agents-yh0z's discipline): the counter needs a KNOWN, DIFFERING
        agent on both sides. An anchored twin whose station is unknown is not evidence that the pair is
        cross-station, so it is left out rather than assumed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            unknown = self._pxzb_row("modern-web", "candidate-id")
            unknown.pop("agent")
            stats = self._pxzb_line(root, [
                ("vuln-triage", ([self._pxzb_row("vuln-triage", "no-candidate-index", state="new",
                                                 change="new")], [], 0)),
                ("modern-web", ([], [unknown], 0)),
            ])
        self.assertEqual(stats["possible_rekey_anchored"], 0,
                         "an unknown agent cannot establish that the pair spans two stations")

    def test_two_appearances_consume_one_retiring_row_in_the_anchored_counter(self):
        """One retiring row explains exactly ONE appearance (agents-l3j1), and the anchored counter keeps
        that rule too: without the consume, N appearances at a recycled line would all count against a
        single retired row."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            stats = self._pxzb_line(root, [
                ("vuln-triage", ([self._pxzb_row("vuln-triage", "no-candidate-index", state="new",
                                                 change="new"),
                                  self._pxzb_row("vuln-triage", "model-snippet", state="new",
                                                 change="new")], [], 0)),
                ("modern-web", ([], [self._pxzb_row("modern-web", "candidate-id")], 0)),
            ])
        self.assertEqual(stats["possible_rekey_anchored"], 1,
                         "one retiring row, two anchored-eligible appearances, ONE pair")
    def test_a_row_with_no_usable_line_is_never_paired(self):
        """The floor rule (agents-yh0z) survives the move: rows whose line the scanner could not name are
        not paired on a location neither of them has."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            stats = self._pxzb_line(root, [
                ("vuln-triage", ([self._pxzb_row("vuln-triage", "no-candidate-index", state="new",
                                                 change="new", line=None)], [], 0)),
                ("modern-web", ([], [self._pxzb_row("modern-web", "no-candidate-index", line=None)], 0)),
            ])
        self.assertEqual(stats["possible_rekey"], 0)


class TestFixedRowsNameTheLinesThatAreContradicted(unittest.TestCase):
    """agents-x9my: the Fixed section warns in GENERAL that a disappearance is not proof; these pin the
    per-row marker that names the specific lines a live row sits on, so nothing needs cross-referencing by
    hand. It is disclosure only: no reclassification, no identity change, and it does not touch the pairing
    `possible_rekey` counts."""

    def _row(self, **over):
        row = {"fingerprint": "fp", "agent": "vuln-triage", "rule_id": "unclassified", "path": "a.py",
               "line_number": 7, "snippet": "prose", "identity_source": "no-candidate-index",
               "severity": "low", "title": "t", "description": "d", "remediation": "r",
               "state": "fixed", "change": "fixed", "false_positive": False}
        row.update(over)
        return row

    def _report(self, findings_rows, fixed_rows):
        stats = {key: 0 for key in findings.DELTA_KEYS}
        stats["new"] = sum(1 for r in findings_rows if r.get("change") == "new")
        stats["fixed"] = len(fixed_rows)
        return findings._render_delta_report("target", findings_rows, stats, fixed_rows)

    def test_a_fixed_row_is_marked_when_a_new_row_sits_on_its_exact_line(self):
        report = self._report([self._row(state="new", change="new")], [self._row()])
        self.assertIn("contradicted here", report)
        self.assertIn("1 NEW finding", report)
        self.assertIn("read that row before closing anything on this line", report)

    def test_the_same_fixed_row_is_silent_when_the_new_row_is_on_another_line(self):
        """The control that makes the marker mean something: a live row elsewhere in the same file must not
        mark this line, or every Fixed row in a busy file would be flagged."""
        report = self._report([self._row(state="new", change="new", line_number=8)], [self._row()])
        self.assertIn("## Resolved in this Run (Fixed)", report)
        self.assertNotIn("contradicted here", report)

    def test_a_false_positive_at_the_line_does_not_mark_the_fixed_row(self):
        """A dismissed row is not a live finding, so it is not a contradiction of anything."""
        report = self._report([self._row(state="new", change="new", false_positive=True)], [self._row()])
        self.assertNotIn("contradicted here", report)

    def test_an_unchanged_row_at_the_line_does_not_mark_the_fixed_row(self):
        report = self._report([self._row(state="new", change="unchanged")], [self._row()])
        self.assertNotIn("contradicted here", report)

    def test_a_row_with_no_usable_line_is_never_marked(self):
        """The agents-yh0z floor survives: an unnamed line cannot be paired with another unnamed line."""
        report = self._report([self._row(state="new", change="new", line_number=None)], [self._row(line_number=None)])
        self.assertNotIn("contradicted here", report)

    def test_the_marker_does_not_depend_on_either_side_s_identity_source(self):
        """Deliberately ANCHORED on both sides, which is the agents-u2xe question, and deliberately still
        marked: naming the line a live row occupies is a coincidence the report can observe, whereas whether
        an anchored twin may be PAIRED into the possible_rekey count is that decision's, not this one's."""
        report = self._report(
            [self._row(state="new", change="new", identity_source="candidate-id")],
            [self._row(identity_source="candidate-id")],
        )
        self.assertIn("contradicted here", report)

    def test_two_new_rows_on_the_line_are_counted_in_the_marker(self):
        report = self._report(
            [self._row(state="new", change="new", fingerprint="fp1"),
             self._row(state="new", change="new", fingerprint="fp2")],
            [self._row()],
        )
        self.assertIn("2 NEW findings", report)


if __name__ == "__main__":
    unittest.main()

