#!/usr/bin/env python3
"""Focused tests for the findings store's durability and concurrency guarantees (agents-3ls).

Covers the two failure modes the bug described: a crash/truncated store being silently reset to
empty (which re-books every prior finding as new), and concurrent factory processes losing each
other's findings via last-writer-wins read-modify-write.
"""

import hashlib
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
from lib.candidate_identity import assign_candidate_ids
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


if __name__ == "__main__":
    unittest.main()


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
            self.assertIn("Identity migration (one-time)",
                          findings._render_delta_report("target", processed, stats, fixed))

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
            self.assertNotIn("313b2133ae08c979", store_file.read_text(),
                             "the raw id must not be persisted: the fingerprint carries identity")

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
        from lib.redaction import redact_finding

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
        observed = set()
        with tempfile.TemporaryDirectory() as td:
            cases = [
                (self._finding(), single),                                  # exact
                (self._finding(), single_with_id),                          # candidate-id
                (self._finding(line_number=99), single),                    # unique
                (self._finding(line_number=99, snippet="reads beta gamma"),
                 ambiguous),                                                # similar-by-model-snippet
                (self._finding(line_number=99, snippet="nothing like it"), ambiguous),  # model-snippet
                (self._finding(), None),                                    # no-candidate-index
                # The location fallbacks need a label that binds nothing, or the rule-keyed
                # lookups answer first and these are unreachable.
                (self._finding(rule_id="invented"), single),                 # location-unique
                (self._finding(rule_id="invented", line_number=99), single),  # path-unique
            ]
            for item, index in cases:
                observed.add(self._run(td, [item], index)[0][0]["identity_source"])
        self.assertEqual(observed, set(findings.IDENTITY_SOURCES), observed)
