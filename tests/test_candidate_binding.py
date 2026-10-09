#!/usr/bin/env python3
"""A finding's rule_id and path are bound to the scanner's candidates (agents-nha).

The triage model returns both strings, so without a binding they are whatever the model wrote:
stored, fingerprinted and rendered. The dispatcher already writes the deterministic scanner's
candidates to the run directory; these tests cover the contract that validates against them,
and the cases where there is nothing to bind to (agents with no pre-pass, or candidates that
are not location-shaped).
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.findings import (  # noqa: E402
    FindingsStore,
    bind_candidates,
    compute_fingerprint,
    load_candidate_index,
    normalize_path,
)


def candidate(rule_id="scanner-rule", path="src/a.js"):
    return {"rule_id": rule_id, "path": path, "line_number": 1, "snippet": "x"}


def finding(**overrides):
    base = {"rule_id": "scanner-rule", "path": "src/a.js", "line_number": 1,
            "snippet": "x", "severity": "low", "title": "t", "description": "d"}
    base.update(overrides)
    return base


class TestNormalizePath(unittest.TestCase):
    def test_normalization_is_shared_with_fingerprints(self):
        for value in ("./src/a.js", "src\\a.js", "  src/a.js  "):
            with self.subTest(value=value):
                self.assertEqual(normalize_path(value), "src/a.js")

    def test_non_text_paths_have_no_normal_form(self):
        self.assertEqual(normalize_path(None), "")
        self.assertEqual(normalize_path({"path": "src/a.js"}), "")


class TestCandidateIndex(unittest.TestCase):
    def _index(self, payload):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "candidates.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            return load_candidate_index(path)

    def test_index_collects_rules_and_normalized_paths(self):
        index = self._index({"candidates": [candidate(), candidate(rule_id="other", path="./src/b.js")]})
        self.assertEqual(index["rule_ids"], {"scanner-rule", "other"})
        self.assertEqual(index["paths"], {"src/a.js", "src/b.js"})

    def test_bare_list_payload_is_supported(self):
        index = self._index([candidate()])
        self.assertIn("scanner-rule", index["rule_ids"])

    def test_context_payloads_return_no_index(self):
        self.assertIsNone(self._index({"summary": "no candidates here"}))
        self.assertIsNone(self._index({"candidates": "not a list"}))
        self.assertIsNone(self._index({"candidates": []}))

    def test_issue_shaped_candidates_return_no_index(self):
        """issue-triage candidates are issue records: nothing location-shaped to bind to."""
        self.assertIsNone(self._index({"candidates": [{"id": "42", "title": "an issue"}]}))

    def test_missing_file_returns_no_index(self):
        self.assertIsNone(load_candidate_index(Path("/nonexistent/candidates.json")))


class TestBinding(unittest.TestCase):
    INDEX = {"rule_ids": {"scanner-rule"}, "paths": {"src/a.js"}}

    def test_matching_values_pass_through(self):
        self.assertEqual(bind_candidates(finding(rule_id="scanner-rule", path="./src/a.js"), self.INDEX),
                         ("scanner-rule", "./src/a.js"))

    def test_unknown_rule_becomes_unclassified(self):
        self.assertEqual(bind_candidates(finding(rule_id="model-invented"), self.INDEX),
                         ("unclassified", "src/a.js"))

    def test_unknown_path_becomes_unknown(self):
        self.assertEqual(bind_candidates(finding(path="elsewhere.js"), self.INDEX),
                         ("scanner-rule", "unknown"))

    def test_no_index_keeps_the_model_values(self):
        self.assertEqual(bind_candidates(finding(rule_id="model-rule", path="model/path.js"), None),
                         ("model-rule", "model/path.js"))

    def test_missing_fields_get_their_defaults(self):
        self.assertEqual(bind_candidates({}, None), ("generic", ""))

    def test_non_text_rule_id_cannot_match(self):
        rule_id, _ = bind_candidates(finding(rule_id={"rule": "scanner-rule"}), self.INDEX)
        self.assertEqual(rule_id, "unclassified")


class TestProcessRunBinding(unittest.TestCase):
    INDEX = {"rule_ids": {"scanner-rule"}, "paths": {"src/a.js"}}

    def test_store_records_the_bound_values(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = FindingsStore("target", findings_dir=Path(tmpdir))
            processed, _, _ = store.process_run(
                "docs-drift", [finding(rule_id="invented", path="elsewhere.js")],
                candidate_index=self.INDEX,
            )
            self.assertEqual(processed[0]["rule_id"], "unclassified")
            self.assertEqual(processed[0]["path"], "unknown")

    def test_fingerprint_uses_the_bound_values(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = FindingsStore("target", findings_dir=Path(tmpdir))
            processed, _, _ = store.process_run(
                "docs-drift", [finding(rule_id="invented", path="elsewhere.js")],
                candidate_index=self.INDEX,
            )
            self.assertEqual(
                processed[0]["fingerprint"],
                compute_fingerprint("docs-drift", "unclassified", "unknown", "x"),
            )

    def test_binding_is_stable_across_runs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = FindingsStore("target", findings_dir=Path(tmpdir))
            item = finding()
            store.process_run("docs-drift", [item], candidate_index=self.INDEX)
            _, stats, _ = store.process_run("docs-drift", [dict(item, line_number=999)],
                                            candidate_index=self.INDEX)
            self.assertEqual(stats["unchanged"], 1)

    def test_no_candidates_is_the_previous_behaviour(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = FindingsStore("target", findings_dir=Path(tmpdir))
            processed, _, _ = store.process_run(
                "docs-drift", [finding(rule_id="model-rule", path="model/path.js")],
            )
            self.assertEqual(processed[0]["rule_id"], "model-rule")
            self.assertEqual(processed[0]["path"], "model/path.js")


if __name__ == "__main__":
    unittest.main()


class TestBindingNeverDestroysARealLocation(unittest.TestCase):
    """agents-0tl: binding must keep the guard's purpose without destroying real locations.

    Observed on the 2026-10-09 dogfood audit: vuln-discovery's candidates file holds exactly one
    entry, the threat-model CONTEXT ({rule_id: threat-model-context, path: THREAT_MODEL.md}),
    which was enough to arm binding - so all seven real model locations (lib/bench/runner.py,
    agents/memory-profile/scripts/scan_memory_leaks.py, ...) were replaced with 'unknown' and
    the findings became untriageable. One of them was real and is now fixed (agents-uxt).
    """

    # The context-shaped index that caused it, as load_candidate_index built it.
    CONTEXT_INDEX = {"rule_ids": {"threat-model-context"}, "paths": {"THREAT_MODEL.md"}}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.target = Path(self.tmp.name)
        (self.target / "lib" / "bench").mkdir(parents=True)
        (self.target / "lib" / "bench" / "runner.py").write_text("x = 1\n")
        (self.target / "THREAT_MODEL.md").write_text("# threat model\n")

    def tearDown(self):
        self.tmp.cleanup()

    def test_an_existing_model_path_survives_binding(self):
        """The 7-of-7 repro, as a regression: a real location must not be blanked."""
        _, path = bind_candidates(finding(path="lib/bench/runner.py"), self.CONTEXT_INDEX,
                                  target_dir=self.target)
        self.assertEqual(path, "lib/bench/runner.py")

    def test_context_shaped_candidates_do_not_blank_real_locations(self):
        """Every real path in the observed set survives, not just the first."""
        for real in ("lib/bench/runner.py", "THREAT_MODEL.md"):
            _, path = bind_candidates(finding(path=real), self.CONTEXT_INDEX, target_dir=self.target)
            self.assertEqual(path, real, f"{real} must survive a context-shaped candidate set")

    def test_invented_path_is_still_bound_to_unknown(self):
        """The guard still does its job: a location that does not exist is not trusted."""
        _, path = bind_candidates(finding(path="lib/bench/invented.py"), self.CONTEXT_INDEX,
                                  target_dir=self.target)
        self.assertEqual(path, "unknown")

    def test_empty_path_is_still_bound_to_unknown(self):
        _, path = bind_candidates(finding(path=""), self.CONTEXT_INDEX, target_dir=self.target)
        self.assertEqual(path, "unknown")

    def test_path_outside_the_target_is_not_a_location(self):
        """Containment: traversal and outside-the-tree absolute paths cannot pass as real."""
        outside = Path(self.tmp.name).parent / "outside-target-secret.txt"
        outside.write_text("secret\n")
        try:
            for escaping in ("../../etc/passwd", str(outside)):
                _, path = bind_candidates(finding(path=escaping), self.CONTEXT_INDEX,
                                          target_dir=self.target)
                self.assertEqual(path, "unknown", f"{escaping!r} must not count as a location")
        finally:
            outside.unlink()

    def test_directory_location_is_accepted(self):
        _, path = bind_candidates(finding(path="lib/bench"), self.CONTEXT_INDEX, target_dir=self.target)
        self.assertEqual(path, "lib/bench")

    def test_no_target_keeps_the_previous_behaviour(self):
        """Without a target to check against, the guard stays closed (unknown), not open."""
        _, path = bind_candidates(finding(path="lib/bench/runner.py"), self.CONTEXT_INDEX)
        self.assertEqual(path, "unknown")

    def test_candidate_paths_are_still_preferred_and_rule_ids_still_bound(self):
        index = {"rule_ids": {"scanner-rule"}, "paths": {"src/a.js"}}
        self.assertEqual(bind_candidates(finding(path="./src/a.js", rule_id="scanner-rule"), index,
                                         target_dir=self.target), ("scanner-rule", "./src/a.js"))
        self.assertEqual(bind_candidates(finding(path="src/a.js", rule_id="invented"), index,
                                         target_dir=self.target), ("unclassified", "src/a.js"))

    def test_store_keeps_a_real_path_through_process_run(self):
        """End to end at the ingest boundary the audit actually used."""
        store = FindingsStore("t", findings_dir=self.target / "store")
        try:
            processed, _, _ = store.process_run(
                agent="vuln-discovery",
                raw_findings=[finding(path="lib/bench/runner.py", title="real")],
                candidate_index=self.CONTEXT_INDEX,
                target_dir=self.target,
            )
        finally:
            store.close()
        self.assertEqual(processed[0]["path"], "lib/bench/runner.py")
