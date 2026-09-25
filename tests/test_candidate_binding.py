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
