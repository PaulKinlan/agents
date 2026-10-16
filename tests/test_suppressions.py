#!/usr/bin/env python3
"""The committed suppressions register is the one the store reads (agents-411).

AGENTS.md's noise-control contract says a wontfix needs a written reason in a *committed*
suppressions file. The store used to read a gitignored per-target JSON, so that contract could
not be satisfied by any path; a malformed file silently became an empty dict. These tests pin
the one path, the parse, and the loud failure modes.
"""

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.findings import (  # noqa: E402
    SUPPRESSIONS_FILENAME,
    FindingsStore,
    SuppressionFileError,
    compute_fingerprint,
    parse_suppressions_yaml,
)
from lib.findings import load_candidate_index  # noqa: E402

FINGERPRINT = "a" * 64  # shape-valid sha256 key; content need not match a real finding

# What the MODEL reports for the same line: masked and re-quoted, the way a run actually arrives.
# Kept different from the candidate's own snippet so the EXISTING model-snippet bridge cannot match
# and the pre-id bridge is the only thing under test (mutation-checked by disabling it).
MASKED_SNIPPET = 'real_key = "sk-ant-fixture-token-***[masked]"' 


def finding(**overrides):
    base = {"rule_id": "unused-export", "path": "src/a.js", "snippet": "unused = True",
            "severity": "low", "title": "t", "description": "d"}
    base.update(overrides)
    return base


class TestParseSuppressions(unittest.TestCase):
    def test_reads_entries_with_comments_and_quotes(self):
        text = (
            "# register\n"
            "\n"
            f"{FINGERPRINT}:\n"
            '  reason: "accepted: see issue #42"\n'
            "  author: paul\n"
            "  date: '2026-09-25'\n"
        )
        entries = parse_suppressions_yaml(text)
        self.assertEqual(entries[FINGERPRINT]["reason"], "accepted: see issue #42")
        self.assertEqual(entries[FINGERPRINT]["author"], "paul")
        self.assertEqual(entries[FINGERPRINT]["date"], "2026-09-25")

    def test_a_hash_inside_quotes_is_not_a_comment(self):
        entries = parse_suppressions_yaml(f"{FINGERPRINT}:\n  reason: 'not a #comment'\n")
        self.assertEqual(entries[FINGERPRINT]["reason"], "not a #comment")

    def test_empty_register_is_valid(self):
        self.assertEqual(parse_suppressions_yaml("# only comments\n\n"), {})

    def test_uppercase_fingerprint_is_normalised(self):
        entries = parse_suppressions_yaml(f"{FINGERPRINT.upper()}:\n  reason: why not\n")
        self.assertIn(FINGERPRINT, entries)

    def test_malformed_registers_raise(self):
        cases = {
            "field before any entry": "  reason: orphan\n",
            "key without a colon": "not-a-key\n",
            "fingerprint is not sha256": "deadbeef:\n  reason: truncated\n",
            "reason missing": f"{FINGERPRINT}:\n  author: paul\n",
            "duplicate entry": (f"{FINGERPRINT}:\n  reason: a\n"
                                f"{FINGERPRINT}:\n  reason: b\n"),
            "field without a colon": f"{FINGERPRINT}:\n  broken field\n",
        }
        for label, text in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(SuppressionFileError):
                    parse_suppressions_yaml(text, source="test.yaml")


class TestStoreReadsTheCommittedRegister(unittest.TestCase):
    def test_committed_register_suppresses_a_finding(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            findings_dir = Path(tmpdir)
            fingerprint = compute_fingerprint("lint", "unused-export", "src/a.js", "unused = True")
            (findings_dir / SUPPRESSIONS_FILENAME).write_text(
                f"{fingerprint}:\n  reason: accepted risk\n", encoding="utf-8")
            store = FindingsStore("target", findings_dir=findings_dir)
            processed, stats, _ = store.process_run("lint", [finding()])
            self.assertEqual(stats["suppressed"], 1)
            self.assertEqual(processed[0]["state"], "wontfix")
            self.assertEqual(processed[0]["suppression_reason"], "accepted risk")

    def test_missing_register_suppresses_nothing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = FindingsStore("target", findings_dir=Path(tmpdir))
            _, stats, _ = store.process_run("lint", [finding()])
            self.assertEqual(stats["suppressed"], 0)

    def test_legacy_json_is_ignored_and_warned_about(self):
        """The gitignored per-target JSON was the only honoured path; it must not be silently."""
        with tempfile.TemporaryDirectory() as tmpdir:
            findings_dir = Path(tmpdir)
            fingerprint = compute_fingerprint("lint", "unused-export", "src/a.js", "unused = True")
            (findings_dir / "target.suppressions.json").write_text(
                json.dumps({fingerprint: {"reason": "old local suppression"}}), encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                store = FindingsStore("target", findings_dir=findings_dir)
                processed, stats, _ = store.process_run("lint", [finding()])
            self.assertEqual(stats["suppressed"], 0)
            self.assertIn("ignored", stderr.getvalue())

    def test_a_malformed_register_raises_instead_of_reading_empty(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / SUPPRESSIONS_FILENAME).write_text(": broken\n", encoding="utf-8")
            with self.assertRaises(SuppressionFileError):
                FindingsStore("target", findings_dir=Path(tmpdir))

    def test_the_repository_register_parses(self):
        register = ROOT / "findings" / SUPPRESSIONS_FILENAME
        self.assertTrue(register.exists())
        entries = parse_suppressions_yaml(register.read_text(encoding="utf-8"), str(register))
        self.assertIsInstance(entries, dict)


class TestThePreCandidateIdRegisterKeyIsHonoured(unittest.TestCase):
    """agents-z3v9p: a row written before the emitted candidate id became the key still dismisses.

    MEASURED on this repository before this fix: of the candidates the secret-scan pre-pass emits,
    21 were covered by a register row only under the pre-step-3 shape (the candidate's own line),
    which nothing looked up any more - so 20 reviewed dismissals were silently re-entering triage
    every night. The rows were labelled "Prose-bound identity" in their own reason, which is the
    misdiagnosis this test replaces: the key was the PRE-PASS's text, never the model's prose.
    """

    CANDIDATE = {
        "rule_id": "openai-key",
        "path": "tests/x.py",
        "line_number": 62,
        "snippet": 'real_key = "sk-ant-fixture-token-000000000"',
        "raw_match": "sk-ant-fixture-token-000000000",
        "candidate_id": "abc123def456abcd",
    }

    def _store_and_index(self, d, rows):
        (Path(d) / SUPPRESSIONS_FILENAME).write_text(
            "".join(f"{fp}:\n  reason: {reason}\n" for fp, reason in rows), encoding="utf-8")
        candidates = Path(d) / "candidates.json"
        candidates.write_text(json.dumps({"candidates": [self.CANDIDATE]}), encoding="utf-8")
        return FindingsStore("t", findings_dir=Path(d)), load_candidate_index(candidates)

    def test_a_row_keyed_on_the_pre_id_snippet_still_suppresses(self):
        pre_id_key = compute_fingerprint(
            "secret-scan", self.CANDIDATE["rule_id"], self.CANDIDATE["path"],
            self.CANDIDATE["snippet"])
        with tempfile.TemporaryDirectory() as d:
            store, index = self._store_and_index(d, [(pre_id_key, "fixture")])
            try:
                processed, stats, _ = store.process_run(
                    "secret-scan",
                    [{"rule_id": self.CANDIDATE["rule_id"], "path": self.CANDIDATE["path"],
                      "line_number": 62, "snippet": MASKED_SNIPPET,
                      "severity": "info", "title": "t", "description": "d"}],
                    candidate_index=index,
                )
            finally:
                store.close()

        self.assertEqual(stats["suppressed"], 1)
        self.assertEqual(processed[0]["state"], "wontfix")
        self.assertEqual(processed[0]["suppression_reason"], "fixture")

    def test_the_emitted_id_key_still_wins_when_the_register_has_both(self):
        """Both shapes present: the stable key is the one that binds, so nothing is downgraded."""
        pre_id_key = compute_fingerprint(
            "secret-scan", self.CANDIDATE["rule_id"], self.CANDIDATE["path"],
            self.CANDIDATE["snippet"])
        id_key = compute_fingerprint(
            "secret-scan", self.CANDIDATE["rule_id"], self.CANDIDATE["path"],
            self.CANDIDATE["candidate_id"])
        with tempfile.TemporaryDirectory() as d:
            store, index = self._store_and_index(d, [(pre_id_key, "fixture"), (id_key, "fixture")])
            try:
                processed, stats, _ = store.process_run(
                    "secret-scan",
                    [{"rule_id": self.CANDIDATE["rule_id"], "path": self.CANDIDATE["path"],
                      "line_number": 62, "snippet": MASKED_SNIPPET,
                      "severity": "info", "title": "t", "description": "d"}],
                    candidate_index=index,
                )
            finally:
                store.close()

        self.assertEqual(stats["suppressed"], 1)
        # Bound by the emitted id, so the row keeps the stable source name.
        self.assertEqual(processed[0]["identity_source"], "candidate-id")

    def test_a_new_finding_at_the_same_location_is_not_absorbed(self):
        """Control, and the reason the lookup is exact: the bridge must not swallow real work.

        A row for rule A at a location must not suppress a finding that some other rule row
        never named.
        """
        pre_id_key = compute_fingerprint(
            "secret-scan", self.CANDIDATE["rule_id"], self.CANDIDATE["path"],
            self.CANDIDATE["snippet"])
        with tempfile.TemporaryDirectory() as d:
            store, index = self._store_and_index(d, [(pre_id_key, "fixture")])
            try:
                processed, stats, _ = store.process_run(
                    "secret-scan",
                    [{"rule_id": "github-pat", "path": self.CANDIDATE["path"],
                      "line_number": 62, "snippet": MASKED_SNIPPET,
                      "severity": "high", "title": "t", "description": "d"}],
                    candidate_index=index,
                )
            finally:
                store.close()

        self.assertEqual(stats["suppressed"], 0)
        self.assertEqual(processed[0]["state"], "new")


if __name__ == "__main__":
    unittest.main()
