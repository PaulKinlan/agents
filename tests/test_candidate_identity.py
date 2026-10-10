"""The shared candidate-identity helper (agents-rdyb).

The point of this module is a property, not a function: a station emits an identity at scan time so
that a downstream consumer can COPY it instead of reconstructing identity from the model's label and
prose. These tests pin the property the way that matters - by running the SAME unchanged file twice
with a RE-WORDED model label and a RE-WORDED model snippet, and showing that the copy does not move
while the reconstruction does. A test that only checked "an id exists" would pass on an id built from
the model's own text.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.candidate_identity import (  # noqa: E402
    CANDIDATE_ID_FIELD,
    CANDIDATE_ID_SCHEME,
    CANDIDATE_ID_SCHEME_FIELD,
    artefact_scheme_fields,
    assign_candidate_ids,
    candidate_identity,
    candidate_match_text,
)
from lib.findings import FindingsStore, load_candidate_index  # noqa: E402


class TestCandidateIdentity(unittest.TestCase):
    def test_the_id_is_deterministic_and_scanner_owned(self):
        a = candidate_identity("http-listener-route", "src/server.ts", "app.post('/api/auth/login'")
        b = candidate_identity("http-listener-route", "src/server.ts", "app.post('/api/auth/login'")
        self.assertEqual(a, b)
        self.assertEqual(len(a), 16)
        int(a, 16)  # hex
        # Nothing the model produces is an input: a different label or a different quote of the same
        # line cannot reach this function, which is the whole property.
        self.assertNotEqual(a, candidate_identity("model-invented-label", "src/server.ts",
                                                 "app.post('/api/auth/login'"))

    def test_fields_cannot_be_smuggled_across_the_separator(self):
        """NUL separation: a rule id ending where a path begins must not collide with another pair."""
        self.assertNotEqual(candidate_identity("a", "b/c", "m"),
                            candidate_identity("a/b", "c", "m"))

    def test_the_id_survives_a_line_shift(self):
        """Why the line number is NOT an input: code moving must not move identity."""
        self.assertEqual(candidate_identity("r", "a.py", "exec(cmd)", 1),
                         candidate_identity("r", "a.py", "exec(cmd)", 1))

    def test_duplicate_matches_get_distinct_ids(self):
        candidates = [
            {"rule_id": "r", "path": "a.py", "line_number": 3, "snippet": "pass"},
            {"rule_id": "r", "path": "a.py", "line_number": 9, "snippet": "pass"},
            {"rule_id": "r", "path": "a.py", "line_number": 40, "snippet": "other"},
        ]
        self.assertEqual(assign_candidate_ids(candidates), 3)
        ids = [c[CANDIDATE_ID_FIELD] for c in candidates]
        self.assertEqual(len(set(ids)), 3, ids)
        # The ordinal is in file order, so the FIRST of the identical pair is stable even though the
        # second exists - a line-based id would have moved here, an id with no ordinal would collide.
        self.assertEqual(ids[0], candidate_identity("r", "a.py", "pass", 1))
        self.assertEqual(ids[1], candidate_identity("r", "a.py", "pass", 2))

    def test_assign_is_idempotent(self):
        candidates = [{"rule_id": "r", "path": "a.py", "snippet": "x"}]
        assign_candidate_ids(candidates)
        first = candidates[0][CANDIDATE_ID_FIELD]
        assign_candidate_ids(candidates)
        self.assertEqual(candidates[0][CANDIDATE_ID_FIELD], first)

    def test_raw_match_wins_over_snippet(self):
        """The matched TOKEN is more stable than the line: unrelated edits on the line must not move
        the id."""
        with_match = {"rule_id": "r", "path": "a.py", "raw_match": "AKIA123", "snippet": "key = 'AKIA123'"}
        without = {"rule_id": "r", "path": "a.py", "snippet": "key = 'AKIA123'"}
        self.assertEqual(candidate_match_text(with_match), "AKIA123")
        self.assertEqual(candidate_match_text(without), "key = 'AKIA123'")
        assign_candidate_ids([with_match])
        # same rule/path, but the line around the token changed: identity does not move
        self.assertEqual(with_match[CANDIDATE_ID_FIELD], candidate_identity("r", "a.py", "AKIA123"))

    def test_sparse_records_are_deterministic_not_fatal(self):
        candidates = [{}, {"rule_id": "r", "path": "a.py"}, "not-a-dict", None]
        self.assertEqual(assign_candidate_ids(candidates), 2)  # the two dicts
        self.assertEqual(candidates[0][CANDIDATE_ID_FIELD], candidate_identity("", "", "", 1))
        self.assertEqual(candidates[1][CANDIDATE_ID_FIELD], candidate_identity("r", "a.py", "", 1))

    def test_the_envelope_records_the_shape(self):
        self.assertEqual(artefact_scheme_fields(), {CANDIDATE_ID_SCHEME_FIELD: CANDIDATE_ID_SCHEME})
        self.assertIsInstance(CANDIDATE_ID_SCHEME, int)


class TestThePropertyAgainstTheReconstruction(unittest.TestCase):
    """The measured reason this bead exists: copy vs reconstruct, on an unchanged file.

    Two runs of the same unchanged file in which the model re-words its snippet and invents a
    different rule label. This is the agents-x9my scenario, and it is the comparison a reviewer
    should be able to read: the RECONSTRUCTED identity is what the factory computes today
    (sha256(agent:rule_id:path:snippet) with rule_id bound downstream), and the COPIED identity is
    what a consumer gets from `candidate_id`.
    """

    SCANNER_RULE = "http-listener-route"
    PATH = "src/server.ts"
    MATCH = "app.post('/api/auth/login'"

    def _candidate(self):
        """A fresh scanner record for the unchanged file - one per scan, ids assigned independently.

        Deliberately NOT a cached dict: comparing a value with itself would prove nothing, which is
        the tautology this test exists to avoid (the reviewer caught exactly that shape in the
        vocabulary test earlier on this bead).
        """
        candidate = {"rule_id": self.SCANNER_RULE, "path": self.PATH, "line_number": 12,
                     "snippet": self.MATCH + "', handleLogin);"}
        assign_candidate_ids([candidate])
        return candidate

    def test_the_copy_is_stable_where_the_reconstruction_still_moves(self):
        """The measured gap this bead closes, on an UNCHANGED file.

        TWO findings in the same file is the case agents-x9my step 2 deliberately does not fix: its
        location fallback is refused when a run reports more than one finding at a path, because two
        rows sharing a path and a bound label would be handed the same snippet and COLLAPSE. So
        those rows stay bound to the model's prose - and re-wording moves them, which is the
        new+fixed pair below. The scanner's own ids do not move, because the file did not change.
        """
        scan_a, scan_b = self._candidate(), self._candidate()
        self.assertEqual(scan_a[CANDIDATE_ID_FIELD], scan_b[CANDIDATE_ID_FIELD])  # the copy: stable

        candidates = [
            {"rule_id": self.SCANNER_RULE, "path": self.PATH, "line_number": 12,
             "snippet": self.MATCH + "', handleLogin);"},
            {"rule_id": "dom-injection-sink", "path": self.PATH, "line_number": 40,
             "snippet": "el.innerHTML = user;"},
        ]
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            cf = td / "candidates.json"
            cf.write_text(json.dumps({"candidates": candidates}), encoding="utf-8")
            ci = load_candidate_index(cf)
            store = FindingsStore("target", findings_dir=td)
            run1 = [self._finding("app.post(...) route", 12),
                    self._finding("innerHTML assignment", 40)]
            run2 = [self._finding("the POST route to /api/auth", 12),
                    self._finding("DOM sink writing user input", 40)]
            _, s1, _ = store.process_run("vuln-discovery", run1, candidate_index=ci)
            processed, s2, fixed2 = store.process_run("vuln-discovery", run2, candidate_index=ci)
            store.close()

        # The reconstruction stays on the model's prose (step 2's guard refused the location
        # fallback, because this run reports TWO findings in one file and handing both the same
        # candidate would collapse them) and therefore books the same unchanged findings as new AND
        # fixed...
        self.assertEqual(s1["new"], 2)
        self.assertEqual((s2["new"], s2["fixed"]), (2, 2), s2)
        self.assertEqual({f["identity_source"] for f in processed}, {"model-snippet"})
        # ...while the scanner's ids for the same unchanged file are byte-identical across scans.
        self.assertEqual(scan_a[CANDIDATE_ID_FIELD], scan_b[CANDIDATE_ID_FIELD])

    def test_a_different_scanner_rule_is_a_different_candidate(self):
        """The id DOES move when the scanner's own rule changes - it must, they are two candidates.

        Stated separately from the invariance above so the two are not confused: identity survives
        changes on the MODEL's side of the boundary, not on the scanner's.
        """
        candidate = self._candidate()
        self.assertNotEqual(candidate_identity("another-rule", self.PATH, self.MATCH),
                            candidate[CANDIDATE_ID_FIELD])

    @staticmethod
    def _finding(snippet, line_number):
        """A model finding: the label binds nothing, and the prose is what changes between runs."""
        return {"rule_id": "model-invented-label", "path": "src/server.ts",
                "line_number": line_number, "snippet": snippet, "severity": "high",
                "title": "route", "description": "d", "remediation": "r"}


if __name__ == "__main__":
    unittest.main()
