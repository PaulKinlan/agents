#!/usr/bin/env python3
"""Bounded batching, deterministic merging and truncation naming (chrome-agent-platform-rn0ky).

The nightly lost a 47-candidate perf-review run to a completion cut mid-JSON at 50,314 bytes and
reported it as "no verdict". These tests pin the three pieces that replace that silence: a bounded
deterministic partition, a merge that refuses to lose or duplicate a candidate, and a classifier
that names truncation from the shape of the fragment rather than guessing.
"""

import json
import unittest

from lib.candidate_batching import (
    DEFAULT_MAX_BATCH_BYTES,
    DEFAULT_MAX_PER_BATCH,
    BatchMergeError,
    BatchPlanError,
    batch_candidate_ids,
    classify_unparseable,
    describe_truncation,
    merge_reports,
    plan_batches,
)


def candidate(index, *, padding=0, with_id=True):
    row = {
        "rule_id": "layout-thrashing-forced-reflow",
        "path": f"src/file{index}.ts",
        "line_number": index,
        "severity": "high",
        "snippet": "el.offsetWidth" + ("x" * padding),
    }
    if with_id:
        row["candidate_id"] = f"cand-perf-{index:03d}"
    return row


def report(rows, *, commits=(), target="demo"):
    findings = [{"candidate_id": f"cand-perf-{i:03d}", "rule_id": "r", "path": "p",
                 "snippet": "s", "severity": "info", "title": "t", "description": "d",
                 "remediation": "x", "false_positive": True} for i in rows]
    payload = {"summary": "s", "target": target, "findings": findings}
    if commits:
        payload["reviewed_commits"] = list(commits)
    return payload


class TestPlanBatches(unittest.TestCase):
    def test_every_candidate_appears_exactly_once_in_prepass_order(self):
        candidates = [candidate(i) for i in range(47)]
        batches = plan_batches(candidates)
        flattened = [row["candidate_id"] for batch in batches for row in batch]
        self.assertEqual(flattened, [row["candidate_id"] for row in candidates])

    def test_batches_are_bounded_by_count(self):
        batches = plan_batches([candidate(i) for i in range(47)], max_per_batch=8)
        self.assertEqual([len(b) for b in batches], [8, 8, 8, 8, 8, 7])
        self.assertEqual(len(batches), 6)

    def test_batches_are_bounded_by_bytes_as_well_as_count(self):
        # 40 records, small count bound, but each record is ~1 KB: the byte budget must cut first.
        candidates = [candidate(i, padding=1000) for i in range(40)]
        batches = plan_batches(candidates, max_per_batch=40, max_batch_bytes=4000)
        self.assertGreater(len(batches), 1)
        for batch in batches:
            payload = json.dumps(batch, ensure_ascii=False).encode("utf-8")
            self.assertLessEqual(len(payload), 4000 + 1200)  # one record may not fit alone

    def test_a_single_oversized_candidate_gets_its_own_batch_rather_than_being_dropped(self):
        huge = candidate(0, padding=20000)
        batches = plan_batches([huge, candidate(1), candidate(2)], max_per_batch=8,
                               max_batch_bytes=1000)
        self.assertEqual(len(batches[0]), 1)
        self.assertEqual(batches[0][0]["candidate_id"], "cand-perf-000")
        self.assertEqual(sum(len(b) for b in batches), 3)

    def test_deterministic_for_the_same_input_and_bounds(self):
        candidates = [candidate(i, padding=i * 7) for i in range(30)]
        self.assertEqual(plan_batches(candidates), plan_batches(candidates))

    def test_empty_list_yields_no_batches(self):
        self.assertEqual(plan_batches([]), [])

    def test_none_is_refused_rather_than_treated_as_empty(self):
        # "no pre-pass" and "a pre-pass with zero candidates" are different facts; batching only
        # ever sees the second, so a None here is a caller bug, not a clean scan.
        with self.assertRaises(BatchPlanError):
            plan_batches(None)

    def test_non_list_is_refused(self):
        with self.assertRaises(BatchPlanError):
            plan_batches({"candidates": [candidate(0)]})

    def test_bounds_must_be_positive(self):
        for bad in (0, -1):
            with self.assertRaises(BatchPlanError):
                plan_batches([candidate(0)], max_per_batch=bad)
            with self.assertRaises(BatchPlanError):
                plan_batches([candidate(0)], max_batch_bytes=bad)

    def test_defaults_are_the_documented_bounds(self):
        self.assertEqual(DEFAULT_MAX_PER_BATCH, 8)
        self.assertEqual(DEFAULT_MAX_BATCH_BYTES, 12_000)


class TestBatchCandidateIds(unittest.TestCase):
    def test_ids_are_copied_verbatim_and_never_invented(self):
        batch = [candidate(0), candidate(1, with_id=False), candidate(2)]
        self.assertEqual(batch_candidate_ids(batch), ["cand-perf-000", "cand-perf-002"])

    def test_non_dict_rows_and_blank_ids_are_skipped(self):
        batch = ["not-a-dict", {"candidate_id": "  "}, {"candidate_id": "cand-perf-009"}]
        self.assertEqual(batch_candidate_ids(batch), ["cand-perf-009"])


class TestMergeReports(unittest.TestCase):
    def test_findings_keep_batch_order(self):
        merged = merge_reports([report([0, 1]), report([2, 3])])
        self.assertEqual([row["candidate_id"] for row in merged["findings"]],
                         ["cand-perf-000", "cand-perf-001", "cand-perf-002", "cand-perf-003"])

    def test_reviewed_commits_are_unioned_first_seen(self):
        merged = merge_reports([report([0], commits=["a", "b"]), report([1], commits=["b", "c"])])
        self.assertEqual(merged["reviewed_commits"], ["a", "b", "c"])

    def test_a_duplicated_candidate_id_is_refused_by_name(self):
        with self.assertRaises(BatchMergeError) as ctx:
            merge_reports([report([0, 1]), report([1, 2])])
        self.assertIn("cand-perf-001", str(ctx.exception))
        self.assertIn("batch 0 and batch 1", str(ctx.exception))

    def test_a_non_object_report_is_refused(self):
        with self.assertRaises(BatchMergeError):
            merge_reports([report([0]), "not-a-report"])

    def test_a_non_list_findings_value_is_refused(self):
        with self.assertRaises(BatchMergeError):
            merge_reports([{"summary": "s", "findings": {"candidate_id": "x"}}])

    def test_no_reports_to_merge_is_refused(self):
        with self.assertRaises(BatchMergeError):
            merge_reports([])

    def test_model_output_cannot_supply_a_station_status(self):
        # verdict/status/scanned_files belong to the factory: a merged report must not carry them
        # from a batch, or model output would decide whether the station passed.
        first = report([0])
        first.update({"verdict": "pass", "status": "PASS", "scanned_files": 0})
        merged = merge_reports([first])
        for key in ("verdict", "status", "scanned_files"):
            self.assertNotIn(key, merged)

    def test_target_falls_back_to_the_first_batch_that_names_one(self):
        self.assertEqual(merge_reports([{"summary": "s", "findings": []},
                                        report([0], target="chosen")])["target"], "chosen")
        self.assertNotIn("target", merge_reports([{"summary": "s", "findings": []}]))

    def test_summary_is_deterministic_and_counts_rows_and_ids(self):
        merged = merge_reports([report([0, 1]), report([2])])
        self.assertEqual(merged["summary"],
                         "Merged 2 bounded batch report(s): 3 row(s) across 3 cited candidate id(s).")


class TestClassifyUnparseable(unittest.TestCase):
    def _cut_report(self, rows):
        """A report cut mid-string, the exact nightly shape: valid head, then a hard stop."""
        text = json.dumps(report(rows), indent=2)
        # Cut inside a string VALUE, not at a structural boundary: the nightly's shape was a hard
        # stop mid-value, which is what "ends inside a string" means.
        marker = text.rindex('"description": "')
        return text[: marker + len('"description": "') + 1]

    def test_a_cut_report_is_named_truncated(self):
        verdict, evidence = classify_unparseable(self._cut_report(range(45)))
        self.assertEqual(verdict, "truncated")
        self.assertTrue(evidence["in_string_at_end"])
        self.assertGreater(evidence["bytes"], 1000)

    def test_unclosed_structure_is_named_truncated(self):
        text = '{"summary": "s", "findings": [{"candidate_id": "cand-perf-001"}'
        verdict, evidence = classify_unparseable(text)
        self.assertEqual(verdict, "truncated")
        self.assertEqual(evidence["depth"], 1)
        self.assertEqual(evidence["open_braces"], 2)
        self.assertEqual(evidence["close_braces"], 1)

    def test_prose_without_json_is_not_called_truncation(self):
        verdict, evidence = classify_unparseable("I reviewed the diff and found nothing of note.")
        self.assertEqual(verdict, "no_json")
        self.assertFalse(evidence["in_string_at_end"])

    def test_prose_that_ends_in_a_quote_is_not_called_truncation(self):
        # Found in review: "ends inside a string" taken on its own called prose with a trailing
        # quote truncated, sending an operator after a token limit that was never hit. Without any
        # JSON structure there is nothing to have been cut.
        verdict, _ = classify_unparseable('The model said "no findings here" and then "')
        self.assertEqual(verdict, "no_json")

    def test_a_bare_array_cut_between_elements_is_called_truncation(self):
        # A report may legally be a bare array; a cut between its elements leaves no string open and
        # its braces balanced, so only bracket counting can tell it from prose (found in review).
        verdict, evidence = classify_unparseable(
            '[{"candidate_id": "cand-perf-000"}, {"candidate_id": "cand-perf-001"}')
        self.assertEqual(verdict, "truncated")
        self.assertEqual(evidence["open_brackets"], 1)
        self.assertEqual(evidence["close_brackets"], 0)
        self.assertFalse(evidence["in_string_at_end"])

    def test_an_empty_output_is_no_json_with_an_explicit_flag(self):
        for text in ("", "   ", None):
            verdict, evidence = classify_unparseable(text)
            self.assertEqual(verdict, "no_json")
            self.assertTrue(evidence.get("empty"))

    def test_braces_inside_strings_do_not_make_a_complete_report_look_truncated(self):
        # A snippet containing '{' must not fake an unbalanced structure: this report is complete
        # and simply had no decodable object for another reason (e.g. it is prose about braces).
        verdict, evidence = classify_unparseable(
            'prose: the snippet uses { and } characters, and quotes a "string".')
        self.assertEqual(verdict, "no_json")
        self.assertEqual(evidence["open_braces"], 1)
        self.assertEqual(evidence["close_braces"], 1)

    def test_escaped_quote_does_not_end_the_string(self):
        verdict, evidence = classify_unparseable('{"snippet": "a \\" b { ')
        self.assertEqual(verdict, "truncated")
        self.assertTrue(evidence["in_string_at_end"])

    def test_candidate_ids_visible_in_the_fragment_are_reported(self):
        text = self._cut_report(range(45))
        _, evidence = classify_unparseable(text)
        self.assertEqual(evidence["ids_seen"], 45)
        self.assertEqual(evidence["last_id"], "cand-perf-044")

    def test_truncation_message_names_batch_bytes_and_visible_ids(self):
        text = self._cut_report(range(45))
        _, evidence = classify_unparseable(text)
        message = describe_truncation(evidence, batch_index=2, batch_count=6,
                                      expected_ids=[f"cand-perf-{i:03d}" for i in range(8)])
        self.assertIn("batch 3/6", message)
        self.assertIn("TRUNCATED mid-JSON", message)
        # ALL EIGHT are visible in this fragment (it holds rows 0..44), so none may be called
        # unaccounted. This assertion used to read "0/8": the evidence kept only the last five ids,
        # which made the message name ids it had actually seen (found in review) - the accounting is
        # the whole point of the line, so it is now counted over every id in the fragment.
        self.assertIn("8/8 candidate id(s) visible", message)
        self.assertNotIn("unaccounted", message)

    def test_only_candidates_the_fragment_lacks_are_named_unaccounted(self):
        # The reviewer's exact shape: a fragment holding 7 of 8 ids. The eighth is the only thing
        # that may be reported as missing, whatever order it sits in.
        ids = [f"cand-perf-{i:03d}" for i in range(8)]
        rows = ", ".join(json.dumps({"candidate_id": cid, "rule_id": "r", "path": "p",
                                     "line_number": 1, "title": "t"}) for cid in ids[:7])
        text = '{"findings": [' + rows + ', {"candidate_id": "cand-perf-00'
        _, evidence = classify_unparseable(text)
        message = describe_truncation(evidence, batch_index=0, batch_count=1, expected_ids=ids)
        self.assertIn("7/8 candidate id(s) visible", message)
        missing_clause = message.split("first unaccounted:", 1)[-1]
        self.assertIn("cand-perf-007", missing_clause)
        for cid in ids[:7]:
            self.assertNotIn(cid, missing_clause, f"a VISIBLE id was named unaccounted: {message}")

    def test_a_run_that_stopped_early_says_which_batches_never_ran(self):
        # A three-batch plan whose first batch was cut must not read as "batch 1/1": the run's shape
        # is three batches and two of them never ran (found in review).
        _, evidence = classify_unparseable('{"summary": "cut')
        message = describe_truncation(evidence, batch_index=0, batch_count=3,
                                      produced_batches=1)
        self.assertIn("batch 1/3", message)
        self.assertIn("only 1 of 3 planned batch(es) produced output", message)
        self.assertIn("later batches never ran", message)

    def test_truncation_message_says_so_when_no_ids_were_supplied(self):
        _, evidence = classify_unparseable('{"summary": "cut')
        message = describe_truncation(evidence, batch_index=0, batch_count=1)
        self.assertIn("count-only accounting", message)


if __name__ == "__main__":
    unittest.main()
