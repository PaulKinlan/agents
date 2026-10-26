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
    MAX_CANDIDATES_PER_BATCH,
    BatchMergeError,
    BatchPlanError,
    batch_candidate_ids,
    carried_candidate_ids,
    classify_unparseable,
    context_prune_notice,
    declared_max_candidates_per_call,
    describe_truncation,
    merge_reports,
    plan_batches,
    prune_context_for_batch,
    resolve_max_candidates_per_call,
    validate_batch_attribution,
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


class TestTheSingleCallClaimHoldsOnlyWithinBothBounds(unittest.TestCase):
    """agents-vnnlt: "every list of 8 or fewer is single-call" was false in two comments.

    The planner's bound is JOINT - a batch stops at DEFAULT_MAX_PER_BATCH records OR before adding a
    record that would cross DEFAULT_MAX_BATCH_BYTES - and a station may declare a LOWER per-call bound
    (vuln-discovery and vuln-verify declare 6). Both comments in `factory` and `batch_brief` now quote
    these numbers, so they are asserted here: a change to any of the three inputs cannot leave the prose
    claiming a call count the planner no longer produces.
    """

    def counts(self, count, *, padding=0, **bounds):
        rows = [candidate(i, padding=padding) for i in range(count)]
        return [len(batch) for batch in plan_batches(rows, **bounds)]

    def test_small_records_at_the_default_bound_are_one_call_only_up_to_eight(self):
        self.assertEqual(self.counts(8), [8])
        self.assertEqual(self.counts(9), [8, 1])
        self.assertEqual(len(self.counts(31)), 4)
        self.assertEqual(len(self.counts(49)), 7)

    def test_the_byte_bound_makes_six_small_looking_records_three_calls(self):
        # The bead's own repro: six candidates of ~5 KB serialise past the 12,000-byte budget two at a
        # time, so a list well under the eight-record ceiling is three calls, not one.
        counts = self.counts(6, padding=5000)
        self.assertEqual(counts, [2, 2, 2])
        rows = [candidate(i, padding=5000) for i in range(6)]
        for batch in plan_batches(rows):
            self.assertLessEqual(len(json.dumps(batch, ensure_ascii=False).encode("utf-8")),
                                 DEFAULT_MAX_BATCH_BYTES + 5_200,
                                 "one oversized record may exceed the budget alone, never two")

    def test_a_station_declaring_six_makes_seven_records_two_calls(self):
        declared = resolve_max_candidates_per_call({"output": {"max_candidates_per_call": 6}})
        self.assertEqual(declared, 6)
        self.assertLess(declared, MAX_CANDIDATES_PER_BATCH,
                        "a declaration may only tighten the policy ceiling")
        self.assertEqual(self.counts(7, max_per_batch=declared), [6, 1])


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

    def test_every_row_array_is_merged_not_just_findings(self):
        """agents-exhhl review P1: merge copied findings only, so vuln-verify's required `verifications`
        array vanished from every merged report while each BATCH passed its own schema check."""
        rows = [{"candidate_id": f"cand-{i}", "verdict": "confirmed"} for i in range(4)]
        merged = merge_reports([
            {"summary": "a", "target": "t", "verifications": rows[:2], "findings": []},
            {"summary": "b", "target": "t", "verifications": rows[2:], "findings": []},
        ])
        self.assertEqual([r["candidate_id"] for r in merged["verifications"]],
                         [r["candidate_id"] for r in rows], "batch order, every row kept")
        self.assertEqual(merged["findings"], [])
        self.assertIn("4 verifications row(s)", merged["summary"])

    def test_a_duplicate_in_another_array_is_refused_too(self):
        row = {"candidate_id": "cand-0", "verdict": "confirmed"}
        with self.assertRaises(BatchMergeError) as ctx:
            merge_reports([{"verifications": [row]}, {"verifications": [row]}])
        self.assertIn("'verifications'", str(ctx.exception))

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

    def test_the_factory_s_own_scanned_count_is_carried_into_the_merge(self):
        """agents-demur: modern-web/resilience/ui-ux-audit/memory-profile REQUIRE `scanned_files`, so a
        merged report without it failed the merged contract check while every batch had passed its own
        - and the whole run reached nobody as a no-verdict."""
        merged = merge_reports([report([0, 1]), report([2])], scanned_files=235)
        self.assertEqual(merged["scanned_files"], 235)

    def test_the_scanned_count_is_not_summed_across_batches(self):
        # Every batch describes the SAME scan, so summing would multiply one count by the batch count.
        parts = [report([0]), report([1])]
        for part in parts:
            part["scanned_files"] = 137
        self.assertEqual(merge_reports(parts, scanned_files=137)["scanned_files"], 137)

    def test_a_digit_string_scanned_count_is_accepted_like_normalize_report_does(self):
        self.assertEqual(merge_reports([report([0])], scanned_files=" 42 ")["scanned_files"], 42)

    def test_a_scanned_count_that_cannot_be_a_count_is_refused(self):
        # A count that cannot be read is a plumbing error, never a number to invent.
        for bad in (-1, True, "many", 2.5, {"count": 3}):
            with self.assertRaises(BatchMergeError) as ctx:
                merge_reports([report([0])], scanned_files=bad)
            self.assertIn("scanned_files", str(ctx.exception))

    def test_summary_is_deterministic_and_counts_rows_and_ids(self):
        merged = merge_reports([report([0, 1]), report([2])])
        self.assertEqual(merged["summary"],
                         "Merged 2 bounded batch report(s): 3 row(s) across 3 cited candidate id(s).")


class TestValidateBatchAttribution(unittest.TestCase):
    """agents-5230a: distinct ids satisfy aggregate coverage while attributing a candidate to a call
    that never saw it. The check is per batch and names both the id and where it belongs."""

    def test_a_row_citing_another_batch_s_candidate_is_refused(self):
        with self.assertRaises(BatchMergeError) as ctx:
            validate_batch_attribution([{"candidate_id": "cand-perf-001"}],
                                       batch_ids=["cand-perf-000"], batch_index=0,
                                       all_batch_ids=[["cand-perf-000"], ["cand-perf-001"]])
        message = str(ctx.exception)
        self.assertIn("cand-perf-001", message)
        self.assertIn("batch 2", message, f"it must say where the id belongs: {message}")

    def test_an_invented_candidate_id_is_refused(self):
        with self.assertRaises(BatchMergeError) as ctx:
            validate_batch_attribution([{"candidate_id": "cand-perf-999"}],
                                       batch_ids=["cand-perf-000"], batch_index=0,
                                       all_batch_ids=[["cand-perf-000"]])
        self.assertIn("not presented in any batch", str(ctx.exception))

    def test_a_row_answering_its_own_batch_is_accepted(self):
        validate_batch_attribution([{"candidate_id": "cand-perf-000"},
                                    {"candidate_id": "cand-perf-001"}],
                                   batch_ids=["cand-perf-000", "cand-perf-001"], batch_index=0,
                                   all_batch_ids=[["cand-perf-000", "cand-perf-001"]])

    def test_a_known_foreign_id_is_refused_even_when_this_batch_has_no_ids(self):
        # agents-ju56b: real pre-passes mix rows with and without candidate_id (the retained vuln-verify
        # bundle has 2 of 5). A batch whose own candidates carry no ids cannot be VERIFIED, but an id that
        # is known to belong to another batch is still a provable misattribution - the early return used
        # to accept exactly that.
        with self.assertRaises(BatchMergeError) as ctx:
            validate_batch_attribution([{"candidate_id": "cand-perf-000"}], batch_ids=[],
                                       batch_index=1,
                                       all_batch_ids=[["cand-perf-000"], []])
        message = str(ctx.exception)
        self.assertIn("belongs to batch 1", message)
        self.assertIn("carry no ids", message)

    def test_the_refusal_names_the_array_it_checked(self):
        # The verifications array is a separate contract (agents-exhhl review P1); a message that says
        # "findings" while checking verifications would send a reader to the wrong rows.
        with self.assertRaises(BatchMergeError) as ctx:
            validate_batch_attribution([{"candidate_id": "cand-3"}], batch_ids=["cand-0"],
                                       batch_index=0, all_batch_ids=[["cand-0"], ["cand-3"]],
                                       array_name="verifications")
        self.assertIn("'verifications'", str(ctx.exception))

    def test_rows_without_an_id_are_left_to_count_accounting(self):
        # A dismissal row may omit candidate_id; identity is not the only contract, so no raise here.
        validate_batch_attribution([{"path": "src/x.ts", "false_positive": True}],
                                   batch_ids=["cand-perf-000"], batch_index=0,
                                   all_batch_ids=[["cand-perf-000"]])
        validate_batch_attribution([], batch_ids=[], batch_index=0, all_batch_ids=[[]])


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


class TestTheBatchBriefNamesTheWholePopulation(unittest.TestCase):
    """agents-g42wa: a batch of 4 candidates carrying 1 id was described to the model as "The candidate
    ids in this batch: cand-vv-012." - so a model answering every candidate it was TOLD about answered
    one and skipped three. Measured on a 16-candidate plan: 13 ids, and the last batch (4 candidates)
    listed 1, which is the reported "13/16 verified, 3 silently dropped". The brief now states the
    population and the unidentified count, and tells the model to answer those rows without an id."""

    def brief(self, candidates, index=0, count=2):
        from lib.candidate_batching import batch_brief
        return batch_brief(candidates, index, count)

    def test_a_mixed_batch_names_its_population_and_the_unidentified_rows(self):
        text = self.brief([{"candidate_id": "cand-vv-012"}, {"path": "a"}, {}, {"candidate_id": "  "}])
        self.assertIn("holds 4 candidate(s)", text)
        self.assertIn("1 carries a candidate_id (cand-vv-012)", text)
        self.assertIn("the other 3 carry NO candidate_id", text)
        self.assertIn("answer those rows too", text)

    def test_a_fully_identified_batch_lists_its_ids_and_no_phantom_count(self):
        text = self.brief([{"candidate_id": "a"}, {"candidate_id": "b"}])
        self.assertIn("each with a candidate_id: a, b", text)
        self.assertNotIn("NO candidate_id", text)

    def test_a_batch_without_any_id_says_so_rather_than_looking_empty(self):
        text = self.brief([{"path": "x"}, {"path": "y"}])
        self.assertIn("holds 2 candidate(s) and NONE of them carry a candidate_id", text)
        self.assertIn("row count", text)

    def test_the_counts_are_the_batch_not_a_sample(self):
        # every population size with every identified count: the arithmetic must hold for each
        from lib.candidate_batching import batch_brief
        for total in range(1, 6):
            for identified in range(total + 1):
                candidates = ([{"candidate_id": f"id{i}"} for i in range(identified)]
                              + [{"path": f"p{i}"} for i in range(total - identified)])
                text = batch_brief(candidates, 0, 2)
                self.assertIn(f"holds {total} candidate(s)", text)
                if identified == 0:
                    self.assertIn("NONE of them carry a candidate_id", text)
                elif total - identified:
                    self.assertIn(f"the other {total - identified} "
                                  f"{'carries' if total - identified == 1 else 'carry'} NO candidate_id",
                                  text)


class TestASingleCallStillHearsItsPopulation(unittest.TestCase):
    """agents-o0nv2: the brief is not a batching feature.

    Only multi-batch prompts carried it, so a station whose candidate list fits ONE call - every list of 8
    or fewer since e5799b72 made the policy bound unconditional, and modern-web's 6 on the reported night
    is exactly that - was told nothing about its population or its ids. Its
    only "copy the candidate_id" text was a schema description inside the JSON blob, right before the
    derived checklist of fields a finding MUST carry (which cannot include the one field that must stay
    omittable). A model reading that checklist as the contract emitted conforming rows citing no id and the
    run was judged 0 of 6.
    """

    def brief(self, candidates, index=0, count=1):
        from lib.candidate_batching import batch_brief
        return batch_brief(candidates, index, count)

    def test_a_single_call_names_the_population_and_every_id(self):
        text = self.brief([{"candidate_id": "a"}, {"candidate_id": "b"}, {"candidate_id": "c"}])
        self.assertIn("The candidate list holds 3 candidate(s), each with a candidate_id: a, b, c.", text)
        self.assertIn("answer for EVERY candidate below", text)
        self.assertIn("never an omission", text)

    def test_a_single_call_is_not_worded_as_a_batch(self):
        text = self.brief([{"candidate_id": "a"}])
        # 'BATCH ' is how a batched prompt is recognised downstream; a single-call prompt must not look
        # like one, and "this batch" would be a lie about a list that was never split.
        self.assertFalse(text.startswith("BATCH "), text)
        self.assertNotIn("BATCH 1 of 1", text)
        self.assertNotIn("This batch", text)

    def test_a_single_call_with_no_ids_states_the_count_only_case(self):
        text = self.brief([{"path": "x"}, {"path": "y"}])
        self.assertIn("holds 2 candidate(s) and NONE of them carry a candidate_id", text)
        self.assertIn("omit the candidate_id field", text)
        self.assertIn("row count", text)

    def test_a_single_mixed_call_names_the_unidentified_rows_too(self):
        text = self.brief([{"candidate_id": "a"}, {"path": "x"}])
        self.assertIn("1 carries a candidate_id (a)", text)
        self.assertIn("the other 1 carries NO candidate_id", text)

    def test_an_empty_list_gets_no_brief_at_all(self):
        # 15 of the 22 stations do not short-circuit an empty pre-pass, so a clean scan really does reach
        # the model with zero candidates; "answer for EVERY candidate ... holds 0 candidate(s)" is
        # self-contradictory, and "" keeps that prompt byte-identical to the pre-change one.
        self.assertEqual(self.brief([]), "")

    def test_the_single_call_boundary_is_eight_and_is_pinned(self):
        # The docstring's claim about which lists are single-call must be the policy's answer, not a
        # memory of one nightly: modern-web's 6 is single-call, docs-drift's 49 is not (7 batches).
        from lib.candidate_batching import MAX_CANDIDATES_PER_BATCH, plan_batches
        self.assertEqual(MAX_CANDIDATES_PER_BATCH, 8)
        for count, batches in ((6, 1), (8, 1), (9, 2), (31, 4), (49, 7)):
            candidates = [{"candidate_id": f"c{i}", "path": f"p{i}"}.copy() for i in range(count)]
            self.assertEqual(len(plan_batches(candidates, MAX_CANDIDATES_PER_BATCH)), batches,
                             f"{count} candidates")

    def test_the_multi_batch_text_is_unmoved_by_the_single_call_branch(self):
        text = self.brief([{"candidate_id": "a"}, {"candidate_id": "b"}], index=0, count=2)
        self.assertEqual(
            text,
            "BATCH 1 of 2: the candidate list is presented in 2 batches so that no single response has to "
            "carry every row. Answer ONLY for the candidates in THIS batch, and answer for EVERY one of "
            "them - a confirmed row or a dismissal with `false_positive: true`, never an omission. This "
            "batch holds 2 candidate(s), each with a candidate_id: a, b.\n\n")

    def test_the_arithmetic_is_the_same_at_every_population_size(self):
        from lib.candidate_batching import batch_brief
        for total in range(1, 6):   # an empty list gets "" on purpose - see the test above
            for identified in range(total + 1):
                candidates = ([{"candidate_id": f"id{i}"} for i in range(identified)]
                              + [{"path": f"p{i}"} for i in range(total - identified)])
                one, many = batch_brief(candidates, 0, 1), batch_brief(candidates, 0, 2)
                self.assertIn(f"holds {total} candidate(s)", one)
                self.assertIn(f"holds {total} candidate(s)", many)


class TestAForeignBatchIdSurvivesTheRepairStage(unittest.TestCase):
    """agents-fv5uk, the reviewer's own repro. Batch ids are consecutive by construction, so a repair that
    only knows its OWN batch's ids re-attaches a row naming a sibling batch's candidate to a near neighbour
    and the ownership check then accepts a foreign answer. Measured on 6ce8a3c0: repair rewrote the EXACT
    foreign id cand-perf-004 to cand-perf-003 and attribution said "accepted". This is the discriminating
    pin - the end-to-end case cannot be, because there every candidate in reach ties at one edit and the
    ambiguity rule refuses the repair even without the guard."""

    def test_repair_refuses_and_attribution_still_rejects(self):
        from lib.candidate_batching import BatchMergeError, validate_batch_attribution
        from lib.findings import repair_cited_candidate_ids

        own, sibling = ["cand-perf-003"], ["cand-perf-004"]
        row = {"candidate_id": sibling[0]}
        repairs = repair_cited_candidate_ids([row], own, foreign=sibling)
        self.assertEqual(repairs, [], "a sibling batch's exact id must never be repaired")
        self.assertEqual(row["candidate_id"], "cand-perf-004", "the row keeps the id the model wrote")
        with self.assertRaises(BatchMergeError) as caught:
            validate_batch_attribution([row], batch_ids=own, batch_index=0,
                                       all_batch_ids=[own, sibling])
        self.assertIn("belongs to batch 2", str(caught.exception))


class TestThePerCallBoundIsPolicy(unittest.TestCase):
    """agents-tq1lt: the bound is ENFORCED, not an opt-in declaration.

    Five VMs hit the same candidate-accounting/JSON-parse failure, and the stations named in the report
    (vuln-triage, docs-drift, deps-supply-chain) never declared `output.max_candidates_per_call` - so
    they kept asking for up to CANDIDATE_PROMPT_SLICE rows in one completion, which is the truncation
    regime this module exists to bound. Undeclared must therefore batch; a declaration may only tighten
    the ceiling, never lift it.
    """

    def test_the_policy_ceiling_is_eight(self):
        self.assertEqual(MAX_CANDIDATES_PER_BATCH, 8,
                         "the ceiling is the documented <9 KB-per-completion bound (rn0ky)")

    def test_an_undeclared_station_batches_at_the_ceiling(self):
        for cfg in ({}, None, [], {"output": {}}, {"output": "nonsense"},
                    {"output": {"schema": "report.schema.json"}}):
            with self.subTest(cfg=cfg):
                self.assertEqual(resolve_max_candidates_per_call(cfg), MAX_CANDIDATES_PER_BATCH)
                self.assertIsNone(declared_max_candidates_per_call(cfg))

    def test_a_declaration_may_tighten_the_ceiling(self):
        cfg = {"output": {"max_candidates_per_call": 6}}
        self.assertEqual(resolve_max_candidates_per_call(cfg), 6)
        self.assertEqual(declared_max_candidates_per_call(cfg), 6)

    def test_a_declaration_equal_to_the_ceiling_is_honoured(self):
        self.assertEqual(
            resolve_max_candidates_per_call({"output": {"max_candidates_per_call": 8}}), 8)

    def test_a_declaration_above_the_ceiling_is_capped_not_honoured(self):
        cfg = {"output": {"max_candidates_per_call": 50}}
        self.assertEqual(resolve_max_candidates_per_call(cfg), MAX_CANDIDATES_PER_BATCH,
                         "a station cannot ask for one 50-candidate completion back")
        self.assertEqual(declared_max_candidates_per_call(cfg), 50,
                         "the declaration is still readable, so the dispatcher can say it was capped")

    def test_a_malformed_declaration_is_refused_rather_than_ignored(self):
        for raw in ("eight", 0, -3, 2.5, True):
            with self.subTest(raw=raw):
                with self.assertRaises(BatchPlanError):
                    resolve_max_candidates_per_call({"output": {"max_candidates_per_call": raw}})

    def test_the_capped_bound_is_what_the_planner_is_given(self):
        # What the dispatcher actually does: resolve, then plan with the resolved number.
        candidates = [candidate(i) for i in range(10)]
        bound = resolve_max_candidates_per_call({"output": {"max_candidates_per_call": 20}})
        batches = plan_batches(candidates, bound)
        self.assertEqual([len(b) for b in batches], [8, 2])
        self.assertEqual([row["candidate_id"] for b in batches for row in b],
                         [row["candidate_id"] for row in candidates])


class TestPerBatchContextPruning(unittest.TestCase):
    """agents-h53yp: a per-candidate context record rides only in the call that can act on it.

    cloud-factory-cf sent ~355 KB of vuln-triage cluster bodies with EACH of its 7 batches and the engine
    exited 1 on batch 3. These pin the prune's two directions: a record whose candidate ids are all in
    another batch is dropped, and a record the factory cannot attribute is KEPT everywhere.
    """

    def cluster(self, index, *, with_id=True):
        item = {"rule_id": "sql-injection", "path": f"src/file{index}.py", "line_number": index}
        if with_id:
            item["candidate_id"] = f"cand-perf-{index:03d}"
        return {"file": f"src/file{index}.py", "items": [item]}

    def context(self):
        return {
            "threat_model_summary": "model evidence",
            "clusters": [self.cluster(i) for i in range(4)] + [self.cluster(9, with_id=False)],
            "prior_verifications": {"cand-perf-000": {"verdict": "verified"}},
        }

    def test_a_record_for_another_batch_is_dropped_and_counts_are_named(self):
        pruned, record = prune_context_for_batch(
            self.context(), [candidate(1), candidate(2)])
        self.assertEqual([cluster["file"] for cluster in pruned["clusters"]],
                         ["src/file1.py", "src/file2.py", "src/file9.py"],
                         "this batch's own records plus the one the factory cannot attribute")
        self.assertEqual(record["kept"], 2)
        self.assertEqual(record["dropped"], 2)
        self.assertEqual(record["batch_ids"], ["cand-perf-001", "cand-perf-002"])
        self.assertLess(len(json.dumps(pruned)), len(json.dumps(self.context())),
                        "the prune must actually shrink the prompt payload")

    def test_records_without_ids_are_kept_everywhere(self):
        pruned, record = prune_context_for_batch(
            self.context(), [candidate(1)])
        self.assertIn("src/file9.py", [cluster["file"] for cluster in pruned["clusters"]],
                      "an unattributable record must never be dropped on a guess")
        self.assertIsNotNone(record, "the attributable records of other batches were still dropped")

    def test_context_keys_that_are_not_per_candidate_are_untouched(self):
        context = self.context()
        pruned, _record = prune_context_for_batch(context, [candidate(1)])
        self.assertEqual(pruned["threat_model_summary"], "model evidence")
        self.assertEqual(pruned["prior_verifications"], context["prior_verifications"],
                         "a dict of cross-batch evidence is not a per-candidate record list")

    def test_a_batch_without_ids_prunes_nothing(self):
        context = self.context()
        pruned, record = prune_context_for_batch(context, [{"rule_id": "r", "path": "src/file1.py"}])
        self.assertIsNone(record, "no join key, so no record may be described as pruned")
        self.assertEqual(pruned, context)

    def test_a_context_without_ids_is_returned_untouched(self):
        context = {"clusters": [{"cluster": i} for i in range(55)]}
        pruned, record = prune_context_for_batch(context, [candidate(1), candidate(2)])
        self.assertIsNone(record)
        self.assertEqual(pruned, context,
                         "the ADR's unsliceable context stays byte-identical when nothing is provable")

    def test_a_non_container_context_is_returned_untouched(self):
        for context in (None, "text", 7):
            pruned, record = prune_context_for_batch(context, [candidate(1)])
            self.assertIsNone(record)
            self.assertEqual(pruned, context)

    def test_nothing_is_dropped_when_every_record_belongs_to_the_batch(self):
        pruned, record = prune_context_for_batch(
            self.context(), [candidate(0), candidate(1), candidate(2), candidate(3)])
        self.assertIsNone(record, "an unchanged context must not be decorated as if it had been pruned")
        self.assertEqual(pruned, self.context())

    def test_the_ids_are_read_from_keys_not_from_text(self):
        # A snippet quoting somebody else's id must not make a record this batch's.
        self.assertEqual(carried_candidate_ids({"snippet": "see cand-perf-002 for comparison"}), set())
        self.assertEqual(carried_candidate_ids({"candidate_id": "cand-perf-002"}), {"cand-perf-002"})
        self.assertEqual(carried_candidate_ids({"candidate_ids": ["a", "b"]}), {"a", "b"})
        self.assertEqual(carried_candidate_ids({"items": [{"candidate_id": "a"}]}), {"a"})

    def oversized_record(self, *, early_id, late_id):
        """A record whose OTHER-batch id comes first and this batch's id is beyond the node bound.

        This is the agents-h53yp review P2 shape: a bounded id scan stops between the two, so the ids it
        found are non-empty, belong to nobody in this batch, and the pre-fix code dropped the record -
        losing current-batch evidence from a >200k-node context.
        """
        return {"file": "src/big.py",
                "items": [{"candidate_id": early_id}]
                         + [{"filler": index} for index in range(20)]
                         + [{"candidate_id": late_id}]}

    def test_a_record_the_bounded_scan_could_not_finish_is_kept_not_dropped(self):
        oversized = self.oversized_record(early_id="cand-perf-099", late_id="cand-perf-001")
        other = {"file": "src/other.py", "items": [{"candidate_id": "cand-perf-098"}]}
        mine = {"file": "src/mine.py", "items": [{"candidate_id": "cand-perf-001"}]}
        context = {"clusters": [oversized, other, mine], "threat_model_summary": "model evidence"}

        pruned, record = prune_context_for_batch(context, [candidate(1)], limit=5)

        self.assertIn("src/big.py", [cluster["file"] for cluster in pruned["clusters"]],
                      "the record carries this batch's id beyond the bound, so it must be KEPT")
        self.assertNotIn("src/other.py", [cluster["file"] for cluster in pruned["clusters"]],
                         "a record that WAS fully scanned is still dropped - the bound does not "
                         "disable the prune")
        self.assertFalse(record["complete"],
                         "a walk that stopped early must be recorded as incomplete, not as a number")
        self.assertIn("at least", context_prune_notice(record, batch_index=0, batch_count=2),
                      "the model must not be told a complete count this call cannot vouch for")

    def test_a_complete_scan_reports_exact_counts(self):
        pruned, record = prune_context_for_batch(self.context(), [candidate(1), candidate(2)])
        self.assertTrue(record["complete"], record)
        self.assertNotIn("at least", context_prune_notice(record, batch_index=0, batch_count=3))

    def test_the_notice_states_the_population_and_that_absence_is_not_absence(self):
        _pruned, record = prune_context_for_batch(self.context(), [candidate(1), candidate(2)])
        notice = context_prune_notice(record, batch_index=1, batch_count=3)
        self.assertIn("batch 2/3: this call presents 2 of the 4 per-candidate record(s)", notice)
        self.assertIn("pruned under: clusters", notice)
        self.assertIn("absence here is not absence in the scan", notice,
                      "a model must be told the other records exist in another call")


if __name__ == "__main__":
    unittest.main()
