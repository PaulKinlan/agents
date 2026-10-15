"""agents-f8dj: the stations that accounted for zero candidates must state how a dismissal is recorded.

The completeness RULE is pinned in test_factory_truth.py and test_findings.py. What is pinned here is each
station's CONTRACT, on two facts that are actually checkable:

  1. the contract STATES the accounting rule - a candidate that was evaluated and rejected is recorded as a
     dismissal, not dropped;
  2. the VOCABULARY the contract demonstrates is one the READER accepts - the dismissall example is parsed out
     of the contract and handed to lib.embargo.is_false_positive() / reported_severity(). The tie is asserted in
     BOTH directions and against the reader's whole dismissall vocabulary, because "a rename fails here" is a
     claim that is only true where it is tested: the flag KEY, the flag being load-bearing (a record without it
     is not a dismissall), the verdict VALUE vocabulary (which is how the brief words the migration - a dismissal
     "with its verdict"), and a reader that stops discriminating at all. A contract that tells the model to
     emit a dismissall nobody reads is a silently green station again.

WHAT THIS DELIBERATELY CANNOT PIN: the model's compliance with its own contract. The acceptance evidence for
that is a nightly run reading candidates_accounted == candidates_presented; a stub would only prove that a
fixture emits what the fixture was written to emit, which is the trap this bead exists to avoid.
"""

from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from lib.embargo import is_false_positive, reported_severity
from lib.findings import (CANDIDATE_PROMPT_SLICE, INCOMPLETE_STATUS, aggregate_candidate_coverage,
                          candidate_accounting_mode, candidate_coverage, read_candidate_count,
                          read_presented_candidate_ids, station_has_verdict, station_is_incomplete,
                          write_line_report)

REPO = Path(__file__).resolve().parent.parent

# The three stations whose pre-pass found candidates while their report listed none of them
# (docs-drift x2, modern-web x2, vuln-discovery x2 in the runs measured for agents-xx9t).
STATIONS = ("docs-drift", "modern-web", "vuln-discovery")

# Candidate-fed stations whose contracts and schemas must declare candidate_id (agents-11aq5, agents-huxil).
CANDIDATE_ID_STATIONS = (
    "docs-drift", "modern-web", "vuln-discovery",
    "secret-scan", "vuln-verify", "deps-supply-chain", "qa-station",
    "accessibility", "memory-profile", "perf-review", "resilience",
    "test-gap", "ui-ux-audit", "pr-fixer",
)


def contract(station: str) -> str:
    return (REPO / "agents" / station / "SKILL.md").read_text()


def dismissal_example(text: str):
    """The dismissal record the contract shows, parsed from the first JSON block that carries one."""
    for block in re.findall(r"```json\n(.*?)```", text, re.S):
        if '"false_positive"' not in block:
            continue
        for finding in json.loads(block).get("findings", [json.loads(block)]):
            if finding.get("false_positive") is True:
                return finding
    return None


class TestStationCandidateAccounting(unittest.TestCase):
    def test_every_station_states_the_accounting_rule(self):
        for station in STATIONS:
            with self.subTest(station=station):
                text = contract(station)
                self.assertIn("false_positive", text)
                self.assertIn("info", text)
                self.assertRegex(text, r"(?i)account")
                # The failure the rule exists for is named, so a reader knows the cost of dropping it.
                self.assertIn("INCOMPLETE", text)

    def test_the_rule_survives_the_filtering_instruction(self):
        """The stations already said 'filter': a contract that both filters and drops is the defect."""
        for station in STATIONS:
            with self.subTest(station=station):
                text = contract(station)
                self.assertNotRegex(text, r"(?i)\bfilter out false positives\b")
                self.assertNotRegex(text, r"(?i)Downgrade or filter these")
                self.assertRegex(text, r"(?i)dismiss")

    def test_the_demonstrated_dismissal_is_one_the_reader_accepts(self):
        for station in STATIONS:
            with self.subTest(station=station):
                finding = dismissal_example(contract(station))
                self.assertIsNotNone(finding, f"{station}'s contract shows no dismissal record to copy")
                # Fact 2: the reader accepts what the contract tells the model to emit. If lib/embargo.py stops
                # reading `false_positive`, this fails rather than the station going quietly green.
                self.assertTrue(is_false_positive(finding))
                # And it must not read as work: a dismissal is reported at info severity, never routed.
                self.assertEqual(reported_severity(finding), "info")

    def test_the_reader_still_recognises_the_dismissal_vocabulary_the_contracts_rely_on(self):
        """agents-f8dj, coord's pin check 3: the arm listing is only worth its 0.004s if a change to the
        READER'S vocabulary actually fails a test here. Measured on a copy of the tree before this test
        existed: removing the flag branch failed (3 failures) and renaming the flag KEY failed (3), but
        renaming the accepted VERDICT VALUES or the VERDICT FIELD names failed NOTHING - so the binding was
        narrower than the write-up claimed. These four assertions close that gap deliberately, one per
        direction of silence:

          * the flag the contracts mandate is accepted;
          * the verdict shape the migration brief words ("list each dismissed candidate with its verdict") is
            accepted, so losing _VERDICT_FIELDS or _FALSE_POSITIVE_VERDICTS breaks this;
          * a record carrying NEITHER marker is NOT a dismissal, so a reader that starts accepting everything
            (which would suppress real findings as evidence) breaks this;
          * the demonstrated example is load-bearing - strip the flag and it stops being a dismissal.
        """
        self.assertTrue(is_false_positive({"severity": "info", "false_positive": True}))
        self.assertTrue(is_false_positive({"severity": "info", "verdict": "false_positive"}),
                        "the verdict vocabulary the migration brief names is no longer accepted")
        self.assertFalse(is_false_positive({"severity": "info", "rule_id": "real-finding", "title": "Real"}),
                         "a record with no dismissal marker must not read as a dismissal")
        example = dismissal_example(contract("docs-drift"))
        self.assertTrue(is_false_positive(example))
        self.assertFalse(is_false_positive({k: v for k, v in example.items() if k != "false_positive"}),
                         "the flag must be what carries the dismissal, not the record's shape")

    def test_a_dismissal_needs_the_fields_the_report_schema_requires(self):
        """The contract's shape must satisfy the schema the factory VALIDATES against, not just the reader."""
        for station in STATIONS:
            with self.subTest(station=station):
                items = json.loads((REPO / "agents" / station / "report.schema.json").read_text())[
                    "properties"]["findings"]["items"]
                finding = dismissal_example(contract(station))
                for field in items.get("required", []):
                    self.assertIn(field, finding, f"{station} omits {field}, which the schema requires")
                for field in finding:
                    self.assertIn(field, items.get("properties", {}),
                                  f"{station} shows {field}, which the schema does not define")

    def test_the_dismissal_flag_is_declared_so_the_prompt_carries_it(self):
        """The factory embeds the schema in the prompt (lib/report_schema.output_contract_prompt), so a field the
        schema does not declare reaches the model only as prose. Declaring it here is what makes the flag visible
        to the model mechanically - and it fails if a later edit drops the declaration while keeping the prose."""
        for station in STATIONS:
            with self.subTest(station=station):
                items = json.loads((REPO / "agents" / station / "report.schema.json").read_text())[
                    "properties"]["findings"]["items"]
                self.assertEqual(items["properties"]["false_positive"]["type"], "boolean")
                self.assertNotIn("false_positive", items.get("required", []),
                                 "a dismissal flag must stay optional: confirmed findings do not carry it")


class TestCountAndIdentityAreTwoBounds(unittest.TestCase):
    """agents-w9ni: the count bounds ROWS, identity bounds WHICH candidates they name.

    MEASURED ON THE PRE-FIX TREE, which is the discriminator for this class: five candidates presented and
    five invented rows (rule_id 'made-up', paths not-a-candidate-0..4.js, no candidate_id) read as
    "accounted 5 of 5" and PASSed. The first test below is that exact population.
    """

    IDS = ["cand-0", "cand-1", "cand-2", "cand-3", "cand-4"]

    def test_invented_rows_do_not_account_for_the_candidates_shown(self):
        got = candidate_coverage(5, 5, presented_ids=self.IDS, cited_ids=[])
        self.assertFalse(got["complete"],
                         "the right NUMBER of rows describing the wrong candidates must not carry the check")
        self.assertEqual(got["identity"], "identity-matched")
        self.assertEqual(got["candidates_accounted"], 0)
        self.assertIn("candidate_id", got["reason"])

    def test_rows_that_name_the_presented_candidates_do_account(self):
        got = candidate_coverage(5, 5, presented_ids=self.IDS, cited_ids=self.IDS)
        self.assertTrue(got["complete"])
        self.assertEqual(got["candidates_accounted"], 5)
        self.assertEqual(got["reason"], "")

    def test_an_id_the_station_was_never_shown_does_not_count(self):
        got = candidate_coverage(3, 3, presented_ids=self.IDS[:3],
                                 cited_ids=["cand-0", "made-up", "cand-9"])
        self.assertEqual(got["candidates_accounted"], 1)
        self.assertFalse(got["complete"], "only the intersection with what was presented may count")

    def test_the_slice_bounds_the_population_on_both_sides(self):
        ids = [f"cand-{i}" for i in range(120)]
        got = candidate_coverage(120, CANDIDATE_PROMPT_SLICE,
                                 presented_ids=ids[:CANDIDATE_PROMPT_SLICE],
                                 cited_ids=ids[:CANDIDATE_PROMPT_SLICE])
        self.assertEqual(got["candidates_presented"], CANDIDATE_PROMPT_SLICE)
        self.assertTrue(got["complete"])

    def test_pre_scheme_candidates_keep_the_count_and_say_it_was_only_a_count(self):
        got = candidate_coverage(5, 5, presented_ids=[])
        self.assertTrue(got["complete"], "a count is still the answer for candidates that carry no ids")
        self.assertEqual(got["identity"], "count-only")
        short = candidate_coverage(5, 2, presented_ids=[])
        self.assertFalse(short["complete"])
        self.assertIn("count-only", short["reason"], "the weaker check must name itself")
        self.assertIn("a partial triage is not a clean result", short["reason"])

    def test_no_prepass_still_asserts_nothing(self):
        got = candidate_coverage(None, 7)
        self.assertTrue(got["complete"])
        self.assertEqual(got["identity"], "not-applicable")


class TestAggregateCandidateAccounting(unittest.TestCase):
    """agents-88cd: an opt-in CLAIMED many-to-one disposition, never a count fallback."""

    def cover(self, ids, rows, total=None):
        return aggregate_candidate_coverage(len(ids) if total is None else total, rows,
                                            presented_ids=ids)

    def test_two_clusters_one_root_cause_has_explicit_claimed_mapping(self):
        got = self.cover(["A", "B"], [{"covered_candidate_ids": ["A", "B"],
                                        "anchor_candidate_id": "A", "title": "one cause"}])
        self.assertTrue(got["complete"])
        self.assertEqual((got["identity"], got["candidates_accounted"]),
                         ("identity-claimed-aggregate", 2))
        self.assertEqual(got["candidate_claims"], [
            {"row_index": 0, "covered_candidate_ids": ["A", "B"], "anchor_candidate_id": "A"}])

    def test_echo_without_explicit_coverage_does_not_account_for_anything(self):
        got = self.cover(["A"], [{"anchor_candidate_id": "A", "title": "found"}])
        self.assertFalse(got["complete"])
        self.assertEqual(got["candidates_accounted"], 0)
        self.assertIn("covered_candidate_ids", got["reason"])

    def test_an_unclaimed_presented_alias_is_incomplete(self):
        got = self.cover(["A", "B"], [{"covered_candidate_ids": ["A"]}])
        self.assertFalse(got["complete"])
        self.assertEqual(got["candidates_accounted"], 1)
        self.assertIn("missing", got["reason"])

    def test_unknown_and_unshown_ids_fail_even_if_all_presented_ids_are_claimed(self):
        unknown = self.cover(["A"], [{"covered_candidate_ids": ["A", "imagined"]}])
        self.assertFalse(unknown["complete"])
        self.assertIn("unknown", unknown["reason"])
        unshown = self.cover(["A", "B"], [{"covered_candidate_ids": ["A", "B", "C"]}], total=2)
        self.assertFalse(unshown["complete"])
        self.assertIn("unknown", unshown["reason"])

    def test_repeated_id_within_or_across_rows_is_not_silently_set_deduped(self):
        within = self.cover(["A"], [{"covered_candidate_ids": ["A", "A"]}])
        across = self.cover(["A"], [{"covered_candidate_ids": ["A"]},
                                    {"covered_candidate_ids": ["A"]}])
        for got in (within, across):
            self.assertFalse(got["complete"])
            self.assertIn("duplicate", got["reason"])

    def test_primary_anchor_must_belong_to_its_own_row_claim(self):
        got = self.cover(["A", "B"], [{"covered_candidate_ids": ["A"], "anchor_candidate_id": "B"},
                                      {"covered_candidate_ids": ["B"]}])
        self.assertFalse(got["complete"])
        self.assertIn("anchor_candidate_id", got["reason"])

    def test_dismissal_counts_by_claim_and_echo_is_not_required(self):
        got = self.cover(["A", "B"], [
            {"covered_candidate_ids": ["A"], "false_positive": True, "severity": "info"},
            {"covered_candidate_ids": ["B"], "title": "real cause"}])
        self.assertTrue(got["complete"])
        self.assertEqual(got["candidates_accounted"], 2)

    def test_only_first_fifty_ids_shown_may_be_claimed(self):
        all_ids = [f"id-{i}" for i in range(52)]
        presented = all_ids[:CANDIDATE_PROMPT_SLICE]
        got = self.cover(presented, [{"covered_candidate_ids": presented}], total=52)
        self.assertTrue(got["complete"])
        self.assertEqual(got["candidates_presented"], CANDIDATE_PROMPT_SLICE)
        unshown = self.cover(presented, [{"covered_candidate_ids": all_ids[:51]}], total=52)
        self.assertFalse(unshown["complete"])
        self.assertIn("unknown", unshown["reason"])

    def test_zero_presented_and_zero_rows_is_complete_but_no_id_fallback_is_forbidden(self):
        self.assertTrue(self.cover([], [], total=0)["complete"])
        self.assertFalse(self.cover([], [{"covered_candidate_ids": []}], total=0)["complete"])
        self.assertFalse(self.cover([], ["not-a-row"], total=0)["complete"])
        got = self.cover([], [{"covered_candidate_ids": ["A"]}], total=1)
        self.assertFalse(got["complete"])
        self.assertIn("unique presented", got["reason"])
        self.assertFalse(self.cover(["A", "A"], [{"covered_candidate_ids": ["A"]}])["complete"])

    def test_opted_in_mode_without_a_candidate_prepass_cannot_claim_count_only(self):
        got = aggregate_candidate_coverage(None, [{"covered_candidate_ids": ["A"]}],
                                           presented_ids=None)
        self.assertFalse(got["complete"])
        self.assertEqual(got["identity"], "identity-claimed-aggregate")
        self.assertIn("pre-pass", got["reason"])

    def test_absent_coverage_list_cannot_pass_by_row_count(self):
        for value in ([], None, "A", [1], [""], ["A", None]):
            with self.subTest(value=value):
                self.assertFalse(self.cover(["A"], [{"covered_candidate_ids": value}])["complete"])

    def test_unknown_mode_refused_and_default_remains_row(self):
        self.assertEqual(candidate_accounting_mode({}), "row")
        self.assertEqual(candidate_accounting_mode({"candidate_accounting": "row"}), "row")
        self.assertEqual(candidate_accounting_mode({"candidate_accounting": "aggregate-claimed"}),
                         "aggregate-claimed")
        for bad in ("aggregate", "unknown", None, 3, False):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                candidate_accounting_mode({"candidate_accounting": bad})

    def test_old_row_mode_scores_and_count_only_fixtures_are_unchanged(self):
        self.assertEqual(candidate_coverage(None, 7), {
            "candidates_in": None, "candidates_presented": None,
            "candidates_accounted": 7, "complete": True, "reason": "", "identity": "not-applicable"})
        self.assertEqual(candidate_coverage(2, 2, presented_ids=[]), {
            "candidates_in": 2, "candidates_presented": 2,
            "candidates_accounted": 2, "complete": True, "reason": "", "identity": "count-only"})
        self.assertEqual(candidate_coverage(2, 1, presented_ids=["A", "B"], cited_ids=["A"]), {
            "candidates_in": 2, "candidates_presented": 2,
            "candidates_accounted": 1, "complete": False,
            "reason": "cited 1 of the 2 candidate id(s) shown (2 found by the pre-pass): a partial "
                      "triage is not a clean result; every row - confirmed or dismissed - must carry "
                      "the candidate_id of the pre-pass candidate it answers",
            "identity": "identity-matched"})


class TestPresentedIdsComeFromTheRun(unittest.TestCase):
    def _run(self, candidates):
        run = tempfile.mkdtemp()
        (Path(run) / "candidates.json").write_text(json.dumps({"candidates": candidates}), encoding="utf-8")
        return run

    def test_ids_are_read_in_presentation_order(self):
        run = self._run([{"candidate_id": "a"}, {"candidate_id": "b"}])
        self.assertEqual(read_presented_candidate_ids(run), ["a", "b"])

    def test_present_but_unnamed_is_empty_not_none(self):
        self.assertEqual(read_presented_candidate_ids(self._run([{"rule_id": "r"}])), [])
        self.assertEqual(read_presented_candidate_ids(self._run([{"candidate_id": "a"}, {"rule_id": "r"}])),
                         [], "partial ids are no ids: the whole presented population must be nameable")

    def test_no_candidates_json_is_none(self):
        self.assertIsNone(read_presented_candidate_ids(tempfile.mkdtemp()))
        self.assertIsNone(read_presented_candidate_ids(None))

    def test_the_reader_agrees_with_the_count_reader_on_the_same_run(self):
        run = self._run([{"candidate_id": f"c{i}", "rule_id": "r"} for i in range(120)])
        self.assertEqual(len(read_presented_candidate_ids(run)), CANDIDATE_PROMPT_SLICE,
                         "the ids must be the population the prompt carried, not the whole pre-pass")
        self.assertEqual(read_candidate_count(run), 120)


class TestIdentityIsVisibleWhereverTheCountIsShown(unittest.TestCase):
    """A count-only check that reads like an identity check is the same blind spot one level down."""

    def _report(self, station):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            return write_line_report("target", "project-audit", [station], findings_dir=root).read_text(
                encoding="utf-8")

    def _station(self, identity, complete=True):
        return {"station": "quiet", "status": "PASS" if complete else INCOMPLETE_STATUS,
                "findings_count": 5, "criticals": 0, "candidates_in": 5, "candidates_presented": 5,
                "candidates_accounted": 5 if complete else 0, "candidate_identity": identity,
                "complete": complete, "note": ""}

    def test_count_only_is_named_in_the_station_table(self):
        self.assertIn("(5/5, count-only)", self._report(self._station("count-only")))

    def test_identity_matched_is_named_too(self):
        self.assertIn("(5/5, identity-matched)", self._report(self._station("identity-matched")))

    def test_an_incomplete_station_shows_which_bound_it_met(self):
        report = self._report(self._station("identity-matched", complete=False))
        # A station with no verdict renders a DASH in the table on purpose (its counts are not a verdict, see
        # test_findings' dash-row tests): the banner is where the numbers and the bound are named.
        self.assertIn("| `quiet` | INCOMPLETE | — | — |", report)
        self.assertIn("0 of 5 shown, identity-matched", report,
                      "the INCOMPLETE banner must say how the count was judged, not only how many")


class TestTheContractsAndSchemasCarryIdentity(unittest.TestCase):
    def test_every_station_declares_candidate_id_so_the_prompt_carries_it(self):
        """Same mechanism as the dismissal flag: the schema is embedded in the prompt, so a field it does not
        declare reaches the model only as prose."""
        for station in CANDIDATE_ID_STATIONS:
            with self.subTest(station=station):
                items = json.loads((REPO / "agents" / station / "report.schema.json").read_text())[
                    "properties"]["findings"]["items"]
                self.assertEqual(items["properties"]["candidate_id"]["type"], "string")
                self.assertNotIn("candidate_id", items.get("required", []),
                                 "pre-scheme reports and stations without a pre-pass do not carry it")

    def test_every_station_contract_asks_for_the_citation(self):
        for station in CANDIDATE_ID_STATIONS:
            with self.subTest(station=station):
                text = contract(station)
                self.assertIn("candidate_id", text)
                self.assertRegex(text, r"(?i)cite the candidate you are answering")
                self.assertRegex(text, r"(?i)count-only",
                                 "the contract must say what happens when no ids exist, so the weak path is known")


class TestCandidateAccountingRefusalAndResolution(unittest.TestCase):
    """agents-11aq5, agents-huxil: driven test proving the refusal is alive for zero-of-N shown IDs and accounts when cited."""

    FAILING_FOUR = ("secret-scan", "vuln-verify", "deps-supply-chain", "qa-station")
    SEVEN_STATIONS = (
        "accessibility", "memory-profile", "perf-review", "resilience",
        "test-gap", "ui-ux-audit", "pr-fixer",
    )
    CLEAN_STATIONS_WITHOUT_CANDIDATES = (
        "log-check", "issue-triage", "bundle-size", "release-notes",
    )

    def _render(self, station):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            return write_line_report("target", "project-audit", [station], findings_dir=root).read_text(
                encoding="utf-8")

    def test_each_of_the_four_stations_refuses_zero_of_n_and_accounts_when_cited(self):
        ids = [f"cand-{i}" for i in range(50)]
        for station_name in self.FAILING_FOUR:
            with self.subTest(station=station_name):
                # Before: station reports 50 findings without candidate_id (0 of 50 accounted)
                cov_before = candidate_coverage(50, 50, presented_ids=ids, cited_ids=[])
                self.assertFalse(cov_before["complete"])
                self.assertEqual(cov_before["candidates_in"], 50)
                self.assertEqual(cov_before["candidates_presented"], 50)
                self.assertEqual(cov_before["candidates_accounted"], 0)
                self.assertEqual(cov_before["identity"], "identity-matched")
                self.assertIn("a partial triage is not a clean result", cov_before["reason"])
                self.assertIn("cited 0 of the 50 candidate id(s) shown", cov_before["reason"])
                self.assertEqual(
                    cov_before["reason"],
                    "cited 0 of the 50 candidate id(s) shown (50 found by the pre-pass): a partial triage is not a clean "
                    "result; every row - confirmed or dismissed - must carry the candidate_id of the pre-pass candidate "
                    "it answers"
                )

                st_before = {
                    "station": station_name,
                    "status": "PASS" if cov_before["complete"] else INCOMPLETE_STATUS,
                    "findings_count": 50,
                    "criticals": 0,
                    "candidates_in": cov_before["candidates_in"],
                    "candidates_presented": cov_before["candidates_presented"],
                    "candidates_accounted": cov_before["candidates_accounted"],
                    "candidate_identity": cov_before["identity"],
                    "complete": cov_before["complete"],
                    "note": cov_before["reason"]
                }
                self.assertTrue(station_is_incomplete(st_before))
                self.assertFalse(station_has_verdict(st_before))
                report_before = self._render(st_before)
                self.assertIn(f"`{station_name}` (0 of 50 shown, identity-matched)", report_before)
                self.assertIn("> **INCOMPLETE**: 1 station(s) did not account for the candidates they were shown", report_before)
                self.assertNotIn("> **Clean Delta**", report_before)

                # After: station reports findings with candidate_ids matching what was presented (50 of 50 accounted)
                cov_after = candidate_coverage(50, 50, presented_ids=ids, cited_ids=ids)
                self.assertTrue(cov_after["complete"])
                self.assertEqual(cov_after["candidates_in"], 50)
                self.assertEqual(cov_after["candidates_presented"], 50)
                self.assertEqual(cov_after["candidates_accounted"], 50)
                self.assertEqual(cov_after["identity"], "identity-matched")
                self.assertEqual(cov_after["reason"], "")

                st_after = {
                    "station": station_name,
                    "status": "PASS" if cov_after["complete"] else INCOMPLETE_STATUS,
                    "findings_count": 0,
                    "criticals": 0,
                    "candidates_in": cov_after["candidates_in"],
                    "candidates_presented": cov_after["candidates_presented"],
                    "candidates_accounted": cov_after["candidates_accounted"],
                    "candidate_identity": cov_after["identity"],
                    "complete": cov_after["complete"],
                    "note": cov_after["reason"]
                }
                self.assertFalse(station_is_incomplete(st_after))
                self.assertTrue(station_has_verdict(st_after))
                report_after = self._render(st_after)
                self.assertNotIn("INCOMPLETE", report_after)
                self.assertIn("> **Clean Delta**: No new, regressed, or resolved findings in this run.", report_after)

    def test_each_of_the_seven_stations_refuses_zero_of_n_and_accounts_when_cited(self):
        ids = [f"cand-{i}" for i in range(50)]
        for station_name in self.SEVEN_STATIONS:
            with self.subTest(station=station_name):
                # Before: station reports 50 findings without candidate_id (0 of 50 accounted)
                cov_before = candidate_coverage(50, 50, presented_ids=ids, cited_ids=[])
                self.assertFalse(cov_before["complete"])
                self.assertEqual(cov_before["candidates_in"], 50)
                self.assertEqual(cov_before["candidates_presented"], 50)
                self.assertEqual(cov_before["candidates_accounted"], 0)
                self.assertEqual(cov_before["identity"], "identity-matched")
                self.assertIn("a partial triage is not a clean result", cov_before["reason"])
                self.assertIn("cited 0 of the 50 candidate id(s) shown", cov_before["reason"])
                self.assertEqual(
                    cov_before["reason"],
                    "cited 0 of the 50 candidate id(s) shown (50 found by the pre-pass): a partial triage is not a clean "
                    "result; every row - confirmed or dismissed - must carry the candidate_id of the pre-pass candidate "
                    "it answers"
                )

                st_before = {
                    "station": station_name,
                    "status": "PASS" if cov_before["complete"] else INCOMPLETE_STATUS,
                    "findings_count": 50,
                    "criticals": 0,
                    "candidates_in": cov_before["candidates_in"],
                    "candidates_presented": cov_before["candidates_presented"],
                    "candidates_accounted": cov_before["candidates_accounted"],
                    "candidate_identity": cov_before["identity"],
                    "complete": cov_before["complete"],
                    "note": cov_before["reason"]
                }
                self.assertTrue(station_is_incomplete(st_before))
                self.assertFalse(station_has_verdict(st_before))
                report_before = self._render(st_before)
                self.assertIn(f"`{station_name}` (0 of 50 shown, identity-matched)", report_before)
                self.assertIn("> **INCOMPLETE**: 1 station(s) did not account for the candidates they were shown", report_before)
                self.assertNotIn("> **Clean Delta**", report_before)

                # After: station reports findings with candidate_ids matching what was presented (50 of 50 accounted)
                cov_after = candidate_coverage(50, 50, presented_ids=ids, cited_ids=ids)
                self.assertTrue(cov_after["complete"])
                self.assertEqual(cov_after["candidates_in"], 50)
                self.assertEqual(cov_after["candidates_presented"], 50)
                self.assertEqual(cov_after["candidates_accounted"], 50)
                self.assertEqual(cov_after["identity"], "identity-matched")
                self.assertEqual(cov_after["reason"], "")

                st_after = {
                    "station": station_name,
                    "status": "PASS" if cov_after["complete"] else INCOMPLETE_STATUS,
                    "findings_count": 0,
                    "criticals": 0,
                    "candidates_in": cov_after["candidates_in"],
                    "candidates_presented": cov_after["candidates_presented"],
                    "candidates_accounted": cov_after["candidates_accounted"],
                    "candidate_identity": cov_after["identity"],
                    "complete": cov_after["complete"],
                    "note": cov_after["reason"]
                }
                self.assertFalse(station_is_incomplete(st_after))
                self.assertTrue(station_has_verdict(st_after))
                report_after = self._render(st_after)
                self.assertNotIn("INCOMPLETE", report_after)
                self.assertIn("> **Clean Delta**: No new, regressed, or resolved findings in this run.", report_after)

    def test_stations_without_candidates_still_do_not_fail(self):
        """Clean stations with no pre-pass or 0 candidates still produce a clean verdict."""
        for station_name in self.CLEAN_STATIONS_WITHOUT_CANDIDATES:
            with self.subTest(station=station_name):
                # No prepass (None)
                cov_none = candidate_coverage(None, 0)
                self.assertTrue(cov_none["complete"])
                self.assertEqual(cov_none["identity"], "not-applicable")
                st_none = {
                    "station": station_name, "status": "PASS", "findings_count": 0, "criticals": 0,
                    "candidates_in": None, "candidates_presented": None, "candidates_accounted": 0,
                    "candidate_identity": cov_none["identity"], "complete": True, "note": ""
                }
                self.assertFalse(station_is_incomplete(st_none))
                self.assertTrue(station_has_verdict(st_none))

                # Empty prepass (0 candidates)
                cov_zero = candidate_coverage(0, 0, presented_ids=[], cited_ids=[])
                self.assertTrue(cov_zero["complete"])
                st_zero = {
                    "station": station_name, "status": "PASS", "findings_count": 0, "criticals": 0,
                    "candidates_in": 0, "candidates_presented": 0, "candidates_accounted": 0,
                    "candidate_identity": cov_zero["identity"], "complete": True, "note": ""
                }
                self.assertFalse(station_is_incomplete(st_zero))
                self.assertTrue(station_has_verdict(st_zero))


if __name__ == "__main__":
    unittest.main()
