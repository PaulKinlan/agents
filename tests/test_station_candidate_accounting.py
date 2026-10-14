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
import unittest
from pathlib import Path

from lib.embargo import is_false_positive, reported_severity

REPO = Path(__file__).resolve().parent.parent

# The three stations whose pre-pass found candidates while their report listed none of them
# (docs-drift x2, modern-web x2, vuln-discovery x2 in the runs measured for agents-xx9t).
STATIONS = ("docs-drift", "modern-web", "vuln-discovery")


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


if __name__ == "__main__":
    unittest.main()
