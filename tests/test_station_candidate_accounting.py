"""agents-f8dj: the stations that accounted for zero candidates must state how a dismissal is recorded.

The completeness RULE is pinned in test_factory_truth.py and test_findings.py. What is pinned here is each
station's CONTRACT, on two facts that are actually checkable:

  1. the contract STATES the accounting rule - a candidate that was evaluated and rejected is recorded as a
     dismissal, not dropped;
  2. the VOCABULARY the contract demonstrates is one the READER accepts - the dismissal example is parsed out
     of the contract and handed to lib.embargo.is_false_positive() / reported_severity(), so a rename or a
     tightened vocabulary in the reader fails HERE instead of quietly returning the station to zero-accounted
     (a contract that tells the model to emit a flag nobody reads is a silently green station again).

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
