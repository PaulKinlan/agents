#!/usr/bin/env python3
"""Deterministic JSON repair of a model's near-JSON report (agents-lb0w3).

The nightly that produced this module: modern-web's model wrote an unescaped double quote inside its
own `summary` string (`"Found 3 "modern" APIs"`) and, on the repair-retry, a JS expression in
`candidate_id` (`path.replace("/", "-")`). Both payloads were report-shaped; both cost the station its
verdict, and neither failure told the operator or the retry what was wrong.

What these tests pin, in the order the module's contract depends on it:
  * a repair is justified by the DECODER's own error position, so the payloads that come back are the
    ones the model wrote (no invented values, no merged members);
  * the shapes no deterministic pass can recover are REFUSED and NAMED instead of guessed at;
  * a payload that was already valid JSON is never touched, and a failed pass hands back the original.
"""

import json
import stat
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from containment_harness import ContainmentHarness  # noqa: E402
from lib.json_repair import (  # noqa: E402
    MAX_REPAIR_STEPS,
    describe_unrepairable,
    repair_json,
)


def decode(region_text):
    """The object `repair_json` produced, decoded strictly - the only postcondition callers rely on."""
    return json.loads(region_text[region_text.find("{"):region_text.rfind("}") + 1])


class TestUnescapedQuotesAreRepaired(unittest.TestCase):
    def test_a_prose_quote_pair_inside_summary_is_escaped_and_the_report_survives(self):
        """The reported failure: the model quoting a word inside its own summary string."""
        text = ('Here is the report:\n{"summary": "Found 3 "modern" APIs: animation-timeline, '
                'popover and :has().", "target": "cap", "scanned_files": 240, "findings": []}\n')
        repaired, notes = repair_json(text)
        self.assertEqual(decode(repaired)["summary"],
                         'Found 3 "modern" APIs: animation-timeline, popover and :has().',
                         "the text must be what the model WROTE, with the quotes escaped")
        self.assertEqual(decode(repaired)["scanned_files"], 240)
        self.assertTrue(notes, "a repair must be recorded, never applied silently")
        self.assertTrue(all("escaped" in note for note in notes), notes)

    def test_prose_with_its_own_braces_before_the_report_does_not_block_the_repair(self):
        """First-`{`-to-last-`}` is only the first GUESS: a brace in the prose must not defeat the pass."""
        text = ('prose {with a brace}\n{"summary": "a "b" c", "findings": []}\ntrailing note')
        repaired, notes = repair_json(text)
        self.assertTrue(notes, "the report is repairable even though the prose has braces")
        self.assertTrue(repaired.startswith("prose {with a brace}\n"), "surrounding prose is untouched")
        report = repaired[repaired.find('{"summary"'):repaired.rfind("}") + 1]
        self.assertEqual(json.loads(report)["summary"], 'a "b" c')

    def test_a_clean_report_is_byte_identical_and_unnoted(self):
        text = '{"summary": "clean", "target": "t", "findings": []}'
        self.assertEqual(repair_json(text), (text, []))

    def test_a_fence_wrapped_clean_report_is_untouched(self):
        text = '```json\n{"summary": "s", "findings": []}\n```'
        repaired, notes = repair_json(text)
        self.assertEqual(notes, [], "nothing to repair means no note: a quiet pass is the common case")


class TestTrailingCommasAreRepaired(unittest.TestCase):
    def test_a_trailing_comma_before_an_array_close_is_dropped(self):
        repaired, notes = repair_json('{"summary": "s", "findings": [{"a": 1},]}')
        self.assertEqual(decode(repaired)["findings"], [{"a": 1}])
        self.assertIn("trailing comma", notes[0])

    def test_a_trailing_comma_before_an_object_close_is_dropped(self):
        repaired, notes = repair_json('{"summary": "s", "findings": [],}')
        self.assertEqual(decode(repaired), {"summary": "s", "findings": []})
        self.assertIn("trailing comma", notes[0])

    def test_ordinary_commas_survive(self):
        text = '{"summary": "s", "findings": [{"a": 1}, {"b": 2}]}'
        self.assertEqual(repair_json(text), (text, []))


class TestTheRepairRefusesToInvent(unittest.TestCase):
    """The half that matters more: a decodable report nobody wrote is worse than a named failure."""

    def test_a_missing_comma_between_members_is_refused_not_folded_into_one_string(self):
        # Escaping the quote here would turn two members into `summary: 'a" "findings": []'` - valid
        # JSON, fabricated content. The pass must refuse and the caller must report the failure.
        text = '{"summary": "a" "findings": []}'
        repaired, notes = repair_json(text)
        self.assertEqual((repaired, notes), (text, []), notes)
        self.assertIsNotNone(describe_unrepairable(text), "the refusal must still be NAMED")

    def test_an_unquoted_js_expression_as_a_value_is_refused_and_named(self):
        """The attempt-1 shape: `path.replace("/", "-")` where a JSON string belonged."""
        text = ('{"summary": "s", "findings": [{"rule_id": "r", '
                '"candidate_id": path.replace("/", "-")}]}')
        repaired, notes = repair_json(text)
        self.assertEqual((repaired, notes), (text, []))
        named = describe_unrepairable(text)
        self.assertIsNotNone(named)
        self.assertIn("not a JSON literal", named)
        self.assertIn("path.replace", named, f"the name must carry the offending text: {named}")

    def test_a_prose_colon_inside_a_string_is_refused_rather_than_repaired(self):
        # `"on": it matters` is indistinguishable from a member name, so the pass refuses. Losing a
        # repair we might have got away with is the price of never fabricating a payload.
        text = '{"summary": "the setting "on": it matters", "findings": []}'
        repaired, notes = repair_json(text)
        self.assertEqual((repaired, notes), (text, []))

    def test_a_truncated_document_is_not_repaired(self):
        # Truncation is classify_unparseable's, and it is named there: appending a brace here would
        # turn a cut completion into a report that looks complete.
        text = '{"summary": "s", "findings": [{"rule_id": "r"'
        self.assertEqual(repair_json(text), (text, []))

    def test_prose_with_no_braces_has_nothing_to_repair(self):
        self.assertEqual(repair_json("All clean, nothing to report."),
                         ("All clean, nothing to report.", []))


class TestThePassIsBounded(unittest.TestCase):
    def test_the_step_bound_is_small_and_positive(self):
        self.assertGreater(MAX_REPAIR_STEPS, 0)
        self.assertLessEqual(MAX_REPAIR_STEPS, 100,
                             "each step re-decodes the region; a large bound is a quadratic scan")

    def test_the_bound_is_actually_spent_and_then_the_original_is_returned(self):
        # One quote pair per summary, nested so that every step needs another escape: the pass must
        # stop at the bound and hand back the ORIGINAL text, never a half-repaired one.
        quotes = "".join(f'"q{index}" ' for index in range(MAX_REPAIR_STEPS + 5))
        text = '{"summary": "' + quotes + '", "findings": []}'
        repaired, notes = repair_json(text)
        self.assertEqual(repaired, text, "an unfinished repair must not be handed to the caller")
        self.assertEqual(notes, [], "no notes means 'nothing was applied', which callers rely on")


class TestDescribeUnrepairable(unittest.TestCase):
    def test_a_decodable_report_has_nothing_to_describe(self):
        self.assertIsNone(describe_unrepairable('{"summary": "s", "findings": []}'))
        self.assertIsNone(describe_unrepairable(""))

    def test_a_missing_comma_between_two_rows_is_named_as_a_missing_comma(self):
        """agents-fsrqw: `[{"a": 1} {"b": 2}]` arrived as "no message at all" - the retry was told
        nothing, and the one thing it needed to hear was that a separator is missing."""
        text = '{"summary": "s", "findings": [{"a": 1} {"b": 2}]}'
        named = describe_unrepairable(text)
        self.assertIsNotNone(named)
        self.assertIn("','", named)
        self.assertIn("missing", named)
        self.assertIn("char", named, "the offset is what locates the fix")
        self.assertEqual(repair_json(text), (text, []),
                         "naming it must not become inserting it: a comma is a place the model left empty")

    def test_a_missing_comma_between_members_is_not_called_an_unescaped_quote(self):
        # Both arrive as "Expecting ',' delimiter" and the decoder stops on a QUOTE, so the quote branch
        # must not claim this one: the model's bug is a missing separator, not a string.
        text = '{"summary": "a" "findings": []}'
        named = describe_unrepairable(text)
        self.assertIsNotNone(named)
        self.assertIn("','", named)
        self.assertNotIn("unescaped quote", named, f"the wrong diagnosis sends the retry looking for a string bug: {named}")

    def test_a_missing_colon_is_named_as_a_missing_colon(self):
        text = '{"summary" "s", "findings": []}'
        named = describe_unrepairable(text)
        self.assertIsNotNone(named)
        self.assertIn("':'", named)
        self.assertIn("member name", named)

    def test_the_excerpt_is_bounded(self):
        text = '{"summary": "s", "findings": [{"rule_id": ' + "x" * 500 + '}]}'
        named = describe_unrepairable(text)
        self.assertIsNotNone(named)
        self.assertLess(len(named), 300, f"a failure line must stay readable: {len(named)} chars")


# The real dispatcher, a real pre-pass and a stub engine: what a night looks like when the model quotes
# a word inside its own summary. One candidate, so this is the SINGLE-call path (no batching involved).
REPAIR_PREPASS = '''
import argparse, json
parser = argparse.ArgumentParser()
parser.add_argument("--target")
parser.add_argument("--output")
args, _unknown = parser.parse_known_args()
candidates = [{
    "candidate_id": "cand-json-000",
    "rule_id": "layout-thrashing-forced-reflow",
    "path": "src/file0.ts",
    "line_number": 1,
    "severity": "high",
    "snippet": "el.offsetWidth",
}]
open(args.output, "w", encoding="utf-8").write(json.dumps({"candidates": candidates}))
'''

REPAIR_AGENT_YAML = """name: probe
class: proposer
plane: [local]
containment: t2-local
triggers: [manual]
blocking: false
short_circuit_empty: false
summary: json repair probe
capabilities:
  write: false
  network: false
  browser: false
  requires: []
budget:
  max_minutes: 5
output:
  schema: report.schema.json
"""

REPAIR_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "RepairProbeReport",
    "type": "object",
    "required": ["summary", "target", "findings"],
    "properties": {
        "summary": {"type": "string"},
        "target": {"type": "string"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["rule_id", "path", "snippet", "severity", "title", "description",
                             "remediation"],
                "properties": {
                    "rule_id": {"type": "string"},
                    "path": {"type": "string"},
                    "line_number": {"type": "integer"},
                    "snippet": {"type": "string"},
                    "severity": {"type": "string",
                                 "enum": ["critical", "high", "medium", "low", "info"]},
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "remediation": {"type": "string"},
                    "candidate_id": {"type": "string"},
                    "false_positive": {"type": "boolean"},
                },
            },
        },
    },
}

# The CAP shape: the model quotes a word inside its own summary string, so the whole report is invalid
# JSON while being perfectly readable to a human.
UNESCAPED_QUOTE_STUB = r"""#!/usr/bin/env bash
set -uo pipefail
cat >/dev/null
printf '%s\n' '{"summary": "Found "one" issue in this file", "target": "probe-target", "findings": [{"rule_id": "layout-thrashing-forced-reflow", "path": "src/file0.ts", "line_number": 1, "snippet": "el.offsetWidth", "severity": "high", "title": "t", "description": "d", "remediation": "x", "candidate_id": "cand-json-000"}]}'
"""

# Attempt 1's shape: an unquoted JS expression where the contract requires a JSON string. No repair can
# recover the value, so the run must fail WITH THE REASON NAMED.
JS_EXPRESSION_STUB = r"""#!/usr/bin/env bash
set -uo pipefail
cat >/dev/null
printf '%s\n' '{"summary": "s", "target": "probe-target", "findings": [{"rule_id": "r", "path": "src/file0.ts", "line_number": 1, "snippet": "s", "severity": "high", "title": "t", "description": "d", "remediation": "x", "candidate_id": path.replace("/", "-")}]}'
"""


class JsonRepairStation(ContainmentHarness):
    """The real dispatcher, a real pre-pass, a stub engine - and the run directory to inspect."""

    def agent(self, yaml_text):  # noqa: D401 - extend the harness's staging with schema + pre-pass
        directory = self.root / "agents" / "probe"
        (directory / "scripts").mkdir(parents=True, exist_ok=True)
        (directory / "agent.yaml").write_text(yaml_text, encoding="utf-8")
        (directory / "SKILL.md").write_text("# Probe\n", encoding="utf-8")
        (directory / "report.schema.json").write_text(json.dumps(REPAIR_SCHEMA, indent=2),
                                                     encoding="utf-8")
        (directory / "scripts" / "prepass.py").write_text(REPAIR_PREPASS, encoding="utf-8")

    def stub(self, script):
        stub = self.bin / "pi"
        stub.write_text(script, encoding="utf-8")
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)

    def run_dir(self):
        dirs = self.run_dirs()
        self.assertEqual(len(dirs), 1, f"expected one run directory, got {dirs}")
        return dirs[0]


class TestARealRunRecoversTheReportItCouldParse(JsonRepairStation):
    def test_an_unescaped_quote_no_longer_costs_the_station_its_verdict(self):
        self.agent(REPAIR_AGENT_YAML)
        self.stub(UNESCAPED_QUOTE_STUB)
        res = self.factory("pi")
        run = self.run_dir()
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

        report = json.loads((run / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["summary"], 'Found "one" issue in this file',
                         "the model's words, with its quotes escaped - not a paraphrase")
        self.assertEqual([row["candidate_id"] for row in report["findings"]], ["cand-json-000"],
                         "the recovered report still answers the candidate it was shown")
        self.assertNotIn("NO VERDICT", report["summary"])

        repairs = json.loads((run / "json_repair.json").read_text(encoding="utf-8"))
        self.assertTrue(repairs["repairs"], "a repair must be recorded in the run directory")
        self.assertIn("escaped", repairs["repairs"][0])

    def test_an_unrepairable_expression_fails_with_the_reason_named(self):
        self.agent(REPAIR_AGENT_YAML)
        self.stub(JS_EXPRESSION_STUB)
        res = self.factory("pi")
        run = self.run_dir()
        self.assertNotEqual(res.returncode, 0, "an unrepairable value must not pass as a verdict")
        reason = (run / "failure_reason.txt").read_text(encoding="utf-8")
        self.assertIn("not a JSON literal", reason,
                      f"the failure must name the shape, not just 'could not parse': {reason}")
        self.assertIn("path.replace", reason, f"and quote what it saw: {reason}")


if __name__ == "__main__":
    unittest.main()
