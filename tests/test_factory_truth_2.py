#!/usr/bin/env python3
"""Second batch of "no unearned verdicts" fixes (fleet-9wyi, fleet-4d1, fleet-xq6d).

- fleet-9wyi: a complete report that names a field `id` instead of `rule_id` is normalised,
  not rejected; output still non-conformant after that is ERROR, with the rejected report
  kept and the cost (findings lost, stations skipped) stated.
- fleet-4d1: qa-station's scorecard is never empty when the store holds findings.
- fleet-xq6d: the exact `disk-quota` URL fragment gendn reported does not match openai-key.
"""

import importlib.machinery
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from lib.report_schema import normalize_report, validate  # noqa: E402
from test_factory_truth import Sandbox, factory_cli  # noqa: E402

THREAT_SCHEMA = json.loads((ROOT / "agents" / "threat-model" / "report.schema.json").read_text())


def tm_output(findings):
    return json.dumps({"summary": "s", "target": "t", "threat_model_markdown": "# TM\n" + "x" * 2000,
                       "findings": findings})


class SchemaAgentCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="factory-truth2-")
        self.addCleanup(tmp.cleanup)
        self.box = Sandbox(Path(tmp.name).resolve())

    def schema_agent(self, name, output):
        self.box.agent(name, output)
        directory = self.box.root / "agents" / name
        with open(directory / "agent.yaml", "a", encoding="utf-8") as f:
            f.write("output:\n  schema: report.schema.json\n")
        (directory / "report.schema.json").write_text(json.dumps(THREAT_SCHEMA), encoding="utf-8")


class TestFieldAliases(SchemaAgentCase):
    def test_gendn_shape_id_instead_of_rule_id_is_accepted(self):
        findings = [{"id": f"TM-{i}", "severity": "Low", "title": f"t{i}", "description": "d",
                     "file": "src/x.ts:12"} for i in range(6)]
        report = json.loads(tm_output(findings))
        self.assertTrue(validate(report, THREAT_SCHEMA), "precondition: the raw shape is rejected")
        notes = normalize_report(report, THREAT_SCHEMA)
        self.assertEqual(validate(report, THREAT_SCHEMA), [])
        self.assertIn("findings[0]: id -> rule_id", notes)
        self.assertEqual(report["findings"][0]["path"], "src/x.ts")
        self.assertEqual(report["findings"][0]["line_number"], 12)
        self.assertEqual(report["findings"][0]["severity"], "low")

    def test_declared_and_canonical_fields_are_never_overwritten(self):
        report = {"findings": [{"rule_id": "keep", "id": "other", "summary": "s", "title": "T"}]}
        normalize_report(report, THREAT_SCHEMA)
        self.assertEqual(report["findings"][0]["rule_id"], "keep")
        self.assertEqual(report["findings"][0]["title"], "T")

    def test_unknown_severity_is_left_for_the_schema_to_reject(self):
        report = {"findings": [{"rule_id": "r", "severity": "urgent", "title": "t", "description": "d"}]}
        normalize_report(report, THREAT_SCHEMA)
        self.assertTrue(validate(report, THREAT_SCHEMA))

    def test_the_station_keeps_its_verdict_end_to_end(self):
        findings = [{"id": "TM-1", "severity": "high", "title": "THREAT_MODEL.md cited but missing",
                     "description": "d"}]
        self.schema_agent("threat-model", tm_output(findings))
        res = self.box.run_agent("threat-model")
        self.assertEqual(res["report"]["findings"][0]["rule_id"], "TM-1")
        self.assertTrue((res["run_dir"] / "normalised_fields.json").exists())
        store = json.loads((self.box.root / "findings" / "target.json").read_text())
        self.assertEqual([f["rule_id"] for f in store["findings"].values()], ["TM-1"])

    def test_the_prompt_carries_the_declared_schema(self):
        self.schema_agent("threat-model", tm_output([]))
        res = self.box.run_agent("threat-model")
        prompt = (res["run_dir"] / "prompt.txt").read_text()
        self.assertIn('"rule_id"', prompt)
        self.assertIn("MUST be one JSON object", prompt)


class TestGenuineRejection(SchemaAgentCase):
    def test_rejection_keeps_the_report_and_states_the_loss(self):
        findings = [{"severity": "high", "description": "no identifier or title at all"}] * 3
        self.schema_agent("threat-model", tm_output(findings))
        with self.assertRaises(factory_cli.StationError) as caught:
            self.box.run_agent("threat-model")
        message = str(caught.exception)
        self.assertIn("3 finding(s) were in the rejected report", message)
        run_dir = next((self.box.root / "runs").iterdir())
        self.assertEqual(len(json.loads((run_dir / "rejected_report.json").read_text())["findings"]), 3)
        self.assertTrue(json.loads((run_dir / "schema_errors.json").read_text()))

    def test_a_halt_names_the_skipped_stations(self):
        self.schema_agent("threat-model", tm_output([{"severity": "high"}]))
        self.box.agent("after-one", json.dumps({"summary": "s", "findings": []}))
        self.box.agent("after-two", json.dumps({"summary": "s", "findings": []}))
        self.box.line(["threat-model", "after-one", "after-two"], halt=True)
        ok, out = self.box.run_line()
        self.assertFalse(ok)
        self.assertIn("Halt at 'threat-model' SKIPPED 2 station(s): after-one, after-two", out)


class TestQaScorecard(unittest.TestCase):
    """fleet-4d1: a store with findings must produce a non-empty scorecard."""

    def test_scorecard_is_not_empty_when_the_store_has_findings(self):
        script = ROOT / "agents" / "qa-station" / "scripts" / "audit_factory_quality.py"
        loader = importlib.machinery.SourceFileLoader("qa_audit_2", str(script))
        spec = importlib.util.spec_from_loader("qa_audit_2", loader)
        qa = importlib.util.module_from_spec(spec)
        loader.exec_module(qa)
        with tempfile.TemporaryDirectory() as tmp:
            findings_dir = Path(tmp)
            records = {f"f{i}": {"agent": "secret-scan", "state": "wontfix" if i < 2 else "new",
                                 "remediation": "r"} for i in range(4)}
            (findings_dir / "gendn-merger.json").write_text(
                json.dumps({"target": "gendn-merger", "findings": records}), encoding="utf-8")
            out = Path(tmp) / "out.json"
            with mock.patch.object(qa, "FINDINGS_DIR", findings_dir), \
                 mock.patch.object(sys, "argv", ["x", "--target", tmp, "--output", str(out)]):
                qa.main()
            payload = json.loads(out.read_text())
            self.assertNotEqual(payload["agent_scorecards"], [])
            card, = payload["agent_scorecards"]
            self.assertEqual((card["agent"], card["total_findings"], card["wontfix"]), ("secret-scan", 4, 2))
            # 50% wontfix over >= 3 findings: the noisy-agent guard can now fire.
            self.assertIn("qa-agent-high-wontfix-noise", [c["rule_id"] for c in payload["candidates"]])


class TestDiskQuota(unittest.TestCase):
    """fleet-xq6d: gendn's exact strings (reference-contract.json:97, index.html:156)."""

    def test_disk_quota_fragment_is_not_an_openai_key(self):
        sys.path.insert(0, str(ROOT / "agents" / "secret-scan" / "scripts"))
        import scan  # noqa: E402
        rule = dict(scan.PATTERNS)["openai-key"]
        for text in (
            "https://w3c.github.io/reporting/#disk-quota-for-buffered-reports-storage-dos",
            '"spec": "https://github.com/w3c/reporting/issues/1#disk-quota-for-buffered-reports"',
            '<a href="https://w3c.github.io/reporting/#disk-quota-for-buffered-reports">quota</a>',
        ):
            with self.subTest(text=text):
                self.assertIsNone(rule.search(text))
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "index.html").write_text(
                '<a href="https://w3c.github.io/reporting/#disk-quota-for-buffered-reports">x</a>\n')
            out = Path(tmp) / "c.json"
            subprocess.run([sys.executable, str(ROOT / "agents" / "secret-scan" / "scripts" / "scan.py"),
                            "--target", tmp, "--output", str(out)], check=True, timeout=60,
                           capture_output=True)
            self.assertEqual(json.loads(out.read_text())["candidates"], [])


if __name__ == "__main__":
    unittest.main()
