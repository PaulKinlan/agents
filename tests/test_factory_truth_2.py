#!/usr/bin/env python3
"""Second batch of "no unearned verdicts" fixes (fleet-9wyi, fleet-4d1, fleet-xq6d).

- fleet-9wyi: a complete report that names a field `id` instead of `rule_id` is normalised,
  not rejected; output still non-conformant after that is ERROR, with the rejected report
  kept and the cost (findings lost, stations skipped) stated.
- fleet-4d1: qa-station's scorecard is never empty when the store holds findings.
- fleet-xq6d: the exact `disk-quota` URL fragment gendn reported does not match openai-key.
"""

import importlib.machinery
import os
os.environ.setdefault("FACTORY_ALLOW_UNPINNED_TOOLS", "1")  # agents-7bj: tests use unpinned stub tools
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
from lib.sandbox import sandbox_available  # noqa: E402
from test_factory_truth import Sandbox, factory_cli  # noqa: E402

_RUNNABLE_BWRAP = sandbox_available()
_NEEDS_BWRAP = "needs a host where bubblewrap actually runs"

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

    def test_locations_with_spaces_drive_letters_and_columns(self):
        """Review r4200726078: parse from the numeric suffix, not a colon-free path."""
        cases = {
            "src/my file.ts:12": ("src/my file.ts", 12),
            "C:\\src\\x.ts:12": ("C:\\src\\x.ts", 12),
            "C:\\src\\x.ts:12:5": ("C:\\src\\x.ts", 12),
            "lib/a.py:7:3": ("lib/a.py", 7),
        }
        for location, (path, line) in cases.items():
            with self.subTest(location=location):
                report = {"findings": [{"id": "r", "file": location, "title": "t", "description": "d"}]}
                normalize_report(report, THREAT_SCHEMA)
                item = report["findings"][0]
                self.assertEqual((item["path"], item["line_number"]), (path, line))
        for location in ("src/no-line.ts", "C:\\x.ts", ":12"):
            with self.subTest(location=location):
                report = {"findings": [{"id": "r", "file": location}]}
                normalize_report(report, THREAT_SCHEMA)
                self.assertEqual(report["findings"][0]["path"], location)
                self.assertNotIn("line_number", report["findings"][0])

    def test_declared_and_canonical_fields_are_never_overwritten(self):
        report = {"findings": [{"rule_id": "keep", "id": "other", "summary": "s", "title": "T"}]}
        normalize_report(report, THREAT_SCHEMA)
        self.assertEqual(report["findings"][0]["rule_id"], "keep")
        self.assertEqual(report["findings"][0]["title"], "T")

    def test_unknown_severity_is_left_for_the_schema_to_reject(self):
        report = {"findings": [{"rule_id": "r", "severity": "urgent", "title": "t", "description": "d"}]}
        normalize_report(report, THREAT_SCHEMA)
        self.assertTrue(validate(report, THREAT_SCHEMA))

    @unittest.skipUnless(_RUNNABLE_BWRAP, _NEEDS_BWRAP)
    def test_the_station_keeps_its_verdict_end_to_end(self):
        findings = [{"id": "TM-1", "severity": "high", "title": "THREAT_MODEL.md cited but missing",
                     "description": "d"}]
        self.schema_agent("threat-model", tm_output(findings))
        res = self.box.run_agent("threat-model")
        self.assertEqual(res["report"]["findings"][0]["rule_id"], "TM-1")
        self.assertTrue((res["run_dir"] / "normalised_fields.json").exists())
        store = json.loads((self.box.root / "findings" / "target.json").read_text())
        self.assertEqual([f["rule_id"] for f in store["findings"].values()], ["TM-1"])

    @unittest.skipUnless(_RUNNABLE_BWRAP, _NEEDS_BWRAP)
    def test_concurrency_recommendation_is_guarded_with_reentrancy_precondition_end_to_end(self):
        """agents-vorw: unchecked concurrency recommendation must be guarded with reentrancy precondition end-to-end."""
        findings = [{
            "rule_id": "sequential-await-waterfall",
            "path": "src/onnx_session.ts",
            "line_number": 15,
            "snippet": "for (const e of exercises) await e.run();",
            "severity": "high",
            "title": "Exercise Forward Pass Waterfall",
            "description": "Sequential await inside loop",
            "remediation": "Replace with await Promise.all(exercises.map(e => e.run()))",
        }]
        report = {
            "summary": "Perf review report",
            "target": "target",
            "findings": findings
        }
        self.schema_agent("perf-review", json.dumps(report))
        res = self.box.run_agent("perf-review")
        stored_finding = res["report"]["findings"][0]
        self.assertTrue(stored_finding["remediation"].startswith("Precondition: Verify backend reentrancy before applying."))
        self.assertIn("ONNX Runtime _OrtRun", stored_finding["remediation"])
        self.assertIn("otherwise preserve serial execution", stored_finding["remediation"])

        # Must be recorded in normalised_fields.json
        norm_file = res["run_dir"] / "normalised_fields.json"
        self.assertTrue(norm_file.exists())
        self.assertIn("enforced reentrancy precondition", norm_file.read_text())

        # Must be persisted in the findings store with the precondition
        store = json.loads((self.box.root / "findings" / "target.json").read_text())
        persisted = list(store["findings"].values())[0]
        self.assertTrue(persisted["remediation"].startswith("Precondition: Verify backend reentrancy before applying."))

    @unittest.skipUnless(_RUNNABLE_BWRAP, _NEEDS_BWRAP)
    def test_existing_target_threat_model_is_preserved_when_markdown_omitted(self):
        """agents-tawg: when agent returns summary + findings without threat_model_markdown,
        target's authoritative THREAT_MODEL.md is synced to findings store."""
        target_dir = self.box.target
        (target_dir / "THREAT_MODEL.md").write_text("# Target Authoritative TM\nSection 1...\n", encoding="utf-8")
        report = {"summary": "s", "target": "target", "findings": []}
        self.schema_agent("threat-model", json.dumps(report))
        res = self.box.run_agent("threat-model")
        self.assertEqual(res["report"]["summary"], "s")
        store_tm = self.box.root / "findings" / "target-THREAT_MODEL.md"
        self.assertTrue(store_tm.exists())
        self.assertEqual(store_tm.read_text(encoding="utf-8"), "# Target Authoritative TM\nSection 1...\n")

    @unittest.skipUnless(_RUNNABLE_BWRAP, _NEEDS_BWRAP)
    def test_findings_store_only_threat_model_is_preserved_on_maintenance_run(self):
        """agents-tawg: when an existing threat model lives only in findings store,
        a maintenance run that returns summary + findings preserves it and does not overwrite it."""
        target_dir = self.box.target
        for cand in [target_dir / "THREAT_MODEL.md", target_dir / "docs" / "THREAT_MODEL.md"]:
            if cand.exists():
                cand.unlink()
        store_tm = self.box.root / "findings" / "target-THREAT_MODEL.md"
        store_tm.parent.mkdir(parents=True, exist_ok=True)
        store_tm.write_text("# Prior Established Threat Model\nStrict Invariants...", encoding="utf-8")

        report = {"summary": "Routine maintenance audit", "target": "target", "findings": []}
        self.schema_agent("threat-model", json.dumps(report))
        res = self.box.run_agent("threat-model")
        self.assertEqual(res["report"]["summary"], "Routine maintenance audit")
        self.assertEqual(store_tm.read_text(encoding="utf-8"), "# Prior Established Threat Model\nStrict Invariants...")

    @unittest.skipUnless(_RUNNABLE_BWRAP, _NEEDS_BWRAP)
    def test_bootstrap_without_threat_model_synthesizes_initial_document(self):
        """agents-tawg: when bootstrapping a target without THREAT_MODEL.md,
        factory synthesizes a provisional 7-section document from summary and findings."""
        target_dir = self.box.target
        for cand in [target_dir / "THREAT_MODEL.md", target_dir / "docs" / "THREAT_MODEL.md",
                     self.box.root / "findings" / "target-THREAT_MODEL.md"]:
            if cand.exists():
                cand.unlink()
        findings = [{
            "rule_id": "tm-open-socket",
            "path": "server.py",
            "line_number": 10,
            "snippet": "listen(0.0.0.0)",
            "severity": "high",
            "title": "Unauthenticated external listener",
            "description": "Listens on all interfaces without authentication",
            "remediation": "Bind to loopback"
        }]
        report = {"summary": "Initial audit of server architecture", "target": "target", "findings": findings}
        self.schema_agent("threat-model", json.dumps(report))
        res = self.box.run_agent("threat-model")
        store_tm = self.box.root / "findings" / "target-THREAT_MODEL.md"
        self.assertTrue(store_tm.exists())
        content = store_tm.read_text(encoding="utf-8")
        self.assertIn("# THREAT MODEL: target (Provisional Bootstrap Baseline)", content)
        self.assertIn("## 1. System Overview & Architecture", content)
        self.assertIn("## 2. Trust Boundaries & Actors", content)
        self.assertIn("## 3. Explicitly Trusted (Non-Threats)", content)
        self.assertIn("## 4. Untrusted Attack Surfaces", content)
        self.assertIn("## 5. Bug-Shape Hints from History", content)
        self.assertIn("## 6. Security Invariants for Auditors", content)
        self.assertIn("## 7. Explicit Exclusions (Wontfix / Accepted Risks)", content)
        self.assertIn("Initial audit of server architecture", content)
        self.assertIn("Unauthenticated external listener", content)

    @unittest.skipUnless(_RUNNABLE_BWRAP, _NEEDS_BWRAP)
    def test_the_prompt_carries_the_declared_schema(self):
        self.schema_agent("threat-model", tm_output([]))
        res = self.box.run_agent("threat-model")
        prompt = (res["run_dir"] / "prompt.txt").read_text()
        self.assertIn('"rule_id"', prompt)
        self.assertIn("MUST be one JSON object", prompt)


@unittest.skipUnless(_RUNNABLE_BWRAP, _NEEDS_BWRAP)
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
        # agents-noo: a schema-violating (no-verdict) station now degrades-and-continues, so it no
        # longer halts. Drive the halt with a GENUINE engine failure (exit non-zero -> StationError)
        # so the downstream stations are still SKIPPED and named in the halt message.
        self.schema_agent("threat-model", tm_output([{"severity": "high"}]))
        (self.box.bin / "pi").write_text("#!/usr/bin/env bash\ncat >/dev/null\necho '{\"findings\": []}'\nexit 1\n")
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
