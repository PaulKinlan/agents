#!/usr/bin/env python3
"""Pre-pass defects that made stations report unearned results.

- secret-scan's openai-key rule matched `sk-` mid-word (journal-aaj, fleet-ctu), and the
  scanner ran every rule over every line, overrunning its budget on large repos (fleet-wa8);
- qa-station read a store filename that never existed, so it always audited nothing, and it
  accepted a missing target (journal-wog);
- docs-drift spawned a full git history walk per missing path and rglob'd the tree per bare
  filename, overrunning its 5-minute budget (journal-idy).
"""

import importlib.machinery
import os
os.environ.setdefault("FACTORY_ALLOW_UNPINNED_TOOLS", "1")  # agents-7bj: tests use unpinned stub tools
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent


class TestQaStationAnatomyValidatesRequiredSections(unittest.TestCase):
    """agents-40jyn: the anatomy audit checked FILE EXISTENCE only, so an agent.yaml that
    parsed to a contract-violating shape (missing `triggers`/`blocking`, an invented `class`)
    or a SKILL.md without its discovery frontmatter passed a clean audit. The contract the
    fleet documents in AGENTS.md ("Required agent.yaml fields", SKILL.md frontmatter) is now
    validated section by section."""

    GOOD_YAML = (
        "name: sample\n"
        "class: observer\n"
        "plane: [local, ci]\n"
        "containment: t0-readonly\n"
        "triggers: [manual, schedule]\n"
        "blocking: false\n"
        "summary: s\n"
        "output:\n"
        "  schema: report.schema.json\n"
        "capabilities:\n"
        "  write: false\n"
    )
    GOOD_SKILL = (
        "---\n"
        "name: sample\n"
        "description: A portable triage agent.\n"
        "---\n\n"
        "# Sample\n\nBody.\n"
    )

    @classmethod
    def _qa_module(cls):
        script = ROOT / "agents" / "qa-station" / "scripts" / "audit_factory_quality.py"
        loader = importlib.machinery.SourceFileLoader("qa_audit_anatomy_40jyn", str(script))
        spec = importlib.util.spec_from_loader("qa_audit_anatomy_40jyn", loader)
        qa = importlib.util.module_from_spec(spec)
        loader.exec_module(qa)
        return qa

    def _audit(self, tmp, name="sample", yaml_text=GOOD_YAML, skill_text=GOOD_SKILL,
               schema_text="{}", extra_files=None):
        agent = Path(tmp) / name
        agent.mkdir(parents=True, exist_ok=True)
        (agent / "agent.yaml").write_text(yaml_text, encoding="utf-8")
        (agent / "SKILL.md").write_text(skill_text, encoding="utf-8")
        (agent / "report.schema.json").write_text(schema_text, encoding="utf-8")
        for rel, text in (extra_files or {}).items():
            target = agent / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        (agent / "scripts").mkdir(exist_ok=True)
        (agent / "scripts" / "prepass.py").write_text("x = 1\n", encoding="utf-8")
        qa = self._qa_module()
        with mock.patch.object(qa, "AGENTS_DIR", Path(tmp)):
            return qa.audit_agent_contracts()

    def test_compliant_agent_produces_no_contract_issues(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self._audit(tmp), [])

    def test_missing_required_yaml_fields_are_named_individually(self):
        with tempfile.TemporaryDirectory() as tmp:
            issues = self._audit(tmp, yaml_text=self.GOOD_YAML.replace(
                "triggers: [manual, schedule]\n", "").replace("blocking: false\n", ""))
        self.assertEqual([i["rule_id"] for i in issues],
                         ["qa-missing-agent-yaml-field", "qa-missing-agent-yaml-field"])
        self.assertIn("'triggers'", issues[0]["title"])
        self.assertIn("'blocking'", issues[1]["title"])

    def test_invented_class_value_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            issues = self._audit(tmp, yaml_text=self.GOOD_YAML.replace(
                "class: observer", "class: wizard"))
        self.assertEqual([i["rule_id"] for i in issues], ["qa-invalid-agent-yaml-value"])
        self.assertIn("'class'", issues[0]["title"])
        self.assertIn("observer", issues[0]["title"])

    def test_empty_plane_list_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            issues = self._audit(tmp, yaml_text=self.GOOD_YAML.replace(
                "plane: [local, ci]", "plane: []"))
        self.assertEqual([i["rule_id"] for i in issues], ["qa-invalid-agent-yaml-value"])
        self.assertIn("'plane'", issues[0]["title"])

    def test_non_boolean_blocking_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            issues = self._audit(tmp, yaml_text=self.GOOD_YAML.replace(
                "blocking: false", "blocking: sometimes"))
        self.assertEqual([i["rule_id"] for i in issues], ["qa-invalid-agent-yaml-value"])
        self.assertIn("'blocking'", issues[0]["title"])

    def test_unparseable_manifest_is_reported_not_clean(self):
        # yaml_mini fails closed on tabs; the audit must surface that rather than
        # silently treating the manifest as satisfied.
        with tempfile.TemporaryDirectory() as tmp:
            issues = self._audit(tmp, yaml_text=self.GOOD_YAML.replace(
                "capabilities:\n", "capabilities:\n\twrite: false\n"))
        self.assertEqual([i["rule_id"] for i in issues], ["qa-agent-yaml-unparseable"])

    def test_skill_without_frontmatter_sections_is_reported(self):
        body_only = "# Sample\n\nNo discovery header.\n"
        with tempfile.TemporaryDirectory() as tmp:
            issues = self._audit(tmp, skill_text=body_only)
        self.assertEqual([i["rule_id"] for i in issues], ["qa-missing-skill-frontmatter"])
        self.assertIn("name", issues[0]["title"])
        self.assertIn("description", issues[0]["title"])

    def test_skill_frontmatter_missing_description_is_reported(self):
        partial = ("---\nname: sample\n---\n\n# Sample\n")
        with tempfile.TemporaryDirectory() as tmp:
            issues = self._audit(tmp, skill_text=partial)
        self.assertEqual([i["rule_id"] for i in issues], ["qa-missing-skill-frontmatter"])
        self.assertIn("description", issues[0]["title"])
        self.assertNotIn("name, description", issues[0]["title"].split(": ")[-1])

    def test_unparseable_report_schema_is_reported_not_clean(self):
        # agents-ipvx9: the anatomy audit checked file EXISTENCE only, so a corrupt
        # report.schema.json passed a clean audit while the runtime loader
        # (lib/report_schema.declared_schema) fails closed on the same file.
        with tempfile.TemporaryDirectory() as tmp:
            issues = self._audit(tmp, schema_text="{ not json")
        self.assertEqual([i["rule_id"] for i in issues], ["qa-report-schema-unparseable"])
        self.assertIn("Does Not Parse", issues[0]["title"])
        self.assertIn("report.schema.json", issues[0]["path"])

    def test_non_object_report_schema_is_reported_not_clean(self):
        # Same rule as the runtime contract: a schema that parses but is not a JSON
        # object is exactly what declared_schema raises ValueError for.
        with tempfile.TemporaryDirectory() as tmp:
            issues = self._audit(tmp, schema_text="[1, 2]")
        self.assertEqual([i["rule_id"] for i in issues], ["qa-report-schema-unparseable"])
        self.assertIn("Not A JSON Object", issues[0]["title"])

    def test_corrupt_declared_schema_is_reported_not_clean(self):
        # agents-43mqf, the review finding's constructed case: the manifest declares
        # output.schema out.schema.json and THAT file is corrupt, while the literal
        # report.schema.json is fine. The old audit parsed only report.schema.json and
        # stayed clean; the runtime fails closed on the declared file.
        with tempfile.TemporaryDirectory() as tmp:
            issues = self._audit(
                tmp,
                yaml_text=self.GOOD_YAML.replace(
                    "  schema: report.schema.json\n", "  schema: out.schema.json\n"),
                extra_files={"out.schema.json": "{ not json"},
            )
        self.assertEqual([i["rule_id"] for i in issues], ["qa-report-schema-unparseable"])
        self.assertIn("out.schema.json", issues[0]["path"])
        self.assertIn("Does Not Parse", issues[0]["title"])

    def test_undeclared_output_schema_is_reported(self):
        # agents-43mqf: declared_schema returns None for an agent.yaml with no output
        # block, and validate_agent_report then checks nothing - silently. The audit
        # must name that hole, and still parse-check the conventional file (a legacy
        # corrupt report.schema.json must not be waved through either).
        without_output = self.GOOD_YAML.replace("output:\n", "").replace(
            "  schema: report.schema.json\n", "")
        with tempfile.TemporaryDirectory() as tmp:
            issues = self._audit(tmp, yaml_text=without_output)
        self.assertEqual([i["rule_id"] for i in issues], ["qa-undeclared-output-schema"])
        with tempfile.TemporaryDirectory() as tmp:
            issues = self._audit(tmp, yaml_text=without_output, schema_text="{ not json")
        self.assertEqual([i["rule_id"] for i in issues],
                         ["qa-undeclared-output-schema", "qa-report-schema-unparseable"])

    def test_non_string_output_schema_is_reported_as_undeclared(self):
        # A list or mapping under output.schema is not a filename; the loader treats it
        # exactly like an undeclared schema, so the audit says so rather than guessing.
        with tempfile.TemporaryDirectory() as tmp:
            issues = self._audit(tmp, yaml_text=self.GOOD_YAML.replace(
                "  schema: report.schema.json\n", "  schema: [report.schema.json]\n"))
        self.assertEqual([i["rule_id"] for i in issues], ["qa-undeclared-output-schema"])

    def test_missing_declared_schema_is_reported(self):
        # agents-43mqf: declared_schema raises FileNotFoundError for a declared file that
        # does not exist; the audit mirrors that instead of parsing whatever else is there.
        # The conventional report.schema.json also being absent fires the required-file rule
        # exactly once - one finding per defect.
        with tempfile.TemporaryDirectory() as tmp:
            issues = self._audit(
                tmp,
                yaml_text=self.GOOD_YAML.replace(
                    "  schema: report.schema.json\n", "  schema: out.schema.json\n"),
            )
        self.assertEqual([i["rule_id"] for i in issues], ["qa-declared-schema-missing"])
        self.assertIn("out.schema.json", issues[0]["path"])
        self.assertIn("Does Not Exist", issues[0]["title"])

    def test_real_fleet_satisfies_agent_contracts(self):
        """Every shipped agent satisfies the QA manifest and skill contract.
        A new violation must be fixed at its agent rather than accepted here."""
        qa = self._qa_module()
        self.assertEqual(qa.audit_agent_contracts(), [])


class TestQaStationSchemaAndThresholdContract(unittest.TestCase):
    """agents-ipvx9: the scorecard audit also drifted from the documented contract -
    the noise rule fired at `> 0.30` in code while agents/qa-station/SKILL.md has
    always required a tuning recommendation at `wontfix_rate > 0.25`. These tests pin
    the code constant to the SKILL.md line and the strict-> boundary behaviour.
    """

    @classmethod
    def _qa_module(cls):
        script = ROOT / "agents" / "qa-station" / "scripts" / "audit_factory_quality.py"
        loader = importlib.machinery.SourceFileLoader("qa_audit_ipvx9", str(script))
        spec = importlib.util.spec_from_loader("qa_audit_ipvx9", loader)
        qa = importlib.util.module_from_spec(spec)
        loader.exec_module(qa)
        return qa

    def _scorecard(self, qa, tmp, wontfix_count, total):
        findings_dir = Path(tmp)
        records = {}
        for i in range(total):
            records[f"f{i}"] = {
                "agent": "lint",
                "state": "wontfix" if i < wontfix_count else "new",
                "remediation": "r",
            }
        (findings_dir / "store.json").write_text(
            json.dumps({"target": "t", "findings": records}), encoding="utf-8")
        with mock.patch.object(qa, "FINDINGS_DIR", findings_dir):
            return qa.audit_findings_precision()

    def _wontfix_candidates(self, data):
        return [c for c in data["noisy_candidates"]
                if c["rule_id"] == "qa-agent-high-wontfix-noise"]

    def test_threshold_drift_guard(self):
        """The SKILL.md contract states the wontfix noise line exactly once and the
        code constant equals it. Either side edited alone fails here, which is the
        drift agents-ipvx9 measured (0.30 in code vs 0.25 in SKILL.md).
        """
        qa = self._qa_module()
        skill = (ROOT / "agents" / "qa-station" / "SKILL.md").read_text(encoding="utf-8")
        documented = re.findall(r"wontfix_rate > (0?\.\d+)", skill)
        self.assertEqual(len(documented), 1,
                         "SKILL.md must state the wontfix noise threshold exactly once")
        self.assertEqual(float(documented[0]), qa.WONTFIX_NOISE_RATE,
                         "code WONTFIX_NOISE_RATE and the SKILL.md contract drifted")

    def test_rate_between_old_and_new_threshold_now_fires(self):
        # 3/11 = 0.273: below the old 0.30 line, above SKILL.md's 0.25. This is the
        # discriminating case - the agent the documented contract acted on but the
        # scanner never surfaced.
        qa = self._qa_module()
        with tempfile.TemporaryDirectory() as tmp:
            data = self._scorecard(qa, tmp, wontfix_count=3, total=11)
        candidates = self._wontfix_candidates(data)
        self.assertEqual(len(candidates), 1)
        self.assertIn("25% Wontfix Threshold", candidates[0]["title"])

    def test_rate_exactly_at_threshold_does_not_fire(self):
        # Strictly greater-than: 3/12 = 0.250 sits ON the SKILL.md line, not over it.
        qa = self._qa_module()
        with tempfile.TemporaryDirectory() as tmp:
            data = self._scorecard(qa, tmp, wontfix_count=3, total=12)
        self.assertEqual(self._wontfix_candidates(data), [])

    def test_real_fleet_report_schemas_parse_as_objects(self):
        """Calibration (agents-40jyn shape): the new schema check adds no violations
        on the fleet as it stands; a new violation must fix its agent or extend this
        pin consciously."""
        qa = self._qa_module()
        issues = [i for i in qa.audit_agent_contracts()
                  if i["rule_id"] == "qa-report-schema-unparseable"]
        self.assertEqual(issues, [])


class TestPrepassFixes(unittest.TestCase):
    def test_openai_rule_does_not_match_mid_word(self):
        sys.path.insert(0, str(ROOT / "agents" / "secret-scan" / "scripts"))
        import scan  # noqa: E402
        rule = dict(scan.PATTERNS)["openai-key"]
        self.assertIsNone(rule.search("#disk-quota-for-buffered-reports-storage-dos"))
        self.assertIsNone(rule.search("fillmask-release-lifecycle.test"))
        self.assertIsNone(rule.search("/ask-the-model-for-everything-now"))
        self.assertIsNotNone(rule.search('key = "sk-proj-abcdefghijklmnop1234"'))
        self.assertTrue(scan.ANY_PATTERN.search('token = "AbCdEfGhIjKlMnOpQrStUvWxYz"'))

    def test_qa_station_reads_the_real_store_and_refuses_a_missing_target(self):
        script = ROOT / "agents" / "qa-station" / "scripts" / "audit_factory_quality.py"
        res = subprocess.run([sys.executable, str(script), "--target", "/nonexistent/agents"],
                             capture_output=True, text=True, timeout=60)
        self.assertNotEqual(res.returncode, 0)
        with tempfile.TemporaryDirectory() as tmp:
            findings_dir = Path(tmp)
            (findings_dir / "proj.json").write_text(json.dumps({"target": "proj", "findings": {
                "f1": {"agent": "lint", "state": "wontfix", "remediation": "x"},
                "f2": {"agent": "lint", "state": "new"}}}), encoding="utf-8")
            loader = importlib.machinery.SourceFileLoader("qa_audit", str(script))
            spec = importlib.util.spec_from_loader("qa_audit", loader)
            qa = importlib.util.module_from_spec(spec)
            loader.exec_module(qa)
            with mock.patch.object(qa, "FINDINGS_DIR", findings_dir):
                data = qa.audit_findings_precision()
            self.assertEqual(data["stores_read"], ["proj.json"])
            card = data["agent_scorecards"][0]
            self.assertEqual((card["total_findings"], card["wontfix"]), (2, 1))
            with mock.patch.object(qa, "FINDINGS_DIR", findings_dir / "empty"):
                data = qa.audit_findings_precision()
            self.assertEqual([c["rule_id"] for c in data["noisy_candidates"]], ["qa-no-findings-store"])

    def test_qa_station_rejects_invalid_raw_states_before_precision_math(self):
        script = ROOT / "agents" / "qa-station" / "scripts" / "audit_factory_quality.py"
        loader = importlib.machinery.SourceFileLoader("qa_audit_states", str(script))
        spec = importlib.util.spec_from_loader("qa_audit_states", loader)
        qa = importlib.util.module_from_spec(spec)
        loader.exec_module(qa)
        with tempfile.TemporaryDirectory() as tmp:
            findings_dir = Path(tmp)
            (findings_dir / "proj.json").write_text(json.dumps({"target": "proj", "findings": {
                "valid": {"agent": "lint", "state": "wontfix"},
                "legacy": {"agent": "lint", "status": "accepted"},
                "invalid": {"agent": "lint", "state": "WONTFIX"},
                "not-string": {"agent": "lint", "state": ["wontfix"]},
                "missing": {"agent": "lint"},
                "no-fallback": {"agent": "lint", "state": "bogus", "status": "new"},
            }}), encoding="utf-8")
            with mock.patch.object(qa, "FINDINGS_DIR", findings_dir):
                data = qa.audit_findings_precision()
            card, = data["agent_scorecards"]
            self.assertEqual((card["total_findings"], card["wontfix"], card["accepted"]), (2, 1, 1))
            self.assertEqual(card["wontfix_rate"], 0.5)
            invalid, = [c for c in data["noisy_candidates"]
                        if c["rule_id"] == "qa-invalid-findings-state"]
            self.assertEqual(invalid["path"], "findings/proj.json")
            self.assertIn("4 invalid lifecycle state(s)", invalid["title"])
            self.assertNotIn("bogus", json.dumps(invalid), "do not echo arbitrary store text")
            (findings_dir / "proj.json").write_text(json.dumps({"target": "proj", "findings": {
                "invalid": {"agent": "lint", "state": "bogus"}
            }}), encoding="utf-8")
            with mock.patch.object(qa, "FINDINGS_DIR", findings_dir):
                only_invalid = qa.audit_findings_precision()
            self.assertEqual(only_invalid["agent_scorecards"], [])
            self.assertEqual({c["rule_id"] for c in only_invalid["noisy_candidates"]},
                             {"qa-invalid-findings-state", "qa-no-findings-store"})

    def test_qa_station_discloses_unreadable_stores_without_losing_valid_scorecards(self):
        script = ROOT / "agents" / "qa-station" / "scripts" / "audit_factory_quality.py"
        loader = importlib.machinery.SourceFileLoader("qa_unreadable_store", str(script))
        spec = importlib.util.spec_from_loader("qa_unreadable_store", loader)
        qa = importlib.util.module_from_spec(spec)
        loader.exec_module(qa)
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / "broken.json").write_text('{"findings": {', encoding="utf-8")
            (directory / "wrong-shape.json").write_text('{"findings": []}', encoding="utf-8")
            (directory / "good-line.json").write_text(json.dumps({
                "line": "daily", "stations": [], "stats": {}, "complete": True,
            }), encoding="utf-8")
            (directory / "good-bundle-baseline.json").write_text(json.dumps({
                "target": "good", "recorded_at": "2026-01-01T00:00:00Z",
                "total_raw_bytes": 2000, "total_gzip_bytes": 900, "asset_count": 3,
                "largest_assets": [],
            }), encoding="utf-8")
            (directory / "good.json").write_text(json.dumps({"findings": {
                "valid": {"agent": "lint", "state": "accepted"},
            }}), encoding="utf-8")
            with mock.patch.object(qa, "FINDINGS_DIR", directory):
                data = qa.audit_findings_precision()
            self.assertEqual(data["stores_read"], ["good.json"])
            self.assertEqual(data["agent_scorecards"][0]["total_findings"], 1)
            unreadable = [c for c in data["noisy_candidates"]
                          if c["rule_id"] == "qa-unreadable-findings-store"]
            self.assertEqual({c["path"] for c in unreadable},
                             {"findings/broken.json", "findings/wrong-shape.json"})
            self.assertTrue(all(c["severity"] == "medium" for c in unreadable))

    def test_qa_station_identifies_sidecars_by_contract_not_suffix_alone(self):
        script = ROOT / "agents" / "qa-station" / "scripts" / "audit_factory_quality.py"
        loader = importlib.machinery.SourceFileLoader("qa_sidecar_shape", str(script))
        spec = importlib.util.spec_from_loader("qa_sidecar_shape", loader)
        qa = importlib.util.module_from_spec(spec)
        loader.exec_module(qa)
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for name in ("command-line.json", "my-bundle-baseline.json"):
                (directory / name).write_text(json.dumps({"target": name[:-5], "findings": {
                    "f": {"agent": "lint", "state": "accepted", "remediation": "fix"},
                }}), encoding="utf-8")
            (directory / "broken-line.json").write_text('{"findings": {', encoding="utf-8")
            with mock.patch.object(qa, "FINDINGS_DIR", directory):
                data = qa.audit_findings_precision()
            self.assertEqual(data["stores_read"], ["command-line.json", "my-bundle-baseline.json"])
            self.assertEqual(data["agent_scorecards"][0]["total_findings"], 2)
            self.assertEqual([(c["rule_id"], c["path"]) for c in data["noisy_candidates"]],
                             [("qa-unreadable-findings-store", "findings/broken-line.json")])

    def test_qa_station_quarantines_deep_json_without_aborting_valid_store(self):
        script = ROOT / "agents" / "qa-station" / "scripts" / "audit_factory_quality.py"
        loader = importlib.machinery.SourceFileLoader("qa_deep_store", str(script))
        spec = importlib.util.spec_from_loader("qa_deep_store", loader)
        qa = importlib.util.module_from_spec(spec)
        loader.exec_module(qa)
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            depth = sys.getrecursionlimit() + 50
            (directory / "deep.json").write_text("[" * depth + "0" + "]" * depth,
                                                 encoding="utf-8")
            (directory / "good.json").write_text(json.dumps({"findings": {
                "valid": {"agent": "lint", "state": "accepted"},
            }}), encoding="utf-8")
            with mock.patch.object(qa, "FINDINGS_DIR", directory):
                data = qa.audit_findings_precision()
            self.assertEqual(data["stores_read"], ["good.json"])
            self.assertEqual(data["agent_scorecards"][0]["total_findings"], 1)
            unreadable, = [c for c in data["noisy_candidates"]
                           if c["rule_id"] == "qa-unreadable-findings-store"]
            self.assertEqual(unreadable["path"], "findings/deep.json")

    def test_qa_station_quarantines_non_string_agents_and_keeps_other_rows(self):
        script = ROOT / "agents" / "qa-station" / "scripts" / "audit_factory_quality.py"
        loader = importlib.machinery.SourceFileLoader("qa_invalid_agent", str(script))
        spec = importlib.util.spec_from_loader("qa_invalid_agent", loader)
        qa = importlib.util.module_from_spec(spec)
        loader.exec_module(qa)
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / "store.json").write_text(json.dumps({"findings": {
                "valid": {"agent": "lint", "state": "wontfix"},
                "regressed": {"agent": "lint", "state": "regressed"},
                "list": {"agent": ["lint"], "state": "new"},
                "dict": {"agent": {"name": "lint"}, "state": "accepted"},
                "blank": {"agent": "", "state": "fixed"},
                "traversal": {"agent": "../../etc/passwd\\nX", "state": "wontfix"},
                "overlong": {"agent": "x" * 65, "state": "new"},
            }}), encoding="utf-8")
            with mock.patch.object(qa, "FINDINGS_DIR", directory):
                data = qa.audit_findings_precision()
            card, = data["agent_scorecards"]
            self.assertEqual((card["agent"], card["total_findings"], card["wontfix"], card["regressed"]),
                             ("lint", 2, 1, 1))
            invalid, = [c for c in data["noisy_candidates"]
                        if c["rule_id"] == "qa-invalid-findings-agent"]
            self.assertEqual(invalid["path"], "findings/store.json")
            self.assertIn("5 invalid agent identifier(s)", invalid["title"])
            self.assertEqual(len(data["noisy_candidates"]), 1)
            self.assertNotIn("../", json.dumps(data["noisy_candidates"]))
            self.assertNotIn("passwd", json.dumps(data["agent_scorecards"]))

    def test_qa_station_reports_non_object_records_as_partial_evidence(self):
        script = ROOT / "agents" / "qa-station" / "scripts" / "audit_factory_quality.py"
        loader = importlib.machinery.SourceFileLoader("qa_bad_records", str(script))
        spec = importlib.util.spec_from_loader("qa_bad_records", loader)
        qa = importlib.util.module_from_spec(spec)
        loader.exec_module(qa)
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / "records.json").write_text(json.dumps({"findings": {
                "valid": {"agent": "lint", "state": "wontfix"},
                "scalar": "fixed", "list": ["lint", "fixed"], "null": None,
            }}), encoding="utf-8")
            with mock.patch.object(qa, "FINDINGS_DIR", directory):
                data = qa.audit_findings_precision()
            self.assertEqual(data["stores_read"], ["records.json"])
            self.assertEqual(data["agent_scorecards"][0]["total_findings"], 1)
            malformed, = [c for c in data["noisy_candidates"]
                          if c["rule_id"] == "qa-invalid-findings-record"]
            self.assertEqual(malformed["path"], "findings/records.json")
            self.assertIn("3 malformed record(s)", malformed["title"])

    def test_qa_station_does_not_treat_an_empty_lifecycle_file_as_measured_precision(self):
        """agents-2e8: a real station can create a valid but empty target.json; the QA
        pre-pass must still surface a measurement gap rather than report clean."""
        script = ROOT / "agents" / "qa-station" / "scripts" / "audit_factory_quality.py"
        loader = importlib.machinery.SourceFileLoader("qa_audit_empty_2e8", str(script))
        spec = importlib.util.spec_from_loader("qa_audit_empty_2e8", loader)
        qa = importlib.util.module_from_spec(spec)
        loader.exec_module(qa)
        with tempfile.TemporaryDirectory() as tmp:
            findings_dir = Path(tmp) / "findings"
            findings_dir.mkdir()
            (findings_dir / "target.json").write_text(
                json.dumps({"target": "target", "findings": {}}), encoding="utf-8")
            out = Path(tmp) / "qa-output.json"
            with mock.patch.object(qa, "FINDINGS_DIR", findings_dir), \
                 mock.patch.object(sys, "argv", ["qa", "--target", tmp, "--output", str(out)]):
                qa.main()
            result = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(result["stores_read"], ["target.json"])
            self.assertEqual(result["agent_scorecards"], [])
            self.assertEqual(result["context"]["agent_scorecards"], [])
            self.assertEqual(result["context"]["stores_read"], ["target.json"])
            self.assertEqual(result["context"]["fleet_size"], result["fleet_size"])
            self.assertEqual(result["context"]["fleet_agents"], result["fleet_agents"])
            gaps = [c for c in result["candidates"] if c["rule_id"] == "qa-no-findings-store"]
            self.assertEqual(len(gaps), 1)
            self.assertIn("No findings lifecycle records", gaps[0]["title"])

    def test_qa_station_derives_missing_remediation_in_the_scorecard(self):
        """agents-e3jru: missing_remediation was counted but never derived - no rate on the scorecard
        and no candidate rule, so an agent whose findings systematically lack remediation never
        surfaced the way a high wontfix rate does (agents-xoxum declares it on the schema)."""
        script = ROOT / "agents" / "qa-station" / "scripts" / "audit_factory_quality.py"
        loader = importlib.machinery.SourceFileLoader("qa_audit_e3jru", str(script))
        spec = importlib.util.spec_from_loader("qa_audit_e3jru", loader)
        qa = importlib.util.module_from_spec(spec)
        loader.exec_module(qa)
        with tempfile.TemporaryDirectory() as tmp:
            findings_dir = Path(tmp)
            records = {f"f{i}": {"agent": "lint", "state": "new",
                                 **({"remediation": "r"} if i < 1 else {})}
                       for i in range(4)}       # 3 of 4 findings carry no remediation
            (findings_dir / "proj.json").write_text(
                json.dumps({"target": "proj", "findings": records}), encoding="utf-8")
            with mock.patch.object(qa, "FINDINGS_DIR", findings_dir):
                data = qa.audit_findings_precision()
            card, = data["agent_scorecards"]
            self.assertEqual(card["missing_remediation"], 3)
            self.assertEqual(card["missing_remediation_rate"], 0.75)
            gaps = [c for c in data["noisy_candidates"] if c["rule_id"] == "qa-agent-remediation-gap"]
            self.assertEqual(len(gaps), 1, data["noisy_candidates"])
            self.assertEqual(gaps[0]["agent"], "lint")
            self.assertEqual(gaps[0]["severity"], "medium")
            self.assertIn("live findings", gaps[0]["title"],
                          "the candidate says what population it measured")

    def test_qa_station_remediation_gap_measures_live_work_only(self):
        """agents-21lfh: dismissals (false_positive rows) and suppressions (wontfix, a human-written
        state) have no next step by design, so a store of correct rejections must not read as a
        remediation contract gap. Only live work (new/accepted/regressed, not dismissed) counts."""
        script = ROOT / "agents" / "qa-station" / "scripts" / "audit_factory_quality.py"
        loader = importlib.machinery.SourceFileLoader("qa_audit_21lfh", str(script))
        spec = importlib.util.spec_from_loader("qa_audit_21lfh", loader)
        qa = importlib.util.module_from_spec(spec)
        loader.exec_module(qa)
        with tempfile.TemporaryDirectory() as tmp:
            findings_dir = Path(tmp)
            (findings_dir / "dismissals.json").write_text(json.dumps({"target": "t", "findings": {
                f"d{i}": {"agent": "triage", "state": "new", "false_positive": True,
                          "description": "rejected: not reproducible"} for i in range(4)}}),
                encoding="utf-8")
            with mock.patch.object(qa, "FINDINGS_DIR", findings_dir):
                data = qa.audit_findings_precision()
            card, = data["agent_scorecards"]
            # The RAW counter stays state- and polarity-blind by contract (agents-xoxum)...
            self.assertEqual(card["missing_remediation"], 4)
            # ...but the DERIVED rate reads live work, of which there is none here.
            self.assertEqual((card["missing_remediation_rate"],
                              [c for c in data["noisy_candidates"]
                               if c["rule_id"] == "qa-agent-remediation-gap"]), (0.0, []))
            (findings_dir / "dismissals.json").unlink()
            (findings_dir / "suppressions.json").write_text(json.dumps({"target": "t", "findings": {
                f"w{i}": {"agent": "triage", "state": "wontfix"} for i in range(4)}}),
                encoding="utf-8")
            with mock.patch.object(qa, "FINDINGS_DIR", findings_dir):
                data = qa.audit_findings_precision()
            card, = data["agent_scorecards"]
            self.assertEqual((card["missing_remediation_rate"],
                              [c for c in data["noisy_candidates"]
                               if c["rule_id"] == "qa-agent-remediation-gap"]), (0.0, []),
                             "suppressed findings have no next step left to describe")
            # A mixed store: the rate divides by LIVE findings, not total.
            (findings_dir / "suppressions.json").unlink()
            (findings_dir / "mixed.json").write_text(json.dumps({"target": "t", "findings": {
                "live1": {"agent": "lint", "state": "new"},
                "live2": {"agent": "lint", "state": "new"},
                "live3": {"agent": "lint", "state": "accepted", "remediation": "r"},
                "gone": {"agent": "lint", "state": "fixed"}}}), encoding="utf-8")
            with mock.patch.object(qa, "FINDINGS_DIR", findings_dir):
                data = qa.audit_findings_precision()
            card, = data["agent_scorecards"]
            # The raw counter is state-blind by contract (agents-xoxum): live1, live2 AND the fixed
            # record lack remediation text. The rate divides by the 3 LIVE findings only.
            self.assertEqual((card["missing_remediation"], card["missing_remediation_rate"]), (3, 0.667))
            gaps = [c for c in data["noisy_candidates"] if c["rule_id"] == "qa-agent-remediation-gap"]
            self.assertEqual(len(gaps), 1,
                             "2 of 3 live findings is 66.7% - over the line, and 3 live findings meets the floor")
            self.assertIn("2 of 3 live findings", gaps[0]["title"])

    def test_qa_station_remediation_gap_stays_quiet_below_the_threshold(self):
        # Same 30%/>=3 shape as the wontfix rule: remediated stores must not raise the candidate,
        # and a store too small to judge (2 findings) must not either.
        script = ROOT / "agents" / "qa-station" / "scripts" / "audit_factory_quality.py"
        loader = importlib.machinery.SourceFileLoader("qa_audit_e3jru_quiet", str(script))
        spec = importlib.util.spec_from_loader("qa_audit_e3jru_quiet", loader)
        qa = importlib.util.module_from_spec(spec)
        loader.exec_module(qa)
        with tempfile.TemporaryDirectory() as tmp:
            findings_dir = Path(tmp)
            (findings_dir / "all-remediated.json").write_text(json.dumps({"target": "t", "findings": {
                f"f{i}": {"agent": "lint", "state": "new", "remediation": "r"} for i in range(4)}}),
                encoding="utf-8")
            with mock.patch.object(qa, "FINDINGS_DIR", findings_dir):
                data = qa.audit_findings_precision()
            card, = data["agent_scorecards"]
            self.assertEqual((card["missing_remediation"], card["missing_remediation_rate"]), (0, 0.0))
            self.assertEqual([c for c in data["noisy_candidates"] if c["rule_id"] == "qa-agent-remediation-gap"], [])
            (findings_dir / "all-remediated.json").unlink()
            (findings_dir / "too-small.json").write_text(json.dumps({"target": "t", "findings": {
                "f0": {"agent": "lint", "state": "new"},
                "f1": {"agent": "lint", "state": "new"}}}), encoding="utf-8")
            with mock.patch.object(qa, "FINDINGS_DIR", findings_dir):
                data = qa.audit_findings_precision()
            self.assertEqual([c for c in data["noisy_candidates"] if c["rule_id"] == "qa-agent-remediation-gap"], [],
                             "2 findings is below the >=3 floor")
            self.assertEqual([c for c in data["noisy_candidates"] if c["rule_id"] == "qa-agent-high-wontfix-noise"], [])

    def test_docs_drift_git_index_sees_deleted_files(self):
        sys.path.insert(0, str(ROOT / "agents" / "docs-drift" / "scripts"))
        import check_docs  # noqa: E402
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            git = ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t"]
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            (repo / "src").mkdir()
            (repo / "src" / "keep.py").write_text("x")
            (repo / "src" / "gone.py").write_text("x")
            subprocess.run(git + ["add", "."], check=True)
            subprocess.run(git + ["commit", "-qm", "a"], check=True)
            subprocess.run(git + ["rm", "-q", "src/gone.py"], check=True)
            subprocess.run(git + ["commit", "-qm", "b"], check=True)
            self.assertEqual(check_docs.git_tracked_or_deleted(repo, "src/keep.py"), (True, True))
            self.assertEqual(check_docs.git_tracked_or_deleted(repo, "./src/gone.py"), (False, True))
            self.assertEqual(check_docs.git_tracked_or_deleted(repo, "src"), (True, True))
            self.assertEqual(check_docs.git_tracked_or_deleted(repo, "nope.py"), (False, False))
            self.assertEqual(check_docs.path_exists_or_matches(repo, repo, "keep.py"), (True, False))

    def test_product_css_has_focus_visible_states(self):
        """[agents-1oc] docs/css/product.css defines :focus-visible states for key interactive controls."""
        product_css = ROOT / "docs" / "css" / "product.css"
        self.assertTrue(product_css.exists())
        content = product_css.read_text(encoding="utf-8")
        self.assertIn(".breadcrumb a:focus-visible", content)
        self.assertIn(".btn:focus-visible", content)
        self.assertIn(".btn-primary:focus-visible", content)
        self.assertIn(".btn-secondary:focus-visible", content)

        # ui-ux scanner pre-pass produces 0 candidates
        script = ROOT / "agents" / "ui-ux-audit" / "scripts" / "scan_ui_ux.py"
        res = subprocess.run([sys.executable, str(script), "--target", str(product_css.parent)],
                             capture_output=True, text=True, check=True)
        data = json.loads(res.stdout)
        focus_candidates = [c for c in data["candidates"] if c["rule_id"] == "missing-focus-visible-state"]
        self.assertEqual(len(focus_candidates), 0, f"Expected 0 missing-focus-visible-state candidates, got: {focus_candidates}")

    def test_product_css_has_prefers_reduced_motion_override(self):
        """[agents-cvm] docs/css/product.css overrides hover transforms/transitions under prefers-reduced-motion."""
        product_css = ROOT / "docs" / "css" / "product.css"
        self.assertTrue(product_css.exists())
        content = product_css.read_text(encoding="utf-8")
        self.assertIn("@media (prefers-reduced-motion: reduce)", content)
        start = content.find("@media (prefers-reduced-motion: reduce)")
        open_brace = content.find("{", start)
        depth = 1
        pos = open_brace + 1
        while pos < len(content) and depth > 0:
            if content[pos] == "{":
                depth += 1
            elif content[pos] == "}":
                depth -= 1
            pos += 1
        block = content[open_brace + 1:pos - 1]
        self.assertIn(".btn", block)
        self.assertIn("transition: none", block)
        self.assertIn("transform: none", block)

    def test_product_css_doc_card_has_no_hover_lift(self):
        """[agents-7nh] docs/css/product.css does not style non-interactive .doc-card with a link-like hover lift."""
        product_css = ROOT / "docs" / "css" / "product.css"
        self.assertTrue(product_css.exists())
        content = product_css.read_text(encoding="utf-8")
        self.assertNotIn(".doc-card:hover", content)

    def test_scan_ui_ux_font_size_units_and_unparsed_values(self):
        """[agents-9vq2] Small rem and px values must not scan green; unknown units stay visible."""
        script = ROOT / "agents" / "ui-ux-audit" / "scripts" / "scan_ui_ux.py"
        with tempfile.TemporaryDirectory() as tmp:
            css = Path(tmp) / "style.css"
            css.write_text(""".rem { font-size: 0.5rem; }
.px { font-size: 8px; }
.fractional { font-size: 11.5px; }
.pt { font-size: 8pt; }
.safe { font-size: 12px; }
.unknown { font-size: 0.6em; }
.dynamic { font-size: clamp(0.5rem, 2vw, 1rem); }
.computed { font-size: calc(1rem - 2px); }
.variable { font-size: var(--font-size); }
/* .comment { font-size: 1px; } */
:root { --font-size: 1px; }
""", encoding="utf-8")
            output = Path(tmp) / "result.json"
            subprocess.run([sys.executable, str(script), "--target", tmp, "--output", str(output)],
                           capture_output=True, text=True, check=True)
            data = json.loads(output.read_text(encoding="utf-8"))
            typography = [c for c in data["candidates"] if c["rule_id"] == "illegible-micro-typography"]
            self.assertEqual([c["line_number"] for c in typography], [1, 2, 3, 4])
            self.assertEqual(data["font_size_values_unparsed"], 4)
            summary = subprocess.run([sys.executable, str(script), "--target", tmp],
                                     capture_output=True, text=True, check=True)
            self.assertEqual(json.loads(summary.stdout)["font_size_values_unparsed"], 4)

            css.write_text(".only { font-size: clamp(0.5rem, 2vw, 1rem); }", encoding="utf-8")
            summary = subprocess.run([sys.executable, str(script), "--target", tmp],
                                     capture_output=True, text=True, check=True)
            unknown_only = json.loads(summary.stdout)
            self.assertEqual(unknown_only["candidates"], [])
            self.assertEqual(unknown_only["font_size_values_unparsed"], 1)

    def test_scan_ui_ux_considers_co_loaded_page_stylesheets_for_focus_visible(self):
        """[agents-p9u] scan_ui_ux does not emit false missing-focus-visible-state when a
        co-loaded stylesheet on the same HTML page defines :focus-visible (e.g. projects.css + product.css)."""
        script = ROOT / "agents" / "ui-ux-audit" / "scripts" / "scan_ui_ux.py"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            css_dir = tmp_path / "css"
            css_dir.mkdir()

            # Global stylesheet defines base :focus-visible ring
            (css_dir / "global.css").write_text("""
            a:focus-visible {
                outline: 2px solid var(--accent);
                outline-offset: 2px;
            }
            """, encoding="utf-8")

            # Component stylesheet defines :hover without its own :focus-visible
            (css_dir / "component.css").write_text("""
            .breadcrumb a:hover {
                text-decoration: underline;
            }
            .nav-link:hover {
                color: #fff;
            }
            """, encoding="utf-8")

            # HTML page links both stylesheets
            (tmp_path / "page.html").write_text("""
            <!doctype html>
            <html>
            <head>
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <link rel="stylesheet" href="/css/global.css">
                <link rel="stylesheet" href="/css/component.css">
            </head>
            <body>
                <nav class="breadcrumb"><a href="#">Home</a></nav>
            </body>
            </html>
            """, encoding="utf-8")

            # 1. Scanning page directory (target contains HTML + CSS)
            res = subprocess.run([sys.executable, str(script), "--target", tmp],
                                 capture_output=True, text=True, check=True)
            data = json.loads(res.stdout)
            focus_candidates = [c for c in data["candidates"] if c["rule_id"] == "missing-focus-visible-state"]
            self.assertEqual(len(focus_candidates), 0,
                             f"Expected 0 false missing-focus-visible-state candidates for co-loaded bundle, got: {focus_candidates}")

            # 2. Scanning CSS directory directly (target contains sibling stylesheets)
            res_css = subprocess.run([sys.executable, str(script), "--target", str(css_dir)],
                                     capture_output=True, text=True, check=True)
            data_css = json.loads(res_css.stdout)
            focus_candidates_css = [c for c in data_css["candidates"] if c["rule_id"] == "missing-focus-visible-state"]
            self.assertEqual(len(focus_candidates_css), 0,
                             f"Expected 0 false missing-focus-visible-state candidates for sibling bundle, got: {focus_candidates_css}")

    def test_scan_ui_ux_candidate_set_does_not_depend_on_the_parent_directory(self):
        """[agents-4655r] Measured: the verdict used to change when a page appeared OUTSIDE the target.

        The pre-pass globbed *.html in target_dir.parent whenever the target had no HTML of its own,
        and the mere existence of such a file flipped has_focus_visible_coverage from the
        target-local sibling fallback to "HTML pages exist, so do not assume unlinked siblings share
        coverage". A/B/C below are the same target with only the parent directory changing - and the
        third run is the same tree the factory's own sandbox sees, since the sandbox binds the target
        read-only and never the parent.
        """
        script = ROOT / "agents" / "ui-ux-audit" / "scripts" / "scan_ui_ux.py"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.mkdir()
            # Identical target content for all three runs; only the parent changes.
            (target / "style.css").write_text(".btn:hover { color: red; }\n", encoding="utf-8")
            (target / "sibling.css").write_text(
                ".g:focus-visible { outline: 2px solid blue; }\n", encoding="utf-8")
            (target / "other.css").write_text(
                ".u:focus-visible { outline: 1px solid red; }\n", encoding="utf-8")

            def focus_candidates():
                res = subprocess.run([sys.executable, str(script), "--target", str(target)],
                                     capture_output=True, text=True, check=True)
                return [(c["rule_id"], c["path"]) for c in json.loads(res.stdout)["candidates"]
                        if c["rule_id"] == "missing-focus-visible-state"]

            without_parent_page = focus_candidates()  # A
            page = root / "page.html"
            page.write_text('<html><head><link rel="stylesheet" href="target/other.css"></head></html>\n',
                            encoding="utf-8")
            with_parent_page = focus_candidates()  # B
            page.unlink()
            after_removing_it = focus_candidates()  # C

            # The target's own sibling stylesheet defines :focus-visible, so the target-local
            # fallback finds coverage and the run is clean - which is also what the sandbox sees.
            self.assertEqual(without_parent_page, [])
            self.assertEqual(after_removing_it, without_parent_page)
            self.assertEqual(
                with_parent_page, without_parent_page,
                "a page in the PARENT changed this target's candidate set: "
                f"A={without_parent_page} B={with_parent_page} C={after_removing_it}")

    def test_scan_ui_ux_still_uses_pages_inside_the_target_for_coverage(self):
        """Control for the test above, so removing the parent read cannot have disabled rule 3.

        With the page INSIDE the target and linked only to the stylesheet that lacks coverage, the
        page-derived rule must still fire: a page exists, and this stylesheet is not co-loaded with
        anything that defines :focus-visible.
        """
        script = ROOT / "agents" / "ui-ux-audit" / "scripts" / "scan_ui_ux.py"
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "site"
            target.mkdir()
            (target / "style.css").write_text(".btn:hover { color: red; }\n", encoding="utf-8")
            (target / "sibling.css").write_text(
                ".g:focus-visible { outline: 2px solid blue; }\n", encoding="utf-8")
            (target / "index.html").write_text(
                '<html><head><link rel="stylesheet" href="style.css"></head></html>\n', encoding="utf-8")

            res = subprocess.run([sys.executable, str(script), "--target", str(target)],
                                 capture_output=True, text=True, check=True)
            focus = [(c["rule_id"], c["path"]) for c in json.loads(res.stdout)["candidates"]
                     if c["rule_id"] == "missing-focus-visible-state"]

        self.assertEqual(focus, [("missing-focus-visible-state", "style.css")])

    def test_scan_ui_ux_flags_genuinely_missing_focus_visible_state(self):
        """[agents-p9u] scan_ui_ux emits missing-focus-visible-state when no stylesheet defines :focus-visible."""
        script = ROOT / "agents" / "ui-ux-audit" / "scripts" / "scan_ui_ux.py"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "bad.css").write_text("""
            .button:hover {
                background: red;
            }
            """, encoding="utf-8")

            res = subprocess.run([sys.executable, str(script), "--target", tmp],
                                 capture_output=True, text=True, check=True)
            data = json.loads(res.stdout)
            focus_candidates = [c for c in data["candidates"] if c["rule_id"] == "missing-focus-visible-state"]
            self.assertEqual(len(focus_candidates), 1)
            self.assertEqual(focus_candidates[0]["severity"], "high")
            self.assertEqual(focus_candidates[0]["path"], "bad.css")

    def test_scan_ui_ux_flags_sibling_stylesheet_not_co_loaded_with_baseline(self):
        """[agents-p9u review P1/P2] When HTML pages exist, a stylesheet loaded on a page without
        the baseline (or an unlinked orphan) must STILL be flagged even if a sibling defines :focus-visible."""
        script = ROOT / "agents" / "ui-ux-audit" / "scripts" / "scan_ui_ux.py"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            css_dir = tmp_path / "css"
            css_dir.mkdir()

            (css_dir / "base.css").write_text("a:focus-visible { outline: 2px solid green; }", encoding="utf-8")
            (css_dir / "widgetA.css").write_text(".widgetA:hover { color: red; }", encoding="utf-8")
            (css_dir / "widgetB.css").write_text(".widgetB:hover { color: blue; }", encoding="utf-8")
            (css_dir / "orphan.css").write_text(".orphan:hover { color: yellow; }", encoding="utf-8")

            # pageA co-loads base.css + widgetA.css
            (tmp_path / "pageA.html").write_text(
                '<link rel="stylesheet" href="/css/base.css">\n<link rel="stylesheet" href="/css/widgetA.css">',
                encoding="utf-8",
            )
            # pageB loads ONLY widgetB.css (baseline is NOT loaded here!)
            (tmp_path / "pageB.html").write_text(
                '<link rel="stylesheet" href="/css/widgetB.css">',
                encoding="utf-8",
            )

            res = subprocess.run([sys.executable, str(script), "--target", tmp],
                                 capture_output=True, text=True, check=True)
            data = json.loads(res.stdout)
            candidates = [c for c in data["candidates"] if c["rule_id"] == "missing-focus-visible-state"]
            flagged_paths = {c["path"] for c in candidates}

            # widgetA is covered by base.css on pageA -> MUST NOT be flagged
            self.assertNotIn("css/widgetA.css", flagged_paths)
            # widgetB is NOT covered on pageB -> MUST be flagged
            self.assertIn("css/widgetB.css", flagged_paths)
            # orphan is not loaded on any page -> MUST be flagged
            self.assertIn("css/orphan.css", flagged_paths)

    def test_scan_ui_ux_comment_mentioning_focus_visible_does_not_exempt(self):
        """[agents-p9u review P2] Comments mentioning :focus-visible must not act as a rule and exempt files."""
        script = ROOT / "agents" / "ui-ux-audit" / "scripts" / "scan_ui_ux.py"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "base.css").write_text("/* TODO: add :focus-visible rings */\n.btn { color: white; }", encoding="utf-8")
            (tmp_path / "component.css").write_text(".link:hover { color: red; }", encoding="utf-8")

            res = subprocess.run([sys.executable, str(script), "--target", tmp],
                                 capture_output=True, text=True, check=True)
            data = json.loads(res.stdout)
            candidates = [c for c in data["candidates"] if c["rule_id"] == "missing-focus-visible-state"]
            self.assertEqual(len(candidates), 1)
            self.assertEqual(candidates[0]["path"], "component.css")

    def test_scan_ui_ux_focus_not_focus_visible_does_not_exempt(self):
        """[agents-ifv] :focus:not(:focus-visible) reset pattern must not count as focus-visible coverage."""
        script = ROOT / "agents" / "ui-ux-audit" / "scripts" / "scan_ui_ux.py"
        test_reset_cases = [
            ":focus:not(:focus-visible) { outline: none; }\n.btn:hover { color: red; }",
            ":focus:not( :focus-visible) { outline: none; }\n.btn:hover { color: red; }",
            ":focus:not(  :focus-visible) { outline: none; }\n.btn:hover { color: red; }",
            ":focus:not(\n    :focus-visible) { outline: none; }\n.btn:hover { color: red; }",
            ":focus:NOT(:focus-visible) { outline: none; }\n.btn:hover { color: red; }",
            ":focus:not(\n  :FOCUS-VISIBLE\n) { outline: none; }\n.btn:hover { color: red; }",
            ":focus:not(:focus-visible, .kb-focus) { outline: none; }\n.btn:hover { color: red; }",
            ":focus:not(.kb-focus, :focus-visible) { outline: none; }\n.btn:hover { color: red; }",
            ":focus:NOT(:focus-visible, .kb-focus) { outline: none; }\n.btn:hover { color: red; }",
            '[class*=":focus-visible"] { color: red; }\n.btn:hover { color: red; }',
            "a:focus:not(:focus-visible) { outline: 0; }\n.link:hover { color: red; }",
        ]
        for snippet in test_reset_cases:
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                (tmp_path / "style.css").write_text(snippet, encoding="utf-8")
                res = subprocess.run([sys.executable, str(script), "--target", tmp],
                                     capture_output=True, text=True, check=True)
                data = json.loads(res.stdout)
                candidates = [c for c in data["candidates"] if c["rule_id"] == "missing-focus-visible-state"]
                self.assertEqual(len(candidates), 1, f"Snippet should not have counted as coverage: {snippet}")
                self.assertEqual(candidates[0]["path"], "style.css")

    def test_scan_ui_ux_supports_feature_query_does_not_exempt(self):
        """[agents-6l1qw] @supports selector(:focus-visible) is a feature query, not a focus ring.

        The matcher's boundary set accepts `)`, so the prelude of an @supports block satisfied it and
        a stylesheet that only ASKS whether :focus-visible is supported was exempted from the
        missing-focus-visible-state rule. MEASURED before the fix: the first snippet below produced
        no candidate, and the same file without the @supports line produced
        [(missing-focus-visible-state, style.css)].
        """
        script = ROOT / "agents" / "ui-ux-audit" / "scripts" / "scan_ui_ux.py"
        supports_cases = [
            "@supports selector(:focus-visible) {\n  .btn { color: red; }\n}\n.btn:hover { color: red; }",
            "@supports not selector(:focus-visible) {\n  .btn { color: red; }\n}\n.btn:hover { color: red; }",
            "@supports (selector(:focus-visible)) {\n  .btn { color: red; }\n}\n.btn:hover { color: red; }",
            "@supports NOT SELECTOR(:FOCUS-VISIBLE) {\n  .btn { color: red; }\n}\n.btn:hover { color: red; }",
            "@media (min-width: 40rem) {\n  @supports selector(:focus-visible) {\n    .btn { color: red; }\n  }\n}\n.btn:hover { color: red; }",
        ]
        for snippet in supports_cases:
            with self.subTest(snippet=snippet):
                with tempfile.TemporaryDirectory() as tmp:
                    (Path(tmp) / "style.css").write_text(snippet, encoding="utf-8")
                    res = subprocess.run([sys.executable, str(script), "--target", tmp],
                                         capture_output=True, text=True, check=True)
                    candidates = [c for c in json.loads(res.stdout)["candidates"]
                                  if c["rule_id"] == "missing-focus-visible-state"]
                self.assertEqual(
                    [(c["rule_id"], c["path"]) for c in candidates],
                    [("missing-focus-visible-state", "style.css")],
                    f"A feature query must not exempt the file: {snippet}")

    def test_scan_ui_ux_literal_supports_before_a_real_rule(self):
        """[agents-u96dl] A literal `@supports` in a string is not an at-rule prelude.

        Raised by rev-6l1qw against the first version of the @supports strip: `@supports[^{]*{`
        matched the literal inside `content: "@supports";` and consumed text up to the NEXT real
        rule's opening brace, deleting that rule's selector - so a file that DID define
        `.btn:focus-visible` was reported as missing it (base 0782039a emitted no candidate). The
        scanner now removes quoted strings, which cannot hold a selector, before the prelude strip.
        """
        script = ROOT / "agents" / "ui-ux-audit" / "scripts" / "scan_ui_ux.py"
        real_rule_after_literal = {
            "style.css": '.btn { content: "@supports"; }\n'
                         '.btn:focus-visible { outline: 2px solid; }\n.btn:hover { color: red; }\n',
            "style-quoted.css": ".btn::after { content: '@supports'; }\n"
                                ".btn:focus-visible { outline: 2px solid; }\n.btn:hover { color: red; }\n",
            "app.vue": '<template><button>x</button></template>\n'
                       '<script>const tag = "@supports";</script>\n<style>\n'
                       ".btn:focus-visible { outline: 2px solid; }\n.btn:hover { color: red; }\n"
                       '</style>\n',
            # What pins the quoted-string strip: no `;` between the literal and the real rule, so the
            # prelude regex would otherwise consume the rule's selector. Measured red before the strip.
            "no-semicolon.vue": '<template><button>x</button></template>\n'
                                '<script>const re = new RegExp("@supports (selector(:focus-visible))")'
                                '</script>\n<style>\n'
                                ".btn:focus-visible { outline: 2px solid; }\n.btn:hover { color: red; }\n"
                                '</style>\n',
            # What pins `[(\w]`: an HTML attribute literal, which is not a string as far as CSS is
            # concerned. Measured red without that constraint.
            "page.html": '<html><head></head><body><div data-x="@supports">hi</div><style>'
                         '.btn:focus-visible { outline: 2px solid; } .btn:hover { color: red; }'
                         '</style></body></html>\n',
            "unquoted.css": '[data-x=@supports] { color: red; }\n'
                            '.btn:focus-visible { outline: 2px solid; }\n.btn:hover { color: red; }\n',
            # What pins the two constraints ON THE PRELUDE PATTERN, now the string strip handles
            # quoted literals: a BARE mention (not in a string) directly in front of a real rule, so a
            # pattern that only stops at `{` would consume that rule's selector. MEASURED per
            # constraint: removing `[(\w]` fails bare-before-rule.css; removing the string strip
            # fails no-semicolon.vue; the `[^{};]` bound in the pattern is not pinned by any case here
            # and is documented as a bound, not as a fix.
            "bare-before-rule.css": "[data-y=@supports] .btn:focus-visible { outline: 2px solid; }\n"
                                    ".btn:hover { color: red; }\n",
            "bare-statement.vue": '<template><button>x</button></template>\n'
                                  '<script>const a = @supports;</script>\n<style>\n'
                                  ".btn:focus-visible { outline: 2px solid; }\n"
                                  ".btn:hover { color: red; }\n</style>\n",
        }
        for name, snippet in real_rule_after_literal.items():
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as tmp:
                    (Path(tmp) / name).write_text(snippet, encoding="utf-8")
                    res = subprocess.run([sys.executable, str(script), "--target", tmp],
                                         capture_output=True, text=True, check=True)
                    focus = [c for c in json.loads(res.stdout)["candidates"]
                             if c["rule_id"] == "missing-focus-visible-state"]
                self.assertEqual(
                    focus, [],
                    f"{name} does define a focus-visible rule; a quoted literal must not hide it")

        # Control: dropping the strings must not exempt the file either - with only a hover rule left,
        # the candidate returns.
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "style.css").write_text(
                '.btn { content: "@supports"; }\n.btn:hover { color: red; }\n', encoding="utf-8")
            res = subprocess.run([sys.executable, str(script), "--target", tmp],
                                 capture_output=True, text=True, check=True)
            focus = [(c["rule_id"], c["path"]) for c in json.loads(res.stdout)["candidates"]
                     if c["rule_id"] == "missing-focus-visible-state"]
        self.assertEqual(focus, [("missing-focus-visible-state", "style.css")])

    def test_scan_ui_ux_counts_a_real_rule_inside_a_supports_block(self):
        """Control for the test above: the @supports PRELUDE is removed, the payload is untouched."""
        script = ROOT / "agents" / "ui-ux-audit" / "scripts" / "scan_ui_ux.py"
        real_rules = [
            "@supports selector(:focus-visible) {\n  .btn:focus-visible { outline: 2px solid blue; }\n}\n.btn:hover { color: red; }",
            "@supports selector(:focus-visible) {\n  :is(a, button:focus-visible) { outline: 2px solid blue; }\n}\n.btn:hover { color: red; }",
        ]
        for snippet in real_rules:
            with self.subTest(snippet=snippet):
                with tempfile.TemporaryDirectory() as tmp:
                    (Path(tmp) / "style.css").write_text(snippet, encoding="utf-8")
                    res = subprocess.run([sys.executable, str(script), "--target", tmp],
                                         capture_output=True, text=True, check=True)
                    focus = [c for c in json.loads(res.stdout)["candidates"]
                             if c["rule_id"] == "missing-focus-visible-state"]
                self.assertEqual(focus, [], f"A real rule inside the block is coverage: {snippet}")

    def test_scan_ui_ux_recognizes_chained_and_combinator_focus_visible_selectors(self):
        """[agents-ifv / agents-vml] scan_ui_ux recognizes chained pseudo-classes, combinators, and pseudo-elements
        on :focus-visible selectors (.card:focus-visible:hover, .btn:focus-visible::after, :is(...))."""
        script = ROOT / "agents" / "ui-ux-audit" / "scripts" / "scan_ui_ux.py"
        chained_selectors = [
            ".card:focus-visible:hover { outline: 2px solid green; }",
            ".btn:focus-visible::after { content: ''; }",
            "input:focus-visible:not([disabled]) { outline: 2px solid green; }",
            ":is(.btn:focus-visible) { outline: 2px solid green; }",
            ".card:focus-visible > .icon { color: green; }",
            ".card:focus-visible .child { outline: 2px solid green; }",
            ".card:focus-visible[data-active] { outline: 2px solid green; }",
            ".card:focus-visible.active { outline: 2px solid green; }",
            ".card:focus-visible#hero { outline: 2px solid green; }",
            "a:FOCUS-VISIBLE { outline: 2px solid green; }",
            "a:Focus-Visible { outline: 2px solid green; }",
            ":focus:not(:focus-visible) { outline: none; }\n.btn:focus-visible { outline: 2px solid blue; }",
            ":focus:not(\n  :focus-visible\n) { outline: none; }\n.btn:focus-visible { outline: 2px solid blue; }",
            ":focus:not(:focus-visible, .kb) { outline: none; }\n.btn:focus-visible { outline: 2px solid blue; }",
            '.x::after { content: ":not("; }\n.btn:focus-visible { outline: 2px solid blue; }\n.card { color: rgb(0, 0, 0); }',
        ]

        for sel in chained_selectors:
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                (tmp_path / "style.css").write_text(f".btn:hover {{ color: red; }}\n{sel}", encoding="utf-8")
                res = subprocess.run([sys.executable, str(script), "--target", tmp],
                                     capture_output=True, text=True, check=True)
                data = json.loads(res.stdout)
                focus_candidates = [c for c in data["candidates"] if c["rule_id"] == "missing-focus-visible-state"]
                self.assertEqual(len(focus_candidates), 0,
                                 f"Failed to recognize valid focus selector {sel!r}: got {focus_candidates}")


if __name__ == "__main__":
    unittest.main()
