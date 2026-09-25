#!/usr/bin/env python3
"""The output contract is enforced (agents-1r5, SF-07).

Every agent ships report.schema.json and names it in agent.yaml; before this fix nothing
loaded it, so model output flowed from a lenient JSON extraction straight into the
findings store. These tests pin three things: the stdlib validator honours the schema
subset the agents actually use, every shipped schema stays inside that subset, and the
dispatcher treats a schema-violating report exactly like unparseable output — the store
never sees it.
"""

import importlib.machinery
import importlib.util
import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

FACTORY_ROOT = Path(__file__).resolve().parent.parent
import sys
sys.path.insert(0, str(FACTORY_ROOT))

from lib.report_schema import declared_schema, validate, validate_agent_report  # noqa: E402

_loader = importlib.machinery.SourceFileLoader("factory_cli", str(FACTORY_ROOT / "factory"))
_spec = importlib.util.spec_from_loader("factory_cli", _loader)
factory_cli = importlib.util.module_from_spec(_spec)
_loader.exec_module(factory_cli)


class TestValidate(unittest.TestCase):
    def test_conformant_report_passes(self):
        schema = {
            "type": "object",
            "required": ["findings"],
            "properties": {
                "summary": {"type": "string"},
                "findings": {"type": "array", "items": {"type": "object",
                                                        "required": ["severity"],
                                                        "properties": {
                                                            "severity": {"enum": ["high", "low"]}}}},
            },
        }
        report = {"summary": "s", "findings": [{"severity": "high"}]}
        self.assertEqual(validate(report, schema), [])

    def test_missing_required_property_is_reported(self):
        errors = validate({"findings": []}, {"type": "object", "required": ["summary"]})
        self.assertEqual(len(errors), 1)
        self.assertIn("summary", errors[0])

    def test_wrong_type_is_reported_once(self):
        # A list where the object belongs: one violation, no cascade of deeper noise.
        errors = validate([1, 2], {"type": "object", "required": ["findings"]})
        self.assertEqual(len(errors), 1)
        self.assertIn("expected type", errors[0])

    def test_boolean_is_not_an_integer(self):
        # Python says isinstance(True, int); JSON Schema disagrees.
        self.assertEqual(validate(1, {"type": "integer"}), [])
        self.assertNotEqual(validate(True, {"type": "integer"}), [])

    def test_enum_violation_is_reported(self):
        errors = validate("urgent", {"enum": ["critical", "high", "medium", "low", "info"]})
        self.assertEqual(len(errors), 1)

    def test_array_items_are_checked_individually(self):
        schema = {"type": "array", "items": {"type": "object", "required": ["rule_id"]}}
        errors = validate([{"rule_id": "a"}, {"path": "b"}], schema)
        self.assertEqual(len(errors), 1)
        self.assertIn("$[1]", errors[0])

    def test_minimum_maximum(self):
        self.assertEqual(validate(0.5, {"type": "number", "minimum": 0, "maximum": 1}), [])
        self.assertEqual(len(validate(2, {"maximum": 1})), 1)

    def test_unknown_keywords_are_ignored(self):
        self.assertEqual(validate("anything", {"description": "d", "title": "t"}), [])


class TestDeclaredSchema(unittest.TestCase):
    def test_undeclared_schema_returns_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            self.assertIsNone(validate_agent_report(Path(tmpdir), {}, {"anything": True}))

    def test_declared_but_missing_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = {"output": {"schema": "report.schema.json"}}
            errors = validate_agent_report(Path(tmpdir), cfg, {"findings": []})
            self.assertIsNotNone(errors)
            self.assertTrue(any("does not exist" in e for e in errors))

    def test_unparseable_schema_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            agent_dir = Path(tmpdir)
            (agent_dir / "report.schema.json").write_text("{not json", encoding="utf-8")
            cfg = {"output": {"schema": "report.schema.json"}}
            errors = validate_agent_report(agent_dir, cfg, {"findings": []})
            self.assertIsNotNone(errors)
            self.assertTrue(any("not valid JSON" in e for e in errors))

    def test_real_agent_schema_loads(self):
        agent_dir = FACTORY_ROOT / "agents" / "secret-scan"
        schema = declared_schema(agent_dir, {"output": {"schema": "report.schema.json"}})
        self.assertIn("findings", schema["required"])

    def test_all_shipped_schemas_stay_inside_the_supported_subset(self):
        """The validator covers type/required/properties/items/enum/minimum/maximum. A
        shipped schema using anything else would be enforced in part and trusted in full —
        the exact failure mode this module exists to remove."""
        supported = {"$schema", "title", "description", "type", "required",
                     "properties", "items", "enum", "minimum", "maximum"}
        for schema_path in sorted(FACTORY_ROOT.glob("agents/*/report.schema.json")):
            with self.subTest(schema=schema_path):
                def walk(node):
                    if not isinstance(node, dict):
                        return
                    for key, value in node.items():
                        self.assertIn(key, supported, f"{schema_path}: unsupported {key!r}")
                        if key == "properties":
                            # keys of a properties map are property names, not keywords
                            for subschema in value.values():
                                walk(subschema)
                        elif key == "items":
                            walk(value)
                        # enum/required hold literals, title/description strings: no schema nodes
                walk(json.loads(schema_path.read_text(encoding="utf-8")))


class TestDispatcherSchemaGate(unittest.TestCase):
    """A report that violates the declared schema is treated like unparseable output:
    placeholder report, no findings store update (the bead's prescribed handling)."""

    def _sandbox(self, sandbox: Path, report_payload: dict):
        (sandbox / "agents" / "probe" / "scripts").mkdir(parents=True)
        (sandbox / "agents" / "probe" / "agent.yaml").write_text(
            "name: probe\n"
            "class: observer\n"
            "containment: t0-readonly\n"
            "short_circuit_empty: false\n"
            "budget: {max_minutes: 1}\n"
            "output:\n"
            "  schema: report.schema.json\n",
            encoding="utf-8",
        )
        (sandbox / "agents" / "probe" / "report.schema.json").write_text(json.dumps({
            "type": "object",
            "required": ["summary", "findings"],
            "properties": {
                "summary": {"type": "string"},
                "scanned_files": {"type": "integer"},
                "findings": {"type": "array", "items": {
                    "type": "object",
                    "required": ["rule_id", "path", "snippet", "severity", "title", "description"],
                    "properties": {"severity": {"enum": ["critical", "high", "medium", "low", "info"]}},
                }},
            },
        }), encoding="utf-8")
        (sandbox / "agents" / "probe" / "scripts" / "prepass.py").write_text(
            "import json, sys\n"
            "args = sys.argv[1:]\n"
            "json.dump({'candidates': [{'rule_id': 'r', 'path': 'a.js', 'line_number': 1, 'snippet': 'x'}]},\n"
            "          open(args[args.index('--output') + 1], 'w'))\n",
            encoding="utf-8",
        )

        report_src = sandbox / "report-src.json"
        report_src.write_text(json.dumps(report_payload), encoding="utf-8")

        (sandbox / "lib" / "adapters").mkdir(parents=True)
        adapter = sandbox / "lib" / "adapters" / "pi.sh"
        shutil.copyfile(FACTORY_ROOT / "lib" / "adapters" / "pi.sh", adapter)
        adapter.chmod(adapter.stat().st_mode | stat.S_IEXEC)
        for module in ("findings.py", "redaction.py", "embargo.py"):
            shutil.copyfile(FACTORY_ROOT / "lib" / module, sandbox / "lib" / module)

        bindir = sandbox / "bin"
        bindir.mkdir()
        stub = bindir / "pi"
        stub.write_text("#!/usr/bin/env bash\n" + f"cat '{report_src}'\n", encoding="utf-8")
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        target = sandbox / "target"
        target.mkdir()
        return target

    def _run(self, sandbox: Path, target: Path):
        with mock.patch.object(factory_cli, "FACTORY_ROOT", sandbox), \
             mock.patch.dict(os.environ,
                             {"PATH": f"{sandbox / 'bin'}{os.pathsep}{os.environ.get('PATH', '')}"}):
            return factory_cli.run_agent("probe", str(target), engine_arg="pi")

    def test_schema_violation_skips_the_store(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = Path(tmpdir)
            # Missing required 'summary'; a finding with a severity outside the enum.
            target = self._sandbox(sandbox, {
                "findings": [{
                    "rule_id": "r", "path": "a.js", "line_number": 1, "snippet": "x",
                    "severity": "urgent", "title": "t", "description": "d",
                }],
            })

            self._run(sandbox, target)

            self.assertFalse((sandbox / "findings" / "target.json").exists(),
                             "the store must never see a schema-violating report")
            report = json.loads(next((sandbox / "runs").glob("*/report.json")).read_text())
            self.assertEqual(report["summary"], "Model output failed the declared report schema.")
            self.assertEqual(report["findings"], [])

    def test_conformant_report_reaches_the_store(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = Path(tmpdir)
            target = self._sandbox(sandbox, {
                "summary": "stub", "scanned_files": 1,
                "findings": [{
                    "rule_id": "r", "path": "a.js", "line_number": 1, "snippet": "x",
                    "severity": "low", "title": "t", "description": "d",
                }],
            })

            self._run(sandbox, target)

            store = json.loads((sandbox / "findings" / "target.json").read_text(encoding="utf-8"))
            record, = store["findings"].values()
            self.assertEqual(record["severity"], "low")


if __name__ == "__main__":
    unittest.main()
