#!/usr/bin/env python3
"""The output contract is enforced (agents-1r5, SF-07).

Every agent ships report.schema.json and names it in agent.yaml; before this fix nothing
loaded it, so model output flowed from a lenient JSON extraction straight into the
findings store. These tests pin three things: the stdlib validator honours the schema
subset the agents actually use, every shipped schema stays inside that subset, and the
dispatcher treats a schema-violating report exactly like unparseable output — the store
never sees it.
"""

import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
os.environ.setdefault("FACTORY_ALLOW_UNPINNED_TOOLS", "1")  # agents-7bj: tests use unpinned stub tools
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

FACTORY_ROOT = Path(__file__).resolve().parent.parent
import sys
sys.path.insert(0, str(FACTORY_ROOT))

from lib.report_schema import (  # noqa: E402
    declared_schema,
    unlocatable_verdicts,
    validate,
    validate_agent_report,
)
from lib.sandbox import sandbox_available  # noqa: E402

# --- hermetic test environment (agents-21ap) -------------------------------------------------
# The pin machinery resolves tools through FACTORY_TOOL_PINS when the OPERATOR'S shell exports
# it (~/.fleet/local.conf does on this VM). Without this scrub the suite observed the host
# rather than the tree: a re-provision generated the host pins file at 02:19:46Z and these
# suites went red on EVERY tree, including landed main, with `trusted tool 'pi' resolved to
# /tmp/.../bin/pi, not the configured path /usr/local/bin/pi`. The tests were right; the
# environment was not hermetic. See tests/hermetic_env.py.
from tests import hermetic_env  # noqa: E402


def setUpModule():
    hermetic_env.isolate_operator_config()


def tearDownModule():
    hermetic_env.restore_operator_config()


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

    def test_max_length_min_length(self):
        self.assertEqual(validate("hello", {"type": "string", "maxLength": 5, "minLength": 1}), [])
        self.assertEqual(validate("", {"type": "string", "minLength": 1}), ["$: length 0 below minLength 1"])
        self.assertEqual(validate("toolong", {"type": "string", "maxLength": 5}), ["$: length 7 exceeds maxLength 5"])

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
                     "properties", "items", "enum", "minimum", "maximum",
                     "maxLength", "minLength"}
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


@unittest.skipUnless(sandbox_available(), "needs a host where bubblewrap actually runs")
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

        # agents-r2ne census: a FACTORY-runtime tree, not a station-script fixture - the copy set
        # is the factory dispatcher's own runtime (the shell adapter, the lib/sinks package
        # directory, budget.py and friends) plus a fixture-seeded prepass.py above, which
        # tests/sandbox_fixtures.py:copy_station_script deliberately does not derive (it follows
        # ONE station script's Python import closure). Different case; not routed through it.
        (sandbox / "lib" / "adapters").mkdir(parents=True)
        adapter = sandbox / "lib" / "adapters" / "pi.sh"
        shutil.copyfile(FACTORY_ROOT / "lib" / "adapters" / "pi.sh", adapter)
        adapter.chmod(adapter.stat().st_mode | stat.S_IEXEC)
        for module in ("findings.py", "redaction.py", "embargo.py",
                       "tool_pins.py", "net_forward.py", "egress_proxy.py"):
            shutil.copyfile(FACTORY_ROOT / "lib" / module, sandbox / "lib" / module)
        # Sink adapters (fleet-km8): findings.py delegates delivery to lib/sinks.
        shutil.copytree(FACTORY_ROOT / "lib" / "sinks", sandbox / "lib" / "sinks", dirs_exist_ok=True)
        shutil.copyfile(FACTORY_ROOT / "lib" / "budget.py", sandbox / "lib" / "budget.py")

        bindir = sandbox / "bin"
        bindir.mkdir()
        stub = bindir / "pi"
        # pi.sh pipes the prompt through `set -o pipefail`: a canned-output stub that
        # exits without draining stdin can SIGPIPE the adapter's printf and falsely
        # report an engine failure instead of the fixture's schema verdict (agents-ub9).
        stub.write_text("#!/usr/bin/env bash\ncat >/dev/null\n" + f"cat '{report_src}'\n",
                        encoding="utf-8")
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        target = sandbox / "target"
        target.mkdir()
        return target

    def _run(self, sandbox: Path, target: Path):
        with mock.patch.object(factory_cli, "FACTORY_ROOT", sandbox), \
             mock.patch.dict(os.environ,
                             {"PATH": f"{sandbox / 'bin'}{os.pathsep}{os.environ.get('PATH', '')}"}):
            return factory_cli.run_agent("probe", str(target), engine_arg="pi")

    def test_stub_drains_a_large_prompt_before_emitting_its_fixture(self):
        """Fail-on-revert: pipefail must not turn canned output into adapter exit 1."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = Path(tmpdir)
            self._sandbox(sandbox, {"summary": "stub", "findings": []})
            res = subprocess.run(
                ["bash", "-o", "pipefail", "-c",
                 'python3 -c \'import sys; sys.stdout.write("x"*200000)\' | "$1"',
                 "bash", str(sandbox / "bin" / "pi")],
                capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(json.loads(res.stdout)["summary"], "stub")

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

            # No verdict is a station failure, never a clean PASS/0 (fleet-ddd).
            # Capture stdout so the deliberate test warning does not leak into gate logs
            # as an unexplained recurring failure (agents-4ass).
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                with self.assertRaises(factory_cli.StationError):
                    self._run(sandbox, target)

            self.assertIn("Model output violates the declared report schema", out.getvalue())
            self.assertIn("missing required property 'summary'", out.getvalue())
            self.assertFalse((sandbox / "findings" / "target.json").exists(),
                             "the store must never see a schema-violating report")
            report = json.loads(next((sandbox / "runs").glob("*/report.json")).read_text())
            self.assertEqual(report["summary"], "NO VERDICT: model output failed the declared report schema.")
            self.assertEqual(report["verdict"], "error")
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

            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self._run(sandbox, target)

            store = json.loads((sandbox / "findings" / "target.json").read_text(encoding="utf-8"))
            record, = store["findings"].values()
            self.assertEqual(record["severity"], "low")



class TestPathlessVerificationRecord(unittest.TestCase):
    """agents-nhpb: a pathless candidate is valid input, and the contract must say so."""

    def _schema(self):
        return json.loads(
            (FACTORY_ROOT / "agents" / "vuln-verify" / "report.schema.json").read_text(encoding="utf-8"))

    def test_a_null_path_unverifiable_record_validates(self):
        """The scanner can emit a candidate with no location, which is a normal output of this
        station's own pipeline rather than a threat - so refusing the report protects nothing and
        kills the station on data it exists to report on. unlocatable_verdicts already decides that
        the only honest verdict for such a record is 'unverifiable'; the schema nevertheless typed
        path as a string, so a model echoing the bundle's null failed validation, which the
        dispatcher treats exactly like unparseable output.

        Load-bearing: with path narrowed back to "string" this fails on the path property ("None is
        not of type 'string'") and not on the verdict rule - the report is otherwise complete.
        """
        report = {
            "summary": "one candidate had no location",
            "target": "example-owner/example-repo",
            "verifications": [{
                "rule_id": "hardcoded-credential",
                "path": None,
                "line_number": None,
                "verdict": "unverifiable",
                "confidence": "low",
                "reasoning": "the scanner emitted no location, so the claim cannot be adjudicated",
            }],
            "findings": [],
        }
        self.assertEqual(validate(report, self._schema()), [])

    def test_the_widening_did_not_open_a_hole_for_verified_findings(self):
        """The widening is narrow on purpose: only the verifications[] entry may be pathless.

        A record in findings[] claims to have survived adversarial testing, and this station may not
        adjudicate what it cannot point at - so a null path there is still a contract violation.
        Without this, "widen path" could be read as license to accept any pathless output at all.
        """
        report = {
            "summary": "x",
            "target": "example-owner/example-repo",
            "verifications": [],
            "findings": [{
                "rule_id": "hardcoded-credential",
                "path": None,
                "line_number": 4,
                "snippet": "s",
                "severity": "high",
                "title": "t",
                "description": "d",
                "remediation": "r",
            }],
        }
        errors = validate(report, self._schema())
        self.assertTrue(any("path" in e for e in errors),
                        f"a verified finding with no path must still be refused, got {errors}")

if __name__ == "__main__":
    unittest.main()


class TestUnlocatableVerdicts(unittest.TestCase):
    """agents-0tl (D): a verifier cannot adjudicate a record it cannot locate.

    On the 2026-10-09 dogfood audit vuln-verify returned verdict 'disproved' with confidence
    'high' for four records whose location was 'unknown' - and one of them was real (the
    memory-profile findings/ exclusion, now fixed as agents-uxt). Nothing rejected that, and the
    schema's enum did not even offer an honest alternative, so 'unverifiable' is now legal and
    the other two verdicts require a resolvable location.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.target = Path(self.tmp.name)
        (self.target / "lib").mkdir()
        (self.target / "lib" / "real.py").write_text("x = 1\n")

    def tearDown(self):
        self.tmp.cleanup()

    def _report(self, **entry):
        base = {"rule_id": "r", "path": "lib/real.py", "line_number": 1,
                "verdict": "disproved", "confidence": "high", "reasoning": "why"}
        base.update(entry)
        return {"summary": "s", "target": "t", "verifications": [base], "findings": []}

    def test_a_located_record_can_still_be_disproved(self):
        """The normal case must keep working - this fix must not blunt real verification."""
        self.assertEqual(unlocatable_verdicts(self._report(), self.target), [])

    def test_unknown_path_cannot_be_disproved(self):
        violations = unlocatable_verdicts(self._report(path="unknown"), self.target)
        self.assertEqual(len(violations), 1)
        self.assertIn("no resolvable location", violations[0])

    def test_disproved_without_any_path_is_a_violation(self):
        for missing in ({"path": "unknown"}, {"path": ""}, {"path": None}):
            violations = unlocatable_verdicts(self._report(**missing), self.target)
            self.assertEqual(len(violations), 1, f"path={missing.get('path')!r} must be rejected")
            self.assertIn("unverifiable", violations[0])
        # The key absent entirely, rather than set to a placeholder.
        report = self._report()
        report["verifications"][0].pop("path")
        violations = unlocatable_verdicts(report, self.target)
        self.assertEqual(len(violations), 1)
        self.assertIn("unverifiable", violations[0])

    def test_verified_without_a_location_is_also_a_violation(self):
        """You cannot verify what you cannot point at either - only 'unverifiable' is honest."""
        violations = unlocatable_verdicts(self._report(path="unknown", verdict="verified"), self.target)
        self.assertEqual(len(violations), 1)

    def test_unverifiable_is_accepted_without_a_location(self):
        self.assertEqual(unlocatable_verdicts(self._report(path="unknown", verdict="unverifiable"), self.target), [])

    def test_a_nonexistent_path_is_not_a_location(self):
        violations = unlocatable_verdicts(self._report(path="lib/invented.py"), self.target)
        self.assertEqual(len(violations), 1)

    def test_without_a_target_only_placeholder_paths_are_unlocatable(self):
        """No target to resolve against: do not reject a claim on a path we cannot check."""
        self.assertEqual(unlocatable_verdicts(self._report(path="lib/real.py"), None), [])
        self.assertEqual(len(unlocatable_verdicts(self._report(path="unknown"), None)), 1)

    def test_reports_without_verifications_are_untouched(self):
        self.assertEqual(unlocatable_verdicts({"findings": [{"path": "x"}]}, self.target), [])

    def test_the_real_schema_now_allows_unverifiable_and_the_rule_fires_through_it(self):
        agent_dir = FACTORY_ROOT / "agents" / "vuln-verify"
        cfg = {"output": {"schema": "report.schema.json"}}
        good = self._report(path="unknown", verdict="unverifiable")
        self.assertEqual(validate_agent_report(agent_dir, cfg, good, target_dir=self.target), [])
        bad = self._report(path="unknown", verdict="disproved")
        errors = validate_agent_report(agent_dir, cfg, bad, target_dir=self.target)
        self.assertTrue(errors and any("unverifiable" in e for e in errors), errors)

    def test_the_shipped_schema_rejects_a_verdict_outside_the_enum(self):
        agent_dir = FACTORY_ROOT / "agents" / "vuln-verify"
        cfg = {"output": {"schema": "report.schema.json"}}
        errors = validate_agent_report(agent_dir, cfg, self._report(verdict="definitely-fine"),
                                       target_dir=self.target)
        self.assertTrue(errors)

    def test_the_repository_root_is_not_a_location_for_a_verdict(self):
        """Review P1 (f76a368): a bare "." must not let a verdict look located."""
        for rootish in (".", "./"):
            violations = unlocatable_verdicts(self._report(path=rootish), self.target)
            self.assertEqual(len(violations), 1, f"path={rootish!r} must be rejected")

    def test_a_directory_location_is_accepted_for_a_verdict(self):
        """Whole-repo findings cite the nearest EXISTING path (a directory is fine)."""
        (self.target / ".github").mkdir()
        self.assertEqual(unlocatable_verdicts(self._report(path=".github"), self.target), [])


class TestUnknownLineIsRepresentable(unittest.TestCase):
    """agents-fy26: an unknown line must be STATED, and the schema must allow it.

    The verifier's pre-pass hands over `line_number: null` with `line_number_unknown: true` for a
    candidate whose line is the factory's own "?" marker. If the report schema still demanded an
    integer, a faithful model report would be rejected as a schema violation and the station would
    fail anyway - the failure moved rather than removed. Sibling stations (vuln-triage,
    log-check) already declare ["integer", "null"]; vuln-verify was the outlier.
    """

    def _errors(self, line_number):
        report = {
            "summary": "s",
            "target": "t",
            "verifications": [{
                "rule_id": "r", "path": "src/app.js", "line_number": line_number,
                "verdict": "disproved", "confidence": "high", "reasoning": "r",
            }],
            "findings": [],
        }
        cfg = {"output": {"schema": "report.schema.json"}}
        return validate_agent_report(FACTORY_ROOT / "agents" / "vuln-verify", cfg, report)

    def test_a_null_line_is_accepted(self):
        self.assertEqual(self._errors(None), [])

    def test_an_integer_line_is_still_accepted(self):
        self.assertEqual(self._errors(7), [])

    def test_the_sentinel_string_is_still_rejected(self):
        """null is the stated unknown; the scanner's own marker must not be echoed as a line."""
        errors = self._errors("?")
        self.assertTrue(any("line_number" in error for error in errors), errors)

    def test_a_null_line_in_the_findings_array_is_accepted(self):
        report = {
            "summary": "s", "target": "t", "verifications": [],
            "findings": [{
                "rule_id": "r", "path": "src/app.js", "line_number": None, "snippet": "s",
                "severity": "high", "title": "t", "description": "d", "remediation": "r",
            }],
        }
        cfg = {"output": {"schema": "report.schema.json"}}
        self.assertEqual(
            validate_agent_report(FACTORY_ROOT / "agents" / "vuln-verify", cfg, report), [])


class TestThreatModelSchemaBound(unittest.TestCase):
    """agents-uhru: threat-model report schema bounds threat_model_markdown to <= 16384 chars."""

    def test_threat_model_markdown_slot_is_bounded_in_schema(self):
        agent_dir = FACTORY_ROOT / "agents" / "threat-model"
        cfg = {"output": {"schema": "report.schema.json"}}
        valid_report = {
            "summary": "Valid summary",
            "target": "sample",
            "findings": [],
            "threat_model_markdown": "x" * 16384,
        }
        self.assertEqual(validate_agent_report(agent_dir, cfg, valid_report), [])

        oversized_report = {
            "summary": "Valid summary",
            "target": "sample",
            "findings": [],
            "threat_model_markdown": "x" * 16385,
        }
        errors = validate_agent_report(agent_dir, cfg, oversized_report)
        self.assertIsNotNone(errors)
        self.assertTrue(any("$.threat_model_markdown: length 16385 exceeds maxLength 16384" in e for e in errors),
                        errors)

