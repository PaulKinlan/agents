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

from lib.embargo import VALID_SEVERITIES

from lib.report_schema import (  # noqa: E402
    declared_schema,
    normalize_report,
    output_contract_prompt,
    required_fields_note,
    unlocatable_verdicts,
    validate,
    validate_agent_report,
    value_constraint_note,
)
from lib.sandbox import sandbox_available  # noqa: E402

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


def _tracked_report_schemas(root: Path = FACTORY_ROOT, *, require_nonempty: bool = True):
    """The tracked station schemas under `root`, read from git's index rather than the filesystem.

    `root` is a parameter so the debris probe can ask the SAME question about a root that is not the
    checkout (agents-fxg2): a decoy written under `agents/` moves that directory's ctime, which the tracked
    symlink `skills -> agents` turns into a witness change, and a gate that ran this suite then recorded
    STALE for a tree nobody had touched. The probe now keeps its decoy outside the tracked station tree
    while still failing against a filesystem-based implementation, because that implementation would be
    asked about the same root and would find it.
    """
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "agents/*/report.schema.json"],
        capture_output=True, text=True, check=True
    ).stdout.splitlines()
    schemas = sorted(root / p for p in out)
    if require_nonempty and not schemas:
        raise RuntimeError("no tracked report schemas found")
    return schemas


class TestDeclaredSchema(unittest.TestCase):
    def test_report_schemas_ignores_untracked_debris(self):
        """A check must read git's objects rather than the filesystem (agents-jcd2, agents-ug3a).

        Untracked debris matching agents/*/report.schema.json must not be absorbed.
        """
        # The probe root is a scratch git repository OUTSIDE the checkout (agents-ug3a). The decoy must not be
        # written under the checkout at all: a TemporaryDirectory(dir=FACTORY_ROOT) cannot run its cleanup if the
        # process is SIGKILLed or the runner times out, `tmp*/` has no root ignore rule, and an interrupted run
        # therefore left a committable temp directory for a later `git add -A` to capture. Nothing is written
        # under the checkout now, so the ctime/STALE witness concern of agents-fxg2 cannot arise either. The
        # assertion keeps its teeth because the decoy is still written and still on disk - a filesystem-based
        # implementation asked about this root would find it and fail - while the reader sees only what the
        # scratch index tracks.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            git = ["git", "-C", str(root), "-c", "user.email=t@t", "-c", "user.name=t",
                   "-c", "commit.gpgsign=false"]
            subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
            tracked = root / "agents" / "zreal_probe"
            tracked.mkdir(parents=True)
            (tracked / "report.schema.json").write_text("{}", encoding="utf-8")
            subprocess.run(git + ["add", "."], check=True, capture_output=True)
            subprocess.run(git + ["commit", "-qm", "seed"], check=True, capture_output=True)
            debris = root / "agents" / "zz_debris_probe_tmp"
            debris.mkdir(parents=True)
            (debris / "report.schema.json").write_text("{}", encoding="utf-8")
            schemas = _tracked_report_schemas(root, require_nonempty=False)
            self.assertEqual(schemas, [tracked / "report.schema.json"],
                             "the reader must return the tracked schema and nothing else")
            self.assertNotIn(debris / "report.schema.json", schemas)
            self.assertTrue((debris / "report.schema.json").is_file(),
                            "the decoy is on disk, so a filesystem-based reader would have absorbed it")
        # And the real checkout is still read correctly, so the assertion above is not just emptiness.
        self.assertIn(FACTORY_ROOT / "agents" / "secret-scan" / "report.schema.json", _tracked_report_schemas())

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
        for schema_path in _tracked_report_schemas():
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

    def test_all_shipped_schemas_satisfy_report_anatomy_contract(self):
        """agents-tz2y: Every committed report.schema.json must satisfy the report anatomy contract:
        top-level object requiring 'findings' array, whose items are objects with required
        'rule_id' (string) and 'severity' whose enum is exactly list(VALID_SEVERITIES)
        from lib.embargo (agents-hqgs)."""
        expected_severities = list(VALID_SEVERITIES)
        schemas = _tracked_report_schemas()
        self.assertEqual(len(schemas), 22,
                         "expected 22 agent report schemas matching agents/*/report.schema.json; "
                         "if an agent station was added or removed, update this count")
        for schema_path in schemas:
            with self.subTest(schema=schema_path.parent.name):
                schema = json.loads(schema_path.read_text(encoding="utf-8"))
                self.assertEqual(schema.get("type"), "object",
                                 f"{schema_path}: top-level schema type must be 'object'")
                top_required = schema.get("required")
                self.assertIsInstance(top_required, list,
                                      f"{schema_path}: top-level 'required' must be an array")
                self.assertIn("findings", top_required,
                              f"{schema_path}: schema must require 'findings'")

                findings_prop = schema.get("properties", {}).get("findings", {})
                self.assertEqual(findings_prop.get("type"), "array",
                                 f"{schema_path}: 'findings' property must be an array")

                items = findings_prop.get("items", {})
                self.assertEqual(items.get("type"), "object",
                                 f"{schema_path}: 'findings' items must be objects")

                item_props = items.get("properties", {})
                self.assertIn("rule_id", item_props,
                              f"{schema_path}: findings items must define 'rule_id'")
                self.assertEqual(item_props["rule_id"].get("type"), "string",
                                 f"{schema_path}: 'rule_id' must be a string")

                self.assertIn("severity", item_props,
                              f"{schema_path}: findings items must define 'severity'")
                sev_enum = item_props["severity"].get("enum")
                self.assertEqual(sev_enum, expected_severities,
                                 f"{schema_path}: 'severity' enum must match factory canonical "
                                 f"severity levels from lib.embargo.VALID_SEVERITIES")

                item_required = items.get("required")
                self.assertIsInstance(item_required, list,
                                      f"{schema_path}: findings items 'required' must be an array")
                self.assertIn("rule_id", item_required,
                              f"{schema_path}: findings items must require 'rule_id'")
                self.assertIn("severity", item_required,
                              f"{schema_path}: findings items must require 'severity'")


class TestDocsDriftCandidateIdentityContract(unittest.TestCase):
    """agents-fmakh: the schema arm must reject missing ids before accounting sees the report."""

    def setUp(self):
        self.agent_dir = FACTORY_ROOT / "agents" / "docs-drift"
        self.cfg = {"output": {"schema": "report.schema.json"}}
        self.schema = declared_schema(self.agent_dir, self.cfg)
        self.finding = {"rule_id": "doc-broken-link", "path": "docs/PLAN.md",
                        "snippet": "[missing](gone.md)", "severity": "medium",
                        "title": "Broken link", "description": "The link is missing"}

    def test_missing_or_blank_id_is_rejected_and_named_in_prompt(self):
        report = {"findings": [dict(self.finding)]}
        self.assertEqual(validate_agent_report(self.agent_dir, self.cfg, report),
                         ["$.findings[0]: missing required property 'candidate_id'"])
        report["findings"][0]["candidate_id"] = ""
        self.assertTrue(any("candidate_id" in error for error in
                            validate_agent_report(self.agent_dir, self.cfg, report)))
        note = required_fields_note(self.schema)
        self.assertIn("`candidate_id`", note.split("Each entry in `findings` MUST include:", 1)[1])
        self.assertIn(note.strip(), output_contract_prompt(self.schema))

    def test_normalization_keeps_the_citation_and_dismissals_still_validate(self):
        row = dict(self.finding, candidate_id="0123456789abcdef", remediation=None,
                   false_positive=True, severity="info")
        report = {"findings": [row]}
        notes = normalize_report(report, self.schema)
        self.assertEqual(row["candidate_id"], "0123456789abcdef")
        self.assertNotIn("remediation", row)
        self.assertTrue(any("remediation null -> omitted" in note for note in notes))
        self.assertEqual(validate_agent_report(self.agent_dir, self.cfg, report), [])
        self.assertEqual(validate_agent_report(self.agent_dir, self.cfg, {"findings": []}), [])
        row["candidate_id"] = None
        normalize_report(report, self.schema)
        self.assertIsNone(row["candidate_id"], "a required null id must not be silently omitted")
        self.assertTrue(any("candidate_id" in error for error in
                            validate_agent_report(self.agent_dir, self.cfg, report)))


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
        # Contract (agents-v52t): the engine runtime, staged by name; lib/sinks as a package tree.
        STAGED_RUNTIME = ("engine", "named", ("sinks",))
        for module in ("findings.py", "redaction.py", "embargo.py",
                       "tool_pins.py", "net_forward.py", "egress_proxy.py",
                       "line_numbers.py"):
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

class TestNormalizeReport(unittest.TestCase):
    """agents-h8i4: normalize_report normalizes scanned_files from a list of paths or string
    into an integer count so schema validation succeeds on attempt 1."""

    def test_normalize_report_scanned_files_list_to_count(self):
        report = {
            "summary": "s",
            "findings": [],
            "scanned_files": ["lib/a.py", "lib/b.py", "lib/c.py"],
        }
        notes = normalize_report(report)
        self.assertEqual(report["scanned_files"], 3)
        self.assertTrue(any("scanned_files" in n for n in notes))

    def test_normalize_report_scanned_files_digit_string_to_int(self):
        report = {
            "summary": "s",
            "findings": [],
            "scanned_files": "42",
        }
        notes = normalize_report(report)
        self.assertEqual(report["scanned_files"], 42)
        self.assertTrue(any("scanned_files" in n for n in notes))

    def test_normalize_report_unicode_digit_does_not_raise(self):
        """Review finding P2: unicode numeric chars like '²' must not raise ValueError."""
        report = {
            "summary": "s",
            "findings": [{"rule_id": "r", "path": "p.py", "line_number": "²", "snippet": "s",
                          "severity": "high", "title": "t", "description": "d", "remediation": "r"}],
            "scanned_files": "²",
        }
        notes = normalize_report(report)
        # Should not raise ValueError; leaves original string for schema validator to handle
        self.assertEqual(report["scanned_files"], "²")


class TestNullOptionalTriageStrings(unittest.TestCase):
    """agents-2scp8: a missing scanner snippet must not discard a whole triage report."""

    @staticmethod
    def schema():
        return json.loads((FACTORY_ROOT / "agents/vuln-triage/report.schema.json").read_text())

    @staticmethod
    def finding(**extra):
        return {"rule_id": "r1", "path": "a.js", "severity": "high", "title": "Reachable",
                "description": "Root cause", **extra}

    def test_eighteen_null_optional_snippets_are_omitted_before_validation(self):
        schema = self.schema()
        report = {"summary": "triaged", "findings": [self.finding(snippet=None) for _ in range(18)]}
        self.assertEqual(len(validate(report, schema)), 18,
                         "precondition: every null snippet rejects the unnormalised report")
        notes = normalize_report(report, schema)
        self.assertEqual(validate(report, schema), [])
        self.assertEqual(sum("snippet null -> omitted" in note for note in notes), 18)
        self.assertTrue(all("snippet" not in finding for finding in report["findings"]))

    def test_null_canonical_snippet_prefers_real_alias_before_omission(self):
        report = {"summary": "s", "findings": [self.finding(snippet=None, code="eval(user)")]}
        notes = normalize_report(report, self.schema())
        self.assertEqual(report["findings"][0]["snippet"], "eval(user)")
        self.assertIn("findings[0]: code -> snippet", notes)
        self.assertEqual(validate(report, self.schema()), [])

    def test_required_and_non_string_fields_still_reject_invalid_values(self):
        schema = self.schema()
        for field, value in (("severity", None), ("snippet", 42),
                             ("covered_candidate_ids", None), ("false_positive", None)):
            with self.subTest(field=field):
                report = {"summary": "s", "findings": [self.finding(**{field: value})]}
                normalize_report(report, schema)
                errors = validate(report, schema)
                self.assertTrue(any(field in error for error in errors), errors)

    def test_non_null_canonical_snippet_is_not_replaced_by_alias(self):
        report = {"summary": "s", "findings": [self.finding(snippet="scanner", code="model")]}
        normalize_report(report, self.schema())
        self.assertEqual(report["findings"][0]["snippet"], "scanner")


class TestStructuredTriageAffectedLocations(unittest.TestCase):
    """agents-jwbts: CAP's 28 path+line objects must not reject 18 valid findings."""

    @staticmethod
    def schema():
        return json.loads((FACTORY_ROOT / "agents/vuln-triage/report.schema.json").read_text())

    @staticmethod
    def cap_census_report():
        findings = []
        for i in range(18):
            locations = [{"path": f"src/{i}-{j}.js", "line_number": i + j + 1}
                         for j in range(2 if i < 10 else 1)]
            finding = {"rule_id": "r1", "path": f"src/{i}.js", "severity": "high",
                       "title": f"Candidate {i}", "description": "Root cause",
                       "snippet": None, "affected_locations": locations}
            if i < 5:
                finding["remediation"] = None
            findings.append(finding)
        return {"summary": "triaged", "findings": findings}

    def test_cap_census_51_violations_become_zero_without_dropping_findings(self):
        schema = self.schema()
        report = self.cap_census_report()
        raw_errors = validate(report, schema)
        self.assertEqual(len(raw_errors), 51)
        self.assertEqual(sum("affected_locations" in error for error in raw_errors), 28)
        self.assertEqual(sum("snippet" in error for error in raw_errors), 18)
        self.assertEqual(sum("remediation" in error for error in raw_errors), 5)
        notes = normalize_report(report, schema)
        self.assertEqual(validate(report, schema), [])
        self.assertEqual(len(report["findings"]), 18)
        self.assertEqual(sum("affected_locations[" in note for note in notes), 28)
        self.assertEqual(sum("null -> omitted" in note for note in notes), 23)
        for i, finding in enumerate(report["findings"]):
            self.assertEqual(finding["affected_locations"],
                             [f"src/{i}-{j}.js:{i + j + 1}" for j in range(2 if i < 10 else 1)])
        self.assertEqual(normalize_report(report, schema), [], "normalization is idempotent")

    def test_malformed_structured_locations_are_still_rejected(self):
        schema = self.schema()
        invalid = (
            {"path": "a.js", "line_number": 0},
            {"path": "a.js", "line_number": -1},
            {"path": "a.js", "line_number": True},
            {"path": "a.js", "line_number": None},
            {"path": "a.js", "line_number": "?"},
            {"path": "", "line_number": 1},
            {"path": 42, "line_number": 1},
            {"path": "a.js", "line_number": 1, "extra": "do not discard"},
            {"path": "a.js"},
        )
        for location in invalid:
            with self.subTest(location=location):
                report = {"summary": "s", "findings": [{"rule_id": "r", "path": "a.js",
                          "severity": "high", "title": "t", "description": "d",
                          "affected_locations": [{"path": "ok.js", "line_number": 1}, location]}]}
                normalize_report(report, schema)
                self.assertEqual(report["findings"][0]["affected_locations"][0], "ok.js:1")
                self.assertEqual(report["findings"][0]["affected_locations"][1], location)
                self.assertEqual(len(validate(report, schema)), 1)

    def test_digit_string_line_uses_the_shared_line_rule_and_schema_gates_repair(self):
        location = {"path": "a.js", "line_number": "42"}
        report = {"summary": "s", "findings": [{"rule_id": "r", "path": "a.js",
                  "severity": "high", "title": "t", "description": "d",
                  "affected_locations": [location]}]}
        normalize_report(report)
        self.assertEqual(report["findings"][0]["affected_locations"], [location])
        schema = self.schema()
        schema["properties"]["findings"]["items"]["properties"]["affected_locations"]["items"]["type"] = "object"
        normalize_report(report, schema)
        self.assertEqual(report["findings"][0]["affected_locations"], [location])
        normalize_report(report, self.schema())
        self.assertEqual(report["findings"][0]["affected_locations"], ["a.js:42"])


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
            "summary": "s", "target": "t",
            "verifications": [{"rule_id": "r", "path": "src/app.js", "line_number": None,
                               "candidate_id": "c0", "verdict": "verified",
                               "confidence": "high", "reasoning": "Located by path"}],
            "findings": [{
                "rule_id": "r", "path": "src/app.js", "line_number": None, "snippet": "s",
                "severity": "high", "title": "t", "description": "d", "remediation": "r",
                "candidate_id": "c0",
            }],
        }
        cfg = {"output": {"schema": "report.schema.json"}}
        self.assertEqual(
            validate_agent_report(FACTORY_ROOT / "agents" / "vuln-verify", cfg, report), [])


class TestVulnVerifyRequiresPublishedVerifiedFindings(unittest.TestCase):
    """agents-t6fut: reject orphan verified verdicts before the findings store is updated."""

    def _report(self, verdict="verified", candidate_id="c0", findings=None):
        return {
            "summary": "verified candidates", "target": "sample",
            "verifications": [{"rule_id": "r1", "path": "src/app.js", "line_number": 7,
                               "candidate_id": candidate_id, "verdict": verdict,
                               "confidence": "high", "reasoning": "Checked source"}],
            "findings": [] if findings is None else findings,
        }

    def _finding(self, candidate_id="c0", **extra):
        return {"rule_id": "r1", "path": "src/app.js", "line_number": 7,
                "candidate_id": candidate_id, "snippet": "danger()", "severity": "critical",
                "title": "Reachable exploit", "description": "Confirmed", "remediation": "Fix",
                **extra}

    def _errors(self, report):
        cfg = {"output": {"schema": "report.schema.json"}}
        return validate_agent_report(FACTORY_ROOT / "agents" / "vuln-verify", cfg, report)

    def test_verified_without_a_finding_is_rejected(self):
        errors = self._errors(self._report())
        self.assertTrue(any("matching candidate_id" in e for e in errors), errors)

    def test_verified_with_no_candidate_id_at_all_is_rejected(self):
        """agents-rcgb3: a pre-pass that leaves a candidate without an id makes `verified` unrepresentable -
        there is no id to cite and inventing one is refused as a foreign citation. The rule is old
        (agents-t6fut); what was missing is that nothing said so, so the model looped through a repair-retry
        it could not legitimately exit."""
        errors = self._errors(self._report(candidate_id=""))
        self.assertTrue(any("candidate_id" in e for e in errors), errors)

    def test_the_station_says_what_to_do_instead(self):
        """The rule is only escapable if the model is TOLD the escape, so pin the words in both places the
        model reads: the schema description it is handed in the prompt, and SKILL.md."""
        import json as _json
        schema = _json.loads((FACTORY_ROOT / "agents" / "vuln-verify" / "report.schema.json")
                             .read_text(encoding="utf-8"))
        description = schema["properties"]["verifications"]["items"]["properties"]["candidate_id"]["description"]
        skill = (FACTORY_ROOT / "agents" / "vuln-verify" / "SKILL.md").read_text(encoding="utf-8")
        # SKILL.md is written in caps, so compare case-insensitively rather than pinning its shouting.
        for label, text in (("schema description", description), ("SKILL.md", skill)):
            upper = text.upper()
            self.assertIn("UNVERIFIABLE", upper, f"{label} must name the escape verdict")
            self.assertIn("CANNOT BE VERIFIED", upper, f"{label} must name the id-less case it applies to")
            self.assertIn("AGENTS-RCGB3", upper, f"{label} must carry the finding it answers")

    def test_verified_with_a_mismatched_or_dismissed_finding_is_rejected(self):
        for findings in ([self._finding("c1")], [self._finding(false_positive=True)]):
            with self.subTest(findings=findings):
                errors = self._errors(self._report(findings=findings))
                self.assertTrue(any("matching candidate_id" in e for e in errors), errors)

    def test_verified_without_an_id_cannot_link_to_a_finding(self):
        report = self._report(findings=[self._finding()])
        del report["verifications"][0]["candidate_id"]
        errors = self._errors(report)
        self.assertTrue(any("matching candidate_id" in e for e in errors), errors)

    def test_linked_verified_and_unpublished_disproved_are_valid(self):
        self.assertEqual(self._errors(self._report(findings=[self._finding()])), [])
        self.assertEqual(self._errors(self._report(verdict="disproved")), [])
        self.assertEqual(self._errors(self._report(verdict="unverifiable")), [])

    def test_disproved_or_unverifiable_finding_cannot_publish(self):
        for verdict in ("disproved", "unverifiable"):
            with self.subTest(verdict=verdict):
                errors = self._errors(self._report(verdict=verdict, findings=[self._finding()]))
                self.assertTrue(any("matching 'verified' verdict" in e for e in errors), errors)

    def test_missing_or_idless_verification_cannot_publish_a_finding(self):
        for report in (self._report(findings=[self._finding(candidate_id="c1")]),
                       self._report(findings=[self._finding(candidate_id="")]),
                       self._report(findings=[self._finding(candidate_id="c0")])):
            with self.subTest(report=report):
                report["verifications"] = []
                errors = self._errors(report)
                self.assertTrue(any("$.findings[0].candidate_id" in e for e in errors), errors)

    def test_a_contradictory_second_verdict_cannot_hide_a_disproof(self):
        report = self._report(findings=[self._finding()])
        report["verifications"].append({**report["verifications"][0], "verdict": "disproved"})
        errors = self._errors(report)
        self.assertTrue(any("matching 'verified' verdict" in e for e in errors), errors)

    def test_dismissal_evidence_requires_no_verified_verdict(self):
        report = self._report(verdict="disproved", findings=[self._finding(false_positive=True)])
        self.assertEqual(self._errors(report), [])


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


class TestThePromptSpellsOutTheRequiredFields(unittest.TestCase):
    """agents-sz8q: the station's report was rejected 35 times for 35 candidates - one violation per
    candidate - and the prompt was already carrying the full JSON Schema. What it never stated was, in
    words, which fields a report MUST carry: a nested `required` array is easy to miss, and the prompt's
    only prose on the subject was about property NAMES ("use `rule_id`, not `id`"). The note below is
    therefore derived from the schema that will judge the answer, so it cannot fall behind it.
    """

    @staticmethod
    def _schema(required=("summary", "findings"), finding_required=("rule_id", "snippet")):
        return {
            "required": list(required),
            "properties": {"findings": {"items": {"required": list(finding_required)}}},
        }

    def test_note_names_every_required_field(self):
        note = required_fields_note(self._schema())
        for field in ("summary", "findings", "rule_id", "snippet"):
            self.assertIn(f"`{field}`", note, f"{field} is required by the schema and must be spelled out")

    def test_the_note_distinguishes_top_level_from_findings(self):
        note = required_fields_note(self._schema())
        self.assertIn("Required top-level fields: `summary`, `findings`", note)
        self.assertIn("Each entry in `findings` MUST include: `rule_id`, `snippet`", note)

    def test_the_note_is_derived_from_the_schema_not_typed_beside_it(self):
        """The control. If the list were hardcoded here, a schema that grows a required field would keep
        producing a note that omits it - the exact drift this helper exists to prevent."""
        base = required_fields_note(self._schema())
        self.assertNotIn("`title`", base)
        grown = required_fields_note(self._schema(finding_required=("rule_id", "snippet", "title")))
        self.assertIn("`title`", grown, "a field added to the schema must appear in the note with no other edit")

    def test_every_shipped_station_schema_derives_its_note_and_is_byte_unchanged(self):
        """agents-2hm5 (rev-sz8q's recorded gap): the control above builds its schema IN CODE, so nothing pinned
        the note against the schemas the stations actually ship. This one starts from the SHIPPED BYTES: appending
        a field to a schema's own required array must move the note, and the file must be byte-unchanged
        afterwards - so a future author cannot satisfy this test by editing the schema instead of the derivation,
        which would be the opposite of the fix. Every station's schema is checked, so a new station cannot be
        typed by hand either."""
        probe = "mutation_probe_field"
        schemas = sorted((FACTORY_ROOT / "agents").glob("*/report.schema.json"))
        self.assertGreaterEqual(len(schemas), 20, f"expected the station schema set, found {len(schemas)}")
        checked_lists = 0
        for path in schemas:
            with self.subTest(schema=path.parent.name):
                shipped = path.read_bytes()
                schema = json.loads(shipped)
                self.assertNotIn(probe, required_fields_note(schema), "nothing may have typed this field")
                self.assertNotIn(probe, output_contract_prompt(schema))
                # The two lists the note is DERIVED from: the schema's own required array, and the findings item's.
                top = schema.get("required")
                if isinstance(top, list) and top:
                    mutated = json.loads(shipped)
                    mutated["required"] = list(top) + [probe]
                    self.assertIn(probe, required_fields_note(mutated),
                                  "a field appended to the schema's required array must move the note")
                    self.assertIn(probe, output_contract_prompt(mutated), "...and the prompt must carry the note")
                    checked_lists += 1
                items = schema.get("properties", {}).get("findings", {}).get("items", {})
                required = items.get("required") if isinstance(items, dict) else None
                if isinstance(required, list) and required:
                    mutated = json.loads(shipped)
                    mutated["properties"]["findings"]["items"]["required"] = list(required) + [probe]
                    self.assertIn(probe, required_fields_note(mutated),
                                  "a field appended to the findings item's required array must move the note")
                    self.assertIn(probe, output_contract_prompt(mutated), "...and the prompt must carry the note")
                    checked_lists += 1
                self.assertEqual(path.read_bytes(), shipped,
                                 "the shipped schema must be byte-unchanged by this test")
        self.assertGreater(checked_lists, 0,
                           "no schema's required arrays were exercised, so the test proved nothing")

    def test_a_schema_with_nothing_required_produces_no_note(self):
        # Silence, not a stray heading, so the prompt is unchanged for a schema that requires nothing.
        self.assertEqual(required_fields_note({"properties": {}}), "")

    def test_the_perf_review_contract_is_covered(self):
        """The station this was filed against: every required finding field in its own schema must be
        named in the note, read from the schema rather than from this test."""
        agent_dir = Path(__file__).resolve().parent.parent / "agents" / "perf-review"
        schema = json.loads((agent_dir / "report.schema.json").read_text(encoding="utf-8"))
        note = required_fields_note(schema)
        for field in schema["properties"]["findings"]["items"]["required"]:
            self.assertIn(f"`{field}`", note)

    def test_the_prompt_fragment_carries_both_the_schema_and_the_required_sets(self):
        """The wiring, asserted on the text the model is given rather than by reading the dispatcher."""
        fragment = output_contract_prompt(self._schema())
        self.assertIn('"required"', fragment, "the schema itself must still be carried verbatim")
        self.assertIn("Each entry in `findings` MUST include: `rule_id`, `snippet`", fragment)

    def test_the_fragment_asks_the_model_for_the_field_that_was_being_omitted(self):
        """The end of the chain that started this bead: perf-review's own schema, through the fragment the
        dispatcher appends, has to name `snippet`."""
        agent_dir = Path(__file__).resolve().parent.parent / "agents" / "perf-review"
        schema = json.loads((agent_dir / "report.schema.json").read_text(encoding="utf-8"))
        self.assertIn("`snippet`", output_contract_prompt(schema))

    def test_no_schema_means_no_fragment(self):
        self.assertEqual(output_contract_prompt(None), "")


class TestThePromptSpellsOutValueConstraints(unittest.TestCase):
    """agents-4vxwv: vuln-triage failed validation twice on VALUE constraints, not missing fields - attempt 1
    sent `summary` as an object where the schema says `"type": "string"`, attempt 2 sent a free-text
    justification where `reachability` allows three enum values. The prompt carried the schema verbatim and
    the required sets were already given in words; nothing said what an ACCEPTED value looks like. The note
    below is derived from the schema that will judge the answer, like `required_fields_note`, so an enum or
    a type can never drift out of the prompt.
    """

    @staticmethod
    def _schema(summary_type="string", reachability=("reachable", "conditional", "unreachable"),
                finding_required=("severity", "reachability", "description")):
        return {
            "required": ["summary", "findings"],
            "properties": {
                "summary": {"type": summary_type},
                "findings": {"type": "array", "items": {
                    "required": list(finding_required),
                    "properties": {
                        "severity": {"enum": ["critical", "high", "low"]},
                        "reachability": {"enum": list(reachability)},
                        "description": {"type": "string"},
                    },
                }},
            },
        }

    def test_every_enum_value_is_named_with_its_field(self):
        note = value_constraint_note(self._schema())
        self.assertIn("`reachability`", note)
        for value in ("reachable", "conditional", "unreachable"):
            self.assertIn(f"`{value}`", note, f"{value} is an accepted enum value and must be spelled out")
        self.assertIn("`severity`", note)
        for value in ("critical", "high", "low"):
            self.assertIn(f"`{value}`", note)

    def test_the_enum_note_is_derived_from_the_schema_not_typed_beside_it(self):
        """The control: if the values were hardcoded, a schema that gains an enum value would keep producing
        a note that omits it - the drift this helper exists to prevent."""
        probe = "probe-reachability-value"
        base = value_constraint_note(self._schema())
        self.assertNotIn(probe, base)
        grown = value_constraint_note(self._schema(reachability=("reachable", probe)))
        self.assertIn(probe, grown, "an enum value added to the schema must appear with no other edit")

    def test_a_required_string_is_named_as_a_string_and_the_shape_is_stated(self):
        """Attempt 1 of the reported run: `summary` arrived as an object."""
        note = value_constraint_note(self._schema())
        self.assertIn("`summary`", note)
        self.assertIn("JSON string", note)
        self.assertIn("never an object", note, "a type name alone did not stop the object")
        # Derived: the words follow the schema's own declared type, so a schema that changes the type
        # cannot leave the note describing the old one.
        self.assertNotIn("JSON integer", note)
        self.assertIn("JSON integer", value_constraint_note(self._schema(summary_type="integer")))

    def test_an_optional_enum_is_still_pinned(self):
        """`reachability` is NOT required in vuln-triage's shipped schema and the model emitted it anyway -
        an optional field with only one accepted spelling must still be spelled out."""
        note = value_constraint_note(self._schema(finding_required=("severity",)))
        self.assertIn("`reachability`", note)
        self.assertIn("`unreachable`", note)

    def test_the_vuln_triage_contract_is_covered(self):
        """The station this was filed against, read from its SHIPPED schema rather than from this test."""
        schema = json.loads((FACTORY_ROOT / "agents" / "vuln-triage" / "report.schema.json")
                            .read_text(encoding="utf-8"))
        prompt = output_contract_prompt(schema)
        for value in schema["properties"]["findings"]["items"]["properties"]["reachability"]["enum"]:
            self.assertIn(f"`{value}`", prompt, "every allowed reachability value must reach the prompt")
        self.assertIn("`summary`", prompt)
        self.assertIn("JSON string", prompt)

    def test_every_shipped_schema_derives_its_value_constraints_and_is_byte_unchanged(self):
        """The control above builds its schema IN CODE, so this one starts from the SHIPPED BYTES: an enum
        declared in a schema's own bytes - top-level or inside `findings` - must move the note (and the
        prompt), and the file must be byte-unchanged afterwards, so a future author cannot satisfy this by
        editing a schema instead of the derivation. Every station's schema is checked, so a new station
        cannot be typed by hand either."""
        probe = "probe-enum-value"
        schemas = sorted((FACTORY_ROOT / "agents").glob("*/report.schema.json"))
        self.assertGreaterEqual(len(schemas), 20, f"expected the station schema set, found {len(schemas)}")
        checked_enums = 0
        checked_strings = 0
        for path in schemas:
            with self.subTest(schema=path.parent.name):
                shipped = path.read_bytes()
                schema = json.loads(shipped)
                note = value_constraint_note(schema)
                self.assertNotIn(probe, note, "nothing may have typed this enum")
                self.assertNotIn(probe, output_contract_prompt(schema))
                # Every enum the schema actually declares must be spelled out with its allowed values.
                finding_item = ((schema.get("properties") or {}).get("findings") or {}).get("items") or {}
                for properties in ((schema.get("properties") or {}), (finding_item.get("properties") or {})):
                    for name, subschema in properties.items():
                        allowed = subschema.get("enum") if isinstance(subschema, dict) else None
                        if not isinstance(allowed, list) or not allowed:
                            continue
                        self.assertIn(f"`{name}`", note, f"enum {name} must be named in the note")
                        for value in allowed:
                            self.assertIn(f"`{value}`", note,
                                          f"allowed {name} value must be named in the note")
                        checked_enums += 1
                # An enum injected at EITHER scope must show up with no other edit, so the scope walk is
                # proven rather than assumed.
                for scope in ("top-level", "findings"):
                    mutated = json.loads(shipped)
                    properties = (mutated.setdefault("properties", {}).setdefault(
                        "findings", {}).setdefault("items", {}).setdefault("properties", {})
                        if scope == "findings" else mutated.setdefault("properties", {}))
                    properties["probe_field"] = {"type": "string", "enum": [probe]}
                    self.assertIn(probe, value_constraint_note(mutated),
                                  f"an enum declared in the {scope} schema must move the note")
                    self.assertIn(probe, output_contract_prompt(mutated),
                                  "...and the prompt must carry the note")
                # A required top-level string property, if the station has one, must be named as a string.
                required = schema.get("required") or []
                top_properties = schema.get("properties") or {}
                for name in required:
                    subschema = top_properties.get(name) or {}
                    if subschema.get("type") == "string" and "enum" not in subschema:
                        self.assertIn(f"`{name}`", note)
                        self.assertIn("JSON string", note)
                        checked_strings += 1
                self.assertEqual(path.read_bytes(), shipped,
                                 "the shipped schema must be byte-unchanged by this test")
        self.assertGreater(checked_enums, 0, "no shipped enum was exercised, so the test proved nothing")
        self.assertGreater(checked_strings, 0, "no shipped required string was exercised")

    def test_nothing_to_say_produces_no_note(self):
        # Silence, not a stray heading, so the prompt is unchanged for a schema with no enums and no
        # required scalar fields.
        self.assertEqual(value_constraint_note({"properties": {}}), "")
        self.assertEqual(value_constraint_note({"required": ["findings"], "properties": {
            "findings": {"items": {"properties": {"tags": {"type": "array"}}}}}}), "")
        self.assertEqual(value_constraint_note(None), "")

    def test_the_repair_retry_prompt_carries_the_value_constraints(self):
        """The repair attempt must be enforced too, and it is - without the dispatcher repeating the note.

        agents-4vxwv: `factory` builds a retry's prompt as `output_contract_prompt(schema)` followed by the
        rejection hint (`contract_block += "\\n\\n" + repair_hint`), and `output_contract_prompt` is what
        this bead extended. So the retried model receives these constraints whether or not the hint sentence
        restates them, and duplicating the note inside the hint would be a second copy of text that is
        already 30 lines above it in the same prompt. What this test pins is the half that lives here: the
        fragment a retry re-sends contains the enum values and the string-shape rule.
        """
        schema = json.loads((FACTORY_ROOT / "agents" / "vuln-triage" / "report.schema.json")
                            .read_text(encoding="utf-8"))
        fragment = output_contract_prompt(schema)
        self.assertIn("`unreachable`", fragment,
                      "a retry re-sends this fragment, so it must state the enum values")
        self.assertIn("never an object", fragment)
        # ...and the fragment is the SAME text every attempt gets, retry or not: no second assembly path.
        self.assertEqual(fragment, output_contract_prompt(declared_schema(
            FACTORY_ROOT / "agents" / "vuln-triage",
            {"output": {"schema": "report.schema.json"}})))

    def test_the_dispatcher_sends_that_fragment_on_a_repair_retry(self):
        """The wiring, read from the dispatcher source rather than restated: a retry's prompt is the
        contract fragment plus the hint. If that composition ever changes, this bead's repair-path claim
        (agents-4vxwv) silently stops being true, so it is asserted where it is made."""
        source = (FACTORY_ROOT / "factory").read_text(encoding="utf-8")
        self.assertIn("contract_block = output_contract_prompt(output_schema)", source)
        self.assertRegex(source, r"contract_block \+= \"\\n\\n\" \+ repair_hint",
                         "the retry prompt must still prepend the contract fragment to the hint")



if __name__ == "__main__":
    unittest.main()

