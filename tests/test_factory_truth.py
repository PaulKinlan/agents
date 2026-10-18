#!/usr/bin/env python3
"""A station that produced no verdict never reads as clean (fleet-810, fleet-ddd, journal-*).

These drive the real dispatcher (`factory`), the real findings CLI and the real line runner in
a sandbox, with a stub `pi` that prints a per-agent canned model output. They pin:

- the run's delta report is written once by the line, from every station (fleet-810);
- model output wrapped in fences/prose still parses; output that does not is ERROR (fleet-ddd,
  journal-mid), as is a failed pre-pass or engine (journal-idy, journal-wog);
- the stored, displayed and andon-counted severity is the triaged one; the fail-closed routing
  value only routes (journal-1kg, journal-35w, journal-y5m, journal-aaj);
- public issue publication refuses an untriaged direct bead sink (agents-559);
- fingerprints bind to the scanner's snippet, so a re-quoted line is not new+fixed churn
  (fleet-oed).
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
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from lib.sandbox import sandbox_available  # noqa: E402

_RUNNABLE_BWRAP = sandbox_available()
_NEEDS_BWRAP = "needs a host where bubblewrap actually runs"

from lib.embargo import is_false_positive, reported_severity  # noqa: E402
from lib.findings import FindingsStore, load_candidate_index  # noqa: E402

_loader = importlib.machinery.SourceFileLoader("factory_cli_truth", str(ROOT / "factory"))
_spec = importlib.util.spec_from_loader("factory_cli_truth", _loader)
factory_cli = importlib.util.module_from_spec(_spec)
_loader.exec_module(factory_cli)

LIB_MODULES = ("findings.py", "redaction.py", "embargo.py", "budget.py", "child_env.py",
               "credential_broker.py", "net_forward.py", "egress_proxy.py",
               "report_schema.py", "containment.py", "sandbox.py", "retention.py",
               "tool_pins.py", "line_numbers.py", "candidate_batching.py")


def finding(**overrides):
    base = {"rule_id": "r1", "path": "a.js", "line_number": 1, "snippet": "x = 1",
            "severity": "medium", "title": "A finding", "description": "d",
            "remediation": "fix"}
    base.update(overrides)
    return base


def report(*findings):
    return json.dumps({"summary": "stub", "scanned_files": 1, "findings": list(findings)})


class Sandbox:
    """A factory root with probe agents whose model output is a file we control.

    agents-r2ne census: a FACTORY-runtime tree, not a station-script fixture - the copy set is
    the factory dispatcher's own runtime (the shell adapter, the lib/sinks package directory,
    budget.py and friends), which tests/sandbox_fixtures.py:copy_station_script deliberately
    does not derive (it follows ONE station script's Python import closure). Different case.
    """

    def __init__(self, root: Path):
        self.root = root
        self.target = root / "target"
        self.target.mkdir()
        (root / "lib" / "adapters").mkdir(parents=True)
        adapter = root / "lib" / "adapters" / "pi.sh"
        shutil.copyfile(ROOT / "lib" / "adapters" / "pi.sh", adapter)
        adapter.chmod(adapter.stat().st_mode | stat.S_IEXEC)
        # Contract (agents-v52t): the dispatcher runtime, staged by name; lib/sinks as a package tree.
        STAGED_RUNTIME = ("dispatcher", "named", ("sinks",))
        for module in LIB_MODULES:
            shutil.copyfile(ROOT / "lib" / module, root / "lib" / module)
        # Sink adapters (fleet-km8): findings.py delegates delivery to lib/sinks.
        shutil.copytree(ROOT / "lib" / "sinks", root / "lib" / "sinks", dirs_exist_ok=True)
        shutil.copyfile(ROOT / "lib" / "budget.py", root / "lib" / "budget.py")
        (root / "outputs").mkdir()
        (root / "lines").mkdir()
        self.bin = root / "bin"
        self.bin.mkdir()
        stub = self.bin / "pi"
        # The adapter passes --skill <agent dir>; print that agent's canned output.
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "skill=''\n"
            "while [ $# -gt 0 ]; do [ \"$1\" = --skill ] && skill=\"$2\"; shift; done\n"
            # Drain the prompt: the adapter pipes it in under `set -euo pipefail` and the real
            # engine reads it, so a stub that exits without reading makes printf take SIGPIPE
            # (141), which the adapter reports as a spurious "engine 'pi' exited 1" (agents-lx4).
            "cat >/dev/null\n"
            f"cat '{root}/outputs/'\"$(basename \"$skill\")\".txt\n",
            encoding="utf-8")
        stub.chmod(0o755)

    def agent(self, name, output, prepass=None, short_circuit=False,
              candidate_accounting=None, report_schema=None):
        directory = self.root / "agents" / name
        (directory / "scripts").mkdir(parents=True)
        manifest = (f"name: {name}\nclass: observer\ncontainment: t0-readonly\n"
                    f"short_circuit_empty: {'true' if short_circuit else 'false'}\n"
                    "budget: {max_minutes: 1}\n")
        if candidate_accounting is not None:
            manifest += f"candidate_accounting: {candidate_accounting}\n"
        if report_schema is not None:
            manifest += "output:\n  schema: report.schema.json\n"
        (directory / "agent.yaml").write_text(manifest, encoding="utf-8")
        if report_schema is not None:
            (directory / "report.schema.json").write_text(json.dumps(report_schema), encoding="utf-8")
        if prepass is not None:
            (directory / "scripts" / "prepass.py").write_text(prepass, encoding="utf-8")
        (self.root / "outputs" / f"{name}.txt").write_text(output, encoding="utf-8")

    def line(self, stations, halt=False):
        (self.root / "lines" / "testline.yaml").write_text(
            "name: testline\n"
            f"andon_halt_on_failure: {'true' if halt else 'false'}\n"
            "andon_halt_on_critical: false\n"
            "stations:\n" + "".join(f"  - {s}\n" for s in stations), encoding="utf-8")

    @contextlib.contextmanager
    def patched(self):
        env = {"PATH": f"{self.bin}{os.pathsep}/usr/bin:/bin"}
        with mock.patch.object(factory_cli, "FACTORY_ROOT", self.root), \
             mock.patch.dict(os.environ, env):
            yield

    def run_line(self):
        out = io.StringIO()
        with self.patched(), contextlib.redirect_stdout(out):
            result = factory_cli.run_line("testline", str(self.target), engine_arg="pi",
                                          explicit_sink="file")
        return result, out.getvalue()

    def run_agent(self, name, sink="file"):
        with self.patched(), contextlib.redirect_stdout(io.StringIO()):
            return factory_cli.run_agent(name, str(self.target), engine_arg="pi", explicit_sink=sink)

    def findings(self, name):
        return (self.root / "findings" / name).read_text(encoding="utf-8")


class SandboxCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="factory-truth-")
        self.addCleanup(tmp.cleanup)
        self.box = Sandbox(Path(tmp.name).resolve())


@unittest.skipUnless(_RUNNABLE_BWRAP, _NEEDS_BWRAP)
class TestLineDeltaReport(SandboxCase):
    """fleet-810: the run's delta report describes the run, not the last station."""

    def test_an_empty_last_station_does_not_make_the_run_clean(self):
        self.box.agent("finder", report(finding(title="Real problem")))
        self.box.agent("quiet", report())
        self.box.line(["finder", "quiet"])
        ok, _ = self.box.run_line()

        self.assertTrue(ok)
        delta = self.box.findings("target-delta.md")
        self.assertNotIn("Clean Delta", delta)
        self.assertIn("Real problem", delta)
        self.assertIn("| **1** |", delta)
        self.assertIn("`finder` | PASS | 1", delta)
        self.assertIn("`quiet` | PASS | 0", delta)
        self.assertEqual(delta, self.box.findings("target-latest.md"))
        # Each station keeps its own report; neither overwrote the run's.
        self.assertIn("Clean Delta", self.box.findings("target-quiet-delta.md"))
        self.assertIn("Real problem", self.box.findings("target-finder-delta.md"))
        machine = json.loads(self.box.findings("target-line.json"))
        self.assertTrue(machine["complete"])
        self.assertEqual(machine["stats"]["new"], 1)

    def test_a_no_verdict_station_makes_the_run_incomplete_not_clean(self):
        self.box.agent("quiet", report())
        self.box.agent("garbled", "I looked at the code and it seems fine.")
        self.box.line(["quiet", "garbled"])
        ok, out = self.box.run_line()

        self.assertFalse(ok, "a line with a no-verdict station must not exit 0")
        self.assertIn("INCOMPLETE", out)
        delta = self.box.findings("target-delta.md")
        self.assertNotIn("Clean Delta", delta)
        self.assertIn("INCOMPLETE", delta)
        self.assertIn("| — | — | — | — | — | — |", delta,
                      "the top delta table must not turn an ERROR with no verdict into six zeroes")
        self.assertIn("`garbled` | ERROR | — | —", delta)
        self.assertFalse(json.loads(self.box.findings("target-line.json"))["complete"])

    def test_an_error_station_prints_dashes_not_zeroes(self):
        """journal-idy: ERROR 0/0 read like a genuine zero."""
        self.box.agent("garbled", "no json here")
        self.box.line(["garbled"])
        _, out = self.box.run_line()
        row = next(l for l in out.splitlines() if l.startswith("garbled"))
        self.assertEqual(row.split(), ["garbled", "ERROR", "-", "-"])

    def test_stations_after_a_halt_are_listed_as_skipped(self):
        # agents-noo: a halt is triggered by a GENUINE failure (engine/pre-pass), NOT by a
        # no-verdict — unparseable output now degrades-and-continues instead of halting. Drive the
        # halt with an engine that exits non-zero (a genuine StationError), so the downstream
        # station is still SKIPPED and named.
        self.box.agent("crashy", report())
        (self.box.bin / "pi").write_text("#!/usr/bin/env bash\ncat >/dev/null\necho '{\"findings\": []}'\nexit 1\n")
        self.box.agent("quiet", report())
        self.box.line(["crashy", "quiet"], halt=True)
        ok, _ = self.box.run_line()
        self.assertFalse(ok)
        delta = self.box.findings("target-delta.md")
        self.assertIn("`quiet` | SKIPPED", delta)
        self.assertNotIn("Clean Delta", delta)

    def test_a_single_station_run_still_writes_the_target_report(self):
        self.box.agent("finder", report(finding(title="Solo")))
        self.box.run_agent("finder")
        self.assertIn("Solo", self.box.findings("target-delta.md"))

    def test_a_schemaless_agent_emitting_a_non_dict_finding_does_not_crash_or_halt(self):
        """agents-qw9: a schemaless agent (no output.schema) can emit a findings list of
        non-dicts; the dispatcher's findings re-sort must tolerate it like the store does
        (lib/findings.py skips non-dicts), never crash, still record a verdict, and not
        halt a line (vuln-triage is an andon_station)."""
        self.box.agent("junkfinder", json.dumps({"summary": "s", "scanned_files": 1,
                                                  "findings": ["not-a-dict"]}))
        self.box.agent("quiet", report())
        self.box.line(["junkfinder", "quiet"], halt=True)
        ok, out = self.box.run_line()

        self.assertTrue(ok, "a non-dict finding must not crash or error the station:\n" + out)
        delta = self.box.findings("target-delta.md")
        # The junk item is skipped (not a dict), so the station passes with zero findings.
        self.assertIn("`junkfinder` | PASS", delta)
        self.assertIn("`quiet` | PASS", delta)
        self.assertNotIn("SKIPPED", delta)


class TestNoVerdictIsAnError(SandboxCase):
    """fleet-ddd, journal-mid, journal-idy, journal-wog."""

    def test_fenced_report_with_a_fence_inside_a_string_parses(self):
        body = {"summary": "s", "findings": [finding(
            remediation="Add:\n```js\ntest('x', () => {});\n```\n")]}
        output = ("Here is my analysis {roughly}.\n\n```json\n" + json.dumps(body, indent=2)
                  + "\n```\n\nLet me know if you want more {details}.")
        self.assertEqual(factory_cli.extract_json_from_output(output), body)

    def test_leading_prose_and_a_trailing_object_pick_the_report(self):
        body = {"summary": "s", "findings": [finding()]}
        output = ("Reading {\"tool\": \"read\"} first.\n" + json.dumps(body)
                  + "\nStats: {\"tokens\": 12}")
        self.assertEqual(factory_cli.extract_json_from_output(output), body)

    def test_uppercase_fence_language_and_bom(self):
        body = {"summary": "s", "findings": []}
        output = "\ufeff```JSON\n" + json.dumps(body) + "\n```"
        self.assertEqual(factory_cli.extract_json_from_output(output), body)

    def test_no_json_at_all_is_none(self):
        self.assertIsNone(factory_cli.extract_json_from_output("All clean, nothing to report."))
        self.assertIsNone(factory_cli.extract_json_from_output("```json\n{broken\n```"))

    @unittest.skipUnless(_RUNNABLE_BWRAP, _NEEDS_BWRAP)
    def test_unparseable_output_raises_and_never_touches_the_store(self):
        self.box.agent("garbled", "Could not decide.")
        with self.assertRaises(factory_cli.StationError):
            self.box.run_agent("garbled")
        self.assertFalse((self.box.root / "findings" / "target.json").exists())

    @unittest.skipUnless(_RUNNABLE_BWRAP, _NEEDS_BWRAP)
    def test_an_object_without_findings_is_not_a_verdict(self):
        """A truncated report whose only decodable piece is an inner object."""
        truncated = json.dumps({"summary": "s", "findings": [{"a": {"b": 1}}]})[:-3]
        self.box.agent("truncated", truncated)
        with self.assertRaises(factory_cli.StationError):
            self.box.run_agent("truncated")

    @unittest.skipUnless(_RUNNABLE_BWRAP, _NEEDS_BWRAP)
    def test_a_failed_prepass_is_an_error_not_a_clean_short_circuit(self):
        self.box.agent("scanner", report(), short_circuit=True,
                       prepass="import sys\nsys.exit(3)\n")
        with self.assertRaises(factory_cli.StationError) as caught:
            self.box.run_agent("scanner")
        self.assertIn("pre-pass exited 3", str(caught.exception))

    @unittest.skipUnless(_RUNNABLE_BWRAP, _NEEDS_BWRAP)
    def test_a_failed_engine_is_an_error_even_with_output(self):
        self.box.agent("crashy", report())
        (self.box.bin / "pi").write_text("#!/usr/bin/env bash\ncat >/dev/null\necho '{\"findings\": []}'\nexit 1\n")
        with self.assertRaises(factory_cli.StationError):
            self.box.run_agent("crashy")

    @unittest.skipUnless(_RUNNABLE_BWRAP, _NEEDS_BWRAP)
    def test_the_cli_exits_non_zero_on_no_verdict(self):
        # agents-r2ne census: copies the factory BINARY (a non-station artefact), not station
        # code - the shared station-script builder does not apply.
        shutil.copyfile(ROOT / "factory", self.box.root / "factory")
        self.box.agent("garbled", "nothing parseable")
        env = dict(os.environ, PATH=f"{self.box.bin}{os.pathsep}/usr/bin:/bin")
        res = subprocess.run([sys.executable, str(self.box.root / "factory"), "run", "garbled",
                              "--target", str(self.box.target), "--engine", "pi", "--sink", "file"],
                             cwd=self.box.root, env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(res.returncode, 2, res.stderr)
        self.assertIn("no verdict", res.stderr)

    def test_a_named_target_with_a_missing_checkout_fails_loudly(self):
        (self.box.root / "targets").mkdir()
        (self.box.root / "targets" / "ghost.yaml").write_text(
            "name: ghost\npath: /nonexistent/ghost\n", encoding="utf-8")
        with self.box.patched():
            with self.assertRaises(FileNotFoundError):
                factory_cli.resolve_target("ghost")

    def test_a_target_overlapping_the_findings_store_is_refused(self):
        """agents-4zg round 4, agents-3da: a raw target whose path overlaps the findings store
        (equal, inside, or an ancestor) is rejected at resolution, so it cannot re-expose the store
        through its read-only bind. When targeting the factory root itself, the refusal includes
        actionable guidance."""
        findings = self.box.root / "findings"
        findings.mkdir()
        (findings / "sub").mkdir()
        with self.box.patched():
            with self.assertRaises(FileNotFoundError) as ctx_eq:
                factory_cli.resolve_target(str(findings))  # equal
            self.assertIn("refusing to scan a raw credential store as a target", str(ctx_eq.exception))
            self.assertNotIn("to audit the software factory itself", str(ctx_eq.exception))

            with self.assertRaises(FileNotFoundError) as ctx_in:
                factory_cli.resolve_target(str(findings / "sub"))  # inside
            self.assertIn("refusing to scan a raw credential store as a target", str(ctx_in.exception))
            self.assertNotIn("to audit the software factory itself", str(ctx_in.exception))

            # Ancestor that merely contains the findings directory (not the factory root itself)
            with self.assertRaises(FileNotFoundError) as ctx_anc:
                factory_cli.resolve_target(str(self.box.root.parent))  # ancestor containing findings
            self.assertIn("refusing to scan a raw credential store as a target", str(ctx_anc.exception))
            self.assertNotIn("to audit the software factory itself", str(ctx_anc.exception))

            # Self-target case: running against the factory root itself carries actionable guidance
            with self.assertRaises(FileNotFoundError) as ctx_self:
                factory_cli.resolve_target(str(self.box.root))  # self-target
            self.assertIn("refusing to scan a raw credential store as a target", str(ctx_self.exception))
            self.assertIn(
                "to audit the software factory itself, run the line from a different factory root, or point --target at a separate clean clone",
                str(ctx_self.exception),
            )

            # Named target pointing to the factory root also carries actionable guidance
            (self.box.root / "targets").mkdir(exist_ok=True)
            (self.box.root / "targets" / "self_target.yaml").write_text(
                f"name: self_target\npath: {self.box.root}\n", encoding="utf-8"
            )
            with self.assertRaises(FileNotFoundError) as ctx_named:
                factory_cli.resolve_target("self_target")
            self.assertIn("refusing to scan a raw credential store as a target", str(ctx_named.exception))
            self.assertIn(
                "to audit the software factory itself, run the line from a different factory root, or point --target at a separate clean clone",
                str(ctx_named.exception),
            )


class TestOneSeveritySource(SandboxCase):
    """journal-1kg, journal-35w, journal-y5m, journal-aaj."""

    def test_reported_severity(self):
        self.assertEqual(reported_severity({"severity": " High "}), "high")
        self.assertEqual(reported_severity({}), "unclassified")
        self.assertEqual(reported_severity({"severity": "urgent"}), "unclassified")
        self.assertEqual(reported_severity({"severity": "critical", "false_positive": True}), "info")

    def test_false_positive_detection(self):
        self.assertTrue(is_false_positive({"title": "Scanner entry point config.ts:433 is a "
                                                    "false positive (comment, not a network call)"}))
        self.assertTrue(is_false_positive({"verdict": "false_positive"}))
        self.assertTrue(is_false_positive({"false_positive": True}))
        self.assertFalse(is_false_positive({"title": "This is not a false positive"}))
        self.assertFalse(is_false_positive({"title": "SQL injection", "status": "new"}))

    @unittest.skipUnless(_RUNNABLE_BWRAP, _NEEDS_BWRAP)
    def test_store_and_andon_agree_and_fps_are_not_critical(self):
        fp = finding(rule_id="r2", severity="critical", snippet="// fetch(url)",
                     title="config.ts:433 is a false positive (comment, not a network call)")
        real = finding(rule_id="r3", severity="critical", snippet="eval(x)", title="Real RCE")
        low = finding(rule_id="r4", severity="low", snippet="y", title="Minor")
        self.box.agent("vuln-triage", report(fp, real, low))
        self.box.line(["vuln-triage"])
        _, out = self.box.run_line()

        row = next(l for l in out.splitlines() if l.startswith("vuln-triage"))
        self.assertEqual(row.split()[1:], ["ALERT", "2", "1"])
        store = json.loads(self.box.findings("target.json"))["findings"]
        by_title = {f["title"]: f for f in store.values()}
        # The store records the triaged severity; routing stays fail-closed for vuln agents.
        self.assertEqual(by_title["Minor"]["severity"], "low")
        self.assertEqual(by_title["Minor"]["routing_severity"], "critical")
        self.assertEqual(sum(f["severity"] == "critical" for f in store.values()), 1)
        fp_record = next(f for f in store.values() if f["false_positive"])
        self.assertEqual(fp_record["severity"], "info")

        delta = self.box.findings("target-delta.md")
        self.assertIn("[CRITICAL] Real RCE", delta)
        self.assertIn("[LOW · routed critical] Minor", delta)
        self.assertIn("Triaged False Positives", delta)
        action = delta.split("## Action Required")[1].split("## ")[0]
        self.assertNotIn("false positive", action)
        self.assertEqual(json.loads(self.box.findings("target-line.json"))["stats"]["new"], 2)

    @unittest.skipUnless(_RUNNABLE_BWRAP, _NEEDS_BWRAP)
    def test_a_secret_scan_info_verdict_does_not_read_critical(self):
        """journal-aaj: triage downgraded to info; the report still said CRITICAL."""
        item = finding(rule_id="openai-key", severity="info", verdict="false_positive",
                       snippet="#disk-quota-for-buffered-reports")
        self.box.agent("secret-scan", report(item))
        self.box.run_agent("secret-scan")
        delta = self.box.findings("target-delta.md")
        self.assertIn("Triaged False Positives", delta)
        self.assertNotIn("CRITICAL", delta)
        self.assertNotIn("Action Required", delta)


class TestStableFingerprints(unittest.TestCase):
    """fleet-oed: a byte-identical file must not book new+fixed churn."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="factory-fp-")
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        cands = self.dir / "candidates.json"
        cands.write_text(json.dumps({"candidates": [
            {"rule_id": "openai-key", "path": "v151/index.html", "line_number": 156,
             "snippet": "<a href=\"#x\">sk-abcdefghijklmnopqrstu</a>"}]}), encoding="utf-8")
        self.index = load_candidate_index(cands)

    def run_with(self, store, snippet, line=156):
        return store.process_run("secret-scan", [{
            "rule_id": "openai-key", "path": "v151/index.html", "line_number": line,
            "snippet": snippet, "severity": "low", "title": "t"}], self.index)

    def test_a_requoted_snippet_is_unchanged_not_new_and_fixed(self):
        store = FindingsStore("t", findings_dir=self.dir)
        self.run_with(store, "sk-abcdefghijklmnopqrstu")
        _, stats, _ = self.run_with(store, "sk-abc***[masked]")
        self.assertEqual((stats["new"], stats["fixed"], stats["unchanged"]), (0, 0, 1))

    def test_a_legacy_fingerprint_is_migrated_without_churn(self):
        store = FindingsStore("t", findings_dir=self.dir)
        # A store written by the old identity (no candidate binding of the snippet).
        store.process_run("secret-scan", [{"rule_id": "openai-key", "path": "v151/index.html",
                                           "snippet": "model quote", "severity": "low",
                                           "title": "t"}], None)
        _, stats, _ = self.run_with(store, "model quote")
        self.assertEqual((stats["new"], stats["fixed"], stats["unchanged"]), (0, 0, 1))
        self.assertEqual(len(store.data["findings"]), 1)


class TestPrepassArgvIsolation(unittest.TestCase):
    """agents-nei P1-1: --target-name must reach only perf-hillclimb's pre-pass, never the
    other agents' pre-passes (which use argparse without that option and would exit)."""

    def test_prepass_argv_adds_target_name_only_for_perf_hillclimb(self):
        secret = factory_cli._prepass_argv(
            Path("prepass.py"), Path("/tmp/read"), "target", Path("/tmp/candidates.json"),
            "secret-scan")
        self.assertIn("--target", secret)
        self.assertIn("--output", secret)
        self.assertNotIn("--target-name", secret)

        hc = factory_cli._prepass_argv(
            Path("measure_and_context.py"), Path("/tmp/read"), "target",
            Path("/tmp/candidates.json"), "perf-hillclimb")
        self.assertIn("--target-name", hc)
        self.assertEqual(hc[hc.index("--target-name") + 1], "target")

    def test_secret_scan_prepass_runs_with_the_dispatcher_argv(self):
        """The real secret-scan pre-pass must accept the dispatcher's argv (fail-on-revert: an
        injected --target-name would make argparse exit 2)."""
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "target"
            target.mkdir()
            (target / "index.html").write_text("<html>no secrets</html>\n", encoding="utf-8")
            out = Path(tmp) / "candidates.json"
            script = ROOT / "agents" / "secret-scan" / "scripts" / "scan.py"
            argv = factory_cli._prepass_argv(script, target, "target", out, "secret-scan")
            res = subprocess.run(argv, capture_output=True, text=True, timeout=60)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertTrue(out.exists())


class TestSkillsInstallHelpCount(unittest.TestCase):
    """agents-074: the skills install help must compute its station count from
    agents/*/agent.yaml at parser-build time, not a hardcoded literal, and must not
    crash when agents/ is absent."""

    def _skills_help(self, factory_root: Path) -> str:
        """Build the parser against a temp factory root and return `skills --help` output."""
        out = io.StringIO()
        with mock.patch.object(factory_cli, "FACTORY_ROOT", factory_root):
            with mock.patch.object(sys, "argv", ["factory", "skills", "--help"]):
                with mock.patch("sys.stdout", out):
                    with self.assertRaises(SystemExit) as cm:
                        factory_cli.main()
        self.assertEqual(cm.exception.code, 0)
        return out.getvalue()

    def test_help_count_follows_the_agents_directory(self):
        """The rendered count must equal the number of station dirs, not a literal 22."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            agents = root / "agents"
            agents.mkdir()
            for name in ("alpha", "beta", "gamma"):
                d = agents / name
                d.mkdir()
                (d / "agent.yaml").write_text(
                    "name: x\nclass: observer\n", encoding="utf-8")
            out = self._skills_help(root)
            self.assertIn("Symlink all 3 factory skills", out)
            self.assertNotIn("Symlink all 22 factory skills", out)

    def test_help_renders_zero_and_does_not_crash_when_agents_is_absent(self):
        """No agents/ dir must not crash parser build; the count renders as 0."""
        with tempfile.TemporaryDirectory() as tmp:
            out = self._skills_help(Path(tmp))
            self.assertIn("Symlink all 0 factory skills", out)

    def test_help_matches_the_real_station_catalog(self):
        """Against the real checkout the rendered count equals the actual station count."""
        real = sum(1 for p in (ROOT / "agents").iterdir()
                   if p.is_dir() and (p / "agent.yaml").exists())
        res = subprocess.run([sys.executable, str(ROOT / "factory"),
                              "skills", "--help"],
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn(f"Symlink all {real} factory skills into ~/.gemini and ~/.claude",
                      res.stdout)


# A pre-pass that writes __N__ candidates, so the prompt slice and the triage count are real.
PREPASS_CANDIDATES = (
    "import argparse, json\n"
    "p = argparse.ArgumentParser()\n"
    "p.add_argument('--target'); p.add_argument('--output'); p.add_argument('--target-name', dest='tn')\n"
    "a = p.parse_args()\n"
    "c = [{'candidate_id': 'c%d' % i, 'rule_id': 'r1', 'path': 'a%d.js' % i,\n"
    "      'line_number': i + 1, 'snippet': 'x = 1'} for i in range(__N__)]\n"
    "json.dump({'candidate_id_scheme': 1, 'candidate_count': len(c), 'candidates': c},\n"
    "          open(a.output, 'w'))\n"
)


def prepass(n):
    return PREPASS_CANDIDATES.replace("__N__", str(n))


def candidates(n):
    """n distinct findings, one per candidate - what a COMPLETE triage of n candidates looks like.

    The rows CITE the ids the stub pre-pass emits (`c%d`, PREPASS_CANDIDATES): since agents-w9ni the check
    compares candidate ids wherever the pre-pass supplies them, so a stub that listed n rows without naming
    a candidate would be a fixture for an unaccounted report, not for a complete triage.
    """
    return report(*[finding(rule_id=f"r1", path=f"a{i}.js", line_number=i + 1, title=f"F{i}",
                            candidate_id=f"c{i}")
                    for i in range(n)])


@unittest.skipUnless(_RUNNABLE_BWRAP, _NEEDS_BWRAP)
class TestPartialTriageIsNotACleanResult(SandboxCase):
    """agents-xx9t: PASS required only the absence of criticals, so a repair-retry that triaged 8 of 49
    candidates printed `perf-review PASS 8 0`, set complete: true in the line JSON and wrote a PASS row in
    the delta report. Outcome (what the station found) and validity (whether it looked at what it was given)
    are two facts, and one field cannot carry both.

    Both directions are driven, because a fix that makes every run INCOMPLETE is the same defect mirrored.
    """

    def test_a_partial_triage_renders_incomplete_with_its_counts(self):
        self.box.agent("partial", candidates(8), prepass=prepass(49))
        self.box.line(["partial"])
        ok, out = self.box.run_line()

        self.assertFalse(ok, "a station that triaged 8 of 49 candidates must not report a clean line")
        self.assertIn("INCOMPLETE", out)
        self.assertIn("8 of 49", out)
        delta = self.box.findings("target-delta.md")
        # Counts are unknown to the verdict machinery (INCOMPLETE is not in VERDICT_STATUSES), so the row keeps
        # the dash convention and the counts ride in the note and the banner.
        self.assertIn("| `partial` | INCOMPLETE | — | — |", delta)
        self.assertIn("cited 8 of the 49 candidate id(s) shown (49 found by the pre-pass)", delta)
        self.assertIn("`partial` (8 of 49 shown, identity-matched)", delta)
        self.assertIn("A partial triage is not a clean result", delta)
        self.assertNotIn("produced no verdict", delta)  # one banner, not two for one station
        self.assertNotIn("Clean Delta", delta)
        machine = json.loads(self.box.findings("target-line.json"))
        self.assertFalse(machine["complete"])
        station = machine["stations"][0]
        self.assertEqual(station["candidates_in"], 49)
        self.assertEqual(station["candidates_presented"], 49)
        self.assertEqual(station["candidates_accounted"], 8)
        self.assertIs(station["complete"], False)

    def test_a_complete_triage_of_the_same_input_still_reads_pass(self):
        self.box.agent("whole", candidates(49), prepass=prepass(49))
        self.box.line(["whole"])
        ok, out = self.box.run_line()

        self.assertTrue(ok, "a complete triage with no criticals must still pass")
        self.assertNotIn("INCOMPLETE", out)
        delta = self.box.findings("target-delta.md")
        self.assertIn("`whole` | PASS | 49", delta)
        self.assertNotIn("partial triage", delta)
        machine = json.loads(self.box.findings("target-line.json"))
        self.assertTrue(machine["complete"])
        self.assertIs(machine["stations"][0]["complete"], True)

    def test_a_station_is_judged_on_the_candidates_it_was_shown_not_the_tail(self):
        """The prompt carries CANDIDATE_PROMPT_SLICE candidates (factory:1683). A station whose pre-pass
        found more than that cannot be marked incomplete for the tail it never received."""
        self.box.agent("sliced", candidates(50), prepass=prepass(77))
        self.box.line(["sliced"])
        ok, out = self.box.run_line()

        self.assertTrue(ok, "triaging everything it was shown is a complete triage")
        machine = json.loads(self.box.findings("target-line.json"))
        station = machine["stations"][0]
        self.assertEqual((station["candidates_in"], station["candidates_presented"],
                          station["candidates_accounted"]), (77, 50, 50))
        self.assertIs(station["complete"], True)

    def test_vuln_verify_accounts_for_verifications_not_only_published_findings(self):
        """Disproved candidates belong to verifications[], not findings[].

        A fabricated 50-row findings[] list must not substitute for 50 actual
        verification verdicts; a missing verification must remain incomplete.
        """
        rows = [{"candidate_id": f"c{i}", "verdict": "disproved"} for i in range(50)]
        self.box.agent("vuln-verify", report(), prepass=prepass(50))
        self.box.line(["vuln-verify"])
        for verifications, findings, expected_status, accounted in (
            (rows, [], "PASS", 50),
            (rows[:-1], [], "INCOMPLETE", 49),
            ([], [finding(candidate_id=f"c{i}") for i in range(50)], "INCOMPLETE", 0),
        ):
            with self.subTest(expected_status=expected_status, accounted=accounted):
                output = json.dumps({"summary": "verified", "verifications": verifications,
                                     "findings": findings})
                (self.box.root / "outputs" / "vuln-verify.txt").write_text(output, encoding="utf-8")
                ok, _ = self.box.run_line()
                station = json.loads(self.box.findings("target-line.json"))["stations"][0]
                self.assertEqual(station["status"], expected_status)
                self.assertEqual(station["candidates_accounted"], accounted)
                self.assertEqual(station["candidate_identity"], "identity-matched")
                self.assertEqual(ok, expected_status == "PASS")
                if expected_status == "PASS":
                    stored = json.loads(self.box.findings("target.json"))
                    self.assertEqual(len(stored["verifications"]), 50,
                                     "verification dispositions must outlive run-dir pruning")
                    self.assertEqual(stored["findings"], {},
                                     "do not invent dismissal findings to make triage durable")

    def test_vuln_verify_linked_critical_verdict_still_alerts(self):
        schema = json.loads((ROOT / "agents" / "vuln-verify" / "report.schema.json").read_text())
        (self.box.target / "a.js").write_text("x = 1\n", encoding="utf-8")
        output = {"summary": "verified", "target": "target",
                  "verifications": [{"rule_id": "r1", "path": "a.js", "line_number": 1,
                                     "candidate_id": "c0", "verdict": "verified",
                                     "confidence": "high", "reasoning": "Reachable"}],
                  "findings": [finding(candidate_id="c0", severity="critical")]}
        self.box.agent("vuln-verify", json.dumps(output), prepass=prepass(1), report_schema=schema)
        self.box.line(["vuln-verify"])
        ok, _ = self.box.run_line()
        station = json.loads(self.box.findings("target-line.json"))["stations"][0]
        self.assertTrue(ok, "ALERT is a complete verdict, not an incomplete line")
        self.assertEqual((station["status"], station["criticals"], station["candidates_accounted"]),
                         ("ALERT", 1, 1))

    def test_vuln_verify_orphan_verified_verdict_never_changes_the_store(self):
        """A schema-valid orphan verdict is rejected before it can fix an existing finding."""
        schema = json.loads((ROOT / "agents" / "vuln-verify" / "report.schema.json").read_text())
        (self.box.target / "a.js").write_text("x = 1\n", encoding="utf-8")
        verified = {"rule_id": "r1", "path": "a.js", "line_number": 1,
                    "candidate_id": "c0", "verdict": "verified", "confidence": "high",
                    "reasoning": "Reachable"}
        good = {"summary": "verified", "target": "target", "verifications": [verified],
                "findings": [finding(candidate_id="c0")]}
        self.box.agent("vuln-verify", json.dumps(good), prepass=prepass(1), report_schema=schema)
        self.box.run_agent("vuln-verify")
        store = self.box.root / "findings" / "target.json"
        before = store.read_text(encoding="utf-8")

        bad = {**good, "findings": []}
        (self.box.root / "outputs" / "vuln-verify.txt").write_text(json.dumps(bad), encoding="utf-8")
        with self.assertRaisesRegex(factory_cli.NoVerdictError, "matching candidate_id"):
            self.box.run_agent("vuln-verify")
        self.assertEqual(store.read_text(encoding="utf-8"), before,
                         "a rejected report must not mark a confirmed finding fixed")

    def test_vuln_verify_disproved_critical_finding_is_rejected_before_store(self):
        """agents-led6d: a critical finding cannot publish against a disproved verdict."""
        schema = json.loads((ROOT / "agents" / "vuln-verify" / "report.schema.json").read_text())
        (self.box.target / "a.js").write_text("x = 1\n", encoding="utf-8")
        verification = {"rule_id": "r1", "path": "a.js", "line_number": 1,
                        "candidate_id": "c0", "verdict": "verified", "confidence": "high",
                        "reasoning": "Reachable"}
        good = {"summary": "verified", "target": "target", "verifications": [verification],
                "findings": [finding(candidate_id="c0", severity="critical")]}
        self.box.agent("vuln-verify", json.dumps(good), prepass=prepass(1), report_schema=schema)
        self.box.run_agent("vuln-verify")
        store = self.box.root / "findings" / "target.json"
        before = store.read_text(encoding="utf-8")

        bad = {**good, "verifications": [{**verification, "verdict": "disproved"}]}
        (self.box.root / "outputs" / "vuln-verify.txt").write_text(json.dumps(bad), encoding="utf-8")
        with self.assertRaisesRegex(factory_cli.NoVerdictError, "matching 'verified' verdict"):
            self.box.run_agent("vuln-verify")
        self.assertEqual(store.read_text(encoding="utf-8"), before,
                         "a contradictory report must not publish or transition findings")

    def test_a_partial_triage_with_nothing_new_never_claims_a_clean_delta(self):
        """agents-kve2: the exact shape of the six runs - 49 shown, 0 accounted, nothing new. The Clean
        Delta branch was an elif of the no-verdict banner with no coverage check, so the report said both
        'INCOMPLETE' and 'Clean Delta', and the header counted the station as having a verdict."""
        self.box.agent("zero", report(), prepass=prepass(49))
        self.box.line(["zero"])
        _, out = self.box.run_line()

        delta = self.box.findings("target-delta.md")
        self.assertIn("did not account for the candidates they were shown", delta)
        self.assertIn("`zero` (0 of 49 shown, identity-matched)", delta)
        self.assertNotIn("Clean Delta", delta)
        self.assertIn("1 station(s), 0 with a verdict", delta)
        self.assertNotIn("produced no verdict", delta)          # one banner per station, not two
        self.assertNotIn("produced no verdict", out)
        self.assertIn("0 of 49", out)

    def test_a_complete_run_with_nothing_new_still_reads_clean_delta(self):
        """The mirror: suppressing the clean banner for genuinely complete runs would be the same error
        reversed. A pre-pass that found nothing, and a fully triaged all-false-positive scan, are both
        complete - and a complete scan with nothing new is allowed to say so."""
        self.box.agent("empty", report(), prepass=prepass(0))
        self.box.line(["empty"])
        _, _ = self.box.run_line()
        self.assertIn("Clean Delta", self.box.findings("target-delta.md"))

        self.box.agent("noisy", report(*[finding(rule_id="r1", path=f"b{i}.js", line_number=i + 1,
                                                title=f"F{i}", verdict="false_positive",
                                                candidate_id=f"c{i}")
                                        for i in range(3)]), prepass=prepass(3))
        self.box.line(["noisy"])
        _, _ = self.box.run_line()
        noisy = self.box.findings("target-delta.md")   # the LINE report carries the station table
        self.assertIn("Clean Delta", noisy)
        self.assertNotIn("did not account", noisy)
        row = next(l for l in noisy.splitlines() if l.startswith("| `noisy`"))
        self.assertIn("PASS", row)

    def test_a_critical_still_alerts_when_the_triage_is_partial(self):
        """The alarm is the outcome and must not be softened by the coverage fact - but the coverage is
        still recorded, so the reader sees both."""
        self.box.agent("bad", report(finding(severity="critical", title="Real RCE")),
                       prepass=prepass(49))
        self.box.line(["bad"])
        _, out = self.box.run_line()

        delta = self.box.findings("target-delta.md")
        self.assertIn("`bad` | ALERT |", delta)
        machine = json.loads(self.box.findings("target-line.json"))
        station = machine["stations"][0]
        self.assertEqual(station["status"], "ALERT")
        self.assertIs(station["complete"], False)
        self.assertIn("49", out)

    def test_a_station_without_a_pre_pass_is_judged_exactly_as_before(self):
        """No candidates.json is not zero candidates: completeness cannot be asserted, so nothing changes."""
        self.box.agent("noprepass", candidates(2))
        self.box.line(["noprepass"])
        ok, _ = self.box.run_line()

        self.assertTrue(ok)
        station = json.loads(self.box.findings("target-line.json"))["stations"][0]
        self.assertIsNone(station["candidates_presented"])
        self.assertIs(station["complete"], True)


@unittest.skipUnless(_RUNNABLE_BWRAP, _NEEDS_BWRAP)
class TestAggregateClaimedLineJudge(SandboxCase):
    """agents-88cd: drive real station->line scores, not a hand-built scorecard."""

    def station(self, output, *, mode="aggregate-claimed", schema=None, n=2):
        directory = self.box.root / "agents" / "grouped"
        if directory.exists():
            (directory / "scripts" / "prepass.py").write_text(prepass(n), encoding="utf-8")
            (self.box.root / "outputs" / "grouped.txt").write_text(output, encoding="utf-8")
        else:
            self.box.agent("grouped", output, prepass=prepass(n), candidate_accounting=mode,
                           report_schema=schema)
        self.box.line(["grouped"])
        ok, out = self.box.run_line()
        machine = json.loads(self.box.findings("target-line.json"))
        return ok, out, machine["stations"][0]

    def test_two_to_one_claim_passes_and_mapping_is_durable_not_verified_grouping(self):
        row = finding(covered_candidate_ids=["c0", "c1"], anchor_candidate_id="c0")
        ok, out, station = self.station(report(row))
        self.assertTrue(ok, out)
        self.assertEqual((station["status"], station["candidate_identity"],
                          station["candidates_accounted"]), ("PASS", "identity-claimed-aggregate", 2))
        self.assertEqual(station["candidate_claims"], [
            {"row_index": 0, "covered_candidate_ids": ["c0", "c1"],
             "anchor_candidate_id": "c0"}])
        self.assertIn("(2/2, identity-claimed-aggregate)", self.box.findings("target-delta.md"))
        run_dir = Path(station["run_dir"])
        self.assertEqual(json.loads((run_dir / "report.json").read_text())["findings"][0]
                         ["covered_candidate_ids"], ["c0", "c1"])

    def test_dismissal_with_claimed_ids_and_no_echo_is_complete(self):
        dismissed = finding(false_positive=True, severity="info", covered_candidate_ids=["c0", "c1"])
        ok, out, station = self.station(report(dismissed))
        self.assertTrue(ok, out)
        self.assertEqual((station["status"], station["findings_count"],
                          station["candidates_accounted"]), ("PASS", 0, 2))
        self.assertIsNone(station["candidate_claims"][0]["anchor_candidate_id"])

    def test_echo_alone_is_incomplete_and_an_alert_still_carries_incompleteness(self):
        _, out, station = self.station(report(finding(anchor_candidate_id="c0")), n=1)
        self.assertEqual((station["status"], station["complete"], station["candidates_accounted"]),
                         ("INCOMPLETE", False, 0))
        self.assertIn("covered_candidate_ids", station["note"])
        self.assertNotIn("produced no verdict", out)
        _, _, alert = self.station(report(finding(severity="critical", covered_candidate_ids=["c0"])))
        self.assertEqual((alert["status"], alert["complete"]), ("ALERT", False))
        self.assertIn("missing", alert["note"])

    def test_unknown_manifest_declaration_refused_before_run(self):
        ok, out, station = self.station(report(), mode="aggregate-claimd", n=1)
        self.assertFalse(ok)
        self.assertEqual(station["status"], "ERROR")
        self.assertIn("unsupported candidate_accounting", station["error"])
        self.assertNotIn("candidate_claims", station)
        self.assertFalse((self.box.root / "runs").exists(), "refusal precedes any pre-pass or engine run")

    def test_schema_invalid_is_no_verdict_not_coverage_incomplete(self):
        schema = {"type": "object", "required": ["summary", "findings"],
                  "properties": {"summary": {"type": "string"},
                                 "findings": {"type": "array", "items": {"type": "object",
                                     "properties": {"covered_candidate_ids": {"type": "array",
                                                                         "items": {"type": "string"}}}}}}}
        _, _, omitted = self.station(report(finding()), schema=schema, n=1)
        self.assertEqual(omitted["status"], "INCOMPLETE", "schema-valid omission reaches coverage judge")
        self.assertFalse(omitted["complete"])
        self.assertIn("covered_candidate_ids", omitted["note"])
        # The same declared field with the wrong shape is a schema failure on
        # BOTH bounded attempts. A malformed report does not enter coverage.
        _, _, invalid = self.station(report(finding(covered_candidate_ids="c0")), schema=schema, n=1)
        self.assertEqual(invalid["status"], "ERROR")
        self.assertIn("no verdict", invalid["error"])
        self.assertNotIn("candidate_claims", invalid)

    def test_non_object_report_row_is_not_an_empty_clean_aggregate(self):
        ok, _, station = self.station(json.dumps({"summary": "s", "findings": ["not-a-row"]}), n=0)
        self.assertFalse(ok)
        self.assertEqual(station["status"], "INCOMPLETE")
        self.assertIn("expected a finding object", station["note"])
        self.assertFalse(json.loads(self.box.findings("target-line.json"))["complete"])

    def test_old_row_mode_fixtures_keep_the_same_scores_and_no_claims_key(self):
        ok, _, row = self.station(candidates(2), mode="row", n=2)
        self.assertTrue(ok)
        self.assertEqual((row["status"], row["candidate_identity"], row["candidates_accounted"]),
                         ("PASS", "identity-matched", 2))
        self.assertNotIn("candidate_claims", row)
        # An old producer with no ids must still take the weaker count-only
        # route and SAY that it did, not inherit the opt-in aggregate judge.
        no_ids = ("import argparse,json\n"
                  "p=argparse.ArgumentParser();p.add_argument('--target');p.add_argument('--output');a=p.parse_args()\n"
                  "json.dump({'candidates':[{'rule_id':'r','path':'a.js','line_number':1}]},open(a.output,'w'))\n")
        self.box.agent("legacy", report(finding()), prepass=no_ids)
        self.box.line(["legacy"])
        ok, _ = self.box.run_line()
        self.assertTrue(ok)
        legacy = json.loads(self.box.findings("target-line.json"))["stations"][0]
        self.assertEqual((legacy["status"], legacy["candidate_identity"],
                          legacy["candidates_accounted"]), ("PASS", "count-only", 1))
        self.assertNotIn("candidate_claims", legacy)


if __name__ == "__main__":
    unittest.main()
