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
               "tool_pins.py")


def finding(**overrides):
    base = {"rule_id": "r1", "path": "a.js", "line_number": 1, "snippet": "x = 1",
            "severity": "medium", "title": "A finding", "description": "d",
            "remediation": "fix"}
    base.update(overrides)
    return base


def report(*findings):
    return json.dumps({"summary": "stub", "scanned_files": 1, "findings": list(findings)})


class Sandbox:
    """A factory root with probe agents whose model output is a file we control."""

    def __init__(self, root: Path):
        self.root = root
        self.target = root / "target"
        self.target.mkdir()
        (root / "lib" / "adapters").mkdir(parents=True)
        adapter = root / "lib" / "adapters" / "pi.sh"
        shutil.copyfile(ROOT / "lib" / "adapters" / "pi.sh", adapter)
        adapter.chmod(adapter.stat().st_mode | stat.S_IEXEC)
        for module in LIB_MODULES:
            shutil.copyfile(ROOT / "lib" / module, root / "lib" / module)
            # Sink adapters (fleet-km8): findings.py delegates delivery to lib/sinks.
            shutil.copytree(ROOT / "lib" / "sinks", root / "lib" / "sinks", dirs_exist_ok=True)
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

    def agent(self, name, output, prepass=None, short_circuit=False):
        directory = self.root / "agents" / name
        (directory / "scripts").mkdir(parents=True)
        (directory / "agent.yaml").write_text(
            f"name: {name}\nclass: observer\ncontainment: t0-readonly\n"
            f"short_circuit_empty: {'true' if short_circuit else 'false'}\n"
            "budget: {max_minutes: 1}\n", encoding="utf-8")
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
        """agents-4zg round 4: a raw target whose path overlaps the findings store (equal,
        inside, or an ancestor) is rejected at resolution, so it cannot re-expose the store
        through its read-only bind."""
        findings = self.box.root / "findings"
        findings.mkdir()
        (findings / "sub").mkdir()
        with self.box.patched():
            with self.assertRaises(FileNotFoundError):
                factory_cli.resolve_target(str(findings))  # equal
            with self.assertRaises(FileNotFoundError):
                factory_cli.resolve_target(str(findings / "sub"))  # inside
            with self.assertRaises(FileNotFoundError):
                factory_cli.resolve_target(str(self.box.root))  # ancestor (contains it)


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
    agents/*/agent.yaml, not a hardcoded literal, so it cannot drift from the catalog."""

    def test_skills_install_help_reports_the_real_station_count(self):
        real = sum(1 for p in (ROOT / "agents").iterdir()
                   if p.is_dir() and (p / "agent.yaml").exists())
        res = subprocess.run([sys.executable, str(ROOT / "factory"),
                              "skills", "--help"],
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn(f"Symlink all {real} factory skills into ~/.gemini and ~/.claude",
                      res.stdout)


if __name__ == "__main__":
    unittest.main()
