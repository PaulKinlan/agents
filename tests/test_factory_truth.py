#!/usr/bin/env python3
"""A station that produced no verdict never reads as clean (fleet-810, fleet-ddd, journal-*).

These drive the real dispatcher (`factory`), the real findings CLI and the real line runner in
a sandbox, with a stub `pi` that prints a per-agent canned model output. They pin:

- the run's delta report is written once by the line, from every station (fleet-810);
- model output wrapped in fences/prose still parses; output that does not is ERROR (fleet-ddd,
  journal-mid), as is a failed pre-pass or engine (journal-idy, journal-wog);
- the stored, displayed and andon-counted severity is the triaged one; the fail-closed routing
  value only routes (journal-1kg, journal-35w, journal-y5m, journal-aaj);
- tracker sinks report what they did, so `--sink beads` filing nothing is explained
  (fleet-eqv, journal-np8);
- fingerprints bind to the scanner's snippet, so a re-quoted line is not new+fixed churn
  (fleet-oed).
"""

import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
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

from lib.embargo import is_false_positive, reported_severity  # noqa: E402
from lib.findings import FindingsStore, load_candidate_index  # noqa: E402

_loader = importlib.machinery.SourceFileLoader("factory_cli_truth", str(ROOT / "factory"))
_spec = importlib.util.spec_from_loader("factory_cli_truth", _loader)
factory_cli = importlib.util.module_from_spec(_spec)
_loader.exec_module(factory_cli)

LIB_MODULES = ("findings.py", "redaction.py", "embargo.py", "budget.py", "child_env.py",
               "report_schema.py", "containment.py")


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
        self.box.agent("garbled", "no json here")
        self.box.agent("quiet", report())
        self.box.line(["garbled", "quiet"], halt=True)
        ok, _ = self.box.run_line()
        self.assertFalse(ok)
        delta = self.box.findings("target-delta.md")
        self.assertIn("`quiet` | SKIPPED", delta)
        self.assertNotIn("Clean Delta", delta)

    def test_a_single_station_run_still_writes_the_target_report(self):
        self.box.agent("finder", report(finding(title="Solo")))
        self.box.run_agent("finder")
        self.assertIn("Solo", self.box.findings("target-delta.md"))


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

    def test_unparseable_output_raises_and_never_touches_the_store(self):
        self.box.agent("garbled", "Could not decide.")
        with self.assertRaises(factory_cli.StationError):
            self.box.run_agent("garbled")
        self.assertFalse((self.box.root / "findings" / "target.json").exists())

    def test_an_object_without_findings_is_not_a_verdict(self):
        """A truncated report whose only decodable piece is an inner object."""
        truncated = json.dumps({"summary": "s", "findings": [{"a": {"b": 1}}]})[:-3]
        self.box.agent("truncated", truncated)
        with self.assertRaises(factory_cli.StationError):
            self.box.run_agent("truncated")

    def test_a_failed_prepass_is_an_error_not_a_clean_short_circuit(self):
        self.box.agent("scanner", report(), short_circuit=True,
                       prepass="import sys\nsys.exit(3)\n")
        with self.assertRaises(factory_cli.StationError) as caught:
            self.box.run_agent("scanner")
        self.assertIn("pre-pass exited 3", str(caught.exception))

    def test_a_failed_engine_is_an_error_even_with_output(self):
        self.box.agent("crashy", report())
        (self.box.bin / "pi").write_text("#!/usr/bin/env bash\necho '{\"findings\": []}'\nexit 1\n")
        with self.assertRaises(factory_cli.StationError):
            self.box.run_agent("crashy")

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


class TestSinkAccounting(SandboxCase):
    """fleet-eqv, journal-np8: --sink beads filing nothing must say why."""

    def test_embargoed_findings_are_counted_and_reported(self):
        (self.box.target / ".beads").mkdir()
        bd = self.box.bin / "bd"
        bd.write_text("#!/usr/bin/env bash\nif [ \"$1\" = list ]; then echo '[]'; exit 0; fi\n"
                      f"echo \"$@\" >> '{self.box.root}/bd.log'\n")
        bd.chmod(0o755)
        items = [finding(rule_id="a", severity="high", snippet="1", title="High one"),
                 finding(rule_id="b", severity="medium", snippet="2", title="Medium one"),
                 finding(rule_id="c", severity="low", snippet="3", title="Low one")]
        self.box.agent("lint", report(*items))
        self.box.line(["lint"])
        with mock.patch.dict(os.environ, {"HOME": str(self.box.root)}):
            out = io.StringIO()
            with self.box.patched(), contextlib.redirect_stdout(out):
                factory_cli.run_line("testline", str(self.box.target), engine_arg="pi",
                                     explicit_sink="beads")
        self.assertEqual((self.box.root / "bd.log").read_text().count("create --title"), 1)
        delta = self.box.findings("target-delta.md")
        self.assertIn("**beads**: published 1, failed 0, duplicate 0, embargoed 1, below band 1", delta)
        machine = json.loads(self.box.findings("target-line.json"))
        self.assertEqual(machine["sinks"]["beads"]["published"], 1)
        self.assertEqual(machine["sinks"]["beads"]["embargoed"], 1)

    def test_a_missing_beads_dir_is_a_reported_failure(self):
        self.box.agent("lint", report(finding()))
        self.box.run_agent("lint", sink="beads")
        delta = self.box.findings("target-delta.md")
        self.assertIn("failed 1", delta)
        self.assertIn("no .beads directory", delta)


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


if __name__ == "__main__":
    unittest.main()
