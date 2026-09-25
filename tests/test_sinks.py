#!/usr/bin/env python3
"""Drive the real findings CLI with isolated, recording bd/gh executables.

No credentials, network calls, live databases, or public test issues are used.
The stand-ins record the process boundary; they do not verify service-side APIs.
"""

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from lib.findings import compute_fingerprint

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = {
    "rule_id": "unused-export",
    "path": "./src/example.py",
    "line_number": 12,
    "snippet": "unused = True",
    "severity": "medium",
    "title": "Unused export",
    "description": "Synthetic sink verification finding.",
    "remediation": "Remove the unused export.",
}


class TestFingerprints(unittest.TestCase):
    def test_documented_sha256_and_normalization(self):
        expected = hashlib.sha256(
            b"lint:unused-export:src/example.py:unused = True"
        ).hexdigest()
        self.assertEqual(
            compute_fingerprint("lint", "unused-export", " ./src\\example.py ",
                                "  unused  = True\n"),
            expected,
        )

    def test_identity_fields_are_not_ignored(self):
        original = ["lint", "unused-export", "src/example.py", "unused = True"]
        fingerprint = compute_fingerprint(*original)
        for index in range(len(original)):
            with self.subTest(field=index):
                changed = original.copy()
                changed[index] += "-different"
                self.assertNotEqual(compute_fingerprint(*changed), fingerprint)


class TestSinks(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="factory-sinks-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.factory = self.root / "factory"
        (self.factory / "lib").mkdir(parents=True)
        self.cli = self.factory / "lib" / "findings.py"
        shutil.copyfile(ROOT / "lib" / "findings.py", self.cli)
        # findings.py renders every published finding through lib.redaction and applies the
        # publication embargo from lib.embargo, so the sandbox needs both modules too (the
        # imports fall back to the package root on sys.path).
        for module in ("redaction.py", "embargo.py"):
            shutil.copyfile(ROOT / "lib" / module, self.factory / "lib" / module)
        self.target = self.root / "target with spaces"
        (self.target / ".beads").mkdir(parents=True)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.calls_file = self.root / "calls.jsonl"
        home = self.root / "home"
        home.mkdir()
        # Only our executables are discoverable; do not inherit tokens or live DB routing.
        self.env = {
            "PATH": str(self.bin),
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "SINK_CALLS": str(self.calls_file),
        }
        recorder = f"#!{sys.executable}\n" + """
import json
import os
import sys
from pathlib import Path

tool = Path(sys.argv[0]).name
with open(os.environ['SINK_CALLS'], 'a', encoding='utf-8') as log:
    log.write(json.dumps({'tool': tool, 'args': sys.argv[1:], 'cwd': os.getcwd()}) + '\\n')
if os.environ.get('SINK_FAIL_TOOL') == tool:
    sys.stderr.write('synthetic tracker unavailable\\n')
    sys.exit(9)
print('fixture-123' if tool == 'bd' else 'https://example.invalid/issues/123')
"""
        for tool in ("bd", "gh"):
            executable = self.bin / tool
            executable.write_text(recorder, encoding="utf-8")
            executable.chmod(0o755)

    def scan(self, sink, items=None, agent="lint", fail_tool=None, candidates=None, visibility=None):
        raw = self.root / "input.json"
        raw.write_text(json.dumps({"findings": [SAMPLE] if items is None else items}),
                       encoding="utf-8")
        cmd = [sys.executable, str(self.cli), "--target", "fixture", "--agent", agent,
               "--input", str(raw), "--sink", sink, "--target-dir", str(self.target)]
        if candidates is not None:
            candidates_file = self.root / "candidates.json"
            candidates_file.write_text(json.dumps(candidates), encoding="utf-8")
            cmd += ["--candidates", str(candidates_file)]
        if visibility is not None:
            cmd += ["--visibility", visibility]
        env = dict(self.env)
        if fail_tool:
            env["SINK_FAIL_TOOL"] = fail_tool
        return subprocess.run(
            cmd, cwd=self.factory, env=env, capture_output=True, text=True, check=True,
            timeout=10,
        )

    def calls(self):
        if not self.calls_file.exists():
            return []
        return [json.loads(line) for line in self.calls_file.read_text().splitlines()]

    def store(self):
        return json.loads((self.factory / "findings" / "fixture.json").read_text())

    def stats(self):
        history = self.factory / "findings" / "fixture-history.jsonl"
        return json.loads(history.read_text().splitlines()[-1])["delta"]

    def report(self):
        report_dir = self.factory / "findings"
        delta = (report_dir / "fixture-delta.md").read_text()
        self.assertEqual(delta, (report_dir / "fixture-latest.md").read_text())
        return delta

    def shifted(self):
        return dict(SAMPLE, line_number=700, path="src/example.py",
                    snippet="  unused  = True\n")

    def test_file_report_clean_delta_after_line_shift(self):
        self.scan("file")
        self.assertIn("Action Required", self.report())
        self.scan("file", [self.shifted()])
        report = self.report()
        self.assertIn("Clean Delta", report)
        self.assertIn("Active Findings (Unchanged)", report)
        self.assertIn("src/example.py:700", report)
        self.assertNotIn("Action Required", report)
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.stats(), {
            "new": 0, "regressed": 0, "fixed": 0, "unchanged": 1, "suppressed": 0,
        })
        self.assertEqual(len(self.store()["findings"]), 1)

    def test_beads_dispatch_and_dedup_across_processes(self):
        self.scan("beads")
        call, = self.calls()
        args = call["args"]
        self.assertEqual(call["tool"], "bd")
        self.assertEqual(call["cwd"], str(self.target))
        self.assertEqual(args[0], "create")
        self.assertEqual(args[args.index("-C") + 1], str(self.target))
        self.assertEqual(args[args.index("--title") + 1], "[lint] Unused export")
        self.assertEqual(args[args.index("--type") + 1], "task")
        fingerprint, = self.store()["findings"]
        description = args[args.index("--description") + 1]
        self.assertIn(fingerprint, description)
        self.assertIn(SAMPLE["snippet"], description)
        self.assertIn(SAMPLE["description"], description)
        self.scan("beads", [self.shifted()])
        self.assertEqual(len(self.calls()), 1)
        self.assertEqual(self.stats()["unchanged"], 1)

    def test_github_dispatch_and_dedup_across_processes(self):
        self.scan("github-issues")
        call, = self.calls()
        args = call["args"]
        self.assertEqual(call["tool"], "gh")
        self.assertEqual(call["cwd"], str(self.target))
        self.assertEqual(args[:2], ["issue", "create"])
        self.assertEqual(args[args.index("--title") + 1], "[factory:lint] Unused export")
        fingerprint, = self.store()["findings"]
        body = args[args.index("--body") + 1]
        self.assertIn(fingerprint, body)
        self.assertIn(SAMPLE["description"], body)
        self.assertIn(SAMPLE["remediation"], body)
        self.scan("github-issues", [self.shifted()])
        self.assertEqual(len(self.calls()), 1)

    def test_duplicate_input_is_one_finding_and_one_delivery(self):
        self.scan("beads", [SAMPLE, self.shifted(), SAMPLE])
        self.assertEqual(len(self.calls()), 1)
        self.assertEqual(self.stats()["new"], 1)
        self.assertEqual(self.stats()["unchanged"], 0)
        self.assertEqual(self.report().count("### [MEDIUM] Unused export"), 1)

    def test_fixed_then_regressed_delivers_once_per_recurrence(self):
        self.scan("github-issues")
        self.scan("github-issues", [])
        self.assertEqual(self.stats()["fixed"], 1)
        self.assertIn("Resolved in this Run", self.report())
        self.scan("github-issues", [self.shifted()])
        self.assertEqual(self.stats()["regressed"], 1)
        self.assertIn("(`regressed`)", self.report())
        self.scan("github-issues", [self.shifted()])
        self.assertEqual(len(self.calls()), 2)
        self.assertNotIn("Action Required", self.report())

    def test_success_is_tracked_per_sink_not_just_per_finding(self):
        self.scan("file")
        self.scan("beads")
        self.scan("github-issues")
        self.scan("beads")
        self.scan("github-issues")
        self.assertEqual([call["tool"] for call in self.calls()], ["bd", "gh"])

    def test_failed_beads_delivery_retries_without_repeating_success(self):
        result = self.scan("beads", fail_tool="bd")
        self.assertIn("Failed to create bead", result.stdout)
        self.scan("beads")
        self.scan("beads")
        self.assertEqual(len(self.calls()), 2)

    def test_failed_github_delivery_retries_without_repeating_success(self):
        result = self.scan("github-issues", fail_tool="gh")
        self.assertIn("Failed to create GitHub issue", result.stdout)
        self.scan("github-issues")
        self.scan("github-issues")
        self.assertEqual(len(self.calls()), 2)

    def test_missing_beads_directory_falls_back_and_can_deliver_later(self):
        (self.target / ".beads").rmdir()
        result = self.scan("beads")
        self.assertIn("Falling back to file sink", result.stdout)
        self.assertIn("Unused export", self.report())
        self.assertEqual(self.calls(), [])
        (self.target / ".beads").mkdir()
        self.scan("beads")
        self.scan("beads")
        self.assertEqual(len(self.calls()), 1)

    def test_missing_cli_preserves_file_fallback(self):
        for tool in ("bd", "gh"):
            (self.bin / tool).unlink()
        for sink in ("beads", "github-issues"):
            with self.subTest(sink=sink):
                self.scan(sink)
                self.assertIn("Unused export", self.report())
        self.assertEqual(self.calls(), [])

    def test_public_github_guard_with_positive_allowed_cases(self):
        items = [dict(SAMPLE, rule_id=severity, severity=severity,
                      title=f"Synthetic {severity}")
                 for severity in ("critical", "high", "medium", "low")]
        result = self.scan("github-issues", items)
        self.assertEqual(result.stdout.count("[SECURITY GUARD]"), 2)
        titles = [call["args"][call["args"].index("--title") + 1]
                  for call in self.calls()]
        self.assertEqual(titles, ["[factory:lint] Synthetic medium",
                                  "[factory:lint] Synthetic low"])
        report = self.report()
        self.assertIn("Synthetic critical", report)
        self.assertIn("Synthetic high", report)
        self.scan("github-issues", items)
        self.assertEqual(len(self.calls()), 2)

    def test_beads_embargoes_critical_and_high_and_keeps_its_band(self):
        """The beads sink is a synced tracker: the bands GitHub refuses must not reach it.

        The security audit found this sink created a bead for all three bands (SF-01). Medium
        stays the only publishing band, as it was before.
        """
        items = [dict(SAMPLE, rule_id=severity, severity=severity)
                 for severity in ("critical", "high", "medium", "low", "info")]
        result = self.scan("beads", items)
        calls = self.calls()
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["args"][calls[0]["args"].index("--type") + 1], "task")
        self.assertEqual(result.stdout.count("[SECURITY GUARD]"), 2)
        # The private delta report keeps every finding for the responder.
        report = self.report()
        self.assertIn("[CRITICAL] Unused export", report)
        self.assertIn("[HIGH] Unused export", report)
        self.assertIn("[MEDIUM] Unused export", report)

    def test_beads_embargoes_absent_severity_fail_closed(self):
        """An absent severity used to default to medium and publish (SF-03)."""
        item = dict(SAMPLE, title="Severity omitted")
        item.pop("severity")
        result = self.scan("beads", [item])
        self.assertEqual(self.calls(), [])
        self.assertEqual(result.stdout.count("[SECURITY GUARD]"), 1)
        self.assertIn("[CRITICAL] Severity omitted", self.report())

    def test_github_embargoes_absent_severity_fail_closed(self):
        """The GitHub guard branched on the raw field, so a deleted key published publicly."""
        item = dict(SAMPLE, title="Severity omitted")
        item.pop("severity")
        result = self.scan("github-issues", [item])
        self.assertEqual(self.calls(), [])
        self.assertEqual(result.stdout.count("[SECURITY GUARD]"), 1)

    def test_beads_embargoes_a_credential_agent_labelled_low(self):
        """A credential finding is critical on identity, not on the model's word."""
        item = dict(SAMPLE, rule_id="aws-access-key", severity="low",
                    title="A key the model called low")
        result = self.scan("beads", [item], agent="secret-scan")
        self.assertEqual(self.calls(), [])
        self.assertEqual(result.stdout.count("[SECURITY GUARD]"), 1)
        self.assertIn("[CRITICAL] aws-access-key match at ./src/example.py:12", self.report())

    def test_a_private_target_may_publish_critical_findings(self):
        """Visibility is the primary input: a private tracker is not a public disclosure."""
        items = [dict(SAMPLE, rule_id="critical-rule", severity="critical",
                      title="Critical but private")]
        result = self.scan("beads", items, visibility="private")
        titles = [call["args"][call["args"].index("--title") + 1] for call in self.calls()]
        self.assertEqual(titles, ["[lint] Critical but private"])
        self.assertNotIn("[SECURITY GUARD]", result.stdout)

    def test_a_private_target_may_publish_a_security_agent_finding(self):
        item = dict(SAMPLE, rule_id="aws-access-key", severity="low",
                    title="Credential on a private target")
        result = self.scan("beads", [item], agent="secret-scan", visibility="private")
        self.assertEqual(len(self.calls()), 1)
        self.assertNotIn("[SECURITY GUARD]", result.stdout)

    def test_a_private_target_publishes_github_issues_for_high(self):
        item = dict(SAMPLE, rule_id="high-rule", severity="high", title="High but private")
        result = self.scan("github-issues", [item], visibility="private")
        self.assertEqual(len(self.calls()), 1)
        self.assertNotIn("[SECURITY GUARD]", result.stdout)

    def test_an_unknown_visibility_value_is_rejected(self):
        raw = self.root / "input.json"
        raw.write_text(json.dumps({"findings": [SAMPLE]}), encoding="utf-8")
        res = subprocess.run(
            [sys.executable, str(self.cli), "--target", "fixture", "--agent", "lint",
             "--input", str(raw), "--sink", "file", "--target-dir", str(self.target),
             "--visibility", "internal"],
            cwd=self.factory, env=dict(self.env), capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(res.returncode, 2)
        self.assertIn("invalid choice", res.stderr)

    def test_security_agents_are_embargoed_whatever_the_label(self):
        """The vulnerability agents are critical on identity too, on both tracker sinks."""
        for agent in ("vuln-discovery", "vuln-verify", "vuln-triage", "threat-model"):
            for sink in ("beads", "github-issues"):
                with self.subTest(agent=agent, sink=sink):
                    item = dict(SAMPLE, rule_id=f"{agent}-finding", severity="medium",
                                title=f"{agent} medium finding")
                    result = self.scan(sink, [item], agent=agent)
                    self.assertEqual(self.calls(), [])
                    self.assertEqual(result.stdout.count("[SECURITY GUARD]"), 1)

    def test_candidates_bind_an_invented_rule_id_and_path(self):
        """The scanner's candidates are the contract: the model's strings are not (agents-nha)."""
        candidates = {"candidates": [{"rule_id": "unused-export", "path": "src/example.py"}]}
        self.scan("file", [dict(SAMPLE, rule_id="model-invented", path="elsewhere.js",
                                title="Invented location")],
                  candidates=candidates)
        record, = self.store()["findings"].values()
        self.assertEqual(record["rule_id"], "unclassified")
        self.assertEqual(record["path"], "unknown")
        report = self.report()
        self.assertIn("unclassified", report)
        self.assertIn("unknown", report)

    def test_candidates_keep_a_matching_rule_id_and_path(self):
        candidates = {"candidates": [{"rule_id": "unused-export", "path": "src/example.py"}]}
        self.scan("file", [dict(SAMPLE, title="Kept")], candidates=candidates)
        record, = self.store()["findings"].values()
        self.assertEqual(record["rule_id"], "unused-export")
        self.assertEqual(record["path"], "./src/example.py")

    def test_issue_shaped_candidates_do_not_bind(self):
        """issue-triage's candidates are issue records, not locations; nothing to bind to."""
        candidates = {"candidates": [{"id": "42", "title": "an issue"}]}
        self.scan("file", [dict(SAMPLE, rule_id="triage-missing-repro", path="issues/42",
                                title="Issue triage")],
                  agent="issue-triage", candidates=candidates)
        record, = self.store()["findings"].values()
        self.assertEqual(record["rule_id"], "triage-missing-repro")
        self.assertEqual(record["path"], "issues/42")

    def test_suppressed_and_accepted_findings_do_not_dispatch(self):
        self.scan("file", [SAMPLE, dict(SAMPLE, rule_id="accepted-rule")])
        store_file = self.factory / "findings" / "fixture.json"
        store = self.store()
        first, second = store["findings"]
        store["findings"][second]["state"] = "accepted"
        store_file.write_text(json.dumps(store), encoding="utf-8")
        suppressions = self.factory / "findings" / "suppressions.yaml"
        suppressions.write_text(f"{first}:\n  reason: Synthetic accepted risk\n",
                                encoding="utf-8")
        items = [SAMPLE, dict(SAMPLE, rule_id="accepted-rule")]
        self.scan("beads", items)
        self.scan("github-issues", items)
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.stats()["suppressed"], 1)
        self.assertEqual(self.stats()["unchanged"], 1)
        self.assertIn("Synthetic accepted risk", self.report())

    def test_a_malformed_register_fails_loudly(self):
        """A register that cannot be parsed must not silently suppress nothing (agents-411)."""
        findings_dir = self.factory / "findings"
        findings_dir.mkdir(parents=True, exist_ok=True)
        (findings_dir / "suppressions.yaml").write_text(": broken\n", encoding="utf-8")
        raw = self.root / "input.json"
        raw.write_text(json.dumps({"findings": [SAMPLE]}), encoding="utf-8")
        res = subprocess.run(
            [sys.executable, str(self.cli), "--target", "fixture", "--agent", "lint",
             "--input", str(raw), "--sink", "file", "--target-dir", str(self.target)],
            cwd=self.factory, env=dict(self.env), capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(res.returncode, 2)
        self.assertIn("Error", res.stderr)
        self.assertIn("suppressions", res.stderr)


if __name__ == "__main__":
    unittest.main()
