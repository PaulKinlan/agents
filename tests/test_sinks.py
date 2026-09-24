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
        # findings.py renders every published finding through lib.redaction, so the sandbox
        # needs that module too (the import falls back to the package root on sys.path).
        shutil.copyfile(ROOT / "lib" / "redaction.py", self.factory / "lib" / "redaction.py")
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

    def scan(self, sink, items=None, agent="lint", fail_tool=None):
        raw = self.root / "input.json"
        raw.write_text(json.dumps({"findings": [SAMPLE] if items is None else items}),
                       encoding="utf-8")
        env = dict(self.env)
        if fail_tool:
            env["SINK_FAIL_TOOL"] = fail_tool
        return subprocess.run(
            [sys.executable, str(self.cli), "--target", "fixture", "--agent", agent,
             "--input", str(raw), "--sink", sink, "--target-dir", str(self.target)],
            cwd=self.factory, env=env, capture_output=True, text=True, check=True,
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

    def test_beads_severity_and_bug_type(self):
        items = [dict(SAMPLE, rule_id=severity, severity=severity)
                 for severity in ("critical", "high", "medium", "low", "info")]
        self.scan("beads", items, agent="vuln-verify")
        calls = self.calls()
        self.assertEqual(len(calls), 3)
        for call in calls:
            self.assertEqual(call["args"][call["args"].index("--type") + 1], "bug")

    def test_suppressed_and_accepted_findings_do_not_dispatch(self):
        self.scan("file", [SAMPLE, dict(SAMPLE, rule_id="accepted-rule")])
        store_file = self.factory / "findings" / "fixture.json"
        store = self.store()
        first, second = store["findings"]
        store["findings"][second]["state"] = "accepted"
        store_file.write_text(json.dumps(store), encoding="utf-8")
        suppressions = self.factory / "findings" / "fixture.suppressions.json"
        suppressions.write_text(json.dumps({first: {"reason": "Synthetic accepted risk"}}),
                                encoding="utf-8")
        items = [SAMPLE, dict(SAMPLE, rule_id="accepted-rule")]
        self.scan("beads", items)
        self.scan("github-issues", items)
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.stats()["suppressed"], 1)
        self.assertEqual(self.stats()["unchanged"], 1)
        self.assertIn("Synthetic accepted risk", self.report())


if __name__ == "__main__":
    unittest.main()
