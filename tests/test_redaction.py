#!/usr/bin/env python3
"""Credential redaction at the publish boundary.

A finding's `snippet` is whatever the scanner matched — for `secret-scan` that is the
credential itself. These tests drive the real CLI and assert the value never reaches a
published surface: the delta report (which the composite action appends to a public step
summary), a tracker sink (beads / GitHub Issues), or scanner stdout.

The fixture credential is assembled at runtime on purpose: a literal in this file would be
reported as a candidate by the factory's own secret-scan pre-pass on every run, which is
exactly the permanent false positive this work exists to avoid.
"""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.redaction import CREDENTIAL_AGENTS, mask_text, redact_finding  # noqa: E402

CREDENTIAL = "AKIA" + "IOSFODNN7EXAMPLE"  # AWS documentation example key, not a live secret


def _secret_finding(**overrides):
    finding = {
        "rule_id": "aws-access-key",
        "path": "src/config.js",
        "line_number": 12,
        "snippet": f'const AWS_KEY = "{CREDENTIAL}";',
        "severity": "high",
        "title": "Hardcoded AWS access key",
        "description": f"The file embeds the credential {CREDENTIAL} directly.",
        "remediation": f"Remove {CREDENTIAL} and read it from the environment.",
    }
    finding.update(overrides)
    return finding


class TestRedactionUnit(unittest.TestCase):
    def test_pattern_masking_covers_every_shape(self):
        # Every fixture is assembled from parts so this file stays clean under the factory's
        # own secret-scan pre-pass; a literal would be reported as a candidate on every run.
        for value in (
            "AKIA" + "IOSFODNN7EXAMPLE",
            "ghp_" + "a" * 36,
            "xox" + "b-123456789012-123456789012" + "-abcdef",
            "api_" + 'key = "' + "a" * 30 + '"',
            "-----BEGIN RSA " + "PRIVATE KEY-----",
        ):
            with self.subTest(value=value[:12]):
                masked = mask_text(f"leaked: {value} end")
                self.assertNotIn(value, masked)
                self.assertIn("[redacted:", masked)

    def test_benign_text_is_untouched(self):
        text = "const key = 'abc'; // unused export"
        self.assertEqual(mask_text(text), text)

    def test_secret_scan_snippets_are_dropped_wholesale(self):
        """Default-deny: an unrecognised credential format must not survive either."""
        published = redact_finding(_secret_finding(agent="secret-scan", snippet="totally-unknown-format-xyz"))
        self.assertNotIn("totally-unknown-format-xyz", published["snippet"])
        self.assertIn("secret-scan match at src/config.js:12", published["snippet"])

    def test_rule_id_alone_triggers_the_drop(self):
        """Either signal fires: a credential rule with no agent field still drops."""
        finding = {"rule_id": "aws-access-key", "path": "src/config.js", "line_number": 12,
                   "snippet": "totally-unknown-format-xyz"}
        self.assertNotIn("totally-unknown-format-xyz", redact_finding(finding)["snippet"])

    def test_model_written_prose_is_masked(self):
        """The triage model sees the raw candidate, so any field it writes can echo it."""
        published = redact_finding(_secret_finding(agent="docs-drift"))
        for field in ("title", "description", "remediation", "snippet"):
            self.assertNotIn(CREDENTIAL, str(published[field]), field)

    def test_identity_fields_survive_for_triage(self):
        published = redact_finding(_secret_finding())
        self.assertEqual(published["rule_id"], "aws-access-key")
        self.assertEqual(published["line_number"], 12)
        self.assertEqual(published["severity"], "high")
        self.assertIn("secret-scan", CREDENTIAL_AGENTS)

    def test_input_finding_is_not_mutated(self):
        """The raw local record and the delivery bookkeeping stay intact."""
        finding = _secret_finding(agent="secret-scan")
        before = dict(finding)
        redact_finding(finding)
        self.assertEqual(finding, before)


class TestCredentialEchoRegression(unittest.TestCase):
    """Regression cases for the factory-astra review of PR #4, which defeated the first version.

    The value being withheld is derived from the finding (scanner output and the agent that
    produced it), not from a pattern in the text, so these hold regardless of the credential's
    shape. Fixtures are assembled at runtime so this file stays clean under the repo's own
    secret-scan pre-pass.
    """

    # Assembled at runtime: an assignment-shaped key, a PEM body, and an unknown shape.
    OPAQUE = "sk-" + "live" + "-" + "9f" * 20
    UNKNOWN_SHAPE = "zkq" + "7" * 24
    PEM_BODY = "MIIEowIBAAKCAQEA" + "t3st" * 12
    # Header and footer assembled too, so the repo's own self-scan stays at 0 candidates.
    PEM_HEADER = "-----BEGIN " + "PRIVATE KEY-----"
    PEM_END = "-----END " + "PRIVATE KEY-----"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="factory-echo-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.factory = self.root / "factory"
        (self.factory / "lib").mkdir(parents=True)
        for module in ("findings.py", "redaction.py"):
            shutil.copyfile(ROOT / "lib" / module, self.factory / "lib" / module)
        self.cli = self.factory / "lib" / "findings.py"
        self.target = self.root / "target"
        (self.target / ".beads").mkdir(parents=True)
        self.calls_file = self.root / "calls.jsonl"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        home = self.root / "home"
        home.mkdir()
        self.env = {"PATH": str(self.bin), "HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config"),
                    "SINK_CALLS": str(self.calls_file)}
        recorder = f"#!{sys.executable}\n" + """
import json, os, sys
from pathlib import Path
with open(os.environ['SINK_CALLS'], 'a', encoding='utf-8') as log:
    log.write(json.dumps({'tool': Path(sys.argv[0]).name, 'args': sys.argv[1:]}) + '\\n')
print('fixture-123')
"""
        for tool in ("bd", "gh"):
            executable = self.bin / tool
            executable.write_text(recorder, encoding="utf-8")
            executable.chmod(0o755)

    def dispatch(self, sink, finding, agent="secret-scan"):
        raw = self.root / "input.json"
        raw.write_text(json.dumps({"findings": [finding]}), encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(self.cli), "--target", "sandbox", "--agent", agent,
             "--input", str(raw), "--sink", sink, "--target-dir", str(self.target)],
            cwd=self.factory, env=self.env, capture_output=True, text=True, check=True, timeout=30,
        )

    def surfaces(self, result):
        found = {
            "delta report": (self.factory / "findings" / "sandbox-latest.md").read_text(encoding="utf-8"),
            "cli stdout": result.stdout,
            "cli stderr": result.stderr,
        }
        if self.calls_file.exists():
            found["tracker call"] = "".join(self.calls_file.read_text().splitlines())
        return found

    def credential_finding(self):
        return {
            "rule_id": "aws-access-key",
            "path": "src/config.js", "line_number": 7,
            "snippet": f"const k = '{CREDENTIAL}'",
            "severity": "high",
            "title": f"Hardcoded key {CREDENTIAL} committed",
            "description": f"The credential {CREDENTIAL} is committed in source.",
            "remediation": f"Remove {CREDENTIAL}.",
        }

    def assert_clean(self, sink, finding, needle, severity="high"):
        self.calls_file.unlink(missing_ok=True)
        finding["severity"] = severity
        result = self.dispatch(sink, finding)
        for name, text in self.surfaces(result).items():
            with self.subTest(sink=sink, surface=name):
                self.assertNotIn(needle, text, f"value reached {name}")

    def test_credential_in_a_title_reaches_no_tracker_field(self):
        """The beads title is built from the published view, not the raw finding."""
        for sink, severity in (("file", "high"), ("beads", "high"), ("github-issues", "medium")):
            self.assert_clean(sink, self.credential_finding(), CREDENTIAL, severity)

    def test_bare_value_echoed_in_prose_is_absent_everywhere(self):
        """A model quoting the matched value on its own — no assignment context to match on."""
        finding = self.credential_finding()
        finding["snippet"] = f"api_key = '{self.OPAQUE}'"
        finding["raw_match"] = self.OPAQUE
        finding["title"] = "Committed live key"
        finding["description"] = f"I checked the file: {self.OPAQUE} is a live credential."
        finding["remediation"] = f"Rotate {self.OPAQUE} now."

        for sink, severity in (("file", "high"), ("beads", "high"), ("github-issues", "medium")):
            self.assert_clean(sink, finding, self.OPAQUE, severity)

    def test_pem_body_echoed_in_prose_is_absent_everywhere(self):
        finding = self.credential_finding()
        finding["rule_id"] = "private-key"
        finding["snippet"] = "-----BEGIN RSA " + "PRIVATE KEY-----"
        finding["description"] = f"The private key material starts {self.PEM_BODY} and continues."
        finding["remediation"] = f"Revoke the key; the body is {self.PEM_BODY}."

        for sink, severity in (("file", "high"), ("beads", "high"), ("github-issues", "medium")):
            self.assert_clean(sink, finding, self.PEM_BODY, severity)

    def test_unknown_shape_in_prose_is_absent_for_a_credential_finding(self):
        """Default-deny: no pattern knows this value, and it still must not be published.

        Every sink, not just the report: the beads log line ("Created bead for: <title>") was
        one of the surfaces the review probes caught still carrying the value.
        """
        unknown = "zkq" + "7" * 24
        finding = self.credential_finding()
        finding["snippet"] = f"token: {unknown}"
        finding["description"] = f"The token {unknown} is in the file."
        finding["title"] = f"Token {unknown} found"

        for sink, severity in (("file", "high"), ("beads", "high"), ("github-issues", "medium")):
            self.assert_clean(sink, finding, unknown, severity)

    def test_credential_smuggled_through_identity_fields(self):
        """`path` and `rule_id` reach this layer as model-returned text, so they are masked too.

        Both were proven leaks in the second review: a scanner-derived filename containing the
        key, and the key appended to rule_id so it appeared in the derived title, the Rule line
        and the tracker fields.
        """
        cases = {
            "path": {"path": f"src/{CREDENTIAL}-leaked.js"},
            "rule-id": {"rule_id": f"provider-credential-{self.UNKNOWN_SHAPE}",
                        "snippet": f"token: {self.UNKNOWN_SHAPE}"},
        }
        needles = {"path": CREDENTIAL, "rule-id": self.UNKNOWN_SHAPE}

        for label, override in cases.items():
            for sink, severity in (("file", "high"), ("beads", "high"), ("github-issues", "medium")):
                with self.subTest(field=label, sink=sink):
                    finding = self.credential_finding()
                    finding.update(override)
                    self.assert_clean(sink, finding, needles[label], severity)

    def test_suppression_reason_is_masked_for_a_credential_finding(self):
        """The suppressed section renders this field, and it is written by a human."""
        from lib.findings import compute_fingerprint

        finding = self.credential_finding()
        fingerprint = compute_fingerprint("secret-scan", finding["rule_id"],
                                          finding["path"], finding["snippet"])
        reports_dir = self.factory / "findings"
        reports_dir.mkdir(parents=True, exist_ok=True)
        (reports_dir / "sandbox.suppressions.json").write_text(json.dumps({
            fingerprint: {"reason": f"accepted risk for {CREDENTIAL}", "author": "fixture",
                          "date": "2026-01-01"}
        }), encoding="utf-8")

        self.assert_clean("file", finding, CREDENTIAL)
        report = (reports_dir / "sandbox-latest.md").read_text(encoding="utf-8")
        self.assertIn("Suppressed", report)

    def test_non_credential_pem_block_in_prose_is_masked(self):
        """A whole-block pattern must run before the header-only pattern, or the body survives."""
        finding = {
            "rule_id": "readme-example", "path": "README.md", "line_number": 4,
            "snippet": "missing usage docs", "severity": "medium",
            "title": "Undocumented usage",
            "description": f"Remove material:\n{self.PEM_HEADER}\n"
                           f"{self.PEM_BODY}\n{self.PEM_END}",
            "remediation": "Delete the example.",
        }
        self.dispatch("file", finding, agent="docs-drift")
        report = self.surfaces(subprocess.CompletedProcess([], 0, "", ""))["delta report"]
        self.assertNotIn(self.PEM_BODY, report)
        self.assertIn("[redacted:pem-block]", report)

    def test_non_credential_finding_still_publishes_its_prose(self):
        """Withholding is scoped to credential findings: docs findings keep their notes."""
        finding = {
            "rule_id": "doc-broken-link", "path": "README.md", "line_number": 12,
            "snippet": "[guide](docs/gone.md)", "severity": "medium",
            "title": "Broken link to a deleted guide",
            "description": "The link target does not exist in the tree.",
            "remediation": "Point it at docs/PLAN.md.",
        }
        self.dispatch("file", finding, agent="docs-drift")
        report = self.surfaces(subprocess.CompletedProcess([], 0, "", ""))["delta report"]
        self.assertIn("Broken link to a deleted guide", report)
        self.assertIn("Point it at docs/PLAN.md.", report)

    def test_matched_value_echoed_by_a_non_credential_agent_is_still_masked(self):
        """Defence in depth: the literal the scanner matched is masked in prose too.

        The value here matches no pattern at all, so only the literal mask derived from the
        finding's own scanner output can catch it.
        """
        secret = self.UNKNOWN_SHAPE
        finding = {
            "rule_id": "doc-quote-drift", "path": "notes.md", "line_number": 3,
            "snippet": f"api_key = '{secret}'",
            "raw_match": secret,
            "severity": "medium", "title": "Documentation quotes a key",
            "description": f"The doc contains {secret} verbatim.",
            "remediation": f"Remove {secret}.",
        }
        self.dispatch("file", finding, agent="docs-drift")
        report = self.surfaces(subprocess.CompletedProcess([], 0, "", ""))["delta report"]
        self.assertNotIn(secret, report)
        # A rule id carrying no credential hint keeps its model-written prose, masked in place.
        self.assertIn("Documentation quotes a key", report)
        self.assertIn("[redacted:", report)


class TestPublishedSurfaces(unittest.TestCase):
    """End-to-end: the real CLI, a sandbox factory, stub tracker binaries."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="factory-redaction-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.factory = self.root / "factory"
        (self.factory / "lib").mkdir(parents=True)
        # A copy, so the report lands inside the sandbox: FACTORY_ROOT is module-level.
        for module in ("findings.py", "redaction.py"):
            shutil.copyfile(ROOT / "lib" / module, self.factory / "lib" / module)
        self.cli = self.factory / "lib" / "findings.py"
        self.target = self.root / "target"
        (self.target / ".beads").mkdir(parents=True)
        self.calls_file = self.root / "calls.jsonl"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        home = self.root / "home"
        home.mkdir()
        self.env = {"PATH": str(self.bin), "HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config"),
                    "SINK_CALLS": str(self.calls_file)}
        recorder = f"#!{sys.executable}\n" + """
import json, os, sys
from pathlib import Path
with open(os.environ['SINK_CALLS'], 'a', encoding='utf-8') as log:
    log.write(json.dumps({'tool': Path(sys.argv[0]).name, 'args': sys.argv[1:]}) + '\\n')
print('fixture-123')
"""
        for tool in ("bd", "gh"):
            executable = self.bin / tool
            executable.write_text(recorder, encoding="utf-8")
            executable.chmod(0o755)

    def dispatch(self, sink, finding, agent):
        raw = self.root / "input.json"
        raw.write_text(json.dumps({"findings": [finding]}), encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(self.cli), "--target", "sandbox", "--agent", agent,
             "--input", str(raw), "--sink", sink, "--target-dir", str(self.target)],
            cwd=self.factory, env=self.env, capture_output=True, text=True, check=True, timeout=30,
        )

    def report(self):
        return (self.factory / "findings" / "sandbox-latest.md").read_text(encoding="utf-8")

    def tracker_calls(self):
        if not self.calls_file.exists():
            return []
        return [json.loads(line) for line in self.calls_file.read_text().splitlines() if line.strip()]

    def assert_nothing_published(self, result):
        surfaces = {"delta report": self.report(), "cli stdout": result.stdout, "cli stderr": result.stderr}
        for call in self.tracker_calls():
            surfaces[f"{call['tool']} {' '.join(call['args'])}"] = json.dumps(call)
        for name, text in surfaces.items():
            with self.subTest(surface=name):
                self.assertNotIn(CREDENTIAL, text, f"credential reached {name}")

    def test_file_sink_masks_the_credential(self):
        result = self.dispatch("file", _secret_finding(agent="secret-scan"), "secret-scan")
        self.assert_nothing_published(result)
        report = self.report()
        self.assertIn("aws-access-key", report)          # still actionable
        self.assertIn("src/config.js:12", report)
        self.assertIn("[redacted:secret-scan match", report)

    def test_beads_sink_masks_the_credential(self):
        result = self.dispatch("beads", _secret_finding(agent="secret-scan"), "secret-scan")
        self.assert_nothing_published(result)
        calls = self.tracker_calls()
        self.assertEqual([c["tool"] for c in calls], ["bd"])
        args = calls[0]["args"]
        # A credential finding publishes scanner-controlled text only; the model's own title is
        # withheld along with the value.
        self.assertEqual(args[args.index("--title") + 1],
                         "[secret-scan] aws-access-key match at src/config.js:12")
        description = args[args.index("--description") + 1]
        self.assertIn("withhold the matched value", description)
        self.assertIn("[redacted:secret-scan match", description)

    def test_github_sink_masks_a_model_echoed_credential(self):
        """Medium severity so the public-disclosure guard lets it through to the sink."""
        result = self.dispatch("github-issues", _secret_finding(agent="docs-drift", severity="medium"),
                               "docs-drift")
        self.assert_nothing_published(result)
        calls = self.tracker_calls()
        self.assertEqual([c["tool"] for c in calls], ["gh"])
        args = calls[0]["args"]
        self.assertIn("--body", args)                       # a body was actually sent
        body = args[args.index("--body") + 1]
        self.assertIn("withhold the matched value", body)
        self.assertEqual(args[args.index("--title") + 1],
                         "[factory:docs-drift] aws-access-key match at src/config.js:12")

    def test_benign_finding_is_published_unchanged(self):
        """No regression: masking must not censor ordinary findings."""
        finding = {"rule_id": "unused-export", "path": "src/example.py", "line_number": 12,
                   "snippet": "unused = True", "severity": "medium", "title": "Unused export",
                   "description": "Synthetic finding.", "remediation": "Remove it."}
        self.dispatch("file", finding, "lint")
        self.assertIn("unused = True", self.report())


class TestScannerStdout(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="factory-scan-stdout-")
        self.addCleanup(temporary.cleanup)
        self.tree = Path(temporary.name)
        (self.tree / "src").mkdir()
        (self.tree / "src" / "config.js").write_text(f'const AWS_KEY = "{CREDENTIAL}";\n')
        self.scan = ROOT / "agents" / "secret-scan" / "scripts" / "scan.py"

    def scan_run(self, *extra):
        return subprocess.run(
            [sys.executable, str(self.scan), "--target", str(self.tree), *extra],
            capture_output=True, text=True, timeout=60,
        )

    def test_stdout_never_carries_the_match(self):
        res = self.scan_run()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertNotIn(CREDENTIAL, res.stdout)
        self.assertIn("aws-access-key", res.stdout)     # the location is still reported

    def test_output_file_keeps_the_local_record(self):
        """The raw value has to survive somewhere: a human needs it to rotate the secret."""
        out = self.tree / "candidates.json"
        res = self.scan_run("--output", str(out))
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertNotIn(CREDENTIAL, res.stdout)
        candidates = json.loads(out.read_text())["candidates"]
        self.assertTrue(candidates, "fixture should be detected")
        self.assertIn(CREDENTIAL, json.dumps(candidates))


if __name__ == "__main__":
    unittest.main()
