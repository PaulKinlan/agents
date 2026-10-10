#!/usr/bin/env python3
"""Credential redaction at the publish boundary.

A finding's `snippet` is whatever the scanner matched — for `secret-scan` that is the
credential itself. These tests drive the real CLI and assert the value never reaches a
published surface: the delta report (which the composite action appends to a public step
summary), the public GitHub issue API payload, or scanner stdout.

The fixture credential is assembled at runtime on purpose: a literal in this file would be
reported as a candidate by the factory's own secret-scan pre-pass on every run, which is
exactly the permanent false positive this work exists to avoid.
"""

import ast
import json
import os
os.environ.setdefault("FACTORY_ALLOW_UNPINNED_TOOLS", "1")  # agents-7bj: tests use unpinned stub tools
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.redaction import CREDENTIAL_AGENTS, mask_text, redact_finding  # noqa: E402
from tests.test_sinks import REPO, SinkFixture  # noqa: E402

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

    def test_non_secret_scan_credential_finding_does_not_claim_deterministic_scanner(self):
        """agents-5gg: non-secret-scan findings are model reports, not deterministic scanners."""
        finding = {
            "agent": "threat-model",
            "rule_id": "tm-accepted-unbrokered-claude-key",
            "path": "factory",
            "line_number": 1053,
            "snippet": 'f"engine \'claude\' runs without the OS filesystem sandbox"',
            "severity": "info",
            "title": "Accepted residual risk",
            "description": "claude carries unbrokered credentials",
            "remediation": "verify claude in sandbox",
        }
        published = redact_finding(finding)
        self.assertNotIn("deterministic scanner", published["description"])
        self.assertIn("The threat-model agent reported `tm-accepted-unbrokered-claude-key`",
                      published["description"])


class TestCredentialEchoRegression(SinkFixture, unittest.TestCase):
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

    def dispatch(self, sink, finding, agent="secret-scan"):
        raw = self.root / "input.json"
        raw.write_text(json.dumps({"findings": [finding]}), encoding="utf-8")
        cmd = [sys.executable, str(self.cli), "--target", "sandbox", "--agent", agent,
               "--input", str(raw), "--sink", sink, "--target-dir", str(self.target)]
        if sink == "beads":
            cmd += ["--beads-dir", str(self.target), "--visibility", "public"]
        return subprocess.run(cmd, cwd=self.factory, env=self.env, capture_output=True,
                              text=True, check=True, timeout=30)

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
        """The public issue title uses the redacted finding, not the raw model field."""
        for sink, severity in (("file", "high"), ("beads", "high")):
            self.assert_clean(sink, self.credential_finding(), CREDENTIAL, severity)

    def test_bare_value_echoed_in_prose_is_absent_everywhere(self):
        """A model quoting the matched value on its own — no assignment context to match on."""
        finding = self.credential_finding()
        finding["snippet"] = f"api_key = '{self.OPAQUE}'"
        finding["raw_match"] = self.OPAQUE
        finding["title"] = "Committed live key"
        finding["description"] = f"I checked the file: {self.OPAQUE} is a live credential."
        finding["remediation"] = f"Rotate {self.OPAQUE} now."

        for sink, severity in (("file", "high"), ("beads", "high")):
            self.assert_clean(sink, finding, self.OPAQUE, severity)

    def test_pem_body_echoed_in_prose_is_absent_everywhere(self):
        finding = self.credential_finding()
        finding["rule_id"] = "private-key"
        finding["snippet"] = "-----BEGIN RSA " + "PRIVATE KEY-----"
        finding["description"] = f"The private key material starts {self.PEM_BODY} and continues."
        finding["remediation"] = f"Revoke the key; the body is {self.PEM_BODY}."

        for sink, severity in (("file", "high"), ("beads", "high")):
            self.assert_clean(sink, finding, self.PEM_BODY, severity)

    def test_unknown_shape_in_prose_is_absent_for_a_credential_finding(self):
        """Default-deny: no pattern knows this value, and it still must not be published.

        The public issue API payload is also checked; not just the local report.
        """
        unknown = "zkq" + "7" * 24
        finding = self.credential_finding()
        finding["snippet"] = f"token: {unknown}"
        finding["description"] = f"The token {unknown} is in the file."
        finding["title"] = f"Token {unknown} found"

        for sink, severity in (("file", "high"), ("beads", "high")):
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
            for sink, severity in (("file", "high"), ("beads", "high")):
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
        (reports_dir / "suppressions.yaml").write_text(
            f"{fingerprint}:\n"
            f'  reason: "accepted risk for {CREDENTIAL}"\n'
            "  author: fixture\n"
            '  date: "2026-01-01"\n',
            encoding="utf-8",
        )

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

    def test_non_scalar_fields_cannot_carry_the_value(self):
        """The type boundary: a dict or list reaches an f-string as its repr, which published
        the value even though the field was 'masked'. Only scalars may become text.

        `rule_id` and `line_number` are the fields the third review used; `description` and
        `snippet` are included because nothing in the pipeline type-checks before dispatch.
        """
        payload = {"kind": "aws-access-key", "observed": CREDENTIAL}
        cases = {
            "rule_id": {"rule_id": payload},
            "line_number": {"line_number": {"line": 12, "observed": CREDENTIAL}},
            "description": {"description": ["seen", {"observed": CREDENTIAL}]},
            "snippet": {"snippet": payload, "raw_match": CREDENTIAL},
        }

        for label, override in cases.items():
            for sink, severity in (("file", "high"), ("beads", "high")):
                with self.subTest(field=label, sink=sink):
                    finding = self.credential_finding()
                    finding.update(override)
                    self.assert_clean(sink, finding, CREDENTIAL, severity)

    def test_scalar_coercion_keeps_useful_values(self):
        """Fail-closed does not mean throwing away the line number or normalising nothing."""
        finding = self.credential_finding()
        finding["line_number"] = "12"                 # numeric string from the model
        self.dispatch("file", finding)
        report = self.surfaces(subprocess.CompletedProcess([], 0, "", ""))["delta report"]
        self.assertIn("src/config.js:12", report)

        finding = self.credential_finding()
        finding["line_number"] = "line 12"            # not a line number: becomes unknown
        self.dispatch("file", finding)
        report = self.surfaces(subprocess.CompletedProcess([], 0, "", ""))["delta report"]
        self.assertIn("src/config.js:?", report)
        self.assertNotIn("line 12", report)

    def test_large_integer_line_number_cannot_carry_a_matched_value(self):
        """A non-text field skips literal masking, so a big integer is a way around it entirely.

        The fourth review's case: a generic-api-key match made of 30 digits, handed back as
        `line_number=int(digits)`. As a *string* the digit cap stopped it; as an int the value
        was returned unchanged and rendered in every location field.
        """
        digits = "3141592653" * 3
        for sink, severity in (("file", "medium"), ("beads", "medium")):
            with self.subTest(sink=sink):
                finding = self.credential_finding()
                finding.update({
                    "rule_id": "generic-api-key",
                    "snippet": f'token = "{digits}"',
                    "line_number": int(digits),
                })
                self.assert_clean(sink, finding, digits, severity)
                report = self.surfaces(subprocess.CompletedProcess([], 0, "", ""))["delta report"]
                self.assertIn("src/config.js:?", report)

    def test_line_number_policy_is_the_same_for_both_types(self):
        """Bounds and matched-literal protection apply to ints exactly as to numeric strings."""
        from lib.redaction import MAX_LINE_NUMBER, publishable_line_number

        self.assertEqual(publishable_line_number(12), 12)
        self.assertEqual(publishable_line_number("12"), 12)
        self.assertEqual(publishable_line_number(" 12 "), 12)
        # agents-wnad: line 0 is unknown ("?"), matching lib.line_numbers.usable_line_number
        self.assertEqual(publishable_line_number(0), "?")
        for rejected in (MAX_LINE_NUMBER + 1, -1, "line 12", "", None, True, 12.5, {"line": 12}):
            with self.subTest(value=rejected):
                self.assertEqual(publishable_line_number(rejected), "?")
        # A number that is itself a matched value does not get published for being small.
        self.assertEqual(publishable_line_number(3141592, {"3141592"}), "?")

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


class TestPublishedSurfaces(SinkFixture, unittest.TestCase):
    """End-to-end: the real CLI, a sandbox factory, stub tracker binaries."""

    def dispatch(self, sink, finding, agent, visibility=None):
        raw = self.root / "input.json"
        raw.write_text(json.dumps({"findings": [finding]}), encoding="utf-8")
        cmd = [sys.executable, str(self.cli), "--target", "sandbox", "--agent", agent,
               "--input", str(raw), "--sink", sink, "--target-dir", str(self.target)]
        if sink == "beads":
            cmd += ["--beads-dir", str(self.target)]
        if visibility:
            cmd += ["--visibility", visibility]
        return subprocess.run(cmd, cwd=self.factory, env=self.env, capture_output=True,
                              text=True, check=True, timeout=30)

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

    def test_direct_beads_sink_files_a_redacted_bead(self):
        """agents-eyo: findings file to beads automatically; redaction must hold at the bead."""
        result = self.dispatch("beads", _secret_finding(agent="secret-scan"), "secret-scan",
                               visibility="public")
        self.assert_nothing_published(result)
        bead, = json.loads(self.remote.read_text())["beads"]
        self.assertIn("aws-access-key", bead["description"])
        self.assertNotIn(CREDENTIAL, bead["title"] + bead["description"])
        self.assertFalse(any(c["tool"] == "gh" for c in self.tracker_calls()))

    def test_beads_sink_masks_a_model_echoed_credential(self):
        """agents-eyo: a non-credential agent that echoes a matched value is masked in the bead."""
        result = self.dispatch("beads", _secret_finding(agent="docs-drift", severity="medium"),
                               "docs-drift")
        self.assert_nothing_published(result)
        bead, = json.loads(self.remote.read_text())["beads"]
        self.assertIn("aws-access-key", bead["description"])
        self.assertNotIn(CREDENTIAL, bead["title"] + bead["description"])

    def test_github_issues_sink_is_refused(self):
        """agents-eyo: public GitHub issues are no longer a findings sink."""
        with self.assertRaises(subprocess.CalledProcessError) as failure:
            self.dispatch("github-issues", _secret_finding(agent="docs-drift", severity="medium"),
                          "docs-drift", visibility="public")
        self.assertIn("no longer a findings sink", failure.exception.stderr)
        self.assertFalse(any(c["tool"] == "gh" for c in self.tracker_calls()))

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



class TestStdoutChannelCarriesOnlyWhatReadersConsume(unittest.TestCase):
    """agents-qslz (P1), restated for the allowlist (agents-h0mb): a value DERIVED from the
    matched text must be dropped with it - and under the allowlist, dropped means ABSENT.

    candidate_id is sha256(rule NUL path NUL match_text NUL ordinal)[:16] - a digest of the
    matched text - and this channel carries no fingerprint, so the id is the only digest of
    the match in the payload. The old shape emitted "[redacted]" sentinel VALUES under the
    known names; the allowlist drops the keys outright, because a reader of this channel
    consumes rule, path, location and severity and nothing else (the reader census is in
    stdout_safe_report's docstring, and the tests that parse station stdout assert only those
    keys).

    Load-bearing: revert the drop in stdout_safe_report (carry unnamed keys through, e.g.
    `else: safe[key] = value`) and this fails with the digest present in the serialized
    output. The assertion is on the serialized channel and the exact surviving key set, not
    on membership of any list in the implementation.
    """

    def test_derived_match_values_and_the_match_text_never_reach_the_channel(self):
        from lib.redaction import stdout_safe_report

        report = {"rule_id": "github-pat", "path": "src/config.js", "line_number": 1,
                  "snippet": "ghp_SECRETVALUE", "raw_match": "ghp_SECRETVALUE",
                  "candidate_id": "45242927149666d8", "identity_source": "candidate-id"}
        safe = stdout_safe_report(report)

        serialized = json.dumps(safe)
        self.assertNotIn("45242927149666d8", serialized,
                         "the confirmation oracle reached the stdout channel")
        self.assertNotIn("ghp_SECRETVALUE", serialized)
        # The channel must stay USABLE: exactly the reader-consumed keys survive.
        self.assertEqual(safe, {"rule_id": "github-pat", "path": "src/config.js",
                                "line_number": 1})


# Assembled at runtime, like CREDENTIAL above: a literal in this file would be reported as a
# candidate by the factory's own secret-scan pre-pass on every run. NO pattern in lib/redaction
# recognises this shape - no vendor prefix, no assignment context - and that is the point of the
# canary: it is a matched value the masker cannot see (agents-dd0w). The previous round's canary
# was AWS-shaped, which mask_text recognises, so it could not see the masker's blind spot.
UNKNOWN_SHAPE_CANARY = "qz8x" + "k2m9" * 5 + "w7vd"


class TestStdoutChannelIsAnAllowlist(unittest.TestCase):
    """agents-h0mb (coord's ruling, after the agents-iukb census) and agents-dd0w: the stdout
    channel DROPS anything a reader does not consume.

    The denylist this replaces - drop named fields, mask every other string - leaked
    vuln-verify's source_context.context_snippet: raw source lines under a name the drop list
    did not know, passed through verbatim because mask_text recognised nothing in them. The
    census then found seven more fields of the same class across the real stations
    (context_snippet, source_context, context_window, preview_head, recent_diff_excerpt,
    readme_excerpt, body, comments). Naming them would fix eight instances and keep the defect
    for the ninth, so the policy is the one the docstring always stated: the channel carries
    the keys its readers need and nothing else. A new station field carrying source text is
    safe by DEFAULT, not by someone remembering to add it to a list.

    The assertions are on the SERIALIZED output - the canary must appear nowhere in it -
    because that is the shape that would have caught the leak where per-key assertions did not.

    Load-bearing: revert the drop in stdout_safe_report (make the unnamed-value branch carry
    the value, e.g. `else: safe[key] = value`) and test_an_unknown_field_carrying_source_text_
    is_dropped fails with the raw canary present in the serialized output while `rule_id` in
    that same payload still survives - the leak is the unknown key, not the reader keys. The
    same revert fails test_a_matched_value_in_a_key_name_never_reaches_the_channel.
    """

    def test_the_canary_matches_no_pattern(self):
        """The premise of the whole class: if any pattern recognised this value, every assertion
        below could be satisfied by adding one more pattern - the enumeration defect again."""
        from lib.redaction import ALL_PATTERNS, mask_text

        self.assertEqual(mask_text(UNKNOWN_SHAPE_CANARY), UNKNOWN_SHAPE_CANARY)
        self.assertEqual([name for name, pattern in ALL_PATTERNS
                          if pattern.search(UNKNOWN_SHAPE_CANARY)], [])

    def test_an_unknown_field_carrying_source_text_is_dropped(self):
        """A station field nobody has added yet: unknown key, source text no pattern knows."""
        from lib.redaction import stdout_safe_report

        canary = UNKNOWN_SHAPE_CANARY
        report = {"candidates": [{
            "rule_id": "custom-scanner-rule", "path": "src/app.js", "line_number": 3,
            "severity": "high",
            # A field a station adds NEXT MONTH: no list anywhere knows this name.
            "brand_new_source_field": "// exfiltrated source line: " + canary,
        }]}
        safe = stdout_safe_report(report)

        serialized = json.dumps(safe)
        self.assertNotIn(canary, serialized,
                         "an unknown field's source text reached the stdout channel")
        self.assertNotIn("brand_new_source_field", serialized,
                         "the unknown key itself survived on the channel")
        # The channel stays usable: the reader keys survive, and nothing else.
        candidate, = safe["candidates"]
        self.assertEqual(candidate, {"rule_id": "custom-scanner-rule", "path": "src/app.js",
                                     "line_number": 3, "severity": "high"})

    def test_a_matched_value_in_a_key_name_never_reaches_the_channel(self):
        """The KEY half of the dict statement (coord's ruling on the dict-key case): the policy
        decides on the key - allowlist membership - never on the key's TEXT, so a key whose
        text contains a matched value is dropped with its value by construction. No station
        legitimately emits a matched value as a key name; this pins both halves of
        `for key, value in report.items()`."""
        from lib.redaction import stdout_safe_report

        canary = UNKNOWN_SHAPE_CANARY
        report = {
            # The canary AS A KEY at the top level...
            canary: "value under a matched-value key",
            "candidates": [{
                # ...and as BOTH key and value inside a candidate.
                canary: canary,
                "rule_id": "r", "path": "src/app.js", "line_number": 1,
            }],
        }
        serialized = json.dumps(stdout_safe_report(report))
        self.assertNotIn(canary, serialized,
                         "a matched value used as a KEY reached the stdout channel")

    def test_the_census_fields_and_their_containers_are_dropped(self):
        """Every field the agents-iukb census found carrying repository text on a real station
        is dropped unnamed - and the container around it goes with it, not recursed into."""
        from lib.redaction import stdout_safe_report

        canary = UNKNOWN_SHAPE_CANARY
        report = {
            "candidates": [{
                "rule_id": "r", "path": "src/app.js", "line_number": 1,
                "snippet": canary, "raw_match": canary, "candidate_id": "0" * 16,
                "context_snippet": canary,
                "source_context": {"context_snippet": canary},
                "context_window": canary, "preview_head": canary,
                "recent_diff_excerpt": canary, "body": canary, "comments": [canary],
            }],
            "readme_excerpt": canary,
        }
        safe = stdout_safe_report(report)

        serialized = json.dumps(safe)
        self.assertNotIn(canary, serialized)
        for name in ("snippet", "raw_match", "candidate_id", "context_snippet",
                     "source_context", "context_window", "preview_head",
                     "recent_diff_excerpt", "readme_excerpt", "body", "comments"):
            self.assertNotIn(name, serialized, f"{name} survived on the channel")
        candidate, = safe["candidates"]
        self.assertEqual(candidate, {"rule_id": "r", "path": "src/app.js", "line_number": 1})

    def test_an_aws_shaped_canary_is_dropped_by_the_same_policy(self):
        """The policy does not depend on which shapes the masker knows: a value mask_text WOULD
        recognise is dropped too, because the key carrying it is not one a reader consumes.
        (The nested-container canary of the tip commit can no longer reach stdout AT ALL - the
        container is dropped, not recursed-and-masked.)"""
        from lib.redaction import stdout_safe_report

        report = {"candidates": [{
            "rule_id": "r", "path": "src/app.js", "line_number": 1,
            "source_context": {"file": "src/app.js", "line": 1,
                               "context_snippet": f'const k = "{CREDENTIAL}";'},
        }]}
        safe = stdout_safe_report(report)

        self.assertNotIn(CREDENTIAL, json.dumps(safe))
        candidate, = safe["candidates"]
        self.assertNotIn("source_context", candidate)

    def test_carried_strings_are_still_masked_for_credential_shapes(self):
        """mask_text remains the shared outer layer on the strings the channel DOES carry:
        a carried field whose text is credential-SHAPED (a path named after a key) is masked."""
        from lib.redaction import stdout_safe_report

        safe = stdout_safe_report({"candidates": [{
            "rule_id": "r", "path": f"src/{CREDENTIAL}-leaked.js", "line_number": 1}]})
        self.assertNotIn(CREDENTIAL, json.dumps(safe))
        self.assertIn("[redacted:aws-access-key]", safe["candidates"][0]["path"])

    def test_small_scalars_pass_by_shape_and_everything_else_is_dropped(self):
        """Counts and flags a summary carries cannot hold repository text, so they pass by
        shape rather than by name. Strings, containers, and non-list/tuple shapes do not."""
        from lib.redaction import stdout_safe_report

        safe = stdout_safe_report({
            "candidate_count": 3, "unlocatable_count": 1, "line_number_unknown": True,
            "notes": None,
            "scanner": "builtin-regex",          # unnamed string: dropped
            "target": "some-project",            # unnamed string: dropped
            "metrics": {"total": 1},             # container that is not candidates: dropped
            "bloat_candidates": [{"size": 1}],   # a second list of dicts: dropped
            "a_tuple": ("not", "carried"),       # not a carried shape: dropped
            "candidates": [],
        })
        self.assertEqual(safe, {"candidate_count": 3, "unlocatable_count": 1,
                                "line_number_unknown": True, "notes": None,
                                "candidates": []})

    def test_the_raw_record_keeps_the_value_and_stdout_does_not(self):
        """The channel split itself: --output keeps the raw value (a human needs it to rotate
        the credential); stdout and stderr never carry it."""
        import contextlib
        import io

        from lib.redaction import emit_station_result

        canary = UNKNOWN_SHAPE_CANARY
        result = {"candidates": [{"snippet": canary,
                                  "source_context": {"context_snippet": "// " + canary}}]}

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "raw.json"
            emit_station_result(result, str(out))
            self.assertIn(canary, out.read_text(encoding="utf-8"),
                          "the raw local record lost the value a human needs to rotate it")

        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            emit_station_result(result, None)
        self.assertNotIn(canary, stdout.getvalue())
        self.assertNotIn(canary, stderr.getvalue())


class TestStationStdoutChannelIsStructural(unittest.TestCase):
    """agents-qslz: EVERY station CLI that accepts --output must route its result through
    lib.redaction.emit_station_result - the helper next to stdout_safe_report above.

    The class this closes cannot be enumerated by grep: ui-ux-audit printed a VARIABLE
    (`out = json.dumps(result, indent=2)` then `print(out)`), which is why two text searches
    missed different subsets of the same leak. So the assertion is POSITIVE and structural -
    parse each script's AST and require a call to the helper - rather than forbidding
    particular print strings, which is the check that kept missing sites.

    Presence alone is not enough (agents-h0mb review, P1): a station that calls the helper
    only inside `if args.output:` and raw-prints in the `else:` satisfies a presence check
    while still leaking on the no-output path. So the test asserts the two-part property
    that makes the no-output stdout channel PROVABLY the helper's:

    1. UNCONDITIONAL ROUTING - an emit_station_result call that is not nested under any
       conditional or short-circuiting construct (if/while/for/try/match, ternary,
       boolean operator, comprehension), so no sibling branch can route around it.
    2. STDOUT EXCLUSIVITY - no other stdout emission anywhere in the script: no print()
       without file=sys.stderr, no reference to sys.stdout, no pprint (whose default
       stream is stdout). With the helper as the ONLY writer to stdout, whatever reaches
       the terminal on the no-output path is the redacted report by construction.

    Together these hold against the whole mutation family, not one spelling: removing the
    call fails (1), conditioning it on --output fails (1), raw-printing the result on any
    path fails (2), and aliasing or wrapping the helper so no direct unconditional call
    remains also fails (1).
    """

    # Scripts that accept --output but have NO stdout result path at all: --output is
    # required, and stdout carries only a one-line human summary. Each entry is a considered
    # exclusion WITH its reason - an omission and a deliberate exclusion must look different
    # to the next reader.
    STDOUT_RESULT_EXCEPTIONS = {
        "agents/log-check/scripts/parse_logs.py":
            "--output is required=True; stdout carries only a one-line scan summary, never result JSON",
        "agents/test-gap/scripts/find_untested.py":
            "--output is required=True; stdout carries only a one-line deficit summary, never result JSON",
        "agents/vuln-triage/scripts/triage.py":
            "--output is required=True; stdout carries only a one-line cluster summary, never result JSON",
    }

    @staticmethod
    def _output_scripts():
        scripts = {}
        for path in sorted(ROOT.glob("agents/*/scripts/*.py")):
            source = path.read_text(encoding="utf-8")
            if '"--output"' in source or "'--output'" in source:
                scripts[str(path.relative_to(ROOT))] = source
        return scripts

    # A helper call nested under any of these has a sibling execution path that does NOT
    # reach it - which is exactly the leak shape (helper under `if args.output:`, raw print
    # in the `else:`). BoolOp covers the `args.output and emit(...)` short-circuit spelling;
    # comprehensions execute zero times on an empty iterable. TryStar/Match are guarded for
    # older interpreters. `with` is unconditional, so it is deliberately absent.
    _CONDITIONAL_ANCESTORS = tuple(cls for cls in (
        ast.If, ast.While, ast.For, ast.AsyncFor, ast.Try, ast.BoolOp, ast.IfExp,
        ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp,
        getattr(ast, "TryStar", None), getattr(ast, "Match", None),
    ) if cls is not None)

    @staticmethod
    def _is_helper_call(node) -> bool:
        func = node.func
        if isinstance(func, ast.Name) and func.id == "emit_station_result":
            return True
        if isinstance(func, ast.Attribute) and func.attr == "emit_station_result":
            return True
        return False

    @classmethod
    def _calls_helper_unconditionally(cls, source: str) -> bool:
        """True iff the script contains a call to emit_station_result that no conditional,
        loop, short-circuit, or comprehension guards - so the call executes on EVERY path
        through its enclosing scope, the no-output path included."""
        tree = ast.parse(source)

        def visit(node, conditioned):
            if isinstance(node, ast.Call) and cls._is_helper_call(node) and not conditioned:
                return True
            return any(
                visit(child, conditioned or isinstance(node, cls._CONDITIONAL_ANCESTORS))
                for child in ast.iter_child_nodes(node)
            )

        return visit(tree, False)

    @staticmethod
    def _stdout_emission_sites(source: str):
        """Every site that can write to stdout WITHOUT going through the helper: a print()
        whose file= is absent or is not sys.stderr, any reference to sys.stdout (covers
        sys.stdout.write/writelines, json.dump(..., sys.stdout), sys.stdout.fileno()), and
        any pprint call (pprint's default stream is stdout)."""
        tree = ast.parse(source)
        sites = []
        for node in ast.walk(tree):
            if (isinstance(node, ast.Attribute) and node.attr == "stdout"
                    and isinstance(node.value, ast.Name) and node.value.id == "sys"):
                sites.append(f"sys.stdout reference at line {node.lineno}")
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id == "print":
                    file_kw = next((k for k in node.keywords if k.arg == "file"), None)
                    stderr = (file_kw is not None
                              and isinstance(file_kw.value, ast.Attribute)
                              and file_kw.value.attr == "stderr"
                              and isinstance(file_kw.value.value, ast.Name)
                              and file_kw.value.value.id == "sys")
                    if not stderr:
                        sites.append(f"print() without file=sys.stderr at line {node.lineno}")
                if isinstance(func, ast.Name) and func.id == "pprint":
                    sites.append(f"pprint() (default stream is stdout) at line {node.lineno}")
                if isinstance(func, ast.Attribute) and func.attr == "pprint":
                    sites.append(f"pprint.pprint() (default stream is stdout) at line {node.lineno}")
        return sites

    def test_every_output_script_routes_its_result_through_the_helper(self):
        """Load-bearing: point one station back at a raw print (e.g. revert
        accessibility/scripts/audit_a11y.py's main() to `print(json.dumps(result, indent=2))`)
        and this fails with `AssertionError: Lists differ:
        ['agents/accessibility/scripts/audit_a11y.py'] != []` naming the unconverted script.

        Load-bearing against the CONDITIONAL-ROUTING mutant too (agents-h0mb review, P1):
        rewrite a converted station to call the helper only inside `if args.output:` and
        raw-print in the `else:` and this fails the same way, because the remaining helper
        call is conditional and no longer counts.
        """
        scripts = self._output_scripts()
        self.assertTrue(scripts, "no --output scripts found - the enumeration itself is broken")
        missing = [rel for rel, source in scripts.items()
                   if rel not in self.STDOUT_RESULT_EXCEPTIONS
                   and not self._calls_helper_unconditionally(source)]
        self.assertEqual(missing, [],
                         "station CLIs with --output and no UNCONDITIONAL emit_station_result "
                         "call (a call nested under if/try/loops/short-circuits leaves a path "
                         "that routes around the helper): " + ", ".join(missing))

    def test_no_output_script_emits_to_stdout_outside_the_helper(self):
        """The exclusivity half of the property: since NO station script writes to stdout by
        any other spelling, the no-output stdout content can only be the helper's redacted
        report.

        Load-bearing: add `print(json.dumps(result, indent=2))` alongside (not instead of)
        the helper call in any converted station and this fails naming the print site - the
        shape a presence-only check can never catch.
        """
        scripts = self._output_scripts()
        self.assertTrue(scripts, "no --output scripts found - the enumeration itself is broken")
        offenders = {}
        for rel, source in scripts.items():
            if rel in self.STDOUT_RESULT_EXCEPTIONS:
                continue  # excepted scripts print a one-line summary, never result JSON
            sites = self._stdout_emission_sites(source)
            if sites:
                offenders[rel] = sites
        self.assertEqual(offenders, {},
                         "station CLIs writing to stdout outside emit_station_result "
                         "(route summaries through the helper's summary= instead): "
                         + "; ".join(f"{rel}: {sites}" for rel, sites in offenders.items()))

    def test_exception_list_is_exact_current_and_reasoned(self):
        """An exception must still exist, still handle --output, still carry a reason, and
        must not hide a script that DOES call the helper (a stale exception reads as an
        omission)."""
        scripts = self._output_scripts()
        for rel, reason in self.STDOUT_RESULT_EXCEPTIONS.items():
            self.assertIn(rel, scripts,
                          f"exception {rel} no longer handles --output - remove it or the rule changed")
            self.assertTrue(reason.strip(), f"exception {rel} must state its reason")
            self.assertFalse(self._calls_helper_unconditionally(scripts[rel]),
                             f"{rel} calls the helper AND is excepted - drop the stale exception")


if __name__ == "__main__":
    unittest.main()
