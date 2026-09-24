#!/usr/bin/env python3
"""The deterministic secret scanner, and the contract that keeps it aligned with the redactor.

Two lists have to agree: `agents/secret-scan/scripts/scan.py` decides what enters the pipeline,
`lib/redaction.py` decides what may leave it. A rule the redactor does not know is a publish path
for whatever that rule matches, and a rule the scanner does not know is a credential nobody ever
hears about. `agents-btg` was the first case — four vendor shapes were maskable but undetectable.

Fixtures are assembled from parts so this file stays clean under the repository's own scan.
"""

import importlib.machinery
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

FACTORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(FACTORY_ROOT))

from lib.redaction import BARE_PATTERNS, BLOCK_PATTERNS, PATTERNS as REDACTION_PATTERNS  # noqa: E402

_loader = importlib.machinery.SourceFileLoader(
    "secret_scan", str(FACTORY_ROOT / "agents" / "secret-scan" / "scripts" / "scan.py")
)
_spec = importlib.util.spec_from_loader("secret_scan", _loader)
secret_scan = importlib.util.module_from_spec(_spec)
_loader.exec_module(secret_scan)

# Shapes the redactor knows only in a whole-block form; the scanner reports the header instead.
REDACTION_ONLY_RULES = {"pem-block"}

SHAPES = {
    "private-key": "-----BEGIN " + "RSA PRIVATE KEY-----",
    "aws-access-key": "AKIA" + "TESTPROBE0000000",
    "github-pat": "ghp_" + "a" * 36,
    "slack-token": "xox" + "b-123456789012-123456789012" + "-abcdef",
    "jwt-token": "ey" + "A" * 12 + ".ey" + "B" * 12 + "." + "C" * 12,
    "openai-key": "sk-" + "proj-" + "Ab1" * 11,
    "stripe-key": "sk_" + "live_" + "51H8xQ2eZvKYlo2C0000000000",
    "google-api-key": "AIza" + "Sy" + "A" * 33,
    "google-oauth": "ya29." + "A" * 25,
    "gitlab-pat": "glpat-" + "x" * 25,
    "npm-token": "npm_" + "b" * 36,
}


def scanner_rule_ids():
    return {rule_id for rule_id, _ in secret_scan.PATTERNS}


def redaction_rule_ids():
    return {rule_id for rule_id, _ in REDACTION_PATTERNS + BARE_PATTERNS + BLOCK_PATTERNS}


class TestScannerCoverage(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="factory-secret-scan-")
        self.addCleanup(temporary.cleanup)
        self.tree = Path(temporary.name)
        self.output = self.tree.parent / "candidates.json"

    def scan(self):
        subprocess.run(
            [sys.executable, str(FACTORY_ROOT / "agents" / "secret-scan" / "scripts" / "scan.py"),
             "--target", str(self.tree), "--output", str(self.output)],
            capture_output=True, text=True, timeout=60, check=True,
        )
        return json.loads(self.output.read_text())["candidates"]

    def test_every_advertised_shape_is_detected(self):
        """One planted credential per shape: a shape that is advertised and undetectable is the
        agents-btg bug — maskable in theory, invisible in practice."""
        for rule_id, value in SHAPES.items():
            (self.tree / f"{rule_id}.js").write_text(f'const x = "{value}";\n')

        detected = {candidate["rule_id"] for candidate in self.scan()}

        for rule_id in sorted(SHAPES):
            with self.subTest(rule=rule_id):
                self.assertIn(rule_id, detected)

    def test_scanner_rules_are_all_known_to_the_redactor(self):
        """The guard that matters: a scanner rule the redactor does not mask is a leak path."""
        unknown = scanner_rule_ids() - redaction_rule_ids()
        self.assertEqual(unknown, set(), f"scanner rules with no redaction: {sorted(unknown)}")

    def test_redaction_only_rules_are_declared(self):
        """Redaction may know more shapes than the scanner, but only from an explicit list."""
        extra = redaction_rule_ids() - scanner_rule_ids()
        self.assertEqual(extra, REDACTION_ONLY_RULES,
                         "add the shape to scan.py PATTERNS, or declare it here with a reason")

    def test_vendor_key_in_an_assignment_is_one_finding(self):
        """The specific rule and the generic catch-all both match; report it once, specifically."""
        (self.tree / "config.js").write_text(f'api_key = "{SHAPES["openai-key"]}";\n')

        candidates = self.scan()

        self.assertEqual(len(candidates), 1, candidates)
        self.assertEqual(candidates[0]["rule_id"], "openai-key")

    def test_two_credentials_on_one_line_are_both_reported(self):
        """Dedup is by matched span, not by line: a line can hold two different credentials."""
        (self.tree / "two.js").write_text(
            f'const a = "{SHAPES["aws-access-key"]}", b = "{SHAPES["github-pat"]}";\n'
        )

        rule_ids = [candidate["rule_id"] for candidate in self.scan()]

        self.assertCountEqual(rule_ids, ["aws-access-key", "github-pat"])

    def test_benign_placeholder_still_filtered(self):
        """Existing behaviour kept: an obvious placeholder is not worth a model round trip."""
        (self.tree / "sample.js").write_text('api_key = "your_api_key_placeholder_000000";\n')

        self.assertEqual(self.scan(), [])


if __name__ == "__main__":
    unittest.main()
