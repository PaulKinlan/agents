#!/usr/bin/env python3
"""Guard rail for the CI redaction: a candidate report must never be echoed whole.

`secret-scan` candidates carry the matched credential in `snippet` / `raw_match`, and this
summary is printed into GitHub Actions logs, which are public on a public repository.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

FACTORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(FACTORY_ROOT))

from lib.candidate_summary import summarise  # noqa: E402

# A benign but distinctive value. It is deliberately not shaped like a real credential:
# the redaction is field-based (raw_match/snippet are simply never read), so a value the
# secret-scan rules would themselves match adds nothing but a permanent self-scan hit.
SECRET = "placeholder-value-that-must-never-be-printed-1234567890"


class TestCandidateSummary(unittest.TestCase):
    def _report(self, tmp: Path) -> Path:
        path = tmp / "ci-secrets.json"
        path.write_text(json.dumps({
            "target": ".",
            "scanner": "scan.py",
            "candidate_count": 1,
            "candidates": [{
                "rule_id": "aws-access-key",
                "path": "src/config.js",
                "line_number": 12,
                "severity": "high",
                "snippet": f"const key = '{SECRET}';",
                "raw_match": SECRET,
            }],
        }))
        return path

    def test_secret_value_never_appears_in_output(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._report(Path(tmpdir))
            output = summarise(path)

            self.assertNotIn(SECRET, output)
            self.assertNotIn("raw_match", output)
            self.assertNotIn("snippet", output)
            # The location must still be reported, or the summary is useless.
            self.assertIn("aws-access-key", output)
            self.assertIn("src/config.js:12", output)
            self.assertIn("1 candidate(s)", output)

    def test_cli_stdout_is_clean(self):
        """Same assertion through the real CLI, which is what CI runs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._report(Path(tmpdir))
            res = subprocess.run(
                [sys.executable, str(FACTORY_ROOT / "lib" / "candidate_summary.py"), str(path)],
                capture_output=True, text=True, timeout=60,
            )

            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertNotIn(SECRET, res.stdout)
            self.assertNotIn(SECRET, res.stderr)
            self.assertIn("aws-access-key", res.stdout)

    def test_credential_shaped_path_is_masked(self):
        """A file named after the key must not leak through the `path` field.

        The first version read a whitelist of fields, but `path` is a field the scanner fills
        with the *name* of the file it matched in — and a name can hold the credential.
        """
        key = "AKIA" + "IOSFODNN7EXAMPLE"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "ci-secrets.json"
            path.write_text(json.dumps({
                "scanner": "scan.py",
                "candidates": [{
                    "rule_id": "generic-api-key",
                    "path": f"src/{key}_leak.js",
                    "line_number": 1,
                    "severity": "high",
                    "snippet": f"const api_key = '{key}';",
                    "raw_match": key,
                }],
            }))
            output = summarise(path)
            self.assertNotIn(key, output)
            self.assertIn("[redacted:", output)
            self.assertIn("generic-api-key", output)

    def test_cli_stdout_masks_a_credential_shaped_path(self):
        """The same case through the real CLI, which is what CI runs."""
        key = "AKIA" + "IOSFODNN7EXAMPLE"
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "ci-secrets.json"
            path.write_text(json.dumps({"candidates": [{
                "rule_id": "generic-api-key", "path": f"src/{key}.js", "line_number": 1,
                "snippet": "x", "raw_match": key,
            }]}))
            res = subprocess.run(
                [sys.executable, str(FACTORY_ROOT / "lib" / "candidate_summary.py"), str(path)],
                capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertNotIn(key, res.stdout)
            self.assertNotIn(key, res.stderr)

    def test_unrecognised_opaque_identity_falls_back_to_a_placeholder(self):
        """No pattern knows this value, so only the shape check can hold it back."""
        unknown = "zkq" + "7" * 24
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "ci-secrets.json"
            path.write_text(json.dumps({"candidates": [{
                "rule_id": f"provider-{unknown}",
                "path": f"src/{unknown}.js",
                "line_number": "line 1",
                "severity": {"level": unknown},
            }]}))
            output = summarise(path)
            self.assertNotIn(unknown, output)
            self.assertIn("unknown", output)
            self.assertIn("unclassified", output)

    def test_identity_fields_survive_when_they_are_ordinary(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = self._report(Path(tmpdir))
            output = summarise(path)
            self.assertIn("aws-access-key", output)
            self.assertIn("src/config.js:12", output)
            self.assertIn("(high)", output)

    def test_bare_list_report_is_supported(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "list.json"
            path.write_text(json.dumps([{"rule_id": "r", "path": "a.js", "line_number": 1}]))
            output = summarise(path)
            self.assertIn("1 candidate(s)", output)
            self.assertIn("unrated", output)

    def test_missing_report_fails_loudly(self):
        res = subprocess.run(
            [sys.executable, str(FACTORY_ROOT / "lib" / "candidate_summary.py"), "/nonexistent/x.json"],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(res.returncode, 1)
        self.assertIn("not found", res.stderr)


if __name__ == "__main__":
    unittest.main()
