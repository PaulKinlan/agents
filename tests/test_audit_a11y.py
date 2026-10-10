#!/usr/bin/env python3
"""agents-qslz: the accessibility station's stdout drops the candidate id and the match.

audit_a11y assigns candidate ids (agents-rdyb), so before the class fix its no---output
branch printed sha256(rule NUL path NUL match_text NUL ordinal)[:16] - a confirmation
oracle for the matched line - straight to the terminal. This drives the real CLI.
"""

import json
import os
os.environ.setdefault("FACTORY_ALLOW_UNPINNED_TOOLS", "1")  # agents-7bj: tests use unpinned stub tools
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class TestStdoutChannelDropsTheMatch(unittest.TestCase):
    """Driven through the real CLI with no --output, because the defect was a raw
    `print(output_json)` in exactly that branch, and a unit test of the helper cannot see
    which branch ran.

    Load-bearing: revert main()'s output to `print(json.dumps(result, indent=2))` and this
    fails with `AssertionError: 'd3b997c7b44a860a' != '[redacted]' ... the confirmation
    oracle reached the station's stdout unmasked` (digest is fixture-derived).
    """

    def test_stdout_drops_id_and_match_but_keeps_location(self):
        script = ROOT / "agents" / "accessibility" / "scripts" / "audit_a11y.py"
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "target"
            target.mkdir()
            (target / "index.html").write_text('<html><body><img src="x.png"></body></html>\n',
                                               encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(script), "--target", str(target)],
                capture_output=True, text=True, timeout=120, cwd=str(ROOT),
                env={**os.environ, "PYTHONPATH": str(ROOT)})
        self.assertEqual(result.returncode, 0, result.stderr[-500:])
        artefact = json.loads(result.stdout)
        self.assertTrue(artefact["candidates"], "fixture must yield a candidate carrying a match")
        for candidate in artefact["candidates"]:
            self.assertEqual(candidate["candidate_id"], "[redacted]",
                             "the confirmation oracle reached the station's stdout unmasked")
            self.assertEqual(candidate["snippet"], "[redacted]")
            # The channel must stay usable: the location still ships.
            self.assertIn("rule_id", candidate)
            self.assertIn("path", candidate)
            self.assertIn("line_number", candidate)
        self.assertIn("stdout redacts matched values", result.stderr)


if __name__ == "__main__":
    unittest.main()
