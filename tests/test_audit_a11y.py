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

sys.path.insert(0, str(ROOT))
from lib.candidate_batching import coerce_scanned_files  # noqa: E402


class TestStdoutChannelDropsTheMatch(unittest.TestCase):
    """Driven through the real CLI with no --output, because the defect was a raw
    `print(output_json)` in exactly that branch, and a unit test of the helper cannot see
    which branch ran.

    Load-bearing: revert main()'s output to `print(json.dumps(result, indent=2))` and this
    fails with `AssertionError: 'candidate_id' unexpectedly found in ...` - the confirmation
    oracle reached the station's stdout (digest is fixture-derived).
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
            # The allowlist drops the match and its derived digest OUTRIGHT - the keys are
            # absent, not masked in place (agents-h0mb).
            self.assertNotIn("candidate_id", candidate,
                             "the confirmation oracle reached the station's stdout")
            self.assertNotIn("snippet", candidate)
            # The channel must stay usable: the location still ships.
            self.assertIn("rule_id", candidate)
            self.assertIn("path", candidate)
            self.assertIn("line_number", candidate)
        self.assertIn("stdout redacts matched values", result.stderr)


class TestPayloadScannedFilesIsAnIntegerCount(unittest.TestCase):
    """agents-owro1: the pre-pass payload emitted `scanned_files` as a LIST of paths while the
    station's own report.schema.json declares {"type": "integer"} and the factory coerces the
    payload key on EVERY pre-pass run (factory -> lib/candidate_batching.coerce_scanned_files),
    so every `factory run accessibility` died before the engine session with
    "scanned_files must be an integer count, not [] (list)".

    Load-bearing: revert main()'s payload to the path list and the first assertion fails naming
    the list; the coercion assertion names the actual consumer that refused it.
    """

    def _run_and_read_artefact(self, files):
        script = ROOT / "agents" / "accessibility" / "scripts" / "audit_a11y.py"
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "target"
            target.mkdir()
            for rel, body in files.items():
                p = target / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(body, encoding="utf-8")
            out = Path(tmp) / "artefact.json"
            result = subprocess.run(
                [sys.executable, str(script), "--target", str(target), "--output", str(out)],
                capture_output=True, text=True, timeout=120, cwd=str(ROOT),
                env={**os.environ, "PYTHONPATH": str(ROOT)})
            self.assertEqual(result.returncode, 0, result.stderr[-500:])
            return json.loads(out.read_text(encoding="utf-8"))

    def test_scanned_files_is_the_integer_count_of_html_files_scanned(self):
        artefact = self._run_and_read_artefact({
            "index.html": "<html><body><img src='a.png'></body></html>\n",
            "about.html": "<html><body>fine</body></html>\n",
            "notes.md": "# not scanned\n",
        })
        # An int, not a list: the exact defect shape the factory's coercion refuses.
        self.assertIsInstance(artefact["scanned_files"], int,
                              "payload scanned_files must be a count, not a path list")
        self.assertEqual(artefact["scanned_files"], 2)

    def test_the_factory_consumer_accepts_the_emitted_value(self):
        # The consumer that exit-2'd the station: coerce_scanned_files on the real payload.
        artefact = self._run_and_read_artefact({
            "index.html": "<html><body><img src='a.png'></body></html>\n",
        })
        self.assertEqual(coerce_scanned_files(artefact["scanned_files"]), 1)

    def test_zero_html_files_yields_a_coercible_zero(self):
        # The observed failure quoted 'not [] (list)': the empty-target shape.
        artefact = self._run_and_read_artefact({"README.md": "# no html\n"})
        self.assertEqual(artefact["scanned_files"], 0)
        self.assertEqual(coerce_scanned_files(artefact["scanned_files"]), 0)


if __name__ == "__main__":
    unittest.main()
