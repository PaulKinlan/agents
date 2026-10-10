#!/usr/bin/env python3
"""pr-fixer's pre-pass must survive an unknown line, and keep the finding (agents-fy26).

`line_no = int(rec.get("line_number") or 1)` raises ValueError on the factory's own "?" marker
for a line the scanner could not name (lib/redaction.publishable_line_number returns it), and the
call sat OUTSIDE the file-read try, so one sentinel candidate took the whole station down - the
same class as the vuln-verify crash, one station over. The finding is still fixable, so it is
windowed from the top of the file rather than dropped.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "agents" / "pr-fixer" / "scripts" / "collect_failures.py"

from tests.sandbox_fixtures import copy_station_script  # noqa: E402


class TestPrFixerUnknownLine(unittest.TestCase):
    def _sandbox(self, tmp: Path):
        sandbox = tmp / "sandbox"
        # The script derives FACTORY_ROOT from its own location, so the sandbox mirrors the real
        # repo layout; the shared builder (agents-8ztd) copies the script's lib import closure
        # rather than a hand-maintained list.
        copy_station_script(sandbox, SCRIPT, "agents/pr-fixer/scripts/collect_failures.py")
        target = sandbox / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "app.js").write_text(
            "const a = 1;\nconst b = 2;\n", encoding="utf-8")
        return sandbox, target

    def _finding(self, **overrides):
        finding = {
            "fingerprint": "a" * 64,
            "agent": "vuln-discovery",
            "rule_id": "dom-injection-sink",
            "path": "src/app.js",
            "line_number": 2,
            "snippet": "x",
            "severity": "high",
            "state": "new",
        }
        finding.update(overrides)
        return finding

    def _run(self, sandbox: Path, target: Path, findings) -> dict:
        out = sandbox / "out.json"
        findings_dir = sandbox / "findings"
        findings_dir.mkdir(exist_ok=True)
        store = findings_dir / f"{target.name}-findings.json"
        store.write_text(json.dumps({f["fingerprint"]: f for f in findings}), encoding="utf-8")
        cmd = [sys.executable,
               str(sandbox / "agents" / "pr-fixer" / "scripts" / "collect_failures.py"),
               "--target", str(target), "--output", str(out)]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        self.assertEqual(res.returncode, 0, res.stderr)
        return json.loads(out.read_text(encoding="utf-8"))

    def test_the_question_mark_sentinel_no_longer_crashes_the_station(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox, target = self._sandbox(Path(tmpdir))

            bundle = self._run(sandbox, target, [self._finding(line_number="?")])

            self.assertEqual(bundle["fixable_candidates_count"], 1)

    def test_a_missing_line_number_is_windowed_from_the_top(self):
        no_line = self._finding()
        del no_line["line_number"]
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox, target = self._sandbox(Path(tmpdir))

            bundle = self._run(sandbox, target, [no_line])

            self.assertEqual(bundle["fixable_candidates_count"], 1)

    def test_a_mixed_batch_keeps_every_finding(self):
        no_line = self._finding(fingerprint="b" * 64, rule_id="no-line")
        del no_line["line_number"]
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox, target = self._sandbox(Path(tmpdir))

            bundle = self._run(sandbox, target, [
                self._finding(fingerprint="c" * 64, rule_id="numeric", line_number=2),
                self._finding(fingerprint="d" * 64, rule_id="sentinel", line_number="?"),
                no_line,
            ])

            self.assertEqual(bundle["fixable_candidates_count"], 3,
                             "a finding was dropped, not windowed")

    def test_a_bound_row_carries_the_persisted_candidate_id_onto_the_bundle(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox, target = self._sandbox(Path(tmpdir))

            bundle = self._run(sandbox, target, [self._finding(candidate_id="c6cab6881fc8535e")])

            self.assertEqual(bundle["candidates"][0]["candidate_id"], "c6cab6881fc8535e")

    def test_an_unbound_row_omits_the_key_and_is_carried_as_absent(self):
        # The ORDINARY case, not the edge: save() routes the record through
        # redact_for_storage, which pops candidate_id and restores it only when truthy
        # (lib/redaction.py:305, :390-392), so a row with no scanner binding reaches disk with
        # the KEY ABSENT - not null. This store fixture is that shape, and the station must read it
        # with .get rather than by index or it raises KeyError here. The other fields are asserted
        # too, so a rebuild that dropped the whole record could not pass this test silently.
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox, target = self._sandbox(Path(tmpdir))
            unbound = self._finding(rule_id="unbound-row")
            self.assertNotIn("candidate_id", unbound, "this test is only load-bearing without the key")

            bundle = self._run(sandbox, target, [unbound])

            candidate = bundle["candidates"][0]
            self.assertIsNone(candidate["candidate_id"],
                              "an absent id must not be fabricated into a value")
            self.assertEqual(bundle["fixable_candidates_count"], 1)
            self.assertEqual(candidate["rule_id"], "unbound-row")
            self.assertEqual(candidate["fingerprint"], "a" * 12)
            self.assertEqual(candidate["path"], "src/app.js")
            self.assertEqual(candidate["line_number"], 2)
            self.assertIn("2: const b = 2;", candidate["source_context"])


if __name__ == "__main__":
    unittest.main()
