#!/usr/bin/env python3
"""pr-fixer's pre-pass must survive an unknown line, and keep the finding (agents-fy26).

`line_no = int(rec.get("line_number") or 1)` raises ValueError on the factory's own "?" marker
for a line the scanner could not name (lib/redaction.publishable_line_number returns it), and the
call sat OUTSIDE the file-read try, so one sentinel candidate took the whole station down - the
same class as the vuln-verify crash, one station over. The finding is still fixable, so it is
windowed from the top of the file rather than dropped.
"""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "agents" / "pr-fixer" / "scripts" / "collect_failures.py"


class TestPrFixerUnknownLine(unittest.TestCase):
    def _sandbox(self, tmp: Path):
        sandbox = tmp / "sandbox"
        script = sandbox / "agents" / "pr-fixer" / "scripts" / "collect_failures.py"
        script.parent.mkdir(parents=True)
        shutil.copyfile(SCRIPT, script)
        # The script imports the shared path-confinement helper and derives FACTORY_ROOT from its
        # own location, so the sandbox mirrors the real repo layout.
        helper = sandbox / "lib" / "path_security.py"
        helper.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / "lib" / "path_security.py", helper)
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


if __name__ == "__main__":
    unittest.main()
