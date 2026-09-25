#!/usr/bin/env python3
"""The verifier's pre-pass hands over locations, never discovery's conclusions (agents-pr7).

Non-negotiable #3: discovery and verification are separate agents with zero shared session state.
The verifier may read where a candidate is, and the raw scanner snippet; it must not be primed
with the discovery model's title, description, severity, remediation or exploit chain. These
tests drive the real pre-pass script in a sandbox and assert those strings never cross.
"""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "agents" / "vuln-verify" / "scripts" / "prepare_verification.py"

CONCLUSIONS = {
    "title": "CONCLUSION-title input reaches innerHTML",
    "description": "CONCLUSION-description attacker controls the DOM",
    "remediation": "CONCLUSION-remediation use textContent",
    "exploit_chain": "CONCLUSION-exploit fetch then eval",
    "original_title": "CONCLUSION-legacy-shaped key",
}


def discovery_finding(**overrides):
    finding = {
        "fingerprint": "a" * 64,
        "agent": "vuln-discovery",
        "rule_id": "dom-injection-sink",
        "path": "src/app.js",
        "line_number": 2,
        "snippet": "el.innerHTML = user;",
        "severity": "high",
        "state": "new",
    }
    finding.update(CONCLUSIONS)
    finding.update(overrides)
    return finding


class TestVerifierPriming(unittest.TestCase):
    def _sandbox(self, tmp: Path):
        sandbox = tmp / "sandbox"
        script = sandbox / "agents" / "vuln-verify" / "scripts" / "prepare_verification.py"
        script.parent.mkdir(parents=True)
        shutil.copyfile(SCRIPT, script)
        target = sandbox / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "app.js").write_text(
            "const el = document.body;\nel.innerHTML = user;\n", encoding="utf-8")
        return sandbox, target

    def _run(self, sandbox: Path, target: Path, findings_file=None) -> dict:
        out = sandbox / "out.json"
        cmd = [sys.executable,
               str(sandbox / "agents" / "vuln-verify" / "scripts" / "prepare_verification.py"),
               "--target", str(target), "--output", str(out)]
        if findings_file is not None:
            cmd += ["--findings", str(findings_file)]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        self.assertEqual(res.returncode, 0, res.stderr)
        return json.loads(out.read_text(encoding="utf-8"))

    def _assert_no_conclusions(self, bundle: dict):
        serialized = json.dumps(bundle)
        for key, value in CONCLUSIONS.items():
            with self.subTest(conclusion=key):
                self.assertNotIn(value, serialized)
                self.assertNotIn(key, serialized)

    def test_the_findings_store_is_reduced_to_locations(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox, target = self._sandbox(Path(tmpdir))
            (sandbox / "findings").mkdir()
            (sandbox / "findings" / "target.json").write_text(json.dumps({"findings": {
                "a" * 64: discovery_finding(),
                # Another agent's conclusions must not reach the verifier at all.
                "b" * 64: discovery_finding(agent="docs-drift", rule_id="doc-broken-link"),
                # A fixed finding is not a candidate.
                "c" * 64: discovery_finding(state="fixed"),
            }}), encoding="utf-8")

            bundle = self._run(sandbox, target)

            self.assertEqual(bundle["candidate_count"], 1)
            candidate = bundle["candidates"][0]
            self.assertEqual(candidate["rule_id"], "dom-injection-sink")
            self.assertEqual(candidate["path"], "src/app.js")
            self.assertEqual(candidate["line_number"], 2)
            self.assertEqual(candidate["snippet"], "el.innerHTML = user;")
            self.assertIn("context_snippet", candidate["source_context"])
            self._assert_no_conclusions(bundle)

    def test_the_scanner_output_is_preferred_over_the_model_report(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox, target = self._sandbox(Path(tmpdir))
            run_dir = sandbox / "runs" / "vuln-discovery-target-20260101-000000"
            run_dir.mkdir(parents=True)
            (run_dir / "candidates.json").write_text(json.dumps({"candidates": [
                {"rule_id": "dom-injection-sink", "path": "src/app.js", "line_number": 2,
                 "snippet": "el.innerHTML = user;"},
            ]}), encoding="utf-8")
            (run_dir / "report.json").write_text(json.dumps({"findings": [
                discovery_finding(snippet="SENTINEL-FROM-REPORT"),
            ]}), encoding="utf-8")

            bundle = self._run(sandbox, target)

            self.assertEqual(bundle["candidate_count"], 1)
            self.assertEqual(bundle["candidates"][0]["snippet"], "el.innerHTML = user;")
            self.assertNotIn("SENTINEL-FROM-REPORT", json.dumps(bundle))
            self._assert_no_conclusions(bundle)

    def test_the_model_report_is_still_a_stripped_fallback(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox, target = self._sandbox(Path(tmpdir))
            run_dir = sandbox / "runs" / "threat-model-target-20260101-000000"
            run_dir.mkdir(parents=True)
            (run_dir / "report.json").write_text(json.dumps({"findings": [
                discovery_finding(agent="threat-model"),
            ]}), encoding="utf-8")

            bundle = self._run(sandbox, target)

            self.assertEqual(bundle["candidate_count"], 1)
            self.assertEqual(bundle["candidates"][0]["path"], "src/app.js")
            self._assert_no_conclusions(bundle)

    def test_direct_findings_input_is_stripped_too(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            sandbox, target = self._sandbox(tmp)
            direct = tmp / "direct.json"
            direct.write_text(json.dumps({"findings": [discovery_finding()]}), encoding="utf-8")

            bundle = self._run(sandbox, target, findings_file=direct)

            self.assertEqual(bundle["candidate_count"], 1)
            self._assert_no_conclusions(bundle)


if __name__ == "__main__":
    unittest.main()
