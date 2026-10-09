#!/usr/bin/env python3
"""The verifier's pre-pass hands over locations, never discovery's conclusions (agents-pr7).

Non-negotiable #3: discovery and verification are separate agents with zero shared session state.
The verifier may read where a candidate is, and the raw scanner snippet; it must not be primed
with the discovery model's title, description, severity, remediation or exploit chain. These
tests drive the real pre-pass script in a sandbox and assert those strings never cross.
"""

import json
import os
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

    def test_successful_repair_retry_is_discovered_after_no_verdict(self):
        """agents-30q review P1: first attempt had no verdict/candidates, but the
        successful threat-model retry's report remains visible to vuln-verify. Cover
        both -attempt2 and the same-second collision suffix on that retry."""
        for suffix in ("-attempt2", "-attempt2-a1b2c3d4"):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as tmpdir:
                sandbox, target = self._sandbox(Path(tmpdir))
                runs = sandbox / "runs"
                first = runs / "threat-model-target-20260101-000000"
                first.mkdir(parents=True)
                (first / "candidates.json").write_text('{"candidates": []}', encoding="utf-8")
                retry = runs / f"threat-model-target-20260101-000000{suffix}"
                retry.mkdir(parents=True)
                (retry / "report.json").write_text(json.dumps({"findings": [
                    discovery_finding(agent="threat-model", snippet="SUCCESSFUL-RETRY")
                ]}), encoding="utf-8")
                bundle = self._run(sandbox, target)
                self.assertEqual(bundle["candidate_count"], 1)
                self.assertEqual(bundle["candidates"][0]["snippet"], "SUCCESSFUL-RETRY")
                self._assert_no_conclusions(bundle)

    def test_successful_retry_takes_precedence_over_first_attempt_at_same_second(self):
        """The retry's attempt suffix sorts ahead of the unsuffixed attempt within the
        same timestamp, so an earlier discovery candidate cannot mask its verdict."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox, target = self._sandbox(Path(tmpdir))
            first = sandbox / "runs" / "threat-model-target-20260101-000000"
            first.mkdir(parents=True)
            (first / "candidates.json").write_text(json.dumps({"candidates": [
                discovery_finding(agent="threat-model", snippet="STALE-FIRST")
            ]}), encoding="utf-8")
            retry = sandbox / "runs" / "threat-model-target-20260101-000000-attempt2"
            retry.mkdir(parents=True)
            (retry / "report.json").write_text(json.dumps({"findings": [
                discovery_finding(agent="threat-model", snippet="SUCCESSFUL-RETRY")
            ]}), encoding="utf-8")
            bundle = self._run(sandbox, target)
            self.assertEqual(bundle["candidate_count"], 1)
            self.assertEqual(bundle["candidates"][0]["snippet"], "SUCCESSFUL-RETRY")
            self._assert_no_conclusions(bundle)

    def test_collision_suffixed_discovery_runs_remain_visible(self):
        """agents-30q review P1: the dispatcher's eight-hex collision suffix is
        also accepted on a non-retry discovery run, without accepting arbitrary names."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox, target = self._sandbox(Path(tmpdir))
            invalid = sandbox / "runs" / "vuln-discovery-target-20990101-000000-nothex12"
            invalid.mkdir(parents=True)
            (invalid / "candidates.json").write_text(json.dumps({"candidates": [
                discovery_finding(snippet="INVALID-SUFFIX")]}), encoding="utf-8")
            run_dir = sandbox / "runs" / "vuln-discovery-target-20260101-000000-a1b2c3d4"
            run_dir.mkdir(parents=True)
            (run_dir / "candidates.json").write_text(json.dumps({"candidates": [
                discovery_finding(snippet="COLLISION-SUFFIX")]}), encoding="utf-8")
            bundle = self._run(sandbox, target)
            self.assertEqual(bundle["candidate_count"], 1)
            self.assertEqual(bundle["candidates"][0]["snippet"], "COLLISION-SUFFIX")
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


class TestPathConfinement(unittest.TestCase):
    """agents-075: a store/run-dir supplied path must never read outside the target.

    The sandbox keeps this from being a kernel-level escape inside the bubblewrap, but on the
    unsandboxed path (non-Linux, or FACTORY_ALLOW_UNSANDBOXED=1) this pre-pass runs as the
    operator, so confinement must be enforced here rather than delegated to the sandbox.
    """

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

    def _candidate(self, path, line_number=1):
        return {
            "fingerprint": "f" * 64,
            "agent": "vuln-discovery",
            "rule_id": "dom-injection-sink",
            "path": path,
            "line_number": line_number,
            "snippet": "x",
        }

    def _run(self, sandbox: Path, target: Path, candidates) -> dict:
        out = sandbox / "out.json"
        findings_file = sandbox / "findings.json"
        findings_file.write_text(json.dumps({"findings": candidates}), encoding="utf-8")
        cmd = [sys.executable,
               str(sandbox / "agents" / "vuln-verify" / "scripts" / "prepare_verification.py"),
               "--target", str(target), "--output", str(out),
               "--findings", str(findings_file)]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        self.assertEqual(res.returncode, 0, res.stderr)
        return json.loads(out.read_text(encoding="utf-8"))

    def _source_context(self, bundle: dict) -> dict:
        self.assertEqual(bundle["candidate_count"], 1)
        return bundle["candidates"][0]["source_context"]

    def test_traversal_path_is_refused_without_reading_outside(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox, target = self._sandbox(Path(tmpdir))
            outside = sandbox / "canary.txt"
            outside.write_text("CANARY-SECRET-DO-NOT-READ\n", encoding="utf-8")

            bundle = self._run(sandbox, target, [self._candidate("../canary.txt")])

            ctx = self._source_context(bundle)
            self.assertIn("outside target directory", ctx["error"])
            self.assertNotIn("CANARY-SECRET-DO-NOT-READ", json.dumps(bundle))

    def test_absolute_path_is_refused(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox, target = self._sandbox(Path(tmpdir))
            secret = sandbox / "secret.txt"
            secret.write_text("ABSOLUTE-SECRET\n", encoding="utf-8")

            bundle = self._run(sandbox, target, [self._candidate(str(secret))])

            ctx = self._source_context(bundle)
            self.assertIn("outside target directory", ctx["error"])
            self.assertNotIn("ABSOLUTE-SECRET", json.dumps(bundle))

    def test_symlink_pointing_outside_is_refused(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox, target = self._sandbox(Path(tmpdir))
            outside = sandbox / "linked-secret.txt"
            outside.write_text("LINKED-SECRET\n", encoding="utf-8")
            link = target / "src" / "evil-link"
            os.symlink(outside, link)

            bundle = self._run(sandbox, target, [self._candidate("src/evil-link")])

            ctx = self._source_context(bundle)
            self.assertIn("outside target directory", ctx["error"])
            self.assertNotIn("LINKED-SECRET", json.dumps(bundle))

    def test_normal_in_target_path_still_reads(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox, target = self._sandbox(Path(tmpdir))

            bundle = self._run(sandbox, target, [self._candidate("src/app.js", line_number=2)])

            ctx = self._source_context(bundle)
            self.assertNotIn("error", ctx)
            self.assertIn("el.innerHTML = user;", ctx["context_snippet"])


if __name__ == "__main__":
    unittest.main()
