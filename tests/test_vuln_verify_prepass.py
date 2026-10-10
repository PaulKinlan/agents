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
        # prepare_verification.py imports shared lib helpers (path confinement, the line-sentinel
        # rule); the sandbox mirrors the real repo layout so FACTORY_ROOT resolves to this tree.
        helper = sandbox / "lib" / "path_security.py"
        helper.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / "lib" / "path_security.py", helper)
        shutil.copyfile(ROOT / "lib" / "line_numbers.py", sandbox / "lib" / "line_numbers.py")
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
            # No fabrication: a store record carries no candidate id, so the reducer must not
            # invent one. An invented id would be worse than none - it would look like provenance.
            self.assertNotIn("candidate_id", candidate)
            self._assert_no_conclusions(bundle)

    def test_the_scanner_output_is_preferred_over_the_model_report(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox, target = self._sandbox(Path(tmpdir))
            run_dir = sandbox / "runs" / "vuln-discovery-target-20260101-000000"
            run_dir.mkdir(parents=True)
            (run_dir / "candidates.json").write_text(json.dumps({"candidates": [
                {"rule_id": "dom-injection-sink", "path": "src/app.js", "line_number": 2,
                 "snippet": "el.innerHTML = user;", "candidate_id": "c6cab6881fc8535e"},
            ]}), encoding="utf-8")
            (run_dir / "report.json").write_text(json.dumps({"findings": [
                discovery_finding(snippet="SENTINEL-FROM-REPORT"),
            ]}), encoding="utf-8")

            bundle = self._run(sandbox, target)

            self.assertEqual(bundle["candidate_count"], 1)
            self.assertEqual(bundle["candidates"][0]["snippet"], "el.innerHTML = user;")
            # agents-q0mt, condition 3: the emitted id must SURVIVE both drop points - the
            # LOCATION_FIELDS allowlist and the literal rebuild below it. Losing it here would be
            # silent and would put the reconstruction back for the rows that had escaped it.
            self.assertEqual(bundle["candidates"][0]["candidate_id"], "c6cab6881fc8535e")
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
        # prepare_verification.py imports shared lib helpers (path confinement, the line-sentinel
        # rule); the sandbox mirrors the real repo layout so FACTORY_ROOT resolves to this tree.
        helper = sandbox / "lib" / "path_security.py"
        helper.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / "lib" / "path_security.py", helper)
        shutil.copyfile(ROOT / "lib" / "line_numbers.py", sandbox / "lib" / "line_numbers.py")
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


class TestUnknownLineNumbers(unittest.TestCase):
    """agents-fy26: an unknown LINE must not crash the station, and must not be presented as real.

    `"?"` is the factory's own unknown marker - lib/redaction.publishable_line_number returns it
    rather than publish a line it cannot trust - so 16 candidates on web-ai-showcase's nightly
    carried it. `"?" <= 0` raised TypeError, vuln-verify errored, and the seven stations after it
    were SKIPPED: their findings read UNKNOWN to anyone who looked and clean to anyone who did not.

    The other half is quieter and was already in the code: an absent line became line 1, which
    hands the verifier a fabricated location. Both directions are pinned here.
    """

    def _sandbox(self, tmp: Path, app_lines: int = 2):
        sandbox = tmp / "sandbox"
        script = sandbox / "agents" / "vuln-verify" / "scripts" / "prepare_verification.py"
        script.parent.mkdir(parents=True)
        shutil.copyfile(SCRIPT, script)
        helper = sandbox / "lib" / "path_security.py"
        helper.parent.mkdir(parents=True)
        shutil.copyfile(ROOT / "lib" / "path_security.py", helper)
        shutil.copyfile(ROOT / "lib" / "line_numbers.py", sandbox / "lib" / "line_numbers.py")
        target = sandbox / "target"
        (target / "src").mkdir(parents=True)
        body = "".join(f"const line{i} = {i};\n" for i in range(1, app_lines + 1))
        (target / "src" / "app.js").write_text(body, encoding="utf-8")
        return sandbox, target

    def _candidate(self, **overrides):
        candidate = {
            "fingerprint": "f" * 64,
            "agent": "vuln-discovery",
            "rule_id": "dom-injection-sink",
            "path": "src/app.js",
            "line_number": 2,
            "snippet": "el.innerHTML = user;",
        }
        candidate.update(overrides)
        return candidate

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

    def test_the_question_mark_sentinel_no_longer_crashes_the_station(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox, target = self._sandbox(Path(tmpdir))

            bundle = self._run(sandbox, target, [self._candidate(line_number="?")])

            self.assertEqual(bundle["candidate_count"], 1)
            candidate = bundle["candidates"][0]
            self.assertIsNone(candidate["line_number"])
            self.assertTrue(candidate["line_number_unknown"])
            self.assertFalse(candidate["source_context"]["line_number_known"])

    def test_a_missing_line_number_is_unknown_not_dropped(self):
        sentinel_free = self._candidate()
        del sentinel_free["line_number"]
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox, target = self._sandbox(Path(tmpdir))

            bundle = self._run(sandbox, target, [sentinel_free])

            self.assertEqual(bundle["candidate_count"], 1)
            self.assertTrue(bundle["candidates"][0]["line_number_unknown"])

    def test_a_mixed_batch_keeps_every_candidate_and_keeps_the_numbers(self):
        no_line = self._candidate(rule_id="no-line")
        del no_line["line_number"]
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox, target = self._sandbox(Path(tmpdir))

            bundle = self._run(sandbox, target, [
                self._candidate(rule_id="numeric", line_number=2),
                self._candidate(rule_id="sentinel", line_number="?"),
                no_line,
            ])

            self.assertEqual(bundle["candidate_count"], 3, "a candidate was dropped, not marked")
            by_rule = {c["rule_id"]: c for c in bundle["candidates"]}
            self.assertEqual(by_rule["numeric"]["line_number"], 2)
            self.assertNotIn("line_number_unknown", by_rule["numeric"])
            self.assertTrue(by_rule["sentinel"]["line_number_unknown"])
            self.assertTrue(by_rule["no-line"]["line_number_unknown"])
            # The sentinel is not echoed back as a line a consumer might compare again.
            self.assertIsNone(by_rule["sentinel"]["line_number"])

    def test_an_unknown_line_gets_file_level_context_not_a_fabricated_window(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox, target = self._sandbox(Path(tmpdir), app_lines=400)

            bundle = self._run(sandbox, target, [self._candidate(line_number="?")])
            ctx = bundle["candidates"][0]["source_context"]

            self.assertFalse(ctx["line_number_known"])
            self.assertEqual(ctx["window_start"], 1)
            self.assertEqual(ctx["window_end"], 200, "a file-level view, not a window on line 1")
            self.assertTrue(ctx["truncated"])
            self.assertIn("unknown", ctx["location_note"])
            self.assertIn("const line1 = 1;", ctx["context_snippet"])

    def test_a_known_line_still_gets_its_own_window(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox, target = self._sandbox(Path(tmpdir), app_lines=400)

            bundle = self._run(sandbox, target, [self._candidate(line_number=200)])
            ctx = bundle["candidates"][0]["source_context"]

            self.assertTrue(ctx["line_number_known"])
            self.assertEqual((ctx["window_start"], ctx["window_end"]), (171, 230))
            self.assertNotIn("location_note", ctx)

    def test_removing_the_normalisation_reintroduces_the_type_error(self):
        """The mutation check: the unknown-line path is what makes the sentinel safe.

        A guard that cannot fail is not a guard, so this mutates the helper back to handing the
        raw value through and asserts the station crashes on the same input the test above
        passes - if this ever stops crashing, the test above is proving nothing. The rule now
        lives in lib/line_numbers.py (agents-ghtz), so that is the copy to mutate.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox, target = self._sandbox(Path(tmpdir))
            script = sandbox / "agents" / "vuln-verify" / "scripts" / "prepare_verification.py"
            helper = sandbox / "lib" / "line_numbers.py"
            original = helper.read_text(encoding="utf-8")
            anchor = "    if isinstance(value, bool):\n        return None\n"
            self.assertIn(anchor, original, "the mutation anchor moved; fix this probe")
            helper.write_text(original.replace(anchor, "    return value\n"), encoding="utf-8")

            out = sandbox / "mutated.json"
            findings_file = sandbox / "findings.json"
            findings_file.write_text(
                json.dumps({"findings": [self._candidate(line_number="?")]}), encoding="utf-8")
            res = subprocess.run(
                [sys.executable, str(script), "--target", str(target),
                 "--output", str(out), "--findings", str(findings_file)],
                capture_output=True, text=True, timeout=60)

            self.assertNotEqual(res.returncode, 0, "the mutated station survived the sentinel")
            self.assertIn("TypeError", res.stderr)


if __name__ == "__main__":
    unittest.main()
