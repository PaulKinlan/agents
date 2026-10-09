#!/usr/bin/env python3
"""Pre-pass defects that made stations report unearned results.

- secret-scan's openai-key rule matched `sk-` mid-word (journal-aaj, fleet-ctu), and the
  scanner ran every rule over every line, overrunning its budget on large repos (fleet-wa8);
- qa-station read a store filename that never existed, so it always audited nothing, and it
  accepted a missing target (journal-wog);
- docs-drift spawned a full git history walk per missing path and rglob'd the tree per bare
  filename, overrunning its 5-minute budget (journal-idy).
"""

import importlib.machinery
import os
os.environ.setdefault("FACTORY_ALLOW_UNPINNED_TOOLS", "1")  # agents-7bj: tests use unpinned stub tools
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent


class TestPrepassFixes(unittest.TestCase):
    def test_openai_rule_does_not_match_mid_word(self):
        sys.path.insert(0, str(ROOT / "agents" / "secret-scan" / "scripts"))
        import scan  # noqa: E402
        rule = dict(scan.PATTERNS)["openai-key"]
        self.assertIsNone(rule.search("#disk-quota-for-buffered-reports-storage-dos"))
        self.assertIsNone(rule.search("fillmask-release-lifecycle.test"))
        self.assertIsNone(rule.search("/ask-the-model-for-everything-now"))
        self.assertIsNotNone(rule.search('key = "sk-proj-abcdefghijklmnop1234"'))
        self.assertTrue(scan.ANY_PATTERN.search('token = "AbCdEfGhIjKlMnOpQrStUvWxYz"'))

    def test_qa_station_reads_the_real_store_and_refuses_a_missing_target(self):
        script = ROOT / "agents" / "qa-station" / "scripts" / "audit_factory_quality.py"
        res = subprocess.run([sys.executable, str(script), "--target", "/nonexistent/agents"],
                             capture_output=True, text=True, timeout=60)
        self.assertNotEqual(res.returncode, 0)
        with tempfile.TemporaryDirectory() as tmp:
            findings_dir = Path(tmp)
            (findings_dir / "proj.json").write_text(json.dumps({"target": "proj", "findings": {
                "f1": {"agent": "lint", "state": "wontfix", "remediation": "x"},
                "f2": {"agent": "lint", "state": "new"}}}), encoding="utf-8")
            loader = importlib.machinery.SourceFileLoader("qa_audit", str(script))
            spec = importlib.util.spec_from_loader("qa_audit", loader)
            qa = importlib.util.module_from_spec(spec)
            loader.exec_module(qa)
            with mock.patch.object(qa, "FINDINGS_DIR", findings_dir):
                data = qa.audit_findings_precision()
            self.assertEqual(data["stores_read"], ["proj.json"])
            card = data["agent_scorecards"][0]
            self.assertEqual((card["total_findings"], card["wontfix"]), (2, 1))
            with mock.patch.object(qa, "FINDINGS_DIR", findings_dir / "empty"):
                data = qa.audit_findings_precision()
            self.assertEqual([c["rule_id"] for c in data["noisy_candidates"]], ["qa-no-findings-store"])

    def test_qa_station_does_not_treat_an_empty_lifecycle_file_as_measured_precision(self):
        """agents-2e8: a real station can create a valid but empty target.json; the QA
        pre-pass must still surface a measurement gap rather than report clean."""
        script = ROOT / "agents" / "qa-station" / "scripts" / "audit_factory_quality.py"
        loader = importlib.machinery.SourceFileLoader("qa_audit_empty_2e8", str(script))
        spec = importlib.util.spec_from_loader("qa_audit_empty_2e8", loader)
        qa = importlib.util.module_from_spec(spec)
        loader.exec_module(qa)
        with tempfile.TemporaryDirectory() as tmp:
            findings_dir = Path(tmp) / "findings"
            findings_dir.mkdir()
            (findings_dir / "target.json").write_text(
                json.dumps({"target": "target", "findings": {}}), encoding="utf-8")
            out = Path(tmp) / "qa-output.json"
            with mock.patch.object(qa, "FINDINGS_DIR", findings_dir), \
                 mock.patch.object(sys, "argv", ["qa", "--target", tmp, "--output", str(out)]):
                qa.main()
            result = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(result["stores_read"], ["target.json"])
            self.assertEqual(result["agent_scorecards"], [])
            gaps = [c for c in result["candidates"] if c["rule_id"] == "qa-no-findings-store"]
            self.assertEqual(len(gaps), 1)
            self.assertIn("No findings lifecycle records", gaps[0]["title"])

    def test_docs_drift_git_index_sees_deleted_files(self):
        sys.path.insert(0, str(ROOT / "agents" / "docs-drift" / "scripts"))
        import check_docs  # noqa: E402
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            git = ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t"]
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            (repo / "src").mkdir()
            (repo / "src" / "keep.py").write_text("x")
            (repo / "src" / "gone.py").write_text("x")
            subprocess.run(git + ["add", "."], check=True)
            subprocess.run(git + ["commit", "-qm", "a"], check=True)
            subprocess.run(git + ["rm", "-q", "src/gone.py"], check=True)
            subprocess.run(git + ["commit", "-qm", "b"], check=True)
            self.assertEqual(check_docs.git_tracked_or_deleted(repo, "src/keep.py"), (True, True))
            self.assertEqual(check_docs.git_tracked_or_deleted(repo, "./src/gone.py"), (False, True))
            self.assertEqual(check_docs.git_tracked_or_deleted(repo, "src"), (True, True))
            self.assertEqual(check_docs.git_tracked_or_deleted(repo, "nope.py"), (False, False))
            self.assertEqual(check_docs.path_exists_or_matches(repo, repo, "keep.py"), (True, False))

    def test_product_css_has_focus_visible_states(self):
        """[agents-1oc] docs/css/product.css defines :focus-visible states for key interactive controls."""
        product_css = ROOT / "docs" / "css" / "product.css"
        self.assertTrue(product_css.exists())
        content = product_css.read_text(encoding="utf-8")
        self.assertIn(".breadcrumb a:focus-visible", content)
        self.assertIn(".btn:focus-visible", content)
        self.assertIn(".btn-primary:focus-visible", content)
        self.assertIn(".btn-secondary:focus-visible", content)

        # ui-ux scanner pre-pass produces 0 candidates
        script = ROOT / "agents" / "ui-ux-audit" / "scripts" / "scan_ui_ux.py"
        res = subprocess.run([sys.executable, str(script), "--target", str(product_css.parent)],
                             capture_output=True, text=True, check=True)
        data = json.loads(res.stdout)
        focus_candidates = [c for c in data["candidates"] if c["rule_id"] == "missing-focus-visible-state"]
        self.assertEqual(len(focus_candidates), 0, f"Expected 0 missing-focus-visible-state candidates, got: {focus_candidates}")

    def test_product_css_has_prefers_reduced_motion_override(self):
        """[agents-cvm] docs/css/product.css overrides hover transforms/transitions under prefers-reduced-motion."""
        product_css = ROOT / "docs" / "css" / "product.css"
        self.assertTrue(product_css.exists())
        content = product_css.read_text(encoding="utf-8")
        self.assertIn("@media (prefers-reduced-motion: reduce)", content)
        start = content.find("@media (prefers-reduced-motion: reduce)")
        open_brace = content.find("{", start)
        depth = 1
        pos = open_brace + 1
        while pos < len(content) and depth > 0:
            if content[pos] == "{":
                depth += 1
            elif content[pos] == "}":
                depth -= 1
            pos += 1
        block = content[open_brace + 1:pos - 1]
        self.assertIn(".btn", block)
        self.assertIn(".doc-card", block)
        self.assertIn("transition: none", block)
        self.assertIn("transform: none", block)


if __name__ == "__main__":
    unittest.main()
