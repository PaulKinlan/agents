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
import importlib.util
import json
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


if __name__ == "__main__":
    unittest.main()
