#!/usr/bin/env python3
"""Tests for perf-review deterministic scanning and reproducible severity verdicts (agents-neb).

Verifies that:
1. The deterministic pre-pass (scan_perf_changes.py) produces stable, reproducible
   candidate lists and candidate ordering across runs and filesystem directory orders.
2. Candidates touched in recent commits have appropriate severity escalation, and ties
   are deterministically broken by (path, line_number, rule_id).
3. Fixed candidate inputs yield a fixed, deterministic severity verdict.
4. The factory's pi models.json generation includes samplingParams temperature pinning.
"""

import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.findings import FindingsStore  # noqa: E402

SCANNER_SCRIPT = ROOT / "agents" / "perf-review" / "scripts" / "scan_perf_changes.py"


def load_scanner_module():
    loader = importlib.machinery.SourceFileLoader("scan_perf_changes", str(SCANNER_SCRIPT))
    spec = importlib.util.spec_from_loader("scan_perf_changes", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class TestPerfReviewScannerDeterminism(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        subprocess.run(["git", "init"], cwd=self.repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=self.repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=self.repo, check=True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_scanner_directory_traversal_and_tie_breaking_are_deterministic(self):
        """Candidate ordering must be fully deterministic across runs and tie-broken by
        (not in_recent_diff, severity != high, path, line_number, rule_id)."""
        mod = load_scanner_module()

        # Create nested directories in non-alphabetical creation order
        (self.repo / "sub_z").mkdir()
        (self.repo / "sub_a").mkdir()
        (self.repo / "sub_m").mkdir()

        (self.repo / "sub_z" / "file_2.js").write_text(
            "function z2() {\n  const w = box.offsetWidth;\n  box.style.width = w + 'px';\n}\n",
            encoding="utf-8"
        )
        (self.repo / "sub_a" / "file_1.js").write_text(
            "function a1() {\n  const h = box.offsetHeight;\n  box.style.height = h + 'px';\n}\n",
            encoding="utf-8"
        )
        (self.repo / "sub_m" / "file_3.html").write_text(
            "<!DOCTYPE html><html><head><script src='app.js'></script></head><body><img src='x.png'></body></html>\n",
            encoding="utf-8"
        )

        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=self.repo, check=True)

        # Make another commit touching sub_z/file_2.js so it is in recent diff
        (self.repo / "sub_z" / "file_2.js").write_text(
            "function z2() {\n  const w = box.offsetWidth;\n  box.style.width = (w + 1) + 'px';\n}\n",
            encoding="utf-8"
        )
        subprocess.run(["git", "commit", "-am", "Touch file_2"], cwd=self.repo, check=True)

        git_ctx = mod.get_recent_git_context(self.repo)
        self.assertIn("sub_z/file_2.js", git_ctx["changed_files"])

        # Run scan multiple times; candidate list and ordering must be 100% identical
        first_run = mod.scan_files(self.repo, git_ctx["changed_files"])
        for _ in range(5):
            next_run = mod.scan_files(self.repo, git_ctx["changed_files"])
            self.assertEqual(
                [(c["rule_id"], c["path"], c["line_number"], c["severity"]) for c in first_run],
                [(c["rule_id"], c["path"], c["line_number"], c["severity"]) for c in next_run],
                "Candidate scan output must be strictly deterministic across repeated invocations"
            )

        # Touched file must appear first
        self.assertTrue(first_run[0]["touched_in_recent_commits"])
        self.assertEqual(first_run[0]["path"], "sub_z/file_2.js")
        self.assertEqual(first_run[0]["severity"], "high")

    def test_severity_escalation_for_recent_diff(self):
        """A medium-severity baseline rule (e.g. unoptimized media or unthrottled listener)
        must escalate to high severity when touched in recent commits."""
        mod = load_scanner_module()

        (self.repo / "page.html").write_text(
            "<html><body><img src='unoptimized.png'></body></html>", encoding="utf-8"
        )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "Add page"], cwd=self.repo, check=True)

        # Baseline: untouched -> medium
        untouched = mod.scan_files(self.repo, [])
        media_cand = [c for c in untouched if c["rule_id"] == "lcp-cls-unoptimized-media"][0]
        self.assertEqual(media_cand["severity"], "medium")
        self.assertFalse(media_cand["touched_in_recent_commits"])

        # When touched in recent diff -> escalated to high
        touched = mod.scan_files(self.repo, ["page.html"])
        media_cand_touched = [c for c in touched if c["rule_id"] == "lcp-cls-unoptimized-media"][0]
        self.assertEqual(media_cand_touched["severity"], "high")
        self.assertTrue(media_cand_touched["touched_in_recent_commits"])


class TestPerfReviewVerdictReproducibility(unittest.TestCase):
    def test_fixed_input_yields_fixed_verdict(self):
        """Fixed findings input must yield an identical severity verdict across runs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store_dir = Path(tmpdir)
            findings_data = [
                {
                    "rule_id": "layout-thrashing-forced-reflow",
                    "path": "src/anim.js",
                    "line_number": 10,
                    "snippet": "const height = box.clientHeight;",
                    "severity": "high",
                    "title": "Forced Synchronous Layout Hazard",
                    "description": "clientHeight read immediately before style mutation",
                    "remediation": "Batch geometry reads before DOM mutations",
                },
                {
                    "rule_id": "lcp-cls-unoptimized-media",
                    "path": "index.html",
                    "line_number": 5,
                    "snippet": "<img src=\"icon.png\">",
                    "severity": "medium",
                    "title": "Undimensioned Image Hazard",
                    "description": "Image without width/height attributes triggers CLS",
                    "remediation": "Add explicit width and height attributes",
                }
            ]

            candidate_index = {
                "rule_ids": {"layout-thrashing-forced-reflow", "lcp-cls-unoptimized-media"},
                "paths": {"src/anim.js", "index.html"},
                "snippets_at": {
                    ("layout-thrashing-forced-reflow", "src/anim.js", 10): "const height = box.clientHeight;",
                    ("lcp-cls-unoptimized-media", "index.html", 5): '<img src="icon.png">',
                },
                "snippets_in": {}
            }

            store1 = FindingsStore("test-target", findings_dir=store_dir / "run1")
            processed1, stats1, _ = store1.process_run("perf-review", findings_data, candidate_index=candidate_index)

            store2 = FindingsStore("test-target", findings_dir=store_dir / "run2")
            processed2, stats2, _ = store2.process_run("perf-review", findings_data, candidate_index=candidate_index)

            self.assertEqual(stats1, stats2)
            self.assertEqual(
                [(f["rule_id"], f["path"], f["severity"], f["routing_severity"]) for f in processed1],
                [(f["rule_id"], f["path"], f["severity"], f["routing_severity"]) for f in processed2],
            )
            self.assertEqual(processed1[0]["severity"], "high")
            self.assertEqual(processed1[1]["severity"], "medium")


class TestFactorySamplingParams(unittest.TestCase):
    def test_pi_models_json_includes_sampling_params(self):
        """_write_pi_models_json must write samplingParams with temperature 0.1 for determinism."""
        loader = importlib.machinery.SourceFileLoader("factory_cli_test", str(ROOT / "factory"))
        spec = importlib.util.spec_from_loader("factory_cli_test", loader)
        factory_mod = importlib.util.module_from_spec(spec)
        loader.exec_module(factory_mod)

        class DummyBroker:
            providers = ["deepseek"]
            def base_url(self, provider):
                return "http://127.0.0.1:8384/proxy/deepseek"

        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_dir = Path(tmpdir)
            factory_mod._write_pi_models_json(cfg_dir, DummyBroker(), "deepseek")
            models_file = cfg_dir / "models.json"
            self.assertTrue(models_file.exists())
            data = json.loads(models_file.read_text(encoding="utf-8"))
            models = data["providers"]["deepseek"]["models"]
            self.assertTrue(len(models) > 0)
            for m in models:
                self.assertIn("samplingParams", m)
                self.assertEqual(m["samplingParams"].get("temperature"), 0.1)


if __name__ == "__main__":
    unittest.main()
