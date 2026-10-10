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
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.findings import FindingsStore  # noqa: E402
from lib.report_schema import (  # noqa: E402
    guard_concurrency_finding,
    has_reentrancy_precondition,
    is_concurrency_recommendation,
    normalize_report,
    unpreconditioned_concurrency_findings,
    validate_agent_report,
)

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
        """Candidate ordering must be fully deterministic and independent of os.walk order.

        The scanner caps inspection at 80 files, so which files it sees depends on directory
        traversal order. It sorts dirs itself; this test reverses the walk to prove the sort —
        not the filesystem — decides the set/order (pre-fix, the reversed walk changed the 80)."""
        mod = load_scanner_module()

        # Enough files (3 x 30) to exceed the 80-file cap, across non-alphabetical dirs.
        for d in ("sub_z", "sub_a", "sub_m"):
            (self.repo / d).mkdir()
            for i in range(30):
                (self.repo / d / f"file_{i}.js").write_text(
                    "function f() {\n  const w = box.offsetWidth;\n  box.style.width = w + 'px';\n}\n",
                    encoding="utf-8",
                )
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "Initial commit"], cwd=self.repo, check=True)

        # Touch one sub_z file so it is priority (recent diff) and must lead the output.
        (self.repo / "sub_z" / "file_0.js").write_text(
            "function f() {\n  const w = box.offsetWidth;\n  box.style.width = (w + 1) + 'px';\n}\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "commit", "-am", "Touch file_0"], cwd=self.repo, check=True)

        git_ctx = mod.get_recent_git_context(self.repo)
        self.assertIn("sub_z/file_0.js", git_ctx["changed_files"])

        normal = mod.scan_files(self.repo, git_ctx["changed_files"])

        def key(run):
            return [(c["rule_id"], c["path"], c["line_number"], c["severity"]) for c in run]

        # Reversed filesystem order must not change which files are scanned or their order.
        real_walk = mod.os.walk

        def reversed_walk(top, *args, **kwargs):
            for root, dirs, files in real_walk(top, *args, **kwargs):
                dirs.reverse()  # in place, so the scanner's IGNORE_DIRS pruning still applies
                yield root, dirs, files

        with mock.patch.object(mod.os, "walk", reversed_walk):
            reversed_run = mod.scan_files(self.repo, git_ctx["changed_files"])
        self.assertEqual(key(normal), key(reversed_run),
                         "Candidate set/order must not depend on os.walk directory order")

        # Touched file must appear first
        self.assertTrue(normal[0]["touched_in_recent_commits"])
        self.assertEqual(normal[0]["path"], "sub_z/file_0.js")
        self.assertEqual(normal[0]["severity"], "high")

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


class TestConcurrencyRecommendationGuard(unittest.TestCase):
    """agents-vorw / hub fleet-4inv: Concurrency recommendation reentrancy guard."""

    def test_scanner_rule_suggestion_carries_reentrancy_precondition(self):
        """scan_perf_changes.py rule suggestion must state reentrancy precondition."""
        mod = load_scanner_module()
        rule = next(r for r in mod.PERF_RULES if r["rule_id"] == "sequential-await-waterfall")
        self.assertIn("reentrant", rule["suggestion"])
        self.assertIn("thread-safe", rule["suggestion"])
        self.assertIn("serial execution", rule["suggestion"])

    def test_detects_concurrency_recommendation(self):
        """Identify findings that recommend concurrency or parallelization."""
        f1 = {"rule_id": "sequential-await-waterfall", "remediation": "Batch items"}
        self.assertTrue(is_concurrency_recommendation(f1))

        f2 = {"rule_id": "custom-rule", "remediation": "Use Promise.all to fetch in parallel"}
        self.assertTrue(is_concurrency_recommendation(f2))

        f3 = {"rule_id": "custom-rule", "description": "Run asyncio.gather on background tasks"}
        self.assertTrue(is_concurrency_recommendation(f3))

        f4 = {"rule_id": "layout-thrashing-forced-reflow", "remediation": "Batch geometry reads"}
        self.assertFalse(is_concurrency_recommendation(f4))

        # Reviewer counterexample P2: "simultaneously"
        f5 = {"rule_id": "custom-rule", "remediation": "Start all forward passes simultaneously"}
        self.assertTrue(is_concurrency_recommendation(f5))

        f6 = {"rule_id": "custom-rule", "remediation": "Run checks at the same time"}
        self.assertTrue(is_concurrency_recommendation(f6))

        # Reviewer P2 finding: CSS @import and stylesheet preloading must NOT be flagged as execution concurrency
        f7 = {
            "rule_id": "render-blocking-head-asset",
            "category": "LCP / FCP",
            "remediation": "Replace CSS @import chains with parallel <link rel=\"stylesheet\"> tags"
        }
        self.assertFalse(is_concurrency_recommendation(f7))

    def test_detects_reentrancy_precondition_or_evidence(self):
        """Identify whether finding already carries backend evidence or precondition."""
        without_precondition = {"remediation": "Replace loop with Promise.all"}
        self.assertFalse(has_reentrancy_precondition(without_precondition))

        with_precondition = {
            "remediation": "IF this runtime is reentrant and thread-safe, use Promise.all; otherwise keep serial execution."
        }
        self.assertTrue(has_reentrancy_precondition(with_precondition))

        with_evidence = {
            "remediation": "The Node.js fs backend is proven reentrant and thread-safe; use Promise.all."
        }
        self.assertTrue(has_reentrancy_precondition(with_evidence))

        with_conditional_mutex = {
            "remediation": "IF the runtime is reentrant, use Promise.all; otherwise preserve serial execution."
        }
        self.assertTrue(has_reentrancy_precondition(with_conditional_mutex))

        # Reviewer P1 finding: negative remediation mentioning "not support" must NOT pass as positive evidence
        negative_remediation = {
            "remediation": "ONNX backend does not support concurrent calls; use Promise.all."
        }
        self.assertFalse(has_reentrancy_precondition(negative_remediation))

        # Reviewer P1 finding: conditional advice WITHOUT serial fallback must NOT pass
        conditional_without_fallback = {
            "remediation": "IF backend is reentrant, use Promise.all"
        }
        self.assertFalse(has_reentrancy_precondition(conditional_without_fallback))

        # Reviewer counterexample P1: description mentions mutex / non-reentrant, but remediation still suggests concurrency
        unsafe_description_bypass = {
            "title": "Inference loop",
            "description": "ONNX Runtime Web uses a non-reentrant mutex around _OrtRun",
            "remediation": "Use Promise.all to run all forward passes simultaneously"
        }
        self.assertFalse(has_reentrancy_precondition(unsafe_description_bypass))

    def test_post_filter_enforces_reentrancy_precondition_on_unpreconditioned_finding(self):
        """Post-filter must prepend reentrancy precondition to unchecked concurrency recommendation."""
        report = {
            "findings": [
                {
                    "rule_id": "sequential-await-waterfall",
                    "path": "src/onnx_runner.ts",
                    "line_number": 42,
                    "title": "Sequential Model Inference Waterfall",
                    "description": "Sequential await in loop slows down execution",
                    "remediation": "Replace loop with await Promise.all(items.map(runInference))",
                },
                {
                    "rule_id": "custom-rule",
                    "path": "src/forward_pass.ts",
                    "line_number": 100,
                    "title": "Forward Pass Optimization",
                    "description": "ONNX Runtime uses a non-reentrant mutex around _OrtRun",
                    "remediation": "Start all forward passes simultaneously",
                }
            ]
        }
        notes = normalize_report(report)
        self.assertEqual(len([n for n in notes if "enforced reentrancy precondition" in n]), 2)

        finding = report["findings"][0]
        self.assertTrue(finding["remediation"].startswith("Precondition: Verify backend reentrancy before applying."))
        self.assertIn("IF the underlying runtime/backend is reentrant and thread-safe", finding["remediation"])
        self.assertIn("ONNX Runtime _OrtRun", finding["remediation"])
        self.assertIn("otherwise preserve serial execution", finding["remediation"])
        self.assertIn("[Precondition Note:", finding["description"])

        finding2 = report["findings"][1]
        self.assertTrue(finding2["remediation"].startswith("Precondition: Verify backend reentrancy before applying."))
        self.assertIn("Start all forward passes simultaneously", finding2["remediation"])
        self.assertIn("otherwise preserve serial execution", finding2["remediation"])

    def test_post_filter_leaves_preconditioned_finding_intact(self):
        """Post-filter must not double-wrap an already preconditioned finding."""
        original_remediation = (
            "IF the WebGPU runtime backend is reentrant and supports concurrent queue submission, "
            "use Promise.all; otherwise preserve serial execution."
        )
        report = {
            "findings": [
                {
                    "rule_id": "sequential-await-waterfall",
                    "path": "src/compute.ts",
                    "line_number": 12,
                    "remediation": original_remediation,
                    "description": "Model check",
                }
            ]
        }
        notes = normalize_report(report)
        self.assertFalse(any("enforced reentrancy precondition" in n for n in notes))
        self.assertEqual(report["findings"][0]["remediation"], original_remediation)

    def test_validator_rejects_unpreconditioned_concurrency_if_normalization_bypassed(self):
        """validate_agent_report must reject an un-preconditioned concurrency finding if un-normalized."""
        raw_report = {
            "summary": "Perf review report",
            "target": "sample-target",
            "findings": [
                {
                    "rule_id": "sequential-await-waterfall",
                    "path": "src/model.ts",
                    "line_number": 20,
                    "snippet": "for (const e of exercises) await e.run();",
                    "severity": "high",
                    "title": "Waterfall",
                    "description": "Slow loop",
                    "remediation": "Use Promise.all to run all exercises concurrently",
                }
            ]
        }
        perf_dir = ROOT / "agents" / "perf-review"
        perf_cfg = {"output": {"schema": "report.schema.json"}}
        violations = validate_agent_report(perf_dir, perf_cfg, raw_report)
        self.assertTrue(any("concurrency recommendation" in v and "reentrancy precondition" in v for v in violations))

        # Once normalized through normalize_report, violations must be cleared
        normalize_report(raw_report)
        violations_after = validate_agent_report(perf_dir, perf_cfg, raw_report)
        self.assertEqual(violations_after, [])


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
