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

        # Reviewer P1 finding: asset mention in description must NOT suppress execution concurrency guard
        f8 = {
            "rule_id": "custom-rule",
            "title": "Inference Latency",
            "description": "Examine stylesheet preload and asset loading on startup",
            "remediation": "Start all inference passes simultaneously"
        }
        self.assertTrue(is_concurrency_recommendation(f8))

        # Reviewer P1 finding: parallelize with worker pool
        f9 = {
            "rule_id": "custom-rule",
            "remediation": "Parallelize model inferences with a worker pool."
        }
        self.assertTrue(is_concurrency_recommendation(f9))

        # Reviewer P1 finding: concurrent requests on shared session
        f10 = {
            "rule_id": "custom-rule",
            "remediation": "Use concurrent requests on the shared session"
        }
        self.assertTrue(is_concurrency_recommendation(f10))

    def test_detects_reentrancy_precondition_or_evidence(self):
        """Identify whether finding already carries backend evidence or precondition."""
        without_precondition = {"remediation": "Replace loop with Promise.all"}
        self.assertFalse(has_reentrancy_precondition(without_precondition))

        with_precondition = {
            "remediation": "IF this runtime is reentrant and thread-safe, use Promise.all; otherwise keep serial execution."
        }
        self.assertTrue(has_reentrancy_precondition(with_precondition))

        # Reviewer P2 finding: scanner advice with "documented serial execution" must be recognized
        with_documented_fallback = {
            "remediation": "IF the underlying backend is reentrant and thread-safe, use Promise.all; otherwise preserve documented serial execution."
        }
        self.assertTrue(has_reentrancy_precondition(with_documented_fallback))

        with_evidence = {
            "snippet": "for (const f of files) await readFile(f);",
            "remediation": "The Node.js fs backend is proven reentrant and thread-safe; use Promise.all."
        }
        self.assertTrue(has_reentrancy_precondition(with_evidence))

        # Reviewer P1 finding: unrelated backend evidence with non-reentrant session runs must NOT pass
        unrelated_backend_evidence = {
            "snippet": "for (const ex of exercises) await ex.run();",
            "remediation": "Node.js fetch supports concurrent requests; use Promise.all for ONNX Runtime Web session runs"
        }
        self.assertFalse(has_reentrancy_precondition(unrelated_backend_evidence))

        # Reviewer P1 finding: mismatched backend evidence (readFile snippet with fetch evidence) must NOT pass
        mismatched_backend_evidence = {
            "snippet": "for (const f of files) await readFile(f);",
            "remediation": "Node.js fetch supports concurrent requests; use Promise.all"
        }
        self.assertFalse(has_reentrancy_precondition(mismatched_backend_evidence))

        # Reviewer P1 finding: positive fetch clause with incidental readFile mention must NOT pass as readFile evidence
        incidental_readfile_counterexample = {
            "snippet": "for (const f of files) await readFile(f);",
            "remediation": "Node.js fetch supports concurrent requests; use Promise.all to parallelize readFile calls"
        }
        self.assertFalse(has_reentrancy_precondition(incidental_readfile_counterexample))

        # Reviewer P1 finding: same-sentence mixed-backend claim (fetch positive evidence + readFile mention) must NOT pass
        same_sentence_mixed_backend = {
            "snippet": "for (const f of files) await readFile(f);",
            "remediation": "Node.js fetch supports concurrent requests, so use Promise.all to parallelize readFile calls"
        }
        self.assertFalse(has_reentrancy_precondition(same_sentence_mixed_backend))

        # Reviewer P1 finding: mismatched network API (axios.get snippet with fetch evidence) must NOT pass
        mismatched_network_api = {
            "snippet": "for (const url of urls) await axios.get(url);",
            "remediation": "Node.js fetch supports concurrent requests; use Promise.all for axios.get calls"
        }
        self.assertFalse(has_reentrancy_precondition(mismatched_network_api))

        # Reviewer P1 finding: intervening words attaching claim to different API must NOT pass
        intervening_api_counterexample = {
            "snippet": "for (const url of urls) await axios.get(url);",
            "remediation": "For axios calls use fetch which supports concurrent requests; use Promise.all"
        }
        self.assertFalse(has_reentrancy_precondition(intervening_api_counterexample))

        # Reviewer P1 finding: inverted conditional recommendation (concurrency on non-reentrant branch) must NOT pass
        inverted_condition = {
            "remediation": "If backend is reentrant, preserve serial execution; otherwise use Promise.all"
        }
        self.assertFalse(has_reentrancy_precondition(inverted_condition))

        # Reviewer P1 finding: fallback branch advocating concurrency for another operation must NOT pass
        fallback_advocating_concurrency = {
            "remediation": "If backend is reentrant, use Promise.all for fetch; otherwise keep serial setup but run inference concurrently"
        }
        self.assertFalse(has_reentrancy_precondition(fallback_advocating_concurrency))

        # Reviewer P1 finding: unconditioned concurrency advice before conditional block must NOT pass
        unconditioned_prefix = {
            "remediation": "Use Promise.any for ONNX sessions. IF fetch is reentrant, use Promise.all for fetches; otherwise preserve serial execution"
        }
        self.assertFalse(has_reentrancy_precondition(unconditioned_prefix))

        # Reviewer P1 finding: intermediate fallback branch advocating concurrency must NOT pass
        intermediate_fallback_concurrency = {
            "remediation": "IF backend is reentrant, use Promise.all; otherwise use Promise.any; else preserve serial execution"
        }
        self.assertFalse(has_reentrancy_precondition(intermediate_fallback_concurrency))

        # Reviewer P1 finding: empty snippet and plural sessions/models must NOT pass backend evidence
        empty_snippet_plural = {
            "snippet": "",
            "remediation": "Node.js fetch supports concurrent requests; use Promise.all for sessions"
        }
        self.assertFalse(has_reentrancy_precondition(empty_snippet_plural))

        # Plural session references in remediation disqualify even if snippet has fetch
        fetch_with_plural_sessions = {
            "snippet": "await fetch(url);",
            "remediation": "The Node.js fetch backend is proven reentrant and thread-safe; use Promise.all for sessions"
        }
        self.assertFalse(has_reentrancy_precondition(fetch_with_plural_sessions))

        # Reviewer P1 finding: bare assertion without naming a backend must NOT pass as evidence
        bare_assertion = {
            "remediation": "Backend is reentrant; use Promise.all"
        }
        self.assertFalse(has_reentrancy_precondition(bare_assertion))

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

    def test_post_filter_withholds_proposed_fix_diff_when_not_proven(self):
        """Reviewer P1 finding: proposed_fix_diff must be withheld unless reentrancy is proven."""
        # Case A: unpreconditioned finding with diff -> diff withheld, remediation guarded
        report1 = {
            "findings": [
                {
                    "rule_id": "sequential-await-waterfall",
                    "path": "src/session.ts",
                    "line_number": 25,
                    "remediation": "Use Promise.all to run requests concurrently",
                    "proposed_fix_diff": "--- a/session.ts\n+++ b/session.ts\n@@ -1,2 +1,2 @@\n- for (const r of reqs) await r();\n+ await Promise.all(reqs.map(r => r()));",
                }
            ]
        }
        notes1 = normalize_report(report1)
        self.assertTrue(any("enforced reentrancy precondition" in n for n in notes1))
        finding1 = report1["findings"][0]
        self.assertNotIn("proposed_fix_diff", finding1)
        self.assertIn("Code patch withheld", finding1["remediation"])

        # Case B: preconditioned remediation but unproven backend -> diff still withheld
        report2 = {
            "findings": [
                {
                    "rule_id": "sequential-await-waterfall",
                    "path": "src/model.ts",
                    "line_number": 10,
                    "remediation": "IF the model runtime is reentrant, use Promise.all; otherwise preserve serial execution.",
                    "proposed_fix_diff": "--- a/model.ts\n+++ b/model.ts\n@@ -1,2 +1,2 @@\n- for (const e of ex) await e();\n+ await Promise.all(ex.map(e => e()));",
                }
            ]
        }
        notes2 = normalize_report(report2)
        self.assertTrue(any("enforced reentrancy precondition" in n for n in notes2))
        finding2 = report2["findings"][0]
        self.assertNotIn("proposed_fix_diff", finding2)
        self.assertIn("Code patch withheld", finding2["remediation"])

        # Case C: proven backend evidence -> remediation not double-wrapped, diff withheld for manual review
        report3 = {
            "findings": [
                {
                    "rule_id": "sequential-await-waterfall",
                    "path": "src/files.ts",
                    "line_number": 5,
                    "snippet": "for (const f of files) await readFile(f);",
                    "remediation": "The Node.js fs.promises backend is proven reentrant and thread-safe; use Promise.all.",
                    "proposed_fix_diff": "--- a/files.ts\n+++ b/files.ts\n@@ -1,2 +1,2 @@\n- for (const f of files) await readFile(f);\n+ await Promise.all(files.map(readFile));",
                }
            ]
        }
        notes3 = normalize_report(report3)
        self.assertTrue(any("enforced reentrancy precondition" in n for n in notes3))
        self.assertNotIn("proposed_fix_diff", report3["findings"][0])
        self.assertIn("Code patch withheld", report3["findings"][0]["remediation"])
        # Remediation was not double-wrapped with generic precondition because it already had backend evidence
        self.assertNotIn("IF the underlying runtime/backend is reentrant and thread-safe", report3["findings"][0]["remediation"])

        # Case D: Reviewer counterexample - unrelated backend evidence with non-reentrant session runs -> diff withheld
        report4 = {
            "findings": [
                {
                    "rule_id": "sequential-await-waterfall",
                    "path": "src/onnx_session.ts",
                    "line_number": 20,
                    "snippet": "for (const ex of exercises) await ex.run();",
                    "remediation": "Node.js fetch supports concurrent requests; use Promise.all for ONNX Runtime Web session runs",
                    "proposed_fix_diff": "--- a/session.ts\n+++ b/session.ts\n@@ -1,2 +1,2 @@\n- for (const ex of exercises) await ex.run();\n+ await Promise.all(exercises.map(ex => ex.run()));",
                }
            ]
        }
        notes4 = normalize_report(report4)
        self.assertTrue(any("enforced reentrancy precondition" in n for n in notes4))
        finding4 = report4["findings"][0]
        self.assertNotIn("proposed_fix_diff", finding4)
        self.assertIn("Code patch withheld", finding4["remediation"])

        # Case E: Reviewer counterexample - incidental stateless I/O in comment does not qualify non-stateless awaited operation
        report5 = {
            "findings": [
                {
                    "rule_id": "sequential-await-waterfall",
                    "path": "src/jobs.ts",
                    "line_number": 30,
                    "snippet": "// fetch(url) in comment\nfor (const job of jobs) await job.run();",
                    "remediation": "The Node.js fetch backend is proven reentrant and thread-safe; use Promise.all.",
                    "proposed_fix_diff": "--- a/jobs.ts\n+++ b/jobs.ts\n@@ -1,2 +1,2 @@\n- for (const job of jobs) await job.run();\n+ await Promise.all(jobs.map(job => job.run()));",
                }
            ]
        }
        notes5 = normalize_report(report5)
        self.assertTrue(any("enforced reentrancy precondition" in n for n in notes5))
        finding5 = report5["findings"][0]
        self.assertNotIn("proposed_fix_diff", finding5)
        self.assertIn("Code patch withheld", finding5["remediation"])

        # Case F: Reviewer counterexample - mixed awaited calls (fetch and job.run) -> diff withheld
        report6 = {
            "findings": [
                {
                    "rule_id": "sequential-await-waterfall",
                    "path": "src/mixed.ts",
                    "line_number": 10,
                    "snippet": "for (const job of jobs) { await fetch(job.url); await job.run(); }",
                    "remediation": "The Node.js fetch backend is proven reentrant and thread-safe; use Promise.all.",
                    "proposed_fix_diff": "--- a/mixed.ts\n+++ b/mixed.ts\n@@ -1,2 +1,2 @@\n- for (const job of jobs) { await fetch(job.url); await job.run(); }\n+ await Promise.all(jobs.map(async j => { await fetch(j.url); await j.run(); }));",
                }
            ]
        }
        notes6 = normalize_report(report6)
        self.assertTrue(any("enforced reentrancy precondition" in n for n in notes6))
        finding6 = report6["findings"][0]
        self.assertNotIn("proposed_fix_diff", finding6)
        self.assertIn("Code patch withheld", finding6["remediation"])

        # Case G: Reviewer P1 finding - URL string literal with // does not mask subsequent stateful call
        report7 = {
            "findings": [
                {
                    "rule_id": "sequential-await-waterfall",
                    "path": "src/jobs.ts",
                    "line_number": 15,
                    "snippet": "for (const job of jobs) await fetch('https://example.test');",
                    "remediation": "The Node.js fetch backend is proven reentrant and thread-safe; use Promise.all.",
                    "proposed_fix_diff": "--- a/jobs.ts\n+++ b/jobs.ts\n@@ -1,2 +1,2 @@\n- for (const job of jobs) await fetch('https://example.test');\n+ await Promise.all(jobs.map(async job => { await fetch('https://example.test'); await job.run(); }));",
                }
            ]
        }
        notes7 = normalize_report(report7)
        self.assertTrue(any("enforced reentrancy precondition" in n for n in notes7))
        finding7 = report7["findings"][0]
        self.assertNotIn("proposed_fix_diff", finding7)
        self.assertIn("Code patch withheld", finding7["remediation"])

        # Case H: Reviewer finding - optional chaining call job.run?.() is inspected and rejected
        report8 = {
            "findings": [
                {
                    "rule_id": "sequential-await-waterfall",
                    "path": "src/jobs.ts",
                    "line_number": 20,
                    "snippet": "for (const job of jobs) await fetch(url);",
                    "remediation": "The Node.js fetch backend is proven reentrant and thread-safe; use Promise.all.",
                    "proposed_fix_diff": "--- a/jobs.ts\n+++ b/jobs.ts\n@@ -1,2 +1,2 @@\n- for (const job of jobs) await fetch(url);\n+ await Promise.all(jobs.map(async job => { await fetch(url); await job.run?.(); }));",
                }
            ]
        }
        notes8 = normalize_report(report8)
        self.assertTrue(any("enforced reentrancy precondition" in n for n in notes8))
        finding8 = report8["findings"][0]
        self.assertNotIn("proposed_fix_diff", finding8)
        self.assertIn("Code patch withheld", finding8["remediation"])

        # Case I: Reviewer finding - un-inspectable computed call syntax fails closed
        report9 = {
            "findings": [
                {
                    "rule_id": "sequential-await-waterfall",
                    "path": "src/jobs.ts",
                    "line_number": 25,
                    "snippet": "for (const job of jobs) await fetch(url);",
                    "remediation": "The Node.js fetch backend is proven reentrant and thread-safe; use Promise.all.",
                    "proposed_fix_diff": "--- a/jobs.ts\n+++ b/jobs.ts\n@@ -1,2 +1,2 @@\n- for (const job of jobs) await fetch(url);\n+ await Promise.all(jobs.map(async (job, i) => { await fetch(url); await jobs[i]?.(); }));",
                }
            ]
        }
        notes9 = normalize_report(report9)
        self.assertTrue(any("enforced reentrancy precondition" in n for n in notes9))
        finding9 = report9["findings"][0]
        self.assertNotIn("proposed_fix_diff", finding9)
        self.assertIn("Code patch withheld", finding9["remediation"])

        # Case J: Reviewer P1 finding - arbitrary receiver method handle.fetch(url) is not an exact recognized API
        report10 = {
            "findings": [
                {
                    "rule_id": "sequential-await-waterfall",
                    "path": "src/client.ts",
                    "line_number": 35,
                    "snippet": "for (const url of urls) await handle.fetch(url);",
                    "remediation": "The Node.js fetch backend is proven reentrant and thread-safe; use Promise.all.",
                    "proposed_fix_diff": "--- a/client.ts\n+++ b/client.ts\n@@ -1,2 +1,2 @@\n- for (const url of urls) await handle.fetch(url);\n+ await Promise.all(urls.map(url => handle.fetch(url)));",
                }
            ]
        }
        notes10 = normalize_report(report10)
        self.assertTrue(any("enforced reentrancy precondition" in n for n in notes10))
        finding10 = report10["findings"][0]
        self.assertNotIn("proposed_fix_diff", finding10)
        self.assertIn("Code patch withheld", finding10["remediation"])

        # Case K: Reviewer P1 finding - mixed advice ('Keep serial setup; run model inference passes concurrently')
        report11 = {
            "findings": [
                {
                    "rule_id": "sequential-await-waterfall",
                    "path": "src/setup.ts",
                    "line_number": 12,
                    "remediation": "Keep serial setup; run model inference passes concurrently.",
                    "proposed_fix_diff": "--- a/setup.ts\n+++ b/setup.ts\n@@ -1,2 +1,2 @@\n- for (const m of models) await m.run();\n+ await Promise.all(models.map(m => m.run()));",
                }
            ]
        }
        notes11 = normalize_report(report11)
        self.assertTrue(any("enforced reentrancy precondition" in n for n in notes11))
        finding11 = report11["findings"][0]
        self.assertNotIn("proposed_fix_diff", finding11)
        self.assertIn("Code patch withheld", finding11["remediation"])

    def test_render_blocking_head_asset_proposing_concurrency_is_guarded(self):
        """Reviewer P1 finding: render-blocking-head-asset proposing execution concurrency is guarded."""
        report = {
            "findings": [
                {
                    "rule_id": "render-blocking-head-asset",
                    "path": "src/loader.ts",
                    "line_number": 15,
                    "remediation": "Parallelize session loading with Promise.all across models.",
                    "proposed_fix_diff": "--- a/loader.ts\n+++ b/loader.ts\n@@ -1,2 +1,2 @@\n- for (const m of models) await m.load();\n+ await Promise.all(models.map(m => m.load()));",
                }
            ]
        }
        notes = normalize_report(report)
        self.assertTrue(any("enforced reentrancy precondition" in n for n in notes))
        finding = report["findings"][0]
        self.assertNotIn("proposed_fix_diff", finding)
        self.assertIn("Code patch withheld", finding["remediation"])

    def test_serial_execution_restoration_patch_retained(self):
        """Reviewer P1/P2 findings: diffs removing Promise.all to restore serial execution are not guarded."""
        # Case A: "Restore serial execution by replacing Promise.all with sequential for-of loop."
        report1 = {
            "findings": [
                {
                    "rule_id": "race-condition",
                    "path": "src/state.ts",
                    "line_number": 42,
                    "remediation": "Restore serial execution by replacing Promise.all with sequential for-of loop.",
                    "proposed_fix_diff": "--- a/state.ts\n+++ b/state.ts\n@@ -1,2 +1,2 @@\n- await Promise.all(items.map(f));\n+ for (const item of items) await f(item);",
                }
            ]
        }
        notes1 = normalize_report(report1)
        self.assertFalse(any("enforced reentrancy precondition" in n for n in notes1))
        self.assertIn("proposed_fix_diff", report1["findings"][0])

        # Case B: Reviewer P1 finding - "Stop using Promise.all and run tasks sequentially"
        report2 = {
            "findings": [
                {
                    "rule_id": "non-reentrant-concurrency",
                    "path": "src/queue.ts",
                    "line_number": 18,
                    "remediation": "Stop using Promise.all and run tasks sequentially.",
                    "proposed_fix_diff": "--- a/queue.ts\n+++ b/queue.ts\n@@ -1,2 +1,2 @@\n- await Promise.all(tasks.map(t => t()));\n+ for (const t of tasks) await t();",
                }
            ]
        }
        notes2 = normalize_report(report2)
        self.assertFalse(any("enforced reentrancy precondition" in n for n in notes2))
        self.assertIn("proposed_fix_diff", report2["findings"][0])

        # Case C: Reviewer P2 finding - "Do not use Promise.all; run tasks sequentially"
        report3 = {
            "findings": [
                {
                    "rule_id": "non-reentrant-concurrency",
                    "path": "src/tasks.ts",
                    "line_number": 22,
                    "remediation": "Do not use Promise.all; run tasks sequentially.",
                    "proposed_fix_diff": "--- a/tasks.ts\n+++ b/tasks.ts\n@@ -1,2 +1,2 @@\n- await Promise.all(tasks.map(t => t()));\n+ for (const t of tasks) await t();",
                }
            ]
        }
        notes3 = normalize_report(report3)
        self.assertFalse(any("enforced reentrancy precondition" in n for n in notes3))
        self.assertIn("proposed_fix_diff", report3["findings"][0])

        # Case D: Reviewer P2 finding - "Remove worker pool; run model inference serially"
        report4 = {
            "findings": [
                {
                    "rule_id": "concurrency-hazard",
                    "path": "src/infer.ts",
                    "line_number": 50,
                    "remediation": "Remove worker pool; run model inference serially.",
                    "proposed_fix_diff": "--- a/infer.ts\n+++ b/infer.ts\n@@ -1,2 +1,2 @@\n- await pool.map(models, runInference);\n+ for (const m of models) await runInference(m);",
                }
            ]
        }
        notes4 = normalize_report(report4)
        self.assertFalse(any("enforced reentrancy precondition" in n for n in notes4))
        self.assertIn("proposed_fix_diff", report4["findings"][0])

        # Case E: Reviewer P1 finding - "Avoid parallelizing model inference; use serial execution"
        report5 = {
            "findings": [
                {
                    "rule_id": "concurrency-hazard",
                    "path": "src/infer.ts",
                    "line_number": 60,
                    "remediation": "Avoid parallelizing model inference; use serial execution.",
                    "proposed_fix_diff": "--- a/infer.ts\n+++ b/infer.ts\n@@ -1,2 +1,2 @@\n- await Promise.all(models.map(m => m.run()));\n+ for (const m of models) await m.run();",
                }
            ]
        }
        notes5 = normalize_report(report5)
        self.assertFalse(any("enforced reentrancy precondition" in n for n in notes5))
        self.assertIn("proposed_fix_diff", report5["findings"][0])

        # Case F: Reviewer P1 finding - "Do not run model inference in parallel; preserve serial execution"
        report6 = {
            "findings": [
                {
                    "rule_id": "concurrency-hazard",
                    "path": "src/infer.ts",
                    "line_number": 65,
                    "remediation": "Do not run model inference in parallel; preserve serial execution.",
                    "proposed_fix_diff": "--- a/infer.ts\n+++ b/infer.ts\n@@ -1,2 +1,2 @@\n- await Promise.all(models.map(m => m.run()));\n+ for (const m of models) await m.run();",
                }
            ]
        }
        notes6 = normalize_report(report6)
        self.assertFalse(any("enforced reentrancy precondition" in n for n in notes6))
        self.assertIn("proposed_fix_diff", report6["findings"][0])

    def test_negated_serial_with_affirmative_parallel_is_concurrency_recommendation(self):
        """Reviewer P1 finding: 'Do not run model inference serially but run it in parallel' must be guarded."""
        finding = {
            "rule_id": "concurrency-hazard",
            "path": "src/infer.ts",
            "line_number": 70,
            "remediation": "Do not run model inference serially but run it in parallel."
        }
        self.assertTrue(is_concurrency_recommendation(finding))
        self.assertFalse(has_reentrancy_precondition(finding))
        report = {"findings": [finding]}
        notes = normalize_report(report)
        self.assertTrue(any("enforced reentrancy precondition" in n for n in notes))

    def test_concurrent_with_trailing_serial_clause_is_concurrency_recommendation(self):
        """Reviewer P1 finding: 'Run GPU concurrently but setup serially' (no patch) must be guarded."""
        finding = {
            "rule_id": "concurrency-hazard",
            "path": "src/gpu.ts",
            "line_number": 15,
            "remediation": "Run GPU concurrently but setup serially."
        }
        self.assertTrue(is_concurrency_recommendation(finding))
        self.assertFalse(has_reentrancy_precondition(finding))
        report = {"findings": [finding]}
        notes = normalize_report(report)
        self.assertTrue(any("enforced reentrancy precondition" in n for n in notes))

    def test_promise_any_concurrency_patch_is_guarded(self):
        """Reviewer P1 finding: Promise.any patch with custom rule must be guarded and diff withheld."""
        finding = {
            "rule_id": "custom-batch-optimization",
            "path": "src/infer.ts",
            "line_number": 80,
            "remediation": "Return the first successful result from the batch.",
            "proposed_fix_diff": "--- a/infer.ts\n+++ b/infer.ts\n@@ -1,2 +1,2 @@\n- for (const m of models) await m.run();\n+ await Promise.any(models.map(m => m.run()));"
        }
        self.assertTrue(is_concurrency_recommendation(finding))
        self.assertFalse(has_reentrancy_precondition(finding))
        report = {"findings": [finding]}
        notes = normalize_report(report)
        self.assertTrue(any("enforced reentrancy precondition" in n for n in notes))
        self.assertNotIn("proposed_fix_diff", report["findings"][0])

    def test_concurrency_hazard_warning_title_is_not_concurrency_recommendation(self):
        """Reviewer P2 finding: 'Concurrent execution of inference sessions is unsafe' is a hazard warning, not recommendation."""
        finding = {
            "rule_id": "thread-safety-hazard",
            "path": "src/onnx.ts",
            "line_number": 30,
            "title": "Concurrent execution of inference sessions is unsafe",
            "description": "Multiple threads running inference can corrupt internal engine state.",
            "remediation": "Add a mutex around the run call.",
            "proposed_fix_diff": "--- a/run.ts\n+++ b/run.ts\n@@ -1,2 +1,3 @@\n+ await mutex.acquire();\n  await session.run();\n+ mutex.release();"
        }
        self.assertFalse(is_concurrency_recommendation(finding))
        report = {"findings": [finding]}
        notes = normalize_report(report)
        self.assertFalse(any("enforced reentrancy precondition" in n for n in notes))
        self.assertIn("proposed_fix_diff", report["findings"][0])

    def test_overlap_model_inference_through_pool_of_workers_is_guarded(self):
        """Reviewer P1 finding: overlap advice through worker pool phrasing is guarded."""
        report = {
            "findings": [
                {
                    "rule_id": "bottleneck",
                    "path": "src/models.ts",
                    "line_number": 45,
                    "remediation": "Overlap model inference calls through a pool of workers.",
                    "proposed_fix_diff": "--- a/models.ts\n+++ b/models.ts\n@@ -1,2 +1,2 @@\n- for (const m of models) await run(m);\n+ await pool.map(models, runInference);",
                }
            ]
        }
        notes = normalize_report(report)
        self.assertTrue(any("enforced reentrancy precondition" in n for n in notes))
        finding = report["findings"][0]
        self.assertNotIn("proposed_fix_diff", finding)
        self.assertIn("Code patch withheld", finding["remediation"])

    def test_plural_worker_pools_in_custom_rule_is_guarded(self):
        """Reviewer P1 finding: plural worker pools in custom rule is guarded."""
        report = {
            "findings": [
                {
                    "rule_id": "custom-rule",
                    "path": "src/service.ts",
                    "line_number": 10,
                    "remediation": "Use worker pools for ONNX sessions.",
                }
            ]
        }
        notes = normalize_report(report)
        self.assertTrue(any("enforced reentrancy precondition" in n for n in notes))
        finding = report["findings"][0]
        self.assertTrue(finding["remediation"].startswith("Precondition: Verify backend reentrancy before applying."))

    def test_mixed_direction_removes_promise_all_but_recommends_concurrency(self):
        """Reviewer P1 finding: diff removing Promise.all while remediation recommends worker pool concurrency is guarded."""
        report = {
            "findings": [
                {
                    "rule_id": "bottleneck",
                    "path": "src/infer.ts",
                    "line_number": 30,
                    "remediation": "Use a worker pool to parallelize model inference across available cores.",
                    "proposed_fix_diff": "--- a/infer.ts\n+++ b/infer.ts\n@@ -1,2 +1,2 @@\n- await Promise.all(models.map(m => m.run()));\n+ pool.dispatch(models);",
                }
            ]
        }
        notes = normalize_report(report)
        self.assertTrue(any("enforced reentrancy precondition" in n for n in notes))
        finding = report["findings"][0]
        self.assertNotIn("proposed_fix_diff", finding)
        self.assertIn("Code patch withheld", finding["remediation"])

    def test_post_filter_leaves_preconditioned_finding_intact(self):
        """Post-filter must not double-wrap an already preconditioned finding."""
        original_remediation = (
            "IF the WebGPU runtime backend is reentrant and supports concurrent queue submission, "
            "use Promise.all; otherwise preserve serial execution."
        )
        scanner_suggestion = (
            "IF the underlying runtime/backend is reentrant and thread-safe, consider concurrent "
            "execution via await Promise.all(items.map(...)); otherwise preserve documented serial execution."
        )
        report = {
            "findings": [
                {
                    "rule_id": "sequential-await-waterfall",
                    "path": "src/compute.ts",
                    "line_number": 12,
                    "remediation": original_remediation,
                    "description": "Model check",
                },
                {
                    "rule_id": "sequential-await-waterfall",
                    "path": "src/batch.ts",
                    "line_number": 50,
                    "remediation": scanner_suggestion,
                    "description": "Scanner rule",
                }
            ]
        }
        notes = normalize_report(report)
        self.assertFalse(any("enforced reentrancy precondition" in n for n in notes))
        self.assertEqual(report["findings"][0]["remediation"], original_remediation)
        self.assertEqual(report["findings"][1]["remediation"], scanner_suggestion)

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
