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

import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tests.test_factory_truth import Sandbox, factory_cli, report  # noqa: E402

from lib.findings import FindingsStore  # noqa: E402
from lib.report_schema import (  # noqa: E402
    _paraphrase_clause_start_connectors,
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

    def test_dismissed_waterfall_does_not_require_concurrency_precondition(self):
        """Dismissals and explicit serial advice are not concurrency recommendations."""
        for dismissal in (
            {
                "rule_id": "sequential-await-waterfall",
                "path": "src/runner.ts",
                "line_number": 12,
                "severity": "info",
                "false_positive": True,
                "description": "Serial execution is required by the backend contract.",
                "remediation": "Keep serial execution; the order is intentional.",
            },
            {
                "rule_id": "sequential-await-waterfall",
                "path": "src/runner.ts",
                "line_number": 12,
                "remediation": "Keep serial execution; the order is intentional.",
            },
            {
                "rule_id": "sequential-await-waterfall",
                "path": "src/runner.ts",
                "line_number": 12,
                "remediation": "No change needed: serial execution is intentional here for ordering.",
            },
            {
                "rule_id": "sequential-await-waterfall",
                "path": "src/runner.ts",
                "line_number": 12,
                "remediation": "Serial execution is intentional.",
            },
            {
                "rule_id": "sequential-await-waterfall",
                "path": "src/runner.ts",
                "line_number": 12,
                "remediation": "Serial execution is required for correctness.",
            },
            {
                "rule_id": "sequential-await-waterfall",
                "path": "src/runner.ts",
                "line_number": 12,
                "remediation": "Sequential execution is required by design.",
            },
            {
                "rule_id": "sequential-await-waterfall",
                "path": "src/runner.ts",
                "line_number": 12,
                "remediation": "Serial execution is intentional here to preserve ordering.",
            },
            {
                "rule_id": "sequential-await-waterfall",
                "path": "src/runner.ts",
                "line_number": 12,
                "remediation": "Serial execution is intentional.\nVerified against the backend contract.",
            },
            {
                "rule_id": "sequential-await-waterfall",
                "path": "src/runner.ts",
                "line_number": 12,
                "remediation": "Serial execution is intentional; do not batch the fetches.",
            },
            {
                "rule_id": "sequential-await-waterfall",
                "path": "src/runner.ts",
                "line_number": 12,
                "remediation": "Out of scope: this candidate is in dev tooling, not shipped production code.",
            },
        ):
            with self.subTest(false_positive=dismissal.get("false_positive")):
                finding = {
                    "snippet": "for (const item of items) await run(item);",
                    "severity": "info",
                    "title": "Intentional serial execution",
                    "description": "Order is required by the backend contract.",
                    **dismissal,
                }
                report = {"summary": "Dismissed waterfall", "target": "sample-target", "findings": [finding]}
                original_remediation = finding["remediation"]
                self.assertFalse(is_concurrency_recommendation(finding))
                self.assertEqual(normalize_report(report), [])
                self.assertEqual(report["findings"][0]["remediation"], original_remediation)
                self.assertEqual(unpreconditioned_concurrency_findings(report), [])
                self.assertEqual(validate_agent_report(
                    ROOT / "agents" / "perf-review",
                    {"output": {"schema": "report.schema.json"}},
                    report,
                ), [])

    def test_scope_words_do_not_hide_terse_waterfall_recommendations(self):
        for remediation in (
            "This is not out of scope: batch the independent fetches here.",
            "Out of scope for the guard: batch the independent fetches in this loop.",
        ):
            with self.subTest(remediation=remediation):
                finding = {"rule_id": "sequential-await-waterfall", "remediation": remediation}
                self.assertTrue(is_concurrency_recommendation(finding))
                self.assertTrue(unpreconditioned_concurrency_findings({"findings": [finding]}))
                self.assertIsNotNone(guard_concurrency_finding(finding, 0))
                self.assertIn("Precondition: Verify backend reentrancy", finding["remediation"])

    def test_serial_rationale_does_not_hide_terse_batching_advice(self):
        for remediation in (
            "Serial execution is required for determinism in one path, but batch the independent fetches in this loop.",
            "The loop's serial execution is intentional by design, yet batch the independent fetches.",
            "Serial execution is intentional only because of a stale comment; batch the independent fetches.",
            "The stale comment claiming serial execution is intentional should be ignored; batch the independent fetches.",
            "Serial execution is intentional.\nBatch the independent fetches.",
            "No change needed: serial execution is intentional for ordering; batch the fetches.",
        ):
            with self.subTest(remediation=remediation):
                finding = {"rule_id": "sequential-await-waterfall", "remediation": remediation}
                self.assertTrue(is_concurrency_recommendation(finding))
                self.assertTrue(unpreconditioned_concurrency_findings({"findings": [finding]}))
                self.assertIsNotNone(guard_concurrency_finding(finding, 0))
                self.assertIn("Precondition: Verify backend reentrancy", finding["remediation"])

    def test_dismissal_language_does_not_hide_a_concurrency_patch(self):
        finding = {
            "rule_id": "sequential-await-waterfall",
            "remediation": "Out of scope: this candidate is in dev tooling.",
            "proposed_fix_diff": "--- a/src/runner.ts\n+++ b/src/runner.ts\n@@ -1 +1 @@\n- await run(item);\n+ await Promise.all(items.map(run));",
        }
        self.assertTrue(is_concurrency_recommendation(finding))
        self.assertEqual(len(unpreconditioned_concurrency_findings({"findings": [finding]})), 2)
        self.assertIsNotNone(guard_concurrency_finding(finding, 0))
        self.assertNotIn("proposed_fix_diff", finding)

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

        # Reviewer P1 finding: first fallback branch not directing serial execution must NOT pass
        deferred_serial_fallback = {
            "remediation": "IF backend is reentrant, use Promise.all; otherwise launch model runs on separate workers; else preserve serial execution"
        }
        self.assertFalse(has_reentrancy_precondition(deferred_serial_fallback))

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

    def test_normalization_replaces_unsafe_intermediate_fallback_and_validates(self):
        """Reviewer P1 finding: guard replaces unsafe fallback rather than wrapping it, passing validation."""
        report = {
            "findings": [
                {
                    "rule_id": "sequential-await-waterfall",
                    "path": "src/tasks.ts",
                    "line_number": 12,
                    "remediation": "IF backend is reentrant, use Promise.all; otherwise use Promise.any; else preserve serial execution",
                }
            ]
        }
        # Before normalization: rejected as having concurrency in fallback
        self.assertFalse(has_reentrancy_precondition(report["findings"][0]))
        # After normalization: repaired cleanly
        notes = normalize_report(report)
        self.assertTrue(any("enforced reentrancy precondition" in n for n in notes))
        finding = report["findings"][0]
        self.assertTrue(has_reentrancy_precondition(finding))
        self.assertNotIn("Promise.any", finding["remediation"])
        # Validation must accept the repaired report without violations
        violations = unpreconditioned_concurrency_findings(report)
        self.assertEqual(violations, [])

    def test_unsafe_fallback_across_sentences_is_rejected_and_repaired(self):
        """agents-b99s8: unsafe intermediate fallback across sentence boundaries is rejected and repaired."""
        remediation = (
            "IF backend is reentrant, use a worker pool; otherwise parallelize operations. "
            "On failure, preserve serial execution; else preserve serial execution."
        )
        finding = {
            "rule_id": "tm-pdf-parse-uncancellable",
            "path": "src/parse.ts",
            "line_number": 42,
            "remediation": remediation,
        }
        # Before normalization: rejected because intermediate fallback advocates concurrency
        self.assertFalse(has_reentrancy_precondition(finding))
        report = {"findings": [finding]}
        notes = normalize_report(report)
        self.assertTrue(any("enforced reentrancy precondition" in n for n in notes))
        guarded = report["findings"][0]["remediation"]
        self.assertNotIn("parallelize operations", guarded)
        self.assertIn("use a worker pool", guarded)
        self.assertIn("otherwise preserve serial execution", guarded)
        self.assertTrue(has_reentrancy_precondition(report["findings"][0]))
        self.assertEqual(unpreconditioned_concurrency_findings(report), [])

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


class TestADescriptiveMentionIsNotAdvice(unittest.TestCase):
    """agents-ekrw4: a concurrency primitive MENTIONED in findings prose is not advice.

    The guard read a bare `Promise.all` / `asyncio.gather` in title+description as a recommendation.
    That is right for a remediation or an added diff line - there the fix itself proposes concurrency -
    but wrong for prose that reports what the code does. Measured on origin/main a468a9ae before the
    fix: every descriptive sentence below classified True and produced one `unpreconditioned
    concurrency` violation, so validate_agent_report rejected a report that had only DESCRIBED the
    code.

    THE CORPUS IS BORROWED, NOT INVENTED. Rows 1-2 are agents-43cso's cases, rows 3-8 are agents-wjqez's
    nominal and first-person cases, and rows 9-10 are the precision half of agents-ttcyx. Those three
    beads were closed as SUPERSEDED by agents-ekrw4 rather than as "invalid against main", because
    each of these reproduces on main; only their regression framing was dead.

    BOTH DIRECTIONS ARE PINNED, for the reason three earlier rounds of this guard produced a recall
    regression each: a precision fix that stops seeing real advice is not a fix. The difference the
    classifier has to see is grammatical - who governs the mention - not a longer word list.
    """

    DESCRIPTIVE = (
        # agents-43cso case 1: attacker-impact sentence; the harm verbs were missing from the hazard list
        ("perf-review",
         "An attacker can use Promise.all to amplify requests and exhaust the connection pool.",
         "Reorganize the request logic."),
        # agents-43cso case 2: leading adverbial phrase + subject + present tense
        ("perf-review",
         "In the login endpoint, the handler uses Promise.all without a cap.",
         "Add a concurrency limit."),
        # agents-wjqez: nominal cues - "the use of X", "a call to X", "the dispatch of X"
        ("unsafe-concurrency",
         "Use of Promise.all on unbounded input exhausts the socket pool.",
         "Bound the concurrency with a semaphore."),
        ("unsafe-concurrency",
         "The use of asyncio.gather here creates an unbounded task set from untrusted input.",
         "Bound the concurrency with a semaphore."),
        ("unsafe-concurrency",
         "A call to Promise.all with attacker-controlled length causes memory exhaustion.",
         "Bound the concurrency with a semaphore."),
        ("unsafe-concurrency",
         "The use of Promise.allSettled without inspecting results silently drops rejections.",
         "Bound the concurrency with a semaphore."),
        ("unsafe-concurrency",
         "The dispatch of requests via Promise.all has no concurrency cap.",
         "Bound the concurrency with a semaphore."),
        # agents-wjqez: first-person PRESENT. "We use X" describes; only "we should use X" advises.
        ("unsafe-concurrency",
         "We use Promise.all to fetch user-supplied URLs, allowing SSRF fan-out.",
         "Bound the concurrency with a semaphore."),
        # agents-ttcyx precision half: subject + FACTUAL modal. will/can describe; should/must advise.
        ("perf-review",
         "The SDK will use Promise.all to fetch configs.",
         "Consider the fan-out."),
        ("perf-review",
         "The handler can call Promise.all on the batch.",
         "Consider the fan-out."),
        # agents-9fcl5 / agents-5rnta: shapes that must stay DESCRIPTIVE while the advice roles grow.
        # A gerund SUBJECT is a description ("Using X exhausts the pool"), so "using" is not accepted as
        # a cue on its own; an avoidance cue is not clause-initial, and no advisory modal governs it.
        ("perf-review",
         "Using Promise.all on unbounded input exhausts the pool.",
         "Bound the concurrency."),
        ("perf-review",
         "Never use Promise.all; it exhausts the connection pool.",
         "Bound the concurrency."),
        ("perf-review",
         "Do not use Promise.all here, the fan-out saturates the socket pool.",
         "Bound the concurrency."),
        # agents-mjhp6 (round-2 reviewer): an OUTCOME report about a landed change, and epistemic or
        # speculative prose. All four were True on origin/main too - residuals, not regressions - and
        # all four are now False: `will` is out of a3's modal set (an outcome, not advice), the
        # first-person opener no longer takes may/might (possibility, not advice), and the a0 openers
        # no longer include maybe/perhaps (speculation).
        ("perf-review",
         "The change to Promise.all will reduce memory usage in the batch stage.",
         "Consider the fan-out."),
        ("perf-review",
         "Switching the loader to asyncio.gather should cut p99 latency, as measured in the benchmark.",
         "Consider the fan-out."),
        ("perf-review",
         "We may use Promise.all in some code paths depending on the runtime.",
         "Consider the fan-out."),
        ("perf-review",
         "Perhaps asyncio.gather is faster for this workload.",
         "Consider the fan-out."),
        # agents-3lr9o (round-1 reviewer): a cue after a comma opening a NOUN-PHRASE SUBJECT rather than
        # an imperative. The finite predicate in the same clause is what tells them apart, and the
        # check is confined to comma/colon anchors so the infinitival advice shape keeps working.
        ("perf-review",
         "In the batch stage, dispatch requests via Promise.all are logged and capped.",
         "Consider the fan-out."),
        ("perf-review",
         "At startup, run worker pools are created eagerly.",
         "Consider the fan-out."),
        # agents-c9w4t: an a3 match whose shape is the OBJECT of a change noun reports an outcome, not
        # advice. The discriminator is the change noun and NOT the modal - "Promise.all would help" and
        # "Switching to Promise.all would reduce latency" are advice and must stay True (pinned above).
        ("perf-review",
         "The change to Promise.all would reduce memory usage in the batch stage.",
         "Consider the fan-out."),
        ("perf-review",
         "The migration to asyncio.gather would cut the p99 latency of the loader.",
         "Consider the fan-out."),
        # agents-4rk3x (round-3 reviewer, P3): the benchmark marker can PRECEDE the match in the same
        # clause, so the evidence check has to look back to the clause start, not only forward.
        ("perf-review",
         "As measured in the benchmark, switching the loader to asyncio.gather should cut p99 latency.",
         "Consider the fan-out."),
    )

    # agents-3lr9o's third row is DELIBERATELY still classified as advice, and pinned that way so a
    # later round has to argue with a test rather than quietly flip it. "On the ingest path, add items
    # to the thread pool from a single producer." has no finite predicate after the shape, so the
    # subject test cannot see it - and read on its own it is an imperative about a concurrency
    # primitive. For a guard whose job is not letting an unguarded recommendation through, withholding
    # an ambiguous sentence is the direction that fails safe; the cost is one withheld clean report.
    AMBIGUOUS_BUT_GUARDED = (
        "On the ingest path, add items to the thread pool from a single producer.",
    )

    # The recall side. None of these may be lost to the precision fix above.
    ADVICE = (
        # clause-initial imperative (the shape agents-vorw / hub fleet-4inv pinned as f3)
        "Run asyncio.gather on background tasks.",
        # infinitival clause opener: the advice is after the comma
        "To reduce latency, use Promise.all for these fetches.",
        # polite second person
        "You may want to use Promise.all here.",
        "You can use Promise.all for these fetches.",
        # first person with an advisory verb - the contrast row for "We use ..." above
        "We should use Promise.all for the fan-out.",
        # advisory modal governing the shape mid-clause
        "These calls should run in parallel.",
        "We recommend Promise.all here.",
        # agents-9fcl5: measured True at merge-base 9655e59d, flipped False by the first cut of this
        # fix, and the reason the LAND-SUMMARY's "every phrasing that worked before" had to be
        # withdrawn rather than argued with. They stay here so the next widening cannot lose them.
        "Try using Promise.all for these fetches.",
        "We could use Promise.all to fetch the user URLs.",
        "Let's parallelize these calls with asyncio.gather.",
        "How about using asyncio.gather for the fan-out?",
        "Switching to Promise.all would reduce latency.",
        "Promise.all would help.",
        # agents-5rnta: imperative advice that names its HAZARD as the reason. True at merge-base,
        # False when the hazard veto was evaluated first - the ordering the reviewer caught.
        "Use Promise.all so background jobs don't starve the worker pool.",
        "Run asyncio.gather to flood the cache warmer up front.",
        "Use Promise.all here; otherwise requests exhaust the timeout budget.",
        # The comma anchor and the infinitive must survive the agents-3lr9o subject test: neither has a
        # finite predicate after the shape, so neither may be reclassified as a description.
        "To reduce latency, use Promise.all; the calls are independent.",
        "We could run these in parallel; the calls are independent.",
        # agents-rk2y7 (round-3 reviewer, P2): a SUBORDINATE clause carries its own subject and verb, so
        # a finite predicate after "when/where/if" is not evidence against the imperative. These were
        # flipped True->False by the agents-3lr9o subject test - the direction where an unguarded
        # recommendation ships - and must stay True.
        "To reduce latency, use Promise.all when tasks are independent.",
        "For the loader, use Promise.all where items are processed independently.",
        "To reduce latency, use Promise.all if the calls are independent.",
        # impl-cygm4 measured 'would' swallowing soft advice on main 23b64372: 'would' was in no opener,
        # so the cue was never clause-initial under any shape, and all six cases below were False in the
        # description field while "We could use ..." was True in the identical frame. Missing advice ships
        # an unguarded recommendation, so this is the dangerous direction and it is pinned here.
        "We would use Promise.all for these fetches.",
        "We would use asyncio.gather here.",
        "You would use Promise.all for these fetches.",
        "I would use Promise.all here.",
        "We would switch to Promise.all for the fan-out.",
        # And the two rows impl-cygm4 pinned from their side, so a narrower a3 cannot lose them:
        "Promise.all would help.",
        "Switching to Promise.all would reduce latency.",
    )

    def test_a_descriptive_mention_is_not_a_recommendation(self):
        for rule_id, description, remediation in self.DESCRIPTIVE:
            finding = {"rule_id": rule_id, "description": description, "remediation": remediation}
            with self.subTest(description=description):
                self.assertFalse(
                    is_concurrency_recommendation(dict(finding)),
                    "prose that describes the code was classified as a concurrency recommendation"
                )

    def test_a_descriptive_mention_produces_no_unpreconditioned_violation(self):
        """The user-visible effect: a report that only described the code is not withheld."""
        for rule_id, description, remediation in self.DESCRIPTIVE:
            finding = {"rule_id": rule_id, "description": description, "remediation": remediation}
            with self.subTest(description=description):
                self.assertEqual(
                    unpreconditioned_concurrency_findings({"findings": [dict(finding)]}), [],
                    "a finding that merely described the code was withheld as unpreconditioned"
                )
                notes = normalize_report({"findings": [dict(finding)]})
                self.assertFalse(
                    any("enforced reentrancy precondition" in n for n in notes),
                    "a descriptive finding must not be annotated with a reentrancy precondition"
                )

    def test_genuine_advice_survives_the_precision_fix(self):
        for description in self.ADVICE:
            finding = {"rule_id": "perf-review", "description": description,
                       "remediation": "Consider the fan-out."}
            with self.subTest(description=description):
                self.assertTrue(
                    is_concurrency_recommendation(dict(finding)),
                    "genuine advice in prose stopped being recognised as a recommendation"
                )
                self.assertEqual(
                    len(unpreconditioned_concurrency_findings({"findings": [dict(finding)]})), 1,
                    "genuine advice in prose must still carry its reentrancy precondition"
                )

    def test_an_ambiguous_imperative_shape_stays_guarded(self):
        """agents-3lr9o row 3: no finite predicate after the shape, so the subject test cannot see it.

        Read on its own the sentence is an imperative about a concurrency primitive, and for this guard
        the safe direction is to withhold it. Pinned True so that changing it requires a decision here
        instead of a silent edit to a role list.
        """
        for description in self.AMBIGUOUS_BUT_GUARDED:
            with self.subTest(description=description):
                self.assertTrue(is_concurrency_recommendation(
                    {"rule_id": "perf-review", "description": description}
                ))

    def test_a_harm_verb_sentence_is_not_read_as_advice(self):
        """agents-ekrw4 root cause 2: the hazard exemption lacked the verbs these sentences use."""
        for description in (
            "An attacker can use Promise.all to amplify requests and exhaust the connection pool.",
            "Unbounded fan-out saturates the socket pool.",
            "Concurrent inference starves the event loop.",
            "The retry storm overwhelms the worker pool.",
        ):
            with self.subTest(description=description):
                self.assertFalse(is_concurrency_recommendation(
                    {"rule_id": "perf-review", "description": description}
                ))


    def test_advice_outranks_a_hazard_reason_in_the_same_sentence(self):
        """agents-ekrw4 ordering (reported by impl-cygm4): the hazard list must not veto real advice.

        A recommendation usually gives the hazard as its REASON. If the hazard test ran first, the
        harm verbs added for precision would create a recall hole in exactly the findings that must
        stay guarded - the fix would be its own counterexample. Advice is therefore tested first, and
        hazard suppression only answers when nothing in the sentence advises.
        """
        for description in (
            "Use a worker pool so requests don't exhaust the socket pool.",
            "Run these in parallel so the batch does not starve the queue.",
            "Use Promise.all here; unbounded fan-out saturates the socket pool.",
            "We should fan these out with a worker pool before the retry storm overwhelms it.",
        ):
            with self.subTest(description=description):
                finding = {"rule_id": "perf-review", "description": description}
                self.assertTrue(
                    is_concurrency_recommendation(dict(finding)),
                    "advice that names its hazard as the reason was suppressed by the hazard test"
                )
                self.assertEqual(
                    len(unpreconditioned_concurrency_findings({"findings": [dict(finding)]})), 1,
                    "advice with a hazard reason must still carry the reentrancy precondition"
                )
        # The other side of the order: an AVOIDANCE framed with a hazard stays descriptive, because
        # the cue is not clause-initial and no advisory modal governs the shape.
        for description in (
            "Never use Promise.all; it exhausts the connection pool.",
            "Do not use Promise.all here, the fan-out saturates the socket pool.",
        ):
            with self.subTest(description=description):
                self.assertFalse(is_concurrency_recommendation(
                    {"rule_id": "perf-review", "description": description}
                ))


class TestDescriptiveProseKeepsItsGuard(unittest.TestCase):
    """agents-wjqez: reporting what the code does is not advice, and must not invalidate the report.

    The guard used to fire on any mention of a primitive, so a hazard finding whose remediation READ
    "The use of Promise.all on unbounded input exhausts the socket pool" was classified as a
    recommendation - guarded, then rejected by validate_agent_report, so the whole report failed and
    the station read INCOMPLETE. The cue is grammatical position before the primitive in its own
    clause: a nominaliser or a subject that performs the verb describes; an imperative, a modal or a
    recommendation verb advises. The advice forms that agents-shwzh measured are pinned here too, so
    narrowing one side cannot silently cost the other.
    """

    DESCRIPTIVE = (
        "Use of Promise.all on unbounded input exhausts the socket pool.",
        "The use of asyncio.gather here creates an unbounded task set from untrusted input.",
        "A call to Promise.all with attacker-controlled length causes memory exhaustion.",
        "We use Promise.all to fetch user-supplied URLs, allowing SSRF fan-out.",
        "The use of Promise.allSettled without inspecting results silently drops rejections.",
        "The dispatch of requests via Promise.all has no concurrency cap.",
    )

    # agents-ttcyx: the same defect reached through the title/description fallback, where the subject
    # and its verb are separated by a modal ("the SDK will use", "the code can call") or the subject
    # is a third party describing the attack ("an attacker can use Promise.all to amplify requests").
    DESCRIPTIVE_IN_PROSE = (
        "An attacker can use Promise.all to amplify requests and exhaust the connection pool.",
        "The SDK will use Promise.all internally for every request.",
        "The code can call Promise.all with an unbounded array.",
        "The handler uses Promise.all without a cap.",
        "A client can call Promise.all with an unbounded array.",
    )

    STILL_ADVICE = (
        "Use Promise.all for these fetches.",
        "Switch this loop to asyncio.gather.",
        "We recommend using Promise.all for the fan-out.",
        "You can use Promise.all for these fetches.",
        "These inference calls should be awaited with Promise.all.",
        "It is better to use Promise.all for the independent fetches.",
        "Please use Promise.all for these calls.",
    )

    def finding(self, remediation, **extra):
        found = {"rule_id": "unsafe-concurrency", "path": "src/model.ts", "line_number": 20,
                 "description": "Multiple inference calls are issued from one handler.",
                 "remediation": remediation}
        found.update(extra)
        return found

    def test_a_descriptive_remediation_is_guarded_rather_than_dropped(self):
        """The remediation field is the advice field, so the role design guards it either way.

        The earlier pin here asserted that a descriptive sentence in `remediation` was not a
        recommendation at all - that was agents-wjqez's mention-based rule. The advice-role design
        that landed as agents-ekrw4 treats the field as an offer of a fix and guards it, which adds
        a precondition to a sentence that does not advise concurrency: noise, not a hole. What must
        never happen is the reverse - concurrency text left unguarded - and that is what this pins.
        """
        for remediation in self.DESCRIPTIVE:
            with self.subTest(remediation=remediation):
                report = {"findings": [self.finding(remediation)]}
                normalize_report(report)
                self.assertEqual(
                    unpreconditioned_concurrency_findings(report), [],
                    "concurrency text in the remediation must never be left unguarded")
        # A fresh, un-normalized report is of course still flagged for guarding - that is the
        # role design saying "this text names concurrency". The pin is that normalizing it leaves
        # nothing unguarded, which is what the loop above asserts.

    def test_genuine_advice_keeps_its_precondition(self):
        for remediation in self.STILL_ADVICE:
            with self.subTest(remediation=remediation):
                self.assertTrue(is_concurrency_recommendation(self.finding(remediation)),
                                "narrowing the description side must not cost the advice side")

    def test_a_would_modal_still_carries_advice_in_the_description(self):
        """agents-s2ywu: the shape that will fix agents-mjhp6 must not take these with it.

        agents-mjhp6 removes the outcome-report false positive ("The change to Promise.all would
        reduce memory usage in the batch stage.") by keying on the change-noun subject. The same
        modal carries genuine advice in the description field, and those rows are TRUE on main
        today - so they are pinned here as the guard on that fix. Deliberately NOT pinned: the six
        soft-advice "would" rows that are currently FALSE ("We would use Promise.all for these
        fetches." and friends) - they are the recall gap reported on agents-mjhp6 and belong to
        whoever narrows the rule, because a red pin is not landable.
        """
        for description in ("Promise.all would help.",
                            "Switching to Promise.all would reduce latency."):
            with self.subTest(description=description):
                self.assertTrue(
                    is_concurrency_recommendation(
                        {"rule_id": "perf-review", "description": description, "remediation": ""}),
                    "advice phrased with 'would' must stay a recommendation: a change-noun-subject "
                    "discriminator is the fix for the outcome-report row, not the modal itself",
                )

    def test_a_description_in_the_title_or_description_is_not_a_recommendation(self):
        """agents-ttcyx: the fallback re-read the sentence, so a description-only finding was advice.

        Here the remedy is empty and the concurrency sentence IS the title/description, which is the
        shape a hazard station actually emits - "The SDK will use Promise.all internally for every
        request" was classified as a recommendation and rejected the whole report.
        """
        for prose in self.DESCRIPTIVE_IN_PROSE:
            with self.subTest(prose=prose):
                self.assertFalse(is_concurrency_recommendation(
                    {"rule_id": "custom-rule", "description": prose, "remediation": ""}))

    def test_a_description_with_no_remedy_still_counts_when_it_advises(self):
        for prose in ("Use Promise.all for every request in this handler.",
                      "You should switch this loop to asyncio.gather."):
            with self.subTest(prose=prose):
                self.assertTrue(is_concurrency_recommendation(
                    {"rule_id": "custom-rule", "description": prose, "remediation": ""}))

    def test_a_description_with_an_unrelated_remediation_is_still_a_description(self):
        """agents-1f71g: the description carried the primitive, the remedy did not.

        The first cut checked only the REMEDIATION for descriptive phrasing, so a hazard finding
        whose remedy is unrelated advice - "Bound the concurrency with a semaphore." - fell through
        to the title/description fallback and was rejected again. The fallback text is classified by
        the same clause-position test now, so this shape is a description whatever the remedy says.
        """
        for prose in self.DESCRIPTIVE:
            with self.subTest(prose=prose):
                found = {"rule_id": "unsafe-concurrency", "path": "src/a.ts", "line_number": 3,
                         "description": prose,
                         "remediation": "Bound the concurrency with a semaphore."}
                self.assertFalse(is_concurrency_recommendation(found))
                self.assertEqual(unpreconditioned_concurrency_findings({"findings": [dict(found)]}), [],
                                 "a description must not be reported as an unguarded recommendation")

    def test_a_remediation_that_offers_or_prescribes_is_advice_not_a_description(self):
        """agents-1ne8e, the DANGEROUS direction: a modal in a REMEDIATION is an offer of a fix.

        Reading "The handler can use Promise.all to fetch independent resources" as a description
        shipped the advice with no reentrancy precondition at all. Ability/prediction modals are
        therefore allowed only in a description; in a remediation any modal means advice, and the
        normative ones are excluded from the filler between subject and verb so they cannot be
        swallowed and read back as description.
        """
        for remediation in (
            "The handler should use Promise.all to fetch independent resources.",
            "We should use Promise.all for this fan-out.",
            "The code must use asyncio.gather here.",
            "This service ought to use Promise.all.",
            "The worker needs to call asyncio.gather.",
            "The handler can use Promise.all to fetch independent resources.",
            "We can use Promise.all to fetch these.",
            "The SDK will use Promise.all to speed this up.",
        ):
            with self.subTest(remediation=remediation):
                self.assertTrue(is_concurrency_recommendation(
                    {"rule_id": "perf-review", "description": "Waterfall.",
                     "remediation": remediation}))

    def test_descriptive_subjects_cover_the_software_inventory(self):
        """agents-1ne8e, the precision direction: five nouns was a list, not an inventory.

        "The function uses Promise.all" fell outside it and rejected the report.
        """
        for noun in ("function", "method", "worker", "pipeline", "loop", "script",
                     "middleware", "route", "endpoint", "module", "adapter", "scheduler"):
            with self.subTest(noun=noun):
                prose = f"The {noun} uses Promise.all without bounded concurrency."
                found = {"rule_id": "unsafe-concurrency", "path": "src/a.ts", "line_number": 3,
                         "description": prose,
                         "remediation": "Bound the concurrency with a semaphore."}
                self.assertFalse(is_concurrency_recommendation(found))
                self.assertEqual(unpreconditioned_concurrency_findings({"findings": [dict(found)]}), [])

    def test_a_title_without_punctuation_does_not_run_into_the_description(self):
        """agents-43cso: title and description are joined at a SENTENCE BOUNDARY, not by a space.

        Joined with a space, "Unbounded inference fan-in" ran straight into the description, so the
        clause the pattern reads was "... fan-in An attacker can use " and the descriptive subject
        was never at a clause start.
        """
        found = {"rule_id": "unsafe-concurrency", "title": "Unbounded inference fan-in",
                 "description": "An attacker can use Promise.all to amplify requests and exhaust the "
                                "connection pool.",
                 "remediation": "Bound the concurrency with a semaphore."}
        self.assertFalse(is_concurrency_recommendation(found))
        self.assertEqual(unpreconditioned_concurrency_findings({"findings": [dict(found)]}), [])

    def test_a_leading_prepositional_phrase_does_not_hide_the_subject(self):
        """agents-43cso: "In the login endpoint, the handler uses ..." is the same description."""
        found = {"rule_id": "unsafe-concurrency",
                 "description": "In the login endpoint, the handler uses Promise.all without a cap.",
                 "remediation": "Bound the concurrency with a semaphore."}
        self.assertFalse(is_concurrency_recommendation(found))
        self.assertEqual(unpreconditioned_concurrency_findings({"findings": [dict(found)]}), [])
        # ... and the same shape with a normative modal is still advice.
        self.assertTrue(is_concurrency_recommendation(
            {"rule_id": "perf-review", "description": "Waterfall.",
             "remediation": "In the login endpoint, the handler should use Promise.all for the fan-out."}))

    def test_one_advice_clause_in_the_same_remediation_still_counts(self):
        # Only the ALL-descriptive case is a description: a remediation that describes today and
        # then recommends is advice, and the guard must still act on it.
        mixed = "We use Promise.all today; switch the loop to asyncio.gather instead."
        self.assertTrue(is_concurrency_recommendation(self.finding(mixed)))

    def test_a_descriptive_remediation_shipping_a_concurrency_patch_is_still_guarded(self):
        # Step 1 (an added diff line that introduces concurrency) is advice whatever the prose says,
        # and the patch is still withheld.
        found = self.finding(
            "The use of Promise.all here exhausts the socket pool.",
            proposed_fix_diff=("--- a/x.ts\n+++ b/x.ts\n@@\n-for (const u of urls) await get(u)\n"
                               "+await Promise.all(urls.map(get))\n"))
        self.assertTrue(is_concurrency_recommendation(found))
        self.assertIsNotNone(guard_concurrency_finding(found, 0))
        self.assertNotIn("proposed_fix_diff", found, "an automated patch must never survive the guard")



class TestACausalOtherwiseIsNotAFallbackBoundary(unittest.TestCase):
    """agents-gjm4n / agents-3t9oz: "otherwise" states a CONSEQUENCE at least as often as a fallback.

    Three reviewed patches tried to tell the two apart by what follows the connector (an imperative
    lexicon, then a concurrency direction, then work dispatched onto a workforce) and each was beaten
    by a consequence whose subject is a noun that is also a verb ("queue", "pool") next to a
    concurrency noun ("workers", "worker pool"). The reading that cannot be beaten that way is
    structural: a connector is a reentrancy fallback only when an IF-reentrant clause precedes it for
    it to fall back FROM. Where no such clause exists there is nothing to withhold, so the guard
    keeps every clause inside the precondition it adds (paraphrasing the clause-start connector so
    the added IF cannot be misread as its antecedent) - no word list decides anything.
    """

    def finding(self, remediation):
        return {"rule_id": "tm-pdf-parse-uncancellable", "path": "src/parse.ts",
                "line_number": 42, "remediation": remediation}

    def test_every_reviewed_consequence_and_the_proposal_after_it_survive(self):
        # The original bead shape plus each review round's counterexample (agents-3t9oz rounds 1-3).
        for consequence in (
            "a slow PDF blocks the queue",
            "queue starvation blocks the pipeline",
            "pool workers block the queue",
            "queue contention on the worker pool blocks throughput",
        ):
            with self.subTest(consequence=consequence):
                report = {"findings": [self.finding(
                    f"Make the parse cancellable; otherwise {consequence}; "
                    "prefer a worker pool with per-parse abort.")]}
                notes = normalize_report(report)
                remediation = report["findings"][0]["remediation"]
                self.assertIn(consequence, remediation,
                              "the causal clause is the reason for the advice, not a fallback")
                self.assertIn("prefer a worker pool with per-parse abort", remediation,
                              "the actionable proposal after it is preserved, not silently dropped")
                self.assertIn("otherwise preserve serial execution", remediation)
                self.assertFalse(any("withheld" in note for note in notes),
                                 f"nothing was withheld, so nothing may claim to be: {notes}")
                self.assertTrue(has_reentrancy_precondition(report["findings"][0]))
                self.assertEqual(unpreconditioned_concurrency_findings(report), [],
                                 "the rewrite must be a report its own validator accepts")
                self.assertEqual(normalize_report(report), [],
                                 "a second pass must find nothing to do: the guard writes "
                                 "what its validator reads")
                self.assertEqual(report["findings"][0]["remediation"], remediation)

    def test_a_fallback_after_an_if_reentrant_clause_is_still_withheld_and_named(self):
        # The cut the guard is entitled to make: here an IF-reentrant clause DOES precede the
        # connector, so what follows it is fallback-branch advice. It is removed, and the note
        # says how much was removed so a deletion is never silent.
        report = {"findings": [self.finding(
            "IF backend is reentrant, use a worker pool; otherwise parallelize operations. "
            "On failure, preserve serial execution; else preserve serial execution.")]}
        notes = normalize_report(report)
        remediation = report["findings"][0]["remediation"]
        self.assertNotIn("parallelize operations", remediation)
        self.assertIn("use a worker pool", remediation)
        self.assertIn("otherwise preserve serial execution", remediation)
        self.assertTrue(any("withheld" in note and "fallback-only advice" in note for note in notes), notes)
        self.assertEqual(unpreconditioned_concurrency_findings(report), [])


class TestCodeIsNeverParaphrased(unittest.TestCase):
    """agents-obqph / agents-hgiui: the guard may restate PROSE connectors, never code.

    The paraphrase exists so a local "otherwise" cannot be misread as the fallback of the IF the guard
    adds. A snippet's own `else` is not that word at all - rewriting it publishes a remediation a
    human is meant to paste as invalid code, which is what both findings measured ("if (a) run(); if
    not, await run();"). The reader that decides is shared with the validator, so the guard cannot
    paraphrase one form while treating the other as prose: fenced blocks, inline spans, a connector
    that opens a call-shaped clause, and a text-final connector all pass through untouched.
    """

    def finding(self, remediation):
        return {"rule_id": "tm-pdf-parse-uncancellable", "path": "src/parse.ts",
                "line_number": 42, "remediation": remediation}

    def test_a_fenced_snippet_that_ends_in_else_keeps_the_keyword(self):
        # hgiui's exact input: the fence's last line ends with the language's own else.
        snippet = "Make the parse cancellable.\n```js\nif (a) run(); else\n```"
        self.assertEqual(_paraphrase_clause_start_connectors(snippet), snippet,
                         "a fenced snippet must pass through byte for byte")

    def test_an_inline_code_span_is_copied_through(self):
        text = "Loop the calls; `if (a) run(); else await run();` then bound them"
        self.assertEqual(_paraphrase_clause_start_connectors(text), text)

    def test_an_unmarked_code_clause_keeps_the_language_keyword(self):
        # obqph's input: no backticks, so the call-shaped clause is the only signal there is.
        text = ("Make the parse cancellable. In the async loop if (a) run(); else await run(); "
                "prefer a worker pool with per-parse abort.")
        out = _paraphrase_clause_start_connectors(text)
        self.assertIn("else await run();", out, "the JS keyword is not an English connector")
        self.assertNotIn("if not, await run();", out)

    def test_a_text_final_connector_is_dropped_instead_of_paraphrased(self):
        # obqph symptom 2: a connector with no clause became "if not," and the wrapper's own
        # "; otherwise ..." then doubled it into "if not; otherwise".
        report = {"findings": [self.finding("Use Promise.all; else")]}
        normalize_report(report)
        remediation = report["findings"][0]["remediation"]
        self.assertNotIn("if not", remediation)
        self.assertEqual(remediation.count("otherwise"), 1, remediation)
        self.assertTrue(remediation.endswith("otherwise preserve serial execution."), remediation)

    def test_prose_connectors_are_still_paraphrased(self):
        text = "Make the parse cancellable; otherwise queue starvation blocks the pipeline"
        self.assertEqual(_paraphrase_clause_start_connectors(text),
                         "Make the parse cancellable; if not, queue starvation blocks the pipeline")
        # A connector that carries its own comma is not paraphrased into a doubled separator.
        self.assertEqual(_paraphrase_clause_start_connectors("Otherwise, run them serially."),
                         "If not, run them serially.")

    def test_a_fenced_else_is_not_read_as_the_guards_fallback_boundary(self):
        """The validator must see the same prose the rewrite does, or the guard loses its own text."""
        report = {"findings": [self.finding(
            "IF backend is reentrant, use a worker pool.\n```js\nif (a) run(); else\n```")]}
        notes = normalize_report(report)
        remediation = report["findings"][0]["remediation"]
        self.assertIn("if (a) run(); else", remediation,
                      "a fallback boundary inside a fence must not cut the snippet in half")
        self.assertTrue(has_reentrancy_precondition(report["findings"][0]))
        self.assertFalse(any("withheld" in note for note in notes), notes)
        self.assertEqual(unpreconditioned_concurrency_findings(report), [],
                         "the rewrite must be a report its own validator accepts")
        self.assertEqual(normalize_report(report), [], "a second pass must find nothing to do")
        self.assertEqual(report["findings"][0]["remediation"], remediation)


class TestAdviceSurvivesTheHarmItNames(unittest.TestCase):
    """agents-5rnta: a recommendation that NAMES a harm is still a recommendation.

    A role-based classifier can decide "is this advice?" in two places, and the ORDER matters more
    than either test: if a hazard-word exemption runs BEFORE the advice-role test, then every
    imperative that explains why it helps - "Use Promise.all so background jobs don't starve the
    worker pool", "Run asyncio.gather to flood the cache warmer up front" - classifies as a
    DESCRIPTION and ships with no reentrancy precondition. That is the dangerous direction, because
    an advice sentence naming the failure it avoids is exactly the shape a good recommendation has.

    On main the advice decision is made by clause position before any hazard wording is considered,
    so these sentences classify correctly today. This class is the invariant a future role-based
    classifier must not invert: it fails the moment a hazard exemption is evaluated first.
    """

    ADVICE_NAMING_A_HARM = (
        "Use Promise.all so background jobs don't starve the worker pool.",
        "Run asyncio.gather to flood the cache warmer up front.",
        "Use Promise.all here; otherwise requests exhaust the timeout budget.",
        "Use asyncio.gather so the queue cannot stall.",
        "Switch to Promise.all and stop the worker pool from starving.",
    )

    def test_imperative_advice_that_names_a_harm_is_still_advice(self):
        for advice in self.ADVICE_NAMING_A_HARM:
            for field_name, other in (("description", "Consider the fan-out."),
                                      ("remediation", "Waterfall.")):
                with self.subTest(advice=advice, field=field_name):
                    found = {"rule_id": "perf-review", field_name: advice}
                    found["remediation" if field_name == "description" else "description"] = other
                    self.assertTrue(
                        is_concurrency_recommendation(found),
                        "a harm verb in the sentence must not turn advice into a description - "
                        "the hazard exemption may not run before the advice decision",
                    )

    def test_such_advice_still_gets_its_reentrancy_precondition(self):
        # Classifying it is half of it: the guard must act on the advice it is given, or the sentence
        # ships unguarded. Measured on the REMEDIATION, because that is the text the guard rewrites
        # and the text has_reentrancy_precondition inspects - a finding whose advice lives only in
        # `description` is a separate, pre-existing shape (the validator never reads that field).
        for advice in self.ADVICE_NAMING_A_HARM:
            with self.subTest(advice=advice):
                report = {"findings": [{"rule_id": "perf-review", "path": "src/a.ts",
                                        "line_number": 3, "description": "A serial waterfall.",
                                        "remediation": advice}]}
                self.assertTrue(normalize_report(report), "the guard must rewrite this finding")
                remediation = report["findings"][0]["remediation"]
                self.assertIn("reentrancy", remediation)
                # Every clause of the advice is kept. A clause-start otherwise is paraphrased to
                # "if not," on purpose (agents-gjm4n), so the clause is matched on its own words.
                for clause in advice.split(";"):
                    self.assertIn(clause.replace("otherwise ", "").rstrip(".").strip(), remediation,
                                  "the advice itself is kept inside the branch, not dropped")
                self.assertEqual(unpreconditioned_concurrency_findings(report), [])


class TestTheOutputContractAsksForWhatTheSchemaRequires(unittest.TestCase):
    """agents-sz8q: the schema required `snippet` on every finding while this SKILL asked for the other six, so a
    finding written from the SKILL alone was rejected - measured on the gendn run as exactly 35 violations for 35
    candidates, one per candidate, which is what makes the count structural rather than noise. It is reproduced here
    in miniature (35 skill-shaped findings -> 35 violations). NOTE, because the distinction decides what the fix is:
    the factory ALREADY puts the whole schema in the prompt (factory:1698), so this SKILL was never the only thing a
    model was told, and the omission cannot be attributed to it alone. The mechanism this test guards is the
    contract being inconsistent between the two places a maintainer reads it; the mechanism that makes a model
    actually emit the field is `required_fields_note`, asserted in tests/test_report_schema.py.

    The property this asserts is that a field the schema REQUIRES is asked for in the SKILL's PROSE - not merely
    shown inside a fenced example. `snippet` was present in the file all along, which is why a word-presence check
    or a careful human read passes while the station rejects everything: it appeared only in the illustrative JSON.
    A required field that is only illustrated is not requested.
    """

    AGENT = ROOT / "agents" / "perf-review"

    def _required_finding_fields(self):
        schema = json.loads((self.AGENT / "report.schema.json").read_text(encoding="utf-8"))
        items = schema["properties"]["findings"]["items"]
        return list(items.get("required", []))

    @staticmethod
    def _prose(text):
        # Fenced blocks are examples, not instructions; the defect this guards against lived inside one.
        return re.sub(r"```.*?```", "", text, flags=re.S)

    def test_every_required_field_is_asked_for_in_prose(self):
        prose = self._prose((self.AGENT / "SKILL.md").read_text(encoding="utf-8"))
        missing = [f for f in self._required_finding_fields() if f not in prose]
        self.assertEqual(
            missing, [],
            f"the schema requires fields the SKILL never asks for: {missing} - a model that follows the SKILL "
            "produces a report this station rejects, which is how it became unusable by construction")

    def test_the_required_field_set_is_read_from_the_schema_not_typed_here(self):
        # If this list were hardcoded the test would keep passing after the schema grew a required field.
        self.assertIn("snippet", self._required_finding_fields())

    def test_the_check_can_fail_on_the_skill_as_it_was(self):
        """The control, using the REAL defect rather than a synthetic one: strip the prose sentence that asks for
        the required fields (leaving the example JSON, which is what the file looked like before this change) and
        the check above must have something to say. Nothing else in this test depends on that sentence."""
        text = (self.AGENT / "SKILL.md").read_text(encoding="utf-8")
        without = re.sub(r"Every finding MUST carry the fields the schema requires[\s\S]*?withhold it for "
                         r"concurrency recommendations\.\n", "", text, count=1)
        self.assertNotEqual(without, text, "the prose sentence this control removes must exist in the SKILL")
        self.assertIn("snippet", text, "snippet is present in the file as a whole...")
        self.assertNotIn("snippet", self._prose(without), "...but not once the prose sentence is removed, which is "
                                                        "exactly the state that rejected 35 of 35 candidates")


class TestFactorySamplingParams(unittest.TestCase):
    def test_pi_models_json_includes_sampling_params(self):
        """_write_pi_models_json must write samplingParams with temperature 0.1 for determinism."""
        loader = importlib.machinery.SourceFileLoader("factory_cli_test", str(ROOT / "factory"))
        spec = importlib.util.spec_from_loader("factory_cli_test", loader)
        factory_mod = importlib.util.module_from_spec(spec)
        loader.exec_module(factory_mod)

        class DummyBroker:
            providers = ["deepseek"]
            placeholder = "factory-broker-placeholder"
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


class TestPerfReviewDeclaresItsContextChannel(unittest.TestCase):
    """agents-ufl3: the three inputs this station's SKILL names must reach the MODEL, not just the file.

    The SKILL tells the model to examine `recent_commits`, `recently_changed_files` and
    `recent_diff_excerpt`. The pre-pass gathered all three and the dispatcher appended only
    `candidates` to the prompt, so the station asked for evidence nothing delivered. The channel
    that closes it is the landed opt-in one (ADR agents-3f4b): a payload carrying a `context` key
    has its value appended to the real prompt.

    These tests assert the WHOLE chain with the REAL scanner rather than a formatting stub: the
    scanner's payload is driven through the real dispatcher and the assertions are made on the
    RETAINED PROMPT, because asserting a config value or a payload field would pass even if nothing
    ever reached the model. The control below is what makes that a measurement rather than a
    coincidence.
    """

    CONTEXT_KEYS = ("recent_commits", "recently_changed_files", "recent_diff_excerpt")

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="ufl3-")
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.repo = self.tmp / "scanned"
        self.repo.mkdir()
        for argv in (["git", "init", "-q", "-b", "main", "."],
                     ["git", "config", "user.name", "T"],
                     ["git", "config", "user.email", "t@t.com"]):
            subprocess.run(argv, cwd=self.repo, check=True, capture_output=True)
        (self.repo / "app.js").write_text("const x = 1;\n", encoding="utf-8")
        (self.repo / "index.html").write_text("<html><body>hi</body></html>\n", encoding="utf-8")
        subprocess.run(["git", "add", "-A"], cwd=self.repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-qm", "chore: initial page"], cwd=self.repo, check=True, capture_output=True)
        # TWO commits on purpose: with a single-commit repo `git diff HEAD~1..HEAD` fails and the
        # excerpt comes back EMPTY, so an assertion on it would pass while measuring nothing.
        (self.repo / "index.html").write_text(
            '<head><script src="blocking.js"></script></head>\n', encoding="utf-8")
        (self.repo / "app.js").write_text(
            "const w = document.body.offsetWidth;\n", encoding="utf-8")
        subprocess.run(["git", "add", "-A"], cwd=self.repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-qm", "feat: render-blocking script and a forced layout read"],
                       cwd=self.repo, check=True, capture_output=True)
        (self.repo / "app.js").write_text(
            "const w = document.body.offsetWidth;\nfor (const u of urls) { await fetch(u); }\n",
            encoding="utf-8")

    def scanner_payload(self):
        """Run the REAL pre-pass exactly as the dispatcher does, and return its parsed payload."""
        out = self.tmp / "payload.json"
        env = dict(os.environ, FACTORY_ALLOW_UNPINNED_TOOLS="1")
        with mock.patch.dict(os.environ, env):
            proc = subprocess.run(
                [sys.executable, str(SCANNER_SCRIPT), "--target", str(self.repo), "--output", str(out)],
                capture_output=True, text=True, timeout=120)
        self.assertEqual(proc.returncode, 0, f"the real scanner must run: {proc.stderr[-400:]}")
        return json.loads(out.read_text(encoding="utf-8"))

    def test_the_real_payload_declares_the_three_inputs_on_the_context_channel(self):
        payload = self.scanner_payload()
        self.assertIn("context", payload, "the station must opt in by key presence on the context channel")
        self.assertEqual(sorted(payload["context"]), sorted(self.CONTEXT_KEYS))
        ctx = payload["context"]
        self.assertTrue(any("render-blocking" in c for c in ctx["recent_commits"]),
                        f"recent_commits must carry the commits: {ctx['recent_commits']}")
        self.assertIn("app.js", ctx["recently_changed_files"])
        self.assertIn("offsetWidth", ctx["recent_diff_excerpt"],
                      "the excerpt must carry actual diff text, not an empty string")
        # One source for both spellings, so the recorded result and the model's input cannot drift.
        for key in self.CONTEXT_KEYS:
            self.assertEqual(payload[key], ctx[key], f"top-level {key} and its context copy must agree")

    def prompt_for(self, payload):
        box_root = self.tmp / "box"
        box_root.mkdir(exist_ok=True)
        box = Sandbox(box_root)
        feed = self.tmp / "feed.json"
        feed.write_text(json.dumps(payload), encoding="utf-8")
        prepass = ("import json, shutil, sys\n"
                   f"shutil.copyfile({str(feed)!r}, sys.argv[sys.argv.index('--output') + 1])\n")
        box.agent("probe", report(), prepass=prepass)
        targets = box.root / "targets"
        targets.mkdir()
        (targets / "trusted.yaml").write_text(
            f"name: trusted\npath: {box.target}\nvisibility: private\ntrusted: true\n", encoding="utf-8")
        before = set((box.root / "runs").glob("probe-*")) if (box.root / "runs").exists() else set()
        with box.patched(), mock.patch.dict(os.environ, {"FACTORY_ALLOW_UNSANDBOXED": "1"}), \
             mock.patch("lib.sandbox._probe_result", False), contextlib.redirect_stdout(io.StringIO()):
            factory_cli.run_agent("probe", "trusted", engine_arg="pi", explicit_sink="file")
        after = set((box.root / "runs").glob("probe-*")) - before
        self.assertEqual(len(after), 1, "one actual dispatcher run must write one prompt")
        return (after.pop() / "prompt.txt").read_text(encoding="utf-8")

    def test_the_three_inputs_reach_the_real_model_prompt(self):
        payload = self.scanner_payload()
        self.assertIn("context", payload, "the station must declare the channel this test measures")
        prompt = self.prompt_for(payload)
        block = json.dumps(payload["context"], indent=2)
        self.assertIn("Station Context:", prompt)
        # Assert the CONTEXT BLOCK ITSELF rather than needles that merely occur somewhere in the prompt.
        # 'offsetWidth' and 'app.js' both reach the model through Scanner Data, because a candidate
        # carries an excerpt of the very code the change touched - so neither discriminates this
        # channel, and asserting them would pass even if the context never arrived. The serialized
        # block, in the channel's own format, can only have come from the context key, and asserting
        # it verbatim also proves the context is not truncated the way the 50-candidate slice would
        # truncate it (the ADR forbids applying that slice to the station's declared context).
        self.assertIn(block, prompt, "the whole declared context must reach the model verbatim")
        for key in self.CONTEXT_KEYS:
            self.assertIn(f'"{key}"', block)

    def test_without_the_context_key_the_model_still_sees_none_of_them(self):
        """THE CONTROL: without the opt-in key the prompt must not carry the inputs.

        This is what makes the test above a measurement of the channel rather than of the prompt
        happening to contain those strings some other way.
        """
        payload = self.scanner_payload()
        self.assertIn("context", payload, "the station must declare the channel this test measures")
        block = json.dumps(payload["context"], indent=2)
        stripped = {k: v for k, v in payload.items() if k != "context"}
        prompt = self.prompt_for(stripped)
        self.assertNotIn("Station Context:", prompt)
        self.assertNotIn(block, prompt)
        # The needles are the channel marker, the serialized block and the context-only key name -
        # NOT a code string: 'offsetWidth' arrives through Scanner Data regardless, so asserting its
        # absence here would be asserting something this channel never controlled. The first version
        # of this control did exactly that and went red, which is how the mistake was found.
        self.assertNotIn('"recent_diff_excerpt"', prompt)


if __name__ == "__main__":
    unittest.main()
