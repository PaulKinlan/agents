#!/usr/bin/env python3
"""Tests for pre-pass scanner artifact directory exclusions (agents-uxt).

Ensures all deterministic pre-pass scanners and bench runners exclude factory
artifact directories ('findings', 'runs') so scanners do not ingest previous
station outputs, reports, or execution logs as target source code.
"""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.exclusions import DEFAULT_IGNORE_DIRS, FACTORY_ARTIFACT_DIRS


class TestPrepassExclusions(unittest.TestCase):
    def test_default_ignore_dirs_contains_artifact_dirs(self):
        """FACTORY_ARTIFACT_DIRS ('findings', 'runs') must be in DEFAULT_IGNORE_DIRS."""
        self.assertIn("findings", FACTORY_ARTIFACT_DIRS)
        self.assertIn("runs", FACTORY_ARTIFACT_DIRS)
        self.assertIn("findings", DEFAULT_IGNORE_DIRS)
        self.assertIn("runs", DEFAULT_IGNORE_DIRS)

    def test_memory_profile_does_not_scan_findings_or_runs(self):
        """agents-uxt: memory-profile pre-pass must ignore findings/ and runs/."""
        sys.path.insert(0, str(ROOT / "agents" / "memory-profile" / "scripts"))
        import scan_memory_leaks

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            # Legitimate source file without leaks
            src_dir = target / "src"
            src_dir.mkdir(parents=True)
            (src_dir / "index.js").write_text("console.log('clean');\n", encoding="utf-8")

            # Artifact directories containing leaked code patterns
            findings_dir = target / "findings"
            findings_dir.mkdir(parents=True)
            (findings_dir / "old_leak.js").write_text(
                "const cache = {};\nwindow.addEventListener('resize', () => { cache[Math.random()] = 1; });\n",
                encoding="utf-8"
            )

            runs_dir = target / "runs" / "run_01"
            runs_dir.mkdir(parents=True)
            (runs_dir / "run_leak.js").write_text(
                "setInterval(() => { window.leaks = window.leaks || []; window.leaks.push(new Array(1000)); }, 100);\n",
                encoding="utf-8"
            )

            result = scan_memory_leaks.scan_memory_leaks(target)
            scanned = result.get("scanned_files", 0)
            candidates = result.get("candidates", [])

            self.assertEqual(scanned, 1)
            self.assertEqual(len(candidates), 0)

    def test_test_gap_does_not_scan_findings_or_runs(self):
        """test-gap pre-pass must ignore findings/ and runs/."""
        sys.path.insert(0, str(ROOT / "agents" / "test-gap" / "scripts"))
        import find_untested

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            src_dir = target / "src"
            src_dir.mkdir(parents=True)
            (src_dir / "module.js").write_text("export function realCode() {}\n", encoding="utf-8")

            (target / "findings").mkdir(parents=True)
            (target / "findings" / "artifact.js").write_text("export function oldFinding() {}\n", encoding="utf-8")

            (target / "runs" / "test_run").mkdir(parents=True)
            (target / "runs" / "test_run" / "run_code.js").write_text("export function runCode() {}\n", encoding="utf-8")

            source_files, test_files = find_untested.find_files(target)
            paths = [str(p.relative_to(target)) for p in source_files]
            self.assertEqual(paths, ["src/module.js"])

    def test_ui_ux_audit_does_not_scan_findings_or_runs(self):
        """ui-ux-audit pre-pass must ignore findings/ and runs/."""
        sys.path.insert(0, str(ROOT / "agents" / "ui-ux-audit" / "scripts"))
        import scan_ui_ux

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            src_dir = target / "src"
            src_dir.mkdir(parents=True)
            (src_dir / "index.html").write_text("<!DOCTYPE html><html><body><h1>Hello</h1></body></html>\n", encoding="utf-8")

            (target / "findings").mkdir(parents=True)
            (target / "findings" / "report.html").write_text("<div>report</div>\n", encoding="utf-8")

            (target / "runs" / "r1").mkdir(parents=True)
            (target / "runs" / "r1" / "preview.html").write_text("<div>preview</div>\n", encoding="utf-8")

            result = scan_ui_ux.scan_ui_ux(target)
            self.assertEqual(result.get("scanned_files"), 1)

    def test_resilience_does_not_scan_findings_or_runs(self):
        """resilience pre-pass must ignore findings/ and runs/."""
        sys.path.insert(0, str(ROOT / "agents" / "resilience" / "scripts"))
        import scan_resilience

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            src_dir = target / "src"
            src_dir.mkdir(parents=True)
            (src_dir / "page.html").write_text("<html><body></body></html>\n", encoding="utf-8")

            (target / "findings").mkdir(parents=True)
            (target / "findings" / "resilience_report.html").write_text("<html></html>\n", encoding="utf-8")

            (target / "runs" / "r1").mkdir(parents=True)
            (target / "runs" / "r1" / "run.html").write_text("<html></html>\n", encoding="utf-8")

            res = scan_resilience.scan_resilience(target)
            self.assertEqual(res.get("scanned_files"), 1)

    def test_log_check_does_not_scan_findings_or_runs(self):
        """log-check pre-pass must ignore findings/ and runs/."""
        sys.path.insert(0, str(ROOT / "agents" / "log-check" / "scripts"))
        import parse_logs

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            (target / "app.log").write_text("2026-10-09 INFO Starting\n", encoding="utf-8")

            (target / "findings").mkdir(parents=True)
            (target / "findings" / "delta.log").write_text("Error: mock\n", encoding="utf-8")

            (target / "runs" / "r1").mkdir(parents=True)
            (target / "runs" / "r1" / "output.log").write_text("Error: execution failure\n", encoding="utf-8")

            found_logs = parse_logs.find_logs(target)
            log_names = [p.name for p in found_logs]
            self.assertEqual(log_names, ["app.log"])

    def test_bench_runner_ignores_findings_and_runs(self):
        """lib/bench/runner.py IGNORE_DIRS must include findings and runs."""
        from lib.bench.runner import IGNORE_DIRS
        self.assertIn("findings", IGNORE_DIRS)
        self.assertIn("runs", IGNORE_DIRS)

    def test_docs_write_does_not_scan_findings_or_runs(self):
        """docs-write pre-pass must ignore findings/ and runs/."""
        sys.path.insert(0, str(ROOT / "agents" / "docs-write" / "scripts"))
        import prepare_docs_fixes

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            src_dir = target / "src"
            src_dir.mkdir(parents=True)
            (src_dir / "index.js").write_text("console.log('hi');\n", encoding="utf-8")
            (target / "README.md").write_text("# Project\n", encoding="utf-8")

            (target / "findings").mkdir(parents=True)
            (target / "findings" / "delta.md").write_text("# Old delta\n", encoding="utf-8")

            (target / "runs" / "r1").mkdir(parents=True)
            (target / "runs" / "r1" / "doc.md").write_text("# Run doc\n", encoding="utf-8")

            res = prepare_docs_fixes.collect_repo_ground_truth(target)
            doc_paths = res.get("markdown_files", [])
            self.assertEqual(doc_paths, ["README.md"])

    def test_perf_review_does_not_scan_findings_or_runs(self):
        """perf-review pre-pass must ignore findings/ and runs/."""
        sys.path.insert(0, str(ROOT / "agents" / "perf-review" / "scripts"))
        import scan_perf_changes

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            src_dir = target / "src"
            src_dir.mkdir(parents=True)
            (src_dir / "app.js").write_text("document.getElementById('test').offsetHeight;\n", encoding="utf-8")

            (target / "findings").mkdir(parents=True)
            (target / "findings" / "old.js").write_text("element.offsetWidth;\n", encoding="utf-8")

            (target / "runs" / "r1").mkdir(parents=True)
            (target / "runs" / "r1" / "leak.js").write_text("element.offsetWidth;\n", encoding="utf-8")

            candidates = scan_perf_changes.scan_files(target, [])
            for c in candidates:
                self.assertNotIn("findings/", c["path"])
                self.assertNotIn("runs/", c["path"])

    def test_all_scanners_include_factory_artifact_dirs(self):
        """All pre-pass scanners must have findings and runs in their effective ignore set."""
        modules = [
            ("agents.memory-profile.scripts.scan_memory_leaks", "IGNORE_DIRS"),
            ("agents.resilience.scripts.scan_resilience", "IGNORE_DIRS"),
            ("agents.ui-ux-audit.scripts.scan_ui_ux", "IGNORE_DIRS"),
            ("agents.test-gap.scripts.find_untested", "IGNORE_DIRS"),
            ("agents.log-check.scripts.parse_logs", "IGNORE_DIRS"),
            ("agents.docs-write.scripts.prepare_docs_fixes", "IGNORE_DIRS"),
            ("agents.perf-review.scripts.scan_perf_changes", "IGNORE_DIRS"),
            ("agents.modern-web.scripts.scan_modern_web", "IGNORE_DIRS"),
            ("agents.secret-scan.scripts.scan", "IGNORE_DIRS"),
            ("agents.accessibility.scripts.audit_a11y", "EXCLUDE_DIRS"),
            ("agents.deps-supply-chain.scripts.audit_deps", "IGNORE_SCAN_DIRS"),
            ("agents.docs-drift.scripts.check_docs", "IGNORE_DIRS"),
            ("agents.vuln-discovery.scripts.scan_surface", "IGNORE_DIRS"),
            ("agents.threat-model.scripts.mine_history", "IGNORED_DIRS"),
            ("lib.bench.runner", "IGNORE_DIRS"),
        ]
        for mod_name, attr in modules:
            with self.subTest(module=mod_name):
                mod = __import__(mod_name, fromlist=[attr])
                ignore_set = getattr(mod, attr)
                self.assertTrue(FACTORY_ARTIFACT_DIRS.issubset(ignore_set),
                                f"{mod_name}.{attr} missing {FACTORY_ARTIFACT_DIRS - ignore_set}")


if __name__ == "__main__":
    unittest.main()
