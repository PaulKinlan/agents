#!/usr/bin/env python3
"""Tests for vuln-discovery surface scanner precision (agents-o5w).

Covers:
- Excluding tests/, test/, and __tests__/ directories from the attack-surface scan.
- Suppressing self-referential matches (re.compile pattern definitions and
  rule-description dicts) so the scanner does not report its own SURFACE_PATTERNS.
- Proof that a fixture-only tree yields zero candidate entry points, while a real
  sink in a non-test file is still detected (no over-suppression).
"""

import sys
import os
os.environ.setdefault("FACTORY_ALLOW_UNPINNED_TOOLS", "1")  # agents-7bj: tests use unpinned stub tools
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agents" / "vuln-discovery" / "scripts"))

import scan_surface  # noqa: E402


class TestSurfaceScannerExclusionsAndSuppression(unittest.TestCase):
    """agents-o5w: verify test-dir exclusion and self-referential suppression."""

    def test_fixture_only_tree_yields_zero_entry_points(self):
        """A tree containing only tests/fixtures must yield exactly zero candidates."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)

            # Fixtures directory with various attack-surface patterns
            fixtures_dir = tmp_path / "fixtures"
            fixtures_dir.mkdir(parents=True)
            (fixtures_dir / "dom.js").write_text("el.innerHTML = user;\n", encoding="utf-8")
            (fixtures_dir / "exec.js").write_text("execSync('ls');\n", encoding="utf-8")

            # tests/ directory with test files carrying sink literals
            tests_dir = tmp_path / "tests"
            tests_dir.mkdir(parents=True)
            (tests_dir / "test_server.py").write_text("app.get('/test', handler)\n", encoding="utf-8")
            (tests_dir / "test_dom.py").write_text("el.innerHTML = user\n", encoding="utf-8")

            # __tests__/ directory (JS convention) with sink literals
            js_tests_dir = tmp_path / "__tests__"
            js_tests_dir.mkdir(parents=True)
            (js_tests_dir / "server.test.ts").write_text("http.createServer();\n", encoding="utf-8")

            candidates, _ = scan_surface.scan_source_files(tmp_path, None)
            self.assertEqual(len(candidates), 0, f"Expected 0 candidates in fixture-only tree, got: {candidates}")

    def test_real_source_entry_point_detected(self):
        """Genuine sinks in non-test production code must still be detected."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)

            src_dir = tmp_path / "src"
            src_dir.mkdir(parents=True)
            (src_dir / "server.ts").write_text("app.post('/api/auth/login', handleLogin);\n", encoding="utf-8")
            (src_dir / "dom.js").write_text("el.innerHTML = userInput;\n", encoding="utf-8")

            candidates, _ = scan_surface.scan_source_files(tmp_path, None)
            rule_ids = {c["rule_id"] for c in candidates}
            self.assertEqual(rule_ids, {"http-listener-route", "dom-injection-sink"})
            for c in candidates:
                self.assertIn(c["path"], {"src/server.ts", "src/dom.js"})

    def test_recompile_and_rule_description_lines_suppressed(self):
        """Pattern definitions (re.compile) and rule-description dicts are suppressed."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            src_dir = tmp_path / "src"
            src_dir.mkdir(parents=True)

            # Each line below contains a literal that matches a SURFACE_PATTERNS rule
            # (interpolate / app.get / innerHTML) but is either a comment, a re.compile
            # definition, or a rule-description dict — all of which must be suppressed.
            code = (
                "// app.get('/commented') should not match\n"
                "# el.innerHTML = user is also a comment\n"
                'SURFACE_PATTERNS = [("x", "y", "z", re.compile(r"(?:interpolate|promptTemplate)"))]\n'
                'rule_meta = {"rule_id": "prompt-template-interpolation", "description": "interpolate into prompt"}\n'
            )
            (src_dir / "rules.py").write_text(code, encoding="utf-8")

            candidates, _ = scan_surface.scan_source_files(tmp_path, None)
            self.assertEqual(len(candidates), 0, f"Expected self-matches suppressed, got: {candidates}")

    def test_pattern_defining_scanner_file_excluded(self):
        """The scanner's own file (scan_surface.py) is excluded from candidate findings."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            scripts_dir = tmp_path / "agents" / "vuln-discovery" / "scripts"
            scripts_dir.mkdir(parents=True)

            # Copy scan_surface.py and append a marker-free literal sink so this test
            # exercises the file-level exclusion via is_scanner_file (not line suppression).
            content = (ROOT / "agents" / "vuln-discovery" / "scripts" / "scan_surface.py").read_text(encoding="utf-8")
            content += "\nel.innerHTML = x;\n"
            (scripts_dir / "scan_surface.py").write_text(content, encoding="utf-8")

            candidates, _ = scan_surface.scan_source_files(tmp_path, None)
            self.assertEqual(len(candidates), 0, f"Expected 0 candidates due to is_scanner_file, got: {candidates}")

    def test_refusal_guard_lines_suppressed(self):
        """agents-5gg: lines raising ContainmentError or StationError are suppressed."""
        self.assertTrue(scan_surface.is_self_referential_line("raise ContainmentError('refusing on target')"))
        self.assertTrue(scan_surface.is_self_referential_line("raise StationError('station failed')"))

    def test_permission_error_lines_not_suppressed(self):
        """agents-qbc: lines raising builtin PermissionError are NOT suppressed."""
        line = "raise PermissionError('human triage approval missing')"
        self.assertFalse(scan_surface.is_self_referential_line(line))
        app_line = 'raise PermissionError(f"user {uid} cannot access {path}")'
        self.assertFalse(scan_surface.is_self_referential_line(app_line))

    def test_threat_model_artifact_file_excluded(self):
        """agents-5gg: is_scanner_file excludes *-THREAT_MODEL.md files."""
        p = Path("target-THREAT_MODEL.md")
        self.assertTrue(scan_surface.is_scanner_file(p, str(p)))


if __name__ == "__main__":
    unittest.main()
