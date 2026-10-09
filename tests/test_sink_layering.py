#!/usr/bin/env python3
"""Layering: the tracker sinks live in lib/sinks/, not lib/findings.py (fleet-km8 / agents-173).

lib/findings.py keeps what core owns — lifecycle, receipts, the embargo partition and the
dispatch accounting — and hands each adapter the findings it may publish. This test pins that
the tracker-specific code moved out and stays out.
"""

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _top_level_defs(path: Path) -> set:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {node.name for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}


class TestSinkLayering(unittest.TestCase):
    def test_findings_py_names_no_tracker_sink(self):
        defs = _top_level_defs(ROOT / "lib" / "findings.py")
        for moved in ("_dispatch_beads", "_existing_bead_fingerprints", "_bd_json",
                      "promote_issue", "_gh_api", "_gh_pages", "_issue_identity"):
            self.assertNotIn(moved, defs, f"{moved} still lives in lib/findings.py")

    def test_beads_adapter_owns_the_beads_sink(self):
        defs = _top_level_defs(ROOT / "lib" / "sinks" / "beads.py")
        for name in ("_dispatch_beads", "_existing_bead_fingerprints", "_bd_json"):
            self.assertIn(name, defs, f"{name} missing from lib/sinks/beads.py")

    def test_github_adapter_owns_the_promotion_sink(self):
        defs = _top_level_defs(ROOT / "lib" / "sinks" / "github.py")
        for name in ("promote_issue", "_gh_api", "_gh_pages", "_issue_identity"):
            self.assertIn(name, defs, f"{name} missing from lib/sinks/github.py")

    def test_findings_py_imports_the_adapters(self):
        tree = ast.parse((ROOT / "lib" / "findings.py").read_text(encoding="utf-8"))
        modules = {node.module for node in ast.walk(tree)
                   if isinstance(node, ast.ImportFrom) and node.module}
        self.assertIn("lib.sinks.beads", modules)
        self.assertIn("lib.sinks.github", modules)


if __name__ == "__main__":
    unittest.main()
