#!/usr/bin/env python3
"""Unit tests for the docs-drift deterministic scanner.

The ASCII tree parser is the part that failed during the agents-vkw audit: it only
recognised a new root while no subtree was open, so in a diagram listing several
top-level entries (`agents/`, `.github/`, `lib/`, `docs/`) every root after the first
was dropped, its parent prefix was lost, and the entry was checked against the wrong
path. `.github/workflows/` was reported missing while it existed.
"""

import importlib.machinery
import importlib.util
import tempfile
import unittest
from pathlib import Path

FACTORY_ROOT = Path(__file__).resolve().parent.parent
loader = importlib.machinery.SourceFileLoader(
    "check_docs", str(FACTORY_ROOT / "agents" / "docs-drift" / "scripts" / "check_docs.py")
)
spec = importlib.util.spec_from_loader("check_docs", loader)
check_docs = importlib.util.module_from_spec(spec)
loader.exec_module(check_docs)


class TestTreeDiagramParser(unittest.TestCase):
    def test_every_root_keeps_its_prefix(self):
        """A second, third and fourth root in the same code block must start new subtrees."""
        diagram = (
            "```text\n"
            "agents/                            # Fleet\n"
            "├── secret-scan/\n"
            "└── qa-station/\n"
            "lines/                             # Composed lines\n"
            ".github/\n"
            "├── actions/factory/\n"
            "└── workflows/\n"
            "lib/\n"
            "├── adapters/\n"
            "└── bench/\n"
            "docs/\n"
            "└── PLAN.md\n"
            "```\n"
        )
        resolved = {full for _, full, _ in check_docs.parse_tree_diagrams(diagram)}

        self.assertIn(".github/workflows/", resolved)
        self.assertIn(".github/actions/factory/", resolved)
        self.assertIn("lib/adapters/", resolved)
        self.assertIn("lib/bench/", resolved)
        self.assertIn("docs/PLAN.md", resolved)
        # `agents/` is normalised to the repo root, so its children stay bare.
        self.assertIn("secret-scan/", resolved)
        # A child must never be silently reattached to the previous root.
        self.assertNotIn("agents/workflows/", resolved)

    def test_missing_directory_is_still_reported(self):
        """The guard rail: fixes to the parser must not disable the drift rule."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "docs").mkdir()
            (tmp / "docs" / "PLAN.md").write_text("# PLAN\n")
            (tmp / "README.md").write_text(
                "```text\n"
                "docs/\n"
                "└── PLAN.md\n"
                "gone/\n"
                "└── vanished/\n"
                "```\n"
            )

            candidates = check_docs.scan_target(tmp)
            references = {c["reference"] for c in candidates}

            self.assertIn("gone/vanished/", references)
            self.assertNotIn("docs/PLAN.md", references)

    def test_repository_readme_resolves_its_governance_paths(self):
        """The README's own diagram must resolve the paths the audit flagged."""
        content = (FACTORY_ROOT / "README.md").read_text(encoding="utf-8")
        paths = {full for _, full, _ in check_docs.parse_tree_diagrams(content)}
        for expected in [".github/workflows/", ".github/actions/factory/", "lib/adapters/"]:
            self.assertIn(expected, paths)


if __name__ == "__main__":
    unittest.main()
