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
        # `agents/` is a real directory in this repository, so its children keep the
        # prefix. It used to be normalised away because the repo is *named* agents, which
        # checked all 22 agent directories against the repo root and emitted 22 false
        # doc-missing-file candidates on every run (agents-04h).
        self.assertIn("agents/secret-scan/", resolved)
        self.assertIn("agents/qa-station/", resolved)
        self.assertNotIn("secret-scan/", resolved)
        # A child must never be silently reattached to the previous root.
        self.assertNotIn("agents/workflows/", resolved)

    def test_repo_root_aliases_still_collapse(self):
        """A tree drawn from outside the repo (`~/agents/`, `./`) keeps the old behaviour."""
        for root in ("~/agents/", "./"):
            diagram = f"```text\n{root}\n├── lib/\n└── docs/PLAN.md\n```\n"
            resolved = {full for _, full, _ in check_docs.parse_tree_diagrams(diagram)}
            with self.subTest(root=root):
                self.assertIn("lib/", resolved)
                self.assertIn("docs/PLAN.md", resolved)

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
        for expected in [".github/workflows/", ".github/actions/factory/", "lib/adapters/",
                         "agents/secret-scan/", "agents/qa-station/"]:
            self.assertIn(expected, paths)

    def test_agent_fleet_is_not_reported_missing(self):
        """The real tree: the 22 agent directories resolve under agents/, not at the root.

        This is the regression that made the station unreadable - 22 of ~130 candidates
        every run, none of them real (agents-04h).
        """
        candidates = check_docs.scan_target(FACTORY_ROOT)
        references = {c["reference"] for c in candidates}
        for agent_dir in ("secret-scan/", "threat-model/", "vuln-triage/", "qa-station/"):
            self.assertNotIn(agent_dir, references)
        # The context-relative directory name from AGENTS.md/CLAUDE.md resolves by name
        # (`docs/audits/` exists), like its siblings PLAN.md/DESIGN.md/INTEGRATION.md.
        self.assertNotIn("audits/", references)

    def test_context_relative_directory_resolves_by_name(self):
        """A directory named without its parent resolves when that name exists in the repo."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "docs" / "audits").mkdir(parents=True)
            (tmp / "docs" / "audits" / "note.md").write_text("# note\n")
            (tmp / "AGENTS.md").write_text(
                "Internal material: `PLAN.md` and `audits/` live in docs.\n")
            references = {c["reference"] for c in check_docs.scan_target(tmp)}
            self.assertNotIn("audits/", references)

    def test_ambiguous_directory_name_is_still_reported(self):
        """The guard rail for the name fallback: `scripts/` is ambiguous, so drift survives.

        This is the drift the review of 946b23e caught: an unconditional name search let a
        `scripts/` reference match `agents/*/scripts/` and silenced a claim about a
        directory that does not exist at the level the document describes.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            for agent in ("alpha", "beta"):
                (tmp / "agents" / agent / "scripts").mkdir(parents=True)
            (tmp / "README.md").write_text("Pre-pass tool lives in `scripts/`.\n")
            references = {c["reference"] for c in check_docs.scan_target(tmp)}
            self.assertIn("scripts/", references)

    def test_generic_directory_name_is_not_resolved_globally(self):
        """A lone `app/src/` must not satisfy a document's claim about `src/`."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "app" / "src").mkdir(parents=True)
            (tmp / "README.md").write_text("Sources live in `src/`.\n")
            references = {c["reference"] for c in check_docs.scan_target(tmp)}
            self.assertIn("src/", references)

    def test_uniqueness_does_not_depend_on_installed_dependencies(self):
        """A name must not stop being unique because node_modules happens to be present.

        The walk skips the directories the scanner itself ignores, so resolution cannot
        change between a clean checkout and one with dependencies installed (review of
        0b9e460).
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "docs" / "audits").mkdir(parents=True)
            (tmp / "node_modules" / "pkg" / "audits").mkdir(parents=True)
            (tmp / "README.md").write_text("Internal notes live in `audits/`.\n")
            references = {c["reference"] for c in check_docs.scan_target(tmp)}
            self.assertNotIn("audits/", references)

    def test_case_variants_cannot_each_look_unique(self):
        """`Audits/` and `audits/` are one ambiguous name, not two unique ones.

        The count is keyed on the lower-cased name so a document cannot resolve its
        `audits/` against one case variant while the other is what it meant.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "Audits").mkdir()
            (tmp / "legacy" / "audits").mkdir(parents=True)
            (tmp / "README.md").write_text("Internal notes live in `audits/`.\n")
            references = {c["reference"] for c in check_docs.scan_target(tmp)}
            self.assertIn("audits/", references)

    def test_unique_non_generic_directory_still_resolves(self):
        """The intended case: exactly one `audits/` anywhere resolves the name."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "docs" / "audits").mkdir(parents=True)
            (tmp / "README.md").write_text("Internal notes live in `audits/`.\n")
            references = {c["reference"] for c in check_docs.scan_target(tmp)}
            self.assertNotIn("audits/", references)

    def test_uri_schemes_are_not_paths(self):
        """`file://` and `chrome://extensions` are URLs, not repository paths."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "DESIGN.md").write_text(
                "The pages render from `file://` with the network off.\n"
                "Load it unpacked from `chrome://extensions`.\n")
            references = {c["reference"] for c in check_docs.scan_target(tmp)}
            self.assertNotIn("file://", references)
            self.assertNotIn("chrome://extensions", references)

    def test_integration_md_agent_fleet_reference_scripts_exist(self):
        """[agents-bjj] Every script listed in docs/INTEGRATION.md Section 5 exists on disk."""
        integration_md = FACTORY_ROOT / "docs" / "INTEGRATION.md"
        self.assertTrue(integration_md.exists())

        candidates = check_docs.scan_target(FACTORY_ROOT)
        table_candidates = [
            c for c in candidates
            if c["path"] == "docs/INTEGRATION.md" and c.get("reference", "").endswith(".py")
        ]
        self.assertEqual(len(table_candidates), 0,
                         f"docs/INTEGRATION.md references missing scripts: {table_candidates}")

    def test_real_drift_is_still_reported(self):
        """The other guard rail: the name-index leniency must not swallow genuine drift."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "lib").mkdir()
            (tmp / "lib" / "present.py").write_text("# here\n")
            (tmp / "README.md").write_text(
                "`lib/present.py` exists, `lib/gone.py` does not, `docs/` is absent.\n")

            references = {c["reference"] for c in check_docs.scan_target(tmp)}
            self.assertIn("lib/gone.py", references)
            self.assertNotIn("lib/present.py", references)


if __name__ == "__main__":
    unittest.main()
