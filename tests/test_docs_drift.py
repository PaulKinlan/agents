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
import subprocess
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
        # The explicit path docs/audits/ from AGENTS.md/CLAUDE.md resolves directly.
        self.assertNotIn("docs/audits/", references)

    def test_bare_directory_fallback_is_retired(self):
        """[agents-vdb] Bare directory names do NOT resolve by name lookup alone.

        A document referencing a bare directory name (e.g. `audits/`) when only a nested
        directory exists (`docs/audits/`) must be reported as missing; documents must
        name the actual path.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "docs" / "audits").mkdir(parents=True)
            (tmp / "docs" / "audits" / "note.md").write_text("# note\n")
            (tmp / "docs" / "PLAN.md").write_text("# plan\n")
            (tmp / "AGENTS.md").write_text(
                "Internal material: `PLAN.md` and `audits/` live in docs.\n")
            references = {c["reference"] for c in check_docs.scan_target(tmp)}
            self.assertIn("audits/", references)
            self.assertNotIn("PLAN.md", references)

    def test_dotted_directory_name_does_not_resolve_via_file_fallback(self):
        """[agents-vdb] A directory with a dot/extension like `audits.json/` or `audits.json`
        must not resolve against a nested directory `docs/audits.json/` via bare-filename matching.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "docs" / "audits.json").mkdir(parents=True)
            (tmp / "docs" / "audits.json" / "note.md").write_text("# note\n")
            (tmp / "AGENTS.md").write_text(
                "Versioned notes live in `audits.json/` or `audits.json`.\n")
            references = {c["reference"] for c in check_docs.scan_target(tmp)}
            self.assertIn("audits.json/", references)
            self.assertIn("audits.json", references)

    def test_explicit_directory_path_resolves(self):
        """[agents-vdb] An explicitly qualified directory path resolves without issue."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "docs" / "audits").mkdir(parents=True)
            (tmp / "docs" / "audits" / "note.md").write_text("# note\n")
            (tmp / "docs" / "PLAN.md").write_text("# plan\n")
            (tmp / "AGENTS.md").write_text(
                "Internal material: `PLAN.md` and `docs/audits/` live in docs.\n")
            references = {c["reference"] for c in check_docs.scan_target(tmp)}
            self.assertNotIn("docs/audits/", references)
            self.assertNotIn("PLAN.md", references)

    def test_ambiguous_directory_name_is_still_reported(self):
        """The guard rail: `scripts/` does not exist at root, so drift survives."""
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


class TestStationSkillScope(unittest.TestCase):
    """A station SKILL.md documents auditing an ARBITRARY target, so its prose names the
    target's layout as often as this repo's own files (agents-6zq).

    Measured on the 2026-10-09 tree: 31 of 31 SKILL.md candidates were target-facing or not
    paths at all, while 49 SKILL.md references that DO resolve - every station's own
    scripts/*.py among them - would stop being checked if SKILL.md were skipped outright.
    These tests pin both halves of that decision: the target-facing shapes are skipped, and
    a station's own missing file is still reported.
    """

    TARGET_FACING = (
        "```text\n"
        "dist/\n"
        "build/\n"
        "src/\n"
        "```\n"
        "Ship `dist/`, `extension/`, `fixtures/`, `test/` and `manifest.json`.\n"
        "Load it from `chrome://extensions` after `try/catch` around `downloadToDir()`;\n"
        "never touch `TODO(baseline/<feature-id>)` or `scripts/*journey*.ts`.\n"
    )

    def _station(self, tmp: Path, skill_body: str) -> Path:
        station = tmp / "agents" / "probe"
        (station / "scripts").mkdir(parents=True)
        (station / "scripts" / "present.py").write_text("# present\n")
        (station / "SKILL.md").write_text(skill_body)
        return station

    def test_target_facing_references_in_a_skill_are_skipped(self):
        """All four target-facing shapes are not claims about this repository."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            self._station(tmp, self.TARGET_FACING)
            references = {c["reference"] for c in check_docs.scan_target(tmp)}
            for target_facing in ("dist/", "build/", "src/", "extension/", "fixtures/",
                                  "test/", "manifest.json", "try/catch", "chrome://extensions",
                                  "script/*journey*.ts", "scripts/*journey*.ts"):
                self.assertNotIn(target_facing, references)

    def test_station_own_missing_script_is_still_reported(self):
        """The guard rail: renaming a station's own script must still fail the check."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            station = self._station(
                tmp, "Run `scripts/scan.py` to produce the report, then cite `scripts/present.py`.\n")

            references = {c["reference"] for c in check_docs.scan_target(tmp)}
            self.assertIn("scripts/scan.py", references)      # missing -> real drift
            self.assertNotIn("scripts/present.py", references)  # present -> no candidate

            # Restoring the file clears the candidate, i.e. this is a real existence check.
            (station / "scripts" / "scan.py").write_text("# restored\n")
            references = {c["reference"] for c in check_docs.scan_target(tmp)}
            self.assertNotIn("scripts/scan.py", references)

    def test_tracked_generic_directory_head_is_still_checked(self):
        """`lib` is a generic word AND a first-party directory here: check it.

        The first version of this filter tested the generic-name list before the existence
        check and hid lib/adapters/gha.sh - the one genuine drift in this repository.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            station = self._station(tmp, "Add `lib/adapters/gha.sh` to complete the adapter set.\n")
            (tmp / "lib" / "adapters").mkdir(parents=True)
            (tmp / "lib" / "adapters" / "pi.sh").write_text("# pi\n")
            subprocess.run(["git", "init", "-q", str(tmp)], check=True)
            subprocess.run(["git", "-C", str(tmp), "add", "-A"], check=True)

            references = {c["reference"] for c in check_docs.scan_target(tmp)}
            self.assertIn("lib/adapters/gha.sh", references)
            self.assertNotIn("lib/adapters/pi.sh", references)

    def test_non_skill_documents_are_unaffected(self):
        """The filter is scoped to SKILL.md: a plan that names `dist/` is still drift."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "docs").mkdir()
            (tmp / "docs" / "PLAN.md").write_text("Distribution lands in `dist/` and `src/`.\n")

            references = {c["reference"] for c in check_docs.scan_target(tmp)}
            self.assertIn("dist/", references)
            self.assertIn("src/", references)

    def _git_repo(self, tmp: Path) -> None:
        subprocess.run(["git", "init", "-q", str(tmp)], check=True)
        subprocess.run(["git", "-C", str(tmp), "add", "-A"], check=True)

    def test_dot_prefixed_directory_is_not_stripped(self):
        """`.github/` must keep its dot: lstrip("./") turned the head into "github".

        Review of 58f9931: a genuine first-party claim about `.github/workflows/...` was
        silently skipped because lstrip treats its argument as a character set.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            self._station(tmp, "The workflow lives at `.github/workflows/nightly.yml`.\n")
            (tmp / ".github" / "workflows").mkdir(parents=True)
            (tmp / ".github" / "workflows" / "ci.yml").write_text("# ci\n")
            self._git_repo(tmp)

            references = {c["reference"] for c in check_docs.scan_target(tmp)}
            self.assertIn(".github/workflows/nightly.yml", references)
            self.assertNotIn(".github/workflows/ci.yml", references)

    def test_qualified_path_with_generic_last_component_is_checkable(self):
        """`agents/x/scripts/` is not a "bare container" just because it ends in scripts/.

        Review of 58f9931: the old test looked at the LAST component, so any qualified path
        ending in a generic name was discarded before its prefix was ever considered. The
        station deliberately has no scripts/ directory, so the reference is genuinely
        missing and the only question is whether it is checkable.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            station = tmp / "agents" / "probe"
            station.mkdir(parents=True)
            (station / "SKILL.md").write_text("The pre-pass lives in `agents/probe/scripts/`.\n")
            self._git_repo(tmp)

            references = {c["reference"] for c in check_docs.scan_target(tmp)}
            self.assertIn("agents/probe/scripts/", references)

    def test_target_layout_container_is_skipped_even_when_it_exists(self):
        """The target-layout guard is LIVE: without it a host with a real dist/ reports noise.

        A bare `dist/` would resolve, so the live case is a file inside a container that
        exists here but belongs to the audited project's layout. Deleting the guard makes
        this test fail (that guard was unreachable before the 58f9931 review, which is why
        it could be removed with no test failing).
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            self._station(tmp, "Score the shipped bundle in `dist/bundle.js` and `test/x.test.js`.\n")
            (tmp / "dist").mkdir()
            (tmp / "dist" / "shipped.js").write_text("// shipped\n")
            (tmp / "test").mkdir()
            (tmp / "test" / "real.test.js").write_text("// real\n")
            self._git_repo(tmp)

            references = {c["reference"] for c in check_docs.scan_target(tmp)}
            self.assertNotIn("dist/bundle.js", references)
            self.assertNotIn("test/x.test.js", references)

    def test_own_source_roots_are_not_treated_as_target_layout(self):
        """`lib/`, `docs/` and `tools/` are this repository's own roots: still checked.

        GENERIC_DIR_NAMES contains them, and using THAT list here hid lib/adapters/gha.sh -
        the one genuine drift in this repository (review of 58f9931).
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            self._station(tmp, "The adapter lives at `lib/adapters/gha.sh`; see `docs/PLAN.md`.\n")
            (tmp / "lib" / "adapters").mkdir(parents=True)
            (tmp / "lib" / "adapters" / "pi.sh").write_text("# pi\n")
            (tmp / "docs").mkdir()
            (tmp / "docs" / "PLAN.md").write_text("# plan\n")
            self._git_repo(tmp)

            references = {c["reference"] for c in check_docs.scan_target(tmp)}
            self.assertIn("lib/adapters/gha.sh", references)

    def test_real_repo_skill_candidates_collapse_to_genuine_only(self):
        """On the real tree: 31 SKILL.md candidates drop to at most the genuine ones."""
        candidates = check_docs.scan_target(FACTORY_ROOT)
        skill_refs = sorted({
            c["reference"] for c in candidates
            if c["path"].startswith("agents/") and c["path"].endswith("SKILL.md")
        })
        self.assertLessEqual(len(skill_refs), 1,
                             f"target-facing SKILL.md noise returned: {skill_refs}")
        for ref in skill_refs:
            head = ref.split("/", 1)[0]
            self.assertTrue((FACTORY_ROOT / head).is_dir(),
                            f"surviving SKILL.md candidate {ref!r} is not own-facing")
