#!/usr/bin/env python3
"""Unit tests for the docs-drift deterministic scanner.

The ASCII tree parser is the part that failed during the agents-vkw audit: it only
recognised a new root while no subtree was open, so in a diagram listing several
top-level entries (`agents/`, `.github/`, `lib/`, `docs/`) every root after the first
was dropped, its parent prefix was lost, and the entry was checked against the wrong
path. `.github/workflows/` was reported missing while it existed.
"""

import errno
import importlib.machinery
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

FACTORY_ROOT = Path(__file__).resolve().parent.parent
loader = importlib.machinery.SourceFileLoader(
    "check_docs", str(FACTORY_ROOT / "agents" / "docs-drift" / "scripts" / "check_docs.py")
)
spec = importlib.util.spec_from_loader("check_docs", loader)
check_docs = importlib.util.module_from_spec(spec)
loader.exec_module(check_docs)


class TestDocsDriftReportExamples(unittest.TestCase):
    def test_each_example_cites_a_candidate_and_the_confirmed_rule_is_scanner_backed(self):
        """agents-fmakh: the SKILL arm must catch examples that teach missing citations."""
        text = (FACTORY_ROOT / "agents" / "docs-drift" / "SKILL.md").read_text(encoding="utf-8")
        examples = [json.loads(block) for block in re.findall(r"```json\s*\n(.*?)```", text, re.S)]
        self.assertEqual(len(examples), 2, "assert against both the dismissal and report examples")
        for example in examples:
            for finding in example.get("findings", [example]):
                with self.subTest(rule=finding["rule_id"]):
                    candidate_id = finding.get("candidate_id")
                    self.assertIsInstance(candidate_id, str)
                    self.assertTrue(candidate_id.startswith("<copy ") and "Scanner Data" in candidate_id,
                                    "the example must require a shown, not invented, citation")
        confirmed = [row for row in examples[1]["findings"] if not row.get("false_positive")]
        self.assertTrue(confirmed, "the report example must demonstrate a confirmed candidate")
        for row in confirmed:
            self.assertIn(row["rule_id"], {"doc-deleted-reference", "doc-missing-file",
                                            "doc-broken-link", "doc-broken-anchor", "doc-missing-symbol"},
                          "a model-only doc-spec-drift row cannot cite a scanner candidate")

    def test_scanner_stamps_a_citable_id_on_a_broken_link(self):
        """Drive the real CLI; report validation and accounting live in their consumer suites."""
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "target"
            target.mkdir()
            (target / "README.md").write_text("# Test\n[missing](gone.md)\n", encoding="utf-8")
            output = Path(tmp) / "candidates.json"
            subprocess.run([sys.executable, str(FACTORY_ROOT / "agents" / "docs-drift" /
                                                "scripts" / "check_docs.py"), "--target", str(target),
                            "--output", str(output)], check=True, capture_output=True, text=True,
                           env={**os.environ, "FACTORY_ALLOW_UNPINNED_TOOLS": "1"})
            emitted = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(emitted["candidate_count"], 1)
            candidate = emitted["candidates"][0]
            self.assertEqual(candidate["rule_id"], "doc-broken-link")
            self.assertRegex(candidate["candidate_id"], r"^[0-9a-f]{16}$")


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

        A wider generic list contained them, and using that list here hid lib/adapters/gha.sh -
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


class TestMarkdownAnchorResolution(unittest.TestCase):
    """Anchor slug generation and broken anchor reporting (agents-8xc4).

    GitHub strips punctuation (including '&') leaving adjacent spaces, then converts
    each space to a hyphen, yielding double hyphens ('--') for '&' headings.
    Tests verify both directions:
      1. '&' headings resolve correctly without false positives.
      2. Genuinely broken anchors are still reported as doc-broken-anchor.
    """

    def test_slugify_heading_preserves_double_hyphen_for_ampersand(self):
        cases = [
            ("3. Target Enrolment Plane (Local Fleet & Scheduler)",
             "3-target-enrolment-plane-local-fleet--scheduler"),
            ("Recipe A: Pull Request & Push Quality Gate",
             "recipe-a-pull-request--push-quality-gate"),
            ("1.1 Action Inputs & Outputs",
             "11-action-inputs--outputs"),
            ("1.2 Required Permissions & Secrets",
             "12-required-permissions--secrets"),
            ("1.3 Security & Public Disclosure Guardrails",
             "13-security--public-disclosure-guardrails"),
            ("5. Agent Fleet Reference & CI Compatibility",
             "5-agent-fleet-reference--ci-compatibility"),
            ("The Software Factory — Integration & Automation Guide",
             "the-software-factory--integration--automation-guide"),
        ]
        for heading, expected_slug in cases:
            with self.subTest(heading=heading):
                self.assertEqual(check_docs.slugify_heading(heading), expected_slug)

    def test_ampersand_heading_anchor_resolves_without_false_positive(self):
        """A same-document link to an '&' heading generates a double-hyphen anchor and resolves."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "doc.md").write_text(
                "# Title\n\n"
                "See [Fleet & Scheduler](#local-fleet--scheduler) or "
                "[Recipe A](#recipe-a-pull-request--push-quality-gate).\n\n"
                "## Local Fleet & Scheduler\n\n"
                "Content here.\n\n"
                "### Recipe A: Pull Request & Push Quality Gate\n\n"
                "Recipe details.\n"
            )
            candidates = check_docs.scan_target(tmp)
            broken = [c for c in candidates if c["rule_id"] == "doc-broken-anchor"]
            self.assertEqual(broken, [], f"Unexpected broken anchor candidates: {broken}")

    def test_genuinely_broken_anchor_is_still_reported(self):
        """The guard rail: an anchor that truly does not exist in the document must be reported."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "doc.md").write_text(
                "# Title\n\n"
                "Broken link: [Missing](#does-not-exist).\n"
                "Single-hyphen mismatch: [Wrong](#local-fleet-scheduler).\n\n"
                "## Local Fleet & Scheduler\n\n"
                "Content.\n"
            )
            candidates = check_docs.scan_target(tmp)
            broken = [c for c in candidates if c["rule_id"] == "doc-broken-anchor"]
            broken_refs = {c["reference"] for c in broken}
            self.assertIn("#does-not-exist", broken_refs)
            self.assertIn("#local-fleet-scheduler", broken_refs)
            self.assertEqual(len(broken), 2)

    def test_cross_document_ampersand_anchor_resolves_and_broken_reported(self):
        """Cross-document links to '&' headings resolve when valid and report when broken."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "target.md").write_text(
                "# Target Document\n\n"
                "## Target Enrolment Plane (Local Fleet & Scheduler)\n\n"
                "Body.\n"
            )
            (tmp / "caller.md").write_text(
                "# Caller\n\n"
                "Valid link: [Enrolment](target.md#target-enrolment-plane-local-fleet--scheduler).\n"
                "Broken link: [Bogus](target.md#broken-section).\n"
            )
            candidates = check_docs.scan_target(tmp)
            broken = [c for c in candidates if c["rule_id"] == "doc-broken-anchor"]
            self.assertEqual(len(broken), 1)
            self.assertEqual(broken[0]["reference"], "target.md#broken-section")
            self.assertEqual(broken[0]["path"], "caller.md")

    def test_integration_md_real_tree_anchors_all_resolve(self):
        """All section anchors in the real docs/INTEGRATION.md resolve with 0 broken-anchor candidates."""
        candidates = check_docs.scan_target(FACTORY_ROOT)
        integration_broken = [
            c for c in candidates
            if c["path"] == "docs/INTEGRATION.md" and c["rule_id"] == "doc-broken-anchor"
        ]
        self.assertEqual(integration_broken, [],
                         f"docs/INTEGRATION.md has unexpected broken anchors: {integration_broken}")


class TestLineSuffixIsALocationNotAFilename(unittest.TestCase):
    """`path:line` points INSIDE a file, so the FILE is what has to resolve.

    Motivated by one real false positive found in the agents-kqd3 triage: this
    repository's own docs reference `lib/findings.py:256`, and the scanner reported the
    file as missing because `:256` was treated as part of its name. Unlike the rest of
    that class - which is prose about the reader's project or another project's inventory
    - this one is a genuine defect, so it is fixed (agents-pxx8).

    The suffix is stripped for RESOLUTION only. Two things must stay true, and both are
    pinned below: the recorded reference keeps the suffix the document wrote, and a
    genuinely absent path with a suffix is still reported.
    """

    def _tree(self, tmp: Path, body: str) -> None:
        (tmp / "lib").mkdir(parents=True)
        (tmp / "lib" / "findings.py").write_text("# present\n")
        (tmp / "docs").mkdir()
        (tmp / "docs" / "PLAN.md").write_text(body)

    def test_existing_file_with_a_line_suffix_resolves(self):
        """The real case: `lib/findings.py:256` names a file that exists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            self._tree(tmp, "The binding step lives in `lib/findings.py:256`.\n")
            self.assertEqual(check_docs.scan_target(tmp), [])

    def test_line_and_column_and_range_suffixes_resolve(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            self._tree(tmp, "See `lib/findings.py:256:12` and `lib/findings.py:256-260`.\n")
            self.assertEqual(check_docs.scan_target(tmp), [])

    def test_missing_file_with_a_line_suffix_is_still_reported(self):
        """The other direction: the suffix must not make a real gap disappear."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            self._tree(tmp, "See `no/such/file.py:12` for the binding step.\n")
            candidates = check_docs.scan_target(tmp)
            self.assertEqual([c["rule_id"] for c in candidates], ["doc-missing-file"])
            self.assertEqual([c["reference"] for c in candidates], ["no/such/file.py:12"])

    def test_a_directory_with_a_line_suffix_is_still_reported(self):
        """P1 from the cross-family review: a directory must not satisfy a FILE claim.

        `lib/adapters:42` names a line inside a file. Resolving it against the existing
        DIRECTORY `lib/adapters` silenced a genuinely missing file, which is the one
        outcome this change must never produce.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "lib" / "adapters").mkdir(parents=True)
            (tmp / "lib" / "adapters" / "gha.sh").write_text("# present\n")
            (tmp / "docs").mkdir()
            (tmp / "docs" / "PLAN.md").write_text("See `lib/adapters:42` for the hook.\n")
            candidates = check_docs.scan_target(tmp)
            self.assertEqual([c["rule_id"] for c in candidates], ["doc-missing-file"])
            self.assertEqual([c["reference"] for c in candidates], ["lib/adapters:42"])

    def test_a_trailing_slash_directory_with_a_line_suffix_is_still_reported(self):
        """`lib/:12` is nonsense - a directory cannot hold a line location."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "lib").mkdir()
            (tmp / "docs").mkdir()
            (tmp / "docs" / "PLAN.md").write_text("See `lib/:12` for the binding.\n")
            self.assertFalse(check_docs.path_exists_or_matches(tmp, tmp / "docs", "lib/:12")[0])

    def test_embedded_double_stars_do_not_abort_the_docs_scan(self):
        """agents-xqwmo: **.md is one-level shorthand; only **/ is recursive."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "docs" / "sub").mkdir(parents=True)
            (tmp / "docs" / "A.md").write_text("# a\n")
            (tmp / "docs" / "sub" / "B.md").write_text("# b\n")
            (tmp / "docs" / "PLAN.md").write_text("See `**.md` and `sub/**.md`.\n")
            resolve = check_docs.path_exists_or_matches
            self.assertEqual(resolve(tmp, tmp / "docs", "**.md"), (True, True))
            self.assertEqual(resolve(tmp, tmp, "**.md"), (False, True),
                             "embedded stars must not silently turn into recursive **")
            self.assertEqual(resolve(tmp, tmp / "docs", "sub/**.md"), (True, True))
            self.assertEqual(resolve(tmp, tmp / "docs", "**/*.md"), (True, True))
            self.assertEqual(resolve(tmp, tmp / "docs", "**.missing"), (False, True))
            candidates = check_docs.scan_target(tmp)
            self.assertFalse(any(c.get("reference") in {"**.md", "sub/**.md"} for c in candidates))

    def test_invalid_or_escaping_wildcards_fail_as_unmatched_not_exceptions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "docs").mkdir()
            resolve = check_docs.path_exists_or_matches
            self.assertEqual(resolve(tmp, tmp / "docs", "../*"), (False, True))
            self.assertEqual(resolve(tmp, tmp / "docs", "/etc/*"), (False, True))
            self.assertEqual(resolve(tmp, tmp / "docs", "[" + "*"), (False, True))

    def test_a_clock_like_token_is_not_reduced_to_a_directory_name(self):
        """Fails if the strip is careless: `12:30` must not become the directory `12`.

        Tested against the resolver rather than scan_target, because a clock-like token
        is not extracted as a reference candidate in the first place - the guard exists
        so that a careless strip cannot turn one into an accidental resolution.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "12").mkdir()
            (tmp / "docs").mkdir()
            exists, _ = check_docs.path_exists_or_matches(tmp, tmp / "docs", "12:30")
            self.assertFalse(
                exists,
                "a non-path token with a colon was stripped and resolved away",
            )


class TestTargetPathScope(unittest.TestCase):
    """agents-dxgdy: document references answer only about paths inside the target."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name).resolve()
        self.target = self.base / "target"
        (self.target / "docs" / "sub").mkdir(parents=True)
        (self.target / "agents").mkdir()
        (self.target / "README.md").write_text("# root\n")
        (self.target / "docs" / "README.md").write_text("# docs\n")
        (self.target / "agents" / "x.md").write_text("# x\n")
        (self.base / "external.md").write_text("# outside\nSee `not-in-target.md`.\n")
        (self.target / "link").symlink_to(self.base, target_is_directory=True)
        (self.target / "skills").symlink_to(self.target / "agents", target_is_directory=True)
        (self.target / "external-doc.md").symlink_to(self.base / "external.md")

    def test_parent_absolute_and_symlinked_direct_references_cannot_escape(self):
        resolve = check_docs.path_exists_or_matches
        for ref, doc_dir in (("../external.md", self.target),
                             ("../../external.md", self.target / "docs"),
                             ("link/external.md", self.target),
                             ("external-doc.md", self.target),
                             (str(self.base / "external.md"), self.target),
                             (str(self.base / "external.md") + ":1", self.target)):
            with self.subTest(ref=ref):
                self.assertEqual(resolve(self.target, doc_dir, ref), (False, False))
        self.assertEqual(resolve(self.target, self.target / "docs" / "sub", "../README.md"),
                         (True, False), "doc-relative parent inside the target is valid")
        self.assertEqual(resolve(self.target, self.target, "skills/x.md"), (True, False),
                         "an in-target symlink is valid")
        self.assertEqual(resolve(self.target, self.target, str(self.target / "README.md")),
                         (True, False), "absolute in-target paths remain valid")

    def test_glob_results_through_symlinks_are_bounded_after_matching(self):
        resolve = check_docs.path_exists_or_matches
        self.assertEqual(resolve(self.target, self.target, "link/*.md"), (False, True))
        self.assertEqual(resolve(self.target, self.target, "skills/*.md"), (True, True))
        self.assertEqual(resolve(self.target, self.target, "../*"), (False, True))
        (self.target / "README.md").write_text("See `link/*.md` and `../external.md`.\n")
        refs = {c["reference"] for c in check_docs.scan_target(self.target)}
        self.assertTrue({"link/*.md", "../external.md"} <= refs, refs)
        self.assertNotIn("not-in-target.md", refs,
                         "a symlinked markdown file outside the target must not be read")

    def test_markdown_links_preserve_in_target_parents_and_site_root_paths(self):
        (self.target / "docs" / "PLAN.md").write_text(
            "[ok](../README.md) [site-root](/docs/README.md)\n"
            "[outside](../../external.md) [through-link](../link/external.md)\n")
        links = [c for c in check_docs.scan_target(self.target)
                 if c.get("reference_type") == "file_link"]
        self.assertEqual({c["reference"] for c in links},
                         {"../../external.md", "../link/external.md"})
        self.assertTrue(all(c["rule_id"] in {"doc-broken-link", "doc-deleted-reference"}
                            for c in links))
        self.assertFalse(check_docs.skill_reference_is_checkable(
            self.target, self.target, "link/external.md"),
            "a directory symlink outside the target is not a first-party prefix")


class TestUnreadableDocsAreNotMissingReferences(unittest.TestCase):
    """agents-tlwvy: an I/O failure is not a missing path or a clean partial scan."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.target = Path(tmp.name).resolve()
        (self.target / "docs").mkdir()
        (self.target / "docs" / "PLAN.md").write_text("See `docs/locked/*.md`.\n")

    def test_glob_io_fault_propagates_but_invalid_patterns_do_not(self):
        resolve = check_docs.path_exists_or_matches
        with mock.patch.object(check_docs.os, "scandir", side_effect=PermissionError(errno.EACCES, "denied")):
            with self.assertRaises(PermissionError):
                resolve(self.target, self.target, "docs/*.md")
        for error in (ValueError("invalid pattern"), NotImplementedError("non-relative")):
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(check_docs.os, "scandir", side_effect=error):
                    self.assertEqual(resolve(self.target, self.target, "docs/*.md"), (False, True))

    def test_direct_exists_and_resolve_io_faults_propagate(self):
        resolve = check_docs.path_exists_or_matches
        original_resolve = Path.resolve
        original_exists = Path.exists

        def fail_resolve(path, *args, **kwargs):
            if path.name == "blocked.md":
                raise PermissionError(errno.EACCES, "denied")
            return original_resolve(path, *args, **kwargs)

        def fail_exists(path):
            if path.name == "blocked.md":
                raise PermissionError(errno.EACCES, "denied")
            return original_exists(path)

        with mock.patch.object(Path, "resolve", fail_resolve):
            with self.assertRaises(PermissionError):
                resolve(self.target, self.target, "blocked.md")
        with mock.patch.object(Path, "exists", fail_exists):
            with self.assertRaises(PermissionError):
                resolve(self.target, self.target, "blocked.md")

    def test_symlink_loops_remain_unresolvable_not_io_failures(self):
        (self.target / "a").symlink_to("b")
        (self.target / "b").symlink_to("a")
        self.assertEqual(check_docs.path_exists_or_matches(self.target, self.target, "a/x.md"),
                         (False, False))

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0,
                     "root ignores ordinary file permission bits")
    def test_real_unreadable_subtree_fails_scan_and_glob_loudly(self):
        locked = self.target / "docs" / "locked"
        locked.mkdir()
        (locked / "inner.md").write_text("See `missing.md`.\n")
        locked.chmod(0)
        self.addCleanup(locked.chmod, 0o700)
        if os.access(locked, os.R_OK):
            self.skipTest("filesystem does not enforce test permission bits")
        with self.assertRaises(PermissionError):
            check_docs.scan_target(self.target)
        with self.assertRaises(PermissionError):
            check_docs.path_exists_or_matches(self.target, self.target, "docs/locked/*.md")
        with self.assertRaises(PermissionError):
            check_docs.path_exists_or_matches(self.target, self.target, "docs/locked/inner.md")

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0,
                     "root ignores ordinary file permission bits")
    def test_unreadable_file_cannot_silently_shrink_document_or_source_scan(self):
        doc = self.target / "docs" / "PLAN.md"
        doc.chmod(0)
        self.addCleanup(doc.chmod, 0o600)
        if os.access(doc, os.R_OK):
            self.skipTest("filesystem does not enforce test permission bits")
        with self.assertRaises(PermissionError):
            check_docs.scan_target(self.target)
        doc.chmod(0o600)
        source = self.target / "source.py"
        source.write_text("def parse(): pass\n")
        source.chmod(0)
        self.addCleanup(source.chmod, 0o600)
        with self.assertRaises(PermissionError):
            check_docs.scan_target(self.target)

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0,
                     "root ignores ordinary file permission bits")
    def test_unreadable_root_cannot_produce_an_empty_scan(self):
        self.target.chmod(0)
        self.addCleanup(self.target.chmod, 0o700)
        if os.access(self.target, os.R_OK):
            self.skipTest("filesystem does not enforce test permission bits")
        with self.assertRaises(PermissionError):
            check_docs.scan_target(self.target)


class TestBoundedWildcardTraversal(unittest.TestCase):
    """agents-dp3n2: wildcard matches are target-scoped and report unreadable paths."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.target = Path(tmp.name).resolve() / "target"
        (self.target / "docs").mkdir(parents=True)
        (self.target / "docs" / "PLAN.md").write_text("# Plan\n")

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0,
                     "root ignores ordinary file permission bits")
    def test_wildcards_in_pruned_unreadable_subtree_fail_loudly(self):
        locked = self.target / ".config" / "locked"
        locked.mkdir(parents=True)
        (locked / "inner.md").write_text("# hidden\n")
        locked.chmod(0)
        self.addCleanup(locked.chmod, 0o700)
        if os.access(locked, os.R_OK):
            self.skipTest("filesystem does not enforce test permission bits")
        for pattern in (".config/*/*.md", ".config/**/*.md"):
            with self.subTest(pattern=pattern):
                with self.assertRaises(PermissionError):
                    check_docs.path_exists_or_matches(self.target, self.target, pattern)
        self.assertEqual(check_docs.path_exists_or_matches(self.target, self.target, "docs/*.md"),
                         (True, True), "a disjoint pattern must not scan the locked subtree")
        (self.target / "docs" / "PLAN.md").write_text("See `.config/*/*.md`.\n")
        with self.assertRaises(PermissionError):
            check_docs.scan_target(self.target)

    def test_outside_symlink_is_not_enumerated_and_in_target_symlink_matches(self):
        outside = self.target.parent / "outside"
        (outside / "deep").mkdir(parents=True)
        (outside / "deep" / "x.md").write_text("# outside\n")
        (self.target / "link").symlink_to(outside, target_is_directory=True)
        (self.target / "skills").symlink_to(self.target / "docs", target_is_directory=True)
        actual_scandir = os.scandir
        visited = []

        def watch(path):
            visited.append(Path(path).resolve())
            return actual_scandir(path)

        with mock.patch.object(check_docs.os, "scandir", side_effect=watch):
            self.assertEqual(check_docs.path_exists_or_matches(self.target, self.target,
                                                                "link/**/*.md"), (False, True))
            self.assertEqual(check_docs.path_exists_or_matches(self.target, self.target,
                                                                "skills/*.md"), (True, True))
        self.assertTrue(visited, "the assertion must observe actual directory enumeration")
        self.assertTrue(all(not path.is_relative_to(outside) for path in visited), visited)

    def test_cache_is_per_scan_and_preserves_file_only_location_semantics(self):
        (self.target / "docs" / "onlydir").mkdir()
        (self.target / "docs" / "onlyfile").write_text("x\n")
        cache = {}
        budget = [check_docs._GLOB_MAX_SCANS]
        actual_scandir = os.scandir
        seen = []

        def watch(path):
            seen.append(str(path))
            return actual_scandir(path)

        resolve = check_docs.path_exists_or_matches
        with mock.patch.object(check_docs.os, "scandir", side_effect=watch):
            self.assertEqual(resolve(self.target, self.target, "docs/only*:12",
                                     glob_cache=cache, glob_budget=budget), (True, True))
            first_count = len(seen)
            self.assertGreater(first_count, 0)
            self.assertEqual(resolve(self.target, self.target, "docs/only*:12",
                                     glob_cache=cache, glob_budget=budget), (True, True))
            self.assertEqual(len(seen), first_count, "duplicate lookups should reuse the scan result")
            self.assertEqual(resolve(self.target, self.target, "docs/onlyd*:12",
                                     glob_cache=cache, glob_budget=budget), (False, True))
            self.assertGreater(len(seen), first_count, "a different pattern must be enumerated")
        self.assertEqual(resolve(self.target, self.target, "docs/onlyd*"), (True, True),
                         "a directory matches without a line suffix")

    def test_exhausted_traversal_budget_fails_instead_of_claiming_absence(self):
        with self.assertRaisesRegex(OSError, "traversal budget exceeded"):
            check_docs.path_exists_or_matches(self.target, self.target, "docs/*.md",
                                              glob_budget=[0])

    def test_multiple_recursive_segments_do_not_cycle_and_match(self):
        (self.target / "docs" / "nested").mkdir()
        (self.target / "docs" / "nested" / "x.md").write_text("# nested\n")
        (self.target / "docs" / "back").symlink_to(self.target / "docs", target_is_directory=True)
        for pattern in ("docs/**/*.md", "docs/**/**/*.md", "docs/*/*.md"):
            with self.subTest(pattern=pattern):
                self.assertEqual(check_docs.path_exists_or_matches(self.target, self.target,
                                                                    pattern), (True, True))


class TestPlanFindingsStoreAgreement(unittest.TestCase):
    """PLAN.md's claim about findings/ must match .gitignore's behaviour (agents-flgz, agents-a2tm)."""

    def test_plan_and_gitignore_agree_on_findings_and_suppressions(self):
        plan_path = FACTORY_ROOT / "docs" / "PLAN.md"
        self.assertTrue(plan_path.exists())
        plan_text = plan_path.read_text(encoding="utf-8")

        # Anchor to the Section 7 "Repo layout" code block rather than scanning the whole file (agents-a2tm)
        section_match = re.search(
            r"## 7\. Repo layout\s*\n\s*```text\n(.*?)\n```",
            plan_text,
            re.DOTALL,
        )
        self.assertIsNotNone(section_match, "docs/PLAN.md must contain ## 7. Repo layout code block")
        tree_block = section_match.group(1)

        findings_lines = [
            line for line in tree_block.splitlines()
            if "findings/" in line and "#" in line
        ]
        self.assertEqual(len(findings_lines), 1, "exactly one findings/ entry in §7 directory tree")
        tree_comment = findings_lines[0].split("#", 1)[1].strip()

        # PLAN.md must declare findings are a gitignored evidence trail
        # and suppressions.yaml is committed (agreeing with §5 line 447)
        self.assertIn("suppressions.yaml", tree_comment)
        self.assertIn("gitignored", tree_comment)
        self.assertNotIn("committed: findings +", tree_comment)

        # Check .gitignore behaviour matches the documented contract:
        # findings/*.md must be gitignored (evidence trail, sensitive)
        res_md = subprocess.run(
            ["git", "-C", str(FACTORY_ROOT), "check-ignore", "-q", "--no-index", "findings/candidate.md"],
            capture_output=True,
        )
        self.assertEqual(
            res_md.returncode, 0,
            "findings/*.md must be gitignored per .gitignore and PLAN.md §5",
        )

        # findings/suppressions.yaml must NOT be gitignored (committed register)
        # and must actually be tracked in git index
        res_track = subprocess.run(
            ["git", "-C", str(FACTORY_ROOT), "ls-files", "--error-unmatch", "findings/suppressions.yaml"],
            capture_output=True,
        )
        self.assertEqual(
            res_track.returncode, 0,
            "findings/suppressions.yaml must be tracked in git index per PLAN.md §7",
        )

        res_supp = subprocess.run(
            ["git", "-C", str(FACTORY_ROOT), "check-ignore", "-q", "--no-index", "findings/suppressions.yaml"],
            capture_output=True,
        )
        self.assertNotEqual(
            res_supp.returncode, 0,
            "findings/suppressions.yaml must be committed per .gitignore and PLAN.md §7",
        )


class TestThreatModelSandboxAlignment(unittest.TestCase):
    """Guard rail for agents-j8s5: THREAT_MODEL.md must truthfully describe sandbox mounts and scope."""

    def test_threat_model_does_not_overstate_invisible_paths(self):
        text = (FACTORY_ROOT / "THREAT_MODEL.md").read_text(encoding="utf-8")
        # agents-k8hh: these absence checks were case-sensitive literal substrings, so a reintroduction that a
        # doc naturally produces - the phrase at the START OF A LINE, where a sentence is capitalised - passed
        # the pin. Matching on whitespace-normalised, lowercased text catches the phrase in ANY CASE, at ANY
        # column, and ACROSS A LINE BREAK (markdown reflow splits sentences mid-phrase).
        # BOUNDARY, stated so the pin is a rule rather than a blanket: a PARAPHRASE of the claim (e.g. "all other
        # paths are hidden") is still NOT caught. This closes the phrase, not the class of rewordings.
        normalised = re.sub(r"\s+", " ", text).lower()
        self.assertNotIn("everything else — including all of `$home`", normalised)
        self.assertNotIn("everything else invisible", normalised)
        self.assertNotIn("everything else — including", normalised)
        # Truthfully documents read-only system mounts and tmpfs scratch
        self.assertIn("/usr", text)
        self.assertIn("/etc", text)
        self.assertIn("/dev", text)
        self.assertIn("/tmp", text)


if __name__ == "__main__":
    unittest.main()

