#!/usr/bin/env python3
"""Tests for modern-web scanner canonical Baseline ID recognition and deduplication (agents-08d v2).

Covers all required acceptance criteria:
(a) The fleet cases including temporal-plaindate, anchor-positioning, dialog-closedby.
(b) '/*' inside a string and inside a '//' comment (must NOT disable scanning).
(c) url(https://...) and JS strings containing '//' (candidates preserved).
(d) Real-corpus candidate parity: scanner over /home/exedev/fleet loses ZERO candidates vs base.
(e) String literals containing 'TODO(baseline/...)' are not treated as annotations.
(f) Fallback window boundaries protect against distant line suppression.
(g) Pinned canonical IDs prevent cross-rule over-suppression.
"""

import importlib.machinery
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

SCANNER_SCRIPT = ROOT / "agents" / "modern-web" / "scripts" / "scan_modern_web.py"


def load_scanner_module():
    loader = importlib.machinery.SourceFileLoader("scan_modern_web", str(SCANNER_SCRIPT))
    spec = importlib.util.spec_from_loader("scan_modern_web", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class TestModernWebCanonicalIdRecognition(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        self.mod = load_scanner_module()

    def tearDown(self):
        self.tmp.cleanup()

    def test_fleet_canonical_cases_including_temporal_plaindate(self):
        """[Acceptance 5a] The fleet cases including temporal-plaindate, anchor-positioning,
        and dialog-closedby must be recognized in known_baseline_fallbacks and suppressed."""
        # 1. Anchor positioning fallback
        (self.repo / "anchor.js").write_text("""
// TODO(baseline/anchor-positioning): Remove positionFallback() and getBoundingClientRect() viewport math.
function positionMenu(el) {
  const rect = el.getBoundingClientRect();
  return { top: rect.top, left: rect.left };
}
""", encoding="utf-8")

        # 2. Dialog closedby fallback
        (self.repo / "modal.html").write_text("""
<!-- TODO(baseline/dialog-closedby): Remove shim when closedby reaches Baseline -->
<dialog class="modal-overlay">
  <button>Close</button>
</dialog>
""", encoding="utf-8")

        # 3. Temporal plaindate fallback (fleet standard)
        (self.repo / "dates_plaindate.js").write_text("""
// TODO(baseline/temporal-plaindate): Remove fallback when Baseline Widely Available
function daysBetween(a, b) {
  return new Date(b) - new Date(a);
}
""", encoding="utf-8")

        # 4. Temporal fallback
        (self.repo / "dates_temporal.js").write_text("""
// TODO(baseline/temporal): Remove fallback when Baseline Widely Available
function daysBetween(a, b) {
  return new Date(b) - new Date(a);
}
""", encoding="utf-8")

        result = self.mod.scan_repository(self.repo, retrieve_guides=False)

        self.assertEqual(len(result["candidates"]), 0, f"Expected 0 candidates, got: {result['candidates']}")
        self.assertEqual(len(result["known_baseline_fallbacks"]), 4)

        features_recognized = {f["feature_id"] for f in result["known_baseline_fallbacks"]}
        self.assertEqual(
            features_recognized,
            {"anchor-positioning", "dialog-closedby", "temporal-plaindate", "temporal"}
        )

    def test_block_comment_start_inside_string_and_line_comment_does_not_disable_scanning(self):
        """[Acceptance 5b] '/*' inside a string literal or '//' line comment must NOT disable
        scanning or mask the rest of the file."""
        # Case 1: '/*' inside a string
        (self.repo / "string_with_slash_star.js").write_text("""
const REGEX_LIKE = "/* not a real block comment";
function compute(a, b) {
  return new Date(b) - new Date(a);
}
""", encoding="utf-8")

        # Case 2: '/*' inside a '//' line comment
        (self.repo / "comment_with_slash_star.js").write_text("""
// Note: do not use /* here
function compute2(a, b) {
  return new Date(b) - new Date(a);
}
""", encoding="utf-8")

        result = self.mod.scan_repository(self.repo, retrieve_guides=False)
        # Both files must have their real date math detected as candidates
        self.assertEqual(len(result["candidates"]), 2)
        for c in result["candidates"]:
            self.assertEqual(c["rule_id"], "legacy-date-math-instead-of-temporal")

    def test_url_and_string_containing_double_slash_preserves_candidates(self):
        """[Acceptance 5c] 'url(https://...)' and JS strings containing '//' must not be mistaken
        for line comments and must preserve all real candidates."""
        # CSS with url(https://...) and overflow: hidden
        (self.repo / "style.css").write_text("""
.hero {
  background: url("https://images.example.com/banner.png");
  overflow: hidden;
}
""", encoding="utf-8")

        # JS with https:// URL string and date math
        (self.repo / "api.js").write_text("""
const BASE_URL = "https://api.example.com/v1";
function diff(a, b) {
  return new Date(b) - new Date(a);
}
""", encoding="utf-8")

        result = self.mod.scan_repository(self.repo, retrieve_guides=False)
        self.assertEqual(len(result["candidates"]), 3)
        rules = {c["rule_id"] for c in result["candidates"]}
        self.assertIn("css-background-url-without-image-set", rules)
        self.assertIn("legacy-overflow-hidden-clipping", rules)
        self.assertIn("legacy-date-math-instead-of-temporal", rules)

    def test_real_corpus_candidate_parity(self):
        """[Acceptance 5d] Real-corpus candidate parity: scanning /home/exedev/fleet must lose
        zero candidates vs base."""
        fleet_dir = Path("/home/exedev/fleet")
        if not fleet_dir.exists():
            self.skipTest("/home/exedev/fleet does not exist on this environment")

        result = self.mod.scan_repository(fleet_dir, retrieve_guides=False)
        # On base origin/main, /home/exedev/fleet produces exactly 14 candidates
        candidates = result["candidates"]
        self.assertGreaterEqual(len(candidates), 14, f"Lost candidates on real corpus: got {len(candidates)}")

        rule_paths = {(c["rule_id"], c["path"]) for c in candidates}
        # Verify key baseline findings exist
        self.assertIn(("client-llm-or-nlp-without-builtin-ai", "dashboard/app.js"), rule_paths)
        self.assertIn(("unsafe-innerhtml-without-sanitizer-api", "dashboard/app.js"), rule_paths)
        self.assertIn(("forms-and-tools-missing-webmcp", "dashboard/app.js"), rule_paths)
        self.assertIn(("legacy-custom-modal", "dashboard/index.html"), rule_paths)
        self.assertIn(("navigation-links-without-speculation-rules", "dashboard/index.html"), rule_paths)
        self.assertIn(("client-llm-or-nlp-without-builtin-ai", "watchdog/watchdog.mjs"), rule_paths)

    def test_marker_inside_string_literal_not_treated_as_annotation(self):
        """[Acceptance 5e] A TODO(baseline/...) marker inside a string literal must not suppress genuine findings."""
        (self.repo / "hint.js").write_text("""
const HINT = "TODO(baseline/temporal)";
function daysBetween(a, b) {
  return new Date(b) - new Date(a);
}
""", encoding="utf-8")

        result = self.mod.scan_repository(self.repo, retrieve_guides=False)
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual(result["candidates"][0]["rule_id"], "legacy-date-math-instead-of-temporal")
        self.assertEqual(len(result["known_baseline_fallbacks"]), 0)

    def test_fallback_window_boundaries(self):
        """[Acceptance 5f] Annotation on line 1 must not suppress an unrelated finding 20+ lines down."""
        lines = ["// TODO(baseline/temporal): Immediate fallback function"]
        lines.append("function immediateDiff(a, b) { return new Date(b) - new Date(a); }")
        lines.extend(["", ""])
        lines.extend([f"// filler line {i}" for i in range(4, 25)])
        lines.append("function distantDiff(a, b) { return new Date(b) - new Date(a); }")

        (self.repo / "distant.js").write_text("\n".join(lines), encoding="utf-8")

        result = self.mod.scan_repository(self.repo, retrieve_guides=False)
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual(result["candidates"][0]["rule_id"], "legacy-date-math-instead-of-temporal")
        self.assertEqual(len(result["known_baseline_fallbacks"]), 1)
        self.assertGreater(result["candidates"][0]["line_number"], 20)

    def test_no_cross_rule_over_suppression(self):
        """[Acceptance 5g] Pinned canonical IDs: TODO(baseline/container-queries) must NOT suppress
        legacy-variant-classes-without-style-queries."""
        (self.repo / "style.css").write_text("""
/* TODO(baseline/container-queries): Container size query fallback */
.theme-dark .panel {
  background: #000;
}
""", encoding="utf-8")

        result = self.mod.scan_repository(self.repo, retrieve_guides=False)
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual(result["candidates"][0]["rule_id"], "legacy-variant-classes-without-style-queries")

    def test_inline_trailing_comment_and_jsx_comment_suppression(self):
        """Inline trailing comments and JSX comments must be recognized as annotations and suppress fallbacks."""
        # Inline trailing comment
        (self.repo / "inline_anchor.js").write_text("""
const rect = el.getBoundingClientRect(); // TODO(baseline/anchor-positioning): Remove getBoundingClientRect()
const pos = { top: rect.top };
""", encoding="utf-8")

        # JSX comment above fallback
        (self.repo / "menu.jsx").write_text("""
function Menu() {
  return (
    <div>
      {/* TODO(baseline/dialog-closedby): Fallback modal */}
      <dialog class="modal-overlay">
        <button>Close</button>
      </dialog>
    </div>
  );
}
""", encoding="utf-8")

        result = self.mod.scan_repository(self.repo, retrieve_guides=False)
        self.assertEqual(len(result["candidates"]), 0)
        self.assertEqual(len(result["known_baseline_fallbacks"]), 2)


    def test_pinned_canonical_ids_select_and_scroll_state_queries(self):
        """[agents-gq4 item 1] Verify select-customizable and scroll-state-queries pinned canonical IDs."""
        # 1. select-customizable
        (self.repo / "custom_select.html").write_text("""
<!-- TODO(baseline/select-customizable): Fallback select -->
<div role="listbox">
  <div role="option">Option 1</div>
</div>
""", encoding="utf-8")

        # 2. scroll-state-queries
        (self.repo / "sticky.css").write_text("""
/* TODO(baseline/scroll-state-queries): Container scroll-state fallback */
.is-stuck {
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}
""", encoding="utf-8")

        result = self.mod.scan_repository(self.repo, retrieve_guides=False)
        self.assertEqual(len(result["candidates"]), 0)
        self.assertEqual(len(result["known_baseline_fallbacks"]), 2)
        features = {f["feature_id"] for f in result["known_baseline_fallbacks"]}
        self.assertEqual(features, {"select-customizable", "scroll-state-queries"})

    def test_marker_after_double_slash_inside_string_literal_not_collected(self):
        """[agents-gq4 item 3] A marker after // inside a string literal must not be treated as an annotation."""
        (self.repo / "string_slash_slash.js").write_text("""
const url_hint = 'see https://example.com // TODO(baseline/temporal)';
function compute(a, b) {
  return new Date(b) - new Date(a);
}
""", encoding="utf-8")

        result = self.mod.scan_repository(self.repo, retrieve_guides=False)
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual(result["candidates"][0]["rule_id"], "legacy-date-math-instead-of-temporal")
        self.assertEqual(len(result["known_baseline_fallbacks"]), 0)

    def test_projects_css_uses_container_queries_without_legacy_viewport_media(self):
        """[agents-2yt] projects.css uses container queries on .project-section and .project-list,
        with only page chrome (.site-header) remaining under viewport media queries."""
        projects_css = ROOT / "docs" / "css" / "projects.css"
        self.assertTrue(projects_css.exists())
        content = projects_css.read_text(encoding="utf-8")

        # 1. Verify container contexts are established on hosting wrapper and standalone list
        self.assertRegex(content, r"\.project-section\s*\{[^}]*container-type:\s*inline-size")
        self.assertRegex(content, r"\.project-list\s*\{[^}]*container-type:\s*inline-size")

        # 2. Verify component rules are enclosed under @container blocks
        self.assertIn("@container (max-width: 42rem)", content)
        container_blocks = []
        for match in re.finditer(r"@container\s*\(max-width:\s*42rem\)\s*\{", content):
            start = match.end()
            depth = 1
            pos = start
            while pos < len(content) and depth > 0:
                if content[pos] == "{":
                    depth += 1
                elif content[pos] == "}":
                    depth -= 1
                pos += 1
            container_blocks.append(content[start:pos - 1])

        self.assertGreaterEqual(len(container_blocks), 1)
        container_text = " ".join(container_blocks)
        self.assertIn(".section-heading", container_text)
        self.assertIn(".project-grid", container_text)
        self.assertIn(".project-card--featured", container_text)
        self.assertIn(".project-list a", container_text)

        # 3. Verify exactly ONE viewport-based width query exists outside of @supports fallbacks,
        # and that it styles ONLY page chrome (.site-header)
        no_comments = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)
        no_supports = re.sub(r"@supports[^{]+\{(?:[^{}]+|\{(?:[^{}]+|\{[^{}]*\})*\})*\}", "", no_comments, flags=re.DOTALL)
        viewport_media_matches = re.findall(r"@media\s*\(\s*(?:min|max)-width[^{]+\{([^{}]+(?:\{[^{}]*\}[^{}]*)*)\}", no_supports)
        self.assertEqual(len(viewport_media_matches), 1,
                         f"Expected exactly 1 viewport width @media query, got: {viewport_media_matches}")
        media_body = viewport_media_matches[0]
        self.assertIn(".site-header", media_body)
        self.assertNotIn(".section-heading", media_body)
        self.assertNotIn(".project-grid", media_body)
        self.assertNotIn(".project-card--featured", media_body)
        self.assertNotIn(".project-list", media_body)

        # 4. Scanner produces zero candidate warnings
        res = self.mod.scan_repository(projects_css.parent, retrieve_guides=False)
        candidates = [c for c in res["candidates"] if c["path"].endswith("projects.css")]
        self.assertEqual(len(candidates), 0, f"Expected 0 candidates for projects.css, got {candidates}")

    def test_every_rule_has_pinned_canonical_baseline_ids(self):
        """agents-mw6m requirement 3: 100% of modern-web rules must have pinned canonical Baseline IDs.
        
        A rule added to RULES with no pinned entry in PINNED_RULE_CANONICAL_IDS fails statically,
        preventing silent fallback suppression failures at authoring time.
        """
        for rule in self.mod.RULES:
            rule_id = rule["rule_id"]
            with self.subTest(rule_id=rule_id):
                self.assertIn(
                    rule_id,
                    self.mod.PINNED_RULE_CANONICAL_IDS,
                    f"Rule '{rule_id}' has no declared pinned canonical Baseline IDs"
                )
                self.assertTrue(
                    len(self.mod.PINNED_RULE_CANONICAL_IDS[rule_id]) > 0,
                    f"Rule '{rule_id}' has empty pinned canonical Baseline IDs"
                )

    def test_audio_feed_baseline_fallback_instances_suppressed(self):
        """agents-mw6m requirement 1: audio-feed false-positive instances (anchor, dialog, plain-date).
        
        Verifies that legitimate Baseline fallback annotations matching canonical IDs or aliases
        are properly recognized in known_baseline_fallbacks and suppressed from candidate findings.
        """
        # 1. v9e4: anchor positioning fallback with TODO(baseline/anchor)
        (self.repo / "v9e4_anchor.js").write_text("""
// TODO(baseline/anchor): Remove positionFallback() and getBoundingClientRect() viewport math.
function positionMenu(el) {
  const rect = el.getBoundingClientRect();
  return { top: rect.top, left: rect.left };
}
""", encoding="utf-8")

        # 2. xm8o: dialog closedby shim with TODO(baseline/dialog)
        (self.repo / "xm8o_dialog.html").write_text("""
<!-- TODO(baseline/dialog): Remove shim when closedby reaches Baseline -->
<dialog class="modal-overlay">
  <button>Close</button>
</dialog>
""", encoding="utf-8")

        # 3. mjvz: temporal PlainDate fallback with TODO(baseline/plain-date)
        (self.repo / "mjvz_temporal.js").write_text("""
// TODO(baseline/plain-date): Remove fallback when Baseline Widely Available
function daysBetween(a, b) {
  return new Date(b) - new Date(a);
}
""", encoding="utf-8")

        result = self.mod.scan_repository(self.repo, retrieve_guides=False)

        self.assertEqual(len(result["candidates"]), 0, f"Expected 0 candidates, got: {result['candidates']}")
        self.assertEqual(len(result["known_baseline_fallbacks"]), 3)
        features = {f["feature_id"] for f in result["known_baseline_fallbacks"]}
        self.assertEqual(features, {"anchor", "dialog", "plain-date"})

    def test_unrecognized_baseline_marker_emits_loud_warning_and_candidate(self):
        """agents-mw6m requirement 2: unrecognized marker emits candidate with loud stderr warning.
        
        When a marker in the fallback window does not match pinned canonical IDs, it must NOT
        be silently emitted: emit with a loud warning on stderr and annotate candidate.
        """
        import io
        import contextlib

        (self.repo / "unrecognized.js").write_text("""
// TODO(baseline/nonexistent-feature-xyz): Deliberate fallback for unrecognised feature
function positionMenu(el) {
  const rect = el.getBoundingClientRect();
  return { top: rect.top, left: rect.left };
}
""", encoding="utf-8")

        stderr_buf = io.StringIO()
        with contextlib.redirect_stderr(stderr_buf):
            result = self.mod.scan_repository(self.repo, retrieve_guides=False)

        warning_output = stderr_buf.getvalue()
        self.assertIn("Warning: [modern-web] TODO(baseline/nonexistent-feature-xyz)", warning_output)
        self.assertIn("does not match rule 'legacy-tooltip-popover-anchor' pinned canonical IDs", warning_output)
        self.assertIn("fallback suppression skipped and finding candidate emitted", warning_output)

        self.assertEqual(len(result["candidates"]), 1)
        candidate = result["candidates"][0]
        self.assertEqual(candidate["rule_id"], "legacy-tooltip-popover-anchor")
        self.assertIn("unrecognized_baseline_annotations", candidate)
        self.assertEqual(
            candidate["unrecognized_baseline_annotations"],
            [{"annotation_line": 2, "feature_id": "nonexistent-feature-xyz"}]
        )

    def test_fallback_window_with_intermittent_blank_lines(self):
        """agents-mw6m: multi-line fallback functions with scattered blank lines are within window."""
        (self.repo / "spaced_function.js").write_text("""
// TODO(baseline/temporal-plaindate): Remove fallback

function daysBetween(a, b) {

  // intermediate comment
  const d1 = new Date(a);

  return new Date(b) - new Date(a);
}
""", encoding="utf-8")

        result = self.mod.scan_repository(self.repo, retrieve_guides=False)
        self.assertEqual(len(result["candidates"]), 0)
        self.assertEqual(len(result["known_baseline_fallbacks"]), 1)
        self.assertEqual(result["known_baseline_fallbacks"][0]["feature_id"], "temporal-plaindate")

    def test_arbitrary_namespaced_suffix_marker_does_not_suppress_and_warns(self):
        """agents-mw6m review finding P1: arbitrary namespaced suffix (e.g. not-a-real-feature.anchor).
        
        Arbitrary dot-separated prefixes must not be stripped to match suffix aliases;
        only declared canonical IDs and standard BCD namespaces are accepted.
        """
        import io
        import contextlib

        (self.repo / "bogus_namespace.js").write_text("""
// TODO(baseline/not-a-real-feature.anchor): Bogus namespace should not match
function positionMenu(el) {
  const rect = el.getBoundingClientRect();
  return { top: rect.top, left: rect.left };
}
""", encoding="utf-8")

        stderr_buf = io.StringIO()
        with contextlib.redirect_stderr(stderr_buf):
            result = self.mod.scan_repository(self.repo, retrieve_guides=False)

        warning_output = stderr_buf.getvalue()
        self.assertIn("Warning: [modern-web] TODO(baseline/not-a-real-feature.anchor)", warning_output)
        self.assertIn("does not match rule 'legacy-tooltip-popover-anchor' pinned canonical IDs", warning_output)
        self.assertIn("fallback suppression skipped and finding candidate emitted", warning_output)

        self.assertEqual(len(result["candidates"]), 1)
        candidate = result["candidates"][0]
        self.assertEqual(candidate["rule_id"], "legacy-tooltip-popover-anchor")
        self.assertIn("unrecognized_baseline_annotations", candidate)
        self.assertEqual(
            candidate["unrecognized_baseline_annotations"],
            [{"annotation_line": 2, "feature_id": "not-a-real-feature.anchor"}]
        )


class TestModernWebPrepassNeverExecutesUnpinnedRemoteCode(unittest.TestCase):
    """agents-9y6: the pre-pass must never execute unpinned, mutable third-party code.

    `load_guides_catalog()` used to fall back to `npx --offline -y modern-web-guidance@latest
    list` when the bundled index was missing, and `--retrieve` ran `npx -y
    modern-web-guidance@latest retrieve` outright. Both bypass the factory's own pin policy
    (lib/tool_pins.py pins trusted BINARIES by SHA-256; it cannot pin the `modern-web-guidance`
    PACKAGE, so even a pinned `npx` would still fetch mutable remote code), and this station
    declares `network: false`, so `--retrieve` could only ever time out into a swallowed
    exception. These tests pin the fail-closed behaviour so neither path can come back.
    """

    # A pattern that reliably fires `legacy-viewport-media-for-components`, so the scan under
    # test produces candidates and a non-empty matched_guide_ids.
    FIRING_CSS = "@media (max-width: 600px) { .card { display: flex; } }\n"

    def setUp(self):
        # Patch the REAL process entry points - not `self.mod.subprocess` - BEFORE the module is
        # loaded, so a reintroduced `from subprocess import run` binds the guarded object and any
        # execution attempt raises instead of running. Review finding P2-1 on 9f5a54e: patching
        # the module attribute missed `from subprocess import run` completely.
        for target in (
            "subprocess.Popen", "subprocess.run", "subprocess.call", "subprocess.check_call",
            "subprocess.check_output", "os.system", "os.popen", "os.spawnv", "os.execv",
        ):
            patcher = mock.patch(target, new=self._refuse)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.mod = load_scanner_module()

    @staticmethod
    def _refuse(*args, **kwargs):
        raise AssertionError(f"pre-pass must not execute a process; called with {args!r}")

    def _repo_with_firing_css(self, tmp):
        repo = Path(tmp)
        (repo / "styles.css").write_text(self.FIRING_CSS, encoding="utf-8")
        return repo

    def test_bundled_catalog_loads_all_guides_without_spawning_a_process(self):
        catalog = self.mod.load_guides_catalog()
        self.assertGreaterEqual(len(catalog), 146, f"expected the full 146-guide catalog, got {len(catalog)}")
        self.assertIn("accessibility", catalog)
        self.assertTrue(all("id" in v for v in catalog.values()))

    def test_missing_bundled_catalog_fails_closed_instead_of_fetching(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = self.mod.BUNDLED_GUIDES_INDEX
            self.mod.BUNDLED_GUIDES_INDEX = Path(tmp) / "does-not-exist.json"
            try:
                with self.assertRaises(self.mod.GuidesCatalogUnavailable) as ctx:
                    self.mod.load_guides_catalog()
            finally:
                self.mod.BUNDLED_GUIDES_INDEX = original
        self.assertIn("bundled guide catalog missing", str(ctx.exception))

    def test_corrupt_or_empty_bundled_catalog_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "guides_index.json"
            original = self.mod.BUNDLED_GUIDES_INDEX
            self.mod.BUNDLED_GUIDES_INDEX = bad
            try:
                bad.write_text("{not json", encoding="utf-8")
                with self.assertRaises(self.mod.GuidesCatalogUnavailable):
                    self.mod.load_guides_catalog()
                bad.write_text("[]", encoding="utf-8")
                with self.assertRaises(self.mod.GuidesCatalogUnavailable):
                    self.mod.load_guides_catalog()
            finally:
                self.mod.BUNDLED_GUIDES_INDEX = original

    def test_truncated_bundled_catalog_fails_closed(self):
        """Review finding P2-3: a one-entry catalog must not pass as success."""
        with tempfile.TemporaryDirectory() as tmp:
            truncated = Path(tmp) / "guides_index.json"
            truncated.write_text('[{"id": "accessibility"}]', encoding="utf-8")
            original = self.mod.BUNDLED_GUIDES_INDEX
            self.mod.BUNDLED_GUIDES_INDEX = truncated
            try:
                with self.assertRaises(self.mod.GuidesCatalogUnavailable) as ctx:
                    self.mod.load_guides_catalog()
            finally:
                self.mod.BUNDLED_GUIDES_INDEX = original
        self.assertIn("incomplete", str(ctx.exception))

    def test_retrieve_flag_fails_closed_rather_than_fetching_remote_guides(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._repo_with_firing_css(tmp)
            with self.assertRaises(self.mod.UnpinnedExecutionRefused) as ctx:
                self.mod.scan_repository(repo, retrieve_guides=True)
        message = str(ctx.exception)
        self.assertIn("unpinned", message)
        self.assertIn("tm-unpinned-third-party-npx-prepass", message)

    def test_scan_still_works_with_the_bundled_catalog_present(self):
        """The normal path must be unaffected: catalog present -> full scan, no process."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._repo_with_firing_css(tmp)
            res = self.mod.scan_repository(repo, retrieve_guides=False)
        self.assertGreaterEqual(res["catalog_total_guides"], 146)
        self.assertEqual(res["retrieved_guides"], {})
        self.assertGreaterEqual(len(res["candidates"]), 1, "expected the viewport-media rule to fire")
        self.assertTrue(res["matched_guide_ids"], "a firing candidate must map to guide ids")

    def test_report_never_carries_an_instruction_to_run_npx(self):
        """The output is the engine's instruction sheet, so assert on the product."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = self._repo_with_firing_css(tmp)
            res = self.mod.scan_repository(repo, retrieve_guides=False)
        blob = json.dumps(res)
        self.assertNotIn("npx", blob, "the report must not tell the engine to run npx")
        self.assertNotIn("@latest", blob, "the report must not name a mutable package tag")
        self.assertNotIn("retrieve_cmd", blob)
        refs = [r for c in res["candidates"] for r in c["modern_web_guidance_refs"]]
        self.assertTrue(refs, "expected guide refs on a firing candidate")
        for ref in refs:
            self.assertTrue(ref["guide_index_ref"].startswith("guides_index.json#"), ref)
            self.assertIn("category", ref)

    def test_the_process_guard_would_catch_a_reintroduction(self):
        """Meta-test (review P2-1): a guard that cannot fail is not a guard. Reintroduce
        `from subprocess import run` in a scratch module and require that calling it raises."""
        with tempfile.TemporaryDirectory() as tmp:
            scratch = Path(tmp) / "reintroduced.py"
            scratch.write_text(
                "from subprocess import run\n"
                "def go():\n"
                "    return run(['npx', '--version'])\n",
                encoding="utf-8",
            )
            loader = importlib.machinery.SourceFileLoader("reintroduced", str(scratch))
            spec = importlib.util.spec_from_loader("reintroduced", loader)
            mod = importlib.util.module_from_spec(spec)
            loader.exec_module(mod)
            with self.assertRaises(AssertionError):
                mod.go()

    def test_module_has_no_process_spawning_or_command_literals(self):
        """Source-level guard: no process module, and no command-shaped npx literal."""
        import ast as _ast
        source = SCANNER_SCRIPT.read_text(encoding="utf-8")
        tree = _ast.parse(source)
        forbidden_modules = ("subprocess", "pty", "multiprocessing")
        from_os_forbidden = {"system", "popen", "spawnv", "spawnl", "spawnvp", "spawnve",
                             "execv", "execve", "execvp", "execvpe"}
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Import):
                for alias in node.names:
                    self.assertNotIn(alias.name, forbidden_modules,
                                     f"forbidden import at line {node.lineno}")
            if isinstance(node, _ast.ImportFrom):
                # Review finding P2-1: `from subprocess import run` puts 'run' in node.names and
                # never the module, so the module must be checked explicitly.
                self.assertNotIn(getattr(node, "module", None), forbidden_modules,
                                 f"forbidden import-from at line {node.lineno}")
                if getattr(node, "module", None) == "os":
                    for alias in node.names:
                        self.assertNotIn(alias.name, from_os_forbidden,
                                         f"forbidden os import at line {node.lineno}")
            if isinstance(node, _ast.Name):
                self.assertNotIn(node.id, forbidden_modules,
                                 f"forbidden name at line {node.lineno}")
            if isinstance(node, _ast.Constant) and isinstance(node.value, str):
                self.assertFalse(re.match(r"^\s*(?:npx|npm)\b", node.value),
                                 f"command-shaped literal at line {node.lineno}: {node.value!r}")


if __name__ == "__main__":
    unittest.main()
