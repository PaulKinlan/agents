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
import subprocess
import sys
import tempfile
import unittest
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


if __name__ == "__main__":
    unittest.main()
