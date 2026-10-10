#!/usr/bin/env python3
"""Deterministic Pre-Pass Scanner for Modern Web Guidance (agents/modern-web/scripts/scan_modern_web.py)

Audits HTML, CSS, SCSS, JS, TS, JSX, TSX, Vue, and Svelte files against the full
146-guide `modern-web-guidance` catalog across all 14 categories:
  - accessibility (2 guides)
  - built-in-ai (4 guides)
  - css (15 guides)
  - forms (16 guides)
  - html (1 guide)
  - js (8 guides)
  - performance (25 guides)
  - privacy (1 guide)
  - security (8 guides)
  - ui-atoms (10 guides)
  - ui-behaviors (29 guides)
  - ui-components (7 guides)
  - visual-design (17 guides)
  - webmcp (3 guides)

Each rule deterministically detects legacy frontend patterns or missing Baseline Web
Platform capabilities and maps them directly to the authoritative guide IDs in
`modern-web-guidance`. The catalog of those IDs is **bundled in this repository**
(`scripts/guides_index.json`, all 146 guides) and is the only source used: the scanner never
invokes the guidance package over the network, because that would mean executing unpinned,
mutable third-party code (`@latest`) from a pre-pass (threat-model
`tm-unpinned-third-party-npx-prepass`; the pin policy is lib/tool_pins.py).
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

FACTORY_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(FACTORY_ROOT) not in sys.path:
    sys.path.insert(0, str(FACTORY_ROOT))

from lib.candidate_identity import assign_candidate_ids, artefact_scheme_fields  # noqa: E402
from lib.line_numbers import line_number_sort_key  # noqa: E402
from lib.redaction import emit_station_result  # noqa: E402

try:
    from lib.exclusions import DEFAULT_IGNORE_DIRS as IGNORE_DIRS
except ImportError:
    IGNORE_DIRS = {
        ".git", "node_modules", "vendor", "dist", "build", ".next", ".nuxt",
        "coverage", ".venv", "venv", "__pycache__", ".beads", "runs", "findings"
    }

WEB_EXTS = {".html", ".htm", ".css", ".scss", ".js", ".mjs", ".ts", ".jsx", ".tsx", ".vue", ".svelte"}
MARKUP_EXTS = {".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte"}
STYLE_EXTS = {".css", ".scss", ".html", ".htm", ".vue", ".svelte"}
SCRIPT_EXTS = {".js", ".mjs", ".ts", ".jsx", ".tsx", ".vue", ".svelte"}

SCRIPT_DIR = Path(__file__).resolve().parent
BUNDLED_GUIDES_INDEX = SCRIPT_DIR / "guides_index.json"

# The bundled index is this scanner's ground truth: the repository ships all 146 guides and
# tests/test_factory_core.py asserts that >= 146 are mapped to rules, so a smaller catalog
# means the file was truncated or corrupted. Review finding P2-3 on 9f5a54e: a one-entry JSON
# satisfied the old "not catalog" check, so truncation passed as success.
EXPECTED_MIN_GUIDES = 146


class GuidesCatalogUnavailable(RuntimeError):
    """The bundled 146-guide catalog is missing, unreadable or empty (fail closed)."""


class UnpinnedExecutionRefused(RuntimeError):
    """The pre-pass was asked to execute unpinned third-party code over the network."""

# Regular expression matching baseline TODO annotations inside comments (agents-08d):
# Matches TODO(baseline/<feature-id>) when preceded by a comment delimiter:
# //, /*, {/*, <!--, or * (multi-line comment lines).
BASELINE_COMMENT_RE = re.compile(
    r"(?://|/\*|\{/\*|<!--|\*)\s*TODO\s*\(\s*baseline/([a-zA-Z0-9_.-]+)\s*\)",
    re.IGNORECASE
)

# Pinned mapping from rule_id to canonical web-features IDs / BCD keys (agents-08d).
# Strict, explicit allowlist — no fuzzy token derivation or startswith matching.
PINNED_RULE_CANONICAL_IDS: Dict[str, Set[str]] = {
    # Popover API & CSS Anchor Positioning
    "legacy-tooltip-popover-anchor": {
        "anchor-positioning",
        "css-anchor-positioning",
        "popover",
    },
    # Dialog closedby
    "legacy-custom-modal": {
        "dialog-closedby",
        "closedby",
        "html.elements.dialog.closedby",
        "api.htmldialogelement.closedby",
    },
    # Temporal API (Date math)
    "legacy-date-math-instead-of-temporal": {
        "temporal",
        "temporal-plaindate",
        "plaindate",
        "temporal-instant",
        "temporal-zoneddatetime",
        "temporal-duration",
        "javascript.builtins.temporal",
    },
    # Scheduler API (yield / postTask)
    "legacy-settimeout-zero-task-yielding": {
        "scheduler-yield",
        "scheduler.yield",
        "api.scheduler.yield",
        "scheduler-api",
    },
    # View Transitions API
    "legacy-view-swap-without-view-transitions": {
        "view-transitions",
        "view-transition",
        "startviewtransition",
    },
    # Atomic DOM reparenting (moveBefore)
    "dom-reparenting-without-movebefore": {
        "movebefore",
        "movebefore()",
        "api.node.movebefore",
    },
    # Scroll snap & events
    "scroll-snap-without-snap-events-or-initial-target": {
        "scroll-snap",
        "scrollsnapchange",
        "scroll-initial-target",
    },
    # Native form controls accent-color
    "custom-checkbox-radio-without-accent-color": {
        "accent-color",
    },
    # Invoker Commands (commandfor)
    "imperative-button-toggle-without-invoker-commands": {
        "invoker-commands",
        "commandfor",
    },
    # Beacon fetchLater
    "legacy-unload-beacon-instead-of-fetchlater": {
        "fetchlater",
        "api.fetchlater",
    },
    # Starting style & discrete display animations
    "discrete-display-animation-without-starting-style": {
        "starting-style",
        "@starting-style",
        "transition-behavior",
    },
    # Native scrollend event
    "debounced-scroll-instead-of-scrollend": {
        "scrollend",
    },
    # Text wrap balance / pretty
    "headings-missing-text-wrap-balance-or-pretty": {
        "text-wrap",
        "text-wrap-balance",
        "text-wrap-pretty",
    },
    # Form validation pseudo-classes (:user-valid / :user-invalid)
    "legacy-form-validation-classes": {
        "user-valid",
        "user-invalid",
        ":user-valid",
        ":user-invalid",
    },
    "a11y-aria-invalid-unsynced": {
        "user-valid",
        "user-invalid",
        ":user-valid",
        ":user-invalid",
    },
    # Relational pseudo-classes (:has / :not)
    "legacy-js-parent-or-child-state-styling": {
        "has",
        ":has()",
    },
    # Container Size & Style Queries
    "legacy-viewport-media-for-components": {
        "container-queries",
        "@container",
    },
    "legacy-variant-classes-without-style-queries": {
        "container-style-queries",
        "style-queries",
    },
    # Light-dark color function
    "dark-mode-media-without-light-dark": {
        "light-dark",
        "light-dark()",
    },
    # Customizable <select> (appearance: base-select)
    "legacy-custom-select-dropdown": {
        "select-customizable",
        "customizable-select",
        "appearance: base-select",
    },
    # Container Scroll-State Queries (sticky header / scroll shadow)
    "sticky-or-scroll-shadow-js-instead-of-scroll-state-queries": {
        "scroll-state-queries",
        "container-scroll-state-queries",
        "scroll-state",
    },
    # Field-sizing content
    "legacy-textarea-auto-resize-js": {
        "field-sizing",
        "field-sizing-content",
    },
    # Content-visibility
    "missing-content-visibility-on-sections": {
        "content-visibility",
        "content-visibility-auto",
    },
    # Fetchpriority
    "missing-fetchpriority-or-lazy-img": {
        "fetchpriority",
        "fetchpriority-high",
    },
    # Speculation Rules
    "navigation-links-without-speculation-rules": {
        "speculation-rules",
        "speculationrules",
    },
    # Interest Invokers
    "hover-focus-tooltip-without-interest-invokers": {
        "interest-invokers",
        "interestfor",
    },
    # Linear easing function
    "cubic-bezier-spring-instead-of-linear-easing": {
        "linear-easing",
        "linear-easing-function",
        "linear()",
    },
    # Scroll-driven animations
    "legacy-scroll-listener-animation": {
        "scroll-driven-animations",
        "animation-timeline",
    },
    # Custom Highlight API
    "dom-wrapping-text-highlight-instead-of-custom-highlights": {
        "custom-highlights",
        "custom-highlight-api",
        "css.highlights",
    },
    # CSS Masks
    "overlay-fade-or-cutout-without-css-masks": {
        "masks",
        "css-masks",
        "masking",
        "mask-image",
    },
    # Font-size-adjust
    "font-face-missing-font-size-adjust": {
        "font-size-adjust",
    },
    # Sanitizer API
    "unsafe-innerhtml-without-sanitizer-api": {
        "sanitizer-api",
        "sethtml",
        "element.sethtml",
    },
    # WebAuthn & Signal API
    "auth-flow-without-passkeys-or-signal-api": {
        "passkeys",
        "webauthn",
        "signal-api",
    },
    # Long Animation Frames (LoAF)
    "performance-observer-missing-loaf-inp": {
        "long-animation-frames",
        "loaf",
    },
    # Interpolate-size & calc-size
    "legacy-max-height-intrinsic-animation": {
        "interpolate-size",
        "calc-size",
        "calc-size()",
    },
}


def normalize_feature_key(s: str) -> str:
    return s.lower().strip()


def rule_matches_baseline_feature(rule_id: str, feature_id: str) -> bool:
    """Check if a rule matches a canonical feature ID via pinned allowlist lookup."""
    f_clean = normalize_feature_key(feature_id)
    candidate_keys = {f_clean}
    if "." in f_clean:
        parts = f_clean.split(".")
        candidate_keys.add(parts[-1])
        if len(parts) >= 2:
            candidate_keys.add(f"{parts[-2]}-{parts[-1]}")
            candidate_keys.add(f"{parts[-2]}.{parts[-1]}")
            no_ns = [p for p in parts if p not in ("api", "html", "javascript", "builtins", "elements")]
            if no_ns:
                candidate_keys.add("-".join(no_ns))
    alt_keys = {re.sub(r"[^a-z0-9]+", "-", k).strip("-") for k in candidate_keys}
    all_keys = candidate_keys | alt_keys
    rule_keys = PINNED_RULE_CANONICAL_IDS.get(rule_id, set())
    return bool(all_keys & rule_keys)


def is_in_string_literal(line: str, pos: int) -> bool:
    """Check if character index `pos` in `line` is inside a string literal (quoted region)."""
    in_quote = None
    escaped = False
    for ch in line[:pos]:
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if in_quote:
            if ch == in_quote:
                in_quote = None
        else:
            if ch in ('"', "'", '`'):
                in_quote = ch
    return in_quote is not None


def extract_baseline_annotations(lines: List[str]) -> List[Tuple[int, str]]:
    """Extract (line_number, feature_id) annotations from comment contexts."""
    annotations: List[Tuple[int, str]] = []
    for idx, line in enumerate(lines, start=1):
        for m in BASELINE_COMMENT_RE.finditer(line):
            # Verify the comment delimiter is not inside a string literal (agents-gq4)
            if is_in_string_literal(line, m.start()):
                continue
            annotations.append((idx, m.group(1).strip()))
    return annotations


def is_in_fallback_window(annot_line: int, line_no: int, lines: List[str], window_before: int = 3, window_after: int = 15) -> bool:
    """Determine if line_no is part of the fallback implementation adjacent to annot_line."""
    if line_no == annot_line:
        return True
    if not (annot_line - window_before <= line_no <= annot_line + window_after):
        return False
    if line_no > annot_line:
        gap_lines = lines[annot_line:line_no - 1]
    else:
        gap_lines = lines[line_no:annot_line - 1]
    blank_count = sum(1 for gl in gap_lines if not gl.strip())
    if blank_count >= 2:
        return False
    return True


# ---------------------------------------------------------------------------
# Comprehensive Rule Matrix mapping 100% of the 146 Modern Web Guidance guides
# ---------------------------------------------------------------------------
RULES: List[Dict[str, Any]] = [
    # === 1. ACCESSIBILITY & FORM VALIDATION (accessibility, forms, css) ===
    {
        "rule_id": "a11y-aria-invalid-unsynced",
        "title": "Manual aria-invalid Without :user-invalid Synchronization",
        "exts": MARKUP_EXTS | SCRIPT_EXTS,
        "pattern": re.compile(r"aria-invalid\s*=|setAttribute\(\s*['\"]aria-invalid['\"]", re.IGNORECASE),
        "exclude_if": re.compile(r":user-invalid|matches\(\s*['\"]:user-invalid['\"]\)", re.IGNORECASE),
        "modern_feature": ":user-valid and :user-invalid synchronized with aria-invalid",
        "guide_ids": ["accessible-error-announcement", "accessibility"],
        "severity": "medium",
        "rationale": "Synchronize programmatic aria-invalid state with :user-invalid so assistive technology announces errors only after user interaction."
    },
    {
        "rule_id": "legacy-form-validation-classes",
        "title": "Premature :invalid or Custom JS Validation Classes Instead of :user-valid / :user-invalid",
        "exts": STYLE_EXTS | MARKUP_EXTS | SCRIPT_EXTS,
        "pattern": re.compile(r"(?:\.(?:is-invalid|is-valid|input-error|field-touched|has-error)\b|(?<!user):invalid\b)", re.IGNORECASE),
        "exclude_if": re.compile(r":user-(?:invalid|valid)", re.IGNORECASE),
        "modern_feature": "CSS :user-valid and :user-invalid pseudo-classes + :has(:user-invalid)",
        "guide_ids": [
            "validate-input-after-interaction",
            "required-field-feedback",
            "select-menu-interaction",
            "style-parent-with-has"
        ],
        "severity": "medium",
        "rationale": ":invalid matches before the user interacts with a required field; :user-invalid and :user-valid fire only after interaction, and parent fieldsets/labels can be styled via :has(:user-invalid)."
    },
    {
        "rule_id": "non-semantic-interactive-markup",
        "title": "Non-Semantic Interactive Element (<div/span onClick>) Instead of Native HTML Controls",
        "exts": MARKUP_EXTS,
        "pattern": re.compile(r"<(?:div|span)\b[^>]*(?:onClick|onclick|@click|v-on:click)[^>]*>", re.IGNORECASE),
        "exclude_if": re.compile(r"<button\b", re.IGNORECASE),
        "modern_feature": "Semantic HTML (<button>, <dialog>, <details>, <search>)",
        "guide_ids": ["accessibility", "html"],
        "severity": "medium",
        "rationale": "Interactive <div> and <span> elements lack native keyboard focus, Enter/Space activation, and ARIA semantics provided by <button> and native HTML elements."
    },

    # === 2. BUILT-IN AI (built-in-ai: 4 guides) ===
    {
        "rule_id": "client-llm-or-nlp-without-builtin-ai",
        "title": "Client-Side AI / Summarization / Translation / Language Detection Without Built-in Web AI APIs",
        "exts": SCRIPT_EXTS,
        "pattern": re.compile(r"(?:openai|generativelanguage\.googleapis|anthropic|/v1/chat/completions|summarizeText|translateText|detectLanguage)", re.IGNORECASE),
        "exclude_if": re.compile(r"\b(?:LanguageModel|Summarizer|Translator|LanguageDetector)\b"),
        "modern_feature": "Built-in Web AI APIs (LanguageModel, Summarizer, Translator, LanguageDetector)",
        "guide_ids": ["language-model", "summarizer", "translator", "language-detection"],
        "severity": "low",
        "rationale": "Browser Built-in AI APIs (Prompt API LanguageModel, Summarizer, Translator, LanguageDetector) allow zero-cost, privacy-preserving on-device inference as primary or progressive enhancement."
    },

    # === 3. CSS ARCHITECTURE, LAYOUT & SIZING (css: 15 guides) ===
    {
        "rule_id": "legacy-max-height-intrinsic-animation",
        "title": "Animating max-height or JS scrollHeight Instead of interpolate-size & calc-size()",
        "exts": STYLE_EXTS | SCRIPT_EXTS,
        "pattern": re.compile(r"(?:transition\s*:[^;]*\bmax-height\b|style\.(?:height|maxHeight)\s*=\s*[^;]*scrollHeight)", re.IGNORECASE),
        "exclude_if": re.compile(r"\b(?:interpolate-size|calc-size\()", re.IGNORECASE),
        "modern_feature": "CSS interpolate-size: allow-keywords and calc-size()",
        "guide_ids": ["animate-to-intrinsic-sizes", "calculate-with-intrinsic-sizes"],
        "severity": "medium",
        "rationale": "interpolate-size: allow-keywords and calc-size() let the browser smoothly animate to/from height: auto or max-content without fragile max-height: 9999px hacks or JS scrollHeight reads."
    },
    {
        "rule_id": "legacy-js-parent-or-child-state-styling",
        "title": "Imperative DOM Parent/Child Traversal for Styling Instead of CSS :has() and :not()",
        "exts": SCRIPT_EXTS,
        "pattern": re.compile(r"(?:parentElement|parentNode|closest\([^)]+\))\s*\.\s*classList\.(?:add|remove|toggle)", re.IGNORECASE),
        "exclude_if": None,
        "modern_feature": "CSS :has() and :not() relational pseudo-classes",
        "guide_ids": ["child-state-based-styling", "content-based-styling", "style-parent-with-has"],
        "severity": "low",
        "rationale": "CSS :has() styles parent or container layouts declaratively based on child presence (e.g. :has(img)) or child state (e.g. :has(input:checked)) without JS DOM mutations."
    },
    {
        "rule_id": "legacy-viewport-media-for-components",
        "title": "Viewport @media Width Queries Used Without CSS Container Queries",
        "exts": {".css", ".scss"},
        "pattern": re.compile(r"@media\s*\(\s*(?:min|max)-width\s*:\s*\d+(?:px|rem|em)\s*\)", re.IGNORECASE),
        "exclude_if": re.compile(r"@container\b|container-type\s*:", re.IGNORECASE),
        "modern_feature": "CSS Container Queries (container-type: inline-size; @container; cqi units)",
        "guide_ids": ["size-aware-styling", "fluid-scaling", "css-layout", "css"],
        "severity": "low",
        "rationale": "Components and fluid typography should scale and adapt to their parent container's inline-size (@container, clamp() with cqi) rather than fixed viewport breakpoints."
    },
    {
        "rule_id": "legacy-variant-classes-without-style-queries",
        "title": "Repeated Theme / Density Variant Selectors Without Container Style Queries",
        "exts": {".css", ".scss"},
        "pattern": re.compile(r"\.(?:theme-(?:dark|light|compact|cozy)|density-(?:compact|comfortable|spacious)|variant-(?:primary|secondary))\s+\.", re.IGNORECASE),
        "exclude_if": re.compile(r"@container\s+style\(", re.IGNORECASE),
        "modern_feature": "CSS Container Style Queries (@container style(--density: compact))",
        "guide_ids": ["design-token-reactivity", "usage-aware-component-variations"],
        "severity": "low",
        "rationale": "Container style queries allow components to react directly to semantic custom properties (--density, --variant) without prop-drilling utility classes."
    },
    {
        "rule_id": "legacy-nth-child-stagger-delays",
        "title": "Hardcoded :nth-child(N) Animation Stagger Delays Instead of sibling-index() / sibling-count()",
        "exts": {".css", ".scss"},
        "pattern": re.compile(r":nth-child\(\d+\)\s*\{[^}]*(?:animation-delay|transition-delay)\s*:", re.IGNORECASE),
        "exclude_if": re.compile(r"\bsibling-(?:index|count)\(\)", re.IGNORECASE),
        "modern_feature": "CSS sibling-index() and sibling-count() functions",
        "guide_ids": ["dynamic-sibling-animations", "dynamic-sibling-styling"],
        "severity": "low",
        "rationale": "sibling-index() and sibling-count() compute stagger delays and radial/spectral layouts dynamically for any number of children without hardcoded :nth-child(1..N) blocks."
    },
    {
        "rule_id": "legacy-compound-transform-property",
        "title": "Compound transform: translate/rotate/scale Instead of Individual Transform Properties",
        "exts": {".css", ".scss"},
        "pattern": re.compile(r"\btransform\s*:\s*(?:translate(?:3d|X|Y)?|scale|rotate)\([^;]+\)\s+(?:translate|scale|rotate)", re.IGNORECASE),
        "exclude_if": re.compile(r"\b(?:translate|rotate|scale)\s*:", re.IGNORECASE),
        "modern_feature": "Individual CSS transform properties (translate, rotate, scale)",
        "guide_ids": ["individual-transform-properties"],
        "severity": "low",
        "rationale": "Individual translate, rotate, and scale properties compose cleanly across hover/active states and keyframes without overwriting each other."
    },
    {
        "rule_id": "legacy-overflow-hidden-clipping",
        "title": "overflow: hidden Used Where overflow: clip Avoids Scroll Container Creation",
        "exts": {".css", ".scss"},
        "pattern": re.compile(r"\boverflow\s*:\s*hidden\b", re.IGNORECASE),
        "exclude_if": re.compile(r"\boverflow(?:-x|-y)?\s*:\s*clip\b|\boverflow-clip-margin\b", re.IGNORECASE),
        "modern_feature": "CSS overflow: clip and overflow-clip-margin",
        "guide_ids": ["overflow-clipping-control"],
        "severity": "low",
        "rationale": "overflow: clip prevents programmatic scrolling overhead, allows single-axis clipping without breaking sticky descendants, and supports overflow-clip-margin for shadows/outlines."
    },
    {
        "rule_id": "repeated-complex-css-calculations",
        "title": "Repeated Complex CSS calc()/color-mix() Expressions Without CSS @function",
        "exts": {".css", ".scss"},
        "pattern": re.compile(r"(?:calc\([^;]{25,}\)|color-mix\([^;]{20,}\))[\s\S]{1,400}(?:calc\([^;]{25,}\)|color-mix\([^;]{20,}\))", re.IGNORECASE),
        "exclude_if": re.compile(r"@function\s+--", re.IGNORECASE),
        "modern_feature": "CSS Custom Functions (@function --name())",
        "guide_ids": ["reduce-style-repetition"],
        "severity": "low",
        "rationale": "CSS @function encapsulates parameterized styling calculations into reusable native CSS functions."
    },

    # === 4. FORMS (forms: 16 guides) ===
    {
        "rule_id": "legacy-custom-select-dropdown",
        "title": "Custom JS Select / Combobox Instead of Customizable <select> (appearance: base-select)",
        "exts": MARKUP_EXTS | STYLE_EXTS,
        "pattern": re.compile(r'(?:role=["\'](?:listbox|combobox)["\']|class=["\'][^"\']*\b(?:custom-select|select-dropdown|select-picker)\b)', re.IGNORECASE),
        "exclude_if": re.compile(r"appearance\s*:\s*base-select|::picker\(select\)", re.IGNORECASE),
        "modern_feature": "Customizable <select> (appearance: base-select, ::picker(select), <selectedcontent>)",
        "guide_ids": [
            "branded-select-styling",
            "animated-select-picker",
            "custom-select-picker-layouts",
            "rich-media-picker",
            "forms"
        ],
        "severity": "medium",
        "rationale": "Customizable <select> with appearance: base-select enables rich HTML inside <option>, animated ::picker(select) popovers, and custom grid layouts while keeping native accessibility."
    },
    {
        "rule_id": "legacy-textarea-auto-resize-js",
        "title": "JavaScript scrollHeight Auto-Resizing on Input/Textarea Instead of field-sizing: content",
        "exts": SCRIPT_EXTS | STYLE_EXTS,
        "pattern": re.compile(r"textarea[\s\S]{0,160}\.style\.height\s*=\s*[^;]*scrollHeight|oninput=[\"'][^\"']*scrollHeight", re.IGNORECASE),
        "exclude_if": re.compile(r"field-sizing\s*:\s*content", re.IGNORECASE),
        "modern_feature": "CSS field-sizing: content",
        "guide_ids": ["form-fields-automatically-fit-contents"],
        "severity": "medium",
        "rationale": "field-sizing: content allows <textarea>, <input>, and <select> elements to automatically grow and shrink to fit user input with a single CSS property."
    },
    {
        "rule_id": "textarea-enter-submit-missing-ime-check",
        "title": "Enter-to-Submit Keydown Handler Missing IME isComposing Guard",
        "exts": SCRIPT_EXTS,
        "pattern": re.compile(r"key\s*===\s*['\"]Enter['\"](?![\s\S]{0,200}\bisComposing\b)", re.IGNORECASE),
        "exclude_if": re.compile(r"\bisComposing\b"),
        "modern_feature": "KeyboardEvent.isComposing guard before form.requestSubmit()",
        "guide_ids": ["ime-safe-enter-submit"],
        "severity": "high",
        "rationale": "Intercepting Enter on a <textarea> without checking event.isComposing prematurely submits incomplete text for CJK/IME users confirming character composition."
    },
    {
        "rule_id": "forms-missing-autofill-inputmode-hints",
        "title": "Auth / Address / Payment Inputs Missing autocomplete, inputmode, enterkeyhint, or :autofill",
        "exts": MARKUP_EXTS | STYLE_EXTS,
        "pattern": re.compile(r"(?:<input\b(?![^>]*\bautocomplete=)[^>]*\b(?:type=['\"](?:email|tel|password)['\"]|name=['\"](?:email|phone|postal|cc-|card|password)[^'\"]*['\"])|:-webkit-autofill\b)", re.IGNORECASE),
        "exclude_if": re.compile(r":autofill\b", re.IGNORECASE),
        "modern_feature": "Standard autocomplete tokens, inputmode, enterkeyhint, and CSS :autofill",
        "guide_ids": [
            "autofill-sign-in-form",
            "autofill-sign-up-form",
            "autofill-address-form",
            "autofill-payment-form",
            "autofill-highlight-inputs",
            "forms"
        ],
        "severity": "medium",
        "rationale": "Proper autocomplete tokens, inputmode, enterkeyhint, and standard :autofill CSS ensure password managers, autofill, and mobile virtual keyboards work reliably."
    },
    {
        "rule_id": "custom-checkbox-radio-without-accent-color",
        "title": "Custom Checkbox / Radio / Range Styling Without CSS accent-color",
        "exts": STYLE_EXTS,
        "pattern": re.compile(r"input\[\s*type\s*=\s*['\"]?(?:checkbox|radio|range)['\"]?\s*\]\s*\{[^}]*appearance\s*:\s*none", re.IGNORECASE),
        "exclude_if": re.compile(r"\baccent-color\s*:", re.IGNORECASE),
        "modern_feature": "CSS accent-color property",
        "guide_ids": ["brand-consistent-forms"],
        "severity": "low",
        "rationale": "accent-color tints native checkboxes, radio buttons, range sliders, and <progress> bars to match brand colors in one line while preserving platform accessibility."
    },

    # === 5. JAVASCRIPT & TEMPORAL (js: 8 guides + sequence-distributed-events) ===
    {
        "rule_id": "legacy-date-math-instead-of-temporal",
        "title": "Legacy Date Object Math / Timezone Hacks Instead of Temporal API",
        "exts": SCRIPT_EXTS,
        "pattern": re.compile(r"(?:\bnew\s+Date\([^)]+\)\s*-\s*new\s+Date|\bgetTimezoneOffset\(\)|\b86400000\b|\b3600000\b|\bfrom\s+['\"](?:moment|dayjs|date-fns)['\"])"),
        "exclude_if": re.compile(r"\bTemporal\."),
        "modern_feature": "Temporal API (Temporal.Now, PlainDate, ZonedDateTime, Duration, Instant)",
        "guide_ids": [
            "calculate-event-differentials",
            "capture-location-agnostic-data",
            "coordinate-global-events",
            "manage-recurring-intervals",
            "model-partial-time-concepts",
            "stabilize-reactive-state",
            "support-global-calendar-systems",
            "sequence-distributed-events"
        ],
        "severity": "low",
        "rationale": "Legacy Date is mutable, lacks time-zone/DST-safe calendar arithmetic, and requires external libraries. Temporal provides immutable PlainDate, ZonedDateTime, Duration, and nanosecond Instant types."
    },
    {
        "rule_id": "manual-duration-formatting",
        "title": "Manual Duration String Concatenation Instead of Intl.DurationFormat",
        "exts": SCRIPT_EXTS,
        "pattern": re.compile(r"Math\.floor\([^)]+\s*/\s*(?:60|3600)\)[\s\S]{0,80}(?:hours?|mins?|minutes?|secs?|seconds?)", re.IGNORECASE),
        "exclude_if": re.compile(r"Intl\.DurationFormat"),
        "modern_feature": "Intl.DurationFormat and Temporal.Duration",
        "guide_ids": ["format-human-readable-durations"],
        "severity": "low",
        "rationale": "Intl.DurationFormat formats durations consistently across locales (long, short, narrow, digital) without fragile string concatenation."
    },

    # === 6. PERFORMANCE (performance: 25 guides) ===
    {
        "rule_id": "legacy-unload-beacon-instead-of-fetchlater",
        "title": "Unload / Visibility Analytics Beacon Without fetchLater() + AbortSignal",
        "exts": SCRIPT_EXTS,
        "pattern": re.compile(r"(?:navigator\.sendBeacon\(|addEventListener\(\s*['\"](?:unload|beforeunload|pagehide)['\"])", re.IGNORECASE),
        "exclude_if": re.compile(r"\bfetchLater\("),
        "modern_feature": "fetchLater() API with AbortController",
        "guide_ids": ["batch-analytics-events", "full-session-analytics"],
        "severity": "medium",
        "rationale": "fetchLater() lets the browser reliably schedule deferred beacons at page unload or after a timeout without blocking bfcache or relying on unreliable unload handlers."
    },
    {
        "rule_id": "legacy-settimeout-zero-task-yielding",
        "title": "setTimeout(fn, 0) / Heavy Loop Yielding Instead of Scheduler API (scheduler.yield / postTask)",
        "exts": SCRIPT_EXTS,
        "pattern": re.compile(r"(?:setTimeout\([^,]+,\s*0\s*\)|requestIdleCallback\()", re.IGNORECASE),
        "exclude_if": re.compile(r"\bscheduler\.(?:yield|postTask)\b"),
        "modern_feature": "Scheduler API (scheduler.yield() and scheduler.postTask())",
        "guide_ids": ["break-up-long-tasks", "schedule-tasks-by-priority"],
        "severity": "medium",
        "rationale": "scheduler.yield() yields to the main thread while preserving task continuation priority, and scheduler.postTask() schedules prioritized work ('user-blocking', 'user-visible', 'background')."
    },
    {
        "rule_id": "manual-visibilitychange-timing",
        "title": "Manual visibilitychange Tracking Without Visibility State Performance Entries",
        "exts": SCRIPT_EXTS,
        "pattern": re.compile(r"addEventListener\(\s*['\"]visibilitychange['\"]|document\.visibilityState", re.IGNORECASE),
        "exclude_if": re.compile(r"visibility-state"),
        "modern_feature": "Page visibility-state PerformanceEntry + content-visibility background throttling",
        "guide_ids": [
            "calculate-total-foreground-time",
            "detect-initial-visibility-state",
            "efficient-background-processing"
        ],
        "severity": "low",
        "rationale": "PerformanceObserver('visibility-state') reconstructs historical background/foreground intervals accurately from navigation start."
    },
    {
        "rule_id": "async-iife-instead-of-top-level-await",
        "title": "Async IIFE at Module Scope Instead of Top-Level await",
        "exts": {".js", ".mjs", ".ts"},
        "pattern": re.compile(r"\(\s*async\s*(?:function\s*)?\(\s*\)\s*(?:=>)?\s*\{"),
        "exclude_if": None,
        "modern_feature": "ES Module Top-Level await",
        "guide_ids": ["conditional-async-dependencies"],
        "severity": "low",
        "rationale": "ES Modules support top-level await natively for conditionally loading polyfills or initializing async dependencies."
    },
    {
        "rule_id": "missing-content-visibility-on-sections",
        "title": "Large Content Sections / Feeds Without content-visibility: auto",
        "exts": STYLE_EXTS,
        "pattern": re.compile(r"\.(?:feed|article-list|comments-section|long-list|virtual-list|tab-panel|page-view)\b\s*\{", re.IGNORECASE),
        "exclude_if": re.compile(r"content-visibility\s*:\s*auto", re.IGNORECASE),
        "modern_feature": "CSS content-visibility: auto and contain-intrinsic-size",
        "guide_ids": [
            "defer-rendering-heavy-content",
            "faster-spa-view-transitions",
            "interactions-in-complex-layouts",
            "performance"
        ],
        "severity": "medium",
        "rationale": "content-visibility: auto skips layout and painting of offscreen sections, cutting initial render time and improving INP in complex layouts."
    },
    {
        "rule_id": "debounced-scroll-instead-of-scrollend",
        "title": "Debounced scroll Listener with setTimeout Instead of Native scrollend Event",
        "exts": SCRIPT_EXTS,
        "pattern": re.compile(r"addEventListener\(\s*['\"]scroll['\"][\s\S]{0,250}(?:setTimeout|debounce)", re.IGNORECASE),
        "exclude_if": re.compile(r"['\"]scrollend['\"]", re.IGNORECASE),
        "modern_feature": "Native scrollend event",
        "guide_ids": ["defer-work-until-scroll-ends"],
        "severity": "medium",
        "rationale": "Listening to the native 'scrollend' event eliminates arbitrary setTimeout debounce timers that fire too early during momentum scrolling or too late after scrolling stops."
    },
    {
        "rule_id": "css-background-url-without-image-set",
        "title": "CSS background-image url() Without Resolution/Format-Aware image-set()",
        "exts": {".css", ".scss"},
        "pattern": re.compile(r"background(?:-image)?\s*:[^;]*url\(['\"]?[^'\")]+\.(?:png|jpg|jpeg|webp)['\"]?\)", re.IGNORECASE),
        "exclude_if": re.compile(r"\bimage-set\(", re.IGNORECASE),
        "modern_feature": "CSS image-set() with AVIF/WebP type() and 1x/2x descriptors",
        "guide_ids": ["deliver-optimized-decorative-images", "resolution-optimized-pseudo-elements"],
        "severity": "low",
        "rationale": "CSS image-set() lets the browser select modern formats (type('image/avif')) and appropriate pixel densities (1x, 2x) for decorative backgrounds and pseudo-elements."
    },
    {
        "rule_id": "background-fetch-missing-low-priority",
        "title": "Background / Prefetch fetch() Call Without priority: 'low'",
        "exts": SCRIPT_EXTS,
        "pattern": re.compile(r"\bfetch\([^)]*(?:analytics|telemetry|metrics|log|prefetch|background|sync)[^)]*\)", re.IGNORECASE),
        "exclude_if": re.compile(r"priority\s*:\s*['\"]low['\"]", re.IGNORECASE),
        "modern_feature": "fetch(url, { priority: 'low' })",
        "guide_ids": ["deprioritize-background-fetches"],
        "severity": "low",
        "rationale": "Setting priority: 'low' on non-critical background fetch() calls prevents them from contending with critical LCP/render resources."
    },
    {
        "rule_id": "missing-fetchpriority-or-lazy-img",
        "title": "Image / Preload / Script Element Missing Resource Priority Hints (fetchpriority / loading)",
        "exts": MARKUP_EXTS,
        "pattern": re.compile(r"(?:<img\b(?![^>]*(?:loading=|fetchpriority=|decoding=))[^>]+src=|<link\b[^>]*rel=['\"]preload['\"](?![^>]*fetchpriority=))", re.IGNORECASE),
        "exclude_if": None,
        "modern_feature": "fetchpriority='high'|'low' on <img>, <link rel='preload'>, and <script>; loading='lazy' on offscreen <img>/<iframe>",
        "guide_ids": [
            "optimize-image-priority",
            "optimize-preload-priority",
            "optimize-script-priority",
            "performance"
        ],
        "severity": "medium",
        "rationale": "Explicit fetchpriority='high' accelerates LCP hero assets and critical preloads, while loading='lazy' defers offscreen images and iframes."
    },
    {
        "rule_id": "performance-observer-missing-loaf-inp",
        "title": "Performance Monitoring Without Long Animation Frames (loaf) & Event Timing",
        "exts": SCRIPT_EXTS,
        "pattern": re.compile(r"new\s+PerformanceObserver\(|performance\.getEntriesByType\("),
        "exclude_if": re.compile(r"long-animation-frame"),
        "modern_feature": "Long Animation Frames ('long-animation-frame') and Event Timing ('event') PerformanceObserver",
        "guide_ids": ["identify-heavy-scripts", "identify-inp-causes"],
        "severity": "low",
        "rationale": "Observing 'long-animation-frame' (LoAF) and 'event' entries pinpoints the exact scripts and attribution responsible for slow Interaction to Next Paint (INP)."
    },
    {
        "rule_id": "navigation-links-without-speculation-rules",
        "title": "Multi-Page Document Navigation Without Speculation Rules Prefetch / Prerender",
        "exts": {".html", ".htm"},
        "pattern": re.compile(r"<nav\b[\s\S]{0,600}<a\s+href=['\"][^#\"']+", re.IGNORECASE),
        "exclude_if": re.compile(r"speculationrules", re.IGNORECASE),
        "modern_feature": "<script type='speculationrules'> for prefetch/prerender",
        "guide_ids": ["improve-next-page-load-performance"],
        "severity": "low",
        "rationale": "Speculation Rules declaratively prefetch or prerender high-likelihood next navigations for near-instant MPA page loads."
    },
    {
        "rule_id": "ab-test-or-transition-without-render-blocking-expect",
        "title": "Client-Side Experiment / Transition Setup Without blocking='render' or <link rel='expect'>",
        "exts": MARKUP_EXTS | SCRIPT_EXTS,
        "pattern": re.compile(r"(?:abTest|experimentVariant|featureFlag|@view-transition\s*\{\s*navigation\s*:\s*auto)", re.IGNORECASE),
        "exclude_if": re.compile(r"blocking=['\"]render['\"]|rel=['\"]expect['\"]", re.IGNORECASE),
        "modern_feature": "blocking='render' attribute and <link rel='expect'>",
        "guide_ids": ["flicker-free-client-side-ab-testing", "consistent-cross-document-transitions"],
        "severity": "low",
        "rationale": "blocking='render' and <link rel='expect'> prevent flash-of-unmodified-content during client-side experiments and stabilize cross-document view transitions."
    },
    {
        "rule_id": "streaming-dom-patching-without-html-setters",
        "title": "Streaming / Chunked HTML Insertion Without Declarative <template> or HTML Setter Methods",
        "exts": SCRIPT_EXTS | MARKUP_EXTS,
        "pattern": re.compile(r"(?:insertAdjacentHTML\(|createContextualFragment\()", re.IGNORECASE),
        "exclude_if": re.compile(r"\b(?:setHTML|setHTMLUnsafe)\("),
        "modern_feature": "Declarative <template> streaming and setHTML() / setHTMLUnsafe()",
        "guide_ids": ["out-of-order-html-streaming"],
        "severity": "low",
        "rationale": "Modern HTML setter methods and declarative templates support out-of-order HTML streaming and Shadow DOM parsing safely."
    },

    # === 7. PRIVACY & SECURITY (privacy: 1 guide, security: 8 guides) ===
    {
        "rule_id": "legacy-useragent-or-unpartitioned-cookies",
        "title": "navigator.userAgent Sniffing or Third-Party Cookie/Iframe Without Privacy Controls",
        "exts": SCRIPT_EXTS | MARKUP_EXTS,
        "pattern": re.compile(r"(?:\bnavigator\.(?:userAgent|platform|appVersion)\b|document\.cookie\s*=)", re.IGNORECASE),
        "exclude_if": re.compile(r"userAgentData|Partitioned", re.IGNORECASE),
        "modern_feature": "User-Agent Client Hints (navigator.userAgentData), Partitioned Cookies (CHIPS), Permissions-Policy, FedCM",
        "guide_ids": ["privacy"],
        "severity": "medium",
        "rationale": "Replace high-entropy navigator.userAgent parsing with navigator.userAgentData Client Hints and scope cross-site state with Partitioned cookies and Permissions-Policy."
    },
    {
        "rule_id": "unsafe-innerhtml-without-sanitizer-api",
        "title": "Direct innerHTML Assignment Instead of Native Sanitizer API (setHTML)",
        "exts": SCRIPT_EXTS,
        "pattern": re.compile(r"\.innerHTML\s*=\s*(?!['\"]\s*['\"])"),
        "exclude_if": re.compile(r"\.setHTML\("),
        "modern_feature": "Sanitizer API (element.setHTML())",
        "guide_ids": ["sanitize-untrusted-html", "security"],
        "severity": "high",
        "rationale": "element.setHTML() uses the browser's built-in Sanitizer API to strip XSS vectors safely when inserting untrusted HTML."
    },
    {
        "rule_id": "auth-flow-without-passkeys-or-signal-api",
        "title": "Password / WebAuthn Authentication Without Passkey Conditional UI & Signal Methods",
        "exts": SCRIPT_EXTS | MARKUP_EXTS,
        "pattern": re.compile(r"(?:navigator\.credentials\.(?:create|get)|type=['\"]password['\"])", re.IGNORECASE),
        "exclude_if": re.compile(r"PublicKeyCredential\.signal|autocomplete=['\"][^'\"]*webauthn", re.IGNORECASE),
        "modern_feature": "WebAuthn Passkeys, Conditional Mediation (autocomplete='webauthn'), and PublicKeyCredential Signal API",
        "guide_ids": [
            "passkeys",
            "passkey-authentication",
            "passkey-registration",
            "passkey-conditional-create",
            "passkey-reauthentication",
            "passkey-management"
        ],
        "severity": "low",
        "rationale": "Modern authentication flows should support Passkey autofill (autocomplete='username webauthn'), conditional creation, and PublicKeyCredential signal methods to keep authenticator credentials in sync."
    },

    # === 8. UI ATOMS, BEHAVIORS & COMPONENTS (ui-atoms: 10, ui-behaviors: 29, ui-components: 7) ===
    {
        "rule_id": "legacy-custom-modal",
        "title": "Custom Modal / Overlay Container or Missing closedby Instead of Declarative <dialog>",
        "exts": MARKUP_EXTS | SCRIPT_EXTS,
        "pattern": re.compile(r'(<div[^>]+(?:class|id)=["\'][^"\']*\b(?:modal|dialog-backdrop|modal-overlay|popup-modal)\b[^"\']*["\']|role=["\']dialog["\']|<dialog\b(?![^>]*\bclosedby=))', re.IGNORECASE),
        "exclude_if": re.compile(r"<dialog\b[^>]*\bclosedby=", re.IGNORECASE),
        "modern_feature": "<dialog closedby='any'> + Invoker Commands (commandfor, command='show-modal')",
        "guide_ids": [
            "light-dismiss-a-dialog",
            "platform-controls-dismiss-dialog",
            "declarative-dialog-popover-control"
        ],
        "severity": "medium",
        "rationale": "Native <dialog closedby='any'> handles top-layer rendering, focus trapping, Escape/back-button dismissal, and light-dismiss without custom JS."
    },
    {
        "rule_id": "legacy-tooltip-popover-anchor",
        "title": "Custom JS Tooltip / Menu / Tour Overlay Instead of Popover API & CSS Anchor Positioning",
        "exts": MARKUP_EXTS | SCRIPT_EXTS | STYLE_EXTS,
        "pattern": re.compile(r'(?:class=["\'][^"\']*\b(?:tooltip|popover-menu|dropdown-menu|context-menu|onboarding-tour|toast-container)\b|getBoundingClientRect\(\)[\s\S]{0,120}(?:top|left)\s*:)', re.IGNORECASE),
        "exclude_if": re.compile(r"\bpopover(?:target)?=|\banchor-name\s*:", re.IGNORECASE),
        "modern_feature": "Popover API (popover='auto'|'manual'|'hint') + CSS Anchor Positioning (anchor-name, position-anchor, position-try-fallbacks, @container anchored)",
        "guide_ids": [
            "position-aware-tooltips",
            "resilient-context-menus-and-nested-dropdowns",
            "persistent-app-tours",
            "persistent-toast-notifications",
            "anchor-positioning-tab-underline"
        ],
        "severity": "medium",
        "rationale": "Popover API promotes overlays to the top layer with built-in light-dismiss, while CSS Anchor Positioning tethers and flips menus/tooltips/toasts without getBoundingClientRect()."
    },
    {
        "rule_id": "hover-focus-tooltip-without-interest-invokers",
        "title": "JS mouseenter/mouseleave/focus Tooltip or Preview Listeners Instead of Interest Invokers",
        "exts": SCRIPT_EXTS | MARKUP_EXTS,
        "pattern": re.compile(r"addEventListener\(\s*['\"](?:mouseenter|mouseover)['\"][\s\S]{0,200}(?:tooltip|preview|popover)", re.IGNORECASE),
        "exclude_if": re.compile(r"\binterestfor=", re.IGNORECASE),
        "modern_feature": "Interest Invokers (interestfor attribute + popover='hint')",
        "guide_ids": ["interest-triggered-tooltips", "interest-triggered-action-previews"],
        "severity": "low",
        "rationale": "The declarative interestfor attribute with popover='hint' manages hover delays, keyboard focus, and touch long-press for tooltips and preview cards automatically."
    },
    {
        "rule_id": "imperative-button-toggle-without-invoker-commands",
        "title": "JS Click Handler Just Calling showModal() / togglePopover() Instead of Invoker Commands",
        "exts": SCRIPT_EXTS | MARKUP_EXTS,
        "pattern": re.compile(r"addEventListener\(\s*['\"]click['\"][\s\S]{0,120}\.(?:showModal|close|togglePopover|showPopover|hidePopover)\(\)", re.IGNORECASE),
        "exclude_if": re.compile(r"\bcommandfor=", re.IGNORECASE),
        "modern_feature": "HTML Invoker Commands (commandfor and command attributes)",
        "guide_ids": ["declarative-dialog-popover-control", "custom-button-actions"],
        "severity": "low",
        "rationale": "Buttons with commandfor='id' and command='show-modal' / 'toggle-popover' / '--custom-command' wire actions declaratively without boilerplate click listeners."
    },
    {
        "rule_id": "legacy-scroll-listener-animation",
        "title": "JavaScript Scroll Event Listener for Parallax / Progress / Reveal Instead of Scroll-Driven Animations",
        "exts": SCRIPT_EXTS,
        "pattern": re.compile(r"addEventListener\(\s*['\"]scroll['\"]|window\.onscroll\s*=", re.IGNORECASE),
        "exclude_if": re.compile(r"animation-timeline\s*:\s*(?:scroll|view)\(", re.IGNORECASE),
        "modern_feature": "CSS Scroll-Driven Animations (animation-timeline: scroll() / view())",
        "guide_ids": [
            "scroll-progress-indicator",
            "shrinking-header-on-scroll",
            "parallax-scroll-effects",
            "scroll-entry-exit-effects",
            "scrollytelling",
            "carousel-slide-effects"
        ],
        "severity": "high",
        "rationale": "JS scroll listeners execute on the main thread and cause scroll jank. CSS Scroll-Driven Animations run off the main thread on the compositor."
    },
    {
        "rule_id": "sticky-or-scroll-shadow-js-instead-of-scroll-state-queries",
        "title": "Sticky Header / Scroll Shadow State Toggled via JS Instead of Container Scroll-State Queries",
        "exts": STYLE_EXTS | SCRIPT_EXTS,
        "pattern": re.compile(r"(?:position\s*:\s*sticky|\.(?:is-stuck|is-pinned|scroll-shadow|back-to-top)\b)", re.IGNORECASE),
        "exclude_if": re.compile(r"container-type\s*:\s*scroll-state|@container\s+scroll-state\(", re.IGNORECASE),
        "modern_feature": "CSS Container Scroll-State Queries (container-type: scroll-state; @container scroll-state(stuck: top | scrollable: bottom | snapped))",
        "guide_ids": [
            "state-aware-sticky-headers",
            "scrollability-affordance-hints",
            "scroll-position-aware-elements",
            "carousel-snap-highlights"
        ],
        "severity": "low",
        "rationale": "Container scroll-state() queries style sticky headers when stuck, show scroll shadows when scrollable, and highlight snapped carousel items purely in CSS."
    },
    {
        "rule_id": "discrete-display-animation-without-starting-style",
        "title": "Entry/Exit or Top-Layer Transitions Without @starting-style and transition-behavior: allow-discrete",
        "exts": {".css", ".scss"},
        "pattern": re.compile(r"(?:dialog(?:\[open\])?|\[popover\]:popover-open)\s*\{[^}]*transition\s*:", re.IGNORECASE),
        "exclude_if": re.compile(r"@starting-style|allow-discrete", re.IGNORECASE),
        "modern_feature": "@starting-style, transition-behavior: allow-discrete, and overlay property",
        "guide_ids": ["animate-element-entry-exit", "animate-to-from-top-layer"],
        "severity": "low",
        "rationale": "@starting-style and transition-behavior: allow-discrete enable smooth CSS entry and exit animations for elements transitioning from display: none or into the top layer."
    },
    {
        "rule_id": "legacy-view-swap-without-view-transitions",
        "title": "DOM / Route View Swap Without View Transitions API",
        "exts": SCRIPT_EXTS | STYLE_EXTS,
        "pattern": re.compile(r"(?:replaceChildren\(|history\.pushState\(|router\.push\()", re.IGNORECASE),
        "exclude_if": re.compile(r"startViewTransition|@view-transition", re.IGNORECASE),
        "modern_feature": "View Transitions API (document.startViewTransition, @view-transition, view-transition-class, active-view-transition-type)",
        "guide_ids": [
            "same-document-transitions",
            "cross-document-transitions",
            "directional-navigation-transitions",
            "group-element-transitions",
            "stack-drill-down"
        ],
        "severity": "low",
        "rationale": "View Transitions smoothly morph DOM updates and full-page navigations with hardware acceleration, group transitions (view-transition-class), and directional types."
    },
    {
        "rule_id": "dom-reparenting-without-movebefore",
        "title": "DOM Reparenting via appendChild / insertBefore Instead of State-Preserving moveBefore()",
        "exts": SCRIPT_EXTS,
        "pattern": re.compile(r"\.(?:appendChild|insertBefore)\([^)]*(?:iframe|video|audio|dialog|modal|player|embed)", re.IGNORECASE),
        "exclude_if": re.compile(r"\.moveBefore\("),
        "modern_feature": "Atomic DOM moveBefore() API",
        "guide_ids": ["move-dom-element-without-losing-state", "persistent-top-layer-ui"],
        "severity": "medium",
        "rationale": "appendChild() and insertBefore() reset iframe state, reload video playback, drop focus, and close top-layer dialogs/popovers. element.moveBefore() reparents nodes atomically while preserving state."
    },
    {
        "rule_id": "cubic-bezier-spring-instead-of-linear-easing",
        "title": "JS Spring Physics or Clamped cubic-bezier Bounce Instead of CSS linear() Easing",
        "exts": STYLE_EXTS | SCRIPT_EXTS,
        "pattern": re.compile(r"cubic-bezier\(\s*[\d.-]+\s*,\s*-[\d.]+\s*,|springPhysics", re.IGNORECASE),
        "exclude_if": re.compile(r"\blinear\([^)]*,[^)]*\)"),
        "modern_feature": "CSS linear() easing function",
        "guide_ids": ["physics-based-easing"],
        "severity": "low",
        "rationale": "CSS linear() easing models multi-point spring, bounce, and elastic curves directly in CSS transitions and keyframes."
    },
    {
        "rule_id": "dom-wrapping-text-highlight-instead-of-custom-highlights",
        "title": "DOM <mark>/<span> Wrapping for Search Highlights Instead of CSS Custom Highlight API",
        "exts": SCRIPT_EXTS,
        "pattern": re.compile(r"replace\([^)]+,\s*['\"]<mark\b", re.IGNORECASE),
        "exclude_if": re.compile(r"CSS\.highlights|new\s+Highlight\("),
        "modern_feature": "CSS Custom Highlight API (CSS.highlights and ::highlight())",
        "guide_ids": ["highlight-text-ranges"],
        "severity": "low",
        "rationale": "CSS.highlights and ::highlight() style arbitrary text ranges without mutating the DOM tree or breaking framework virtual DOM nodes."
    },
    {
        "rule_id": "scroll-snap-without-snap-events-or-initial-target",
        "title": "CSS Scroll Snap Used Without scrollsnapchange Events or scroll-initial-target",
        "exts": STYLE_EXTS | SCRIPT_EXTS,
        "pattern": re.compile(r"scroll-snap-type\s*:", re.IGNORECASE),
        "exclude_if": re.compile(r"scrollsnapchange|scroll-initial-target", re.IGNORECASE),
        "modern_feature": "scrollsnapchange / scrollsnapchanging events and CSS scroll-initial-target",
        "guide_ids": [
            "scroll-snap-realtime-feedback",
            "scroll-snap-state-sync",
            "scroll-target-on-load",
            "pull-to-reveal",
            "swipe-to-remove",
            "navigation-drawer"
        ],
        "severity": "low",
        "rationale": "Pair scroll-snap containers with scrollsnapchange/scrollsnapchanging events for active indicator sync and scroll-initial-target: nearest for zero-JS initial scroll positioning."
    },
    {
        "rule_id": "accordion-hidden-content-not-searchable",
        "title": "Accordion / Collapsible Content Hidden With display: none Instead of <details name> or hidden='until-found'",
        "exts": MARKUP_EXTS,
        "pattern": re.compile(r'class=["\'][^"\']*\b(?:accordion|collapse-panel|faq-item)\b|<details\b(?![^>]*\bname=)', re.IGNORECASE),
        "exclude_if": re.compile(r'hidden=["\']until-found["\']|<details\b[^>]*\bname=', re.IGNORECASE),
        "modern_feature": "<details name='group'> (exclusive accordions) and hidden='until-found' + beforematch event",
        "guide_ids": ["search-hidden-content"],
        "severity": "low",
        "rationale": "Content hidden with display: none is invisible to Find-in-Page (Ctrl+F) and fragment links. Use <details name='...'> or hidden='until-found' so collapsed content auto-expands on search."
    },
    {
        "rule_id": "js-intersection-observer-scrollspy",
        "title": "Custom IntersectionObserver Table-of-Contents Scrollspy Instead of scroll-target-group & :target-current",
        "exts": SCRIPT_EXTS | STYLE_EXTS,
        "pattern": re.compile(r"IntersectionObserver[\s\S]{0,300}(?:toc|scrollspy|active-section|activeHeading)", re.IGNORECASE),
        "exclude_if": re.compile(r"scroll-target-group|:target-current", re.IGNORECASE),
        "modern_feature": "CSS scroll-target-group: auto and :target-current pseudo-class",
        "guide_ids": ["scrollspy"],
        "severity": "low",
        "rationale": "scroll-target-group: auto on a nav container with :target-current highlights the active section link natively in CSS without IntersectionObserver JS."
    },
    {
        "rule_id": "custom-spinner-or-progress-ring-div",
        "title": "Non-Semantic <div> Spinner / Progress Ring Without <progress>, conic-gradient, or prefers-reduced-motion",
        "exts": MARKUP_EXTS | STYLE_EXTS,
        "pattern": re.compile(r'class=["\'][^"\']*\b(?:spinner|loading-spinner|progress-ring|circular-progress)\b', re.IGNORECASE),
        "exclude_if": re.compile(r"<progress\b", re.IGNORECASE),
        "modern_feature": "Semantic <progress> element with conic-gradient(), @property, and prefers-reduced-motion",
        "guide_ids": ["progress-ring", "spinner"],
        "severity": "low",
        "rationale": "Building spinners and progress rings on top of <progress> provides built-in assistive technology state announcements and respects prefers-reduced-motion."
    },

    # === 9. VISUAL DESIGN (visual-design: 17 guides) ===
    {
        "rule_id": "legacy-webkit-scrollbar-styling",
        "title": "Non-Standard ::-webkit-scrollbar Instead of Standard scrollbar-color & scrollbar-width",
        "exts": {".css", ".scss"},
        "pattern": re.compile(r"::-webkit-scrollbar\b", re.IGNORECASE),
        "exclude_if": re.compile(r"\bscrollbar-(?:color|width)\s*:", re.IGNORECASE),
        "modern_feature": "Standard CSS scrollbar-color, scrollbar-width, and @media (prefers-contrast: more)",
        "guide_ids": ["customize-scrollbar-color-and-thickness", "adapt-scrollbar-to-contrast-preferences"],
        "severity": "low",
        "rationale": "Standard scrollbar-color and scrollbar-width work across all modern engines and should adapt to @media (prefers-contrast: more)."
    },
    {
        "rule_id": "dark-mode-media-without-light-dark",
        "title": "Verbose @media (prefers-color-scheme: dark) Color Duplication Instead of CSS light-dark()",
        "exts": {".css", ".scss"},
        "pattern": re.compile(r"@media\s*\(\s*prefers-color-scheme\s*:\s*dark\s*\)", re.IGNORECASE),
        "exclude_if": re.compile(r"\blight-dark\(", re.IGNORECASE),
        "modern_feature": "CSS color-scheme: light dark and light-dark() function",
        "guide_ids": ["dark-mode", "component-specific-light-dark-theme"],
        "severity": "low",
        "rationale": "Declaring color-scheme: light dark with light-dark(lightVal, darkVal) defines adaptive theme tokens inline and adapts native browser scrollbars and form controls."
    },
    {
        "rule_id": "js-color-contrast-instead-of-contrast-color",
        "title": "JavaScript Luminance / Contrast Calculation Instead of CSS contrast-color()",
        "exts": SCRIPT_EXTS | STYLE_EXTS,
        "pattern": re.compile(r"(?:getContrastColor|getLuminance|0\.299\s*\*|0\.587\s*\*|0\.114\s*\*)", re.IGNORECASE),
        "exclude_if": re.compile(r"\bcontrast-color\(", re.IGNORECASE),
        "modern_feature": "CSS contrast-color() function",
        "guide_ids": ["contrast-color"],
        "severity": "low",
        "rationale": "CSS contrast-color(var(--bg)) automatically picks black or white text with maximum contrast against any dynamic background color."
    },
    {
        "rule_id": "headings-missing-text-wrap-balance-or-pretty",
        "title": "Heading / Body Typography Without text-wrap: balance / pretty or text-box Alignment",
        "exts": {".css", ".scss"},
        "pattern": re.compile(r"\bh[1-4]\b\s*\{(?![^}]*text-wrap\s*:)", re.IGNORECASE),
        "exclude_if": re.compile(r"text-wrap\s*:\s*(?:balance|pretty|nowrap)|text-box\s*:", re.IGNORECASE),
        "modern_feature": "CSS text-wrap: balance, text-wrap: pretty, text-wrap: nowrap, and text-box (text-box-trim)",
        "guide_ids": [
            "improve-text-layout-and-legibility",
            "precise-text-alignment",
            "prevent-text-wrapping"
        ],
        "severity": "low",
        "rationale": "text-wrap: balance prevents awkward single-word orphans in headings, text-wrap: pretty improves body paragraphs, and text-box trims half-leading for optical vertical centering."
    },
    {
        "rule_id": "font-face-missing-font-size-adjust",
        "title": "@font-face or Multi-Font Stack Without font-size-adjust for Visually Stable Fallbacks",
        "exts": {".css", ".scss"},
        "pattern": re.compile(r"@font-face\s*\{(?![^}]*font-size-adjust)", re.IGNORECASE),
        "exclude_if": re.compile(r"\bfont-size-adjust\s*:", re.IGNORECASE),
        "modern_feature": "CSS font-size-adjust (ex-height / cap-height / ic-width)",
        "guide_ids": ["visually-stable-font-fallbacks", "visually-stable-mixed-fonts"],
        "severity": "low",
        "rationale": "font-size-adjust normalizes x-height/cap-height across web fonts and system fallbacks, preventing layout shift (CLS) on font swap and harmonizing mixed-font inline runs."
    },
    {
        "rule_id": "canvas-html-rendering-or-html2canvas",
        "title": "Canvas Text/UI Rendering or html2canvas Workaround Instead of HTML-in-Canvas",
        "exts": SCRIPT_EXTS | MARKUP_EXTS,
        "pattern": re.compile(r"(?:html2canvas|fillText\(|strokeText\(|new\s+THREE\.CSS3DRenderer)", re.IGNORECASE),
        "exclude_if": re.compile(r"\blayoutsubtree\b|\bdrawElementImage\b", re.IGNORECASE),
        "modern_feature": "HTML-in-Canvas (layoutsubtree attribute and ctx.drawElementImage())",
        "guide_ids": [
            "expose-canvas-content-to-browser-features",
            "export-html-media-from-canvas",
            "apply-webgl-shaders",
            "interactive-content-in-3d-scenes"
        ],
        "severity": "low",
        "rationale": "HTML-in-Canvas renders live, accessible DOM subtrees inside 2D/WebGL/3D canvas scenes while preserving assistive technology, translation, and CSS layout."
    },
    {
        "rule_id": "overlay-fade-or-cutout-without-css-masks",
        "title": "Fade-Out Gradient Overlay Div or Clip Hack Instead of CSS Masks (mask-image / mask-composite)",
        "exts": STYLE_EXTS | MARKUP_EXTS,
        "pattern": re.compile(r"(?:class=['\"][^'\"]*\b(?:fade-overlay|gradient-mask|cutout|spotlight)\b|clip-path\s*:\s*polygon\()", re.IGNORECASE),
        "exclude_if": re.compile(r"\bmask(?:-image|-composite)?\s*:", re.IGNORECASE),
        "modern_feature": "CSS Masks (mask-image, mask-composite) and @property",
        "guide_ids": [
            "soft-edge-content-fade",
            "shaped-cutouts",
            "complex-shapes",
            "visually-texture-content",
            "interactive-content-reveal"
        ],
        "severity": "low",
        "rationale": "CSS mask-image and mask-composite create background-independent soft edge fades, knockouts, organic shapes, and pointer-tracking reveals without opaque overlay divs."
    },

    # === 10. WEBMCP (webmcp: 3 guides) ===
    {
        "rule_id": "forms-and-tools-missing-webmcp",
        "title": "Interactive Forms / Client Actions Without WebMCP Agent Tool Annotations",
        "exts": MARKUP_EXTS | SCRIPT_EXTS,
        "pattern": re.compile(r"<form\b(?![^>]*\btoolname=)[^>]*\b(?:id|action|onSubmit|@submit)=", re.IGNORECASE),
        "exclude_if": re.compile(r"\b(?:toolname=|modelContext\b)", re.IGNORECASE),
        "modern_feature": "WebMCP Declarative Form Attributes (toolname, tooldescription) and navigator.modelContext / document.modelContext",
        "guide_ids": ["webmcp", "agentic-forms", "agentic-javascript-tools"],
        "severity": "low",
        "rationale": "Annotating key forms with WebMCP attributes (toolname, tooldescription) or registering client tools via modelContext exposes structured capabilities directly to browser AI agents."
    }
]


def load_guides_catalog() -> Dict[str, Dict[str, Any]]:
    """Load the 146-guide modern-web-guidance catalog from the bundled JSON index.

    The bundled index is the ONLY source. This used to fall back to
    `npx --offline -y modern-web-guidance@latest list`, i.e. executing unpinned, mutable
    third-party code from a pre-pass, which bypasses the factory's own pin policy
    (lib/tool_pins.py; lib/sandbox.py binds only pinned tools). The fallback could only ever
    fire when the bundled file was missing or corrupt - a broken install - and would then
    paper over it by running that code.

    It now fails closed instead: a missing or unusable bundled index raises, because the
    guide catalog is the scanner's ground truth for coverage and silently scanning without
    it produces a report that looks complete while checking nothing.
    """
    if not BUNDLED_GUIDES_INDEX.exists():
        raise GuidesCatalogUnavailable(
            f"bundled guide catalog missing: {BUNDLED_GUIDES_INDEX}. The modern-web pre-pass "
            "refuses to fetch a catalog by executing unpinned remote code "
            "(threat-model tm-unpinned-third-party-npx-prepass); restore the file "
            "(agents/modern-web/scripts/guides_index.json, 146 guides) from the repository."
        )
    try:
        items = json.loads(BUNDLED_GUIDES_INDEX.read_text(encoding="utf-8"))
    except Exception as exc:
        raise GuidesCatalogUnavailable(
            f"bundled guide catalog is unreadable: {BUNDLED_GUIDES_INDEX} ({exc}). "
            "Fail closed rather than scanning without guide coverage."
        ) from exc

    catalog: Dict[str, Dict[str, Any]] = {}
    for item in items if isinstance(items, list) else []:
        if isinstance(item, dict) and "id" in item:
            catalog[item["id"]] = item
    if len(catalog) < EXPECTED_MIN_GUIDES:
        raise GuidesCatalogUnavailable(
            f"bundled guide catalog is incomplete: {BUNDLED_GUIDES_INDEX} yielded "
            f"{len(catalog)} guides, expected at least {EXPECTED_MIN_GUIDES}. Fail closed "
            "rather than scanning against a truncated catalog: the coverage numbers in the "
            "report would otherwise look plausible while most guides go unchecked."
        )
    return catalog


def scan_repository(target_dir: Path, retrieve_guides: bool = False) -> Dict[str, Any]:
    catalog = load_guides_catalog()
    candidates: List[Dict[str, Any]] = []
    known_baseline_fallbacks: List[Dict[str, Any]] = []
    scanned_files = 0
    matched_guide_ids: Set[str] = set()

    # Verify total guide coverage of RULES against catalog
    covered_guides: Set[str] = set()
    for r in RULES:
        covered_guides.update(r.get("guide_ids", []))

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = sorted([d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")])
        for fname in sorted(files):
            fpath = Path(root) / fname
            ext = fpath.suffix.lower()
            if ext not in WEB_EXTS:
                continue

            try:
                if fpath.stat().st_size > 2 * 1024 * 1024:
                    continue
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            scanned_files += 1
            rel_path = str(fpath.relative_to(target_dir))
            lines = content.splitlines()

            # Extract baseline annotations from comments in this file (agents-08d)
            baseline_annotations = extract_baseline_annotations(lines)

            for rule in RULES:
                if ext not in rule["exts"]:
                    continue
                if rule["exclude_if"] and rule["exclude_if"].search(content):
                    continue

                for match in rule["pattern"].finditer(content):
                    start_pos = match.start()
                    line_no = content.count("\n", 0, start_pos) + 1
                    snippet_line = lines[line_no - 1].strip() if 0 <= line_no - 1 < len(lines) else match.group(0)[:120]

                    # Check if this candidate falls within an annotated fallback window for this rule
                    is_known_fallback = False
                    for annot_line, feat in baseline_annotations:
                        if is_in_fallback_window(annot_line, line_no, lines) and rule_matches_baseline_feature(rule["rule_id"], feat):
                            is_known_fallback = True
                            known_baseline_fallbacks.append({
                                "feature_id": feat,
                                "rule_id": rule["rule_id"],
                                "path": rel_path,
                                "line_number": line_no,
                                "annotation_line": annot_line
                            })
                            break
                    if is_known_fallback:
                        continue

                    guide_ids = rule.get("guide_ids", [])
                    matched_guide_ids.update(guide_ids)
                    guide_refs = [
                        {
                            "id": gid,
                            "category": catalog.get(gid, {}).get("category", ""),
                            "description": catalog.get(gid, {}).get("description", ""),
                            "featuresUsed": catalog.get(gid, {}).get("featuresUsed", []),
                            # Emitted so the engine can cite the guide WITHOUT being told to run
                            # unpinned remote code: the catalog is bundled in this repository.
                            "guide_index_ref": f"{BUNDLED_GUIDES_INDEX.name}#{gid}"
                        }
                        for gid in guide_ids
                    ]

                    candidates.append({
                        "rule_id": rule["rule_id"],
                        "title": rule["title"],
                        "path": rel_path,
                        "line_number": line_no,
                        "snippet": snippet_line[:200],
                        "severity": rule["severity"],
                        "modern_feature": rule["modern_feature"],
                        "rationale": rule["rationale"],
                        "guide_ids": guide_ids,
                        "modern_web_guidance_refs": guide_refs
                    })
                    break  # One representative match per rule per file to keep signal-to-noise high

    # Deterministic tie-breakers. `line_number_sort_key` orders an unknown location after every
    # known line instead of at an implicit line 0; these candidates carry the scanner's own
    # 1-based line ints, so the order is unchanged - the safety is just declared (agents-ghtz).
    candidates.sort(key=lambda c: (
        c["severity"] != "high",
        c["path"],
        line_number_sort_key(c.get("line_number")),
        c["rule_id"],
    ))

    retrieved_markdown: Dict[str, str] = {}
    if retrieve_guides and matched_guide_ids:
        # Fail closed. This used to run `npx -y modern-web-guidance@latest retrieve ...`, i.e.
        # fetch mutable remote code with no pin. It cannot even work in a contained run: this
        # station declares no network tool (agent.yaml `requires: []`, `network: false`), so
        # lib/containment.egress_allowlist() is empty and the sandbox is unshared - the call
        # could only ever fail its egress or hit the 15s timeout. The bundled index carries
        # each guide's category/description/featuresUsed; guide bodies are not fetched here.
        raise UnpinnedExecutionRefused(
            "--retrieve needs 'modern-web-guidance@latest' over the network, which the factory "
            "refuses to execute unpinned (threat-model tm-unpinned-third-party-npx-prepass; "
            "lib/tool_pins.py). This station also declares network:false, so it has no egress "
            "allowlist. Use the bundled catalog metadata instead."
        )

    # Every candidate gets a deterministic identity at scan time (agents-rdyb), so a consumer can
    # COPY it rather than reconstruct identity from the model's label and prose.
    assign_candidate_ids(candidates)

    return {
        **artefact_scheme_fields(),
        "target": target_dir.name,
        "scanned_files": scanned_files,
        "catalog_total_guides": len(catalog),
        "rules_count": len(RULES),
        "guides_covered_by_rules": len(covered_guides),
        "matched_guide_count": len(matched_guide_ids),
        "matched_guide_ids": sorted(matched_guide_ids),
        "known_baseline_fallbacks": known_baseline_fallbacks,
        "known_baseline_fallback_count": len(known_baseline_fallbacks),
        "candidates": candidates,
        "retrieved_guides": retrieved_markdown
    }


def main():
    parser = argparse.ArgumentParser(description="Modern Web Guidance deterministic scanner (146 guides)")
    parser.add_argument("--target", required=True, help="Target repository directory")
    parser.add_argument("--output", help="Output JSON path")
    parser.add_argument("--retrieve", action="store_true", help="Refused: guide retrieval would execute unpinned remote code (see UnpinnedExecutionRefused)")
    args = parser.parse_args()

    target_dir = Path(args.target).resolve()
    try:
        result = scan_repository(target_dir, retrieve_guides=args.retrieve)
    except (GuidesCatalogUnavailable, UnpinnedExecutionRefused) as exc:
        # Fail closed, and say why in one line rather than dumping a traceback: this is a
        # policy refusal or a broken install, not an internal crash.
        print(f"error: {exc}", file=sys.stderr)
        return 2
    emit_station_result(result, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
