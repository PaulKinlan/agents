#!/usr/bin/env python3
"""Deterministic Pre-Pass Scanner for Modern Web Guidance (agents/modern-web/scripts/scan_modern_web.py)

Scans HTML, CSS, JS, TS, JSX, TSX, Vue, and Svelte files for legacy frontend
idioms that have native Baseline Web Platform replacements (<dialog>, Popover API,
CSS Anchor Positioning, Container Queries, :has(), :user-valid, View Transitions,
Scroll-Driven Animations, content-visibility, fetchpriority, color-mix).
Also queries the local modern-web-guidance index if available.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

IGNORE_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", ".next", ".nuxt",
    "coverage", ".venv", "venv", "__pycache__", ".beads", "runs"
}

WEB_EXTS = {".html", ".htm", ".css", ".scss", ".js", ".mjs", ".ts", ".jsx", ".tsx", ".vue", ".svelte"}

MODERN_WEB_SEARCH_SCRIPT = Path(
    os.path.expanduser("~/.gemini/config/plugins/modern-web-guidance-plugin/skills/modern-web-guidance/scripts/search_features.py")
)

RULES = [
    {
        "rule_id": "legacy-custom-modal",
        "title": "Custom Modal / Overlay Container Instead of Native <dialog>",
        "exts": {".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte", ".js", ".ts"},
        "pattern": re.compile(r'(<div[^>]+(?:class|id)=["\'][^"\']*\b(?:modal|dialog-backdrop|modal-overlay|popup-modal)\b[^"\']*["\']|role=["\']dialog["\'])', re.IGNORECASE),
        "exclude_if": re.compile(r"<dialog\b", re.IGNORECASE),
        "modern_feature": "<dialog> element with showModal(), ::backdrop, and closedby='any'",
        "guidance_query": "dialog modal backdrop",
        "severity": "medium",
        "rationale": "Native <dialog> provides top-layer rendering, automatic focus trapping, Escape key handling, inert background, and ::backdrop without custom JS/z-index hacks."
    },
    {
        "rule_id": "legacy-tooltip-popover",
        "title": "Custom JS Tooltip / Dropdown Instead of Popover API & CSS Anchor Positioning",
        "exts": {".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte", ".js", ".ts", ".css"},
        "pattern": re.compile(r'(?:class=["\'][^"\']*\b(?:tooltip|popover-menu|dropdown-menu)\b|getBoundingClientRect\(\)[\s\S]{0,120}(?:top|left)\s*:)', re.IGNORECASE),
        "exclude_if": re.compile(r"\bpopover(?:target)?=", re.IGNORECASE),
        "modern_feature": "Popover API (popover='auto', popovertarget) + CSS Anchor Positioning (anchor-name, position-anchor)",
        "guidance_query": "popover anchor positioning",
        "severity": "medium",
        "rationale": "The native Popover API promotes elements to the top layer with built-in light-dismiss, while CSS Anchor Positioning eliminates runtime getBoundingClientRect() layout reads."
    },
    {
        "rule_id": "legacy-scroll-listener-animation",
        "title": "JavaScript Scroll Event Listener Used for Visual/Scroll Effects",
        "exts": {".js", ".mjs", ".ts", ".jsx", ".tsx", ".vue", ".svelte"},
        "pattern": re.compile(r"addEventListener\(\s*['\"]scroll['\"]|window\.onscroll\s*=", re.IGNORECASE),
        "exclude_if": re.compile(r"animation-timeline\s*:\s*(?:scroll|view)\(", re.IGNORECASE),
        "modern_feature": "CSS Scroll-Driven Animations (animation-timeline: scroll() / view())",
        "guidance_query": "scroll-driven animations timeline",
        "severity": "high",
        "rationale": "JS scroll listeners run on the main thread and cause jank during scrolling. CSS Scroll-Driven Animations run off the main thread on the compositor."
    },
    {
        "rule_id": "legacy-js-parent-selector",
        "title": "Imperative DOM Parent Traversal / State Toggling Instead of CSS :has()",
        "exts": {".js", ".mjs", ".ts", ".jsx", ".tsx"},
        "pattern": re.compile(r"(?:parentElement|parentNode|closest\([^)]+\))\s*\.\s*classList\.(?:add|remove|toggle)", re.IGNORECASE),
        "exclude_if": None,
        "modern_feature": "CSS :has() relational pseudo-class",
        "guidance_query": "has relational selector parent",
        "severity": "low",
        "rationale": "CSS :has() allows styling parent or preceding sibling containers reactively based on child/input state without imperative JS DOM mutations."
    },
    {
        "rule_id": "legacy-form-validation-classes",
        "title": "Manual Form Validation State Classes Instead of :user-valid / :user-invalid",
        "exts": {".css", ".scss", ".js", ".ts", ".jsx", ".tsx", ".html"},
        "pattern": re.compile(r"(?:\.(?:is-invalid|is-valid|input-error|field-touched)\b|:invalid\b)", re.IGNORECASE),
        "exclude_if": re.compile(r":user-(?:invalid|valid)", re.IGNORECASE),
        "modern_feature": "CSS :user-valid and :user-invalid pseudo-classes",
        "guidance_query": "user-valid user-invalid form validation",
        "severity": "low",
        "rationale": ":invalid fires prematurely before user interaction; :user-invalid and :user-valid match only after the user interacts with the input, eliminating custom JS dirty/touched state tracking."
    },
    {
        "rule_id": "legacy-viewport-media-for-components",
        "title": "Component-Level Viewport @media Queries Without CSS Container Queries",
        "exts": {".css", ".scss"},
        "pattern": re.compile(r"@media\s*\(\s*(?:min|max)-width\s*:\s*\d+(?:px|rem|em)\s*\)", re.IGNORECASE),
        "exclude_if": re.compile(r"@container\b|container-type\s*:", re.IGNORECASE),
        "modern_feature": "CSS Container Queries (container-type: inline-size; @container)",
        "guidance_query": "container queries inline-size",
        "severity": "low",
        "rationale": "Reusable UI cards, sidebars, and panels should adapt to their container's available inline-size via @container rather than assuming fixed viewport widths."
    },
    {
        "rule_id": "missing-fetchpriority-or-lazy-img",
        "title": "Image Element Missing Modern Resource Hints (fetchpriority / loading / decoding)",
        "exts": {".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte"},
        "pattern": re.compile(r"<img\b(?![^>]*(?:loading=|fetchpriority=|decoding=))[^>]+src=", re.IGNORECASE),
        "exclude_if": None,
        "modern_feature": "fetchpriority='high' on LCP hero images; loading='lazy' decoding='async' on below-the-fold images",
        "guidance_query": "fetchpriority lcp image optimization",
        "severity": "medium",
        "rationale": "Explicit fetchpriority='high' accelerates Largest Contentful Paint (LCP), while loading='lazy' and decoding='async' prevent offscreen images from competing for bandwidth and main-thread decode."
    },
    {
        "rule_id": "legacy-view-swap-without-transition",
        "title": "DOM / Route View Swap Without View Transitions API",
        "exts": {".js", ".mjs", ".ts", ".jsx", ".tsx"},
        "pattern": re.compile(r"(?:innerHTML\s*=|replaceChildren\(|history\.pushState\()", re.IGNORECASE),
        "exclude_if": re.compile(r"startViewTransition", re.IGNORECASE),
        "modern_feature": "View Transitions API (document.startViewTransition() / @view-transition { navigation: auto })",
        "guidance_query": "view transitions startViewTransition",
        "severity": "low",
        "rationale": "Wrapping DOM state changes in document.startViewTransition() provides smooth hardware-accelerated morphing with graceful fallback."
    }
]


def lookup_modern_guidance(query: str) -> List[Dict[str, Any]]:
    """Query the modern-web-guidance skill script if installed."""
    if not MODERN_WEB_SEARCH_SCRIPT.exists():
        return []
    try:
        res = subprocess.run(
            [sys.executable, str(MODERN_WEB_SEARCH_SCRIPT), query],
            capture_output=True, text=True, timeout=3
        )
        if res.returncode == 0 and res.stdout.strip():
            data = json.loads(res.stdout)
            if isinstance(data, list):
                return data[:2]
            elif isinstance(data, dict) and "results" in data:
                return data["results"][:2]
    except Exception:
        pass
    return []


def scan_repository(target_dir: Path) -> Dict[str, Any]:
    candidates: List[Dict[str, Any]] = []
    scanned_files = 0
    guidance_cache: Dict[str, Any] = {}

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for fname in sorted(files):
            fpath = Path(root) / fname
            ext = fpath.suffix.lower()
            if ext not in WEB_EXTS:
                continue

            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            scanned_files += 1
            rel_path = str(fpath.relative_to(target_dir))
            lines = content.splitlines()

            for rule in RULES:
                if ext not in rule["exts"]:
                    continue
                if rule["exclude_if"] and rule["exclude_if"].search(content):
                    continue

                for match in rule["pattern"].finditer(content):
                    start_pos = match.start()
                    line_no = content.count("\n", 0, start_pos) + 1
                    snippet_line = lines[line_no - 1].strip() if 0 <= line_no - 1 < len(lines) else match.group(0)[:120]

                    q = rule["guidance_query"]
                    if q not in guidance_cache:
                        guidance_cache[q] = lookup_modern_guidance(q)

                    candidates.append({
                        "rule_id": rule["rule_id"],
                        "title": rule["title"],
                        "path": rel_path,
                        "line_number": line_no,
                        "snippet": snippet_line[:200],
                        "severity": rule["severity"],
                        "modern_feature": rule["modern_feature"],
                        "rationale": rule["rationale"],
                        "modern_web_guidance_refs": guidance_cache[q]
                    })
                    break  # One representative match per rule per file to keep noise low

    return {
        "target": target_dir.name,
        "scanned_files": scanned_files,
        "modern_web_guidance_plugin_detected": MODERN_WEB_SEARCH_SCRIPT.exists(),
        "candidates": candidates
    }


def main():
    parser = argparse.ArgumentParser(description="Modern Web Guidance deterministic scanner")
    parser.add_argument("--target", required=True, help="Target repository directory")
    parser.add_argument("--output", help="Output JSON path")
    args = parser.parse_args()

    target_dir = Path(args.target).resolve()
    result = scan_repository(target_dir)
    out = json.dumps(result, indent=2)

    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
    else:
        print(out)


if __name__ == "__main__":
    main()
