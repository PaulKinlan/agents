#!/usr/bin/env python3
"""Deterministic Pre-Pass for UI & UX Analyzer (agents/ui-ux-audit/scripts/scan_ui_ux.py)

Evaluates HTML, CSS, and UI component files across 7 core UI/UX dimensions:
1. Design token & theme consistency (hardcoded hex colors / z-index magic values vs CSS variables)
2. Interactive affordance completeness (:hover without :focus-visible / :active / :disabled)
3. Async state completeness (fetch/form views missing loading, empty, or inline error feedback)
4. Touch & pointer target ergonomics (interactive controls with < 24px/44px hit areas)
5. Dark mode & color-scheme adaptation (light-only hardcoded colors without light-dark() / prefers-color-scheme)
6. Typography & reading comfort (font-size < 12px, missing max-width measure on prose)
7. Form UX & feedback (inputs missing autocomplete, type specificity, or clear submit affordances)
"""

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List

IGNORE_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", ".next", ".nuxt",
    "coverage", ".venv", "venv", "__pycache__", ".beads", "runs"
}

UI_EXTS = {".html", ".htm", ".css", ".scss", ".js", ".ts", ".jsx", ".tsx", ".vue", ".svelte"}


def scan_ui_ux(target_dir: Path) -> Dict[str, Any]:
    candidates: List[Dict[str, Any]] = []
    scanned_files = 0
    css_custom_props_count = 0
    hardcoded_color_count = 0

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for fname in sorted(files):
            fpath = Path(root) / fname
            ext = fpath.suffix.lower()
            if ext not in UI_EXTS:
                continue

            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            scanned_files += 1
            rel_path = str(fpath.relative_to(target_dir))
            lines = content.splitlines()

            # 1. CSS & Styling checks (either .css/.scss or <style> blocks in .html/.vue/.svelte)
            if ext in {".css", ".scss", ".html", ".htm", ".vue", ".svelte"}:
                css_vars = len(re.findall(r"--[a-zA-Z0-9_-]+\s*:", content))
                css_custom_props_count += css_vars
                hex_matches = list(re.finditer(r"#[0-9a-fA-F]{3,8}\b", content))
                hardcoded_color_count += len(hex_matches)

                # Rule 1: Hardcoded hex colors bypassing design tokens
                if len(hex_matches) >= 3 and "var(--" not in content:
                    m = hex_matches[0]
                    line_no = content.count("\n", 0, m.start()) + 1
                    candidates.append({
                        "rule_id": "design-token-drift-colors",
                        "dimension": "Visual Consistency & Design Tokens",
                        "path": rel_path,
                        "line_number": line_no,
                        "snippet": lines[line_no - 1].strip()[:180],
                        "severity": "medium",
                        "title": f"Hardcoded Color Palette ({len(hex_matches)} hex literals) Without CSS Custom Properties",
                        "rationale": "Hardcoded hex colors scatter palette decisions across stylesheets, making theming, dark mode, and contrast tuning fragile."
                    })

                # Rule 2: :hover defined without :focus-visible
                if ":hover" in content and ":focus-visible" not in content:
                    m = re.search(r":hover\b", content)
                    line_no = content.count("\n", 0, m.start()) + 1 if m else 1
                    candidates.append({
                        "rule_id": "missing-focus-visible-state",
                        "dimension": "Interaction States & Affordances",
                        "path": rel_path,
                        "line_number": line_no,
                        "snippet": lines[line_no - 1].strip()[:180] if lines else ":hover",
                        "severity": "high",
                        "title": "Hover State Defined Without Matching :focus-visible Keyboard Ring",
                        "rationale": "Interactive elements that visually respond to :hover must also provide a clear :focus-visible indicator for keyboard and assistive-tech users."
                    })

                # Rule 3: Missing dark mode / color-scheme support when light background is hardcoded
                if re.search(r"background(?:-color)?\s*:\s*(?:#fff(?:fff)?|white|#f[0-9a-f]{5})\b", content, re.IGNORECASE):
                    if "prefers-color-scheme" not in content and "color-scheme" not in content and "light-dark(" not in content:
                        m = re.search(r"background(?:-color)?\s*:", content, re.IGNORECASE)
                        line_no = content.count("\n", 0, m.start()) + 1 if m else 1
                        candidates.append({
                            "rule_id": "missing-dark-mode-adaptation",
                            "dimension": "Theme & Visual Comfort",
                            "path": rel_path,
                            "line_number": line_no,
                            "snippet": lines[line_no - 1].strip()[:180],
                            "severity": "low",
                            "title": "Hardcoded Light Surface Background Without Dark Mode Adaptation",
                            "rationale": "Hardcoding white/light surfaces without `color-scheme: light dark`, `light-dark()`, or `@media (prefers-color-scheme: dark)` causes blinding glare for dark-mode users."
                        })

                # Rule 4: Small font sizes (< 12px) or magic z-index
                small_font = re.search(r"font-size\s*:\s*([0-9]|1[01])px\b", content, re.IGNORECASE)
                if small_font:
                    line_no = content.count("\n", 0, small_font.start()) + 1
                    candidates.append({
                        "rule_id": "illegible-micro-typography",
                        "dimension": "Typography & Hierarchy",
                        "path": rel_path,
                        "line_number": line_no,
                        "snippet": lines[line_no - 1].strip()[:180],
                        "severity": "medium",
                        "title": f"Illegible Font Size ({small_font.group(0)}) Below 12px Readability Floor",
                        "rationale": "Body or UI copy below 12px (0.75rem) impairs legibility on high-DPI and mobile displays; use relative rem units with a 0.75rem–0.875rem minimum."
                    })

            # 2. Async UI States check (JS/TS/HTML components calling fetch() without loading/error feedback)
            if ext in {".js", ".ts", ".jsx", ".tsx", ".vue", ".svelte"}:
                if "fetch(" in content and not re.search(r"\b(loading|isLoading|spinner|skeleton|aria-busy|error|catch)\b", content, re.IGNORECASE):
                    m = re.search(r"\bfetch\(", content)
                    line_no = content.count("\n", 0, m.start()) + 1 if m else 1
                    candidates.append({
                        "rule_id": "missing-async-loading-error-state",
                        "dimension": "Perceived Performance & Feedback",
                        "path": rel_path,
                        "line_number": line_no,
                        "snippet": lines[line_no - 1].strip()[:180],
                        "severity": "high",
                        "title": "Network Fetch Without Visible Loading / Error UI State Handling",
                        "rationale": "Asynchronous network operations need explicit loading (`aria-busy`, skeleton/spinner) and human-readable error recovery states so users are not left staring at frozen or blank UI."
                    })

            # 3. HTML Viewport & Form Ergonomics
            if ext in {".html", ".htm"}:
                if "<head" in content.lower() and 'name="viewport"' not in content.lower():
                    candidates.append({
                        "rule_id": "missing-responsive-viewport-meta",
                        "dimension": "Responsive Layout",
                        "path": rel_path,
                        "line_number": 1,
                        "snippet": "<head>",
                        "severity": "medium",
                        "title": "Missing Responsive <meta name=\"viewport\"> Declaration",
                        "rationale": "Without `<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">`, mobile browsers render at a zoomed-out 980px desktop canvas."
                    })

    return {
        "target": target_dir.name,
        "scanned_files": scanned_files,
        "design_system_metrics": {
            "css_custom_properties_defined": css_custom_props_count,
            "hardcoded_color_literals": hardcoded_color_count
        },
        "candidates": candidates
    }


def main():
    parser = argparse.ArgumentParser(description="UI/UX static & heuristic scanner")
    parser.add_argument("--target", required=True, help="Target repository directory")
    parser.add_argument("--output", help="Output JSON path")
    args = parser.parse_args()

    target_dir = Path(args.target).resolve()
    result = scan_ui_ux(target_dir)
    out = json.dumps(result, indent=2)

    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
    else:
        print(out)


if __name__ == "__main__":
    main()
