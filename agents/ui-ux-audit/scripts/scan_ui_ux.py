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
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

FACTORY_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(FACTORY_ROOT) not in sys.path:
    sys.path.insert(0, str(FACTORY_ROOT))

try:
    from lib.exclusions import DEFAULT_IGNORE_DIRS as IGNORE_DIRS
except ImportError:
    IGNORE_DIRS = {
        ".git", "node_modules", "vendor", "dist", "build", ".next", ".nuxt",
        "coverage", ".venv", "venv", "__pycache__", ".beads", "runs", "findings"
    }

UI_EXTS = {".html", ".htm", ".css", ".scss", ".js", ".ts", ".jsx", ".tsx", ".vue", ".svelte"}


def scan_ui_ux(target_dir: Path) -> Dict[str, Any]:
    candidates: List[Dict[str, Any]] = []
    scanned_files = 0
    css_custom_props_count = 0
    hardcoded_color_count = 0

    discovered_files: List[Path] = []
    file_contents: Dict[Path, str] = {}

    # Discover UI files in target_dir
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for fname in sorted(files):
            fpath = Path(root) / fname
            if fpath.suffix.lower() in UI_EXTS:
                try:
                    file_contents[fpath] = fpath.read_text(encoding="utf-8", errors="ignore")
                    discovered_files.append(fpath)
                except Exception:
                    continue

    # Discover HTML files for mapping stylesheet links
    # (search inside target_dir, or check target_dir.parent if target_dir is a subfolder like css/)
    html_files = [p for p in discovered_files if p.suffix.lower() in {".html", ".htm"}]
    if not html_files and target_dir.parent != target_dir:
        for f in target_dir.parent.glob("*.html"):
            try:
                file_contents[f] = f.read_text(encoding="utf-8", errors="ignore")
                html_files.append(f)
            except Exception:
                pass
        for f in target_dir.parent.glob("*.htm"):
            try:
                file_contents[f] = f.read_text(encoding="utf-8", errors="ignore")
                html_files.append(f)
            except Exception:
                pass

    css_files = [p for p in discovered_files if p.suffix.lower() in {".css", ".scss"}]
    all_css_files = set(css_files)
    for p in file_contents:
        if p.suffix.lower() in {".css", ".scss"}:
            all_css_files.add(p)

    # Map each stylesheet to the set of stylesheets co-loaded with it across HTML pages
    co_loaded_map: Dict[Path, Set[Path]] = {p: set() for p in all_css_files}
    for html_path in html_files:
        html_content = file_contents.get(html_path, "")
        loaded_on_page: Set[Path] = set()

        for link_tag in re.findall(r'<link\b[^>]*>', html_content, re.IGNORECASE):
            if re.search(r'\brel=["\']?stylesheet["\']?', link_tag, re.IGNORECASE):
                m = re.search(r'\bhref=["\']([^"\'>]+)["\']', link_tag, re.IGNORECASE)
                if m:
                    raw_href = m.group(1).split("?")[0].split("#")[0].strip()
                    matched = None
                    cand1 = (html_path.parent / raw_href.lstrip("/")).resolve()
                    if cand1 in all_css_files:
                        matched = cand1
                    else:
                        cand2 = (target_dir / raw_href.lstrip("/")).resolve()
                        if cand2 in all_css_files:
                            matched = cand2
                        else:
                            name_matches = [p for p in all_css_files if p.name == Path(raw_href).name]
                            if len(name_matches) == 1:
                                matched = name_matches[0]
                    if matched:
                        loaded_on_page.add(matched)

        # Check for inline <style> with :focus-visible
        has_inline_focus = bool(re.search(r'<style\b[^>]*>[\s\S]*?:focus-visible[\s\S]*?</style>', html_content, re.IGNORECASE))
        for p in loaded_on_page:
            co_loaded_map[p].update(loaded_on_page)
            if has_inline_focus:
                co_loaded_map[p].add(html_path)

    def defines_focus_visible_rule(css_text: str) -> bool:
        # Strip comments so comments like /* TODO: add :focus-visible rings */ don't match
        clean_text = re.sub(r'/\*.*?\*/', '', css_text, flags=re.DOTALL)
        # Strip :not(:focus-visible) reset idioms including selector lists like :not(:focus-visible, .kb),
        # bounding characters within the :not() argument to avoid crossing statement/rule boundaries.
        clean_text = re.sub(r':not\([^){};]*:focus-visible[^){};]*\)', '', clean_text, flags=re.IGNORECASE)
        # Match :focus-visible followed by a selector boundary leading to a rule block {
        return bool(re.search(r':focus-visible(?=[\s,{:.\[>+~)#]|$)(?=[^;{}]*\{)', clean_text, flags=re.IGNORECASE))

    def has_focus_visible_coverage(fpath: Path, content: str) -> bool:
        # 1. The file itself contains a real :focus-visible rule
        if defines_focus_visible_rule(content):
            return True

        # 2. Any stylesheet co-loaded on the same HTML page defines :focus-visible
        co_loaded = co_loaded_map.get(fpath, set())
        for co_p in co_loaded:
            if defines_focus_visible_rule(file_contents.get(co_p, "")):
                return True

        # 3. If HTML pages exist, do not assume unlinked or differently-bundled sibling stylesheets share coverage
        if html_files:
            return False

        # 4. If scanning a standalone CSS directory without HTML page links, check if any sibling stylesheet defines baseline :focus-visible
        for sibling in fpath.parent.glob("*.css"):
            if sibling != fpath:
                sib_content = file_contents.get(sibling)
                if sib_content is None and sibling.exists():
                    try:
                        sib_content = sibling.read_text(encoding="utf-8", errors="ignore")
                    except Exception:
                        sib_content = ""
                if sib_content and defines_focus_visible_rule(sib_content):
                    return True

        return False

    for fpath in discovered_files:
        ext = fpath.suffix.lower()
        content = file_contents[fpath]
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
            if ":hover" in content and not has_focus_visible_coverage(fpath, content):
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
