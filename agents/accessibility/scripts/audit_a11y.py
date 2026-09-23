#!/usr/bin/env python3
"""Deterministic accessibility auditor pre-pass for Software Factory.

Scans HTML files and templates (pages/, extension/, views/, components/, public/)
for WCAG 2.1 AA accessibility violations:
  1. missing alt attributes on images/areas (WCAG 1.1.1)
  2. unlabelled buttons (WCAG 4.1.2)
  3. missing form labels on inputs/selects/textareas (WCAG 1.3.1, 3.3.2)
  4. missing or empty lang attributes on <html> (WCAG 3.1.1)
  5. positive tabindex (tabIndex > 0) (WCAG 2.4.3)
  6. non-semantic click handlers without keyboard accessibility (WCAG 2.1.1, 4.1.2)

Outputs structured candidate violations for model triage.
"""

import argparse
import json
import os
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

EXCLUDE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", ".beads", "runs", "scratch",
    "findings", "__pycache__", ".nyc_output", "coverage", "dist", "build", ".build"
}

HTML_EXTENSIONS = {
    ".html", ".htm", ".xhtml", ".vue", ".svelte", ".jsx", ".tsx",
    ".ejs", ".handlebars", ".hbs", ".mustache", ".jinja", ".jinja2", ".erb", ".php"
}

NON_SEMANTIC_CLICK_TAGS = {
    "div", "span", "p", "a", "li", "ul", "ol", "tr", "td", "th", "b", "i",
    "section", "article", "header", "footer", "main", "aside", "nav"
}

class A11yHTMLParser(HTMLParser):
    def __init__(self, rel_path: str, lines: List[str]):
        super().__init__()
        self.rel_path = rel_path
        self.lines = lines
        self.candidates: List[Dict[str, Any]] = []

        # State tracking
        self.label_for_ids: Set[str] = set()
        self.open_labels: int = 0
        self.form_controls: List[Dict[str, Any]] = []
        self.active_buttons: List[Dict[str, Any]] = []

    def get_snippet(self, line_number: int) -> str:
        if 1 <= line_number <= len(self.lines):
            return self.lines[line_number - 1].strip()[:200]
        return ""

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        line_no, _ = self.getpos()
        attrs_dict: Dict[str, str] = {k.lower(): (v or "") for k, v in attrs}
        snippet = self.get_snippet(line_no)

        # 1. Check missing lang attribute on <html>
        if tag.lower() == "html":
            lang = attrs_dict.get("lang", "").strip()
            xml_lang = attrs_dict.get("xml:lang", "").strip()
            if not lang and not xml_lang:
                self.candidates.append({
                    "rule_id": "missing-lang-attribute",
                    "path": self.rel_path,
                    "line_number": line_no,
                    "snippet": snippet or "<html>",
                    "tag": tag,
                    "wcag_criterion": "WCAG 2.1 AA 3.1.1 Language of Page",
                    "severity": "medium",
                    "title": f"Missing 'lang' Attribute on <html> Element: {self.rel_path}",
                    "description": "Root <html> element does not specify a language, preventing screen readers from choosing the correct pronunciation and inflection.",
                    "remediation": "Add a valid BCP 47 language code to the root element, e.g. `<html lang=\"en\">`."
                })

        # 2. Check missing alt attribute on <img>, <area>, <input type="image">
        if tag.lower() == "img":
            if "alt" not in attrs_dict:
                # If aria-hidden="true", decorative images may omit alt in some specs, but WCAG 1.1.1 requires alt="" or role="presentation"
                is_decorative = attrs_dict.get("role") in {"presentation", "none"} or attrs_dict.get("aria-hidden") == "true"
                if not is_decorative:
                    self.candidates.append({
                        "rule_id": "missing-alt-attribute",
                        "path": self.rel_path,
                        "line_number": line_no,
                        "snippet": snippet or f"<img src=\"{attrs_dict.get('src', '')}\">",
                        "tag": tag,
                        "wcag_criterion": "WCAG 2.1 AA 1.1.1 Non-text Content",
                        "severity": "medium",
                        "title": f"Missing 'alt' Attribute on <img>: {self.rel_path}:{line_no}",
                        "description": "Image element lacks an 'alt' attribute, leaving screen reader users without text alternatives.",
                        "remediation": "Provide descriptive alt text for informative images (`alt=\"Description\"`) or an empty alt string for decorative images (`alt=\"\" role=\"presentation\"`)."
                    })
        elif tag.lower() == "area" and "alt" not in attrs_dict:
            self.candidates.append({
                "rule_id": "missing-alt-attribute",
                "path": self.rel_path,
                "line_number": line_no,
                "snippet": snippet or "<area>",
                "tag": tag,
                "wcag_criterion": "WCAG 2.1 AA 1.1.1 Non-text Content",
                "severity": "medium",
                "title": f"Missing 'alt' Attribute on <area>: {self.rel_path}:{line_no}",
                "description": "Image map area lacks alternative text.",
                "remediation": "Add an `alt` attribute describing the destination or purpose of the area link."
            })

        # 3. Track <label> nesting and for attributes
        if tag.lower() == "label":
            self.open_labels += 1
            for_id = attrs_dict.get("for", "").strip()
            if for_id:
                self.label_for_ids.add(for_id)

        # 4. Check form controls for missing labels
        if tag.lower() in {"input", "select", "textarea"}:
            itype = attrs_dict.get("type", "text").lower()
            if itype == "image" and "alt" not in attrs_dict and "aria-label" not in attrs_dict:
                self.candidates.append({
                    "rule_id": "missing-alt-attribute",
                    "path": self.rel_path,
                    "line_number": line_no,
                    "snippet": snippet or f"<input type=\"image\">",
                    "tag": tag,
                    "wcag_criterion": "WCAG 2.1 AA 1.1.1 Non-text Content",
                    "severity": "high",
                    "title": f"Missing 'alt' on Image Input: {self.rel_path}:{line_no}",
                    "description": "Graphical submit button `<input type=\"image\">` lacks alternative text.",
                    "remediation": "Add an `alt` attribute describing the button's action (e.g. `alt=\"Search\"`)."
                })
            elif itype in {"button", "submit", "reset"}:
                val = attrs_dict.get("value", "").strip()
                aria_label = attrs_dict.get("aria-label", "").strip()
                aria_labelledby = attrs_dict.get("aria-labelledby", "").strip()
                title = attrs_dict.get("title", "").strip()
                if not (val or aria_label or aria_labelledby or title):
                    self.candidates.append({
                        "rule_id": "unlabelled-button",
                        "path": self.rel_path,
                        "line_number": line_no,
                        "snippet": snippet or f"<input type=\"{itype}\">",
                        "tag": tag,
                        "wcag_criterion": "WCAG 2.1 AA 4.1.2 Name, Role, Value",
                        "severity": "high",
                        "title": f"Unlabelled Input Button: {self.rel_path}:{line_no}",
                        "description": f"<input type=\"{itype}\"> has no accessible label or value.",
                        "remediation": f"Provide a visible `value=\"...\"` or `aria-label=\"...\"` attribute."
                    })
            elif itype != "hidden":
                # Stash for deferred check after full document parse to account for <label for="..."> following input
                self.form_controls.append({
                    "tag": tag,
                    "line_number": line_no,
                    "snippet": snippet,
                    "id": attrs_dict.get("id", "").strip(),
                    "aria_label": attrs_dict.get("aria-label", "").strip(),
                    "aria_labelledby": attrs_dict.get("aria-labelledby", "").strip(),
                    "title": attrs_dict.get("title", "").strip(),
                    "is_enclosed_in_label": self.open_labels > 0
                })

        # 5. Check <button> elements
        if tag.lower() == "button":
            has_aria = bool(attrs_dict.get("aria-label", "").strip() or attrs_dict.get("aria-labelledby", "").strip() or attrs_dict.get("title", "").strip())
            self.active_buttons.append({
                "line_number": line_no,
                "snippet": snippet or "<button>",
                "has_aria": has_aria,
                "text_content": ""
            })

        # 6. Check positive tabindex (tabindex > 0)
        if "tabindex" in attrs_dict:
            raw_val = attrs_dict["tabindex"].strip()
            try:
                tval = int(raw_val)
                if tval > 0:
                    self.candidates.append({
                        "rule_id": "positive-tabindex",
                        "path": self.rel_path,
                        "line_number": line_no,
                        "snippet": snippet or f"<{tag} tabindex=\"{tval}\">",
                        "tag": tag,
                        "wcag_criterion": "WCAG 2.1 AA 2.4.3 Focus Order",
                        "severity": "medium",
                        "title": f"Positive TabIndex Value ({tval}) Disrupts Focus Order: {self.rel_path}:{line_no}",
                        "description": f"Positive tabindex='{tval}' forces keyboard focus out of natural DOM reading sequence.",
                        "remediation": "Replace with `tabindex=\"0\"` to include in natural sequential focus order, or `tabindex=\"-1\"` for programmatic focus."
                    })
            except ValueError:
                pass

        # 7. Check non-semantic click handlers
        tlower = tag.lower()
        if tlower in NON_SEMANTIC_CLICK_TAGS:
            if tlower == "a" and "href" in attrs_dict:
                # <a> with href is already interactive
                pass
            else:
                has_click = any(
                    k in attrs_dict for k in [
                        "onclick", "@click", "v-on:click", "(click)", "ng-click", "on-click"
                    ]
                )
                if has_click:
                    role = attrs_dict.get("role", "").lower()
                    has_role = role in {"button", "link", "tab", "menuitem", "checkbox", "switch"}
                    has_tabindex = "tabindex" in attrs_dict
                    has_keyboard = any(
                        any(evt in k for evt in ["keydown", "keypress", "keyup"])
                        for k in attrs_dict
                    )
                    if not (has_role and has_tabindex):
                        self.candidates.append({
                            "rule_id": "non-semantic-click-handler",
                            "path": self.rel_path,
                            "line_number": line_no,
                            "snippet": snippet or f"<{tag} {attrs_dict.get('onclick', '')}>",
                            "tag": tag,
                            "wcag_criterion": "WCAG 2.1 AA 2.1.1 Keyboard & 4.1.2 Name, Role, Value",
                            "severity": "high",
                            "title": f"Non-Semantic Click Handler Without Keyboard Accessibility: {self.rel_path}:{line_no}",
                            "description": f"<{tag}> element has a click event handler but lacks semantic interactive role and keyboard accessibility.",
                            "remediation": f"Refactor into a `<button type=\"button\">` element, or add `role=\"button\" tabindex=\"0\"` and a `keydown` handler for Enter and Space keys."
                        })

    def handle_data(self, data: str):
        if self.active_buttons:
            self.active_buttons[-1]["text_content"] += data

    def handle_endtag(self, tag: str):
        if tag.lower() == "label" and self.open_labels > 0:
            self.open_labels -= 1

        if tag.lower() == "button" and self.active_buttons:
            btn = self.active_buttons.pop()
            # If button has no aria attribute and text content is empty / whitespace
            if not btn["has_aria"] and not btn["text_content"].strip():
                self.candidates.append({
                    "rule_id": "unlabelled-button",
                    "path": self.rel_path,
                    "line_number": btn["line_number"],
                    "snippet": btn["snippet"],
                    "tag": "button",
                    "wcag_criterion": "WCAG 2.1 AA 4.1.2 Name, Role, Value",
                    "severity": "high",
                    "title": f"Empty or Unlabelled <button>: {self.rel_path}:{btn['line_number']}",
                    "description": "Button element contains neither text content nor an aria-label/aria-labelledby attribute.",
                    "remediation": "Add descriptive inner text or an `aria-label=\"...\"` describing the action."
                })

    def finalize(self):
        # Evaluate form controls now that all <label for="..."> IDs have been collected
        for ctrl in self.form_controls:
            has_explicit_label = ctrl["id"] and ctrl["id"] in self.label_for_ids
            has_implicit_label = ctrl["is_enclosed_in_label"]
            has_aria = bool(ctrl["aria_label"] or ctrl["aria_labelledby"] or ctrl["title"])

            if not (has_explicit_label or has_implicit_label or has_aria):
                self.candidates.append({
                    "rule_id": "missing-form-label",
                    "path": self.rel_path,
                    "line_number": ctrl["line_number"],
                    "snippet": ctrl["snippet"] or f"<{ctrl['tag']}>",
                    "tag": ctrl["tag"],
                    "wcag_criterion": "WCAG 2.1 AA 1.3.1 Info and Relationships & 3.3.2 Labels or Instructions",
                    "severity": "high",
                    "title": f"Missing Form Label for <{ctrl['tag']}>: {self.rel_path}:{ctrl['line_number']}",
                    "description": f"Form control <{ctrl['tag']}> does not have an associated `<label for=\"...\">`, enclosing `<label>`, or `aria-label`.",
                    "remediation": f"Associate a `<label for=\"{ctrl['id'] or 'input-id'}\">` or add `aria-label=\"...\"`."
                })

def scan_file(file_path: Path, target_dir: Path) -> List[Dict[str, Any]]:
    rel_path = str(file_path.relative_to(target_dir))
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []

    lines = content.splitlines()
    parser = A11yHTMLParser(rel_path, lines)
    try:
        parser.feed(content)
        parser.close()
        parser.finalize()
        return parser.candidates
    except Exception as e:
        sys.stderr.write(f"HTMLParser warning on {rel_path}: {e}, falling back to regex scanner\n")
        return scan_file_regex(rel_path, lines)

def scan_file_regex(rel_path: str, lines: List[str]) -> List[Dict[str, Any]]:
    """Regex fallback for templates with broken/non-standard HTML tags."""
    candidates = []
    has_html_tag = False
    has_lang = False

    re_html = re.compile(r"""<html(?:\s+[^>]*)?>""", re.IGNORECASE)
    re_lang = re.compile(r"""\blang\s*=\s*['"][^'"]+['"]""", re.IGNORECASE)
    re_img_missing_alt = re.compile(r"""<img\b(?![^>]*\balt\b)[^>]*>""", re.IGNORECASE)
    re_tabindex = re.compile(r"""\btabindex\s*=\s*['"]([1-9][0-9]*)['"]""", re.IGNORECASE)
    re_onclick_div = re.compile(r"""<(?:div|span|p|li)\b[^>]*\bonclick\s*=[^>]*>""", re.IGNORECASE)

    for idx, line in enumerate(lines, start=1):
        # 1. <html> without lang
        m_html = re_html.search(line)
        if m_html:
            has_html_tag = True
            if re_lang.search(m_html.group(0)):
                has_lang = True
            else:
                candidates.append({
                    "rule_id": "missing-lang-attribute",
                    "path": rel_path,
                    "line_number": idx,
                    "snippet": line.strip()[:200],
                    "tag": "html",
                    "wcag_criterion": "WCAG 2.1 AA 3.1.1 Language of Page",
                    "severity": "medium",
                    "title": f"Missing 'lang' Attribute on <html>: {rel_path}:{idx}",
                    "description": "Root <html> element does not specify a language.",
                    "remediation": "Add `lang=\"en\"` to the <html> tag."
                })

        # 2. <img> without alt
        if re_img_missing_alt.search(line):
            candidates.append({
                "rule_id": "missing-alt-attribute",
                "path": rel_path,
                "line_number": idx,
                "snippet": line.strip()[:200],
                "tag": "img",
                "wcag_criterion": "WCAG 2.1 AA 1.1.1 Non-text Content",
                "severity": "medium",
                "title": f"Missing 'alt' on <img>: {rel_path}:{idx}",
                "description": "Image element lacks alt text attribute.",
                "remediation": "Add descriptive `alt=\"...\"` or `alt=\"\"` for decorative images."
            })

        # 3. Positive tabindex
        m_tab = re_tabindex.search(line)
        if m_tab:
            candidates.append({
                "rule_id": "positive-tabindex",
                "path": rel_path,
                "line_number": idx,
                "snippet": line.strip()[:200],
                "tag": "element",
                "wcag_criterion": "WCAG 2.1 AA 2.4.3 Focus Order",
                "severity": "medium",
                "title": f"Positive TabIndex Value ({m_tab.group(1)}): {rel_path}:{idx}",
                "description": "Positive tabindex disrupts natural keyboard navigation order.",
                "remediation": "Use `tabindex=\"0\"` or default sequential focus order."
            })

        # 4. Non-semantic click handler
        if re_onclick_div.search(line):
            candidates.append({
                "rule_id": "non-semantic-click-handler",
                "path": rel_path,
                "line_number": idx,
                "snippet": line.strip()[:200],
                "tag": "div/span",
                "wcag_criterion": "WCAG 2.1 AA 2.1.1 Keyboard",
                "severity": "high",
                "title": f"Non-Semantic Click Handler: {rel_path}:{idx}",
                "description": "Non-interactive element has an onclick listener.",
                "remediation": "Refactor to `<button type=\"button\">` or add role and keyboard handlers."
            })

    return candidates

def find_html_files(target_dir: Path) -> List[Path]:
    files = []
    
    # Priority directories
    priority_dirs = ["pages", "extension", "views", "templates", "components", "src", "public", "app"]
    
    # Track checked paths to avoid duplicates
    seen = set()

    for pdir in priority_dirs:
        dpath = target_dir / pdir
        if dpath.is_dir():
            for root, dirs, fnames in os.walk(dpath):
                dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".")]
                for fn in fnames:
                    p = Path(root) / fn
                    if p.suffix.lower() in HTML_EXTENSIONS and p not in seen:
                        seen.add(p)
                        files.append(p)

    # Also scan root HTML files
    for item in target_dir.glob("*.html"):
        if item.is_file() and item not in seen:
            seen.add(item)
            files.append(item)
    for item in target_dir.glob("*.htm"):
        if item.is_file() and item not in seen:
            seen.add(item)
            files.append(item)

    return files

def main():
    parser = argparse.ArgumentParser(description="Deterministic WCAG 2.1 AA accessibility scanner")
    parser.add_argument("--target-dir", "--target", dest="target_dir", required=True, help="Target repository directory")
    parser.add_argument("--output", help="Path to write JSON candidates output")
    args = parser.parse_args()

    target_dir = Path(args.target_dir).resolve()
    if not target_dir.exists():
        sys.stderr.write(f"Target directory not found: {target_dir}\n")
        sys.exit(1)

    html_files = find_html_files(target_dir)
    all_candidates = []

    for fpath in html_files:
        cand = scan_file(fpath, target_dir)
        all_candidates.extend(cand)

    result = {
        "target": target_dir.name,
        "scanned_files_count": len(html_files),
        "scanned_files": [str(p.relative_to(target_dir)) for p in html_files],
        "candidate_count": len(all_candidates),
        "candidates": all_candidates
    }

    output_json = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(output_json, encoding="utf-8")
    else:
        print(output_json)

if __name__ == "__main__":
    main()
