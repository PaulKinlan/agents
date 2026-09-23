#!/usr/bin/env python3
"""Deterministic documentation drift scanner for docs-drift agent.

Pre-pass scanner that inspects markdown documentation files (README.md,
docs/*.md, AGENTS.md, etc.) and extracts:
1. Markdown links (file targets and anchor references)
2. Referenced file and directory paths in code blocks, tree diagrams, and inline backticks
3. Code symbols (functions, classes)
4. CLI commands and flags

Checks all references against actual repository files, git status/history,
and source code to detect broken links, deleted references, and doc drift.
Outputs candidate matches as JSON.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

IGNORE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build",
    "__pycache__", ".beads", ".agent-state", "runs", "findings", "scratch"
}

IGNORE_SYMBOLS = {
    "JSON", "YAML", "SHA256", "UUID", "HTTP", "HTTPS", "OAuth", "REST",
    "HTML", "CSS", "API", "CLI", "Git", "GitHub", "Actions", "Boolean",
    "String", "Array", "Object", "True", "False", "None", "Null", "Nil",
    "GET", "POST", "PUT", "DELETE", "HEAD", "PR", "PRs", "SDLC", "CI", "CD",
    "Markdown", "Linux", "Darwin", "macOS", "Windows", "Keychain", "Plan",
    "Factory", "Agent", "Line", "Sinks", "Engines", "Catalogue", "Triage",
    "Model", "Engine", "Sink", "Target", "Rule", "Status", "Important", "Note",
    "Warning", "Caution", "Tip", "Auto", "Local", "Both"
}

EXTERNAL_REPO_INDICATORS = {
    "chrome-agent-platform", "fauxmium", "@puppeteer", "anthropics/",
    "google-github-actions/", "actions/"
}

def is_ignored_doc(p: Path, target_dir: Path) -> bool:
    """Check if document file is in an ignored directory."""
    try:
        rel = p.relative_to(target_dir)
        return any(part in IGNORE_DIRS or (part.startswith(".") and part != ".") for part in rel.parts)
    except ValueError:
        return False

def slugify_heading(heading: str) -> str:
    """Converts a markdown heading text into a GitHub anchor slug."""
    text = heading.strip().lower()
    text = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", text)
    text = re.sub(r"[`*_#]", "", text)
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s]+", "-", text)
    return text.strip("-")

def get_markdown_headings(file_path: Path) -> Set[str]:
    """Extract all heading anchor slugs from a markdown file."""
    slugs = set()
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return slugs

    for line in content.splitlines():
        line = line.strip()
        if line.startswith("#"):
            heading_text = line.lstrip("#").strip()
            slug = slugify_heading(heading_text)
            if slug:
                slugs.add(slug)
    return slugs

def git_tracked_or_deleted(target_dir: Path, rel_path: str) -> Tuple[bool, bool]:
    """Check if git tracks or previously tracked/deleted this file.
    
    Returns (currently_tracked, previously_tracked).
    """
    clean_path = rel_path.strip().lstrip("./")
    cmd_ls = ["git", "-C", str(target_dir), "ls-files", clean_path]
    try:
        res = subprocess.run(cmd_ls, capture_output=True, text=True, check=False)
        if res.stdout.strip():
            return True, True
    except Exception:
        pass

    cmd_log = ["git", "-C", str(target_dir), "log", "-1", "--all", "--", clean_path]
    try:
        res = subprocess.run(cmd_log, capture_output=True, text=True, check=False)
        if res.stdout.strip():
            return False, True
    except Exception:
        pass

    return False, False

def expand_path_braces(path_str: str) -> List[str]:
    """Expands brace expressions like lib/adapters/{antigravity,claude,pi}.sh"""
    match = re.search(r"\{([^}]+)\}", path_str)
    if not match:
        return [path_str]
    prefix = path_str[:match.start()]
    suffix = path_str[match.end():]
    options = [opt.strip() for opt in match.group(1).split(",")]
    results = []
    for opt in options:
        sub_paths = expand_path_braces(f"{prefix}{opt}{suffix}")
        results.extend(sub_paths)
    return results

def path_exists_or_matches(target_dir: Path, doc_dir: Path, path_str: str) -> Tuple[bool, bool]:
    """Checks if a path or path template exists.
    
    Returns (exists, was_wildcard).
    """
    clean_p = path_str.strip()
    if clean_p.endswith("/"):
        clean_p = clean_p[:-1]

    # Handle template wildcards like <name>, <project>, <target>, *
    if re.search(r"<[^>]+>|\*", clean_p):
        glob_pattern = re.sub(r"<[^>]+>", "*", clean_p)
        matches_root = list(target_dir.glob(glob_pattern))
        matches_doc = list(doc_dir.glob(glob_pattern))
        return (len(matches_root) > 0 or len(matches_doc) > 0), True

    # Direct path checks (doc-relative or repo-relative)
    p1 = (doc_dir / clean_p).resolve()
    p2 = (target_dir / clean_p).resolve()

    try:
        if p1.exists():
            return True, False
    except Exception:
        pass

    try:
        if p2.exists():
            return True, False
    except Exception:
        pass

    # Bare filename search across target repo
    if "/" not in clean_p and "." in clean_p:
        try:
            matches = list(target_dir.rglob(clean_p))
            valid_matches = [m for m in matches if ".git" not in m.parts]
            if valid_matches:
                return True, False
        except Exception:
            pass

    return False, False

def parse_tree_diagrams(content: str) -> List[Tuple[int, str, str]]:
    """Parses ASCII tree diagrams in code blocks and extracts referenced paths.
    
    Returns list of (line_number, full_path, raw_line).
    """
    in_block = False
    stack: List[Tuple[int, str]] = []  # (depth, dir_name)
    tree_items: List[Tuple[int, str, str]] = []
    has_root = False

    for line_idx, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("```"):
            in_block = not in_block
            stack = []
            has_root = False
            continue

        if not in_block:
            continue

        # Check for root directory of the tree diagram (e.g. agents/<name>/ or ~/agents/)
        if not stack and not any(c in line for c in ["├──", "└──", "│"]):
            root_m = re.match(r"^([a-zA-Z0-9_.~/{}<>-]+/[*]?)(?:\s+#.*)?$", stripped)
            if root_m:
                root_name = root_m.group(1).strip()
                has_root = True
                # Normalize ~/agents/ -> repo root
                if root_name in ["~/agents/", "agents/", "./"]:
                    stack.append((0, ""))
                else:
                    stack.append((0, root_name))
                continue

        if any(c in line for c in ["├──", "└──", "│"]):
            m = re.match(r"^([├└│─\s]*?)(?:├──|└──)\s*([a-zA-Z0-9_./{},<>*@~-]+)(?:\s+#.*)?$", line)
            if not m:
                continue
            prefix = m.group(1)
            name = m.group(2).strip()

            clean_prefix = re.sub(r"[─]", " ", prefix)
            base_depth = 1 if has_root else 0
            depth = (len(clean_prefix) // 4) + base_depth

            while stack and stack[-1][0] >= depth:
                stack.pop()

            prefix_dirs = [s[1].rstrip("/") for s in stack if s[1]]
            full_path = "/".join(prefix_dirs + [name]) if prefix_dirs else name
            if name.endswith("/"):
                stack.append((depth, name))

            tree_items.append((line_idx, full_path, line.strip()))

    return tree_items

def scan_target(target_dir: Path) -> List[Dict[str, Any]]:
    candidates = []

    # 1. Discover all documentation files
    doc_files: List[Path] = []
    source_files: List[Path] = []
    
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]
        for file in files:
            fp = Path(root) / file
            ext = fp.suffix.lower()
            if ext == ".md":
                doc_files.append(fp)
            elif ext in {".py", ".sh", ".ts", ".js", ".json", ".yaml", ".yml", ".go", ".rs"}:
                source_files.append(fp)

    # Pre-cache source file contents for symbol lookup
    source_cache: Dict[str, str] = {}
    for sf in source_files:
        try:
            if sf.stat().st_size < 1024 * 1024:
                source_cache[str(sf.relative_to(target_dir))] = sf.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

    # Pre-cache headings in markdown files
    headings_cache: Dict[Path, Set[str]] = {}
    for df in doc_files:
        headings_cache[df] = get_markdown_headings(df)

    # 2. Inspect each documentation file
    for doc_path in doc_files:
        if is_ignored_doc(doc_path, target_dir):
            continue

        rel_doc = str(doc_path.relative_to(target_dir))
        doc_dir = doc_path.parent
        try:
            content = doc_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        # Check ASCII directory tree blocks
        tree_entries = parse_tree_diagrams(content)
        for line_idx, tree_path, raw_line in tree_entries:
            if tree_path.startswith("~"):
                continue
            expanded = expand_path_braces(tree_path)
            for exp_p in expanded:
                exists, _ = path_exists_or_matches(target_dir, doc_dir, exp_p)
                if not exists:
                    _, was_deleted = git_tracked_or_deleted(target_dir, exp_p)
                    rule_id = "doc-deleted-reference" if was_deleted else "doc-missing-file"
                    candidates.append({
                        "rule_id": rule_id,
                        "path": rel_doc,
                        "line_number": line_idx,
                        "snippet": raw_line[:200],
                        "reference": exp_p,
                        "reference_type": "file_path",
                        "severity": "medium",
                        "title": f"Specification Drift: Missing '{exp_p}'",
                        "description": f"Repository layout in {rel_doc} specifies '{exp_p}', which does not exist in the codebase.",
                        "remediation": f"Implement '{exp_p}' or update specification diagram to mark as planned/future."
                    })

        # Process lines
        lines = content.splitlines()
        for line_idx, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str:
                continue

            # A. Check markdown links: [text](target)
            link_matches = re.finditer(r"\[([^\]]+)\]\(([^)]+)\)", line)
            for lm in link_matches:
                link_text = lm.group(1).strip()
                raw_target = lm.group(2).strip()

                if raw_target.startswith(("http://", "https://", "mailto:", "ftp:", "javascript:")):
                    continue

                # Same-document anchor: #anchor
                if raw_target.startswith("#"):
                    anchor = raw_target.lstrip("#").lower()
                    doc_slugs = headings_cache.get(doc_path, set())
                    if anchor and anchor not in doc_slugs:
                        candidates.append({
                            "rule_id": "doc-broken-anchor",
                            "path": rel_doc,
                            "line_number": line_idx,
                            "snippet": line_str[:200],
                            "reference": raw_target,
                            "reference_type": "anchor",
                            "severity": "low",
                            "title": f"Broken Section Anchor '#{anchor}'",
                            "description": f"Anchor '#{anchor}' referenced in [{link_text}]({raw_target}) not found in {rel_doc}.",
                            "remediation": f"Update heading or fix anchor slug to match headings in {rel_doc}."
                        })
                    continue

                # File link, possibly with anchor: file.md#anchor
                target_parts = raw_target.split("#", 1)
                file_target = target_parts[0].strip()
                anchor_target = target_parts[1].strip().lower() if len(target_parts) > 1 else None

                if file_target:
                    resolved_file = None
                    p1 = (doc_dir / file_target).resolve()
                    p2 = (target_dir / file_target.lstrip("/")).resolve()

                    if p1.exists() and p1.is_file():
                        resolved_file = p1
                    elif p2.exists() and p2.is_file():
                        resolved_file = p2

                    if resolved_file is None:
                        _, previously_tracked = git_tracked_or_deleted(target_dir, file_target)
                        rule_id = "doc-deleted-reference" if previously_tracked else "doc-broken-link"
                        sev = "high" if "README" in rel_doc or "AGENTS" in rel_doc else "medium"
                        candidates.append({
                            "rule_id": rule_id,
                            "path": rel_doc,
                            "line_number": line_idx,
                            "snippet": line_str[:200],
                            "reference": file_target,
                            "reference_type": "file_link",
                            "severity": sev,
                            "title": f"Broken File Link '{file_target}'",
                            "description": f"Link target '{file_target}' in {rel_doc} does not exist on disk" +
                                           (" (previously existed in git history)." if previously_tracked else "."),
                            "remediation": f"Correct the relative path or remove reference to deleted file."
                        })
                    elif anchor_target:
                        target_slugs = headings_cache.get(resolved_file)
                        if target_slugs is None:
                            target_slugs = get_markdown_headings(resolved_file)
                            headings_cache[resolved_file] = target_slugs
                        if anchor_target not in target_slugs:
                            candidates.append({
                                "rule_id": "doc-broken-anchor",
                                "path": rel_doc,
                                "line_number": line_idx,
                                "snippet": line_str[:200],
                                "reference": raw_target,
                                "reference_type": "anchor",
                                "severity": "low",
                                "title": f"Broken Section Anchor '#{anchor_target}' in '{file_target}'",
                                "description": f"File '{file_target}' exists, but section anchor '#{anchor_target}' was not found.",
                                "remediation": f"Update anchor to match actual section title in '{file_target}'."
                            })

            # B. Check inline backticks for referenced paths, files, and commands
            backticks = re.findall(r"`([^`\n]+)`", line)
            for item in backticks:
                item_clean = item.strip()
                if not item_clean or len(item_clean) < 3:
                    continue

                if item_clean.startswith(("http:", "https:", "~", "/dev", "/tmp", "/etc", "/usr", "$")):
                    continue
                if any(op in item_clean for op in ["->", "=>", "==", "!=", "<=", ">="]):
                    continue
                if any(ext_ind in item_clean for ext_ind in EXTERNAL_REPO_INDICATORS):
                    continue

                # Check if it looks like a path
                looks_like_path = False
                has_slash = "/" in item_clean and not item_clean.startswith("/")
                has_ext = any(item_clean.endswith(ext) for ext in [
                    ".py", ".sh", ".json", ".yaml", ".yml", ".md", ".ts", ".js", ".plist", ".toml"
                ])

                if (has_slash or has_ext) and not any(c in item_clean for c in [" ", "|", ";", '"', "'"]):
                    looks_like_path = True

                if looks_like_path:
                    expanded_paths = expand_path_braces(item_clean)
                    for exp_p in expanded_paths:
                        exists, is_wc = path_exists_or_matches(target_dir, doc_dir, exp_p)
                        if not exists:
                            _, was_deleted = git_tracked_or_deleted(target_dir, exp_p)
                            rule_id = "doc-deleted-reference" if was_deleted else "doc-missing-file"
                            candidates.append({
                                "rule_id": rule_id,
                                "path": rel_doc,
                                "line_number": line_idx,
                                "snippet": line_str[:200],
                                "reference": exp_p,
                                "reference_type": "file_path",
                                "severity": "medium",
                                "title": f"Missing Referenced File '{exp_p}'",
                                "description": f"Document references path '{exp_p}', which does not exist in repository.",
                                "remediation": f"Create the missing file or update documentation to reflect actual path."
                            })

                # C. Check for documented functions/classes: foo() or CamelCaseClass
                fn_match = re.match(r"^([a-zA-Z_][a-zA-Z0-9_]{3,})\(\)$", item_clean)
                if fn_match:
                    fn_name = fn_match.group(1)
                    if fn_name not in IGNORE_SYMBOLS:
                        found = any(fn_name in content for content in source_cache.values())
                        if not found:
                            candidates.append({
                                "rule_id": "doc-missing-symbol",
                                "path": rel_doc,
                                "line_number": line_idx,
                                "snippet": line_str[:200],
                                "reference": f"{fn_name}()",
                                "reference_type": "symbol",
                                "severity": "medium",
                                "title": f"Missing Referenced Function '{fn_name}()'",
                                "description": f"Document mentions function '{fn_name}()', but it was not found in source code.",
                                "remediation": f"Verify whether '{fn_name}' was renamed, removed, or has yet to be implemented."
                            })

                if re.match(r"^[A-Z][a-zA-Z0-9]+(?:Store|Adapter|Manager|Runner|Report|Scanner|Service|Client)$", item_clean):
                    class_name = item_clean
                    if class_name not in IGNORE_SYMBOLS:
                        found = any(class_name in content for content in source_cache.values())
                        if not found:
                            candidates.append({
                                "rule_id": "doc-missing-symbol",
                                "path": rel_doc,
                                "line_number": line_idx,
                                "snippet": line_str[:200],
                                "reference": class_name,
                                "reference_type": "symbol",
                                "severity": "medium",
                                "title": f"Missing Referenced Symbol '{class_name}'",
                                "description": f"Document references symbol '{class_name}', but it was not found in codebase.",
                                "remediation": f"Check if symbol '{class_name}' was renamed or deleted."
                            })

    return candidates

def main():
    parser = argparse.ArgumentParser(description="Deterministic doc drift scanner for docs-drift agent")
    parser.add_argument("--target", required=True, help="Target repository directory")
    parser.add_argument("--output", help="Path to output JSON file (default: stdout)")
    args = parser.parse_args()

    target_dir = Path(args.target).resolve()
    if not target_dir.exists():
        sys.stderr.write(f"Target directory not found: {target_dir}\n")
        sys.exit(1)

    candidates = scan_target(target_dir)

    result = {
        "target": str(target_dir),
        "scanner": "check_docs.py",
        "candidate_count": len(candidates),
        "candidates": candidates
    }

    output_json = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(output_json, encoding="utf-8")
    else:
        print(output_json)

if __name__ == "__main__":
    main()
