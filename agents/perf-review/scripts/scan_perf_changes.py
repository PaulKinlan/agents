#!/usr/bin/env python3
"""Deterministic Pre-Pass for Recent-Change Performance Review (agents/perf-review/scripts/scan_perf_changes.py)

Inspects recent git commits and working-tree changes (`git diff`, `git log -n 5`),
analyzes touched files for performance regressions and hot-path hazards (layout
thrashing, render-blocking scripts/styles, LCP/CLS image regressions, sequential
async waterfalls, main-thread INP bottlenecks, and heavy synchronous imports),
and emits candidate findings with surrounding context so the model can synthesize
exact code fixes.
"""

import argparse
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Set

IGNORE_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", ".next", ".nuxt",
    "coverage", ".venv", "venv", "__pycache__", ".beads", "runs"
}

CODE_EXTS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".html", ".css", ".py", ".go"}

PERF_RULES = [
    {
        "rule_id": "layout-thrashing-forced-reflow",
        "title": "Forced Synchronous Layout / Reflow Hazard",
        "exts": {".js", ".mjs", ".ts", ".tsx", ".jsx"},
        "pattern": re.compile(r"\b(offsetWidth|offsetHeight|clientWidth|clientHeight|getBoundingClientRect|getComputedStyle|scrollTop|scrollHeight)\b"),
        "severity": "high",
        "category": "INP / Rendering",
        "suggestion": "Batch DOM geometry reads before any DOM style/layout writes, or use ResizeObserver / IntersectionObserver / CSS Anchor Positioning instead of synchronous layout queries."
    },
    {
        "rule_id": "sequential-await-waterfall",
        "title": "Sequential Await inside Iteration / Network Waterfall",
        "exts": {".js", ".mjs", ".ts", ".tsx", ".jsx", ".py"},
        "pattern": re.compile(r"(?:for\s*\([^)]*\)|while\s*\([^)]*\))[\s\S]{0,160}\bawait\s+"),
        "severity": "high",
        "category": "Latency / Waterfall",
        "suggestion": "Replace sequential `await` inside loops with concurrent execution via `await Promise.all(items.map(...))` (or `asyncio.gather` in Python) where operations are independent."
    },
    {
        "rule_id": "render-blocking-head-asset",
        "title": "Render-Blocking Script or CSS @import on Critical Path",
        "exts": {".html", ".css"},
        "pattern": re.compile(r"(<script\b(?![^>]*(?:defer|async|type=['\"]module['\"]))[^>]+src=['\"][^'\"]+['\"][^>]*>|@import\s+url\()", re.IGNORECASE),
        "severity": "high",
        "category": "LCP / FCP",
        "suggestion": "Add `defer` or `type=\"module\"` to `<script>` tags in `<head>`, and replace CSS `@import` chains with parallel `<link rel=\"stylesheet\">` or `<link rel=\"preload\">` tags."
    },
    {
        "rule_id": "lcp-cls-unoptimized-media",
        "title": "Image / Media Missing Explicit Dimensions (CLS) or Fetch Priority (LCP)",
        "exts": {".html", ".jsx", ".tsx", ".vue", ".svelte"},
        "pattern": re.compile(r"<img\b(?![^>]*\bwidth=)(?![^>]*\baspect-ratio)[^>]+src=", re.IGNORECASE),
        "severity": "medium",
        "category": "LCP / CLS",
        "suggestion": "Add explicit `width` and `height` attributes (or CSS `aspect-ratio`) to reserve layout space and prevent Cumulative Layout Shift (CLS); add `fetchpriority=\"high\"` to hero LCP images."
    },
    {
        "rule_id": "unthrottled-high-frequency-listener",
        "title": "Unthrottled High-Frequency Event Listener (scroll/mousemove/resize/input)",
        "exts": {".js", ".mjs", ".ts", ".tsx", ".jsx"},
        "pattern": re.compile(r"addEventListener\(\s*['\"](?:scroll|mousemove|pointermove|resize|touchmove)['\"]"),
        "severity": "medium",
        "category": "INP / Main Thread",
        "suggestion": "Pass `{ passive: true }` to scroll/touch listeners, debounce/throttle via `requestAnimationFrame`, or migrate visual scroll effects to CSS `animation-timeline: scroll()`."
    },
    {
        "rule_id": "heavy-json-or-regex-in-hotpath",
        "title": "Expensive Synchronous JSON Clone or Uncompiled Regex in Hot Path",
        "exts": {".js", ".mjs", ".ts", ".tsx", ".jsx"},
        "pattern": re.compile(r"(?:JSON\.parse\(\s*JSON\.stringify\(|new\s+RegExp\([^)]+\))"),
        "severity": "medium",
        "category": "CPU / Main Thread",
        "suggestion": "Use native `structuredClone()` instead of `JSON.parse(JSON.stringify(...))`, and hoist `new RegExp(...)` compilation to module scope."
    }
]


def get_recent_git_context(target_dir: Path) -> Dict[str, Any]:
    """Gather recent commits, changed files, and diff summary."""
    recent_commits = []
    changed_files: Set[str] = set()
    diff_excerpt = ""

    try:
        log_res = subprocess.run(
            ["git", "log", "-n", "5", "--oneline"],
            cwd=str(target_dir), capture_output=True, text=True, timeout=5
        )
        if log_res.returncode == 0:
            recent_commits = [line.strip() for line in log_res.stdout.splitlines() if line.strip()]

        # Working tree + last 3 commits changed files
        for cmd in [
            ["git", "diff", "--name-only"],
            ["git", "diff", "--name-only", "HEAD~3..HEAD"],
            ["git", "diff", "--name-only", "HEAD~1..HEAD"]
        ]:
            res = subprocess.run(cmd, cwd=str(target_dir), capture_output=True, text=True, timeout=5)
            if res.returncode == 0 and res.stdout.strip():
                for f in res.stdout.splitlines():
                    if f.strip():
                        changed_files.add(f.strip())

        diff_res = subprocess.run(
            ["git", "diff", "HEAD~1..HEAD", "--unified=2"],
            cwd=str(target_dir), capture_output=True, text=True, timeout=5
        )
        if diff_res.returncode == 0:
            diff_excerpt = diff_res.stdout[:6000]
    except Exception:
        pass

    return {
        "recent_commits": recent_commits,
        "changed_files": sorted(changed_files),
        "diff_excerpt": diff_excerpt
    }


def scan_files(target_dir: Path, priority_files: List[str]) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    priority_set = set(priority_files)

    # Collect files to inspect: prioritize recently modified files first, then rest of repo
    all_files: List[Path] = []
    for rel in priority_files:
        p = target_dir / rel
        if p.exists() and p.is_file() and p.suffix.lower() in CODE_EXTS:
            all_files.append(p)

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for fname in sorted(files):
            fpath = Path(root) / fname
            if fpath.suffix.lower() in CODE_EXTS and fpath not in all_files:
                all_files.append(fpath)

    for fpath in all_files[:80]:
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        rel_path = str(fpath.relative_to(target_dir))
        in_recent_diff = rel_path in priority_set
        lines = content.splitlines()

        for rule in PERF_RULES:
            if fpath.suffix.lower() not in rule["exts"]:
                continue
            for m in rule["pattern"].finditer(content):
                line_no = content.count("\n", 0, m.start()) + 1
                start_idx = max(0, line_no - 3)
                end_idx = min(len(lines), line_no + 3)
                context_window = "\n".join(lines[start_idx:end_idx])
                snippet = lines[line_no - 1].strip() if 0 <= line_no - 1 < len(lines) else m.group(0)

                candidates.append({
                    "rule_id": rule["rule_id"],
                    "title": rule["title"],
                    "category": rule["category"],
                    "path": rel_path,
                    "line_number": line_no,
                    "touched_in_recent_commits": in_recent_diff,
                    "snippet": snippet[:200],
                    "context_window": context_window[:500],
                    "severity": "high" if (in_recent_diff and rule["severity"] == "medium") else rule["severity"],
                    "suggestion": rule["suggestion"]
                })
                break

    # Sort so findings in recently changed files appear first
    candidates.sort(key=lambda c: (not c["touched_in_recent_commits"], c["severity"] != "high"))
    return candidates


def main():
    parser = argparse.ArgumentParser(description="Performance change review deterministic scanner")
    parser.add_argument("--target", required=True, help="Target repository path")
    parser.add_argument("--output", help="Output JSON path")
    args = parser.parse_args()

    target_dir = Path(args.target).resolve()
    git_ctx = get_recent_git_context(target_dir)
    candidates = scan_files(target_dir, git_ctx["changed_files"])

    payload = {
        "target": target_dir.name,
        "recent_commits": git_ctx["recent_commits"],
        "recently_changed_files": git_ctx["changed_files"],
        "recent_diff_excerpt": git_ctx["diff_excerpt"],
        "candidates": candidates
    }

    out = json.dumps(payload, indent=2)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
    else:
        print(out)


if __name__ == "__main__":
    main()
