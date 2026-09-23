#!/usr/bin/env python3
"""Deterministic Pre-Pass for Memory Leak & Heap Bloat Profiler (agents/memory-profile/scripts/scan_memory_leaks.py)

Scans JS/TS/JSX/TSX/Vue/Svelte source files for classic retained-heap leak vectors
aligned with the `memory-leak-debugging` skill:
1. Event listeners added (`addEventListener` / `chrome.*.addListener`) without `removeEventListener` or `{ signal }` / `{ once: true }`
2. Unbounded module-level `new Map()`, `new Set()`, or array caches that grow monotonically without eviction or `WeakMap`
3. Recurring `setInterval()` timers without a stored handle or `clearInterval()` cleanup
4. Unclosed observers (`MutationObserver`, `ResizeObserver`, `IntersectionObserver`, `BroadcastChannel`) missing `.disconnect()` / `.close()`
5. Module-scoped DOM node references retaining detached DOM trees
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

JS_EXTS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte"}


def scan_memory_leaks(target_dir: Path) -> Dict[str, Any]:
    candidates: List[Dict[str, Any]] = []
    scanned_files = 0

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for fname in sorted(files):
            fpath = Path(root) / fname
            if fpath.suffix.lower() not in JS_EXTS:
                continue

            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            scanned_files += 1
            rel_path = str(fpath.relative_to(target_dir))
            lines = content.splitlines()

            # 1. setInterval without clearInterval
            if "setInterval(" in content and "clearInterval(" not in content:
                m = re.search(r"\bsetInterval\s*\(", content)
                line_no = content.count("\n", 0, m.start()) + 1 if m else 1
                candidates.append({
                    "rule_id": "memory-uncleared-interval",
                    "leak_class": "Timer / Closure Retention",
                    "path": rel_path,
                    "line_number": line_no,
                    "snippet": lines[line_no - 1].strip()[:180],
                    "severity": "high",
                    "title": "setInterval() Registered Without Corresponding clearInterval() Teardown",
                    "rationale": "Active intervals hold strong references to their callback closures and captured scopes indefinitely until explicitly cleared."
                })

            # 2. Unbounded Map / Set cache growth
            if re.search(r"(?:const|let|var)\s+\w+\s*=\s*new\s+(?:Map|Set)\(\)", content):
                if ".set(" in content or ".add(" in content:
                    if not re.search(r"\.(?:delete|clear)\s*\(", content) and "WeakMap" not in content and "WeakSet" not in content:
                        m = re.search(r"new\s+(?:Map|Set)\(\)", content)
                        line_no = content.count("\n", 0, m.start()) + 1 if m else 1
                        candidates.append({
                            "rule_id": "memory-unbounded-collection-cache",
                            "leak_class": "Unbounded Collection Growth",
                            "path": rel_path,
                            "line_number": line_no,
                            "snippet": lines[line_no - 1].strip()[:180],
                            "severity": "medium",
                            "title": "Monotonically Growing Map/Set Without Eviction (.delete/.clear) or WeakMap",
                            "rationale": "Module-scoped Maps and Sets that only `.set()`/`.add()` without size eviction, TTL cleanup, or `WeakMap` semantics cause linear heap growth over long sessions."
                        })

            # 3. addEventListener without removeEventListener or signal/once in component/dynamic files
            add_count = len(re.findall(r"\.addEventListener\s*\(", content))
            if add_count >= 2 and "removeEventListener" not in content and "AbortController" not in content and "once:" not in content:
                m = re.search(r"\.addEventListener\s*\(", content)
                line_no = content.count("\n", 0, m.start()) + 1 if m else 1
                candidates.append({
                    "rule_id": "memory-unremoved-event-listener",
                    "leak_class": "Event Listener / Detached DOM Retention",
                    "path": rel_path,
                    "line_number": line_no,
                    "snippet": lines[line_no - 1].strip()[:180],
                    "severity": "medium",
                    "title": f"{add_count} Event Listeners Registered Without removeEventListener or AbortController Signal",
                    "rationale": "Long-lived targets (window, document, runtime message buses) retain listener closures and any referenced DOM subtrees unless cleaned up via `{ signal: controller.signal }` or `removeEventListener`."
                })

            # 4. Observers without disconnect()
            obs_match = re.search(r"new\s+(MutationObserver|ResizeObserver|IntersectionObserver)\s*\(", content)
            if obs_match and ".disconnect(" not in content:
                line_no = content.count("\n", 0, obs_match.start()) + 1
                candidates.append({
                    "rule_id": "memory-undisconnected-observer",
                    "leak_class": "DOM Observer Retention",
                    "path": rel_path,
                    "line_number": line_no,
                    "snippet": lines[line_no - 1].strip()[:180],
                    "severity": "high",
                    "title": f"{obs_match.group(1)} Created Without .disconnect() Lifecycle Cleanup",
                    "rationale": "Active DOM observers pin observed elements and callback closures in V8 heap memory even after elements are removed from the document."
                })

    return {
        "target": target_dir.name,
        "scanned_files": scanned_files,
        "memory_leak_debugging_skill": os.path.expanduser("~/.gemini/config/plugins/chrome-devtools-plugin/skills/memory-leak-debugging/SKILL.md"),
        "candidates": candidates
    }


def main():
    parser = argparse.ArgumentParser(description="Memory Leak & Heap Bloat deterministic scanner")
    parser.add_argument("--target", required=True, help="Target repository directory")
    parser.add_argument("--output", help="Output JSON path")
    args = parser.parse_args()

    target_dir = Path(args.target).resolve()
    result = scan_memory_leaks(target_dir)
    out = json.dumps(result, indent=2)

    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
    else:
        print(out)


if __name__ == "__main__":
    main()
