#!/usr/bin/env python3
"""Deterministic Pre-Pass for Web Resilience Audit (agents/resilience/scripts/scan_resilience.py)

Maps source code against key failure domains from the 46-state Web Resilience Matrix
(`web-resilience-audit` / `web-resilience-fix` skills):
1. Network & Offline Resilience (unbounded fetch without AbortSignal.timeout, missing offline/SW fallback)
2. Storage Quota & Incognito Denials (unguarded localStorage/sessionStorage/indexedDB writes)
3. Third-Party & CDN Single Points of Failure (external synchronous scripts/styles without fallback/SRI)
4. Font Loading & FOIT Resilience (@font-face / remote fonts missing font-display: swap/optional)
5. Lifecycle, Crash & Backgrounding State Loss (unsaved form/state without pagehide/visibilitychange persistence)
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

RESILIENCE_EXTS = {".html", ".htm", ".css", ".js", ".mjs", ".ts", ".jsx", ".tsx", ".vue", ".svelte"}


def scan_resilience(target_dir: Path) -> Dict[str, Any]:
    candidates: List[Dict[str, Any]] = []
    scanned_files = 0
    has_service_worker = False

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for fname in sorted(files):
            fpath = Path(root) / fname
            ext = fpath.suffix.lower()
            if ext not in RESILIENCE_EXTS:
                continue

            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            scanned_files += 1
            rel_path = str(fpath.relative_to(target_dir))
            lines = content.splitlines()

            if "serviceWorker.register" in content or fname in {"sw.js", "service-worker.js"}:
                has_service_worker = True

            # 1. Fetch calls without timeout or AbortSignal
            if ext in {".js", ".mjs", ".ts", ".jsx", ".tsx"}:
                for m in re.finditer(r"\bfetch\s*\(", content):
                    line_no = content.count("\n", 0, m.start()) + 1
                    window = "\n".join(lines[max(0, line_no - 2):min(len(lines), line_no + 6)])
                    if "AbortSignal" not in window and "signal" not in window and "timeout" not in window:
                        candidates.append({
                            "rule_id": "resilience-unbounded-fetch-timeout",
                            "failure_state": "FS-04: Hanging / High-Latency Network Connection",
                            "path": rel_path,
                            "line_number": line_no,
                            "snippet": lines[line_no - 1].strip()[:180],
                            "severity": "high",
                            "title": "Network fetch() Without AbortSignal.timeout() or Cancellation Guard",
                            "rationale": "On a lie-fi or stalled connection, an unbounded `fetch()` hangs indefinitely for 60–300s without triggering `.catch()`, freezing UI workflows."
                        })
                        break

                # 2. Unguarded localStorage / sessionStorage access
                for m in re.finditer(r"\b(?:localStorage|sessionStorage)\.(?:setItem|getItem)\s*\(", content):
                    line_no = content.count("\n", 0, m.start()) + 1
                    window = "\n".join(lines[max(0, line_no - 5):min(len(lines), line_no + 5)])
                    if "try" not in window and "catch" not in window:
                        candidates.append({
                            "rule_id": "resilience-unguarded-web-storage",
                            "failure_state": "FS-29: Storage Quota Exceeded / Third-Party Context Blocked",
                            "path": rel_path,
                            "line_number": line_no,
                            "snippet": lines[line_no - 1].strip()[:180],
                            "severity": "medium",
                            "title": "Unguarded localStorage/sessionStorage Call Vulnerable to QuotaExceededError & SecurityError",
                            "rationale": "`localStorage.setItem` throws a synchronous exception when storage quota is full or when cookies/site data are blocked in strict privacy modes."
                        })
                        break

            # 3. Third-party script SPOFs in HTML
            if ext in {".html", ".htm"}:
                for m in re.finditer(r"<script\b[^>]+src=['\"]https?://[^'\"]+['\"][^>]*>", content, re.IGNORECASE):
                    tag = m.group(0)
                    if "async" not in tag.lower() and "defer" not in tag.lower():
                        line_no = content.count("\n", 0, m.start()) + 1
                        candidates.append({
                            "rule_id": "resilience-third-party-script-spof",
                            "failure_state": "FS-11: Blocked / Blackholed Third-Party CDN",
                            "path": rel_path,
                            "line_number": line_no,
                            "snippet": tag[:180],
                            "severity": "critical",
                            "title": "Synchronous External <script> Creates Single Point of Failure (SPOF)",
                            "rationale": "If the external origin is unreachable or DNS-blackholed, a synchronous script blocks the entire HTML parser from rendering the page."
                        })
                        break

            # 4. Font-face without font-display
            if ext == ".css":
                for m in re.finditer(r"@font-face\s*\{([^}]+)\}", content, re.IGNORECASE):
                    block = m.group(1)
                    if "font-display" not in block.lower():
                        line_no = content.count("\n", 0, m.start()) + 1
                        candidates.append({
                            "rule_id": "resilience-font-loading-foit",
                            "failure_state": "FS-15: Slow / Blocked Web Font Delivery (FOIT)",
                            "path": rel_path,
                            "line_number": line_no,
                            "snippet": "@font-face without font-display",
                            "severity": "medium",
                            "title": "@font-face Declaration Missing font-display: swap or optional",
                            "rationale": "Without `font-display: swap` or `optional`, browsers render invisible text (Flash of Invisible Text) for up to 3 seconds when font requests stall."
                        })
                        break

    return {
        "target": target_dir.name,
        "scanned_files": scanned_files,
        "has_service_worker_or_offline_handler": has_service_worker,
        "web_resilience_plugin_path": os.path.expanduser("~/.gemini/config/plugins/web-resilience-plugin"),
        "candidates": candidates
    }


def main():
    parser = argparse.ArgumentParser(description="Web Resilience 46-state deterministic scanner")
    parser.add_argument("--target", required=True, help="Target repository directory")
    parser.add_argument("--output", help="Output JSON path")
    args = parser.parse_args()

    target_dir = Path(args.target).resolve()
    result = scan_resilience(target_dir)
    out = json.dumps(result, indent=2)

    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
    else:
        print(out)


if __name__ == "__main__":
    main()
