#!/usr/bin/env python3
"""Deterministic pre-pass for log-check agent.

Scans the target repository for log files (*.log, logs/, test-output, error dumps),
extracts stack traces, unhandled exceptions, and fatal errors, and correlates them
with source file paths.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

LOG_PATTERNS = ["*.log", "*error*", "*stderr*", "*stdout*", "*output*.txt"]
STACK_TRACE_RE = re.compile(
    r"(?:(?:Error|Exception|TypeError|ReferenceError|SyntaxError|UnhandledPromiseRejection|AssertionError):[^\n]+|"
    r"^\s*at\s+(?:.+?\s+\()?([a-zA-Z0-9_./\\-]+):(\d+):(\d+)\)?)",
    re.MULTILINE
)

def find_logs(target_dir: Path) -> List[Path]:
    logs = []
    # 1. Search for common log files
    for root, dirs, files in os.walk(target_dir):
        # Skip node_modules, .git, .beads, venv
        dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", ".beads", "venv", ".next", "dist")]
        for f in files:
            p = Path(root) / f
            if any(p.match(pattern) for pattern in LOG_PATTERNS) or f.endswith(".log"):
                if p.stat().st_size > 0 and p.stat().st_size < 10 * 1024 * 1024:  # < 10MB
                    logs.append(p)

    # 2. Also check common log directories
    for log_dir_name in ["logs", "log", "reports", "tmp"]:
        ld = target_dir / log_dir_name
        if ld.exists() and ld.is_dir():
            for f in ld.iterdir():
                if f.is_file() and f not in logs and f.stat().st_size < 10 * 1024 * 1024:
                    logs.append(f)

    return logs

def parse_log_file(log_path: Path, target_dir: Path) -> List[Dict[str, Any]]:
    findings = []
    try:
        content = log_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []

    lines = content.splitlines()
    error_blocks = []
    current_block = []

    for i, line in enumerate(lines):
        is_err = any(kw in line.lower() for kw in ("error:", "exception", "unhandled", "fatal", "panic", "traceback"))
        if is_err or (current_block and line.strip().startswith("at ")):
            current_block.append((i + 1, line))
        else:
            if current_block:
                error_blocks.append(current_block)
                current_block = []

    if current_block:
        error_blocks.append(current_block)

    # Deduplicate error signatures
    seen_sigs = set()
    for block in error_blocks:
        first_line = block[0][1].strip()
        sig = first_line[:120]
        if sig in seen_sigs:
            continue
        seen_sigs.add(sig)

        # Look for source references in stack trace
        source_ref = None
        source_line = None
        for line_num, line_text in block:
            m = re.search(r"([a-zA-Z0-9_\-./]+\.(?:js|ts|jsx|tsx|py)):(\d+)", line_text)
            if m:
                potential_path = m.group(1)
                if not "node_modules" in potential_path:
                    source_ref = potential_path
                    source_line = int(m.group(2))
                    break

        findings.append({
            "log_file": str(log_path.relative_to(target_dir)),
            "line_in_log": block[0][0],
            "error_signature": sig,
            "stack_snippet": "\n".join(t[1] for t in block[:10]),
            "source_reference": source_ref,
            "source_line": source_line
        })

    return findings

def main():
    parser = argparse.ArgumentParser(description="Log Check Pre-pass")
    parser.add_argument("--target", required=True, help="Path to target directory")
    parser.add_argument("--output", required=True, help="Output JSON path")
    args = parser.parse_args()

    target_path = Path(args.target).resolve()
    log_files = find_logs(target_path)
    
    extracted_errors = []
    for lf in log_files:
        errs = parse_log_file(lf, target_path)
        extracted_errors.extend(errs)

    payload = {
        "target": target_path.name,
        "scanned_log_files_count": len(log_files),
        "log_files": [str(p.relative_to(target_path)) for p in log_files],
        "candidate_errors_count": len(extracted_errors),
        "candidates": extracted_errors
    }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print(f"log-check: scanned {len(log_files)} log files, found {len(extracted_errors)} candidate error signatures.")

if __name__ == "__main__":
    main()
