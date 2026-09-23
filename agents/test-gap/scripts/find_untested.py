#!/usr/bin/env python3
"""Deterministic pre-pass for test-gap agent.

Maps all source files against test files (*.test.*, *.spec.*, __tests__/, test/),
calculates the test coverage deficit, and extracts exported functions from untested files.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Set

SRC_EXTS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".py"}
TEST_PATTERNS = ["*.test.*", "*.spec.*", "*_test.*", "test_*.*"]

EXPORT_RE = re.compile(
    r"(?:export\s+(?:async\s+)?function\s+([a-zA-Z0-9_$]+)|"
    r"export\s+const\s+([a-zA-Z0-9_$]+)\s*=|"
    r"export\s+class\s+([a-zA-Z0-9_$]+)|"
    r"def\s+([a-zA-Z0-9_]+)\()",
    re.MULTILINE
)

def find_files(target_dir: Path):
    source_files = []
    test_files = []

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", ".beads", "venv", ".next", "dist", "build")]
        for f in files:
            p = Path(root) / f
            if any(p.match(pat) for pat in TEST_PATTERNS) or "test" in p.parts or "__tests__" in p.parts:
                test_files.append(p)
            elif p.suffix in SRC_EXTS:
                source_files.append(p)

    return source_files, test_files

def extract_exports(file_path: Path) -> List[str]:
    exports = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        for m in EXPORT_RE.finditer(content):
            name = next(g for g in m.groups() if g is not None)
            exports.append(name)
    except Exception:
        pass
    return exports

def main():
    parser = argparse.ArgumentParser(description="Test Gap Pre-pass")
    parser.add_argument("--target", required=True, help="Path to target directory")
    parser.add_argument("--output", required=True, help="Output JSON path")
    args = parser.parse_args()

    target_path = Path(args.target).resolve()
    sources, tests = find_files(target_path)

    test_basenames = {t.stem.split(".")[0].lower() for t in tests}

    untested_modules = []
    for s in sources:
        base = s.stem.split(".")[0].lower()
        has_test = base in test_basenames
        rel_path = str(s.relative_to(target_path))
        
        # Skip top level config files like eslint, prettier, vite config
        if any(cfg in rel_path.lower() for cfg in ("config", "eslint", "prettier", "tsconfig")):
            continue

        exports = extract_exports(s)
        if not has_test and exports:
            untested_modules.append({
                "path": rel_path,
                "exported_symbols": exports,
                "symbols_count": len(exports),
                "has_test": False
            })

    # Sort by number of symbols (most critical modules first)
    untested_modules.sort(key=lambda x: x["symbols_count"], reverse=True)

    tested_count = len(sources) - len(untested_modules)
    total_src = len(sources)
    coverage_ratio = (tested_count / total_src) if total_src > 0 else 1.0

    payload = {
        "target": target_path.name,
        "total_source_files": total_src,
        "total_test_files": len(tests),
        "coverage_ratio": round(coverage_ratio, 2),
        "untested_files_count": len(untested_modules),
        "candidates": untested_modules[:15]  # top 15 modules needing tests
    }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print(f"test-gap: {len(sources)} source files, {len(tests)} tests. Deficit: {len(untested_modules)} untested modules.")

if __name__ == "__main__":
    main()
