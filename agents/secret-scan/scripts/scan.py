#!/usr/bin/env python3
"""Deterministic secret scanner for secret-scan agent.

Pre-pass scanner that inspects a target directory for high-entropy tokens,
API keys, private keys, and credentials.
Uses gitleaks if available, otherwise runs a deterministic regex suite.
Outputs raw candidate matches as JSON to stdout or a designated output file.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# Built-in high-confidence regex patterns for when gitleaks is not installed
PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}")),
    ("github-pat", re.compile(r"ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}")),
    ("slack-token", re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*")),
    ("generic-api-key", re.compile(r"""(?i)(?:api_key|apikey|secret|token|password)\s*[:=]\s*['"][a-zA-Z0-9_\-]{20,80}['"]""")),
    ("jwt-token", re.compile(r"ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
]

IGNORE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build",
    "__pycache__", ".beads", ".agent-state", "runs", "fixtures", "findings"
}

IGNORE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".webm", ".zip", ".tar", ".gz", ".wasm", ".lock"
}

def scan_with_gitleaks(target_dir: Path) -> list:
    if not shutil.which("gitleaks"):
        return None
    
    cmd = [
        "gitleaks", "detect",
        "--source", str(target_dir),
        "--no-git",
        "--report-format", "json",
        "--report-path", "/dev/stdout",
        "--exit-code", "0"
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if res.stdout.strip():
            raw_data = json.loads(res.stdout)
            candidates = []
            for item in raw_data:
                candidates.append({
                    "rule_id": item.get("RuleID", "gitleaks-secret"),
                    "path": os.path.relpath(item.get("File", ""), target_dir),
                    "line_number": item.get("StartLine", 0),
                    "snippet": item.get("Secret", "").strip() or item.get("Match", "").strip(),
                    "raw_match": item.get("Match", "").strip()
                })
            return candidates
        return []
    except Exception as e:
        sys.stderr.write(f"gitleaks error: {e}, falling back to built-in scan\n")
        return None

BENIGN_PLACEHOLDERS = (
    "fixture", "synthetic", "example", "placeholder", "dummy",
    "mock-", "test-key", "your_api_key", "your-api-key", "xxxx", "000000"
)

def scan_with_builtin(target_dir: Path) -> list:
    candidates = []
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in IGNORE_EXTENSIONS:
                continue
            filepath = Path(root) / file
            rel_path = filepath.relative_to(target_dir)
            
            # Skip large files (> 2MB)
            try:
                if filepath.stat().st_size > 2 * 1024 * 1024:
                    continue
                content = filepath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            lines = content.splitlines()
            for line_idx, line in enumerate(lines, start=1):
                # Avoid checking absurdly long minified lines
                if len(line) > 1000:
                    continue
                for rule_id, pattern in PATTERNS:
                    match = pattern.search(line)
                    if match:
                        matched_str = match.group(0).lower()
                        if rule_id == "generic-api-key" and any(p in matched_str for p in BENIGN_PLACEHOLDERS):
                            continue
                        snippet = line.strip()
                        candidates.append({
                            "rule_id": rule_id,
                            "path": str(rel_path),
                            "line_number": line_idx,
                            "snippet": snippet[:200],
                            "raw_match": match.group(0)[:100]
                        })
    return candidates

def main():
    parser = argparse.ArgumentParser(description="Deterministic scanner for secret-scan agent")
    parser.add_argument("pos_target", nargs="?", help="Optional positional target directory")
    parser.add_argument("--target", help="Target directory to scan")
    parser.add_argument("--output", help="Path to write JSON candidates to (default: stdout)")
    args = parser.parse_args()

    raw_target = args.target or args.pos_target
    if not raw_target:
        sys.stderr.write("Error: --target or positional target directory required\n")
        sys.exit(1)
    target_dir = Path(raw_target).resolve()
    if not target_dir.exists():
        sys.stderr.write(f"Target does not exist: {target_dir}\n")
        sys.exit(1)

    candidates = scan_with_gitleaks(target_dir)
    if candidates is None:
        candidates = scan_with_builtin(target_dir)

    result = {
        "target": str(target_dir),
        "scanner": "gitleaks" if shutil.which("gitleaks") else "builtin-regex",
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
