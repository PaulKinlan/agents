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

FACTORY_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(FACTORY_ROOT))

from lib.redaction import stdout_safe_report  # noqa: E402

# Built-in high-confidence regex patterns for when gitleaks is not installed
PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("aws-access-key", re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}")),
    ("github-pat", re.compile(r"ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}")),
    ("slack-token", re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*")),
    ("generic-api-key", re.compile(r"""(?i)(?:api_key|apikey|secret|token|password)\s*[:=]\s*['"][a-zA-Z0-9_\-]{20,80}['"]""")),
    ("jwt-token", re.compile(r"ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    # Vendor shapes the redactor already knows (lib/redaction.py). A rule that exists there but
    # not here means the scanner never surfaces it; a rule here that is missing there means the
    # matched value can be published. tests/test_secret_scanner.py enforces the match.
    ("openai-key", re.compile(r"sk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{16,}")),
    ("stripe-key", re.compile(r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("google-oauth", re.compile(r"ya29\.[0-9A-Za-z_-]{20,}")),
    ("gitlab-pat", re.compile(r"glpat-[A-Za-z0-9_-]{20,}")),
    ("npm-token", re.compile(r"npm_[A-Za-z0-9]{36}")),
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
                found = []
                for rule_id, pattern in PATTERNS:
                    match = pattern.search(line)
                    if match:
                        found.append((rule_id, match))

                # One credential is one finding. A vendor rule and the generic catch-all both
                # match `api_key = "sk-..."`; keep the most specific and the longest, then drop
                # any match overlapping one already taken. Order-independent on purpose, so the
                # list above does not have to carry a specificity contract.
                found.sort(key=lambda item: (item[0] == "generic-api-key",
                                             -(item[1].end() - item[1].start())))
                claimed_spans = []
                for rule_id, match in found:
                    if any(start < match.end() and match.start() < end for start, end in claimed_spans):
                        continue
                    matched_str = match.group(0).lower()
                    if rule_id == "generic-api-key" and any(p in matched_str for p in BENIGN_PLACEHOLDERS):
                        continue
                    claimed_spans.append(match.span())
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
        # The file is the local record of what matched — it is what a human needs in order
        # to rotate a credential, and it is gitignored. Every published render of a finding
        # is masked instead (see lib/redaction.py), so write the raw record here only.
        Path(args.output).write_text(output_json, encoding="utf-8")
    else:
        # stdout goes to a terminal or a CI log, which cannot be un-published: never emit
        # match text there, whatever shape the credential turns out to be.
        print(json.dumps(stdout_safe_report(result), indent=2))
        sys.stderr.write(
            "Note: stdout redacts matched values. Use --output <file> for the raw local record.\n"
        )

if __name__ == "__main__":
    main()
