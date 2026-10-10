#!/usr/bin/env python3
"""Deterministic secret scanner for secret-scan agent.

Pre-pass scanner that inspects a target directory for high-entropy tokens,
API keys, private keys, and credentials.
Uses gitleaks if available, otherwise runs a deterministic regex suite.
stdout carries the redacted report (reader keys and counts only); --output writes the raw
local record of candidate matches.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

FACTORY_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(FACTORY_ROOT))

from lib.candidate_identity import assign_candidate_ids, artefact_scheme_fields  # noqa: E402

from lib.redaction import emit_station_result  # noqa: E402
from lib.tool_pins import ToolPinError, resolve_tool  # noqa: E402


def _gitleaks_binary() -> Optional[str]:
    """The pin-authenticated gitleaks binary, or None when gitleaks is genuinely absent.

    gitleaks is a trusted tool (lib/tool_pins.TRUSTED_TOOLS), so a gitleaks PRESENT on
    PATH that the pin cannot authenticate is a loud failure — never a silent fallback to
    the built-in scan and never an execution from PATH order (agents-28nn round 4, review
    P1: a station script's own trusted-tool launch is a census kind of its own; the
    pre-pass used to shutil.which and execute without consulting the pin). A wrong answer
    that looks like a normal one is the finding family's defect: 'no gitleaks findings'
    must mean the pinned gitleaks ran. A genuinely ABSENT gitleaks keeps the documented
    builtin-regex fallback — the result's `scanner` field names which actually ran.
    """
    try:
        return resolve_tool("gitleaks")
    except ToolPinError as e:
        if shutil.which("gitleaks") is None:
            return None  # not installed at all: the documented builtin fallback
        sys.stderr.write(f"Error: gitleaks is present but cannot be authenticated: {e}\n")
        sys.exit(2)

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
    # Anchored: `sk-` must start a token. Unanchored, it matched inside ordinary words — the
    # `disk-quota-...` URL fragment (journal-aaj) and `ask-...` feature slugs (fleet-ctu).
    ("openai-key", re.compile(r"(?<![A-Za-z0-9_-])sk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{16,}")),
    ("stripe-key", re.compile(r"(?<![A-Za-z0-9_-])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("google-oauth", re.compile(r"ya29\.[0-9A-Za-z_-]{20,}")),
    ("gitlab-pat", re.compile(r"glpat-[A-Za-z0-9_-]{20,}")),
    ("npm-token", re.compile(r"npm_[A-Za-z0-9]{36}")),
]

def _scoped(pattern: "re.Pattern[str]") -> str:
    """A pattern's source with a leading global flag turned into a scoped group."""
    source = pattern.pattern
    match = re.match(r"\(\?([aiLmsux]+)\)", source)
    if match:
        return f"(?{match.group(1)}:{source[match.end():]})"
    return f"(?:{source})"


# Every rule at once. A file (and then a line) none of the rules can match is skipped before
# the per-rule pass: running 15 patterns over every line of a large repository overran the
# station's 5-minute budget, the process group was killed and no scanner ran (fleet-wa8).
ANY_PATTERN = re.compile("|".join(_scoped(pattern) for _, pattern in PATTERNS))

try:
    from lib.exclusions import DEFAULT_IGNORE_DIRS
    IGNORE_DIRS = DEFAULT_IGNORE_DIRS | {"fixtures"}
except ImportError:
    IGNORE_DIRS = {
        ".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build",
        "__pycache__", ".beads", ".agent-state", "runs", "fixtures", "findings"
    }

IGNORE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".webm", ".zip", ".tar", ".gz", ".wasm", ".lock"
}

GITLEAKS_TIMEOUT_SECONDS = 150


def scan_with_gitleaks(target_dir: Path) -> Optional[list]:
    gitleaks_bin = _gitleaks_binary()
    if not gitleaks_bin:
        return None

    cmd = [
        gitleaks_bin, "detect",
        "--source", str(target_dir),
        "--no-git",
        "--report-format", "json",
        "--report-path", "/dev/stdout",
        "--exit-code", "0"
    ]
    try:
        # Bounded: the station budget kills the whole pre-pass otherwise, and then nothing
        # ran at all. On expiry fall back to the built-in scan (fleet-wa8).
        res = subprocess.run(cmd, capture_output=True, text=True, check=False,
                             timeout=GITLEAKS_TIMEOUT_SECONDS)
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

            if not ANY_PATTERN.search(content):
                continue
            lines = content.splitlines()
            for line_idx, line in enumerate(lines, start=1):
                # Avoid checking absurdly long minified lines
                if len(line) > 1000:
                    continue
                if not ANY_PATTERN.search(line):
                    continue
                found = []
                for rule_id, pattern in PATTERNS:
                    # finditer, not search: one line can hold several credentials of the
                    # SAME shape, and search() would silently keep only the first.
                    found.extend((rule_id, match) for match in pattern.finditer(line))

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
    parser.add_argument("--output", help="Path to write the raw local JSON record to (default: stdout, which redacts matched values)")
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
    scanner = "gitleaks"
    if candidates is None:
        candidates = scan_with_builtin(target_dir)
        # The label names the scanner that ACTUALLY ran — not a second PATH probe, which
        # could disagree with the scan (agents-28nn round 4).
        scanner = "builtin-regex"

    # Every candidate gets a deterministic identity at scan time (agents-rdyb), so a consumer can
    # COPY it rather than reconstruct identity from the model's label and prose.
    assign_candidate_ids(candidates)

    result = {
        **artefact_scheme_fields(),
        "target": str(target_dir),
        "scanner": scanner,
        "candidate_count": len(candidates),
        "candidates": candidates
    }

    # One spelling of the output rule (agents-qslz): the --output file keeps the raw local
    # record, stdout gets the redacted form plus the advisory.
    emit_station_result(result, args.output)

if __name__ == "__main__":
    main()
