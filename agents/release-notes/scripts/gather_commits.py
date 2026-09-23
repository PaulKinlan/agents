#!/usr/bin/env python3
"""Deterministic commit and PR history gatherer for release-notes agent.

Pre-pass script that queries git log to collect commits since the last
release tag (or within a specified commit window). Extracts:
- Commit hash and short hash
- Author name and email
- Timestamp
- Subject and body
- PR number references
- Conventional commit category and breaking change flags
- Modified file lists

Outputs commit history JSON to stdout or a designated output file.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PR_PATTERNS = [
    re.compile(r"\(#(\d+)\)$"),                        # Squash merge: feat: foo (#123)
    re.compile(r"Merge pull request #(\d+)", re.IGNORECASE), # Merge commit: Merge pull request #123
    re.compile(r"(?:pull\/|PR\s*#?|#)(\d+)", re.IGNORECASE), # Body/subject mention
]

CONVENTIONAL_PATTERN = re.compile(
    r"^([a-zA-Z]+)(?:\(([^)]+)\))?(!)?:\s*(.+)$"
)

def get_latest_tag(target_dir: Path) -> Optional[str]:
    """Finds the most recent git tag in the target repository."""
    cmd = ["git", "-C", str(target_dir), "describe", "--tags", "--abbrev=0"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except Exception:
        pass

    # Fallback to sorting all tags
    cmd_all = ["git", "-C", str(target_dir), "tag", "--sort=-creatordate"]
    try:
        res = subprocess.run(cmd_all, capture_output=True, text=True, check=False)
        tags = [t.strip() for t in res.stdout.splitlines() if t.strip()]
        if tags:
            return tags[0]
    except Exception:
        pass

    return None

def extract_pr_number(subject: str, body: str) -> Optional[int]:
    """Extracts pull request number from commit subject or body."""
    # Check subject first (highest precision)
    for pat in PR_PATTERNS[:2]:
        m = pat.search(subject)
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                pass

    # Check body
    for pat in PR_PATTERNS:
        m = pat.search(body)
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                pass

    return None

def parse_conventional_commit(subject: str, body: str) -> Tuple[str, Optional[str], bool, str]:
    """Extracts type, scope, breaking flag, and description.
    
    Returns (commit_type, scope, is_breaking, clean_description).
    """
    m = CONVENTIONAL_PATTERN.match(subject.strip())
    is_breaking_body = "BREAKING CHANGE:" in body or "BREAKING-CHANGE:" in body

    if m:
        c_type = m.group(1).lower()
        scope = m.group(2)
        exclamation = bool(m.group(3))
        desc = m.group(4).strip()
        is_breaking = exclamation or is_breaking_body
        return c_type, scope, is_breaking, desc

    # Fallback classification based on keywords
    sub_lower = subject.lower()
    is_breaking = is_breaking_body or "breaking" in sub_lower
    if sub_lower.startswith("fix") or "bug" in sub_lower:
        return "fix", None, is_breaking, subject.strip()
    elif sub_lower.startswith("feat") or "add" in sub_lower:
        return "feat", None, is_breaking, subject.strip()
    elif sub_lower.startswith("docs"):
        return "docs", None, is_breaking, subject.strip()
    elif sub_lower.startswith("chore"):
        return "chore", None, is_breaking, subject.strip()
    elif sub_lower.startswith("refactor"):
        return "refactor", None, is_breaking, subject.strip()
    elif sub_lower.startswith("perf"):
        return "perf", None, is_breaking, subject.strip()

    return "other", None, is_breaking, subject.strip()

def get_files_changed(target_dir: Path, commit_hash: str) -> List[str]:
    """Retrieves list of files touched by a commit."""
    cmd = ["git", "-C", str(target_dir), "show", "--name-only", "--format=", commit_hash]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if res.returncode == 0:
            return [line.strip() for line in res.stdout.splitlines() if line.strip()]
    except Exception:
        pass
    return []

def gather_commits(target_dir: Path, since_tag: Optional[str] = None, max_count: int = 50) -> Dict[str, Any]:
    # Verify target is git repository
    chk_cmd = ["git", "-C", str(target_dir), "rev-parse", "--is-inside-work-tree"]
    try:
        chk = subprocess.run(chk_cmd, capture_output=True, text=True, check=False)
        if chk.returncode != 0 or chk.stdout.strip() != "true":
            sys.stderr.write(f"Target is not a git repository: {target_dir}\n")
            return {"target": str(target_dir), "commit_count": 0, "commits": []}
    except Exception as e:
        sys.stderr.write(f"Git check failed: {e}\n")
        return {"target": str(target_dir), "commit_count": 0, "commits": []}

    base_tag = since_tag or get_latest_tag(target_dir)
    
    if base_tag:
        git_range = f"{base_tag}..HEAD"
        cmd = [
            "git", "-C", str(target_dir), "log", git_range,
            "--format=%H%x1f%h%x1f%an%x1f%ae%x1f%cI%x1f%s%x1f%b%x1e"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        raw_log = res.stdout
    else:
        git_range = f"HEAD (recent {max_count})"
        cmd = [
            "git", "-C", str(target_dir), "log", f"-n{max_count}",
            "--format=%H%x1f%h%x1f%an%x1f%ae%x1f%cI%x1f%s%x1f%b%x1e"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        raw_log = res.stdout

    # Parse individual records
    raw_records = [r for r in raw_log.split("\x1e") if r.strip()]
    commits: List[Dict[str, Any]] = []

    for rec in raw_records:
        parts = rec.split("\x1f")
        if len(parts) < 7:
            continue
        full_hash = parts[0].strip()
        short_hash = parts[1].strip()
        author_name = parts[2].strip()
        author_email = parts[3].strip()
        date_iso = parts[4].strip()
        subject = parts[5].strip()
        body = parts[6].strip()

        pr_num = extract_pr_number(subject, body)
        c_type, scope, is_breaking, desc = parse_conventional_commit(subject, body)
        files = get_files_changed(target_dir, full_hash)

        commits.append({
            "hash": full_hash,
            "short_hash": short_hash,
            "author": author_name,
            "author_email": author_email,
            "date": date_iso,
            "subject": subject,
            "body": body,
            "pr_number": pr_num,
            "type": c_type,
            "scope": scope,
            "is_breaking": is_breaking,
            "description": desc,
            "files_changed": files
        })

    return {
        "target": str(target_dir),
        "base_ref": base_tag,
        "head_ref": "HEAD",
        "range": git_range,
        "commit_count": len(commits),
        "commits": commits
    }

def main():
    parser = argparse.ArgumentParser(description="Gather commit history for release-notes agent")
    parser.add_argument("--target", required=True, help="Target repository directory")
    parser.add_argument("--output", help="Path to write output JSON (default: stdout)")
    parser.add_argument("--since-tag", help="Explicit base tag to gather commits since")
    parser.add_argument("--max-count", type=int, default=50, help="Max commits if no tag exists")
    args = parser.parse_args()

    target_dir = Path(args.target).resolve()
    if not target_dir.exists():
        sys.stderr.write(f"Target directory does not exist: {target_dir}\n")
        sys.exit(1)

    result = gather_commits(target_dir=target_dir, since_tag=args.since_tag, max_count=args.max_count)
    output_json = json.dumps(result, indent=2)

    if args.output:
        Path(args.output).write_text(output_json, encoding="utf-8")
    else:
        print(output_json)

if __name__ == "__main__":
    main()
