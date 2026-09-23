#!/usr/bin/env python3
"""Deterministic issue fetcher for issue-triage agent.

Pre-pass script that extracts open issues from either local beads issues
(.beads/issues.jsonl) or GitHub issues via the gh CLI.
Outputs a structured JSON payload containing candidate issues for agent triage.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

def fetch_beads_issues(target_dir: Path) -> Optional[List[Dict[str, Any]]]:
    """Extract open issues from .beads/issues.jsonl if the target uses beads."""
    beads_file = target_dir / ".beads" / "issues.jsonl"
    if not beads_file.exists():
        return None

    candidates = []
    try:
        with open(beads_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except Exception:
                    continue

                status = str(data.get("status", "")).lower()
                # Only process non-closed issues
                if status in ("closed", "resolved", "done"):
                    continue

                issue_id = str(data.get("id", ""))
                title = str(data.get("title", "")).strip()
                body = str(data.get("description", "")).strip()
                labels = data.get("labels", [])
                if not isinstance(labels, list):
                    labels = [str(labels)]

                comments = []
                for c in data.get("comments", []):
                    if isinstance(c, dict):
                        text = c.get("text") or c.get("body", "")
                        if text:
                            comments.append(str(text))
                    elif isinstance(c, str):
                        comments.append(c)

                candidates.append({
                    "id": issue_id,
                    "number": issue_id,
                    "title": title,
                    "body": body,
                    "labels": labels,
                    "author": str(data.get("created_by") or data.get("owner", "")),
                    "created_at": str(data.get("created_at", "")),
                    "updated_at": str(data.get("updated_at", "")),
                    "comments": comments,
                    "status": status,
                    "issue_type": str(data.get("issue_type", "task")),
                    "priority": data.get("priority"),
                    "source": "beads"
                })
    except Exception as e:
        sys.stderr.write(f"Warning: error reading beads issues at {beads_file}: {e}\n")
        return None

    return candidates

def fetch_github_issues(target_dir: Path) -> Optional[List[Dict[str, Any]]]:
    """Fetch open issues using the GitHub CLI (gh) if available."""
    gh_bin = shutil.which("gh")
    if not gh_bin:
        sys.stderr.write("Note: gh CLI not found in PATH.\n")
        return None

    cmd = [
        gh_bin, "issue", "list",
        "--state", "open",
        "--json", "number,title,body,labels,author,comments",
        "--limit", "50"
    ]
    try:
        res = subprocess.run(cmd, cwd=str(target_dir), capture_output=True, text=True, check=False)
        if res.returncode != 0:
            sys.stderr.write(f"Note: gh issue list failed (code {res.returncode}): {res.stderr.strip()}\n")
            return None

        raw_issues = json.loads(res.stdout or "[]")
        candidates = []
        for item in raw_issues:
            labels = [
                lbl.get("name") if isinstance(lbl, dict) else str(lbl)
                for lbl in item.get("labels", [])
            ]
            author = ""
            if isinstance(item.get("author"), dict):
                author = item["author"].get("login", "")
            elif item.get("author"):
                author = str(item.get("author"))

            comments = []
            for c in item.get("comments", []):
                if isinstance(c, dict):
                    body = c.get("body", "")
                    if body:
                        comments.append(body)
                elif isinstance(c, str):
                    comments.append(c)

            candidates.append({
                "id": str(item.get("number")),
                "number": item.get("number"),
                "title": str(item.get("title", "")).strip(),
                "body": str(item.get("body", "")).strip(),
                "labels": labels,
                "author": author,
                "created_at": str(item.get("createdAt", "")),
                "comments": comments,
                "status": "open",
                "issue_type": "issue",
                "source": "github"
            })
        return candidates
    except Exception as e:
        sys.stderr.write(f"Warning: unexpected error executing gh CLI: {e}\n")
        return None

def main():
    parser = argparse.ArgumentParser(description="Deterministic issue fetcher for issue-triage agent")
    parser.add_argument("--target", required=True, help="Target repository path")
    parser.add_argument("--output", help="Path to write JSON output to (default: stdout)")
    args = parser.parse_args()

    target_dir = Path(args.target).resolve()
    if not target_dir.exists():
        sys.stderr.write(f"Error: Target directory does not exist: {target_dir}\n")
        sys.exit(1)

    # 1. Try beads first (per SDLC sink rules)
    candidates = fetch_beads_issues(target_dir)
    source = "beads"

    # 2. Fall back to GitHub issues via gh CLI
    if candidates is None:
        candidates = fetch_github_issues(target_dir)
        source = "github"

    # 3. If neither available or failed, return clean empty candidate list
    if candidates is None:
        candidates = []
        source = "none"

    result = {
        "target": str(target_dir),
        "source": source,
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
