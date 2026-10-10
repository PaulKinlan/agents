#!/usr/bin/env python3
"""Deterministic issue fetcher for issue-triage agent.

Queries either the local Beads repository or GitHub CLI for open issues.
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

FACTORY_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(FACTORY_ROOT) not in sys.path:
    sys.path.insert(0, str(FACTORY_ROOT))

from lib.redaction import emit_station_result, mask_literals, mask_text  # noqa: E402
from lib.tool_pins import ToolPinError, resolve_tool  # noqa: E402


def _redact_stderr(raw_stderr: str) -> str:
    """Mask credential patterns and active environment token literals from gh stderr."""
    literals = {
        v.strip()
        for k, v in os.environ.items()
        if (k in ("GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN") or k.endswith(("_TOKEN", "_KEY", "_SECRET")))
        and isinstance(v, str) and len(v.strip()) >= 8
    }
    return mask_literals(mask_text(raw_stderr), literals)

def fetch_beads_issues(target_dir: Path) -> Optional[List[Dict[str, Any]]]:
    """Extract open issues from .beads/issues.jsonl if the target uses beads."""
    issues_file = target_dir / ".beads" / "issues.jsonl"
    if not issues_file.is_file():
        return None

    candidates = []
    try:
        with open(issues_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                issue = json.loads(line)
                status = issue.get("status", "").lower()
                # Consider open, in_progress, or untriaged issues
                if status in ("open", "in_progress", "triage", ""):
                    candidates.append({
                        "id": f"beads-{issue.get('id', 'unknown')}",
                        "title": issue.get("title", ""),
                        "body": issue.get("description", ""),
                        "labels": issue.get("labels", []),
                        "source": "beads",
                        "raw": issue,
                    })
    except Exception as e:
        sys.stderr.write(f"Warning: failed reading beads issues: {e}\n")
        return None

    return candidates

def _parse_github_repo(target_dir: Path) -> Optional[str]:
    """Try to determine owner/repo from git remotes."""
    try:
        res = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=str(target_dir),
            capture_output=True,
            text=True,
            check=False
        )
        if res.returncode != 0:
            return None
        url = res.stdout.strip()
        # Parse github.com:owner/repo.git or https://github.com/owner/repo.git
        if "github.com" in url:
            part = url.split("github.com")[-1].lstrip("/:")
            if part.endswith(".git"):
                part = part[:-4]
            return part
    except Exception:
        pass
    return None

def fetch_github_issues(target_dir: Path) -> Optional[List[Dict[str, Any]]]:
    """Fetch open issues using the GitHub CLI (gh) if available."""
    gh_bin = shutil.which("gh")
    if not gh_bin:
        sys.stderr.write("Note: gh CLI not found in PATH.\n")
        return None

    repo_slug = _parse_github_repo(target_dir)
    cmd = [
        gh_bin, "issue", "list",
        "--state", "open",
        "--limit", "50",
        "--json", "number,title,body,labels,author,createdAt,comments"
    ]
    if repo_slug:
        cmd.extend(["--repo", repo_slug])

    try:
        res = subprocess.run(cmd, cwd=str(target_dir), capture_output=True, text=True, check=False)
        if res.returncode != 0:
            redacted_err = _redact_stderr(res.stderr.strip())
            sys.stderr.write(f"Error: gh issue list failed (code {res.returncode}): {redacted_err}\n")
            sys.exit(2)

        raw_issues = json.loads(res.stdout or "[]")
        candidates = []
        for issue in raw_issues:
            labels = [l.get("name") if isinstance(l, dict) else str(l) for l in issue.get("labels", [])]
            comments_text = "\n".join([c.get("body", "") for c in issue.get("comments", [])])
            full_body = issue.get("body", "")
            if comments_text:
                full_body += f"\n\n--- Comments ---\n{comments_text}"

            candidates.append({
                "id": f"gh-{issue.get('number')}",
                "title": issue.get("title", ""),
                "body": full_body,
                "labels": labels,
                "source": "github",
                "author": issue.get("author", {}).get("login", "") if isinstance(issue.get("author"), dict) else "",
                "created_at": issue.get("createdAt", ""),
                "raw": issue,
            })
        return candidates
    except Exception as e:
        redacted_err = _redact_stderr(str(e))
        sys.stderr.write(f"Error: unexpected error executing gh CLI: {redacted_err}\n")
        sys.exit(2)

def main():
    parser = argparse.ArgumentParser(description="Deterministic issue fetcher for issue-triage agent")
    parser.add_argument("--target", required=True, help="Path to target repository")
    parser.add_argument("--output", required=False, help="Path to output candidates JSON")
    args = parser.parse_args()

    target_dir = Path(args.target).resolve()
    if not target_dir.is_dir():
        sys.stderr.write(f"Error: target directory {target_dir} does not exist\n")
        sys.exit(1)

    candidates = []
    beads_candidates = fetch_beads_issues(target_dir)
    if beads_candidates is not None:
        candidates.extend(beads_candidates)
        source = "beads"
    else:
        gh_candidates = fetch_github_issues(target_dir)
        if gh_candidates is not None:
            candidates.extend(gh_candidates)
            source = "github"
        else:
            source = "none"

    result = {
        "target": str(target_dir),
        "source": source,
        "candidate_count": len(candidates),
        "candidates": candidates
    }

    emit_station_result(result, args.output)

if __name__ == "__main__":
    main()
