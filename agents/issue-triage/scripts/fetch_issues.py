#!/usr/bin/env python3
"""Deterministic issue fetcher for issue-triage agent.

Pre-pass script that extracts open issues from either local beads issues
(.beads/issues.jsonl) or GitHub issues via the gh CLI.
Outputs a structured JSON payload containing candidate issues for agent triage.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

FACTORY_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(FACTORY_ROOT) not in sys.path:
    sys.path.insert(0, str(FACTORY_ROOT))

from lib.redaction import emit_station_result, mask_literals, mask_text  # noqa: E402
from lib.tool_pins import ToolPinError, prepass_tool  # noqa: E402


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
    """Fetch open issues using the GitHub CLI (gh), resolved THROUGH THE PIN.

    gh is a trusted tool (lib/tool_pins.TRUSTED_TOOLS) and this pre-pass holds GH_TOKEN,
    so the binary must be authenticated BEFORE it executes — including on the
    trusted-private UNSANDBOXED path, where no sandbox bind boundary verifies anything
    (agents-28nn round 4, review P1: a PATH-planted fake gh ran with GH_TOKEN in its
    environment and its result was accepted). And the failure must be LOUD: a gh that was
    not the pinned gh, or that failed, must NOT look like "there are no open issues" — a
    wrong answer that looks like a normal one. So an unauthenticated gh and a failed gh
    both exit nonzero (the factory turns a nonzero pre-pass into a StationError: "no scan
    was performed"), never a quiet None that main() would report as an empty source.
    """
    try:
        gh_bin = prepass_tool("gh")
    except ToolPinError as e:
        redacted_err = _redact_stderr(str(e))
        sys.stderr.write(f"Error: trusted tool 'gh' cannot be authenticated: {redacted_err}\n")
        sys.exit(2)

    cmd = [
        gh_bin, "issue", "list",
        "--state", "open",
        "--json", "number,title,body,labels,author,comments",
        "--limit", "50"
    ]
    try:
        res = subprocess.run(cmd, cwd=str(target_dir), capture_output=True, text=True, check=False)
        if res.returncode != 0:
            redacted_err = _redact_stderr(res.stderr.strip())
            sys.stderr.write(f"Error: gh issue list failed (code {res.returncode}): {redacted_err}\n")
            sys.exit(2)

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
        redacted_err = _redact_stderr(str(e))
        sys.stderr.write(f"Error: unexpected error executing gh CLI: {redacted_err}\n")
        sys.exit(2)


def main():
    parser = argparse.ArgumentParser(description="Deterministic issue fetcher for issue-triage agent")
    parser.add_argument("--target", required=True, help="Target repository path")
    parser.add_argument("--output", help="Path to write the raw local JSON record to (default: stdout, which redacts matched values)")
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

    emit_station_result(result, args.output)


if __name__ == "__main__":
    main()
