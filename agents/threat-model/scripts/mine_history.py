#!/usr/bin/env python3
"""Deterministic pre-pass for threat-model agent.

Mines repository git history, issue tracker records (.beads/issues.jsonl),
package configurations, and code patterns for security fixes, past bugs,
and exposed entry points to produce a rich factual basis for threat modeling.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

SECURITY_KEYWORDS = [
    "security", "vuln", "cve", "sanitize", "escape", "bypass", "auth",
    "leak", "crash", "isolate", "inject", "token", "secret", "permission",
    "boundary", "origin", "cors", "credential", "taint", "sandbox"
]

ENTRY_POINT_PATTERNS = [
    ("server-listener", re.compile(r"""(?:app\.(?:get|post|put|delete|use)|createServer|new WebSocketServer)\s*\(""")),
    ("extension-messaging", re.compile(r"""chrome\.runtime\.(?:onMessage|onConnect(?:External)?)\.addListener""")),
    ("code-execution", re.compile(r"""(?:child_process|spawn|exec|execSync|execFile|eval|new Function)\s*\(""")),
    ("dom-injection", re.compile(r"""(?:innerHTML|outerHTML|document\.write|insertAdjacentHTML)\s*=""")),
    ("external-fetch", re.compile(r"""(?:fetch|axios(?:\.get|\.post)?|request\.continue)\s*\(""")),
]

def mine_git_history(target_dir: Path, max_commits: int = 40) -> List[Dict[str, Any]]:
    """Extract security-relevant and bug-fix commits from git log."""
    if not (target_dir / ".git").exists():
        return []

    # Pattern for relevant commits
    pattern = "|".join(SECURITY_KEYWORDS)
    cmd = [
        "git", "-C", str(target_dir), "log",
        f"-E", f"--grep={pattern}",
        f"-n", str(max_commits),
        "--format=%H|%ad|%s",
        "--date=short"
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        commits = []
        for line in res.stdout.splitlines():
            parts = line.split("|", 2)
            if len(parts) == 3:
                commit_hash, date, subject = parts
                # Get files changed
                files_cmd = ["git", "-C", str(target_dir), "show", "--name-only", "--format=", commit_hash]
                files_res = subprocess.run(files_cmd, capture_output=True, text=True, check=False)
                files = [f.strip() for f in files_res.stdout.splitlines() if f.strip()]
                commits.append({
                    "hash": commit_hash[:10],
                    "date": date,
                    "subject": subject,
                    "files": files[:8]
                })
        return commits
    except Exception as e:
        sys.stderr.write(f"Git history mining failed: {e}\n")
        return []

def mine_beads_issues(target_dir: Path, max_issues: int = 30) -> List[Dict[str, Any]]:
    """Mine beads issues for resolved bugs and security incidents."""
    issues_file = target_dir / ".beads" / "issues.jsonl"
    if not issues_file.exists():
        return []

    relevant = []
    try:
        with open(issues_file, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except Exception:
                    continue

                title = record.get("title", "")
                desc = record.get("description", "")
                issue_type = record.get("issue_type", "")
                status = record.get("status", "")

                text_to_check = f"{title} {desc}".lower()
                is_security_related = any(k in text_to_check for k in SECURITY_KEYWORDS)
                is_closed_bug = (issue_type == "bug" and status == "closed")

                if is_security_related or is_closed_bug:
                    relevant.append({
                        "id": record.get("id"),
                        "title": title,
                        "issue_type": issue_type,
                        "status": status,
                        "close_reason": record.get("close_reason"),
                        "summary_snippet": desc[:250].replace("\n", " ").strip()
                    })
                    if len(relevant) >= max_issues:
                        break
    except Exception as e:
        sys.stderr.write(f"Beads mining failed: {e}\n")

    return relevant

def scan_entry_points(target_dir: Path) -> List[Dict[str, Any]]:
    """Scan source files for exposed attack surfaces and sensitive primitives."""
    findings = []
    ignored = {".git", "node_modules", "dist", "build", "coverage", ".beads", "runs", "fixtures"}

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in ignored]
        for fname in files:
            if not fname.endswith((".js", ".ts", ".mjs", ".cjs", ".py", ".go")):
                continue

            fpath = Path(root) / fname
            rel_path = fpath.relative_to(target_dir).as_posix()

            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            for line_idx, line in enumerate(content.splitlines(), start=1):
                for category, regex in ENTRY_POINT_PATTERNS:
                    if regex.search(line):
                        findings.append({
                            "category": category,
                            "path": rel_path,
                            "line_number": line_idx,
                            "snippet": line.strip()[:140]
                        })
                        if len(findings) > 60:
                            return findings
    return findings

def extract_project_metadata(target_dir: Path) -> Dict[str, Any]:
    """Extract runtime manifest details (dependencies, scripts)."""
    meta = {}
    pkg_json = target_dir / "package.json"
    if pkg_json.exists():
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
            meta["name"] = data.get("name")
            meta["dependencies"] = list(data.get("dependencies", {}).keys())
            meta["scripts"] = list(data.get("scripts", {}).keys())
        except Exception:
            pass
    return meta

def main():
    parser = argparse.ArgumentParser(description="Mine project history and architecture for threat modeling")
    parser.add_argument("--target-dir", "--target", dest="target_dir", required=True, help="Target repository directory")
    parser.add_argument("--output", help="Output JSON path")
    args = parser.parse_args()

    target_dir = Path(args.target_dir).resolve()
    if not target_dir.exists():
        sys.stderr.write(f"Target directory not found: {target_dir}\n")
        sys.exit(1)

    sys.stderr.write(f"Mining git history from {target_dir}...\n")
    git_fixes = mine_git_history(target_dir)

    sys.stderr.write(f"Mining beads issues...\n")
    beads_bugs = mine_beads_issues(target_dir)

    sys.stderr.write(f"Scanning entry points and sensitive primitives...\n")
    entry_points = scan_entry_points(target_dir)

    meta = extract_project_metadata(target_dir)

    result = {
        "target": target_dir.name,
        "metadata": meta,
        "git_fixes_count": len(git_fixes),
        "git_security_fixes": git_fixes[:25],
        "beads_bugs_count": len(beads_bugs),
        "beads_bugs": beads_bugs[:25],
        "entry_points_count": len(entry_points),
        "entry_points": entry_points[:40]
    }

    output_json = json.dumps(result, indent=2)
    if args.output:
        Path(args.output).write_text(output_json, encoding="utf-8")
        print(f"Saved mined data to {args.output}")
    else:
        print(output_json)

if __name__ == "__main__":
    main()
