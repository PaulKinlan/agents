"""The `github-issues` sink: one issue per finding via `gh issue create`.

Moved from lib/findings.py unchanged in behaviour (fleet-km8). The issue guard below
re-checks the embargo so a direct call cannot publish an embargoed finding.
"""

import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Sequence

from lib.embargo import effective_severity, embargo_reason
from lib.redaction import redact_finding
from lib.sinks.base import Sink, SinkContext

GITHUB_TOKEN_VARS = ("GH_TOKEN", "GITHUB_TOKEN")


def _dispatch_github(target_name: str, target_dir: Path, findings: List[Dict[str, Any]], visibility: Any = "public") -> Dict[str, Any]:
    """Public disclosure guard and issue creation for GitHub Issues. Returns delivery counts."""
    result: Dict[str, Any] = {"published": 0, "failed": 0, "skipped": 0, "note": ""}
    gh_bin = shutil.which("gh")
    if not gh_bin and findings:
        result["failed"] = len(findings)
        result["note"] = "gh binary not available: nothing filed"
        return result
    for f in findings:
        if f["state"] not in ("new", "regressed") or "github-issues" in f.get("dispatched_sinks", []):
            continue
        # dispatch_to_sink already logged and filtered this; the check keeps a direct call to
        # this sink safe. Fail-closed severity and credential-agent identity live in one place.
        if embargo_reason(f, "github-issues", visibility):
            # The guard's own log line is published too: derive every value it renders.
            guarded = redact_finding(f)
            print(f"[SECURITY GUARD] Suppressing public GitHub issue for {effective_severity(f)} finding: {guarded['title']}")
            print(f"-> Please review in private store or file private security advisory.")
            result["skipped"] += 1
            continue
        if gh_bin and effective_severity(f) in ("critical", "high", "medium", "low"):
            published = redact_finding(f)
            title = f"[factory:{published['agent']}] {published['title']}"
            body = (
                f"**Rule**: `{published['rule_id']}`\n"
                f"**Severity**: `{published['severity']}`\n"
                f"**Location**: `{published['path']}:{published.get('line_number', '?')}`\n"
                f"**Fingerprint**: `{f['fingerprint']}`\n\n"
                f"### Description\n{published['description']}\n\n"
                f"### Remediation\n{published.get('remediation', 'N/A')}\n"
            )
            cmd = [gh_bin, "issue", "create", "--title", title, "--body", body]
            try:
                res = subprocess.run(cmd, cwd=str(target_dir), capture_output=True, text=True, check=False, timeout=30)
                if res.returncode == 0:
                    f.setdefault("dispatched_sinks", []).append("github-issues")
                    result["published"] += 1
                    print(f"Created GitHub issue: {res.stdout.strip()}")
                else:
                    result["failed"] += 1
                    print(f"Failed to create GitHub issue (exit {res.returncode}): {res.stderr.strip()}")
            except Exception as e:
                result["failed"] += 1
                print(f"Failed to create GitHub issue: {e}")
        else:
            result["skipped"] += 1
    return result


class GitHubIssuesSink(Sink):
    name = "github-issues"

    def credential_env(self, options: Dict[str, Any]) -> Sequence[str]:
        return GITHUB_TOKEN_VARS

    def publish(self, ctx: SinkContext, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        return _dispatch_github(ctx.target_name, ctx.target_dir, findings, ctx.visibility)
