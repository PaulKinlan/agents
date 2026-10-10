#!/usr/bin/env python3
"""GitHub-issues tracker sink: the human-approved issue -> bead promotion (agents-eyo).

Moved out of lib/findings.py for layering (fleet-km8). Public GitHub issues are no longer a
findings sink; `promote_issue` is the explicit, human-approved link between a verified public
issue and one bead. Nothing in the automatic findings path calls it.
"""

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from lib.redaction import redact_finding
from lib.tool_pins import resolve_tool
from lib.sinks.beads import _BEAD_ID, _bd_json


_PUBLIC_REPO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$")

_ISSUE_FP = re.compile(r"\*\*Fingerprint\*\*:\s*`([0-9a-f]{64})`")

def _gh_api(gh_bin: str, target_dir: Path, endpoint: str, *, payload: Optional[Dict[str, Any]] = None,
            paginate: bool = False) -> Any:
    """Force github.com even if GH_HOST points at an internal GitHub Enterprise server."""
    cmd = [gh_bin, "api", "--hostname", "github.com"]
    if paginate:
        cmd += ["--paginate", "--slurp"]
    if payload is not None:
        cmd += ["--method", "POST", "--input", "-"]
    cmd.append(endpoint)
    res = subprocess.run(cmd, cwd=str(target_dir), capture_output=True, text=True,
                         input=json.dumps(payload) if payload is not None else None,
                         check=False, timeout=60)
    if res.returncode != 0:
        # gh stderr can contain sensitive response bodies. Never echo it into a public log.
        raise RuntimeError(f"github.com API {endpoint.split('?')[0]} failed (exit {res.returncode})")
    try:
        return json.loads(res.stdout)
    except ValueError as e:
        raise RuntimeError("github.com API returned invalid JSON; refusing publication") from e


def _gh_pages(data: Any) -> List[Dict[str, Any]]:
    if not isinstance(data, list) or any(not isinstance(page, list) for page in data):
        raise RuntimeError("github.com issue listing was incomplete or malformed; refusing publication")
    issues = [item for page in data for item in page]
    if any(not isinstance(item, dict) for item in issues):
        raise RuntimeError("github.com issue listing contains malformed entries; refusing publication")
    return issues


def _issue_identity(issue: Dict[str, Any], repo: str) -> Tuple[str, int]:
    number = issue.get("number")
    url = issue.get("html_url")
    if (not isinstance(number, int) or isinstance(number, bool) or number <= 0
            or not isinstance(url, str)
            or url.lower() != f"https://github.com/{repo}/issues/{number}".lower()):
        raise RuntimeError("github.com returned an issue outside the configured public repository")
    return url, number

_PROMOTION_APPROVAL_LABEL = "factory-approved"

def promote_issue(target_name: str, target_dir: Path, repo: str, visibility: str,
                  issue_url: str, beads_dir: Path, *,
                  store: Optional[Any] = None) -> Dict[str, str]:
    """Explicit human-approved issue -> ONE linked bead; safe to call again after partial failure.

    Publication never calls this function. A future approved automation can call the same
    function only after a human has added `factory-approved` to the verified public issue.
    The store lock serialises promotion attempts in this checkout; bd's repo-scoped external
    reference repairs a lost local receipt or failed issue backlink on retry.

    Pass `store` (an open FindingsStore instance) to avoid opening a second file descriptor and
    self-deadlocking in the same process (agents-ynjh).
    """
    if visibility != "public" or not isinstance(repo, str) or not _PUBLIC_REPO.fullmatch(repo):
        raise ValueError("promotion requires explicit public visibility and OWNER/REPO")
    match = re.fullmatch(r"https://github\.com/([^/]+)/([^/]+)/issues/([1-9][0-9]*)", issue_url,
                         flags=re.IGNORECASE)
    if not match or f"{match.group(1)}/{match.group(2)}".lower() != repo.lower():
        raise ValueError("issue URL must be in the explicitly configured public github.com repo")
    beads_dir = beads_dir.expanduser().resolve()
    if not beads_dir.is_dir() or not (beads_dir / ".beads").is_dir():
        raise ValueError("explicit beads_path must point at an initialized project Beads DB")
    gh_bin, bd_bin = resolve_tool("gh"), resolve_tool("bd")
    destination = _gh_api(gh_bin, target_dir, f"repos/{repo}")
    if (not isinstance(destination, dict)
            or destination.get("full_name", "").lower() != repo.lower()
            or destination.get("html_url", "").lower() != f"https://github.com/{repo}".lower()
            or destination.get("private") is not False
            or destination.get("has_issues") is not True):
        raise RuntimeError("configured destination is not a verified public github.com issue repository")
    number = int(match.group(3))
    issue = _gh_api(gh_bin, target_dir, f"repos/{repo}/issues/{number}")
    if not isinstance(issue, dict) or "pull_request" in issue:
        raise RuntimeError("issue lookup failed or returned a pull request")
    verified_url, _ = _issue_identity(issue, repo)
    if verified_url.lower() != issue_url.lower():
        raise RuntimeError("issue lookup did not match the requested URL")
    fingerprints = set(_ISSUE_FP.findall(str(issue.get("body") or "")))
    if len(fingerprints) != 1:
        raise ValueError("issue must carry exactly one factory fingerprint marker")
    labels = issue.get("labels")
    if (not isinstance(labels, list)
            or _PROMOTION_APPROVAL_LABEL not in {
                label.get("name") for label in labels if isinstance(label, dict)
            }):
        raise PermissionError("human triage approval missing: apply factory-approved issue label first")
    fp, = fingerprints
    external_ref = f"factory:github.com/{repo.lower()}:{fp}"

    def _apply_with_store(s: Any) -> Dict[str, str]:
        finding = s.data["findings"].get(fp)
        if not isinstance(finding, dict) or finding.get("fingerprint") != fp:
            raise ValueError("issue fingerprint is not a finding in this target's local store")
        if finding.get("false_positive") or finding.get("state") == "wontfix":
            raise ValueError("triaged false positives and suppressed findings are not work")
        prior_issue = finding.get("github_issue")
        if prior_issue and (not isinstance(prior_issue, dict)
                            or str(prior_issue.get("url", "")).lower() != issue_url.lower()):
            raise ValueError("local finding is linked to a different public issue")
        if finding.get("promoted_issue") and str(finding["promoted_issue"]).lower() != issue_url.lower():
            raise ValueError("local promotion receipt points at a different issue")
        # Read every bead, including CLOSED, before creating. An unavailable or malformed
        # listing is not an empty database: never create a possible duplicate.
        beads = _bd_json(bd_bin, beads_dir, ["list", "--all", "--json", "-n", "0"])
        if not isinstance(beads, list) or any(not isinstance(bead, dict) for bead in beads):
            raise RuntimeError("bead listing malformed; refusing to create a duplicate")
        matches = [b for b in beads if b.get("external_ref") == external_ref]
        if len(matches) > 1:
            raise RuntimeError("multiple beads already carry this repo-scoped fingerprint")
        # Legacy unscoped refs/description markers are ambiguous across repositories;
        # refuse rather than create a second work item before a human resolves the old bead.
        legacy = [b for b in beads if b.get("external_ref") == f"factory:{fp}"
                  or (f"Fingerprint: {fp}" in str(b.get("description") or "")
                      and b.get("external_ref") != external_ref)]
        if legacy and not matches:
            raise RuntimeError("legacy bead fingerprint exists; link it manually before promotion")
        if finding.get("bead_id") and (not matches or str(matches[0].get("id")) != finding["bead_id"]):
            raise RuntimeError("local bead receipt disagrees with project DB; refusing another create")
        created = False
        if matches:
            bead = matches[0]
            bead_id = bead.get("id")
            if not isinstance(bead_id, str) or not _BEAD_ID.fullmatch(bead_id):
                raise RuntimeError("existing bead has an invalid id")
            prior_description = str(bead.get("description") or "")
            linked_urls = re.findall(r"(?m)^Issue:\s*(https://github\.com/\S+/issues/[0-9]+)",
                                     prior_description)
            if linked_urls and any(url.lower() != issue_url.lower() for url in linked_urls):
                raise RuntimeError("existing bead links a different issue; manual triage required")
            if issue_url not in prior_description:
                # Repair an existing bead whose issue link was lost; preserve its text.
                desc = prior_description + f"\n\nIssue: {issue_url}\nFingerprint: {fp}"
                _bd_json(bd_bin, beads_dir, ["update", bead_id, "--description", desc, "--json"])
        else:
            published = redact_finding(finding)
            desc = (f"{published.get('description', '')}\n\n"
                    f"Issue: {issue_url}\nFingerprint: {fp}\n"
                    f"Path: {published.get('path', '')}:{published.get('line_number', '?')}\n"
                    f"Snippet: {published.get('snippet', '')}")
            bead = _bd_json(bd_bin, beads_dir, [
                "create", "--title", f"[{published['agent']}] {published['title']}",
                "--description", desc,
                "--type", "bug" if "vuln" in finding.get("agent", "")
                or "secret" in finding.get("agent", "") else "task",
                "--external-ref", external_ref, "--json",
            ])
            bead_id = bead.get("id") if isinstance(bead, dict) else None
            if not isinstance(bead_id, str) or not _BEAD_ID.fullmatch(bead_id):
                raise RuntimeError("bd create did not return an id; query by external ref before retry")
            created = True
        finding["bead_id"] = bead_id
        finding["promoted_issue"] = issue_url
        finding["github_issue"] = {"url": verified_url, "number": number, "repo": repo}
        s.save()  # persist the bead side before attempting the GitHub backlink
        marker = f"<!-- factory-promotion:{external_ref}:{bead_id} -->"
        comments = _gh_pages(_gh_api(gh_bin, target_dir,
            f"repos/{repo}/issues/{number}/comments?per_page=100", paginate=True))
        if not any(marker in str(comment.get("body") or "") for comment in comments):
            _gh_api(gh_bin, target_dir, f"repos/{repo}/issues/{number}/comments", payload={
                "body": f"Human-approved factory promotion: work tracked as `{bead_id}`.\n\n{marker}",
            })
        return {"status": "created" if created else "already_promoted", "bead_id": bead_id,
                "issue": issue_url, "external_ref": external_ref}

    if store is not None:
        return _apply_with_store(store)

    # Lazy import: lib.sinks.github <- lib.findings would be a cycle at module import time
    # (findings.py imports promote_issue from here), so import the store only when promotion runs.
    from lib.findings import FindingsStore

    with FindingsStore(target_name=target_name) as s:
        return _apply_with_store(s)
