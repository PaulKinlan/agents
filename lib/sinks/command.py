"""The `command` sink: pipe normalized findings to any program (fleet-km8).

Jira, Linear, a webhook, a spreadsheet — anything the target's owner can script — without a
factory change. Configured in the target manifest:

    sink: command
    sink_command: "python3 scripts/file-to-linear.py --team SEC"   # argv, no shell
    sink_timeout: 120                                              # seconds (default 120)
    sink_env: [LINEAR_API_KEY]                                     # env vars the command may see

The command runs in the target directory with the factory's allowlisted child environment
plus only the `sink_env` names. It is split with shlex and never run through a shell; use
`sh -c '...'` explicitly if you need one.

Input (stdin), JSON Lines, protocol `factory-sink/1`:

    {"type": "run", "protocol": "factory-sink/1", "target": ..., "agent": ..., "visibility": ...,
     "generated": ..., "stats": {...}, "count": N}
    {"type": "finding", "fingerprint": ..., "agent": ..., "rule_id": ..., "path": ...,
     "line_number": ..., "severity": ..., "routing_severity": ..., "title": ..., "description": ...,
     "remediation": ..., "snippet": ..., "state": ..., "change": ..., "first_seen": ..., "last_seen": ...}
    ... one line per finding

Findings are the *published view* (lib/redaction.redact_finding) and only those core's
embargo allows for this sink: the rules are exactly those for any other tracker.

Output (stdout, optional), JSON Lines, one per finding:

    {"fingerprint": ..., "status": "published" | "duplicate" | "failed" | "skipped",
     "ref": "SEC-123", "message": "..."}

- exit non-zero, or a timeout: nothing was delivered (all failed, no receipts);
- exit 0 with no status lines: every finding was delivered;
- exit 0 with status lines: a finding without one was NOT delivered (failed) — a partial
  answer is never read as success.
Delivered findings get a `command` receipt (and `sink_refs.command` when a ref is given), so
they are not sent again; `duplicate` is counted and not receipted, like beads.
"""

import json
import shlex
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Sequence

from lib.embargo import effective_severity
from lib.redaction import redact_finding
from lib.sinks.base import Sink, SinkContext, new_result

PROTOCOL = "factory-sink/1"
DEFAULT_TIMEOUT_SECONDS = 120.0
FINDING_FIELDS = (
    "agent", "rule_id", "path", "line_number", "severity", "title", "description",
    "remediation", "snippet", "state", "change", "first_seen", "last_seen",
)
STATUSES = ("published", "duplicate", "failed", "skipped")


def _names(value: Any) -> List[str]:
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str):
        return [v.strip() for v in value.strip("[]").split(",") if v.strip()]
    return []


def finding_record(finding: Dict[str, Any]) -> Dict[str, Any]:
    """One finding as the command sees it: the published view, plus identity and routing."""
    published = redact_finding(finding)
    record = {"type": "finding", "fingerprint": finding.get("fingerprint")}
    record.update({key: published.get(key) for key in FINDING_FIELDS})
    record["routing_severity"] = effective_severity(finding)
    return record


class CommandSink(Sink):
    name = "command"

    def credential_env(self, options: Dict[str, Any]) -> Sequence[str]:
        return _names(options.get("sink_env"))

    def publish(self, ctx: SinkContext, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        result = new_result()
        pending = [f for f in findings if self.name not in f.get("dispatched_sinks", [])]
        if not pending:
            return result
        command = ctx.options.get("sink_command")
        argv = shlex.split(command) if isinstance(command, str) and command.strip() else []
        if not argv:
            result["failed"] = len(pending)
            result["note"] = "sink_command is not configured in the target manifest: nothing sent"
            return result
        try:
            timeout = float(ctx.options.get("sink_timeout") or DEFAULT_TIMEOUT_SECONDS)
        except (TypeError, ValueError):
            timeout = DEFAULT_TIMEOUT_SECONDS

        header = {
            "type": "run", "protocol": PROTOCOL, "target": ctx.target_name, "agent": ctx.agent,
            "visibility": ctx.visibility, "generated": datetime.now(timezone.utc).isoformat(),
            "stats": ctx.stats, "count": len(pending),
        }
        payload = "\n".join(json.dumps(r) for r in [header] + [finding_record(f) for f in pending]) + "\n"
        try:
            res = subprocess.run(argv, cwd=str(ctx.target_dir), input=payload, capture_output=True,
                                 text=True, check=False, timeout=timeout)
        except subprocess.TimeoutExpired:
            result["failed"] = len(pending)
            result["note"] = f"sink_command timed out after {timeout:g}s: nothing delivered"
            return result
        except OSError as e:
            result["failed"] = len(pending)
            result["note"] = f"sink_command could not start ({e}): nothing sent"
            return result
        if res.returncode != 0:
            result["failed"] = len(pending)
            tail = (res.stderr or "").strip().splitlines()[-1:] or [""]
            result["note"] = f"sink_command exited {res.returncode}: nothing delivered {tail[0][:200]}".rstrip()
            return result

        statuses: Dict[str, Dict[str, Any]] = {}
        for line in (res.stdout or "").splitlines():
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if isinstance(item, dict) and item.get("status") in STATUSES and item.get("fingerprint"):
                statuses[str(item["fingerprint"])] = item

        for f in pending:
            if statuses:
                answer = statuses.get(f.get("fingerprint"), {"status": "failed",
                                                             "message": "no status from sink_command"})
            else:
                answer = {"status": "published"}
            status = answer["status"]
            if status == "published":
                f.setdefault("dispatched_sinks", []).append(self.name)
                if answer.get("ref"):
                    f.setdefault("sink_refs", {})[self.name] = str(answer["ref"])
                result["published"] += 1
            elif status == "duplicate":
                result["duplicate"] += 1
            elif status == "skipped":
                result["skipped"] += 1
            else:
                result["failed"] += 1
        missing = sum(1 for f in pending if statuses and f.get("fingerprint") not in statuses)
        if missing:
            result["note"] = f"sink_command reported no status for {missing} finding(s): counted as failed"
        return result
