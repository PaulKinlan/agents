"""The `command` sink: pipe normalized findings to any program (fleet-km8).

Jira, Linear, a webhook, a spreadsheet — anything the target's owner can script — without a
factory change. Configured in the target manifest:

    sink: command
    sink_command: "python3 scripts/file-to-linear.py --team SEC"   # argv, no shell
    sink_timeout: 120                                              # seconds (default 120)
    sink_env: [LINEAR_API_KEY]                                     # env vars the command may see

The command runs in the target directory, in its own process group (killed, with everything
it started, on timeout and when it returns), with the factory's allowlisted child environment
plus only the `sink_env` names. Its stderr is never published: it is redacted into a private
`sink-command-stderr.log` in the run directory, and the sink note names only the exit status. It is split with shlex and never run through a shell; use
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
import os
import shlex
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from lib.budget import StationBudget, StationTimeout, run_station_command
from lib.embargo import effective_severity
from lib.redaction import mask_literals, mask_text, redact_finding
from lib.sinks.base import Sink, SinkContext, new_result
# The manifest's sink_command is argv assembled at RUNTIME from config — invisible to a
# literal call-site census (agents-28nn round 3, review P1: a configured `git`/`gh`/...
# executed from PATH order, the pin never consulted, with this sink's credentials in its
# environment). pin_trusted_argv routes argv[0] through resolve_tool when it names a
# trusted tool — and refuses a trusted tool anywhere ELSE in the argv, because the pinned
# thing is the executed argv, not its first element (agents-28nn round 4: 'env git ...'
# is the environment running git): the pinned binary runs, or nothing does and the note
# says why.
from lib.tool_pins import ToolPinError, pin_trusted_argv

PROTOCOL = "factory-sink/1"
DEFAULT_TIMEOUT_SECONDS = 120.0
FINDING_FIELDS = (
    "agent", "rule_id", "path", "line_number", "severity", "title", "description",
    "remediation", "snippet", "state", "change", "first_seen", "last_seen",
)
STATUSES = ("published", "duplicate", "failed", "skipped")
DIAGNOSTICS_FILENAME = "sink-command-stderr.log"


def _write_diagnostics(ctx: SinkContext, stderr: str, secret_names: Sequence[str]) -> Optional[Path]:
    """Keep the command's stderr in a private (0600) file; it never goes into a note.

    Notes are rendered into the delta report and the public-adjacent step summary, and an
    auth failure can echo a token. The file is redacted too: known credential shapes and
    the literal values of the variables the command was given (`sink_env`).
    """
    if not stderr or not stderr.strip() or ctx.diagnostics_dir is None:
        return None
    literals = {os.environ[n] for n in secret_names if len(os.environ.get(n, "")) >= 4}
    text = mask_literals(mask_text(stderr), literals)
    directory = Path(ctx.diagnostics_dir)
    directory.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass
    path = directory / DIAGNOSTICS_FILENAME
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as handle:
        handle.write(f"--- {datetime.now(timezone.utc).isoformat()} {ctx.target_name}/{ctx.agent}\n")
        handle.write(text if text.endswith("\n") else text + "\n")
    return path


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
            argv = pin_trusted_argv(argv)
        except ToolPinError as e:
            # Fail closed, but never silently (same honest-failure shape as the other
            # sinks): a trusted tool the pin cannot authenticate is never executed from
            # PATH order, and the note names the cause.
            result["failed"] = len(pending)
            result["note"] = f"sink_command's trusted tool cannot be authenticated ({e}): nothing sent"
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
        # Own session, killed with everything it started on timeout AND on return
        # (lib/budget.run_station_command), so nothing it spawned can still deliver — or hold
        # the sink's credentials — after this run recorded its result.
        stdout = stderr = ""
        try:
            res = run_station_command(argv, StationBudget(timeout / 60.0, label="sink_command"),
                                      "sink_command", kill_group_on_exit=True,
                                      cwd=str(ctx.target_dir), input=payload,
                                      capture_output=True, text=True)
            returncode, stdout, stderr = res.returncode, res.stdout, res.stderr
        except StationTimeout:
            returncode = None
        except OSError as e:
            result["failed"] = len(pending)
            result["note"] = f"sink_command could not start ({type(e).__name__}): nothing sent"
            return result
        # stderr is never published (it can echo a credential): a private file holds it and the
        # note names only the exit status and that path.
        diagnostics = _write_diagnostics(ctx, stderr or "", self.credential_env(ctx.options))
        where = f"; stderr kept privately in {diagnostics}" if diagnostics else ""
        if returncode is None:
            result["failed"] = len(pending)
            result["note"] = f"sink_command timed out after {timeout:g}s: nothing delivered{where}"
            return result
        if returncode != 0:
            result["failed"] = len(pending)
            result["note"] = f"sink_command exited {returncode}: nothing delivered{where}"
            return result

        statuses: Dict[str, Dict[str, Any]] = {}
        for line in (stdout or "").splitlines():
            try:
                item = json.loads(line)
            except ValueError:
                continue
            if isinstance(item, dict) and item.get("status") in STATUSES and item.get("fingerprint"):
                statuses[str(item["fingerprint"])] = item

        # agents-nzdi: a silent sink is recorded UNVERIFIED, never published.
        #
        # THIS REPLACES AN ABSENCE-IS-DELIVERY BRANCH. When stdout yielded no parseable status
        # line at all, this loop used to answer "published" for EVERY pending finding, and
        # "published" is what appends to dispatched_sinks - a receipt that findings.py:1167
        # consumes as the PENDING FILTER. So a sink that exited 0 and told us nothing had its
        # findings marked delivered PERMANENTLY and was never offered them again: not the next
        # run, not ever, with nothing recording that nothing had arrived. `curl` without -f
        # exits 0 on an HTTP 500, so this was reachable by an ordinary sink command.
        #
        # The rule that condemns the old branch is stated one screen above, at line 36: "a
        # partial answer is never read as success". The code refused a PARTIAL answer as
        # success and then read NO ANSWER AT ALL as complete success - the principle applied to
        # every case except its own exclusion.
        #
        # WHY UNVERIFIED RATHER THAN FAILED, AND WHY NOT A RECEIPT: exit 0 with silence is not
        # evidence of failure either. A sink may legitimately have delivered and said nothing.
        # What we must not do is CLAIM DELIVERY WE DID NOT READ, and what we must not do is
        # consume the retry. So the value is honest (we could not verify), it counts as
        # not-delivered, it writes NO receipt, and the finding stays retryable. This is the
        # non-breaking step: the tolerance remains, its consequence is removed. Tightening the
        # PROTOCOL so that a silent sink is required to declare itself is a separate change
        # (filed by coord with the version bump), because that one alters a published contract
        # other people's sinks are written against.
        silent = not statuses
        for f in pending:
            if not silent:
                answer = statuses.get(f.get("fingerprint"), {"status": "failed",
                                                             "message": "no status from sink_command"})
            else:
                answer = {"status": "unverified",
                          "message": "sink_command exited 0 but reported no status for any "
                                     "finding: delivery NOT verified (agents-nzdi)"}
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
        elif silent and pending:
            # Name the reason rather than leaving a bare failure count: the operator needs to
            # know the sink was SILENT, not that it complained. No receipt was written, so the
            # next run will offer these findings again.
            result["note"] = (f"sink_command exited 0 but reported no status for any of "
                              f"{len(pending)} finding(s): delivery NOT verified, nothing "
                              f"receipted and all {len(pending)} will be retried")
        return result
