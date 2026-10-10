#!/usr/bin/env python3
"""Sinks are adapters behind one interface; core retains public-issue guard (fleet-km8).

Pins: the registry reproduces the old sink spellings and credential grants exactly; core
(lib/findings.py) contains no tracker name; and the generic `command` sink pipes the
published view of embargo-cleared findings to a configured program, receipts what the
program says it delivered, and never reads a failure or a partial answer as success.
"""

import ast
import contextlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from lib import sinks  # noqa: E402
from lib.child_env import child_environment  # noqa: E402
from test_factory_truth import Sandbox, factory_cli, report  # noqa: E402

SAMPLE = {"rule_id": "r1", "path": "src/a.js", "line_number": 3, "snippet": "x()",
          "severity": "medium", "title": "Medium thing", "description": "d", "remediation": "fix"}

RECEIVER = r'''
import json, os, sys
lines = [json.loads(l) for l in sys.stdin if l.strip()]
log = os.environ.get("RECEIVER_LOG") or os.path.join(os.getcwd(), "receiver.log")
with open(log, "a") as f:
    f.write(json.dumps({"lines": lines, "secret": os.environ.get("TRACKER_TOKEN"),
                        "leak": os.environ.get("ANTHROPIC_API_KEY")}) + "\n")
mode = sys.argv[1] if len(sys.argv) > 1 else "ok"
if mode == "fail":
    sys.stderr.write("tracker down\n"); sys.exit(7)
if mode == "refs":
    for l in lines[1:]:
        print(json.dumps({"fingerprint": l["fingerprint"], "status": "published", "ref": "SEC-1"}))
if mode == "partial":
    print(json.dumps({"fingerprint": lines[1]["fingerprint"], "status": "duplicate"}))
if mode == "sleep":
    import time; time.sleep(5)
'''


class TestRegistry(unittest.TestCase):
    def test_spellings_are_unchanged(self):
        self.assertEqual(sinks.expand("both"), ["beads"])
        self.assertEqual(sinks.expand("file,all"), ["beads"])
        self.assertEqual(sinks.expand(" beads , github-issues "), ["beads", "github-issues"])
        self.assertEqual(sinks.expand("file"), ["file"])
        self.assertEqual(sorted(sinks.SINKS), ["beads", "command", "file", "github-issues"])

    def test_credential_grants_are_unchanged(self):
        parent = {"PATH": "/bin", "GH_TOKEN": "g", "GITHUB_TOKEN": "h", "TRACKER_TOKEN": "t"}
        for spec, has_github in (("file", False), ("beads", False), ("github-issues", True),
                                 ("both", False), ("all", False), ("beads,github-issues", True)):
            with self.subTest(spec=spec):
                env = child_environment(sink=spec, parent=parent)
                self.assertEqual("GH_TOKEN" in env, has_github)
                self.assertNotIn("TRACKER_TOKEN", env)
        env = child_environment(sink="command", parent=parent, sink_options={"sink_env": ["TRACKER_TOKEN"]})
        self.assertEqual(env.get("TRACKER_TOKEN"), "t")
        self.assertNotIn("GH_TOKEN", env)

    def test_detection_reads_target_guidance(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(sinks.detect(Path(tmp)))
            Path(tmp, "AGENTS.md").write_text("Rule: bd is the only tracker.\n")
            self.assertEqual(sinks.detect(Path(tmp)), "beads")

    def test_core_keeps_public_issue_guard_and_delegates_delivery(self):
        source = (ROOT / "lib" / "findings.py").read_text()
        self.assertIn('"github-issues" in names', source)
        self.assertIn("adapter.publish(context, publishable)", source)


class CommandSinkCase(unittest.TestCase):
    """Drive the real findings CLI with --sink command."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="factory-cmd-sink-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.factory = self.root / "factory"
        shutil.copytree(ROOT / "lib", self.factory / "lib",
                        ignore=shutil.ignore_patterns("__pycache__", "bench", "adapters"))
        self.target = self.root / "target"
        self.target.mkdir()
        (self.target / "receiver.py").write_text(RECEIVER)
        self.log = self.target / "receiver.log"

    def scan(self, items, mode="ok", visibility="public", command=None, extra=(), env_extra=None):
        raw = self.root / "input.json"
        raw.write_text(json.dumps({"findings": items}))
        command = command if command is not None else f"{sys.executable} receiver.py {mode}"
        cmd = [sys.executable, str(self.factory / "lib" / "findings.py"), "--target", "fx",
               "--agent", "lint", "--input", str(raw), "--sink", "command",
               "--target-dir", str(self.target),
               "--sink-option", f"sink_command={command}", *extra]
        if visibility is not None:
            cmd += ["--visibility", visibility]
        env = {"PATH": "/usr/bin:/bin", "HOME": str(self.root), "TRACKER_TOKEN": "tok"}
        env.update(env_extra or {})
        return subprocess.run(cmd, cwd=self.factory, env=env, capture_output=True, text=True,
                              check=False, timeout=60)

    def received(self):
        if not self.log.exists():
            return []
        return [json.loads(l) for l in self.log.read_text().splitlines()]

    def store(self):
        return json.loads((self.factory / "findings" / "fx.json").read_text())["findings"]

    def report(self):
        return (self.factory / "findings" / "fx-delta.md").read_text()


class TestCommandSink(CommandSinkCase):
    def test_protocol_receipt_and_no_resend(self):
        result = self.scan([SAMPLE])
        call, = self.received()
        header, finding = call["lines"]
        self.assertEqual((header["type"], header["protocol"], header["target"], header["count"]),
                         ("run", "factory-sink/1", "fx", 1))
        self.assertEqual(header["visibility"], "public")
        self.assertEqual(finding["type"], "finding")
        self.assertEqual((finding["rule_id"], finding["path"], finding["severity"], finding["state"]),
                         ("r1", "src/a.js", "medium", "new"))
        record, = self.store().values()
        self.assertEqual(finding["fingerprint"], record["fingerprint"])
        self.assertIn("command", record["dispatched_sinks"])
        self.assertIn("[Sink command] published 1", result.stdout)
        self.assertIn("**command**: published 1", self.report())
        self.scan([SAMPLE])
        self.assertEqual(len(self.received()), 1, "a delivered finding is not sent again")

    def test_refs_are_recorded(self):
        self.scan([SAMPLE], mode="refs")
        record, = self.store().values()
        self.assertEqual(record["sink_refs"], {"command": "SEC-1"})

    def test_a_failing_command_delivers_nothing_and_is_retried(self):
        result = self.scan([SAMPLE], mode="fail")
        self.assertIn("failed 1", result.stdout)
        self.assertIn("exited 7", result.stdout)
        record, = self.store().values()
        self.assertNotIn("command", record["dispatched_sinks"])
        self.scan([SAMPLE])
        self.assertEqual(len(self.received()), 2)

    def test_a_partial_answer_is_not_success(self):
        other = dict(SAMPLE, rule_id="r2", snippet="y()", title="Second")
        result = self.scan([SAMPLE, other], mode="partial")
        self.assertIn("published 0, failed 1, duplicate 1", result.stdout)
        self.assertTrue(all("command" not in r["dispatched_sinks"] for r in self.store().values()))

    def test_the_embargo_applies_exactly_as_for_any_tracker(self):
        high = dict(SAMPLE, rule_id="h", snippet="h()", severity="high", title="High thing")
        result = self.scan([SAMPLE, high], visibility=None)
        call, = self.received()
        self.assertEqual([l["title"] for l in call["lines"][1:]], ["Medium thing"])
        self.assertIn("[SECURITY GUARD]", result.stdout)
        self.assertIn("embargoed 1", result.stdout)
        self.scan([SAMPLE, high], visibility="private")
        self.assertEqual([l["title"] for l in self.received()[1]["lines"][1:]], ["High thing"])

    def test_findings_are_the_published_view(self):
        leaked = dict(SAMPLE, description="key sk-proj-abcdefghijklmnopqrstuvwx in config")
        self.scan([leaked])
        finding = self.received()[0]["lines"][1]
        self.assertNotIn("sk-proj-abcdefghijklmnopqrstuvwx", json.dumps(finding))

    def test_missing_command_and_timeout_are_reported_failures(self):
        result = self.scan([SAMPLE], command="")
        self.assertIn("sink_command is not configured", result.stdout)
        result = self.scan([SAMPLE], mode="sleep", extra=["--sink-option", "sink_timeout=1"])
        self.assertIn("timed out", result.stdout)
        record, = self.store().values()
        self.assertNotIn("command", record["dispatched_sinks"])

    def test_no_shell_is_involved(self):
        marker = self.root / "pwned"
        self.scan([SAMPLE], command=f"{sys.executable} receiver.py ok; touch {marker}")
        self.assertFalse(marker.exists())


def _gone(pid: int, wait: float = 3.0) -> bool:
    import time
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


class TestCommandSinkReview(CommandSinkCase):
    """PR #29 review: stderr is never published (r4200705589); the command's whole process
    group is killed and waited for on timeout and on return (r4200705643)."""

    def write_script(self, name, body):
        path = self.target / name
        path.write_text(body)
        return f"{sys.executable} {name}"

    def test_stderr_never_reaches_the_note_and_is_kept_privately_redacted(self):
        command = self.write_script("leaky.py",
            "import os, sys\nsys.stdin.read()\n"
            "sys.stderr.write('401 for token ' + os.environ.get('TRACKER_TOKEN', '') +"
            " ' and sk-proj-abcdefghijklmnopqrstuvwx\\n')\nsys.exit(3)\n")
        run_dir = self.root / "run"
        result = self.scan([SAMPLE], command=command,
                           extra=["--run-dir", str(run_dir), "--sink-option", "sink_env=TRACKER_TOKEN"],
                           env_extra={"TRACKER_TOKEN": "tok-SECRET-1234"})
        published = result.stdout + self.report() + (self.factory / "findings" / "fx-summary.md").read_text()
        for leaked in ("tok-SECRET-1234", "sk-proj-abcdefghijklmnopqrstuvwx", "401 for token"):
            self.assertNotIn(leaked, published)
        self.assertIn("sink_command exited 3: nothing delivered", result.stdout)
        log = run_dir / "sink-command-stderr.log"
        self.assertIn(str(log), result.stdout)
        self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)
        text = log.read_text()
        self.assertIn("401 for token", text)
        self.assertNotIn("tok-SECRET-1234", text)
        self.assertNotIn("sk-proj-abcdefghijklmnopqrstuvwx", text)

    def test_a_timeout_kills_the_whole_group(self):
        pidfile = self.target / "child.pid"
        command = (f"sh -c 'sleep 60 >/dev/null 2>&1 & echo $! > {pidfile}; sleep 60'")
        result = self.scan([SAMPLE], command=command, extra=["--sink-option", "sink_timeout=1"])
        self.assertIn("timed out", result.stdout)
        self.assertTrue(_gone(int(pidfile.read_text())), "a descendant outlived the timeout")
        record, = self.store().values()
        self.assertNotIn("command", record["dispatched_sinks"])

    def test_descendants_are_killed_when_the_command_returns(self):
        pidfile = self.target / "late.pid"
        late = self.target / "late-delivery"
        for exit_code in (0, 4):
            with self.subTest(exit_code=exit_code):
                command = (f"sh -c 'cat >/dev/null; (sleep 2; touch {late}) >/dev/null 2>&1 & "
                           f"echo $! > {pidfile}; exit {exit_code}'")
                self.scan([dict(SAMPLE, rule_id=f"x{exit_code}", snippet=f"x{exit_code}")],
                          command=command)
                self.assertTrue(_gone(int(pidfile.read_text()), wait=1.0))
        import time
        time.sleep(2.5)
        self.assertFalse(late.exists(), "a background child delivered after the run returned")


class TestCommandSinkFromManifest(unittest.TestCase):
    """targets/<name>.yaml -> factory run -> command, with only sink_env added to the env."""

    def test_manifest_configures_the_command(self):
        with tempfile.TemporaryDirectory(prefix="factory-cmd-manifest-") as tmp:
            box = Sandbox(Path(tmp).resolve())
            shutil.copytree(ROOT / "lib" / "sinks", box.root / "lib" / "sinks", dirs_exist_ok=True)
            shutil.copyfile(ROOT / "lib" / "budget.py", box.root / "lib" / "budget.py")  # command sink
            (box.target / "receiver.py").write_text(RECEIVER)
            (box.root / "targets").mkdir()
            (box.root / "targets" / "proj.yaml").write_text(
                "name: proj\n"
                f"path: {box.target}\n"
                "visibility: private\n"
                "sink: command\n"
                f"sink_command: \"{sys.executable} receiver.py ok\"\n"
                "sink_env: [TRACKER_TOKEN]\n", encoding="utf-8")
            box.agent("lint", report(dict(SAMPLE, severity="high")))
            with box.patched(), \
                 mock.patch.dict(os.environ, {"TRACKER_TOKEN": "tok",
                                              "ANTHROPIC_API_KEY": "never-for-a-sink"}), \
                 contextlib.redirect_stdout(io.StringIO()):
                factory_cli.run_agent("lint", "proj", engine_arg="pi")
            call, = [json.loads(l) for l in (box.target / "receiver.log").read_text().splitlines()]
            self.assertEqual(call["secret"], "tok")
            self.assertIsNone(call["leak"])
            self.assertEqual(call["lines"][0]["visibility"], "private")
            self.assertEqual(call["lines"][1]["title"], "Medium thing")


if __name__ == "__main__":
    unittest.main()
