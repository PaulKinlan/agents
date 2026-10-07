#!/usr/bin/env python3
"""Process-boundary sink tests: public issue first, never a publication-time bead.

Every test uses an isolated gh/bd recorder and fake GitHub API. No token, network,
shared findings directory or real issue is used. The recorder simulates a persisted
remote so a second CLI process cannot rely solely on local delivery receipts.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from lib.findings import compute_fingerprint

ROOT = Path(__file__).resolve().parent.parent
REPO = "PaulKinlan/example"
SAMPLE = {
    "rule_id": "unused-export", "path": "./src/example.py", "line_number": 12,
    "snippet": "unused = True", "severity": "medium", "title": "Unused export",
    "description": "Synthetic sink verification finding.",
    "remediation": "Remove the unused export.",
}


class TestFingerprints(unittest.TestCase):
    def test_documented_sha256_and_normalization(self):
        expected = hashlib.sha256(b"lint:unused-export:src/example.py:unused = True").hexdigest()
        self.assertEqual(compute_fingerprint("lint", "unused-export", " ./src\\example.py ",
                                             "  unused  = True\n"), expected)

    def test_identity_fields_are_not_ignored(self):
        original = ["lint", "unused-export", "src/example.py", "unused = True"]
        for index in range(len(original)):
            changed = original.copy()
            changed[index] += "-different"
            self.assertNotEqual(compute_fingerprint(*original), compute_fingerprint(*changed))


class SinkFixture:
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="factory-sinks-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.factory = self.root / "factory"
        (self.factory / "lib").mkdir(parents=True)
        for module in ("findings.py", "redaction.py", "embargo.py"):
            shutil.copyfile(ROOT / "lib" / module, self.factory / "lib" / module)
        self.cli = self.factory / "lib" / "findings.py"
        self.target = self.root / "target with spaces"
        self.target.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.calls_file = self.root / "calls.jsonl"
        self.remote = self.root / "remote.json"
        self.remote.write_text(json.dumps({"issues": [], "comments": {}}), encoding="utf-8")
        home = self.root / "home"
        home.mkdir()
        self.env = {
            "PATH": str(self.bin), "HOME": str(home),
            "XDG_CONFIG_HOME": str(home / ".config"), "SINK_CALLS": str(self.calls_file),
            "SINK_REMOTE": str(self.remote), "SINK_REPO": REPO,
        }
        recorder = f"#!{sys.executable}\n" + r'''
import json
import os
import sys
from pathlib import Path

tool = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ['SINK_CALLS'], 'a', encoding='utf-8') as log:
    log.write(json.dumps({'tool': tool, 'args': args, 'stdin':
                          sys.stdin.read() if '--input' in args else '',
                          'cwd': os.getcwd()}) + '\n')
if tool == 'bd':
    sys.exit(19)  # no publication-time bead may ever be created
if args[:3] != ['api', '--hostname', 'github.com']:
    sys.exit(18)  # reject gh defaults that might target github.int.exe.xyz
endpoint = args[-1]
repo = os.environ['SINK_REPO']
remote_path = Path(os.environ['SINK_REMOTE'])
state = json.loads(remote_path.read_text())
if endpoint == f'repos/{repo}':
    url = os.environ.get('SINK_REPO_URL', f'https://github.com/{repo}')
    print(json.dumps({'full_name': repo, 'html_url': url,
                      'private': os.environ.get('SINK_PRIVATE') == '1', 'has_issues': True}))
elif endpoint == f'repos/{repo}/issues?state=all&per_page=100':
    if os.environ.get('SINK_FAIL_LIST'):
        sys.exit(9)
    print(json.dumps([state['issues']]))
elif endpoint.startswith(f'repos/{repo}/issues/') and endpoint.endswith('/comments?per_page=100'):
    number = endpoint.split('/')[4]
    print(json.dumps([state['comments'].get(number, [])]))
elif endpoint.startswith(f'repos/{repo}/issues/') and endpoint.endswith('/comments'):
    if os.environ.get('SINK_FAIL_COMMENT'):
        sys.exit(9)
    number = endpoint.split('/')[4]
    comment = json.loads(json.loads(open(os.environ['SINK_CALLS']).readlines()[-1])['stdin'])
    state['comments'].setdefault(number, []).append(comment)
    remote_path.write_text(json.dumps(state))
    print(json.dumps(comment))
elif endpoint == f'repos/{repo}/issues' and '--method' in args:
    payload = json.loads(json.loads(open(os.environ['SINK_CALLS']).readlines()[-1])['stdin'])
    number = len(state['issues']) + 1
    issue = dict(payload, number=number, html_url=f'https://github.com/{repo}/issues/{number}',
                 state='OPEN')
    state['issues'].append(issue)
    remote_path.write_text(json.dumps(state))
    print(json.dumps(issue))
else:
    sys.exit(17)
'''
        for tool in ("gh", "bd"):
            executable = self.bin / tool
            executable.write_text(recorder, encoding="utf-8")
            executable.chmod(0o755)

    def scan(self, sink="github-issues", items=None, *, agent="lint", visibility="public",
             repo=REPO, extra_env=None):
        raw = self.root / "input.json"
        raw.write_text(json.dumps({"findings": [SAMPLE] if items is None else items}), encoding="utf-8")
        cmd = [sys.executable, str(self.cli), "--target", "fixture", "--agent", agent,
               "--input", str(raw), "--sink", sink, "--target-dir", str(self.target)]
        if visibility is not None:
            cmd += ["--visibility", visibility]
        if repo is not None:
            cmd += ["--repo", repo]
        return subprocess.run(cmd, cwd=self.factory, env=dict(self.env, **(extra_env or {})),
                              capture_output=True, text=True, check=False, timeout=20)

    def calls(self, *, write_only=False):
        if not self.calls_file.exists():
            return []
        calls = [json.loads(line) for line in self.calls_file.read_text().splitlines()]
        return [c for c in calls if '--method' in c['args'] or c['tool'] == 'bd'] if write_only else calls

    def state(self):
        return json.loads(self.remote.read_text())

    def store(self):
        return json.loads((self.factory / "findings" / "fixture.json").read_text())

    def finding(self):
        return next(iter(self.store()["findings"].values()))

class TestSinks(SinkFixture, unittest.TestCase):
    def test_file_stays_local_and_does_not_contact_trackers(self):
        result = self.scan("file")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), [])
        report = (self.factory / "findings" / "fixture-delta.md").read_text()
        self.assertIn("Unused export", report)
        self.assertEqual(self.finding()["change"], "new")

    def test_seeded_high_severity_reaches_public_issue_not_just_configuration(self):
        high = dict(SAMPLE, severity="high", title="Seeded high finding", rule_id="seed-high")
        result = self.scan(items=[high])
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        issue, = self.state()["issues"]
        fp = self.finding()["fingerprint"]
        self.assertIn("Seeded high finding", issue["title"])
        self.assertIn(f"**Fingerprint**: `{fp}`", issue["body"])
        self.assertEqual(self.finding()["github_issue"], {
            "url": issue["html_url"], "number": issue["number"], "repo": REPO})
        self.assertEqual(self.calls(write_only=True)[0]["tool"], "gh")
        self.assertTrue(self.state()["comments"]["1"])
        self.assertFalse(any(c["tool"] == "bd" for c in self.calls()))

    def test_every_real_band_including_info_and_security_identity_publishes(self):
        items = [dict(SAMPLE, rule_id=severity, severity=severity, title=severity)
                 for severity in ("critical", "high", "medium", "low", "info")]
        result = self.scan(items=items)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(len(self.state()["issues"]), 5)
        security = dict(SAMPLE, severity="low", title="Sensitive scanner result")
        result = self.scan(items=[security], agent="secret-scan")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(len(self.state()["issues"]), 6)
        self.assertTrue(any(f["agent"] == "secret-scan" and f["routing_severity"] == "critical"
                            for f in self.store()["findings"].values()))

    def test_sensitive_value_is_redacted_before_publication(self):
        token = "AKIA" + "IOSFODNN7EXAMPLE"
        item = dict(SAMPLE, severity="high", title="Key " + token, snippet=token,
                    description="Leaked " + token)
        result = self.scan(items=[item], agent="secret-scan")
        self.assertEqual(result.returncode, 0, result.stderr)
        issue, = self.state()["issues"]
        self.assertNotIn(token, issue["title"] + issue["body"])
        self.assertIn(token, self.finding()["snippet"])

    def test_retries_search_open_and_closed_and_repair_lost_receipt(self):
        self.assertEqual(self.scan().returncode, 0)
        issue, = self.state()["issues"]
        state = self.state()
        state["issues"][0]["state"] = "CLOSED"
        self.remote.write_text(json.dumps(state))
        # Simulate a lost local receipt: the remote issue still owns the fingerprint.
        store = self.store()
        fp, = store["findings"]
        store["findings"][fp].pop("github_issue")
        store["findings"][fp]["dispatched_sinks"] = []
        (self.factory / "findings" / "fixture.json").write_text(json.dumps(store))
        shifted = dict(SAMPLE, line_number=700)
        self.assertEqual(self.scan(items=[shifted]).returncode, 0)
        self.assertEqual(len(self.state()["issues"]), 1)
        self.assertEqual(self.finding()["github_issue"]["url"], issue["html_url"])
        self.assertEqual(len(self.state()["comments"]["1"]), 1)
        self.assertTrue(any("state=all" in a for c in self.calls() for a in c["args"]))

    def test_transition_comments_new_fixed_regressed_once(self):
        self.assertEqual(self.scan().returncode, 0)
        self.assertEqual(self.scan(items=[]).returncode, 0)
        self.assertEqual(self.scan(items=[]).returncode, 0)
        self.assertEqual(self.scan(items=[dict(SAMPLE, line_number=88)]).returncode, 0)
        self.assertEqual(self.scan(items=[dict(SAMPLE, line_number=89)]).returncode, 0)
        comments = [c["body"] for c in self.state()["comments"]["1"]]
        self.assertEqual(len(comments), 3)
        for transition in ("new", "fixed", "regressed"):
            self.assertEqual(sum(f"Factory transition: {transition}" in c for c in comments), 1)
        self.assertEqual(len(self.state()["issues"]), 1)

    def test_created_issue_survives_a_failed_comment_and_repairs_on_retry(self):
        failed = self.scan(extra_env={"SINK_FAIL_COMMENT": "1"})
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(len(self.state()["issues"]), 1)
        self.assertEqual(self.finding()["github_pending_transitions"][0]["state"], "new")
        self.assertEqual(self.scan().returncode, 0)
        self.assertEqual(len(self.state()["issues"]), 1)
        self.assertEqual(len(self.state()["comments"]["1"]), 1)
        self.assertEqual(self.finding()["github_pending_transitions"], [])

    def test_a_lost_comment_receipt_does_not_repeat_transition(self):
        self.assertEqual(self.scan().returncode, 0)
        store = self.store()
        fp, = store["findings"]
        event = self.state()["comments"]["1"][0]["body"].split("factory-transition:")[1].split(":")[1].split(" ")[0]
        store["findings"][fp]["github_pending_transitions"] = [
            {"state": "new", "at": "recovered", "event": event}]
        (self.factory / "findings" / "fixture.json").write_text(json.dumps(store))
        self.assertEqual(self.scan().returncode, 0)
        self.assertEqual(len(self.state()["comments"]["1"]), 1)
        self.assertEqual(self.finding()["github_pending_transitions"], [])

    def test_concurrent_processes_publish_one_issue(self):
        raw = self.root / "input.json"
        raw.write_text(json.dumps({"findings": [SAMPLE]}))
        cmd = [sys.executable, str(self.cli), "--target", "fixture", "--agent", "lint",
               "--input", str(raw), "--sink", "github-issues", "--target-dir", str(self.target),
               "--visibility", "public", "--repo", REPO]
        procs = [subprocess.Popen(cmd, cwd=self.factory, env=self.env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                 for _ in range(2)]
        try:
            for proc in procs:
                out, err = proc.communicate(timeout=40)
                self.assertEqual(proc.returncode, 0, out + err)
        finally:
            for proc in procs:
                if proc.poll() is None:
                    proc.kill()
        self.assertEqual(len(self.state()["issues"]), 1)
        self.assertEqual(len(self.state()["comments"]["1"]), 1)

    def test_unreadable_listing_fails_closed_and_retries(self):
        failed = self.scan(extra_env={"SINK_FAIL_LIST": "1"})
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("publication failed", failed.stderr)
        self.assertEqual(self.state()["issues"], [])
        self.assertEqual(self.scan().returncode, 0)
        self.assertEqual(len(self.state()["issues"]), 1)

    def test_wrong_or_private_destination_never_creates(self):
        for config in ({"SINK_REPO_URL": "https://github.int.exe.xyz/PaulKinlan/example"},
                       {"SINK_PRIVATE": "1"}):
            with self.subTest(config=config):
                result = self.scan(extra_env=config)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.state()["issues"], [])

    def test_missing_visibility_repo_or_unapproved_beads_fail_loudly(self):
        for kwargs in ({"visibility": None}, {"visibility": "private"}, {"repo": None},
                       {"repo": "https://github.int.exe.xyz/PaulKinlan/example"},
                       {"sink": "beads"}, {"sink": "github-issues,beads"}):
            with self.subTest(kwargs=kwargs):
                result = self.scan(**kwargs)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.state()["issues"], [])
                self.assertFalse(any(c["tool"] == "bd" for c in self.calls()))

    def test_false_positive_is_evidence_not_public_work(self):
        item = dict(SAMPLE, false_positive=True)
        self.assertEqual(self.scan(items=[item]).returncode, 0)
        self.assertEqual(self.state()["issues"], [])
        self.assertEqual(self.finding()["severity"], "info")


if __name__ == "__main__":
    unittest.main()
