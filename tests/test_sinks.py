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
remote_path = Path(os.environ['SINK_REMOTE'])
state = json.loads(remote_path.read_text())
if tool == 'bd':
    if not os.environ.get('SINK_ALLOW_BD'):
        sys.exit(19)  # no publication-time bead may ever be created
    if args[0] == 'list':
        if os.environ.get('SINK_FAIL_BD_LIST'):
            sys.exit(9)
        print(json.dumps(state.get('beads', [])))
    elif args[0] == 'create':
        beads = state.setdefault('beads', [])
        bead = {'id': f'fixture-{len(beads) + 1}',
                'external_ref': args[args.index('--external-ref') + 1],
                'description': args[args.index('--description') + 1],
                'title': args[args.index('--title') + 1], 'status': 'open'}
        beads.append(bead)
        remote_path.write_text(json.dumps(state))
        print(json.dumps(bead))
    elif args[0] == 'update':
        bead = next((b for b in state.get('beads', []) if b['id'] == args[1]), None)
        if bead is None:
            sys.exit(9)
        bead['description'] = args[args.index('--description') + 1]
        remote_path.write_text(json.dumps(state))
        print(json.dumps([bead]))  # real bd 1.3.1 update --json returns an array
    else:
        sys.exit(19)
    sys.exit(0)
if args[:3] != ['api', '--hostname', 'github.com']:
    sys.exit(18)  # reject gh defaults that might target github.int.exe.xyz
endpoint = args[-1]
repo = os.environ['SINK_REPO']
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
elif endpoint.startswith(f'repos/{repo}/issues/') and '--method' not in args:
    if os.environ.get('SINK_FAIL_ISSUE_LOOKUP'):
        sys.exit(9)
    number = int(endpoint.split('/')[4])
    issue = next((i for i in state['issues'] if i['number'] == number), None)
    if issue is None:
        sys.exit(9)
    print(json.dumps(issue))
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
             repo=REPO, extra_env=None, candidates=None):
        raw = self.root / "input.json"
        raw.write_text(json.dumps({"findings": [SAMPLE] if items is None else items}), encoding="utf-8")
        cmd = [sys.executable, str(self.cli), "--target", "fixture", "--agent", agent,
               "--input", str(raw), "--sink", sink, "--target-dir", str(self.target)]
        if visibility is not None:
            cmd += ["--visibility", visibility]
        if repo is not None:
            cmd += ["--repo", repo]
        if candidates is not None:
            path = self.root / "candidates.json"
            path.write_text(json.dumps(candidates), encoding="utf-8")
            cmd += ["--candidates", str(path)]
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

    def report(self):
        return (self.factory / "findings" / "fixture-delta.md").read_text()

    def summary_report(self):
        return (self.factory / "findings" / "fixture-summary.md").read_text()

    def stats(self):
        history = self.factory / "findings" / "fixture-history.jsonl"
        return json.loads(history.read_text().splitlines()[-1])["delta"]

    def shifted(self):
        return dict(SAMPLE, line_number=700, path="src/example.py", snippet="  unused  = True\n")


class TestSinks(SinkFixture, unittest.TestCase):
    def test_file_stays_local_and_does_not_contact_trackers(self):
        result = self.scan("file")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), [])
        report = (self.factory / "findings" / "fixture-delta.md").read_text()
        self.assertIn("Unused export", report)
        self.assertEqual(self.finding()["change"], "new")

    def test_step_summary_withholds_high_critical_prose(self):
        """The public Actions step summary remains reduced even though issues are public."""
        high = dict(SAMPLE, severity="high", rule_id="xss-injection",
                    title="XSS via profile name", path="src/profile.js", line_number=42,
                    description="PoC: <img src=x onerror=alert(1)> executes.",
                    snippet="<img src=x onerror=alert(1)>",
                    remediation="Escape the name before interpolation.")
        medium = dict(SAMPLE)
        self.assertEqual(self.scan("file", [high, medium]).returncode, 0)
        summary = self.summary_report()
        self.assertIn("| **2** |", summary)
        self.assertIn("xss-injection", summary)
        self.assertIn("src/profile.js:42", summary)
        self.assertIn("Withheld", summary)
        for sensitive in ("XSS via profile name", "PoC: <img", "Escape the name"):
            self.assertNotIn(sensitive, summary)
        self.assertIn("Unused export", summary)
        self.assertIn("Synthetic sink verification finding.", summary)
        self.assertIn("XSS via profile name", self.report())

    def test_step_summary_uses_routing_severity_when_model_understates_it(self):
        understated = dict(SAMPLE, severity="low", rule_id="sqli",
                           title="SQL injection via sort parameter", path="src/query.js",
                           line_number=7, description="PoC: ' OR 1=1--",
                           remediation="Parameterise.")
        self.assertEqual(self.scan("file", [understated], agent="vuln-discovery").returncode, 0)
        summary = self.summary_report()
        self.assertIn("[LOW · routed critical]", summary)
        self.assertIn("sqli", summary)
        self.assertIn("src/query.js:7", summary)
        for sensitive in ("SQL injection via sort parameter", "PoC:", "Parameterise."):
            self.assertNotIn(sensitive, summary)

    def test_clean_delta_after_line_shift_and_no_withheld_note(self):
        self.assertEqual(self.scan("file").returncode, 0)
        self.assertIn("Action Required", self.report())
        self.assertEqual(self.scan("file", [self.shifted()]).returncode, 0)
        self.assertIn("Clean Delta", self.report())
        self.assertIn("Active Findings (Unchanged)", self.report())
        self.assertIn("src/example.py:700", self.report())
        self.assertNotIn("Action Required", self.report())
        self.assertNotIn("Withheld", self.summary_report())
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.stats(), {"new": 0, "regressed": 0, "fixed": 0,
                                        "unchanged": 1, "suppressed": 0,
                                        "false_positive": 0})
        self.assertEqual(len(self.store()["findings"]), 1)

    def test_duplicate_input_is_one_finding_and_one_issue(self):
        result = self.scan(items=[SAMPLE, self.shifted(), SAMPLE])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.stats()["new"], 1)
        self.assertEqual(len(self.store()["findings"]), 1)
        self.assertEqual(len(self.state()["issues"]), 1)
        self.assertEqual(self.report().count("### [MEDIUM] Unused export"), 1)

    def test_candidates_bind_invented_identity_and_keep_matching_identity(self):
        candidates = {"candidates": [{"rule_id": "unused-export", "path": "src/example.py"}]}
        result = self.scan("file", [dict(SAMPLE, rule_id="model-invented",
                                              path="elsewhere.js", title="Invented location")],
                           candidates=candidates)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.finding()["rule_id"], "unclassified")
        self.assertEqual(self.finding()["path"], "unknown")
        self.assertIn("unclassified", self.report())
        self.assertIn("unknown", self.report())
        # A fresh store: the next assertion must not be affected by prior identity.
        (self.factory / "findings" / "fixture.json").unlink()
        result = self.scan("file", [dict(SAMPLE, title="Kept")], candidates=candidates)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.finding()["rule_id"], "unused-export")
        self.assertEqual(self.finding()["path"], "./src/example.py")

    def test_issue_shaped_candidates_have_no_location_binding(self):
        candidates = {"candidates": [{"id": "42", "title": "an issue"}]}
        item = dict(SAMPLE, rule_id="triage-missing-repro", path="issues/42", title="Issue triage")
        result = self.scan("file", [item], agent="issue-triage", candidates=candidates)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.finding()["rule_id"], "triage-missing-repro")
        self.assertEqual(self.finding()["path"], "issues/42")

    def test_suppressed_and_accepted_findings_do_not_publish(self):
        self.assertEqual(self.scan("file", [SAMPLE, dict(SAMPLE, rule_id="accepted-rule")]).returncode, 0)
        store_file = self.factory / "findings" / "fixture.json"
        store = self.store()
        first, second = store["findings"]
        store["findings"][second]["state"] = "accepted"
        store_file.write_text(json.dumps(store))
        (self.factory / "findings" / "suppressions.yaml").write_text(
            f"{first}:\n  reason: Synthetic accepted risk\n")
        result = self.scan(items=[SAMPLE, dict(SAMPLE, rule_id="accepted-rule")])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.stats()["suppressed"], 1)
        self.assertEqual(self.stats()["unchanged"], 1)
        self.assertIn("Synthetic accepted risk", self.report())

    def test_malformed_suppression_register_and_visibility_fail_loudly(self):
        raw = self.root / "input.json"
        raw.write_text(json.dumps({"findings": [SAMPLE]}))
        invalid = subprocess.run([sys.executable, str(self.cli), "--target", "fixture",
                                  "--agent", "lint", "--input", str(raw), "--sink", "file",
                                  "--visibility", "internal"], cwd=self.factory, env=self.env,
                                 capture_output=True, text=True, timeout=10)
        self.assertEqual(invalid.returncode, 2)
        self.assertIn("invalid choice", invalid.stderr)
        findings_dir = self.factory / "findings"
        findings_dir.mkdir(exist_ok=True)
        (findings_dir / "suppressions.yaml").write_text(": broken\n")
        malformed = self.scan("file")
        self.assertEqual(malformed.returncode, 2)
        self.assertIn("suppressions", malformed.stderr)

    def test_missing_gh_binary_retains_local_finding_and_exits_nonzero(self):
        (self.bin / "gh").unlink()
        result = self.scan()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("publication failed", result.stderr)
        self.assertEqual(self.finding()["state"], "new")
        self.assertEqual(self.state()["issues"], [])

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
