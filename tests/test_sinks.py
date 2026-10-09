#!/usr/bin/env python3
"""Process-boundary sink tests: public issue first, never a publication-time bead.

Every test uses an isolated gh/bd recorder and fake GitHub API. No token, network,
shared findings directory or real issue is used. The recorder simulates a persisted
remote so a second CLI process cannot rely solely on local delivery receipts.
"""

import hashlib
import json
import os
os.environ.setdefault("FACTORY_ALLOW_UNPINNED_TOOLS", "1")  # agents-7bj: tests use unpinned stub tools
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from lib.findings import compute_fingerprint
from lib.sinks.beads import _BEAD_EXTERNAL_REF_RE

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

    def test_bead_external_ref_matcher(self):
        """_BEAD_EXTERNAL_REF_RE accepts unscoped and repo-scoped refs; rejects unrelated scopes."""
        fp = "0123456789abcdef" * 4
        # (i) Accept unscoped factory:<64hex> and repo-scoped factory:github.com/owner/repo:<64hex>
        m_unscoped = _BEAD_EXTERNAL_REF_RE.match(f"factory:{fp}")
        self.assertIsNotNone(m_unscoped)
        self.assertEqual(m_unscoped.group(1), fp)

        m_scoped = _BEAD_EXTERNAL_REF_RE.match(f"factory:github.com/owner/repo:{fp}")
        self.assertIsNotNone(m_scoped)
        self.assertEqual(m_scoped.group(1), fp)

        m_scoped_alnum = _BEAD_EXTERNAL_REF_RE.match(f"factory:github.com/Owner-1.A/Repo_2.b:{fp}")
        self.assertIsNotNone(m_scoped_alnum)
        self.assertEqual(m_scoped_alnum.group(1), fp)

        # (ii) Reject malformed github scopes, missing components, or unrelated scopes
        self.assertIsNone(_BEAD_EXTERNAL_REF_RE.match(f"factory:github.com/not an owner/repo:{fp}"))
        self.assertIsNone(_BEAD_EXTERNAL_REF_RE.match(f"factory:github.com/owner/not a repo:{fp}"))
        self.assertIsNone(_BEAD_EXTERNAL_REF_RE.match(f"factory:unrelated:{fp}"))
        self.assertIsNone(_BEAD_EXTERNAL_REF_RE.match(f"factory:gitlab.com/owner/repo:{fp}"))
        self.assertIsNone(_BEAD_EXTERNAL_REF_RE.match(f"factory:github.com/owner:{fp}"))
        self.assertIsNone(_BEAD_EXTERNAL_REF_RE.match(f"factory:github.com/owner/repo/extra:{fp}"))
        self.assertIsNone(_BEAD_EXTERNAL_REF_RE.match(f"factory:github.com/-owner/repo:{fp}"))
        self.assertIsNone(_BEAD_EXTERNAL_REF_RE.match(f"factory:github.com/owner/-repo:{fp}"))


class SinkFixture:
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="factory-sinks-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.factory = self.root / "factory"
        (self.factory / "lib").mkdir(parents=True)
        for module in ("findings.py", "redaction.py", "embargo.py", "tool_pins.py"):
            shutil.copyfile(ROOT / "lib" / module, self.factory / "lib" / module)
            # Sink adapters (fleet-km8): findings.py delegates delivery to lib/sinks.
            shutil.copytree(ROOT / "lib" / "sinks", self.factory / "lib" / "sinks", dirs_exist_ok=True)
        self.cli = self.factory / "lib" / "findings.py"
        self.target = self.root / "target with spaces"
        self.target.mkdir()
        (self.target / ".beads").mkdir()
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
            "FACTORY_ALLOW_UNPINNED_TOOLS": "1",  # agents-7bj: stub gh/bd are unpinned
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

    def scan(self, sink="beads", items=None, *, agent="lint", visibility="public",
             repo=None, extra_env=None, candidates=None):
        raw = self.root / "input.json"
        raw.write_text(json.dumps({"findings": [SAMPLE] if items is None else items}), encoding="utf-8")
        cmd = [sys.executable, str(self.cli), "--target", "fixture", "--agent", agent,
               "--input", str(raw), "--sink", sink, "--target-dir", str(self.target)]
        if sink in ("beads", "both", "all"):
            cmd += ["--beads-dir", str(self.target)]
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

    def test_duplicate_input_is_one_finding_and_one_bead(self):
        result = self.scan("beads", items=[SAMPLE, self.shifted(), SAMPLE])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.stats()["new"], 1)
        self.assertEqual(len(self.store()["findings"]), 1)
        self.assertEqual(len(self.state()["beads"]), 1)
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

    def test_beads_sink_files_a_bead_automatically_without_a_public_issue(self):
        """agents-eyo: findings file to beads directly — no public issue, no human step."""
        result = self.scan("beads")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        bead, = self.state()["beads"]
        fp = self.finding()["fingerprint"]
        self.assertEqual(bead["external_ref"], f"factory:{fp}")
        self.assertIn("Unused export", bead["title"])
        self.assertIn(f"Fingerprint: {fp}", bead["description"])
        self.assertEqual(self.state()["issues"], [])
        self.assertFalse(any(c["tool"] == "gh" for c in self.calls()))
        self.assertEqual(self.finding()["dispatched_sinks"], ["beads"])

    def test_fresh_store_dedupes_by_fingerprint(self):
        """agents-eyo: a reset store re-files nothing — the external_ref fingerprint is the guard."""
        self.assertEqual(self.scan("beads").returncode, 0)
        (self.factory / "findings" / "fixture.json").unlink()
        self.assertEqual(self.scan("beads").returncode, 0)
        self.assertEqual(len(self.state()["beads"]), 1)

    def test_regressed_finding_with_closed_bead_creates_new_bead(self):
        """A finding that was fixed and then reappears (regressed) with its prior bead closed creates a NEW bead (guards FIX 1)."""
        # 1. Initial run: finding is filed to beads
        self.assertEqual(self.scan("beads").returncode, 0)
        self.assertEqual(len(self.state()["beads"]), 1)
        self.assertEqual(self.finding()["state"], "new")
        self.assertEqual(self.finding()["dispatched_sinks"], ["beads"])

        # 2. Finding is fixed in a subsequent run
        self.assertEqual(self.scan("beads", items=[]).returncode, 0)
        self.assertEqual(self.finding()["state"], "fixed")

        # 3. Prior bead is closed in the tracker
        remote_state = self.state()
        remote_state["beads"][0]["status"] = "closed"
        self.remote.write_text(json.dumps(remote_state))

        # 4. Finding reappears (regressed): prior bead is closed, so a new bead is filed
        result = self.scan("beads")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.finding()["state"], "regressed")
        self.assertEqual(self.finding()["dispatched_sinks"], ["beads"])
        beads = self.state()["beads"]
        self.assertEqual(len(beads), 2)
        self.assertEqual(beads[0]["status"], "closed")
        self.assertEqual(beads[1]["status"], "open")
        self.assertEqual(beads[0]["external_ref"], beads[1]["external_ref"])

    def test_regressed_finding_with_open_bead_does_not_duplicate(self):
        """A finding that was fixed and reappears (regressed) while prior bead is still open does NOT file a duplicate."""
        self.assertEqual(self.scan("beads").returncode, 0)
        self.assertEqual(len(self.state()["beads"]), 1)

        self.assertEqual(self.scan("beads", items=[]).returncode, 0)
        self.assertEqual(self.finding()["state"], "fixed")

        # Reappears while prior bead is still open
        result = self.scan("beads")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.finding()["state"], "regressed")
        self.assertEqual(len(self.state()["beads"]), 1)

    def test_repo_scoped_external_ref_dedupes(self):
        """_existing_bead_fingerprints accepts repo-scoped promote_issue external_ref shape (FIX 4)."""
        self.assertEqual(self.scan("file").returncode, 0)
        fp = self.finding()["fingerprint"]
        remote_state = self.state()
        remote_state["beads"] = [{
            "id": "promoted-1",
            "external_ref": f"factory:github.com/{REPO.lower()}:{fp}",
            "description": "promoted bead",
            "title": "Promoted bead",
            "status": "open",
        }]
        self.remote.write_text(json.dumps(remote_state))
        result = self.scan("beads")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.state()["beads"]), 1)

    def test_unrelated_scoped_external_ref_does_not_suppress_finding(self):
        """factory:unrelated:<64hex> is rejected and does not suppress finding in _dispatch_beads."""
        self.assertEqual(self.scan("file").returncode, 0)
        fp = self.finding()["fingerprint"]
        remote_state = self.state()
        remote_state["beads"] = [{
            "id": "unrelated-1",
            "external_ref": f"factory:unrelated:{fp}",
            "description": "unrelated bead with arbitrary scope",
            "title": "Unrelated bead",
            "status": "open",
        }]
        self.remote.write_text(json.dumps(remote_state))
        result = self.scan("beads")
        self.assertEqual(result.returncode, 0, result.stderr)
        beads = self.state()["beads"]
        self.assertEqual(len(beads), 2)
        self.assertEqual(beads[1]["external_ref"], f"factory:{fp}")

    def test_malformed_scoped_external_ref_does_not_suppress_finding(self):
        """factory:github.com/not an owner/repo:<64hex> is rejected and does not suppress finding in _dispatch_beads."""
        self.assertEqual(self.scan("file").returncode, 0)
        fp = self.finding()["fingerprint"]
        remote_state = self.state()
        remote_state["beads"] = [{
            "id": "malformed-1",
            "external_ref": f"factory:github.com/not an owner/repo:{fp}",
            "description": "malformed bead scope with spaces",
            "title": "Malformed bead",
            "status": "open",
        }]
        self.remote.write_text(json.dumps(remote_state))
        result = self.scan("beads")
        self.assertEqual(result.returncode, 0, result.stderr)
        beads = self.state()["beads"]
        self.assertEqual(len(beads), 2)
        self.assertEqual(beads[1]["external_ref"], f"factory:{fp}")

    def test_low_and_info_findings_never_reach_beads(self):
        """agents-eyo: beads is a synced tracker and never takes low/info."""
        result = self.scan("beads", [dict(SAMPLE, severity="low", rule_id="low-x"),
                                     dict(SAMPLE, severity="info", rule_id="info-x")])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.state().get("beads", []), [])

    def test_high_severity_without_visibility_is_embargoed_from_beads(self):
        """agents-eyo: missing visibility withholds high/critical from the synced tracker."""
        result = self.scan("beads", [dict(SAMPLE, severity="high", rule_id="high-x")],
                           visibility=None)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.state().get("beads", []), [])

    def test_missing_bd_binary_retains_local_finding_and_exits_nonzero(self):
        (self.bin / "bd").unlink()
        result = self.scan("beads")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("publication failed", result.stderr)
        self.assertEqual(self.finding()["state"], "new")
        self.assertEqual(self.state().get("beads", []), [])

    def test_unreadable_bead_listing_fails_closed_and_retries(self):
        failed = self.scan("beads", extra_env={"SINK_FAIL_BD_LIST": "1"})
        self.assertNotEqual(failed.returncode, 0)
        self.assertIn("publication failed", failed.stderr)
        self.assertEqual(self.state().get("beads", []), [])
        self.assertEqual(self.scan("beads").returncode, 0)
        self.assertEqual(len(self.state()["beads"]), 1)

    def test_false_positive_is_evidence_not_work(self):
        item = dict(SAMPLE, false_positive=True)
        self.assertEqual(self.scan("beads", items=[item]).returncode, 0)
        self.assertEqual(self.state().get("beads", []), [])
        self.assertEqual(self.finding()["severity"], "info")

    def test_github_issues_sink_is_refused(self):
        """agents-eyo: public GitHub issues are no longer a findings sink."""
        result = self.scan("github-issues")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no longer a findings sink", result.stderr)
        self.assertEqual(self.state()["issues"], [])
        self.assertFalse(any(c["tool"] == "gh" for c in self.calls()))


if __name__ == "__main__":
    unittest.main()
