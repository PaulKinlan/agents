#!/usr/bin/env python3
"""Explicit issue-to-bead promotion: no live GitHub or Beads calls, only process stubs."""

import importlib.machinery
import importlib.util
import io
import json
import os
os.environ.setdefault("FACTORY_ALLOW_UNPINNED_TOOLS", "1")  # agents-7bj: tests use unpinned stub tools
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from tests.test_sinks import REPO, SinkFixture

ROOT = Path(__file__).resolve().parent.parent


class TestPromotion(SinkFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        # agents-eyo: findings file to beads now, not public issues. Seed the finding locally
        # (file sink: no tracker) plus a legacy public issue carrying its fingerprint marker;
        # each test calls approve() to add the human-triage label before promotion.
        published = self.scan(sink="file")
        self.assertEqual(published.returncode, 0, published.stderr)
        fp = self.finding()["fingerprint"]
        state = self.state()
        state["issues"] = [{
            "number": 1,
            "html_url": f"https://github.com/{REPO}/issues/1",
            "body": f"**Fingerprint**: `{fp}`",
            "labels": [],
            "state": "OPEN",
            "title": "Public input issue",
        }]
        self.remote.write_text(json.dumps(state))
        self.issue_url = state["issues"][0]["html_url"]
        self.calls_file.unlink(missing_ok=True)

    def approve(self):
        state = self.state()
        state["issues"][0]["labels"] = [{"name": "factory-approved"}]
        self.remote.write_text(json.dumps(state))

    def promote(self, *, issue_url=None, extra_env=None):
        cmd = [sys.executable, str(self.cli), "--target", "fixture",
               "--target-dir", str(self.target), "--visibility", "public",
               "--repo", REPO, "--beads-dir", str(self.target),
               "--promote-issue", issue_url or self.issue_url]
        env = dict(self.env, SINK_ALLOW_BD="1", **(extra_env or {}))
        return subprocess.run(cmd, cwd=self.factory, env=env, capture_output=True,
                              text=True, check=False, timeout=30)

    def writes(self, tool, operation):
        return [c for c in self.calls() if c["tool"] == tool
                and (c["args"][0] if tool == "bd" else c["args"][-1]) == operation]

    def test_non_approved_issue_never_creates_a_bead(self):
        res = self.promote()
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("human triage approval missing", res.stderr)
        self.assertFalse(any(c["tool"] == "bd" for c in self.calls()))
        self.assertEqual(self.state().get("beads", []), [])

    def test_approved_issue_creates_one_two_way_link_then_noops(self):
        self.approve()
        first = self.promote()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(json.loads(first.stdout)["status"], "created")
        bead, = self.state()["beads"]
        fp = self.finding()["fingerprint"]
        self.assertEqual(bead["external_ref"], f"factory:github.com/{REPO.lower()}:{fp}")
        self.assertIn(f"Issue: {self.issue_url}", bead["description"])
        self.assertIn(f"Fingerprint: {fp}", bead["description"])
        self.assertEqual(self.finding()["bead_id"], bead["id"])
        self.assertEqual(self.finding()["promoted_issue"], self.issue_url)
        comments = [c["body"] for c in self.state()["comments"]["1"]]
        self.assertTrue(any("factory-promotion:" in c and bead["id"] in c for c in comments))
        second = self.promote()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(json.loads(second.stdout)["status"], "already_promoted")
        self.assertEqual(len(self.state()["beads"]), 1)
        self.assertEqual(self.state()["comments"]["1"],
                         [dict(body=c) for c in comments])
        self.assertEqual(len(self.writes("bd", "create")), 1)

    def test_promoted_sensitive_finding_never_puts_the_matched_value_in_bd_or_gh(self):
        token = "AKIA" + "IOSFODNN7EXAMPLE"
        sensitive = {"rule_id": "aws-access-key", "path": "src/config.js", "line_number": 3,
                     "snippet": token, "severity": "high", "title": "Exposed " + token,
                     "description": "Remove the leaked " + token, "remediation": "Rotate it."}
        result = self.scan(sink="file", items=[sensitive], agent="secret-scan")
        self.assertEqual(result.returncode, 0, result.stderr)
        fp = next(f["fingerprint"] for f in self.store()["findings"].values()
                  if f["agent"] == "secret-scan")
        state = self.state()
        state["issues"] = [{
            "number": 1,
            "html_url": f"https://github.com/{REPO}/issues/1",
            "body": f"**Fingerprint**: `{fp}`",
            "labels": [{"name": "factory-approved"}],
            "state": "OPEN",
            "title": "Sensitive public issue",
        }]
        self.remote.write_text(json.dumps(state))
        self.calls_file.unlink(missing_ok=True)
        promoted = self.promote()
        self.assertEqual(promoted.returncode, 0, promoted.stderr)
        bead, = self.state()["beads"]
        self.assertNotIn(token, bead["title"] + bead["description"])
        self.assertNotIn(token, json.dumps(self.calls()))
        self.assertIn("factory-promotion:", self.state()["comments"]["1"][-1]["body"])

    def test_wrong_repo_missing_marker_and_unrelated_fingerprint_refuse(self):
        self.approve()
        wrong_repo = self.promote(issue_url="https://github.com/Elsewhere/example/issues/1")
        self.assertNotEqual(wrong_repo.returncode, 0)
        self.assertFalse(any(c["tool"] == "bd" for c in self.calls()))
        for body in ("no marker", "**Fingerprint**: `" + "f" * 64 + "`"):
            with self.subTest(body=body):
                state = self.state()
                state["issues"][0]["body"] = body
                self.remote.write_text(json.dumps(state))
                failed = self.promote()
                self.assertNotEqual(failed.returncode, 0)
                self.assertEqual(self.state().get("beads", []), [])
                self.assertFalse(any(c["tool"] == "bd" and c["args"][0] == "create"
                                     for c in self.calls()))

    def test_suppressed_finding_is_not_promoted_even_with_an_old_issue(self):
        self.approve()
        store = self.store()
        fp, = store["findings"]
        store["findings"][fp]["state"] = "wontfix"
        (self.factory / "findings" / "fixture.json").write_text(json.dumps(store))
        refused = self.promote()
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(self.state().get("beads", []), [])

    def test_legacy_unscoped_bead_ref_requires_manual_resolution(self):
        self.approve()
        fp = self.finding()["fingerprint"]
        state = self.state()
        state["beads"] = [{"id": "legacy-1", "external_ref": f"factory:{fp}",
                           "description": f"Fingerprint: {fp}", "status": "closed"}]
        self.remote.write_text(json.dumps(state))
        refused = self.promote()
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(len(self.state()["beads"]), 1)
        self.assertEqual(len(self.writes("bd", "create")), 0)

    def test_unreadable_issue_or_beads_listing_refuses_without_create(self):
        self.approve()
        for failure in ("SINK_FAIL_ISSUE_LOOKUP", "SINK_FAIL_BD_LIST"):
            with self.subTest(failure=failure):
                res = self.promote(extra_env={failure: "1"})
                self.assertNotEqual(res.returncode, 0)
                self.assertEqual(self.state().get("beads", []), [])
        self.assertEqual(len(self.writes("bd", "create")), 0)

    def test_failed_issue_backlink_repairs_without_a_second_bead(self):
        self.approve()
        failed = self.promote(extra_env={"SINK_FAIL_COMMENT": "1"})
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(len(self.state()["beads"]), 1)
        self.assertEqual(self.finding()["bead_id"], "fixture-1")
        retried = self.promote()
        self.assertEqual(retried.returncode, 0, retried.stderr)
        self.assertEqual(json.loads(retried.stdout)["status"], "already_promoted")
        self.assertEqual(len(self.state()["beads"]), 1)
        self.assertEqual(len(self.writes("bd", "create")), 1)
        self.assertEqual(sum("factory-promotion:" in c["body"]
                             for c in self.state()["comments"]["1"]), 1)

    def test_existing_bead_linked_to_another_issue_refuses_relinking(self):
        self.approve()
        self.assertEqual(self.promote().returncode, 0)
        state = self.state()
        state["beads"][0]["description"] = state["beads"][0]["description"].replace(
            f"Issue: {self.issue_url}", f"Issue: https://github.com/{REPO}/issues/99")
        self.remote.write_text(json.dumps(state))
        refused = self.promote()
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(len(self.state()["beads"]), 1)
        self.assertEqual(len(self.writes("bd", "create")), 1)

    def test_lost_local_receipt_uses_repo_scoped_external_ref(self):
        self.approve()
        self.assertEqual(self.promote().returncode, 0)
        store = self.store()
        fp, = store["findings"]
        store["findings"][fp].pop("bead_id")
        store["findings"][fp].pop("promoted_issue")
        (self.factory / "findings" / "fixture.json").write_text(json.dumps(store))
        retried = self.promote()
        self.assertEqual(retried.returncode, 0, retried.stderr)
        self.assertEqual(len(self.state()["beads"]), 1)
        self.assertEqual(self.finding()["bead_id"], "fixture-1")
        self.assertEqual(len(self.writes("bd", "create")), 1)

    def test_closed_bead_still_blocks_duplicate_promotion(self):
        self.approve()
        self.assertEqual(self.promote().returncode, 0)
        state = self.state()
        state["beads"][0]["status"] = "closed"
        self.remote.write_text(json.dumps(state))
        store = self.store()
        fp, = store["findings"]
        store["findings"][fp].pop("bead_id")
        (self.factory / "findings" / "fixture.json").write_text(json.dumps(store))
        retried = self.promote()
        self.assertEqual(retried.returncode, 0, retried.stderr)
        self.assertEqual(len(self.state()["beads"]), 1)
        self.assertEqual(len(self.writes("bd", "create")), 1)

    def test_concurrent_promotions_share_one_work_item(self):
        self.approve()
        cmd = [sys.executable, str(self.cli), "--target", "fixture", "--target-dir",
               str(self.target), "--visibility", "public", "--repo", REPO,
               "--beads-dir", str(self.target), "--promote-issue", self.issue_url]
        env = dict(self.env, SINK_ALLOW_BD="1")
        procs = [subprocess.Popen(cmd, cwd=self.factory, env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                 for _ in range(2)]
        try:
            for proc in procs:
                out, err = proc.communicate(timeout=45)
                self.assertEqual(proc.returncode, 0, out + err)
        finally:
            for proc in procs:
                if proc.poll() is None:
                    proc.kill()
        self.assertEqual(len(self.state()["beads"]), 1)
        self.assertEqual(len(self.writes("bd", "create")), 1)

    def test_factory_promote_routes_named_target_into_trusted_findings_child(self):
        self.approve()
        targets = self.factory / "targets"
        targets.mkdir()
        (targets / "fixture.yaml").write_text(
            f"name: fixture\npath: {self.target}\nrepo: {REPO}\n"
            f"beads_path: {self.target}\nsink: beads\nvisibility: public\n")
        loader = importlib.machinery.SourceFileLoader("factory_cli_promotion", str(ROOT / "factory"))
        spec = importlib.util.spec_from_loader("factory_cli_promotion", loader)
        factory_cli = importlib.util.module_from_spec(spec)
        loader.exec_module(factory_cli)
        env = dict(self.env, SINK_ALLOW_BD="1")
        stdout = io.StringIO()
        # The real child_environment correctly strips arbitrary SINK_* variables;
        # inject only the recorder's synthetic routing in this isolated test.
        with mock.patch.object(factory_cli, "FACTORY_ROOT", self.factory), \
             mock.patch.object(factory_cli, "child_environment", return_value=env) as child_env, \
             mock.patch.dict(os.environ, env, clear=True), redirect_stdout(stdout):
            factory_cli.promote_public_issue("fixture", self.issue_url)
        # agents-dpt: the promotion child resolves gh/bd itself, so it is also built with the
        # trusted-tool pin source (no new trust: the parent verified against the same pins).
        child_env.assert_called_once_with(sink="github-issues", trusted_tools=True)
        self.assertEqual(json.loads(stdout.getvalue())["status"], "created")
        self.assertEqual(len(self.state()["beads"]), 1)


if __name__ == "__main__":
    unittest.main()
