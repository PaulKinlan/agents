"""Containment: planted artifacts and a session tampering with its own record.

Split out of tests/test_containment.py (agents-ryw9); TestDispatcher keeps the
policy/admission subset. The harness stays in tests/containment_harness.py, and the
header below is copied verbatim from the family modules agents-3iog split.
"""

import hashlib
import http.server
import importlib.machinery
import importlib.util
import json
import os
os.environ.setdefault("FACTORY_ALLOW_UNPINNED_TOOLS", "1")  # agents-7bj: tests use unpinned stub tools
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.containment import (  # noqa: E402
    ENGINE_READ_SCOPE, ENGINE_TOOL_POLICIES, GRANTABLE_POLICIES, READ_ONLY, WORKTREE_WRITE,
    WORKTREE_WRITE_UNVERIFIED_ENGINES, ContainmentError, banner_lines,
    budget_note, check_engine, downgrade_network_to_withheld, egress_allowlist, load_policy,
    policy_record,
)
from lib.sandbox import SANDBOXED_ENGINES, sandbox_available, sandbox_command  # noqa: E402
from lib.credential_broker import PLACEHOLDER_PREFIX  # noqa: E402
from lib.child_env import child_environment  # noqa: E402
from lib import egress_proxy  # noqa: E402
from lib import containment as containment_module  # noqa: E402
from lib import sandbox as sandbox_module  # noqa: E402
from lib.egress_proxy import EgressProxy  # noqa: E402

# Whether THIS host can run bubblewrap. The confinement acceptance test needs it; the
# fail-closed and opt-in tests simulate its absence with a broken bwrap on PATH, so they run
# anywhere (review P0, agents-9n7).
_BWRAP = sandbox_available()

_loader = importlib.machinery.SourceFileLoader("factory_cli_pnu", str(ROOT / "factory"))
_spec = importlib.util.spec_from_loader("factory_cli_pnu", _loader)
factory_cli = importlib.util.module_from_spec(_spec)
_loader.exec_module(factory_cli)

STUB_REPORT = "echo '{\"summary\":\"stub\",\"scanned_files\":0,\"findings\":[]}'\n"


def manifest(**overrides):
    cfg = {
        "name": "probe",
        "containment": "t0-readonly",
        "capabilities": {"write": False, "network": False, "browser": False, "requires": []},
        "budget": {"max_minutes": 5},
    }
    cfg.update(overrides)
    return cfg

from tests import containment_harness as harness

# TestDispatcher's tests read TestAdapters.ENGINE_BINARY. Import the MODULE, not the name:
# a class imported into this namespace would be collected by discovery here as well, which is
# the duplicate-run shape this split exists to remove (agents-3iog).
from tests import test_containment_adapters as adapters

class TestHardening(harness.ContainmentHarness):
    """Planted artifacts and a session tampering with its own record."""


    def test_a_planted_session_patch_tmp_symlink_is_not_followed(self):
        """agents-5bn: the run dir is rw-bound inside the sandbox, so a write-granted session
        could plant a symlink at session.patch.tmp pointing at an arbitrary operator-writable
        host file; host-side collection writing the temp file must not follow it. Unlink the name
        before writing so the planted target is never overwritten."""
        target = self.root / "symlink-target"
        target.mkdir()
        subprocess.run(["git", "init", "-q", str(target)], check=True, capture_output=True)
        (target / "f.txt").write_text("one\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(target), "add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(target), "-c", "user.email=f@t", "-c", "user.name=f",
                        "commit", "-qm", "init"], check=True, capture_output=True)
        wt = self.root / "symlink-wt"
        gitdir = factory_cli._create_session_worktree(target, wt)
        (wt / "f.txt").write_text("one\ntwo\n", encoding="utf-8")
        run_dir = self.root / "symlink-run"
        run_dir.mkdir()
        canary = self.root / "canary.txt"
        canary.write_text("DO NOT OVERWRITE", encoding="utf-8")
        # A planted symlink at the temp-file path, as a write-granted session could leave.
        (run_dir / "session.patch.tmp").symlink_to(canary)
        try:
            patch_file = factory_cli._collect_session_diff(wt, run_dir, gitdir)
            self.assertIsNotNone(patch_file)
            self.assertEqual(canary.read_text(encoding="utf-8"), "DO NOT OVERWRITE",
                             "the planted symlink must never redirect the temp write at its target")
            self.assertIn("two", (run_dir / "session.patch").read_text(encoding="utf-8"))
        finally:
            factory_cli._remove_session_worktree(target, wt)


    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_a_forged_candidates_json_without_a_prepass_fails_closed(self):
        """agents-5bn: even a write-granted agent with no deterministic pre-pass must not be
        able to mint its own candidates.json — it has no trusted origin. The dispatcher refuses
        findings dispatch when candidates.json exists but no pre-pass produced it."""
        self._git_init_target()
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "printf '{\"candidates\":[{\"rule_id\":\"forged\",\"path\":\"forged.py\"}]}'"
            " > ../candidates.json\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        res = self.factory("pi")
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertIn("candidates.json appeared during the engine session", res.stderr)


    def test_write_run_artifact_does_not_follow_a_planted_symlink(self):
        """agents-5bn P0: a write-granted session can plant a symlink at any run-dir path; the
        helper must unlink it first so the write never follows it to an arbitrary host file."""
        run_dir = self.root / "symlink-artifact-run"
        run_dir.mkdir()
        canary = self.root / "authorized_keys"
        canary.write_text("SSH CANARY", encoding="utf-8")
        target = run_dir / "report.json"
        target.symlink_to(canary)
        factory_cli._write_run_artifact(target, '{"summary": "clean"}')
        self.assertEqual(canary.read_text(encoding="utf-8"), "SSH CANARY",
                         "the write must not follow the planted symlink")
        self.assertEqual(target.read_text(encoding="utf-8"), '{"summary": "clean"}',
                         "the artifact must be a fresh regular file")


    def test_write_run_artifact_fails_closed_on_a_planted_directory(self):
        """agents-5bn P0: a session could plant a directory at an artifact path; unlink on a
        directory raises, so the write fails closed rather than erroring into a bad state."""
        run_dir = self.root / "symlink-dir-run"
        run_dir.mkdir()
        target = run_dir / "report.json"
        target.mkdir()
        with self.assertRaises(factory_cli.StationError):
            factory_cli._write_run_artifact(target, "x")


    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_a_planted_report_json_symlink_is_not_followed(self):
        """agents-5bn P0 end-to-end: a write-granted session plants a symlink at
        run_dir/report.json pointing at a host canary; the post-session report.json write must
        unlink it first, so the canary is untouched and the real report is written."""
        self._git_init_target()
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        canary = self.root / "authorized_keys"
        canary.write_text("SSH CANARY", encoding="utf-8")
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            f"ln -s {canary} ../report.json\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(canary.read_text(encoding="utf-8"), "SSH CANARY",
                         "the post-session report.json write must not follow the planted symlink")
        report = json.loads((self.run_dirs()[0] / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(report.get("summary"), "stub", "the real report.json must be written")


    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_staging_writes_no_content_blobs_into_the_shared_object_store(self):
        """agents-7ik (c): intent-to-add staging must not litter the target's shared
        .git/objects with unreferenced content blobs (a plain `git add -A` wrote one per
        new/modified file every run). At most the canonical empty blob (size 0) may
        appear, once; never the session's content."""
        self._git_init_target()
        self._editing_stub()
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        objects = self.target / ".git" / "objects"
        before = {p for p in objects.rglob("*") if p.is_file()}
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        after = {p for p in objects.rglob("*") if p.is_file()}
        new_objects = after - before
        self.assertLessEqual(len(new_objects), 1,
                             f"staging wrote {len(new_objects)} objects: {new_objects}")
        for obj in new_objects:
            sha = f"{obj.parent.name}{obj.name}"
            size = subprocess.run(["git", "-C", str(self.target), "cat-file", "-s", sha],
                                  capture_output=True, text=True, check=True).stdout.strip()
            self.assertEqual(size, "0", "the only allowed new object is the empty blob")


    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_gitignored_edits_are_reported_honestly(self):
        """agents-7ik (a): a session whose only edits land in gitignored paths must not
        be reported as 'no file edits' — the files exist on disk — but as ignored edits,
        honestly not representable as a patch proposal."""
        self._git_init_target()
        (self.target / ".gitignore").write_text("ignored/\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.target), "add", ".gitignore"], check=True,
                       capture_output=True)
        subprocess.run(["git", "-C", str(self.target), "-c", "user.email=factory@test",
                        "-c", "user.name=factory", "commit", "-qm", "gitignore"],
                       check=True, capture_output=True)
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "mkdir -p ignored && printf 'junk\\n' > ignored/x.txt\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("gitignored files", res.stdout)
        self.assertIn("not representable as a patch proposal", res.stdout)
        self.assertNotIn("no file edits", res.stdout)
        self.assertFalse((self.run_dirs()[0] / "session.patch").exists())


    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_a_session_cannot_tamper_with_its_own_policy_record(self):
        """agents-7ik (2): run_dir is the read-write bind, so a granted-write session can
        reach its own policy.json — but whatever it writes there does not survive it: the
        dispatcher rewrites the record from its captured bytes after the session closes."""
        self._git_init_target()
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "echo \"POLICY:${FACTORY_TOOL_POLICY:-unset}\"\n"
            # The tamper: overwrite the containment record mid-session.
            "printf '%s' '{\"tampered\": true, \"granted\": {\"tool_policy\": \"unrestricted\"}}' "
            "> ../policy.json\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.stub_line("POLICY:"), WORKTREE_WRITE,
                         "sanity: this really was a granted-write session")
        record = json.loads((self.run_dirs()[0] / "policy.json").read_text(encoding="utf-8"))
        self.assertNotIn("tampered", record)
        self.assertEqual(record["granted"]["tool_policy"], WORKTREE_WRITE,
                         "the post-session rewrite must restore the dispatcher's record")

if __name__ == "__main__":
    unittest.main()
