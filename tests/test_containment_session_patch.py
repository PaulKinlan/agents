"""Containment: the session patch: collection, staging and worktree lifecycle.

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

class TestSessionPatch(harness.ContainmentHarness):
    """The session patch: collection, staging and worktree lifecycle."""


    def test_collect_session_diff_raises_on_a_stale_index_lock(self):
        """Review P1-1 (agents-6ce): if a crashed run left a stale index.lock, `git add -A`
        exits non-zero (128) while the following `git diff --cached` returns an empty rc0 diff.
        _collect_session_diff must RAISE, not return None — returning None would print 'no file
        edits (empty proposal)' and exit 0, silently discarding the engine's proposal. Uses a
        real linked worktree (round 2) so the .git marker and admin gitdir match production."""
        target = self.root / "lock-target"
        target.mkdir()
        subprocess.run(["git", "init", "-q", str(target)], check=True, capture_output=True)
        (target / "f.txt").write_text("one\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(target), "add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(target), "-c", "user.email=f@t", "-c", "user.name=f",
                        "commit", "-qm", "init"], check=True, capture_output=True)
        wt = self.root / "lock-wt"
        gitdir = factory_cli._create_session_worktree(target, wt)
        # The session "edited" a file, then a crashed run left a stale lock in the admin gitdir.
        (wt / "f.txt").write_text("one\ntwo\n", encoding="utf-8")
        lock = gitdir / "index.lock"
        lock.write_text("", encoding="utf-8")
        run_dir = self.root / "lock-run"
        run_dir.mkdir()
        try:
            with self.assertRaises(factory_cli.StationError):
                factory_cli._collect_session_diff(wt, run_dir, gitdir)
            self.assertFalse((run_dir / "session.patch").exists(),
                             "a failed stage must not produce a patch")
        finally:
            lock.unlink(missing_ok=True)


    def test_second_collection_write_failure_keeps_the_first_patch_intact(self):
        """agents-nei P1-2 (round 4): each kept win re-collects session.patch in place, so a
        failure during a LATER collection's write (disk full) could truncate the earlier good
        patch and strand an already-durable KEPT row. The write must go to a sibling temp file
        and be atomically os.replace()'d only after it completes."""
        target = self.root / "atomic-target"
        target.mkdir()
        subprocess.run(["git", "init", "-q", str(target)], check=True, capture_output=True)
        (target / "f.txt").write_text("one\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(target), "add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(target), "-c", "user.email=f@t", "-c", "user.name=f",
                        "commit", "-qm", "init"], check=True, capture_output=True)
        wt = self.root / "atomic-wt"
        gitdir = factory_cli._create_session_worktree(target, wt)
        run_dir = self.root / "atomic-run"
        run_dir.mkdir()

        # First collection succeeds and writes the first accumulated proposal.
        (wt / "f.txt").write_text("one\ntwo\n", encoding="utf-8")
        factory_cli._collect_session_diff(wt, run_dir, gitdir)
        patch_file = run_dir / "session.patch"
        first_patch = patch_file.read_bytes()
        self.assertIn(b"two", first_patch)
        self.assertNotIn(b"three", first_patch)

        # A second accumulated edit is re-collected, but its write fails (disk full) only
        # AFTER the target file has been truncated and a partial prefix written — the exact
        # failure the temp-file+replace path must survive. The earlier patch must remain
        # byte-for-byte intact (a), so the already-durable KEPT row's proposal still matches
        # what is on disk (b), and the failed temp file must be cleaned up.
        (wt / "f.txt").write_text("one\ntwo\nthree\n", encoding="utf-8")

        def write_prefix_then_fail(path, data, encoding="utf-8"):
            # In-place implementations truncate the write target and write a prefix before the
            # error. Here the prefix lands in whatever file _collect_session_diff is writing;
            # the assertions below prove that file is a throwaway temp, not session.patch.
            path.write_bytes(data[:12].encode(encoding))
            raise OSError("disk full")

        with mock.patch.object(Path, "write_text", write_prefix_then_fail):
            with self.assertRaises(OSError):
                factory_cli._collect_session_diff(wt, run_dir, gitdir)

        self.assertEqual(patch_file.read_bytes(), first_patch)  # (a) byte-for-byte intact
        self.assertIn(b"two", patch_file.read_bytes())          # (b) kept proposal still on disk
        self.assertNotIn(b"three", patch_file.read_bytes())
        self.assertFalse((run_dir / "session.patch.tmp").exists(),
                         "a failed write must not leak the temp file")


    def test_a_non_utf8_worktree_marker_fails_closed(self):
        """agents-7ik (4): a binary .git marker raises UnicodeDecodeError (a ValueError,
        not an OSError) — it must surface as a clean StationError, never an unhandled
        traceback. Fail-closed: host-side git is refused against the marker."""
        target = self.root / "bin-target"
        target.mkdir()
        subprocess.run(["git", "init", "-q", str(target)], check=True, capture_output=True)
        (target / "f.txt").write_text("one\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(target), "add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(target), "-c", "user.email=f@t", "-c", "user.name=f",
                        "commit", "-qm", "init"], check=True, capture_output=True)
        wt = self.root / "bin-wt"
        gitdir = factory_cli._create_session_worktree(target, wt)
        (wt / ".git").write_bytes(b"\xff\xfe\x00not-a-gitdir-pointer")
        with self.assertRaises(factory_cli.StationError) as ctx:
            factory_cli._validate_worktree_marker(wt, gitdir)
        self.assertIn("not UTF-8", str(ctx.exception))
        factory_cli._remove_session_worktree(target, wt)


    def test_a_redirected_worktree_git_marker_is_refused_not_followed(self):
        """Review P1-1 round 2 (agents-6ce): the worktree's .git marker is a FILE inside the
        writable run_dir, so a write-enabled model can replace `gitdir: <target>/.git/worktrees/
        <name>` with `gitdir: <target>/.git`. An unpinned host-side `git add -A` would then run
        against the operator's real repo and STAGE THE OPERATOR'S uncommitted target edits.
        _collect_session_diff must validate the marker against the admin gitdir captured at
        creation and REFUSE; its --git-dir/--work-tree pinning is the second layer that makes
        the redirect ineffective regardless. The operator's target index must be untouched."""
        target = self.root / "redirect-target"
        target.mkdir()
        subprocess.run(["git", "init", "-q", str(target)], check=True, capture_output=True)
        (target / "committed.txt").write_text("base\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(target), "add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(target), "-c", "user.email=f@t", "-c", "user.name=f",
                        "commit", "-qm", "init"], check=True, capture_output=True)
        # An operator edit sitting UNSTAGED in the target's own checkout — exactly what the
        # attack would stage into the target's index if host-side git followed the marker.
        (target / "committed.txt").write_text("base\nOPERATOR UNCOMMITTED WORK\n", encoding="utf-8")
        index_before = (target / ".git" / "index").read_bytes()

        wt = self.root / "redirect-wt"
        gitdir = factory_cli._create_session_worktree(target, wt)
        # The model edits its worktree, then repoints the .git marker at the target's real .git.
        (wt / "committed.txt").write_text("base\nmodel edit\n", encoding="utf-8")
        (wt / ".git").write_text(f"gitdir: {target / '.git'}\n", encoding="utf-8")

        run_dir = self.root / "redirect-run"
        run_dir.mkdir()
        try:
            with self.assertRaises(factory_cli.StationError):
                factory_cli._collect_session_diff(wt, run_dir, gitdir)
            self.assertFalse((run_dir / "session.patch").exists(),
                             "a refused marker redirect must not produce a patch")
            self.assertEqual((target / ".git" / "index").read_bytes(), index_before,
                             "the redirected marker must never stage the operator's target index")
        finally:
            factory_cli._remove_session_worktree(target, wt)


    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_the_worktree_is_removed_even_when_the_engine_fails(self):
        """agents-6ce hard requirement: no leaked worktrees. An engine that edits the worktree
        and then FAILS must still have its disposable worktree discarded by the finally block,
        and the target checkout must stay byte-identical. Gated on bwrap and asserting the
        worktree-write policy + a /worktree cwd FIRST (review P1-2 round 2): without a real OS
        sandbox the run downgrades to read-only, no worktree is created, and the cleanup
        assertions below would pass vacuously — proving nothing about worktree cleanup."""
        self._git_init_target()
        # A stub that records its policy/cwd, edits a file inside the worktree, then fails
        # (non-zero, no report). The adapter propagates the failure (pi.sh: `pi ... || exit 1`),
        # so run_agent raises StationError only AFTER the finally has removed the worktree.
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "echo \"POLICY:${FACTORY_TOOL_POLICY:-unset}\"\n"
            "echo \"CWD:$(pwd)\"\n"
            "printf '// edited then crashed\\n' >> fixme.txt\n"
            "cat >/dev/null\n"
            "exit 7\n",
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        before = self._target_fingerprint()
        res = self.factory("pi")
        self.assertNotEqual(res.returncode, 0, "a failed engine must fail the run")
        # Prove the worktree path was actually taken (review P1-2 round 2): the grant was
        # worktree-write and the engine ran inside the disposable worktree, not the target.
        # Without this the cleanup assertions below could pass on a downgraded read-only run.
        self.assertEqual(self.stub_line("POLICY:"), WORKTREE_WRITE)
        self.assertTrue(self.stub_line("CWD:").endswith("/worktree"), self.stub_line("CWD:"))
        # No worktree leaked despite the failure, and the target is byte-identical.
        self._assert_no_leaked_worktree()
        self.assertEqual(self._target_fingerprint(), before,
                         "the target checkout must be byte-identical even when the engine fails")
        # agents-7ik (d): a failed session's partial edits are NOT collected as a proposal.
        self.assertIn("discarding its partial edits", res.stdout)
        self.assertFalse((self.run_dirs()[0] / "session.patch").exists(),
                         "a failed session must not leave a proposal patch")


    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_the_session_patch_carries_a_base_commit_and_applies_cleanly(self):
        """agents-7ik (b): session.patch begins with a `base-commit:` trailer naming the
        base HEAD, so a proposal can never be applied blind against a moved HEAD — and
        git apply skips the trailer (verified here by applying the whole marked patch to a
        fresh clone of the same base)."""
        self._git_init_target()
        self._editing_stub()
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        run_dir = self.run_dirs()[0]
        patch_text = (run_dir / "session.patch").read_text(encoding="utf-8")
        head = subprocess.run(["git", "-C", str(self.target), "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
        self.assertTrue(patch_text.startswith(f"base-commit: {head}\n"),
                        patch_text[:120])
        clone = self.root / "apply-clone"
        subprocess.run(["git", "clone", "-q", str(self.target), str(clone)],
                       check=True, capture_output=True)
        applied = subprocess.run(["git", "-C", str(clone), "apply",
                                  str(run_dir / "session.patch")],
                                 capture_output=True, text=True)
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.assertTrue((clone / "proposed.txt").exists(),
                        "the proposal's new file must apply")


    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_a_tampered_candidates_json_fails_closed(self):
        """agents-5bn: candidates.json is the scanner's ground truth (agents-nha) that binds
        the model's rule_id/path at findings dispatch, which runs AFTER the session. The run
        dir is rw-bound inside the sandbox, so a write-granted session can overwrite it. The
        dispatcher snapshots the trusted bytes before the session and must REFUSE the dispatch
        (station failure) when the session changed them — never book findings against forged
        ground truth."""
        self._git_init_target()
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        scripts = self.root / "agents" / "probe" / "scripts"
        scripts.mkdir(parents=True)
        (scripts / "prepass.py").write_text(
            "import json, sys\n"
            "out = sys.argv[sys.argv.index('--output') + 1]\n"
            "with open(out, 'w', encoding='utf-8') as fh:\n"
            "    json.dump({'candidates': [{'rule_id': 'vuln-x', 'path': 'fixme.txt',\n"
            "                              'line_number': 1, 'snippet': 'original line'}]}, fh)\n",
            encoding="utf-8",
        )
        # A write-granted session that overwrites the scanner ground truth from inside its
        # worktree (the run dir is the worktree's parent): ../candidates.json.
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "printf 'FORGED' > ../candidates.json\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        res = self.factory("pi")
        self.assertEqual(res.returncode, 2, res.stdout + res.stderr)
        self.assertIn("candidates.json changed during the engine session", res.stderr)


    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_an_untampered_write_session_with_candidates_dispatches(self):
        """agents-5bn positive control: a write-granted session that leaves candidates.json
        alone still dispatches normally — the snapshot verification must not false-positive on
        the honest path (a pre-pass that produces candidates, then a normal editing session)."""
        self._git_init_target()
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        scripts = self.root / "agents" / "probe" / "scripts"
        scripts.mkdir(parents=True)
        (scripts / "prepass.py").write_text(
            "import json, sys\n"
            "out = sys.argv[sys.argv.index('--output') + 1]\n"
            "with open(out, 'w', encoding='utf-8') as fh:\n"
            "    json.dump({'candidates': [{'rule_id': 'vuln-x', 'path': 'fixme.txt',\n"
            "                              'line_number': 1, 'snippet': 'original line'}]}, fh)\n",
            encoding="utf-8",
        )
        self._editing_stub()
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        run_dir = self.run_dirs()[0]
        patch = run_dir / "session.patch"
        self.assertTrue(patch.exists(), "the honest editing session must still collect a patch")
        self.assertIn("proposed fix", patch.read_text(encoding="utf-8"))


    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_a_preplaced_session_patch_is_discarded_when_no_edits_are_made(self):
        """agents-5bn: a write-granted session runs with the run dir rw-bound, so it can write
        run_dir/session.patch directly and be credited with a proposal it never made in the
        worktree. When the session makes no trackable edits, _collect_session_diff returns None
        and the dispatcher must discard any session.patch left in the run dir — only a collected
        patch is a real proposal."""
        self._git_init_target()
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "printf 'forged proposal' > ../session.patch\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertFalse((self.run_dirs()[0] / "session.patch").exists(),
                         "a forged pre-placed session.patch must not survive a no-edit session")

if __name__ == "__main__":
    unittest.main()
