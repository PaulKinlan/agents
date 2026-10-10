"""agents-4sij: the store lock wait is BOUNDED, and its failure is loud and identifiable.

A reviewer lost an entire deadline to the old behaviour: FindingsStore took a blocking flock with no
timeout and no diagnostic, so a contended store produced no verdict at all. The failure mode of an
unbounded wait is SILENCE, not an error.

These tests hold the lock DELIBERATELY and assert the bounded failure. A free-lock test proves
nothing here, because a test that passes on the old code cannot show that the old code was the
defect. Every opener runs in its own process under an outer timeout, so if the bound regresses to an
unbounded wait the child is killed and the assertion fails - instead of hanging the suite, which is
what the defect did to a real reviewer.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Takes the store lock and holds it, exactly as a long factory run does.
HOLDER = (
    "import sys, time; sys.path.insert(0, {root!r}); from pathlib import Path;"
    "from lib.findings import FindingsStore;"
    "s = FindingsStore('probe', findings_dir=Path({tmp!r}));"
    "print('HELD', flush=True); time.sleep(60)"
)
# Opens the same store and reports HOW it failed: the type matters, because a caller must be able to
# tell contention from a genuine store error.
OPENER = (
    "import sys, time; sys.path.insert(0, {root!r}); from pathlib import Path;"
    "from lib.findings import FindingsStore, StoreBusyError;"
    "t0 = time.monotonic();"
    "\ntry:\n"
    "    s = FindingsStore('probe', findings_dir=Path({tmp!r}));"
    "    s.close()\n"
    "except StoreBusyError as e:\n"
    "    print('StoreBusyError', e); sys.exit(3)\n"
    "print('acquired after %.1fs' % (time.monotonic() - t0)); sys.exit(0)"
)

OUTER_TIMEOUT = 25  # generous on purpose: exceeding it means the wait was NOT bounded


class TestStoreLockWaitIsBounded(unittest.TestCase):
    def _hold_lock(self, tmp):
        proc = subprocess.Popen(
            [sys.executable, "-c", HOLDER.format(root=str(ROOT), tmp=tmp)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.addCleanup(self._reap, proc)  # never leave a lock holder behind
        line = proc.stdout.readline()
        self.assertEqual(line.strip(), "HELD", "the holder never took the lock")
        return proc

    @staticmethod
    def _reap(proc):
        """Kill and REAP the holder: an unwaited child outlives the test and warns on collection."""
        proc.kill()
        proc.wait(timeout=10)
        for stream in (proc.stdout, proc.stderr):
            if stream is not None:
                stream.close()

    def _open(self, tmp, timeout_env=None):
        env = dict(os.environ)
        if timeout_env is not None:
            env["FACTORY_STORE_LOCK_TIMEOUT"] = timeout_env
        started = time.monotonic()
        proc = subprocess.run(
            [sys.executable, "-c", OPENER.format(root=str(ROOT), tmp=tmp)],
            capture_output=True, text=True, env=env, timeout=OUTER_TIMEOUT,
        )
        return proc, time.monotonic() - started

    def test_a_contended_writer_fails_bounded_with_the_holder_named(self):
        """The diagnostic is the point: "store busy" with no owner makes a lane retry blindly."""
        with tempfile.TemporaryDirectory() as tmp:
            self._hold_lock(tmp)
            proc, elapsed = self._open(tmp, timeout_env="1")

            self.assertNotEqual(proc.returncode, 0, proc.stdout)
            out = proc.stdout + proc.stderr
            self.assertIn("is locked", out)
            self.assertIn("pid ", out)          # who holds it
            self.assertIn("since ", out)        # and since when
            self.assertIn("waited 1s", out)     # the bound that was hit
            self.assertIn("StoreBusyError", out)  # distinguishable from a store error
            self.assertLess(elapsed, OUTER_TIMEOUT, "the wait was not bounded")

    def test_the_wait_is_bounded_but_not_instant(self):
        """It must WAIT up to the bound and then fail - not give up at once and not wait forever."""
        with tempfile.TemporaryDirectory() as tmp:
            self._hold_lock(tmp)
            proc, elapsed = self._open(tmp, timeout_env="2")

            self.assertNotEqual(proc.returncode, 0)
            self.assertGreaterEqual(elapsed, 1.0, "it did not wait for the store at all")
            self.assertLess(elapsed, 12.0, "the wait was not bounded by the timeout")

    def test_the_bound_is_raised_by_the_environment(self):
        """A lane that must wait longer can say so per process, without editing the default."""
        with tempfile.TemporaryDirectory() as tmp:
            self._hold_lock(tmp)
            proc, elapsed = self._open(tmp, timeout_env="4")
            self.assertNotEqual(proc.returncode, 0)
            self.assertGreaterEqual(elapsed, 3.0, "the environment override was ignored")

    def test_a_reader_never_waits_for_a_held_lock(self):
        """Requirement 4: a reader that blocks behind a writer is the same bug wearing a new hat.

        The store is replaced atomically on save, so a read-only open that cannot take the shared
        lock proceeds anyway rather than blocking.
        """
        with tempfile.TemporaryDirectory() as tmp:
            self._hold_lock(tmp)
            sys.path.insert(0, str(ROOT))
            from lib.findings import FindingsStore  # imported here: the child needs it first

            started = time.monotonic()
            store = FindingsStore("probe", findings_dir=Path(tmp), read_only=True, lock_timeout=0)
            try:
                self.assertIn("findings", store.data)
            finally:
                store.close()
            self.assertLess(time.monotonic() - started, 5.0, "a reader blocked on a writer's lock")

    def test_a_free_store_acquires_immediately(self):
        """The guard must not reject an uncontended store - the bound is a ceiling, not a delay."""
        with tempfile.TemporaryDirectory() as tmp:
            sys.path.insert(0, str(ROOT))
            from lib.findings import FindingsStore

            started = time.monotonic()
            store = FindingsStore("probe", findings_dir=Path(tmp))
            try:
                lock_text = (Path(tmp) / "probe.json.lock").read_text(encoding="utf-8")
                self.assertIn(f"pid {os.getpid()}", lock_text)  # the holder names itself
            finally:
                store.close()
            self.assertLess(time.monotonic() - started, 1.0)
            # Released: the metadata is cleared BEFORE the unlock, so a stale owner is never shown.
            self.assertEqual((Path(tmp) / "probe.json.lock").read_text(encoding="utf-8").strip(), "")


    def test_a_reader_that_proceeded_unlocked_does_not_erase_the_live_holder(self):
        """agents-4sij review P1: the diagnostic must survive the READ path.

        A read-only store that cannot take the shared lock proceeds UNLOCKED - it never held the
        lock - so close() must not clear the holder line. Clearing it turned the file from
        "pid N lane L since T" into EMPTY while the writer was still running, so every later waiter
        reported "holder unknown" with a holder very much alive: the diagnostic this bead exists to
        provide, destroyed by the read path.
        """
        with tempfile.TemporaryDirectory() as tmp:
            self._hold_lock(tmp)
            lock_file = Path(tmp) / "probe.json.lock"
            before = lock_file.read_text(encoding="utf-8").strip()
            self.assertIn("pid ", before, "the holder never published its line")

            sys.path.insert(0, str(ROOT))
            from lib.findings import FindingsStore  # imported here: the child needs it first

            FindingsStore("probe", findings_dir=Path(tmp), read_only=True, lock_timeout=0).close()

            after = lock_file.read_text(encoding="utf-8").strip()
            self.assertIn("pid ", after,
                          "the reader erased the live holder's diagnostic line")

    def test_the_cli_reports_a_contended_store_cleanly_instead_of_a_traceback(self):
        """agents-4sij review P2: StoreBusyError is a SIBLING of StoreFileError, so the CLI had to
        name it. Before that, contention - which this bead introduced as a bounded failure - reached
        the operator as an uncaught traceback instead of the deliberate "Error: ..." and exit 2.

        Load-bearing: drop StoreBusyError from that tuple and this fails on the traceback.
        """
        import json
        target = f"locktest-{os.getpid()}"
        findings_dir = ROOT / "findings"
        findings_dir.mkdir(exist_ok=True)
        lock_file = findings_dir / f"{target}.json.lock"
        try:
            sys.path.insert(0, str(ROOT))
            from lib.findings import FindingsStore

            # This process holds the lock; the CLI is a DIFFERENT process, where flock really
            # excludes (same-process reopens are the self-deadlock coord filed separately).
            holder = FindingsStore(target, lock_timeout=0)
            findings_in_dir = Path(tempfile.mkdtemp())
            findings_in = findings_in_dir / "in.json"
            try:
                findings_in.write_text(json.dumps({"findings": []}), encoding="utf-8")
                res = subprocess.run(
                    [sys.executable, str(ROOT / "lib" / "findings.py"), "--target", target,
                     "--agent", "vuln-discovery", "--input", str(findings_in), "--sink", "file"],
                    capture_output=True, text=True, timeout=OUTER_TIMEOUT,
                )
            finally:
                holder.close()
                shutil.rmtree(findings_in_dir, ignore_errors=True)
            self.assertEqual(res.returncode, 2,
                             f"expected the clean error path, got rc={res.returncode}: {res.stderr}")
            self.assertIn("is locked", res.stderr)
            self.assertNotIn("Traceback", res.stderr,
                             "contention arrived as an uncaught traceback")
        finally:
            # Never leave litter in the repo's findings directory.
            try:
                lock_file.unlink(missing_ok=True)
            except OSError:
                pass

    def test_a_reader_holding_the_shared_lock_does_not_claim_to_be_the_writer(self):
        """Review out-of-scope note, pinned: the holder metadata describes a WRITER.

        A read-only store that takes the shared lock on a FREE store is not writing anything, so it
        must leave that line alone - otherwise two concurrent readers clobber each other's line, and
        a waiter is told that a reader owns the store. Load-bearing: with publishing left
        unconditional, the first reader writes "pid ... lane ..." and this fails.
        """
        with tempfile.TemporaryDirectory() as tmp:
            sys.path.insert(0, str(ROOT))
            from lib.findings import FindingsStore

            lock_file = Path(tmp) / "probe.json.lock"
            FindingsStore("probe", findings_dir=Path(tmp), read_only=True).close()
            self.assertEqual(lock_file.read_text(encoding="utf-8").strip(), "",
                             "a reader published holder metadata describing a writer")

            reader = FindingsStore("probe", findings_dir=Path(tmp), read_only=True)
            try:
                self.assertEqual(lock_file.read_text(encoding="utf-8").strip(), "",
                                 "a second reader wrote a line while the first was open")
            finally:
                reader.close()

    def test_the_promote_path_reports_a_contended_store_cleanly_too(self):
        """The SECOND store-opening site (lib/sinks/github.py), reached only from main()'s promote
        branch at findings.py:1529. Promoting a public issue is human-invoked, which is the worst
        place for a traceback, so the bounded-wait failure must take the same clean path as the run.

        The harness has to be IN-PROCESS, and that is not a shortcut: resolve_tool ENFORCES a
        content pin on gh, so a fake gh can never be injected through PATH - which is the point of
        that module. So this patches resolve_tool and asserts the catch turns StoreBusyError into a
        clean exit 2 rather than letting it escape. Load-bearing: without the promote-path catch the
        exception propagates and this fails on StoreBusyError instead of SystemExit.

        BOTH tools that path resolves are intercepted, gh and bd, because github.py:83 resolves them
        on its first line: a host with no bd pin (and no bd on PATH) otherwise failed HERE, on a
        ToolPinError for a tool this test never means to run. That failed loudly rather than wrongly,
        but it made the harness unportable to a host whose pin state is not this one's.
        """
        import contextlib
        import io
        import json as _json
        import shutil
        from unittest import mock

        import lib.sinks.github as ghmod
        from lib.findings import FindingsStore, main as findings_main
        from lib.tool_pins import resolve_tool as real_resolve_tool

        target = f"locktest-promote-{os.getpid()}"
        findings_dir = ROOT / "findings"
        findings_dir.mkdir(exist_ok=True)
        lock_file = findings_dir / f"{target}.json.lock"
        repo = "example-owner/example-repo"
        url = f"https://github.com/{repo}/issues/7"
        fp = "a" * 64
        fake_bin = Path(tempfile.mkdtemp())
        beads_dir = Path(tempfile.mkdtemp())
        (beads_dir / ".beads").mkdir()
        bd = fake_bin / "bd"
        bd.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            "if 'list' in sys.argv:\n"
            "    print(json.dumps([]))\n"
            "else:\n"
            "    sys.exit('fake bd: unexpected call on the promote path')\n",
            encoding="utf-8")
        bd.chmod(0o755)
        gh = fake_bin / "gh"
        gh.write_text(
            "#!/usr/bin/env python3\n"
            "import json, sys\n"
            "endpoint = sys.argv[-1]\n"
            "if endpoint.endswith('/issues/7'):\n"
            "    print(json.dumps({'number': 7, 'html_url': '" + url + "',\n"
            "                      'body': '**Fingerprint**: `" + fp + "`',\n"
            "                      'labels': [{'name': 'factory-approved'}]}))\n"
            "else:\n"
            "    print(json.dumps({'full_name': '" + repo + "',\n"
            "                      'html_url': 'https://github.com/" + repo + "',\n"
            "                      'private': False, 'has_issues': True}))\n",
            encoding="utf-8")
        gh.chmod(0o755)

        def fake_resolve(name, *args, **kwargs):
            if name == "gh":
                return str(gh)
            if name == "bd":
                return str(bd)
            return real_resolve_tool(name, *args, **kwargs)

        holder = FindingsStore(target, lock_timeout=0)  # this process holds the store lock
        try:
            err = io.StringIO()
            # Short bound: this exercises the BOUND and the clean error path, not the default 10s.
            with mock.patch.dict(os.environ, {"FACTORY_STORE_LOCK_TIMEOUT": "1"}), \
                 mock.patch.object(ghmod, "resolve_tool", side_effect=fake_resolve):
                with contextlib.redirect_stderr(err):
                    with self.assertRaises(SystemExit) as caught:
                        findings_main(["--target", target, "--target-dir", str(ROOT),
                                       "--promote-issue", url, "--repo", repo,
                                       "--visibility", "public", "--beads-dir", str(beads_dir)])
            self.assertEqual(caught.exception.code, 2, err.getvalue())
            self.assertIn("is locked", err.getvalue(),
                          "the promote path did not report the contention")
        finally:
            holder.close()
            try:
                lock_file.unlink(missing_ok=True)
            except OSError:
                pass
            shutil.rmtree(fake_bin, ignore_errors=True)
            shutil.rmtree(beads_dir, ignore_errors=True)

    def test_promote_issue_uses_existing_store_without_reopening_file(self):
        """agents-ynjh: promote_issue uses provided store directly without second open/flock."""
        import lib.sinks.github as ghmod
        from lib.findings import FindingsStore
        target = f"test-ynjh-{int(time.time())}"
        findings_dir = ROOT / "findings"
        findings_dir.mkdir(exist_ok=True)
        fp = "a" * 64
        # Hold the lock on this target in this process.
        store = FindingsStore(target, lock_timeout=0)
        try:
            mock_store = mock.MagicMock()
            mock_store.data = {"findings": {fp: {"fingerprint": fp, "title": "Test", "agent": "probe"}}}
            with mock.patch("lib.findings.FindingsStore") as mock_fs_cls, \
                 mock.patch("lib.sinks.github.resolve_tool", return_value="/bin/true"), \
                 mock.patch("lib.sinks.github._gh_api") as mock_gh, \
                 mock.patch("lib.sinks.github._bd_json") as mock_bd:
                mock_gh.side_effect = [
                    {"full_name": "owner/repo", "html_url": "https://github.com/owner/repo", "private": False, "has_issues": True},
                    {"number": 1, "html_url": "https://github.com/owner/repo/issues/1", "body": f"**Fingerprint**: `{fp}`", "labels": [{"name": "factory-approved"}]},
                    [],
                    {},
                ]
                mock_bd.side_effect = [
                    [],  # list returns no beads
                    {"id": "fixture-1"},  # create returns new bead
                ]
                res = ghmod.promote_issue(
                    target, ROOT, "owner/repo", "public",
                    "https://github.com/owner/repo/issues/1", ROOT,
                    store=mock_store,
                )
                self.assertEqual(res["status"], "created")
                self.assertEqual(res["bead_id"], "fixture-1")
                # FindingsStore was NOT instantiated because store was passed in directly
                mock_fs_cls.assert_not_called()
                mock_store.save.assert_called_once()
        finally:
            store.close()
            try:
                (findings_dir / f"{target}.json.lock").unlink(missing_ok=True)
            except OSError:
                pass
