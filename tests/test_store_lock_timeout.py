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
import subprocess
import sys
import tempfile
import time
import unittest
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
            try:
                findings_in = Path(tempfile.mkdtemp()) / "in.json"
                findings_in.write_text(json.dumps({"findings": []}), encoding="utf-8")
                res = subprocess.run(
                    [sys.executable, str(ROOT / "lib" / "findings.py"), "--target", target,
                     "--agent", "vuln-discovery", "--input", str(findings_in), "--sink", "file"],
                    capture_output=True, text=True, timeout=OUTER_TIMEOUT,
                )
            finally:
                holder.close()
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

if __name__ == "__main__":
    unittest.main()
