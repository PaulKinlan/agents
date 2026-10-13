"""agents-kxbv: the beads pre-commit hook must never decide whether a commit exists.

The hook's payload is the passive ``.beads/issues.jsonl`` export - issues live in the local Dolt DB
and sync over ``refs/dolt/data`` - so no export outcome may block a commit. The pre-change hook
already continued for its own timeout (124/142) and for "database not initialized" (3), but aborted
on every OTHER non-zero result, which included 75 (EX_TEMPFAIL, "try again") - the code a bounded
``bd`` returns when the VM-wide lock is unavailable. A fast, correct refusal therefore killed the
commit while a 300s stall was tolerated, which is the inversion this suite pins.

Measured, not asserted: against the pre-change hook, the ``exit 75`` and ``exit 1`` cases below
return 75 and 1 from the hook; a stash-the-fix run is what makes this a discriminator rather than a
suite born green.

Hermetic: a stub ``bd`` on PATH, no git repository, no lock, no network, no repository state.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / ".beads" / "hooks" / "pre-commit"


def _stub_dir(body: str) -> tempfile.TemporaryDirectory:
    """A directory holding an executable ``bd`` stub that runs ``body``."""
    tmp = tempfile.TemporaryDirectory(prefix="kxbv-hook-")
    stub = Path(tmp.name) / "bd"
    stub.write_text("#!/usr/bin/env sh\n" + body)
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return tmp


class TestPreCommitHookFailsOpen(unittest.TestCase):
    def _run(self, bd_body: str, timeout_env: str | None = None, wall: int = 30):
        """Run the real hook with a stub bd first on PATH. Returns (CompletedProcess, elapsed)."""
        with _stub_dir(bd_body) as stub_dir:
            env = dict(os.environ)
            env["PATH"] = stub_dir + os.pathsep + env.get("PATH", "")
            if timeout_env is not None:
                env["BEADS_HOOK_TIMEOUT"] = timeout_env
            started = time.monotonic()
            proc = subprocess.run(
                ["sh", str(HOOK)], cwd=stub_dir, env=env,
                capture_output=True, text=True, timeout=wall,
            )
            return proc, time.monotonic() - started

    def test_a_healthy_export_does_not_disturb_the_commit(self):
        proc, _ = self._run("exit 0\n")
        self.assertEqual(proc.returncode, 0, f"healthy path must exit 0:\n{proc.stderr}")
        self.assertNotIn("could not export", proc.stderr)

    def test_lock_unavailable_fails_open(self):
        """DISCRIMINATOR: the pre-change hook returned 75 and git aborted the commit."""
        proc, _ = self._run("echo 'bd: lock unavailable (75)' >&2\nexit 75\n")
        self.assertEqual(proc.returncode, 0,
                         f"bd exit 75 (EX_TEMPFAIL, 'try again') must not abort the commit:\n{proc.stderr}")
        self.assertIn("continuing without beads", proc.stderr)

    def test_a_generic_bd_error_fails_open(self):
        """DISCRIMINATOR: the pre-change hook returned 1 and git aborted the commit."""
        proc, _ = self._run("echo 'bd: boom' >&2\nexit 1\n")
        self.assertEqual(proc.returncode, 0,
                         f"a bd error must not abort the commit (the export is a copy, not the source):\n{proc.stderr}")
        self.assertIn("continuing without beads", proc.stderr)

    def test_database_not_initialized_still_fails_open(self):
        """Not a discriminator (3 already continued), kept because it shares the same exit path."""
        proc, _ = self._run("exit 3\n")
        self.assertEqual(proc.returncode, 0, f"exit 3 must continue:\n{proc.stderr}")

    def test_a_slow_export_is_bounded_by_env_and_fails_open(self):
        """The TWO-LAYER case: the inner timeout (124) and the outer policy meet in one shell.
        Asserts ELAPSED time as well as the exit code - the bound must FIRE rather than wait."""
        proc, elapsed = self._run("sleep 5\n", timeout_env="1")
        self.assertEqual(proc.returncode, 0, f"a timed-out export must continue:\n{proc.stderr}")
        self.assertLess(elapsed, 4.0, f"the bound must fire rather than wait for the export ({elapsed:.1f}s)")
        self.assertIn("continuing without beads", proc.stderr)

    def test_the_default_bound_is_a_stall_limit_not_five_minutes(self):
        """Structural, and honest about being structural: the default bound cannot be waited out in a
        test, so it is asserted from the hook's own text. 300s was the measured harm (agents-kxbv:
        four lanes' bead writes stalled behind one lock incident, one finding needed another actor to
        record it, a lane was wedged 64 minutes); 20s was chosen above the measured healthy runs
        (hook no-op p50 0.07s over 20 runs; lock-taking bd calls p50 1.9s / max 13.5s on this VM).
        Any default above 30s reintroduces a stall a lane cannot tell from a hang."""
        text = HOOK.read_text()
        self.assertNotIn("BEADS_HOOK_TIMEOUT:-300", text, "the 300s default must not come back")
        match = re.search(r"BEADS_HOOK_TIMEOUT:-(\d+)", text)
        self.assertIsNotNone(match, "the hook must declare a default bound")
        self.assertLessEqual(int(match.group(1)), 30,
                             "a default bound above 30s reintroduces the stall this bead measured")
        self.assertIn("STOPGAP (agents-kxbv)", text,
                      "the stopgap marker must be present so the next installer's reader knows")

    def test_the_hook_still_aborts_nothing_that_is_not_a_commit_blocker(self):
        """The policy in one line: the hook's LAST word on a non-zero result is 'continue', so no
        future edit can quietly restore `exit $_bd_exit` at the tail."""
        text = HOOK.read_text()
        self.assertNotIn('if [ "$_bd_exit" -ne 0 ]; then exit "$_bd_exit"; fi', text,
                         "the abort-on-non-zero tail is what made a bounded shim break commits")


if __name__ == "__main__":
    unittest.main()
