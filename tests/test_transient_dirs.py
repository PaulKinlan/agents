"""Tests for agents-uxs: /tmp factory transient dirs must not leak on a hard kill.

A run that the reaper or `timeout` SIGKILLs cannot run its normal-path cleanup, so its
factory-sock-*/factory-pi-* mkdtemp dirs survive. The fix is two-fold: (1) each run sweeps
stale same-prefix dirs older than _TRANSIENT_DIR_MAX_AGE_SECONDS at the point of creating its
own dirs, and (2) every created dir is registered in _TRANSIENT_DIRS and removed by an atexit
handler on any catchable exit.
"""

import importlib.machinery
import importlib.util
import os
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_loader = importlib.machinery.SourceFileLoader("factory_cli_uxs", str(ROOT / "factory"))
_spec = importlib.util.spec_from_loader("factory_cli_uxs", _loader)
factory_cli = importlib.util.module_from_spec(_spec)
_loader.exec_module(factory_cli)

MAX_AGE = factory_cli._TRANSIENT_DIR_MAX_AGE_SECONDS


class SweepStaleTransientDirsTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _mk(self, name: str, age_seconds: float) -> Path:
        d = self.root / name
        d.mkdir()
        t = time.time() - age_seconds
        os.utime(d, (t, t))
        return d

    def test_sweep_removes_only_stale_transient_dirs(self):
        old_sock = self._mk("factory-sock-old", MAX_AGE + 60)
        old_pi = self._mk("factory-pi-old", MAX_AGE + 60)
        fresh_sock = self._mk("factory-sock-fresh", 60)
        fresh_pi = self._mk("factory-pi-fresh", 60)
        unrelated = self._mk("factory-somethingelse", MAX_AGE + 60)

        removed = factory_cli._sweep_stale_transient_dirs(root=self.root, now=time.time())

        self.assertEqual(removed, 2)
        self.assertFalse(old_sock.exists())
        self.assertFalse(old_pi.exists())
        self.assertTrue(fresh_sock.exists())
        self.assertTrue(fresh_pi.exists())
        self.assertTrue(unrelated.exists())  # not a transient prefix; never swept

    def test_sweep_returns_zero_when_nothing_is_stale(self):
        self._mk("factory-sock-fresh", 60)
        self.assertEqual(factory_cli._sweep_stale_transient_dirs(root=self.root, now=time.time()), 0)

    def test_sweep_ignores_plain_files(self):
        f = self.root / "factory-sock-file"
        f.write_text("not a dir", encoding="utf-8")
        t = time.time() - (MAX_AGE + 60)
        os.utime(f, (t, t))
        self.assertEqual(factory_cli._sweep_stale_transient_dirs(root=self.root, now=time.time()), 0)
        self.assertTrue(f.exists())


class TransientDirRegistryTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()
        factory_cli._TRANSIENT_DIRS.clear()

    def test_cleanup_transient_dirs_empties_the_registry_and_removes_dirs(self):
        d1 = self.root / "factory-sock-a"
        d2 = self.root / "factory-pi-b"
        d1.mkdir()
        d2.mkdir()
        factory_cli._TRANSIENT_DIRS.extend([d1, d2])

        factory_cli._cleanup_transient_dirs()

        self.assertFalse(d1.exists())
        self.assertFalse(d2.exists())
        self.assertEqual(factory_cli._TRANSIENT_DIRS, [])

    def test_make_dirs_register_themselves_and_cleanup_removes_them(self):
        # _make_* allocate real /tmp dirs; the sweep side-effect only reaps 24h+ orphans.
        sock = factory_cli._make_socket_dir()
        pi = factory_cli._make_pi_config_dir()
        try:
            self.assertTrue(sock.is_dir())
            self.assertTrue(pi.is_dir())
            self.assertIn(sock, factory_cli._TRANSIENT_DIRS)
            self.assertIn(pi, factory_cli._TRANSIENT_DIRS)
            self.assertEqual(os.stat(sock).st_mode & 0o777, 0o700)
            self.assertEqual(os.stat(pi).st_mode & 0o777, 0o700)
        finally:
            factory_cli._cleanup_transient_dirs()
            self.assertFalse(sock.exists())
            self.assertFalse(pi.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
