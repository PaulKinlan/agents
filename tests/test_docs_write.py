"""tests/test_docs_write.py - docs-write's pre-pass must never emit a successful-looking
zero when its docs-drift producer or the temp file it depends on fails (agents-h0mb
review, P1): an empty scan and a failed scan are different outcomes, so failure is
reported on stderr with a nonzero exit and NO payload is emitted.
"""

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agents" / "docs-write" / "scripts"))

import prepare_docs_fixes  # noqa: E402


class TestProducerFailureIsVisible(unittest.TestCase):

    def _run_main(self, target):
        argv = ["prepare_docs_fixes.py", "--target", str(target)]
        stdout, stderr = io.StringIO(), io.StringIO()
        exit_code = None
        with mock.patch.object(sys, "argv", argv), \
                contextlib.redirect_stdout(stdout), \
                contextlib.redirect_stderr(stderr):
            try:
                prepare_docs_fixes.main()
            except SystemExit as exc:
                exit_code = exc.code
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def _target(self, tmp):
        target = Path(tmp)
        (target / "README.md").write_text("# Project\n", encoding="utf-8")
        return target

    def test_nonzero_producer_exit_fails_instead_of_emitting_an_empty_scan(self):
        """Load-bearing: restore the old `if res.returncode == 0 ...` guard (drop the
        nonzero-exit failure) and this test fails because main() returns None having
        emitted a drift_candidates_count=0 payload."""
        with tempfile.TemporaryDirectory() as tmp:
            fake = mock.Mock(returncode=1, stderr="boom: not a git repo", stdout="")
            with mock.patch.object(prepare_docs_fixes.subprocess, "run",
                                   return_value=fake) as run:
                exit_code, out, err = self._run_main(self._target(tmp))
            self.assertTrue(run.called, "the docs-drift producer must be invoked")
            self.assertEqual(exit_code, 2,
                             "a failed producer must exit nonzero, not emit a zero-candidate payload")
            self.assertIn("exited 1", err)
            self.assertEqual(out, "",
                             "a failed scan must not emit a successful-looking payload on stdout")

    def test_temp_file_failure_fails_instead_of_emitting_an_empty_scan(self):
        """Load-bearing: restore the old `except Exception: pass` and this test fails
        because the OSError is swallowed and main() emits a zero-candidate payload."""
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(prepare_docs_fixes.tempfile, "NamedTemporaryFile",
                                   side_effect=OSError("disk full")):
                exit_code, out, err = self._run_main(self._target(tmp))
            self.assertEqual(exit_code, 2,
                             "a temp-file failure must exit nonzero, not emit a zero-candidate payload")
            self.assertIn("could not create a temp file", err)
            self.assertEqual(out, "",
                             "a failed scan must not emit a successful-looking payload on stdout")

    def test_empty_scan_still_succeeds_and_is_distinct_from_failure(self):
        """The guard must not break the happy path: a producer that ran and found nothing
        still emits a zero-candidate payload - which is now MEANINGFUL, because failure
        can no longer produce the same output."""
        def fake_run(cmd, **kwargs):
            out_path = cmd[cmd.index("--output") + 1]
            Path(out_path).write_text(json.dumps({"candidates": []}), encoding="utf-8")
            return mock.Mock(returncode=0, stderr="", stdout="")

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(prepare_docs_fixes.subprocess, "run",
                                   side_effect=fake_run):
                exit_code, out, err = self._run_main(self._target(tmp))
            self.assertIsNone(exit_code, "a successful empty scan must not exit")
            payload = json.loads(out)
            self.assertEqual(payload["drift_candidates_count"], 0)


if __name__ == "__main__":
    unittest.main()
