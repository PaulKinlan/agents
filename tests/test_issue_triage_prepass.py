#!/usr/bin/env python3
"""Tests for issue-triage pre-pass (fetch_issues.py), verifying gh stderr redaction (agents-ujtv).

Non-negotiable security requirement: raw gh stderr must never be echoed unredacted.
gh stderr can contain sensitive response bodies, auth headers, token fragments, or
attacker-controlled stderr if gh is compromised/trojaned.
Redaction must mask known credential patterns (via mask_text) and active environment
token literals (GH_TOKEN, GITHUB_TOKEN via mask_literals).
"""

import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "agents" / "issue-triage" / "scripts" / "fetch_issues.py"

spec = importlib.util.spec_from_file_location("fetch_issues", str(SCRIPT))
fetch_issues_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetch_issues_mod)
fetch_github_issues = fetch_issues_mod.fetch_github_issues


class TestIssueTriageGhStderrRedaction(unittest.TestCase):
    def test_fetch_github_issues_redacts_credentials_in_gh_stderr(self):
        """gh stderr containing vendor token shapes and ambient env tokens must be redacted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            fake_bin = tmppath / "bin"
            fake_bin.mkdir()

            classic_pat = "ghp_" + "A" * 36
            fine_grained_pat = "github_pat_" + "1" * 22 + "_" + "A" * 59
            ambient_secret = "my-custom-ambient-secret-987654321"

            # Fake gh script that fails and prints secrets to stderr
            fake_gh = fake_bin / "gh"
            fake_gh.write_text(
                "#!/usr/bin/env bash\n"
                f'echo "Error: authentication failed for {classic_pat}" >&2\n'
                f'echo "Fine-grained PAT {fine_grained_pat} expired" >&2\n'
                f'echo "Authorization: Bearer {ambient_secret} was rejected" >&2\n'
                "exit 1\n",
                encoding="utf-8"
            )
            fake_gh.chmod(fake_gh.stat().st_mode | stat.S_IXUSR)

            target_repo = tmppath / "repo"
            target_repo.mkdir()

            # Execute with PATH pointing to fake_gh and ambient GH_TOKEN set
            orig_path = os.environ.get("PATH", "")
            orig_gh_token = os.environ.get("GH_TOKEN")
            try:
                os.environ["PATH"] = f"{fake_bin}:{orig_path}"
                os.environ["GH_TOKEN"] = ambient_secret

                stderr_capture = io.StringIO()
                with patch("sys.stderr", stderr_capture):
                    result = fetch_github_issues(target_repo)

                captured = stderr_capture.getvalue()

                # Result must be None on failure
                self.assertIsNone(result)

                # ASSERT ABSENCE: Neither the PATs nor the ambient secret literal may appear
                self.assertNotIn(classic_pat, captured,
                                 "Classic PAT was leaked into stderr unredacted")
                self.assertNotIn(fine_grained_pat, captured,
                                 "Fine-grained PAT was leaked into stderr unredacted")
                self.assertNotIn(ambient_secret, captured,
                                 "Ambient GH_TOKEN literal was leaked into stderr unredacted")

                # ASSERT PRESENCE OF REDACTION MARKERS
                self.assertIn("[redacted:github-pat]", captured,
                              "Expected [redacted:github-pat] marker in redacted stderr")
                self.assertIn("[redacted:value]", captured,
                              "Expected [redacted:value] marker for ambient GH_TOKEN")
            finally:
                os.environ["PATH"] = orig_path
                if orig_gh_token is not None:
                    os.environ["GH_TOKEN"] = orig_gh_token
                else:
                    os.environ.pop("GH_TOKEN", None)

    def test_fetch_issues_cli_invocation_redacts_stderr_end_to_end(self):
        """End-to-end subprocess execution of fetch_issues.py must not leak secrets to stderr."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            fake_bin = tmppath / "bin"
            fake_bin.mkdir()

            pat_secret = "ghp_" + "B" * 36
            env_secret = "super-secret-ci-token-88889999"

            fake_gh = fake_bin / "gh"
            fake_gh.write_text(
                "#!/usr/bin/env bash\n"
                f'echo "fatal: could not read Username for https://github.com with token {pat_secret}" >&2\n'
                f'echo "debug: token={env_secret}" >&2\n'
                "exit 128\n",
                encoding="utf-8"
            )
            fake_gh.chmod(fake_gh.stat().st_mode | stat.S_IXUSR)

            target_repo = tmppath / "repo"
            target_repo.mkdir()

            env = dict(os.environ)
            env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
            env["GITHUB_TOKEN"] = env_secret

            res = subprocess.run(
                [sys.executable, str(SCRIPT), "--target", str(target_repo)],
                capture_output=True,
                text=True,
                env=env,
                check=False
            )

            # Absence assertions on process stderr
            self.assertNotIn(pat_secret, res.stderr, "PAT leaked in process stderr")
            self.assertNotIn(env_secret, res.stderr, "GITHUB_TOKEN leaked in process stderr")

            # Redaction marker assertions
            self.assertIn("[redacted:github-pat]", res.stderr)
            self.assertIn("[redacted:value]", res.stderr)

    def test_fetch_github_issues_preserves_innocuous_diagnostic_message(self):
        """Standard non-secret error diagnostics must pass through cleanly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            fake_bin = tmppath / "bin"
            fake_bin.mkdir()

            error_msg = "Could not resolve host: github.com"
            fake_gh = fake_bin / "gh"
            fake_gh.write_text(
                f"#!/usr/bin/env bash\necho '{error_msg}' >&2\nexit 1\n",
                encoding="utf-8"
            )
            fake_gh.chmod(fake_gh.stat().st_mode | stat.S_IXUSR)

            target_repo = tmppath / "repo"
            target_repo.mkdir()

            orig_path = os.environ.get("PATH", "")
            try:
                os.environ["PATH"] = f"{fake_bin}:{orig_path}"
                stderr_capture = io.StringIO()
                with patch("sys.stderr", stderr_capture):
                    result = fetch_github_issues(target_repo)
                captured = stderr_capture.getvalue()
                self.assertIsNone(result)
                self.assertIn(error_msg, captured)
                self.assertIn("Note: gh issue list failed (code 1):", captured)
            finally:
                os.environ["PATH"] = orig_path

    def test_fetch_github_issues_success_path_extracts_candidates_without_leak(self):
        """When gh succeeds, candidate issues are extracted cleanly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            fake_bin = tmppath / "bin"
            fake_bin.mkdir()

            issues_json = [
                {
                    "number": 42,
                    "title": "Bug in parser",
                    "body": "Parser fails on trailing comma",
                    "labels": [{"name": "bug"}],
                    "author": {"login": "octocat"},
                    "createdAt": "2026-10-10T12:00:00Z",
                    "comments": [{"body": "Confirmed"}]
                }
            ]

            fake_gh = fake_bin / "gh"
            fake_gh.write_text(
                f"#!/usr/bin/env bash\necho '{json.dumps(issues_json)}'\nexit 0\n",
                encoding="utf-8"
            )
            fake_gh.chmod(fake_gh.stat().st_mode | stat.S_IXUSR)

            target_repo = tmppath / "repo"
            target_repo.mkdir()

            orig_path = os.environ.get("PATH", "")
            try:
                os.environ["PATH"] = f"{fake_bin}:{orig_path}"
                stderr_capture = io.StringIO()
                with patch("sys.stderr", stderr_capture):
                    result = fetch_github_issues(target_repo)
                self.assertIsNotNone(result)
                self.assertEqual(len(result), 1)
                self.assertEqual(result[0]["number"], 42)
                self.assertEqual(result[0]["title"], "Bug in parser")
                self.assertEqual(stderr_capture.getvalue(), "")
            finally:
                os.environ["PATH"] = orig_path


if __name__ == "__main__":
    unittest.main()
