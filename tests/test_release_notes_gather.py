#!/usr/bin/env python3
"""agents-vei8y: the target-controlled --since-tag reached `git log` as a raw argv token, so a
tag whose token begins with '-' was parsed as a git OPTION - measured: the current shape made
`git log "--output=<path>..HEAD" --format=...` write the log to a caller-chosen file OUTSIDE the
target. The fix puts the format option first and ends option parsing with --end-of-options
before the range, and a failed log is LOUD (nonzero exit, stderr names the range) instead of a
quiet empty log that reads like "no commits".

This drives the real CLI against scratch git repos, because the contract lives in the argv
ORDER, which a unit test of a dict cannot see.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo)] + list(args), check=True,
                   capture_output=True, text=True, timeout=60)


def _make_repo(tagged: bool) -> Path:
    repo = Path(tempfile.mkdtemp()) / "target"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "t")
    (repo / "a.txt").write_text("one\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "feat: first")
    if tagged:
        _git(repo, "tag", "v1")
        (repo / "a.txt").write_text("two\n", encoding="utf-8")
        _git(repo, "commit", "-qam", "feat: second")
    return repo


def _run_cli(repo: Path, extra_args, out_name: str):
    out = repo.parent / out_name
    # The script path is spelled INLINE in this call on purpose: the coverage oracle's
    # subprocess heuristic reads the literal from inside the run(...) arguments (a module-level
    # constant is invisible to it and the genuinely-executed relation would report unmapped).
    res = subprocess.run(
        [sys.executable,
         str(ROOT / "agents" / "release-notes" / "scripts" / "gather_commits.py"),
         "--target", str(repo), "--output", str(out)]
        + list(extra_args),
        capture_output=True, text=True, timeout=120, cwd=str(ROOT),
        env={**os.environ, "PYTHONPATH": str(ROOT)})
    return res, out


class TestSinceTagNeverReachesGitAsAnOption(unittest.TestCase):

    def test_legit_tag_still_resolves_the_range(self):
        repo = _make_repo(tagged=True)
        res, out = _run_cli(repo, ["--since-tag", "v1"], "legit.json")
        self.assertEqual(res.returncode, 0, res.stderr[-500:])
        report = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(report["commit_count"], 1,
                         "commits after v1 must still be gathered with the separator in place")
        self.assertIn("feat: second", [c["subject"] for c in report["commits"]])

    def test_no_tag_falls_back_to_recent_commits(self):
        repo = _make_repo(tagged=False)
        res, out = _run_cli(repo, [], "notag.json")
        self.assertEqual(res.returncode, 0, res.stderr[-500:])
        report = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(report["commit_count"], 1)

    def test_option_shaped_tag_cannot_execute_and_fails_loudly(self):
        # The measured injection: with the old argv shape this token ran as --output and
        # wrote the log OUTSIDE the target. argparse's separated form ('--since-tag
        # --output=x') refuses a leading-dash value outright, so the reachable path into
        # gather_commits is the '--since-tag=<value>' form - which argparse accepts - and
        # the same token also arrives via get_latest_tag from a malicious repo's own tag
        # list. It must not execute, and the failure must be loud (nonzero exit naming the
        # range), never a quiet "0 commits".
        repo = _make_repo(tagged=True)
        outside = repo.parent / "escape.txt"
        res, out = _run_cli(
            repo, [f"--since-tag=--output={outside}"], "attack.json")
        self.assertNotEqual(res.returncode, 0,
                            "an option-shaped tag must fail loudly, not read as 'no commits'")
        self.assertIn("--output=", res.stderr, "stderr must name the rejected range")
        self.assertFalse(outside.exists(),
                         "the option-shaped tag executed: git wrote outside the target")
        self.assertFalse(out.exists(), "no artefact may be produced by a failed log")

    def test_nonexistent_tag_also_fails_loudly(self):
        # The loud rc check must not turn a caller error into a quiet "no commits" either.
        repo = _make_repo(tagged=True)
        res, out = _run_cli(repo, ["--since-tag", "no-such-tag"], "missing.json")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("no-such-tag", res.stderr)
        self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
