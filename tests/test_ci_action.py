#!/usr/bin/env python3
"""The factory CI action fetches pinned code and never holds credentials while fetching (SF-10).

The action is the highest-privilege component consumers install: it runs with their model key
and GitHub token. Fetching whatever main happens to be at run time, into the same job, is the
supply-chain hole the audit found. These tests pin the fix: an immutable commit SHA, a
credential-free fetch step, and a fetch script that refuses anything that is not a full SHA.
"""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ACTION = ROOT / ".github" / "actions" / "factory" / "action.yml"
FETCH = ROOT / ".github" / "actions" / "factory" / "fetch_factory.sh"
SECRET_VARS = ("GH_TOKEN", "GITHUB_TOKEN", "GEMINI_API_KEY", "ANTHROPIC_API_KEY")


def action_text() -> str:
    return ACTION.read_text(encoding="utf-8")


def pinned_sha() -> str:
    match = re.search(r"factory_ref:\n(?:.*\n)*?\s+default: '([0-9a-f]+)'", action_text())
    if not match:
        raise AssertionError("factory_ref input with a default is required")
    return match.group(1)


def step_block(name: str) -> str:
    for block in re.split(r"\n    - name: ", action_text()):
        if block.startswith(name):
            return block
    raise AssertionError(f"step not found: {name}")


class TestActionPinning(unittest.TestCase):
    def test_factory_ref_default_is_a_full_commit_sha(self):
        self.assertRegex(pinned_sha(), r"^[0-9a-f]{40}$")

    def test_the_action_never_clones_a_branch(self):
        text = action_text()
        self.assertNotIn("git clone", text)
        self.assertNotRegex(text, r"origin (main|master)\b")
        self.assertIn("fetch_factory.sh", text)

    def test_fetch_step_holds_no_credentials(self):
        block = step_block("Fetch Pinned Factory Repository")
        for var in SECRET_VARS:
            with self.subTest(var=var):
                self.assertRegex(block, rf"{var}: ''")
        self.assertIn("GIT_TERMINAL_PROMPT: '0'", block)
        self.assertIn("FACTORY_REF: ${{ inputs.factory_ref }}", block)

    def test_run_step_still_receives_the_credentials(self):
        block = step_block("Execute Factory Agent")
        for var in SECRET_VARS:
            with self.subTest(var=var):
                self.assertIn(var, block)


class TestFetchFactoryScript(unittest.TestCase):
    def _run(self, origin: Path, ref: str, dest: Path):
        env = dict(os.environ)
        env.update({"FACTORY_REPO_URL": str(origin), "FACTORY_REF": ref,
                    "GIT_TERMINAL_PROMPT": "0"})
        return subprocess.run(["bash", str(FETCH), str(dest)], env=env,
                              capture_output=True, text=True, timeout=180)

    def test_fetches_exactly_the_pinned_commit(self):
        if not (ROOT / ".git").exists():
            self.skipTest("not a git checkout")
        sha = pinned_sha()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            origin = tmp / "origin.git"
            subprocess.run(["git", "clone", "--bare", "--quiet", str(ROOT), str(origin)],
                           check=True, capture_output=True, text=True, timeout=180)
            dest = tmp / "software-factory"
            res = self._run(origin, sha, dest)

            self.assertEqual(res.returncode, 0, res.stderr + res.stdout)
            self.assertTrue((dest / "factory").exists(), "the factory CLI must be checked out")
            self.assertTrue((dest / "lib" / "findings.py").exists(), "the tree must be complete")
            head = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"],
                                  capture_output=True, text=True, check=True).stdout.strip()
            self.assertEqual(head, sha)

    def test_a_branch_name_is_rejected_before_any_fetch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            res = self._run(tmp / "does-not-exist.git", "main", tmp / "dest")
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("40-character commit SHA", res.stderr)
            self.assertFalse((tmp / "dest").exists(), "the destination must not be touched")

    def test_the_script_carries_no_secret_names(self):
        # Comments may name the variables the caller must blank; executable lines may not use them.
        code = "\n".join(
            line for line in FETCH.read_text(encoding="utf-8").splitlines()
            if not line.lstrip().startswith("#")
        )
        for name in SECRET_VARS:
            with self.subTest(name=name):
                self.assertNotIn(name, code)


if __name__ == "__main__":
    unittest.main()
