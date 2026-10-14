#!/usr/bin/env python3
"""Tests for tools/red-first.sh gate implementation and failure modes.

Validates the four teeth of the red-first gate:
1. GREEN: executes changed tests at tip, reports pass/fail count and tree.
2. RED: constructs tree at merge-base with test files applied, and enforces
   CONTENT VERIFICATION in both directions:
   - expect 0: the marker carried by a delta-touched implementation-source path
     is absent from the red tree (rejects leaks) - a BOUND on where the marker
     came from, not proof the implementation changed (the accepted limitation is
     pinned by test_data_memo_marker_is_a_disclosed_bound);
   - expect > 0: test label present in red tree (rejects missing tests).
3. REPORT: reports DISCRIMINATOR set, GUARD set, and NEITHER set.
   Loudly rejects the three vacuous forms:
   - a red run with ZERO failures;
   - a passing assertion whose captured value is EMPTY (reported as a failure, not a pass);
   - a red that cannot name its pre-fix object as a GIT SHA.
4. RE-CUT ARTIFACT DELTA & NAMED FEATURES (coordinator requirement):
   - reports per-line removals in re-cut patch artifacts;
   - counts named features and rejects artifacts dropping required cases,
     even when the total line count grows.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RED_FIRST_SH = ROOT / "tools" / "red-first.sh"


class TestRedFirst(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory(dir="/tmp")
        self.repo_dir = Path(self.tmp_dir.name) / "repo"
        self.repo_dir.mkdir()
        self.cache_dir = Path(self.tmp_dir.name) / "checks"
        self.cache_dir.mkdir()

        # Initialize fixture git repository
        self._run_cmd(["git", "init", "-b", "main", str(self.repo_dir)])
        self._run_cmd(["git", "-C", str(self.repo_dir), "config", "user.name", "Test User"])
        self._run_cmd(["git", "-C", str(self.repo_dir), "config", "user.email", "test@example.com"])

        # Create tools directory and copy red-first.sh
        (self.repo_dir / "tools").mkdir(parents=True)
        shutil.copy2(RED_FIRST_SH, self.repo_dir / "tools" / "red-first.sh")
        (self.repo_dir / "tools" / "red-first.sh").chmod(0o755)

        # Base implementation: add() only
        (self.repo_dir / "lib").mkdir(parents=True)
        (self.repo_dir / "lib" / "__init__.py").write_text("", encoding="utf-8")
        (self.repo_dir / "lib" / "calc.py").write_text(
            "def add(a, b):\n    return a + b\n", encoding="utf-8"
        )

        # Base tests: test_add
        (self.repo_dir / "tests").mkdir(parents=True)
        (self.repo_dir / "tests" / "__init__.py").write_text("", encoding="utf-8")
        (self.repo_dir / "tests" / "test_calc.py").write_text(
            "import unittest\n"
            "from lib.calc import add\n\n"
            "class TestCalc(unittest.TestCase):\n"
            "    def test_add_guard(self):\n"
            "        self.assertEqual(add(2, 3), 5)\n",
            encoding="utf-8",
        )

        self._run_cmd(["git", "-C", str(self.repo_dir), "add", "."])
        self._run_cmd(["git", "-C", str(self.repo_dir), "commit", "-m", "initial commit"])
        self.base_commit = self._get_commit_sha("HEAD")

        # Create a feature branch with multiply() added
        self._run_cmd(["git", "-C", str(self.repo_dir), "checkout", "-b", "feature"])
        (self.repo_dir / "lib" / "calc.py").write_text(
            "def add(a, b):\n    return a + b\n\n"
            "def multiply(a, b):\n    return a * b\n",
            encoding="utf-8",
        )

        # Update test with a discriminator test and a guard test
        (self.repo_dir / "tests" / "test_calc.py").write_text(
            "import unittest\n"
            "from lib.calc import add\n\n"
            "class TestCalc(unittest.TestCase):\n"
            "    def test_add_guard(self):\n"
            "        self.assertEqual(add(2, 3), 5)\n\n"
            "    def test_multiply_discriminator(self):\n"
            "        from lib.calc import multiply\n"
            "        self.assertEqual(multiply(3, 4), 12)\n",
            encoding="utf-8",
        )

        self._run_cmd(["git", "-C", str(self.repo_dir), "add", "."])
        self._run_cmd(["git", "-C", str(self.repo_dir), "commit", "-m", "implement multiply"])
        self.feature_commit = self._get_commit_sha("HEAD")

    def tearDown(self):
        self.tmp_dir.cleanup()

    def _run_cmd(self, cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=check,
        )

    def _get_commit_sha(self, ref: str) -> str:
        res = self._run_cmd(["git", "-C", str(self.repo_dir), "rev-parse", ref])
        return res.stdout.strip()

    def _run_red_first(self, args: list[str], env_overrides: dict | None = None) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env["FLEET_CHECKS_DIR"] = str(self.cache_dir)
        env["RED_FIRST_NO_CACHE"] = "1"
        if env_overrides:
            env.update(env_overrides)
        return subprocess.run(
            ["bash", "tools/red-first.sh"] + args,
            cwd=str(self.repo_dir),
            env=env,
            capture_output=True,
            text=True,
        )

    def test_honest_red_first_run_passes_all_four_teeth(self):
        """Honest run: green passes, red fails on discriminator, guards pass, content verified."""
        res = self._run_red_first([
            "--base", self.base_commit,
            "--expect-absent", "def multiply",
            "--expect-present", "test_multiply_discriminator",
            "tests/test_calc.py",
        ])
        self.assertEqual(res.returncode, 0, f"red-first failed unexpectedly:\n{res.stdout}\n{res.stderr}")
        self.assertIn("green run: 2 passed, 0 failed", res.stdout)
        self.assertTrue("red run: 1 passed, 1 failed" in res.stdout or "red run: 1 passed, 0 failed, 1 errors" in res.stdout)
        self.assertIn("DISCRIMINATOR set (1 cases):", res.stdout)
        self.assertIn("test_multiply_discriminator", res.stdout)
        self.assertIn("GUARD set (1 cases):", res.stdout)
        self.assertIn("test_add_guard", res.stdout)
        self.assertIn("NEITHER set (0 cases):", res.stdout)
        self.assertIn("VERDICT: PASS", res.stdout)

    def test_content_verification_direction_1_rejects_implementation_leak(self):
        """Tooth 2: expect 0 fails if new implementation string exists in red tree."""
        # Create a branch where the added implementation leaks into the pre-fix base
        self._run_cmd(["git", "-C", str(self.repo_dir), "checkout", "main"])
        (self.repo_dir / "lib" / "calc.py").write_text(
            "def add(a, b):\n    return a + b\n\n# leak: def multiply\n",
            encoding="utf-8",
        )
        self._run_cmd(["git", "-C", str(self.repo_dir), "commit", "-am", "base with leaked string"])
        leak_base = self._get_commit_sha("HEAD")

        self._run_cmd(["git", "-C", str(self.repo_dir), "checkout", "-b", "leak-branch"])
        (self.repo_dir / "lib" / "calc.py").write_text(
            "def add(a, b):\n    return a + b\n\n# leak: def multiply\n\ndef multiply(a, b):\n    return a * b\n",
            encoding="utf-8",
        )
        (self.repo_dir / "tests" / "test_calc.py").write_text(
            "import unittest\n"
            "from lib.calc import add\n\n"
            "class TestCalc(unittest.TestCase):\n"
            "    def test_add_guard(self):\n"
            "        self.assertEqual(add(2, 3), 5)\n\n"
            "    def test_multiply_discriminator(self):\n"
            "        from lib.calc import multiply\n"
            "        self.assertEqual(multiply(3, 4), 12)\n",
            encoding="utf-8",
        )
        self._run_cmd(["git", "-C", str(self.repo_dir), "commit", "-am", "implement multiply and discriminator"])

        res = self._run_red_first([
            "--base", leak_base,
            "--expect-absent", "def multiply",
            "--expect-present", "test_multiply_discriminator",
            "tests/test_calc.py",
        ])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("content verification failed: string 'def multiply' exists in red implementation tree", res.stderr)
        self.assertIn("A partially applied patch looks exactly like a passing pin", res.stderr)

    def test_content_verification_direction_2_rejects_missing_tests(self):
        """Tooth 2: expect > 0 fails if new test label is absent from red tree tests."""
        # Add a second test file in feature branch with a discriminator label
        (self.repo_dir / "tests" / "test_other.py").write_text(
            "import unittest\n\n"
            "class TestOther(unittest.TestCase):\n"
            "    def test_other_discriminator(self):\n"
            "        self.assertTrue(True)\n",
            encoding="utf-8",
        )
        self._run_cmd(["git", "-C", str(self.repo_dir), "add", "."])
        self._run_cmd(["git", "-C", str(self.repo_dir), "commit", "-m", "add test_other"])

        # Running red-first with test_other_discriminator but only applying test_calc.py fails
        res = self._run_red_first([
            "--base", self.base_commit,
            "--expect-absent", "def multiply",
            "--expect-present", "test_other_discriminator",
            "tests/test_calc.py",
        ])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("content verification failed: label 'test_other_discriminator' was NOT found in red tree tests", res.stderr)

    def test_unrelated_marker_is_refused(self):
        """Tooth 2: marker from an unrelated changed file (e.g. docs) is refused by delta justification."""
        (self.repo_dir / "docs.md").write_text("GLITTERBERRY_UNRELATED_TOKEN_77\n", encoding="utf-8")
        self._run_cmd(["git", "-C", str(self.repo_dir), "add", "."])
        self._run_cmd(["git", "-C", str(self.repo_dir), "commit", "-m", "add docs with unrelated token"])

        res = self._run_red_first([
            "--base", self.base_commit,
            "--expect-absent", "GLITTERBERRY_UNRELATED_TOKEN_77",
            "--expect-present", "test_multiply_discriminator",
            "tests/test_calc.py",
        ])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("neither-direction-verified", res.stderr)
        self.assertIn("absent marker 'GLITTERBERRY_UNRELATED_TOKEN_77' is not justified by delta", res.stderr)

    def test_non_code_delta_path_cannot_certify_implementation(self):
        """Tooth 2: marker from a committed non-code delta path (e.g. root notes.txt) cannot certify green implementation."""
        (self.repo_dir / "notes.txt").write_text("NEW_NOTE_UNRELATED_TO_IMPL_6611\n", encoding="utf-8")
        self._run_cmd(["git", "-C", str(self.repo_dir), "add", "."])
        self._run_cmd(["git", "-C", str(self.repo_dir), "commit", "-m", "add notes with unrelated token"])

        res = self._run_red_first([
            "--base", self.base_commit,
            "--expect-absent", "NEW_NOTE_UNRELATED_TO_IMPL_6611",
            "--expect-present", "test_multiply_discriminator",
            "tests/test_calc.py",
        ])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("neither-direction-verified", res.stderr)
        self.assertIn("absent marker 'NEW_NOTE_UNRELATED_TO_IMPL_6611' is not justified by delta", res.stderr)

    def test_data_memo_marker_is_a_disclosed_bound(self):
        """Tooth 2 bound (agents-twue): a committed data/memo.py holding ONLY a marker comment, imported by nothing
        but carrying an allow-listed source extension, is ACCEPTED by the path rule - that is the accepted limitation
        of the bound. So this case asserts the intended behaviour rather than a refusal: rc0, the marker reported as
        a delta-touched implementation-source path, the limit disclosed, and NO claim that the implementation changed.
        The load-bearing claim stays the measured DISCRIMINATOR set, which the same run still reports."""
        (self.repo_dir / "data").mkdir()
        (self.repo_dir / "data" / "memo.py").write_text(
            "# DATA_MEMO_ONLY_29485 - not imported by any code\n", encoding="utf-8"
        )
        self._run_cmd(["git", "-C", str(self.repo_dir), "add", "."])
        self._run_cmd(["git", "-C", str(self.repo_dir), "commit", "-m", "add inert data memo"])

        # Prove the fixture, not the claim: nothing imports the memo.
        self.assertNotIn("memo", (self.repo_dir / "lib" / "calc.py").read_text(encoding="utf-8"))
        self.assertNotIn("data", (self.repo_dir / "tests" / "test_calc.py").read_text(encoding="utf-8"))

        res = self._run_red_first([
            "--base", self.base_commit,
            "--expect-absent", "DATA_MEMO_ONLY_29485",
            "--expect-present", "test_multiply_discriminator",
            "tests/test_calc.py",
        ])
        # The accepted limitation: the bound admits data/memo.py, so the run reaches the discriminator proof.
        self.assertEqual(res.returncode, 0, f"boundary case behaved unexpectedly:\n{res.stdout}\n{res.stderr}")
        self.assertIn("delta-touched implementation-source path 'data/memo.py'", res.stdout)
        self.assertIn("a path-based check cannot prove implementation", res.stdout)
        # The tool must not carry the semantic claim the path cannot support.
        self.assertNotIn("the implementation changed", res.stdout)
        self.assertIn("DISCRIMINATOR set (1 cases):", res.stdout)
        self.assertIn("VERDICT: PASS", res.stdout)

        # The bound must be ON THE VERDICT LINE, not only beside the evidence (agents-0kcp). The verdict line is
        # the single line most likely to be read, quoted and acted on, so a bound a reader can miss there is the
        # defect wearing a label - disclosures beside the evidence do not reach a reader who reads only this.
        verdict_lines = [ln for ln in res.stdout.splitlines() if "VERDICT" in ln]
        self.assertEqual(len(verdict_lines), 1, f"expected exactly one verdict line:\n{res.stdout}")
        self.assertIn("path-origin evidence only", verdict_lines[0],
                      f"the VERDICT line itself must carry tooth 2's bound (agents-0kcp): {verdict_lines[0]!r}")

    def test_untracked_file_cannot_certify_green_tree(self):
        """Tooth 2: an untracked file cannot certify the green tree (empty match refuses, never falls back)."""
        (self.repo_dir / "untracked-probe.txt").write_text("UNTRACKED_MARKER_XYZ_90210\n", encoding="utf-8")

        res = self._run_red_first([
            "--base", self.base_commit,
            "--expect-absent", "UNTRACKED_MARKER_XYZ_90210",
            "--expect-present", "test_multiply_discriminator",
            "tests/test_calc.py",
        ])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("neither-direction-verified", res.stderr)

    def test_bogus_markers_are_refused(self):
        """Tooth 2: bogus markers that cannot establish exclusivity preconditions are refused."""
        res = self._run_red_first([
            "--base", self.base_commit,
            "--expect-absent", "NEVER_IN_GREEN_OR_RED_85927",
            "--expect-present", "test_add_guard",
            "tests/test_calc.py",
        ])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("neither-direction-verified", res.stderr)

    def test_vacuous_form_1_zero_red_failures_rejected_loudly(self):
        """Vacuous form 1: a red run with ZERO failures is rejected loudly."""
        # Create a test that passes on BOTH revisions (pure guard, no discriminator)
        (self.repo_dir / "tests" / "test_calc.py").write_text(
            "import unittest\n"
            "from lib.calc import add\n\n"
            "class TestCalc(unittest.TestCase):\n"
            "    def test_new_guard(self):\n"
            "        self.assertEqual(add(2, 3), 5)\n",
            encoding="utf-8",
        )
        self._run_cmd(["git", "-C", str(self.repo_dir), "commit", "-am", "pure guard tests"])

        res = self._run_red_first([
            "--base", self.base_commit,
            "--expect-present", "test_new_guard",
            "tests/test_calc.py",
        ])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("FAIL: vacuous red run: 0 failures on pre-fix tree", res.stderr)

    def test_vacuous_form_2_empty_captured_value_rejected_loudly_as_failure(self):
        """Vacuous form 2: passing assertion with EMPTY captured value is reported as FAILURE."""
        # Create a test that passes vacuously with empty capture: 'ok 7a ... (got )'
        (self.repo_dir / "tests" / "test_calc.py").write_text(
            "import unittest\n"
            "from lib.calc import add\n\n"
            "class TestCalc(unittest.TestCase):\n"
            "    def test_empty_capture_vacuous_pass(self):\n"
            "        # Simulates a harness reporting an empty captured value\n"
            "        print('ok 7a ... (got )')\n"
            "        self.assertTrue(True)\n",
            encoding="utf-8",
        )
        self._run_cmd(["git", "-C", str(self.repo_dir), "commit", "-am", "add vacuous empty capture test"])

        res = self._run_red_first([
            "--base", self.base_commit,
            "--expect-present", "test_empty_capture_vacuous_pass",
            "tests/test_calc.py",
        ])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("FAIL: vacuous pass detected in green run (passing assertion whose captured value is EMPTY)", res.stderr)
        self.assertIn("test_empty_capture_vacuous_pass", res.stderr)

    def test_vacuous_form_3_invalid_git_sha_rejected_loudly(self):
        """Vacuous form 3: pre-fix object cannot be named as a git SHA is rejected loudly."""
        res = self._run_red_first([
            "--base", "nonexistent_ref_or_opaque_path_12345",
            "tests/test_calc.py",
        ])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("cannot name pre-fix object as a GIT SHA", res.stderr)

    def test_neither_set_reported_explicitly_when_assertion_fails_on_green(self):
        """Tooth 3: assertions in NEITHER set (e.g. failing on green) are printed explicitly."""
        (self.repo_dir / "tests" / "test_calc.py").write_text(
            "import unittest\n"
            "from lib.calc import add\n\n"
            "class TestCalc(unittest.TestCase):\n"
            "    def test_broken_on_green(self):\n"
            "        self.assertEqual(add(1, 1), 999)\n",
            encoding="utf-8",
        )
        self._run_cmd(["git", "-C", str(self.repo_dir), "commit", "-am", "add failing test"])

        res = self._run_red_first([
            "--base", self.base_commit,
            "tests/test_calc.py",
        ])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("green run failed at tip", res.stderr)

    def test_tooth_4_re_cut_artifact_detects_unintended_removals(self):
        """Tooth 4: per-line removals in a re-cut patch artifact are reported and rejected."""
        # Create an artifact in base commit
        self._run_cmd(["git", "-C", str(self.repo_dir), "checkout", "main"])
        (self.repo_dir / "patches").mkdir(parents=True, exist_ok=True)
        patch_file = self.repo_dir / "patches" / "tool.patch"
        patch_file.write_text(
            "--- a/tool.sh\n+++ b/tool.sh\n"
            "@@ -1,5 +1,8 @@\n"
            "+# section-7 case 1\n"
            "+# section-7 case 2\n"
            "+# 11s case line\n"
            "+# line to be dropped later\n",
            encoding="utf-8",
        )
        self._run_cmd(["git", "-C", str(self.repo_dir), "add", "."])
        self._run_cmd(["git", "-C", str(self.repo_dir), "commit", "-m", "add base patch artifact"])
        patch_base = self._get_commit_sha("HEAD")

        # Now checkout a branch and re-cut the artifact: drop the line while adding 2 new lines
        # Total line count GROWS from 4 added lines to 5 added lines, while dropping 1 line!
        self._run_cmd(["git", "-C", str(self.repo_dir), "checkout", "-b", "recut-branch"])
        # Add multiply implementation and test so Teeth 1-3 pass honestly
        (self.repo_dir / "lib" / "calc.py").write_text(
            "def add(a, b):\n    return a + b\n\n"
            "def multiply(a, b):\n    return a * b\n",
            encoding="utf-8",
        )
        (self.repo_dir / "tests" / "test_calc.py").write_text(
            "import unittest\n"
            "from lib.calc import add\n\n"
            "class TestCalc(unittest.TestCase):\n"
            "    def test_add_guard(self):\n"
            "        self.assertEqual(add(2, 3), 5)\n\n"
            "    def test_multiply_discriminator(self):\n"
            "        from lib.calc import multiply\n"
            "        self.assertEqual(multiply(3, 4), 12)\n",
            encoding="utf-8",
        )
        patch_file.write_text(
            "--- a/tool.sh\n+++ b/tool.sh\n"
            "@@ -1,5 +1,9 @@\n"
            "+# section-7 case 1\n"
            "+# section-7 case 2\n"
            "+# 11s case line\n"
            "+# new line 1\n"
            "+# new line 2\n",
            encoding="utf-8",
        )
        self._run_cmd(["git", "-C", str(self.repo_dir), "commit", "-am", "recut artifact with dropped line and multiply"])

        # Running red-first must detect the removal and fail unless --allow-removals is set
        res = self._run_red_first([
            "--base", patch_base,
            "--artifact", "patches/tool.patch",
            "--expect-absent", "def multiply",
            "--expect-present", "test_multiply_discriminator",
            "tests/test_calc.py",
        ])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("artifact delta for patches/tool.patch", res.stdout)
        self.assertIn("removed lines from previously reviewed artifact", res.stdout)
        self.assertIn("unintended removal detected in re-cut artifact", res.stderr)

        # With --allow-removals, it proceeds to check named features and passes
        res_allowed = self._run_red_first([
            "--base", patch_base,
            "--artifact", "patches/tool.patch",
            "--allow-removals",
            "--named-features", "section-7,11s",
            "--expect-absent", "def multiply",
            "--expect-present", "test_multiply_discriminator",
            "tests/test_calc.py",
        ])
        self.assertIn("named feature 'section-7' in patches/tool.patch: count = 2", res_allowed.stdout)
        self.assertIn("named feature '11s' in patches/tool.patch: count = 1", res_allowed.stdout)
        self.assertIn("VERDICT: PASS", res_allowed.stdout)

    def test_tooth_4_re_cut_artifact_missing_named_feature_is_rejected_loudly(self):
        """Tooth 4: re-cut artifact dropping a named feature is rejected even if total lines grew."""
        self._run_cmd(["git", "-C", str(self.repo_dir), "checkout", "main"])
        (self.repo_dir / "patches").mkdir(parents=True, exist_ok=True)
        patch_file = self.repo_dir / "patches" / "feature.patch"
        patch_file.write_text(
            "+# section-7 case 1\n+# 11s case line\n",
            encoding="utf-8",
        )
        self._run_cmd(["git", "-C", str(self.repo_dir), "add", "."])
        self._run_cmd(["git", "-C", str(self.repo_dir), "commit", "-m", "base feature patch"])
        feat_base = self._get_commit_sha("HEAD")

        # In branch, drop 11s but add 5 other lines: line count increases
        self._run_cmd(["git", "-C", str(self.repo_dir), "checkout", "-b", "drop-feature-branch"])
        (self.repo_dir / "lib" / "calc.py").write_text(
            "def add(a, b):\n    return a + b\n\n"
            "def multiply(a, b):\n    return a * b\n",
            encoding="utf-8",
        )
        (self.repo_dir / "tests" / "test_calc.py").write_text(
            "import unittest\n"
            "from lib.calc import add\n\n"
            "class TestCalc(unittest.TestCase):\n"
            "    def test_add_guard(self):\n"
            "        self.assertEqual(add(2, 3), 5)\n\n"
            "    def test_multiply_discriminator(self):\n"
            "        from lib.calc import multiply\n"
            "        self.assertEqual(multiply(3, 4), 12)\n",
            encoding="utf-8",
        )
        patch_file.write_text(
            "+# section-7 case 1\n+# other 1\n+# other 2\n+# other 3\n+# other 4\n",
            encoding="utf-8",
        )
        self._run_cmd(["git", "-C", str(self.repo_dir), "commit", "-am", "drop 11s case and multiply"])

        res = self._run_red_first([
            "--base", feat_base,
            "--artifact", "patches/feature.patch",
            "--allow-removals",
            "--named-features", "section-7,11s",
            "--expect-absent", "def multiply",
            "--expect-present", "test_multiply_discriminator",
            "tests/test_calc.py",
        ])
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("missing required named feature '11s' (count: 0)", res.stderr)

    def test_tree_cache_avoids_re_executing_same_tree(self):
        """Fast gate speed: cached runs avoid re-invoking test suite."""
        cache_env = {"FLEET_CHECKS_DIR": str(self.cache_dir), "RED_FIRST_NO_CACHE": "0"}
        # First run populates cache
        res1 = self._run_red_first([
            "--base", self.base_commit,
            "--expect-absent", "def multiply",
            "--expect-present", "test_multiply_discriminator",
            "tests/test_calc.py",
        ], env_overrides=cache_env)
        self.assertEqual(res1.returncode, 0)
        self.assertFalse("using cached green run" in res1.stdout)

        # Second run hits cache
        res2 = self._run_red_first([
            "--base", self.base_commit,
            "--expect-absent", "def multiply",
            "--expect-present", "test_multiply_discriminator",
            "tests/test_calc.py",
        ], env_overrides=cache_env)
        self.assertEqual(res2.returncode, 0)
        self.assertIn("using cached green run", res2.stdout)
        self.assertIn("using cached red run", res2.stdout)


if __name__ == "__main__":
    unittest.main()
