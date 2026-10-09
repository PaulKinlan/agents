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
import yaml

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

    def test_the_pin_carries_the_landed_factory_fixes(self):
        """Review r4200726007: vendored users run the pinned factory, not this checkout, so
        the pin must move with the payload. It must be in this history (so a merge commit
        keeps it reachable) and contain the fixes this repo says have landed."""
        if not (ROOT / ".git").exists():
            self.skipTest("not a git checkout")
        sha = pinned_sha()
        present = subprocess.run(["git", "-C", str(ROOT), "cat-file", "-e", f"{sha}^{{commit}}"],
                                 capture_output=True, timeout=30)
        if present.returncode != 0:
            self.skipTest("pinned commit not in this (shallow?) clone")
        ancestor = subprocess.run(["git", "-C", str(ROOT), "merge-base", "--is-ancestor", sha, "HEAD"],
                                  capture_output=True, timeout=30)
        self.assertEqual(ancestor.returncode, 0, "the pinned factory must be an ancestor of HEAD")
        for marker in (
            "def normalize_report",            # fleet-9wyi: field-name synonyms
            "--external-ref",                  # fleet-xkf: beads dedupe by fingerprint
            "def write_line_report",           # fleet-810: run-level delta report
        ):
            with self.subTest(marker=marker):
                found = subprocess.run(["git", "-C", str(ROOT), "grep", "-q", "-F", "-e", marker,
                                        sha, "--", "lib"], capture_output=True, timeout=30)
                self.assertEqual(found.returncode, 0, f"pinned factory {sha[:12]} lacks {marker!r}")

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


class TestStepSummaryRouting(unittest.TestCase):
    """agents-pgj: the step summary is public-adjacent on a public repo (any logged-in
    GitHub account reads it), so it gets the reduced summary variant — never the full
    delta report — and the full report ships as an auth-gated run artifact."""

    def test_the_summary_appended_is_the_reduced_variant(self):
        block = step_block("Execute Factory Agent")
        self.assertIn('-summary.md', block)
        self.assertIn('cat "$SUMMARY_FILE" >> $GITHUB_STEP_SUMMARY', block)
        # The full report must NOT be the file appended.
        self.assertNotIn('cat "$REPORT_FILE" >> $GITHUB_STEP_SUMMARY', block)

    def test_the_full_report_is_uploaded_as_a_run_artifact(self):
        block = step_block("Upload Full Delta Report Artifact")
        self.assertIn("actions/upload-artifact@v4", block)
        self.assertIn("/findings/", block)

    def test_the_comment_no_longer_claims_reports_are_publishable_whole(self):
        block = step_block("Execute Factory Agent")
        self.assertNotIn("The report is safe to publish", block)
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


class TestExpressionInjectionGuard(unittest.TestCase):
    """agents-bjb: GitHub Actions script injection guard (actionlint-style check).

    Untrusted inputs interpolated directly into run: script bodies via ${{ inputs.* }}
    lead to arbitrary command execution in steps holding GH_TOKEN/model API keys.
    All inputs must be passed via env: and quoted inside shell scripts.
    """

    def test_no_inputs_expression_in_any_action_run_body(self):
        """No ${{ inputs.* }} expression may appear inside any run: body in .github/actions/**."""
        action_files = sorted(
            list((ROOT / ".github" / "actions").rglob("*.yml")) +
            list((ROOT / ".github" / "actions").rglob("*.yaml"))
        )
        self.assertTrue(action_files, "expected to find action.yml files under .github/actions/")

        violations = []
        pattern = re.compile(r"\$\{\{\s*inputs\.")

        for p in action_files:
            rel = p.relative_to(ROOT)
            content = p.read_text(encoding="utf-8")
            data = yaml.safe_load(content)

            def find_run_blocks(val, path=""):
                runs = []
                if isinstance(val, dict):
                    for k, v in val.items():
                        subpath = f"{path}.{k}" if path else k
                        if k == "run" and isinstance(v, str):
                            runs.append((subpath, v))
                        else:
                            runs.extend(find_run_blocks(v, subpath))
                elif isinstance(val, list):
                    for idx, item in enumerate(val):
                        runs.extend(find_run_blocks(item, f"{path}[{idx}]"))
                return runs

            for step_path, run_body in find_run_blocks(data):
                matches = pattern.findall(run_body)
                if matches:
                    violating_lines = [
                        line.strip() for line in run_body.splitlines()
                        if pattern.search(line)
                    ]
                    violations.append(
                        f"{rel} ({step_path}): found {len(matches)} injection vector(s):\n  "
                        + "\n  ".join(violating_lines)
                    )

        self.assertEqual(
            violations, [],
            "Expression injection vulnerability: ${{ inputs.* }} found in run: body:\n"
            + "\n".join(violations)
        )

    def test_factory_action_passes_inputs_via_env(self):
        block = step_block("Execute Factory Agent")
        for input_var in ("TARGET_PATH", "AGENT_NAME", "ENGINE_ARG", "SINK_ARG"):
            with self.subTest(input_var=input_var):
                self.assertIn(f"{input_var}:", block)
        self.assertIn('"$TARGET_PATH"', block)
        self.assertIn('"$AGENT_NAME"', block)
        self.assertIn('"$ENGINE_ARG"', block)
        self.assertIn('"$SINK_ARG"', block)
        run_part = block.split("run:")[1]
        self.assertNotIn("${{ inputs.", run_part)

    def test_artifact_name_not_interpolated_from_inputs(self):
        """Line 147 fix: pass artifact name via env or $GITHUB_OUTPUT, not ${{ inputs.agent }}."""
        block = step_block("Upload Full Delta Report Artifact")
        self.assertNotIn("${{ inputs.", block)

    def test_reproduction_input_injection_blocked_by_env_indirection(self):
        """Reproduce-first: verify that direct substitution executes commands, while env indirection blocks it."""
        with tempfile.TemporaryDirectory() as td:
            marker_vuln = Path(td) / "vuln_marker"
            marker_safe = Path(td) / "safe_marker"

            # 1. Direct substitution in script (the expression injection vulnerability)
            malicious_input_vuln = f'target" ; touch "{marker_vuln}" ; echo "'
            vulnerable_script = f'TARGET_PATH="{malicious_input_vuln}"'
            subprocess.run(["bash", "-c", vulnerable_script], capture_output=True, check=True)
            self.assertTrue(
                marker_vuln.exists(),
                "Direct interpolation failed to execute injected command (reproduction failed)"
            )

            # 2. Env indirection with quoted reference (the fix)
            malicious_input_safe = f'target" ; touch "{marker_safe}" ; echo "'
            safe_script = 'TARGET_PATH="$TARGET_INPUT"'
            subprocess.run(
                ["bash", "-c", safe_script],
                env={"TARGET_INPUT": malicious_input_safe, "PATH": os.environ.get("PATH", "")},
                capture_output=True,
                check=True
            )
            self.assertFalse(
                marker_safe.exists(),
                "Env indirection unexpectedly executed injected command"
            )


if __name__ == "__main__":
    unittest.main()
