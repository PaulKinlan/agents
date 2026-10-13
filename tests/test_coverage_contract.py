#!/usr/bin/env python3
"""Contract-declared cross-file coverage dependencies (agents-1kzf).

THE HOLE THIS TESTS (agents-1kzf):
When a diff modifies a public function signature in a source file (e.g. child_environment
in lib/child_env.py adding verified_pins=), a test in an UNTOUCHED file (tests/test_promotion.py)
that mocks or asserts that signature can break. Because the untouched test file does not
directly import the modified lib module (it accesses the function via a re-exporting module
like factory_cli), standard import-based candidate discovery in the fast gate and coverage
oracle misses it.

The remedy is a declarative contract in tests/coverage-contract.json. This suite enforces that:
1. tests/coverage-contract.json exists, is valid JSON, and maps existent files.
2. Any test that mocks a public lib function without directly importing the defining lib module
   is statically detected and required to be declared in tests/coverage-contract.json.
3. When check-coverage.py or tools/fast-gate.sh evaluates a changed file with declared contract
   dependencies, the contracted test suites are required candidate tests and flagged as omitted
   if not executed.
"""

from tests import tracked_test_paths
import ast
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
CONTRACT_PATH = ROOT / "tests" / "coverage-contract.json"
ORACLE_SCRIPT = Path("/home/exedev/fleet/remote/check-coverage.py")


def _copy_gate_registry(dest: Path) -> None:
    """agents-hr6q: the gate's arm registry is a DIRECTORY now (tools/fast-gate-arms.d/), and the script
    refuses to run without it, so a copy of tools/fast-gate.sh alone is not a runnable gate. These tests
    copy the gate into a temp tree to mutate its inputs; they must copy its registry the same way, or they
    would be testing the refusal instead of the behaviour they name.
    """
    import shutil

    shutil.copytree(ROOT / "tools" / "fast-gate-arms.d", dest / "tools" / "fast-gate-arms.d")


class TestCoverageContract(unittest.TestCase):

    def test_coverage_contract_file_exists_and_is_valid(self):
        """tests/coverage-contract.json must exist, be valid JSON, and map existent source paths
        to existent test suite paths."""
        self.assertTrue(CONTRACT_PATH.is_file(), "tests/coverage-contract.json must exist")
        data = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        self.assertIsInstance(data, dict, "contract must be a JSON object mapping source paths to suite lists")
        self.assertTrue(data, "contract must declare at least one cross-file mapping")

        for src, suites in data.items():
            src_path = ROOT / src
            # A pattern may be a GLOB, which is what tools/fast-gate.sh's own validator accepts
            # (glob.glob(pat)) and what the harness oracle matches with fnmatch - the arm registry is a
            # directory whose members are added one file at a time (agents-hr6q), so listing 29 literal
            # paths in the contract would make every new arm edit this file too. A pattern must still
            # MATCH something, so a typo cannot declare coverage for a file that does not exist.
            if any(ch in src for ch in "*?["):
                self.assertTrue(sorted(ROOT.glob(src)), f"contract pattern {src!r} matches no file")
            else:
                self.assertTrue(src_path.exists(), f"contract source path {src!r} does not exist")
            self.assertIsInstance(suites, list, f"contract suites for {src!r} must be a list")
            self.assertTrue(suites, f"contract suites for {src!r} must not be empty")
            for suite in suites:
                suite_path = ROOT / suite
                self.assertTrue(suite_path.is_file(), f"contract suite {suite!r} does not exist")

    def test_cross_module_mocks_are_declared_in_coverage_contract(self):
        """Statically inspect all tests for mock.patch.object of public lib functions.
        If a test mocks a lib function without directly importing the defining module,
        it must be declared in tests/coverage-contract.json."""
        contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))

        # 1. Discover all public functions defined in lib/*.py
        lib_defs = {}
        for p in sorted(ROOT.glob("lib/*.py")):
            tree = ast.parse(p.read_text(encoding="utf-8"))
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if not node.name.startswith("_"):
                        lib_defs[node.name] = p.relative_to(ROOT).as_posix()

        # 2. Check all tests for mock.patch.object targeting these functions
        undeclared = []
        for tf in tracked_test_paths("tests/test_*.py"):
            content = tf.read_text(encoding="utf-8")
            tree = ast.parse(content)

            # Discover direct imports from lib in this test file
            imported_lib_stems = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        parts = alias.name.split(".")
                        if parts[0] == "lib" and len(parts) > 1:
                            imported_lib_stems.add(parts[1])
                elif isinstance(node, ast.ImportFrom):
                    if node.module and node.module.startswith("lib."):
                        imported_lib_stems.add(node.module.split(".")[1])
                    elif node.module == "lib":
                        for alias in node.names:
                            imported_lib_stems.add(alias.name)

            # Find mock.patch.object(target, 'attr')
            for m in re.finditer(r'mock\.patch\.object\(\s*[a-zA-Z0-9_]+,\s*["\']([a-zA-Z0-9_]+)["\']', content):
                attr = m.group(1)
                if attr in lib_defs:
                    defining_file = lib_defs[attr]
                    defining_stem = Path(defining_file).stem
                    if defining_stem not in imported_lib_stems:
                        tf_rel = tf.relative_to(ROOT).as_posix()
                        declared = contract.get(defining_file, [])
                        if tf_rel not in declared:
                            undeclared.append((tf_rel, attr, defining_file))

        self.assertEqual(
            undeclared, [],
            f"Found cross-module mocks without direct import not declared in tests/coverage-contract.json: {undeclared}. "
            "Declare these dependencies in tests/coverage-contract.json so the coverage oracle and fast-gate "
            "track them as required consumers (agents-1kzf)."
        )

    def test_check_cmd_is_declared_in_coverage_contract(self):
        """tools/check-cmd.sh has .py consumers (tests/test_check_conf_consistency.py and
        tests/test_gate_entrypoint_config.py); because check-coverage.py's stem/import heuristic
        does not match .sh sources to .py tests, it must be declared in coverage-contract.json (agents-b0eg)."""
        contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        self.assertIn("tools/check-cmd.sh", contract)
        suites = contract["tools/check-cmd.sh"]
        self.assertIn("tests/test_check_conf_consistency.py", suites)
        self.assertIn("tests/test_gate_entrypoint_config.py", suites)

    def test_oracle_extract_coverage_flags_omitted_contract_suites(self):
        """When check-coverage.py runs on a diff modifying a contracted file (e.g. lib/child_env.py)
        without executing the contracted suite (tests/test_promotion.py), it must report
        tests/test_promotion.py in omitted suites."""
        if not ORACLE_SCRIPT.is_file():
            self.skipTest("fleet check-coverage.py not available in environment")

        import importlib.util
        spec = importlib.util.spec_from_file_location("check_coverage_oracle", str(ORACLE_SCRIPT))
        oracle_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(oracle_mod)

        with tempfile.NamedTemporaryFile("w") as log:
            log.write("fast-gate: passed: tests/test_child_env.py\n")
            log.flush()

            # Mock git commands so oracle sees non-merged commit with lib/child_env.py changed
            orig_check_output = oracle_mod.subprocess.check_output
            def mock_check_output(cmd, *args, **kwargs):
                if isinstance(cmd, list):
                    if "rev-parse" in cmd:
                        return ("deadbeef" * 5) + "\n"
                    if any("diff" in str(x) for x in cmd):
                        return "lib/child_env.py\n"
                return orig_check_output(cmd, *args, **kwargs)

            from unittest.mock import patch
            with patch.object(oracle_mod.subprocess, "check_output", side_effect=mock_check_output):
                cov = oracle_mod.extract_coverage(log.name, str(ROOT), "HEAD", "bash tools/fast-gate.sh")

            self.assertIn("lib/child_env.py", cov.get("unmapped", []),
                          "changed file with omitted contract suite must be flagged in unmapped")
            self.assertIn("tests/test_promotion.py", cov.get("omitted", []),
                          "contract-declared suite must be named in omitted suites when not executed (agents-1kzf)")

    def test_malformed_coverage_contract_aborts_fast_gate_loudly(self):
        """A malformed tests/coverage-contract.json must not be silently ignored by tools/fast-gate.sh;
        the gate must fail loudly with exit non-zero without mutating tracked files (agents-1kzf, agents-v2vf)."""
        import os
        import tempfile
        import shutil
        fast_gate = ROOT / "tools" / "fast-gate.sh"
        with tempfile.TemporaryDirectory() as tmpdir:
            tmproot = Path(tmpdir)
            (tmproot / "tools").mkdir()
            (tmproot / "tests").mkdir()
            shutil.copy2(fast_gate, tmproot / "tools" / "fast-gate.sh")
            _copy_gate_registry(tmproot)
            (tmproot / "tests" / "coverage-contract.json").write_text("not valid json", encoding="utf-8")
            res = subprocess.run(
                ["bash", str(tmproot / "tools" / "fast-gate.sh")],
                cwd=str(tmproot), capture_output=True, text=True,
                env=dict(os.environ, GIT_CHANGED="lib/child_env.py")
            )
            self.assertNotEqual(res.returncode, 0, "malformed contract must fail fast-gate loudly")
            self.assertIn("fast-gate: FAIL: tests/coverage-contract.json is malformed", res.stderr)

    def test_invalid_coverage_contract_value_aborts_fast_gate_loudly(self):
        """Non-list/non-string values or nonexistent suites in coverage-contract.json must fail loudly (agents-fk5j)."""
        import os
        import tempfile
        import shutil
        fast_gate = ROOT / "tools" / "fast-gate.sh"
        cases = (
            ('{"lib/child_env.py": 42}', "must be list of suite paths or string, got int"),
            ('{"lib/child_env.py": ["tests/nonexistent_suite_xyz.py"]}', "does not exist"),
            ('{"": ["tests/test_promotion.py"]}', "pattern must be non-empty string"),
            ('{}', "must not be empty"),
            ('{"nonexistent/file.py": ["tests/test_promotion.py"]}', "does not exist"),
            ('{"lib/child_env.py": []}', "suite list for 'lib/child_env.py' must not be empty"),
        )
        for bad_contract, expected_err in cases:
            with self.subTest(contract=bad_contract):
                with tempfile.TemporaryDirectory() as tmpdir:
                    tmproot = Path(tmpdir)
                    (tmproot / "tools").mkdir()
                    (tmproot / "tests").mkdir()
                    (tmproot / "lib").mkdir()
                    (tmproot / "lib" / "child_env.py").touch()
                    shutil.copy2(fast_gate, tmproot / "tools" / "fast-gate.sh")
                    _copy_gate_registry(tmproot)
                    (tmproot / "tests" / "coverage-contract.json").write_text(bad_contract, encoding="utf-8")
                    res = subprocess.run(
                        ["bash", str(tmproot / "tools" / "fast-gate.sh")],
                        cwd=str(tmproot), capture_output=True, text=True,
                        env=dict(os.environ, GIT_CHANGED="lib/child_env.py")
                    )
                    self.assertNotEqual(res.returncode, 0, f"bad contract {bad_contract!r} must fail fast-gate")
                    self.assertIn(expected_err, res.stderr)

        # Directory instead of regular file must abort exit 1
        with tempfile.TemporaryDirectory() as tmpdir:
            tmproot = Path(tmpdir)
            (tmproot / "tools").mkdir()
            (tmproot / "tests").mkdir()
            (tmproot / "tests" / "coverage-contract.json").mkdir()
            shutil.copy2(fast_gate, tmproot / "tools" / "fast-gate.sh")
            _copy_gate_registry(tmproot)
            res = subprocess.run(
                ["bash", str(tmproot / "tools" / "fast-gate.sh")],
                cwd=str(tmproot), capture_output=True, text=True,
                env=dict(os.environ, GIT_CHANGED="lib/child_env.py")
            )
            self.assertEqual(res.returncode, 1, "directory at coverage-contract.json must exit 1")
            self.assertIn("exists but is not a regular file", res.stderr)


if __name__ == "__main__":
    unittest.main()
