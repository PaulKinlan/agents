#!/usr/bin/env python3
"""The shared sandbox builder copies a station's real import closure (agents-8ztd).

The three station-script fixtures used to hand-list lib/ copies; the redaction line was the
third list and broke twice (agents-h0mb). These tests pin the replacement's one guarantee: a
lib module reaches the sandbox by being IMPORTED by the station under test, not by a fixture
author remembering a line.
"""

import tempfile
import unittest
from pathlib import Path

import sandbox_fixtures
from sandbox_fixtures import ROOT, copy_station_script, lib_import_closure

COLLECT_FAILURES = ROOT / "agents" / "pr-fixer" / "scripts" / "collect_failures.py"
PREPARE_VERIFICATION = ROOT / "agents" / "vuln-verify" / "scripts" / "prepare_verification.py"


class TestLibImportClosure(unittest.TestCase):
    def test_collect_failures_closure_includes_redaction(self):
        # The regression that motivated the bead: the emit_station_result rule (agents-qslz)
        # added lib/redaction.py to the station scripts' imports and three fixtures each had to
        # be patched by hand. The closure must contain it by derivation, not by list.
        closure = lib_import_closure(COLLECT_FAILURES)
        self.assertIn(Path("lib/redaction.py"), closure)
        self.assertIn(Path("lib/path_security.py"), closure)

    def test_function_level_and_sibling_imports_are_followed(self):
        # lib/redaction.py imports lib.line_numbers inside a function, with a bare
        # `from line_numbers import ...` fallback. Both forms must resolve, or the sandbox
        # silently exercises redaction's inline fallback instead of the real module.
        closure = lib_import_closure(COLLECT_FAILURES)
        self.assertIn(Path("lib/line_numbers.py"), closure)

    def test_prepare_verification_closure_is_its_three_lib_imports(self):
        self.assertEqual(
            lib_import_closure(PREPARE_VERIFICATION),
            {Path("lib/line_numbers.py"), Path("lib/path_security.py"), Path("lib/redaction.py")},
        )

    def test_stdlib_and_unresolved_imports_are_ignored(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            script = Path(tmpdir) / "script.py"
            script.write_text("import json\nimport os.path\nfrom typing import Optional\n",
                              encoding="utf-8")
            self.assertEqual(lib_import_closure(script), set())


class TestCopyStationScript(unittest.TestCase):
    def test_copies_script_and_closure_into_repo_shaped_sandbox(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = Path(tmpdir) / "sandbox"
            script = copy_station_script(sandbox, COLLECT_FAILURES,
                                         "agents/pr-fixer/scripts/collect_failures.py")
            self.assertEqual(script, sandbox / "agents" / "pr-fixer" / "scripts" /
                             "collect_failures.py")
            self.assertTrue(script.is_file())
            for rel in ("lib/redaction.py", "lib/path_security.py", "lib/line_numbers.py"):
                self.assertTrue((sandbox / rel).is_file(), rel)

    def test_a_new_lib_import_reaches_the_sandbox_without_a_fixture_change(self):
        # The bead's core claim: the NEXT shared import must arrive by being imported.
        # lib/embargo.py is imported by no station these fixtures drive, so it can only appear
        # in the sandbox because the (synthetic) script under test imports it.
        self.assertNotIn(Path("lib/embargo.py"), lib_import_closure(COLLECT_FAILURES))
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            script_src = tmp / "station.py"
            script_src.write_text("from lib.embargo import check_embargo\n", encoding="utf-8")
            sandbox = tmp / "sandbox"
            copy_station_script(sandbox, script_src, "agents/x/scripts/station.py")
            self.assertTrue((sandbox / "lib" / "embargo.py").is_file())


if __name__ == "__main__":
    unittest.main()
