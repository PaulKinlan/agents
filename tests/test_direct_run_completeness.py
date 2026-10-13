#!/usr/bin/env python3
"""agents-9lh8: a test module's `if __name__ == "__main__"` block must be its LAST statement.

WHY THIS IS A CONTRACT AND NOT A STYLE POINT. When a test file is executed DIRECTLY
(`python3 tests/test_x.py`, or `python3 -m tests.test_x`, which is the form that works for
modules that do not insert the repo root themselves), the file runs as `__main__`, so
`unittest.main()` collects only the test classes DEFINED ABOVE the block. A block that sits
mid-file therefore reports `OK` while silently running a SUBSET. Measured before the move in
agents-9lh8, via `python3 -m tests.test_x`:

    test_findings.py           Ran 20 tests ... OK   (57 test methods in the module)
    test_docs_drift.py         Ran 13 ... OK         (33)
    test_report_schema.py      Ran 23 ... OK         (40)
    test_candidate_binding.py  Ran 17 ... OK         (30)
    test_model_rule_id.py      Ran 13 ... OK         (20)
    test_tool_pins.py          Ran 49 ... OK         (51)

THE BOUND, STATED SO THE NEXT READER DOES NOT HAVE TO ASK: this was never a CI bug. The gate
uses DISCOVERY (`python3 -m unittest discover -s tests -t .`), which imports the modules as
modules, so `__main__` NEVER fires and every test runs - no gate was lying, and no gate is
being fixed here. The hole is only for a human or a lane that executes the file, which our own
guidance ("run the single test file") tells people to do: they get `OK` and a green light for
tests that never ran.

WHY THE INVARIANT LIVES HERE RATHER THAN IN EACH FILE'S OWN SUITE: the defect is produced by
appending a test BELOW the block, which is what happened to all six modules - the block was
last when it was written and later work added tests after it. Nobody notices at review time,
because the file still reads fine and its suite still passes under discovery. So the property
belongs to the CLASS: 70 of the 71 committed `tests/test_*.py` modules carry this block, and
this suite asserts the shape for all of them. `tools/fast-gate.sh`'s `tests/test_*.py)` arm maps
this suite, so any test-file change re-checks the whole class.
"""

import ast
import pathlib
import unittest

from tests import tracked_test_paths

ROOT = pathlib.Path(__file__).resolve().parents[1]


def walked_test_modules() -> list:
    """The test modules this contract walks: the TRACKED ones (agents-4ieg).

    Not `ROOT.glob("tests/test_*.py")`: the fast-gate probes in tests/test_fast_gate_mapping.py create and
    delete real test modules in tests/ during a run, and the gate's witness says untracked files are not
    witnessed - so a filesystem walk can see a file that is gone by the time it is read. Measured as a full
    gate failure on union tree 906d415e7b89a1765c8277bf8ab4cd78754c7215:
    "FileNotFoundError: .../tests/test_multi_a_probe_tmp.py" in this module, with both modules in shard 1.
    """
    return tracked_test_paths("tests/test_*.py")
#: The modules agents-9lh8 relocated a mid-file block in. Named explicitly so the walk cannot
#: silently stop covering them (see test_the_walk_covers_the_modules_agents_9lh8_named).
BEAD_MODULES = (
    "tests/test_findings.py",
    "tests/test_docs_drift.py",
    "tests/test_report_schema.py",
    "tests/test_candidate_binding.py",
    "tests/test_model_rule_id.py",
    "tests/test_tool_pins.py",
    # already relocated by agents-dso1 before this bead; covered so it cannot drift back
    "tests/test_pin_generator_hasher.py",
)


def mid_file_main_blocks(source: str, label: str = "<source>") -> "list[str]":
    """Return one message per TOP-LEVEL `if __name__ == "__main__"` block that is not last.

    Top-level only: a nested guard is a different construct and not this convention. "Last"
    means no top-level statement begins after the block ends, so the block is the final thing
    the interpreter would reach when the module runs as `__main__`.
    """
    tree = ast.parse(source)
    findings = []
    for node in tree.body:
        if not (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
                and isinstance(node.test.left, ast.Name) and node.test.left.id == "__name__"):
            continue
        after = [n for n in tree.body if n.lineno > node.end_lineno]
        if after:
            findings.append(
                f"{label}: the __main__ block at :{node.lineno} precedes {len(after)} more "
                f"top-level statement(s), the last at :{max(n.end_lineno for n in after)} - "
                f"direct execution would run only the tests above the block")
    return findings


class TheDirectRunContractTest(unittest.TestCase):
    def test_no_test_module_runs_a_subset_when_executed_directly(self):
        offenders = []
        walked = 0
        for path in walked_test_modules():
            walked += 1
            offenders += mid_file_main_blocks(
                path.read_text(), str(path.relative_to(ROOT)))
        self.assertGreater(walked, 50, "the walk must actually see the test tree")
        self.assertEqual([], offenders,
                         "move the __main__ block to the END of the file: executed directly it "
                         "otherwise reports OK while running only what is defined above it")

    def test_the_walk_covers_the_modules_agents_9lh8_named(self):
        """Non-vacuity for the walk: the files this bead was about are inside the glob."""
        walked = {str(p.relative_to(ROOT)) for p in walked_test_modules()}
        for name in BEAD_MODULES:
            self.assertIn(name, walked)

    def test_the_walk_is_blind_to_a_probe_that_exists_only_during_a_run(self):
        """agents-4ieg, DRIVEN AGAINST THE WALK ITSELF: a file that exists transiently must not be in the
        walk, because the walk reads what it finds and the probes are deleted the moment their case ends.
        Red against the glob this replaces (which lists the probe) and green against tracked_test_paths,
        which sees exactly what the gate witnesses: the tracked tree.
        """
        probe = ROOT / "tests" / "test_walker_probe_tmp.py"
        probe.write_text("import unittest\n", encoding="utf-8")
        try:
            walked = {str(p.relative_to(ROOT)) for p in walked_test_modules()}
            self.assertNotIn("tests/test_walker_probe_tmp.py", walked,
                             "an untracked, transient probe file must not be walked: the walker reads every "
                             "path it finds, and test_fast_gate_mapping.py deletes its probes mid-run")
            self.assertIn("tests/test_direct_run_completeness.py", walked,
                          "the walk must still see the tracked modules - non-vacuity for the pin")
        finally:
            probe.unlink(missing_ok=True)

    def test_the_detection_fires_on_a_mid_file_block_and_stays_quiet_on_a_last_one(self):
        """The detector is proven to fire, so a green run is not a green light for a dead check."""
        mid = "import unittest\n\n\nclass T(unittest.TestCase):\n    def test_a(self):\n        pass\n\n\nif __name__ == '__main__':\n    unittest.main()\n\n\nclass U(unittest.TestCase):\n    def test_b(self):\n        pass\n"
        last = "import unittest\n\n\nclass T(unittest.TestCase):\n    def test_a(self):\n        pass\n\n\nif __name__ == '__main__':\n    unittest.main()\n"
        self.assertEqual(1, len(mid_file_main_blocks(mid, "mid.py")),
                         "a mid-file block must be reported")
        self.assertEqual([], mid_file_main_blocks(last, "last.py"),
                         "a trailing block must not be reported")


if __name__ == "__main__":
    unittest.main()
