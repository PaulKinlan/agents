"""The containment suites' shape, pinned (agents-3iog).

The mid-file suite ran 220 discovered tests, but only 112 were distinct: the two
subclasses that add their own assertions inherited TestDispatcher's 54 tests and
re-ran them under its identical setUp, so 108 executions - roughly 100 s of the
file's 163 s - were duplicates of work already done. That is a shape, not a
suite's business, so it gets a shape test.

The invariant: a containment TestCase may only inherit from `unittest.TestCase`
or from the shared harness, which defines NO test methods. Inheriting from a
class that has tests (i.e. re-running them) is the defect this pins.
"""
import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODULES = sorted(ROOT.glob("tests/test_containment*.py")) + [ROOT / "tests/containment_harness.py"]


def _classes(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            tests = frozenset(
                f.name for f in node.body
                if isinstance(f, ast.FunctionDef) and f.name.startswith("test"))
            bases = tuple(ast.unparse(b) for b in node.bases)
            yield node.name, bases, tests


class TestTheContainmentSuitesDoNotReRunInheritedTests(unittest.TestCase):
    def test_the_shared_harness_defines_no_tests(self):
        classes = {name: tests for name, _bases, tests in _classes(ROOT / "tests/containment_harness.py")}
        self.assertIn("ContainmentHarness", classes)
        # EVERY class, not just the harness one. The file is deliberately not test_*.py, so
        # discovery never collects it, and the arm covering harness changes runs the six modules
        # that IMPORT it - not a class nothing imports. Measured while sizing that arm: a leaked
        # test class added to this module left the entire mapped set GREEN, which is the
        # silent-green shape this pin exists to prevent. A test method inside ContainmentHarness
        # is also caught, because it is re-run by every subclass.
        offenders = {name: sorted(tests) for name, tests in classes.items() if tests}
        self.assertEqual(offenders, {},
                         "the harness module must hold setUp and helpers only: a test method in ANY "
                         "class here is never collected and never run (agents-3iog)")

    def test_no_containment_case_inherits_from_a_class_that_has_tests(self):
        with_tests = {}
        for path in MODULES:
            for name, _bases, tests in _classes(path):
                if tests:
                    with_tests[name] = tests
        offenders = []
        for path in MODULES:
            for name, bases, _tests in _classes(path):
                for base in bases:
                    base_name = base.split(".")[-1].rstrip(")")
                    if base_name in with_tests:
                        offenders.append(
                            f"{path.name}: {name} inherits {len(with_tests[base_name])} tests "
                            f"from {base_name}")
        self.assertEqual(offenders, [],
                         "a containment Case inherits a class that has tests, so it re-runs them "
                         "under the base's own setUp - inherit harness.ContainmentHarness instead "
                         "(agents-3iog)")
