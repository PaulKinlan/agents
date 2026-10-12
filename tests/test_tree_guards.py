#!/usr/bin/env python3
"""Tree-guard tier for agents-factory (agents-dv23, ADR agents-c07o).

Runs always-on across all fast-gate runs to enforce repository-wide invariants
over all source files (factory + lib/**/*.py).

Extracted from tests/test_budget.py (TestNoUnboundedSubprocess) so that repo-wide
subprocess execution bounds are enforced on every changed file, even when a new
lib file is introduced without an explicit budget.py mapping (closing agents-c04d).
"""

import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent.parent


class TestNoUnboundedSubprocess(unittest.TestCase):
    """Guard rail for SF-06: a subprocess call must carry a timeout or use a wrapper."""

    def test_every_dispatcher_subprocess_call_is_bounded(self):
        paths = [ROOT / "factory"] + sorted((ROOT / "lib").rglob("*.py"))
        offenders = []
        for path in paths:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                if not isinstance(func, ast.Attribute):
                    continue
                if func.attr == "communicate":
                    # agents-dhk8: THE HOLE THIS GUARD RAIL HAD. It checked the calls that
                    # CREATE a subprocess and none of the calls that WAIT on one, which is
                    # where an unbounded wait actually happens: `proc.communicate()` with no
                    # timeout in lib/budget.py passed this test for as long as the escape
                    # hatch existed, while being able to block for the LIFETIME of a process
                    # outside our group (measured: 25.1 s against a descendant that slept
                    # 25 s). communicate() is Popen-specific, so a rule for it cannot
                    # misfire - and it is checked for EVERY receiver shape (agents-v4jt): the
                    # Name requirement used to sit above this branch, so self.proc.
                    # communicate() or holders[k].communicate() were skipped entirely, which
                    # is the same hole one shape over. `wait` is deliberately NOT covered:
                    # Event.wait and thread waits share the name, and flagging them would turn
                    # other lanes' branches red for a false positive; the sole .wait( in the
                    # tree is lib/net_forward.py:162 child.wait(), bounded transitively by the
                    # station's group kill because that engine child gets no
                    # start_new_session. If wait coverage is ever wanted, key it on the
                    # receiver being a known Popen rather than on the method name.
                    if not any(kw.arg == "timeout" for kw in node.keywords):
                        offenders.append(
                            f"{path.relative_to(ROOT)}:{node.lineno}: .communicate() without timeout="
                        )
                    continue
                if not isinstance(func.value, ast.Name) or func.value.id != "subprocess":
                    continue
                where = f"{path.relative_to(ROOT)}:{node.lineno}"
                if func.attr in ("run", "call", "check_call", "check_output"):
                    if not any(kw.arg == "timeout" for kw in node.keywords):
                        offenders.append(f"{where}: subprocess.{func.attr} without timeout=")
                if func.attr == "Popen" and path.name not in ("budget.py", "net_forward.py"):
                    offenders.append(f"{where}: subprocess.Popen outside lib/budget.py")
        # lib/net_forward.py (agents-2x6) is the deliberate exception: it IS the in-sandbox
        # relay/supervisor — it runs inside the bubblewrap invocation, where
        # lib/budget.py's host-side machinery cannot reach it. Its child is bounded
        # transitively instead: the enclosing run_station_command kills the whole process
        # group at the station budget, and net_forward forwards signals and propagates the
        # child's exit code (tests/test_factory_core.py
        # TestDispatcherBudget.test_hung_engine_is_killed_at_the_station_budget rides this
        # exact path).
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
