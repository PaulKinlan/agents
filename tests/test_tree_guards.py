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
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


def check_worktree_beads_decoy(root: Path) -> list[str]:
    """Check whether a linked git worktree contains decoy .beads database paths.

    Returns a list of violating path strings, or an empty list if clean.
    Canonical repositories (.git is a directory) legitimately hold the database and
    are exempt.
    """
    if not (root / ".git").is_file():
        return []
    beads_dir = root / ".beads"
    if not beads_dir.is_dir():
        return []
    candidates = [
        beads_dir / "embeddeddolt",
        beads_dir / "dolt",
    ]
    return [str(p) for p in candidates if p.is_dir()]


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

# The fast-gate consumer-coverage pin lived here until agents-undf moved it to
# tests/test_fast_gate_consumer_coverage.py: agents-dv23 pins this file to hold exactly the
# tree-guard classes, so a consumer-coverage pin placed here made the union red.

class TestWorktreeBeadsDecoyGuard(unittest.TestCase):
    """Guard rail against silent worktree decoy .beads databases (agents-5br9).

    In any linked git worktree ((ROOT / ".git").is_file()), .beads/ must not contain
    a local database directory (embeddeddolt/ or dolt/).
    Worktrees must share the canonical repository's database via upstream bd's
    git-common-dir fallback; a decoy database causes bd to report an empty ledger
    and risk overwriting remote data on bd dolt push.
    """

    def test_worktree_has_no_local_beads_database(self):
        found = check_worktree_beads_decoy(ROOT)
        if found:
            paths_str = ", ".join(found)
            self.fail(
                f"a worktree should hold no database; a decoy here means bd will report an "
                f"empty ledger and a push from it would overwrite the shared one - "
                f"move {paths_str} aside and re-run"
            )

    def test_decoy_guard_detects_and_refuses_decoy_database(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / ".git").write_text("gitdir: /path/to/.git/worktrees/test\n", encoding="utf-8")
            decoy = tmp / ".beads" / "embeddeddolt"
            decoy.mkdir(parents=True)

            found = check_worktree_beads_decoy(tmp)
            self.assertEqual(found, [str(decoy)])

    def test_decoy_guard_exempts_canonical_repository(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / ".git").mkdir()
            db = tmp / ".beads" / "embeddeddolt"
            db.mkdir(parents=True)

            found = check_worktree_beads_decoy(tmp)
            self.assertEqual(found, [])

    def test_decoy_guard_passes_clean_worktree(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / ".git").write_text("gitdir: /path/to/.git/worktrees/test\n", encoding="utf-8")
            beads_dir = tmp / ".beads"
            beads_dir.mkdir(parents=True)
            (beads_dir / "config.yaml").write_text("issue_prefix: agents\n", encoding="utf-8")

            found = check_worktree_beads_decoy(tmp)
            self.assertEqual(found, [])

    def test_decoy_guard_ignores_non_directory_files(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / ".git").write_text("gitdir: /path/to/.git/worktrees/test\n", encoding="utf-8")
            beads_dir = tmp / ".beads"
            beads_dir.mkdir(parents=True)
            # A regular file (not directory) should not be flagged as a database directory
            (beads_dir / "embeddeddolt").write_text("not a directory\n", encoding="utf-8")

            found = check_worktree_beads_decoy(tmp)
            self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
