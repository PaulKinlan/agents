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


def staged_runtime_missing_modules(root: Path) -> list[str]:
    """Staging lists in tests/ that do NOT carry the modules the runtime they build imports.

    WHY THIS GUARD EXISTS (agents-o7e2). Six-plus test suites build a staged factory runtime by
    copying an EXPLICIT list of lib/ modules into a temp tree. A one-line import added to
    lib/findings.py therefore breaks every one of those suites with ModuleNotFoundError, and
    NOTHING NAMES WHICH ONES - measured on 2026-10-13, when findings.py gained
    `from lib.line_numbers import usable_line_number` and five separate copy lists had to be found
    by running suites and reading failures. That is a speed-and-fragility defect: any change to
    findings.py costs a tree-wide edit and the fast gate's omitted suites fail for whoever runs
    them next rather than for whoever broke them.

    THE RULE IS DERIVED, NOT ENUMERATED, and it is calibrated against the real tree rather than
    guessed. A list that stages `findings.py` builds the engine, so it must carry the HARD import
    closure of lib/findings.py; a list that also stages factory-only modules builds the whole
    dispatcher, so it must carry the hard closure of `factory` too. "Hard" is doing real work in
    that sentence and it is the reason this passes today:
      - module scope only - an import inside a function runs when it is called, so a tree that
        never calls it needs no copy of the module;
      - NOT under `try: ... except ImportError` - an optional dependency by construction;
      - NOT under `if TYPE_CHECKING:` - that never runs at all (lib/scheduler.py is imported that
        way, which is why requiring the raw closure demanded a module these suites do not need).
    Where the closure had to be a judgement, it was made by running it: the raw module-scope
    closure flagged six sites for lib/sandbox.py (imported at module scope by lib/egress_proxy.py)
    while every one of those suites passes, so the rule is the closure of the ENTRY POINTS a tree
    runs, not of every file its list happens to copy. And "which entry points does this list run?"
    is answered by the dispatcher's own dependency markers (budget.py, child_env.py), not by "it
    copies something only factory imports" - that weaker test failed six healthy sites too.

    Returns a list of 'path:line: stages [...]; missing [...]' strings, or [] when every list is
    complete.
    """
    def hard_local_imports(path: Path) -> set[str]:
        if not path.exists():
            return set()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            return set()
        optional: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.If) and "TYPE_CHECKING" in ast.unparse(node.test):
                for sub in ast.walk(node):
                    if isinstance(sub, (ast.Import, ast.ImportFrom)):
                        optional.add(id(sub))
            if isinstance(node, ast.Try):
                guarded = any(h.type is None or "Error" in ast.unparse(h.type) for h in node.handlers)
                if guarded:
                    for sub in node.body:
                        for inner in ast.walk(sub):
                            if isinstance(inner, (ast.Import, ast.ImportFrom)):
                                optional.add(id(inner))
        found: set[str] = set()

        def walk(node: ast.AST) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                                      ast.Lambda)):
                    continue
                if id(child) in optional:
                    continue
                if isinstance(child, ast.ImportFrom):
                    module = child.module or ""
                    if module.startswith("lib."):
                        found.add(module.split(".")[1])
                    elif module == "lib":
                        found.update(alias.name for alias in child.names)
                elif isinstance(child, ast.Import):
                    for alias in child.names:
                        if alias.name.startswith("lib."):
                            found.add(alias.name.split(".")[1])
                walk(child)

        walk(tree)
        return found

    def closure(entries: list[str]) -> set[str]:
        seen: set[str] = set()
        stack = list(entries)
        while stack:
            module = stack.pop()
            if module in seen:
                continue
            seen.add(module)
            path = root / "lib" / f"{module}.py"
            if path.exists():
                stack.extend(hard_local_imports(path))
        # A package directory (lib/sinks) is staged as a tree by every one of these sites, so it is
        # satisfied by the copytree rather than by a name in the module list.
        return {m for m in seen if not (root / "lib" / m).is_dir()}

    engine = closure(["findings"])
    runtime = engine | closure(list(hard_local_imports(root / "factory")) + ["findings"])
    # WHICH REQUIREMENT APPLIES IS CALIBRATED, NOT MERELY DERIVED. "Stages findings.py" is the
    # engine; a list that also stages budget.py or child_env.py is building the DISPATCHER, because
    # those are modules only `factory` imports at module scope. The first cut of this rule keyed on
    # "stages any factory-only module", which flagged six sites for sandbox/budget/... because they
    # copy lib/egress_proxy.py (to exercise the proxy directly) without building a dispatcher - and
    # every one of those suites passes. A guard that fails on a healthy tree is worse than none, so
    # the discriminator is the dispatcher's own dependency set, verified against all ten sites.
    dispatcher_markers = {"budget", "child_env"}

    def literal_list(node: ast.AST, consts: dict[str, list[str]]) -> list[str] | None:
        if isinstance(node, ast.Name) and node.id in consts:
            return consts[node.id]
        if not isinstance(node, (ast.Tuple, ast.List)):
            return None
        names = []
        for element in node.elts:
            if not (isinstance(element, ast.Constant) and isinstance(element.value, str)):
                return None
            names.append(element.value)
        return names

    problems: list[str] = []
    for path in sorted((root / "tests").glob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        consts = {
            node.targets[0].id: [e.value for e in node.value.elts]
            for node in tree.body
            if isinstance(node, ast.Assign) and isinstance(node.value, (ast.Tuple, ast.List))
            and isinstance(node.targets[0], ast.Name)
            and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in node.value.elts)
        }
        for node in ast.walk(tree):
            if not isinstance(node, ast.For):
                continue
            names = literal_list(node.iter, consts)
            if not names:
                continue
            body = ast.unparse(node)
            if '"lib"' not in body and "'lib'" not in body:
                continue
            staged = {n[:-3] if n.endswith(".py") else n for n in names}
            if "findings" not in staged and "budget" not in staged:
                continue
            required = runtime if staged & dispatcher_markers else engine
            missing = sorted(required - staged)
            if missing:
                problems.append(
                    f"{path.name}:{node.lineno}: this staging list builds a runtime that imports "
                    f"{sorted(m + '.py' for m in missing)} at module scope but does not copy it"
                )
    return problems


class TestStagedRuntimeCarriesItsImports(unittest.TestCase):
    """agents-o7e2: a staging list must carry the modules its runtime imports at module scope."""

    def test_every_staging_list_carries_its_runtime_imports(self):
        problems = staged_runtime_missing_modules(ROOT)
        self.assertEqual(problems, [], "\n".join(problems))

    def test_the_guard_names_the_site_and_the_missing_module(self):
        """The case the guard must REJECT, so a green result means something.

        A synthetic tree whose findings.py gains a hard import that its staging list does not
        copy - the exact failure measured on 2026-10-13 - must be reported with the site and the
        module named. Without this, a guard that silently reports nothing would look identical to
        a tree with nothing wrong.
        """
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "lib").mkdir()
            (tmp / "tests").mkdir()
            (tmp / "lib" / "findings.py").write_text(
                "from lib.embargo import x\nfrom lib.newthing import y\n", encoding="utf-8")
            (tmp / "lib" / "embargo.py").write_text("x = 1\n", encoding="utf-8")
            (tmp / "lib" / "newthing.py").write_text("y = 1\n", encoding="utf-8")
            (tmp / "factory").write_text("from lib.embargo import x\n", encoding="utf-8")
            (tmp / "tests" / "test_staged.py").write_text(
                "import shutil\nfrom pathlib import Path\nROOT = Path(__file__).parent\n"
                'MODULES = ("findings.py", "embargo.py")\n'
                'def build(root):\n    for module in MODULES:\n'
                '        shutil.copyfile(ROOT / "lib" / module, root / "lib" / module)\n',
                encoding="utf-8")
            problems = staged_runtime_missing_modules(tmp)
            self.assertEqual(len(problems), 1, problems)
            self.assertIn("test_staged.py", problems[0])
            self.assertIn("newthing.py", problems[0])

    def test_the_closure_is_derived_and_not_vacuous(self):
        """The requirement is read from the source, so the guard proves it went and looked."""
        tree = ast.parse((ROOT / "lib" / "findings.py").read_text(encoding="utf-8"))
        self.assertTrue(tree.body)
        source = (ROOT / "lib" / "findings.py").read_text(encoding="utf-8")
        self.assertIn("from lib.", source)   # findings.py imports siblings; the closure is real


if __name__ == "__main__":
    unittest.main()
