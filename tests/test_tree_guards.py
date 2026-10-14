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


def catches_a_missing_module(handler: ast.ExceptHandler) -> bool:
    """True only when this handler can actually swallow a MISSING MODULE (agents-85ef).

    `except ValueError:` cannot - a missing lib module raises ModuleNotFoundError, which is not a
    ValueError - so an import under it is required, and the earlier rule ("any *Error handler makes the
    import optional") dropped a real dependency. A bare `except:` and the four names below can catch it.
    """
    if handler.type is None:
        return True
    names: list[str] = []
    if isinstance(handler.type, ast.Name):
        names = [handler.type.id]
    elif isinstance(handler.type, ast.Tuple):
        names = [e.id for e in handler.type.elts if isinstance(e, ast.Name)]
    return any(n in {"ImportError", "ModuleNotFoundError", "Exception", "BaseException"} for n in names)


def type_checking_names(tree: ast.AST) -> set[str]:
    """The names in one module that hold `typing.TYPE_CHECKING` (agents-b8ke).

    Both spellings are collected, because both are used: `from typing import TYPE_CHECKING as TC`
    binds `TC`, and `import typing` leaves `typing.TYPE_CHECKING` as an attribute.
    """
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "") == "typing":
            for alias in node.names:
                if alias.name == "TYPE_CHECKING":
                    names.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "typing":
                    names.add(f"{alias.asname or alias.name}.TYPE_CHECKING")
    return names


def import_time_truth(test: ast.expr, type_checking: set[str]) -> bool | None:
    """What a module-level `if` test evaluates to WHILE THE MODULE IS BEING IMPORTED.

    True/False when the value is statically known, None when it is not (`sys.version_info`, an
    environment lookup, anything read at runtime). Callers ask `is False`: a guard whose value is
    unknown runs as far as this rule is concerned, exactly like an unguarded import.
    """
    if isinstance(test, ast.Constant) and isinstance(test.value, (bool, type(None))):
        return bool(test.value)
    if isinstance(test, ast.Name) and test.id in type_checking:
        return False
    if isinstance(test, ast.Attribute) and ast.unparse(test) in type_checking:
        return False
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        inner = import_time_truth(test.operand, type_checking)
        return None if inner is None else not inner
    if isinstance(test, ast.BoolOp):
        values = [import_time_truth(value, type_checking) for value in test.values]
        if isinstance(test.op, ast.And):
            if any(value is False for value in values):
                return False
            return True if all(value is True for value in values) else None
        if isinstance(test.op, ast.Or):
            if any(value is True for value in values):
                return True
            return False if all(value is False for value in values) else None
    return None


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
      - NOT under a `TYPE_CHECKING` guard that is STATICALLY FALSE at import time - `if
        TYPE_CHECKING:` never runs at all (lib/scheduler.py is imported that way, which is why
        requiring the raw closure demanded a module these suites do not need), while
        `if not TYPE_CHECKING:` DOES run, so what it imports is required (agents-b8ke: the first
        rule asked whether the test's source TEXT mentioned TYPE_CHECKING, which is just as true
        of the negation, and that false negative was invisible to this guard's own tests).
    Where the closure had to be a judgement, it was made by running it: the raw module-scope
    closure flagged six sites for lib/sandbox.py (imported at module scope by lib/egress_proxy.py)
    while every one of those suites passes, so the rule is the closure of the ENTRY POINTS a tree
    runs, not of every file its list happens to copy. And "which entry points does this list run?"
    is answered by the dispatcher's own dependency markers (budget.py, child_env.py), not by "it
    copies something only factory imports" - that weaker test failed six healthy sites too.

    TWO MORE SHAPES OF WRONG, both found by reviewers and both fixed here rather than narrowed away
    (agents-85ef): a class BODY executes at import time, so `class Init: from lib.absent import x`
    breaks a staged tree exactly as a module-scope import does, and an `except ValueError:` cannot catch
    a missing module (that raises ModuleNotFoundError), so an import under it is required too. Both were
    measured against a real staged tree that raised ModuleNotFoundError while this guard reported
    nothing. A genuine `except ImportError:` fallback is still optional, and the tests hold that control.

    REJECTED ATTEMPTS ARE RECORDED HERE BECAUSE THEY WILL BE RE-PROPOSED, and each was rejected by
    measuring it rather than by argument:
      - walk into package directories (lib/sinks/*.py) as part of the closure: the engine closure would
        gain lib/budget.py through lib/sinks/command.py and SEVEN healthy sites go red demanding a
        module they never import. The package is staged as a tree by copytree and its internal imports
        are not the tree's entry points, so a module reachable ONLY through a package is out of scope
        for this rule - a known, measured false negative rather than a guessed fix;
      - fail loudly on any staging loop whose module list this guard cannot read, AS A BLANKET: rejected by
        measurement, because the detector fired on healthy loops whose bodies merely mention lib (seven of
        them) and still on four when it required the body to copy something - no text search can exclude this
        guard's own source, which contains `findings` and `budget` throughout. The hole it aimed at was real
        (agents-n5e0: a concatenated list resolved to nothing, was skipped in silence, and reported the same
        green as a list that was read and checked), so what replaced it is a three-way classification whose
        middle class is derived from THIS rule's own construction rather than from a search of the text:
        (1) RESOLVE MORE FIRST - a name bound to an earlier list, `BASE + ('embargo.py',)` and
        `[*BASE, 'embargo.py']` are read by name, because where a case can be checked, checking beats
        refusing; (2) EXHAUSTIVE BY CONSTRUCTION - an iterable that enumerates every lib/*.py covers the
        whole requirement space, so green for it is justified rather than unchecked; (3) EVERYTHING ELSE
        THAT STAGES LIB MODULES is reported LOUDLY as an unreadable list. Class 3 needs one further fact to
        stay green on a healthy tree - the loop must COPY a lib file whose SOURCE path is built from its own
        loop variable, which is what makes that variable a module name rather than an incidental counter -
        and it was measured over all nine loops under tests/ whose iterable this rule cannot read: one is
        the exhaustive lib-glob, eight are not staging loops by that test, none is left, so the report is
        silent on today's tree and fires only on a list genuinely built at runtime.

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
        type_checking = type_checking_names(tree)
        for node in ast.walk(tree):
            # agents-b8ke: ask what the test EVALUATES to at import time, not whether its source
            # TEXT mentions TYPE_CHECKING. `if not TYPE_CHECKING:` runs, so its imports are
            # required; the text match called them optional and a staged tree that omitted the
            # module raised ModuleNotFoundError while this guard reported nothing.
            if isinstance(node, ast.If) and import_time_truth(node.test, type_checking) is False:
                for sub in ast.walk(node):
                    if isinstance(sub, (ast.Import, ast.ImportFrom)):
                        optional.add(id(sub))
            if isinstance(node, ast.Try):
                if any(catches_a_missing_module(h) for h in node.handlers):
                    for sub in node.body:
                        for inner in ast.walk(sub):
                            if isinstance(inner, (ast.Import, ast.ImportFrom)):
                                optional.add(id(inner))
        found: set[str] = set()

        def walk(node: ast.AST) -> None:
            for child in ast.iter_child_nodes(node):
                # A CLASS BODY runs at import time, so its imports are required like any other
                # module-scope import (agents-85ef). A METHOD does not, and is skipped as a
                # FunctionDef below - which is the whole reason this is not just "walk everything".
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
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
        """Read a staging list, or None when this rule genuinely cannot.

        RESOLVE MORE FIRST, because where a case can be checked, checking beats refusing (agents-n5e0,
        agents-1p9g). A name bound to an earlier list, a concatenation of resolvable halves
        (`BASE + ('embargo.py',)`) and a spread of a resolvable one (`[*BASE, 'embargo.py']`) are all read
        by NAME, so an incomplete list built any of those ways is reported with the missing module rather
        than skipped. None means UNREADABLE, and the caller now acts on that difference instead of
        conflating it with an empty list - `if not names: continue` treated both as nothing to do.
        """
        if isinstance(node, ast.Name):
            return consts.get(node.id)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = literal_list(node.left, consts)
            right = literal_list(node.right, consts)
            if left is None or right is None:
                return None
            return left + right
        if not isinstance(node, (ast.Tuple, ast.List)):
            return None
        names: list[str] = []
        for element in node.elts:
            if isinstance(element, ast.Starred):
                inner = literal_list(element.value, consts)
                if inner is None:
                    return None
                names.extend(inner)
                continue
            if not (isinstance(element, ast.Constant) and isinstance(element.value, str)):
                return None
            names.append(element.value)
        return names

    def stages_every_lib_py(node: ast.AST) -> bool:
        """An iterable that enumerates EVERY lib/*.py satisfies every requirement this rule can produce, so green
        for it is JUSTIFIED rather than unchecked. The proof is this rule's own construction above: a requirement
        is `root/'lib'/f'{module}.py'` and only non-directory modules under lib/ are ever returned, so a list
        holding all of lib/*.py cannot be missing anything. This is the class a blanket "fail loudly on any
        unreadable list" turned RED (tests/test_adapter_auth_failure.py:250), and the reason the rule is a
        three-way classification rather than a refusal.
        """
        while (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
               and node.func.id in {"sorted", "list", "tuple", "set"} and node.args):
            node = node.args[0]
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            return False
        method = node.func.attr
        receiver = ast.unparse(node.func.value)
        if method == "iterdir":
            return "lib" in receiver
        if method in {"glob", "rglob"} and node.args and isinstance(node.args[0], ast.Constant):
            pattern = str(node.args[0].value)
            return pattern.endswith(".py") and "*" in pattern and ("lib" in receiver or "lib" in pattern)
        return False

    def stages_lib_modules_by_variable(node: ast.For) -> bool:
        """Whether a loop whose iterable this rule cannot read is ACTUALLY a staging loop: it copies a lib file
        whose SOURCE path is built from its own loop variable, which is what makes that variable a module NAME
        rather than an incidental counter.

        This is the discriminator the file used to say it did not have (agents-n5e0), and it is a shape test on
        the copy call rather than a search of the source text, because a text search cannot exclude this guard's
        own loops: "the body mentions lib" fired on seven healthy loops and "the body copies something" still on
        four (see the docstring above). Measured over the nine loops under tests/ whose iterable is unreadable:
        this test is false for eight of them and the ninth is the exhaustive lib-glob, so the report below stays
        silent on today's tree.
        """
        loop_variables = {n.id for n in ast.walk(node.target) if isinstance(n, ast.Name)}
        for call in ast.walk(node):
            if not isinstance(call, ast.Call) or not call.args:
                continue
            func = call.func
            name = func.attr if isinstance(func, ast.Attribute) else (
                func.id if isinstance(func, ast.Name) else "")
            if name not in {"copyfile", "copy", "copy2", "copytree", "move"}:
                continue
            if {n.id for n in ast.walk(call.args[0]) if isinstance(n, ast.Name)} & loop_variables:
                return True
        return False

    problems: list[str] = []
    for path in sorted((root / "tests").glob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        # A binding is a binding whether the expression sits in a loop header or in a module-level name
        # (agents-1p9g): the consts map used to accept only literal tuple/list assignments, so
        # `MODULES = BASE + ('embargo.py',)` stayed unresolved and the loop iterating it was skipped in
        # silence - the same defect as the inline concatenation, one level up. It is now built in source
        # order through the same resolver the loop header uses, so one name may be built from an earlier
        # name.
        #
        # A LATER BINDING REPLACES AN EARLIER ONE, and a name this rule cannot read must never be read as
        # its stale value (agents-g7b7, found by review of e3c81f23 and reproduced there): handling only
        # plain `Assign` left `MODULES += ("extra.py",)` holding the OLD list, so the guard reported a module
        # MISSING while the staged tree copies it. A false FAILURE is worse than the silent skip it
        # replaced, so every module-level binding is accounted for and an unreadable one DROPS the name -
        # the loop header then treats it exactly like any other unreadable iterable.
        def module_scope_store_names(statement: ast.stmt) -> set[str]:
            """Names STORED anywhere inside a module-level statement, excluding nested function/class bodies.

            Their locals are not module names, but `for MODULES in ...:`, `with open(...) as MODULES:`,
            `import MODULES`, and their `if`/`try` spellings all bind at module scope. This is how a binding
            this rule does not model is found and dropped instead of being left to be read as its old value.
            """
            found: set[str] = set()

            def walk(current: ast.AST) -> None:
                for child in ast.iter_child_nodes(current):
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                        continue
                    if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                        found.add(child.id)
                    elif isinstance(child, ast.alias):
                        found.add((child.asname or child.name).split(".")[0])
                    walk(child)

            walk(statement)
            return found

        def module_scope_bindings(statement: ast.stmt) -> dict[str, list[str] | None]:
            """Every module-level Name this statement BINDS, mapped to the list it holds - or None for unreadable.

            The three assignment forms resolve through the same resolver the loop header uses, and
            AugAssign(Add) concatenates onto the value the name already holds; every other module-level binding
            maps to None so the name is DROPPED. Over-invalidation is deliberate and safe: an unreadable name
            takes the same path as any other unreadable iterable (loud where the loop stages lib modules,
            quiet where it is provably exhaustive), while a stale name quietly checks the WRONG list.
            """
            if isinstance(statement, ast.Assign):
                bindings = {target.id: literal_list(statement.value, consts)
                            for target in statement.targets if isinstance(target, ast.Name)}
                for other in (target for target in statement.targets if not isinstance(target, ast.Name)):
                    for name in module_scope_store_names(other):
                        bindings[name] = None
                return bindings
            if isinstance(statement, ast.AnnAssign):
                if not isinstance(statement.target, ast.Name):
                    return {}
                readable = None if statement.value is None else literal_list(statement.value, consts)
                return {statement.target.id: readable}
            if isinstance(statement, ast.AugAssign):
                if not isinstance(statement.target, ast.Name):
                    return {}
                current = consts.get(statement.target.id)
                added = literal_list(statement.value, consts) if isinstance(statement.op, ast.Add) else None
                concatenated = current + added if current is not None and added is not None else None
                return {statement.target.id: concatenated}
            return {name: None for name in module_scope_store_names(statement)}

        consts: dict[str, list[str]] = {}
        for statement in tree.body:
            for name, resolved in module_scope_bindings(statement).items():
                if resolved is None:
                    consts.pop(name, None)
                else:
                    consts[name] = resolved
        for node in ast.walk(tree):
            if not isinstance(node, ast.For):
                continue
            names = literal_list(node.iter, consts)
            body = ast.unparse(node)
            if '"lib"' not in body and "'lib'" not in body:
                continue
            if names is None:
                # THE GUARD MUST SAY WHAT IT COULD NOT SEE (agents-n5e0). `if not names: continue` swallowed
                # this case silently - and an EMPTY literal list with it - so a staging list built at runtime
                # reported the same green as one that was READ AND CHECKED. The two classes above are handled
                # first: an exhaustive lib-glob cannot be missing a module, so green is justified; anything
                # else that stages lib modules by name is reported so the author can make it checkable.
                if stages_every_lib_py(node.iter) or not stages_lib_modules_by_variable(node):
                    continue
                problems.append(
                    f"{path.name}:{node.lineno}: this loop stages lib modules named by a list built at "
                    "RUNTIME, so no requirement can be checked against it and a missing module would pass "
                    "unnoticed; spell the list as a literal or a concatenation of literals, or stage every "
                    "lib/*.py with a glob, so the modules the runtime imports can be checked"
                )
                continue
            staged = {n[:-3] if n.endswith(".py") else n for n in names}
            if "findings" not in staged and "budget" not in staged:
                continue
            required = runtime if staged & dispatcher_markers else engine
            missing = sorted(required - staged)
            if missing:
                problems.append(
                    f"{path.name}:{node.lineno}: this staging list builds a runtime that imports "
                    f"{sorted(m + '.py' for m in missing)} at import time but does not copy it"
                )
    return problems


def staged_suite_source(modules: tuple[str, ...]) -> str:
    """The bytes of the synthetic staging suite used by the fixtures below.

    One source of truth on purpose (agents-fe64): the assertion that the diagnostic carries
    `file:line` COMPUTES the loop's line from this text instead of copying a literal, so it cannot
    pass while the promise is broken and cannot fail for a fixture that moved.
    """
    listed = ", ".join(f'"{module}"' for module in modules)
    return ("import shutil\nfrom pathlib import Path\nROOT = Path(__file__).parent\n"
            f"MODULES = ({listed})\n"
            "def build(root):\n    for module in MODULES:\n"
            '        shutil.copyfile(ROOT / "lib" / module, root / "lib" / module)\n')


def staged_tree(findings_source: str) -> Path:
    """A synthetic factory tree whose ONLY staging list copies findings.py and embargo.py.

    findings.py's siblings are supplied as embargo.py and extra.py, so a module the source imports
    but the list does not copy is exactly the failure this guard exists to catch.
    """
    directory = Path(tempfile.mkdtemp())
    (directory / "lib").mkdir()
    (directory / "tests").mkdir()
    (directory / "factory").write_text("from lib.embargo import x\n", encoding="utf-8")
    (directory / "lib" / "findings.py").write_text(findings_source, encoding="utf-8")
    (directory / "lib" / "embargo.py").write_text("x = 1\n", encoding="utf-8")
    (directory / "lib" / "extra.py").write_text("required = 1\n", encoding="utf-8")
    (directory / "tests" / "test_staged.py").write_text(
        staged_suite_source(("findings.py", "embargo.py")), encoding="utf-8")
    return directory


class TestStagedRuntimeCarriesItsImports(unittest.TestCase):
    """agents-o7e2: a staging list must carry the modules its runtime imports at module scope."""

    def test_every_staging_list_carries_its_runtime_imports(self):
        problems = staged_runtime_missing_modules(ROOT)
        self.assertEqual(problems, [], "\n".join(problems))

    def test_a_module_level_concatenated_staging_list_is_checked_by_name(self):
        """agents-1p9g, the reviewer's repro against the first attempt: a binding is a binding.

        The first fix resolved an INLINE concatenation while the consts map still accepted only literal
        tuple/list assignments, so `MODULES = BASE + ('embargo.py',)` stayed unresolved and the loop
        iterating it was skipped in silence - the same silent skip, one level up, and the reviewer's repro
        was exactly that edit to the synthetic suite. So this pin drives the MODULE-LEVEL spelling (and the
        starred one, which is the third shape the original finding named): findings.py imports lib/extra.py
        at module scope and neither list stages it.
        """
        findings_source = "from lib.embargo import x\nfrom lib.extra import required\n"

        def suite(modules_expression: str) -> str:
            return ("import shutil\nfrom pathlib import Path\nROOT = Path(__file__).parent\n"
                    'BASE = ("findings.py",)\n'
                    f"MODULES = {modules_expression}\n"
                    "def build(root):\n    for module in MODULES:\n"
                    '        shutil.copyfile(ROOT / "lib" / module, root / "lib" / module)\n')

        concatenated = staged_tree(findings_source)
        (concatenated / "tests" / "test_staged.py").write_text(
            suite('BASE + ("embargo.py",)'), encoding="utf-8")
        found = "\n".join(staged_runtime_missing_modules(concatenated))
        self.assertIn("extra.py", found,
                      "a MODULE-LEVEL concatenation must be checked, not skipped: `MODULES = BASE + (...)` "
                      "is the reviewer's repro and extra.py is imported at module scope")

        starred = staged_tree(findings_source)
        (starred / "tests" / "test_staged.py").write_text(
            suite('[*BASE, "embargo.py"]'), encoding="utf-8")
        self.assertIn("extra.py", "\n".join(staged_runtime_missing_modules(starred)),
                      "a spread of a resolvable list is the same binding and is read the same way")

        complete = staged_tree(findings_source)
        (complete / "tests" / "test_staged.py").write_text(
            suite('BASE + ("embargo.py", "extra.py")'), encoding="utf-8")
        self.assertEqual(staged_runtime_missing_modules(complete), [],
                         "resolution is not refusal: a complete module-level concatenation stays green")

    def test_a_later_binding_replaces_the_earlier_one_instead_of_going_stale(self):
        """agents-g7b7, found by the independent review of e3c81f23 (P2): a later binding replaces an early one.

        Resolving only plain assignment left the consts map holding the OLD list when a suite re-bound the
        name, so the guard reported a module MISSING while the staged tree copies it - a false failure, which
        is worse than the silent skip it replaced. Measured on e3c81f23 before this rule: an AugAssign that
        COMPLETES the list still reported extra.py missing. The four cases below are the resolution, the
        incomplete read, the annotated literal, and the honest unreadable re-binding.
        """
        findings_source = "from lib.embargo import x\nfrom lib.extra import required\n"

        def suite(statements: str) -> str:
            return ("import shutil\nfrom pathlib import Path\nROOT = Path(__file__).parent\n"
                    'BASE = ("findings.py",)\n'
                    f"{statements}"
                    "def build(root):\n    for module in MODULES:\n"
                    '        shutil.copyfile(ROOT / "lib" / module, root / "lib" / module)\n')

        def reported(statements: str) -> str:
            tree = staged_tree(findings_source)
            (tree / "tests" / "test_staged.py").write_text(suite(statements), encoding="utf-8")
            return "\n".join(staged_runtime_missing_modules(tree))

        self.assertEqual(reported('MODULES = BASE + ("embargo.py",)\nMODULES += ("extra.py",)\n'), "",
                         "a later `+=` replaces the earlier binding, so the complete list must report nothing")

        incomplete = reported('MODULES = BASE\nMODULES += ("embargo.py",)\n')
        self.assertIn("extra.py", incomplete, "the one module that is missing must still be named")
        self.assertNotIn("embargo.py", incomplete,
                         "the += value is part of the list, so it is not missing")

        self.assertEqual(reported('MODULES: tuple = BASE + ("embargo.py", "extra.py")\n'), "",
                         "an annotated literal is a binding like any other and must be READ, not refused")

        rebound = reported('MODULES = BASE + ("embargo.py",)\nMODULES = runtime_modules()\n')
        self.assertIn("RUNTIME", rebound,
                      "a re-binding this rule cannot read is reported, not silently checked as its old value")

    def test_a_staging_list_built_at_runtime_is_reported_and_an_exhaustive_glob_is_not(self):
        """agents-n5e0: the silent skip is gone for the lists that cannot be resolved either.

        `if not names: continue` gave the same green to a list this guard READ AND CHECKED and to one it
        could not read at all, so a helper returning module names - the third shape the original finding
        named - was invisible; a missing module would have passed unnoticed and reported as clean. The
        discriminator is the copy call rather than the text of the loop: a loop that copies a lib file whose
        SOURCE path is built from its own loop variable is a staging loop, and that one is now REPORTED.
        THE CONTROLS ARE THE POINT, because the blanket version of this check was measured red on healthy
        loops of this very tree: a loop over an exhaustive `(ROOT/'lib').glob('*.py')` cannot be missing a
        module (class 2), and a loop over a case table whose copy sources are literals is not a staging loop.
        """
        findings_source = "from lib.embargo import x\nfrom lib.extra import required\n"

        def suite(body: str) -> str:
            return ("import shutil\nfrom pathlib import Path\nROOT = Path(__file__).parent\n"
                    "def listed_modules():\n    return (\"findings.py\", \"embargo.py\")\n"
                    "def build(root):\n" + body)

        runtime_built = staged_tree(findings_source)
        (runtime_built / "tests" / "test_staged.py").write_text(
            suite('    for module in listed_modules():\n'
                  '        shutil.copyfile(ROOT / "lib" / module, root / "lib" / module)\n'),
            encoding="utf-8")
        problems = staged_runtime_missing_modules(runtime_built)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("test_staged.py", problems[0])
        self.assertIn("RUNTIME", problems[0],
                      "an unreadable staging list must SAY SO rather than report the same green as a "
                      "list that was checked")

        exhaustive = staged_tree(findings_source)
        (exhaustive / "tests" / "test_staged.py").write_text(
            suite('    for source in sorted((ROOT / "lib").glob("*.py")):\n'
                  '        shutil.copyfile(source, root / "lib" / source.name)\n'),
            encoding="utf-8")
        self.assertEqual(staged_runtime_missing_modules(exhaustive), [],
                         "a list holding every lib/*.py cannot be missing a module, so green is justified "
                         "rather than a false refusal")

        case_table = staged_tree(findings_source)
        (case_table / "tests" / "test_staged.py").write_text(
            suite('    for case, expected in (("a", "b"), ("c", "d")):\n'
                  '        shutil.copyfile(ROOT / "lib" / "findings.py", root / "lib" / case)\n'),
            encoding="utf-8")
        self.assertEqual(staged_runtime_missing_modules(case_table), [],
                         "the loop variable is an incidental counter, not a module name, so a loop with "
                         "literal copy sources is not a staging list")

    def test_the_guard_names_the_site_and_the_missing_module(self):
        """The case the guard must REJECT, so a green result means something.

        A synthetic tree whose findings.py gains a hard import that its staging list does not
        copy - the exact failure measured on 2026-10-13 - must be reported with the site and the
        module named. Without this, a guard that silently reports nothing would look identical to
        a tree with nothing wrong.

        agents-fe64: the diagnostic also promises the LINE, so the line is asserted - computed
        from the fixture (the loop is on the 6th line of it, not the 5th the reviewer guessed)
        rather than copied, so removing `:{node.lineno}` from the diagnostic fails this test.
        """
        tmp = staged_tree("from lib.embargo import x\nfrom lib.newthing import y\n")
        (tmp / "lib" / "newthing.py").write_text("y = 1\n", encoding="utf-8")
        problems = staged_runtime_missing_modules(tmp)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("test_staged.py", problems[0])
        self.assertIn("newthing.py", problems[0])
        suite_line = next(index for index, line in enumerate(
            staged_suite_source(("findings.py", "embargo.py")).splitlines(), 1)
            if "for module in MODULES" in line)
        self.assertIn(f"test_staged.py:{suite_line}:", problems[0])

    def test_the_requirement_is_derived_from_the_source_and_enforced(self):
        """agents-eq11, found by a reviewer: the earlier version of this test was VACUOUS.

        It asserted that findings.py contains a `from lib.` import and never called the guard, so it
        would have passed against a guard that returned [] for every tree - a test that cannot fail for
        the property it names, which is the defect the guard itself exists to remove. This one asserts
        the derived requirement is ENFORCED: a tree staging the engine without a sibling the engine
        imports must be reported, and the module it names is one the guard learned by reading the source.
        """
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "lib").mkdir()
            (tmp / "tests").mkdir()
            (tmp / "factory").write_text("from lib.embargo import x\n", encoding="utf-8")
            (tmp / "lib" / "findings.py").write_text(
                "from lib.embargo import needed\n", encoding="utf-8")
            (tmp / "lib" / "embargo.py").write_text("needed = 1\n", encoding="utf-8")
            (tmp / "tests" / "test_staged.py").write_text(
                "import shutil\nfrom pathlib import Path\nROOT = Path(__file__).parent\n"
                'MODULES = ("findings.py",)\n'
                'def build(root):\n    for module in MODULES:\n'
                '        shutil.copyfile(ROOT / "lib" / module, root / "lib" / module)\n',
                encoding="utf-8")
            problems = staged_runtime_missing_modules(tmp)
            self.assertEqual(len(problems), 1, problems)
            self.assertIn("embargo.py", problems[0])

    def test_import_time_imports_are_required_even_in_a_class_body_or_an_odd_handler(self):
        """agents-85ef, found by a reviewer against a real staged tree rather than by inspection.

        A class body executes at import time, so `class Init: from lib.extra import required` fails a
        staged tree exactly as a module-scope import does; and `except ValueError:` cannot catch a
        missing module, so an import under it is required too. Both were measured against a staged tree
        that raised ModuleNotFoundError while this guard reported nothing. THE THIRD CASE IS THE CONTROL:
        a genuine `except ImportError:` fallback must stay unflagged, or the fix would demand modules
        from trees that run perfectly well without them.
        """
        synthetic = staged_tree

        class_body = synthetic("from lib.embargo import x\n\nclass Init:\n"
                               "    from lib.extra import required\n")
        self.assertEqual(len(staged_runtime_missing_modules(class_body)), 1,
                         staged_runtime_missing_modules(class_body))
        self.assertIn("extra.py", staged_runtime_missing_modules(class_body)[0])

        odd_handler = synthetic("from lib.embargo import x\ntry:\n"
                                "    from lib.extra import required\n"
                                "except ValueError:\n    pass\n")
        self.assertIn("extra.py", "".join(staged_runtime_missing_modules(odd_handler)),
                      "an except that cannot catch a missing module does not make the import optional")

        real_fallback = synthetic("from lib.embargo import x\ntry:\n"
                                  "    from lib.extra import required\n"
                                  "except ImportError:\n    required = None\n")
        self.assertEqual(staged_runtime_missing_modules(real_fallback), [],
                         "a genuine ImportError fallback means the tree runs without the module")

    def test_a_type_checking_guard_is_read_by_what_it_evaluates_to_at_runtime(self):
        """agents-b8ke, the reviewer's repro: `if not TYPE_CHECKING:` RUNS at import time.

        The rule used to ask whether the test's SOURCE TEXT contained "TYPE_CHECKING", which is just
        as true of the negation, so an import under `if not TYPE_CHECKING:` counted as optional: a
        staged tree that omitted the module raised ModuleNotFoundError while this guard reported
        nothing (reproduced on the reviewed tip, and - the point of the merger's gate datum -
        invisible to this class's own tests). The four controls below are the shapes that must NOT
        move: a plain `if TYPE_CHECKING:` never runs, `TYPE_CHECKING and X` can never be true either,
        and `TYPE_CHECKING or X` CAN run, so its import is required like any other.
        """
        def findings(body: str) -> str:
            return "from lib.embargo import x\nfrom typing import TYPE_CHECKING\n" + body

        def missing(root: Path) -> str:
            return "\n".join(staged_runtime_missing_modules(root))

        negated = staged_tree(findings("if not TYPE_CHECKING:\n    from lib.extra import required\n"))
        self.assertIn("extra.py", missing(negated),
                      "`if not TYPE_CHECKING:` runs, so the module it imports is required")

        aliased = staged_tree("from lib.embargo import x\nfrom typing import TYPE_CHECKING as TC\n"
                              "if not TC:\n    from lib.extra import required\n")
        self.assertIn("extra.py", missing(aliased),
                      "the alias is the same guard and the same requirement")

        attribute = staged_tree("from lib.embargo import x\nimport typing\n"
                                "if not typing.TYPE_CHECKING:\n    from lib.extra import required\n")
        self.assertIn("extra.py", missing(attribute),
                      "the attribute spelling is the same import-time guard")

        plain = staged_tree(findings("if TYPE_CHECKING:\n    from lib.extra import required\n"))
        self.assertEqual(staged_runtime_missing_modules(plain), [],
                         "a TYPE_CHECKING guard never runs, so its import stays optional")

        conjunction = staged_tree(findings(
            "if TYPE_CHECKING and __debug__:\n    from lib.extra import required\n"))
        self.assertEqual(staged_runtime_missing_modules(conjunction), [],
                         "`TYPE_CHECKING and X` can never be true, so it never runs either")

        disjunction = staged_tree(findings(
            "if TYPE_CHECKING or __debug__:\n    from lib.extra import required\n"))
        self.assertIn("extra.py", missing(disjunction),
                      "`TYPE_CHECKING or X` can run at import time, so the import is required")


if __name__ == "__main__":
    unittest.main()
