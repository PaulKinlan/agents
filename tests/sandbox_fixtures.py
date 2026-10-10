#!/usr/bin/env python3
"""Shared sandbox builder for station-script fixtures (agents-8ztd).

Fixtures that run a station script in a disposable sandbox used to decide BY HAND which lib/
modules to copy next to the script: each of test_path_security.py, test_vuln_verify_prepass.py
and test_pr_fixer_prepass.py carried its own list, and the redaction copy ended up appended,
character-for-character identical, in all three. That is the same defect shape agents-h0mb
removed at the station level: a hand-maintained enumeration the next instance silently escapes.
A station gains a shared import and every fixture that did not add the line reddens with an
ImportError that looks like an unrelated fixture problem.

This builder answers "which libs does the sandbox need" from the artefact under test instead of
from a list: it parses the station script, follows its imports into lib/, and copies the
transitive closure. A new shared helper reaches every sandbox by being imported, not by someone
remembering a line.

Run its tests with: python3 -m unittest discover -s tests -p 'test_sandbox_fixtures.py' -v
"""

import ast
import shutil
from pathlib import Path
from typing import Optional, Set

ROOT = Path(__file__).resolve().parent.parent
LIB = ROOT / "lib"


def _lib_file(dotted: str) -> Optional[Path]:
    """Resolve a dotted module name under lib/ to a repo file, or None if it is not one."""
    parts = dotted.split(".")
    if parts[0] != "lib" or len(parts) < 2:
        return None
    for candidate in (LIB.joinpath(*parts[1:]).with_suffix(".py"),
                      LIB.joinpath(*parts[1:]) / "__init__.py"):
        if candidate.is_file():
            return candidate
    return None


def _imported_names(source: Path) -> Set[str]:
    """Every absolute module name `source` imports, at any nesting depth (try/if/function).

    Module-level scanning is deliberate: lib/redaction.py imports lib.line_numbers inside a
    function with a fallback, and a sandbox that skips function-level imports would silently
    exercise the fallback instead of the real module.
    """
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level or not node.module:
                continue  # relative imports: lib/ has no packages that use them
            names.add(node.module)
            # `from lib import redaction` names the module in the alias, not in node.module.
            for alias in node.names:
                names.add(f"{node.module}.{alias.name}")
    return names


def lib_import_closure(entry: Path) -> Set[Path]:
    """Repo-relative Paths of the lib/ modules `entry` transitively imports.

    A bare `from line_numbers import ...` INSIDE a lib module is a sibling import (the
    fallback form in lib/redaction.py); bare names in a non-lib file are not resolved against
    lib/, because a station script may legitimately import a sibling script instead.
    """
    closure: Set[Path] = set()
    stack = [entry]
    visited = {entry.resolve()}
    while stack:
        current = stack.pop()
        in_lib = LIB.resolve() in current.resolve().parents
        for name in _imported_names(current):
            candidates = [name]
            if in_lib and "." not in name:
                candidates.append(f"lib.{name}")
            for dotted in candidates:
                path = _lib_file(dotted)
                if path is None:
                    continue
                closure.add(path.relative_to(ROOT))
                resolved = path.resolve()
                if resolved not in visited:
                    visited.add(resolved)
                    stack.append(path)
    return closure


def copy_station_script(sandbox: Path, script_src: Path, script_rel: str) -> Path:
    """Copy a station script and its lib/ import closure into a sandbox mirror of the repo.

    `script_rel` is the script's path INSIDE the sandbox (e.g.
    "agents/pr-fixer/scripts/collect_failures.py") so the script's FACTORY_ROOT, derived from
    __file__, resolves to the sandbox tree. The fixture keeps its own per-test differences
    (target files, findings stores); the copy mechanism is what is shared. Returns the
    sandboxed script path.
    """
    script = sandbox / script_rel
    script.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(script_src, script)
    for rel in sorted(lib_import_closure(script_src)):
        dst = sandbox / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel, dst)
    return script
