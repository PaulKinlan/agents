"""Hermetic test package initialization (agents-v1a2).

Establishes a deterministic test environment across all test modules:
clears ambient operator tool pins (FACTORY_TOOL_PINS) and sets the
dev/test opt-in (FACTORY_ALLOW_UNPINNED_TOOLS=1) so that tests run
against the repository tree rather than ambient host machine state.
"""

import pathlib
import subprocess

from tests import hermetic_env

hermetic_env.isolate_operator_config()

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def tracked_paths(pattern: str, root: pathlib.Path | None = None) -> list:
    """The TRACKED paths matching git pathspec `pattern`, in path order (agents-4ieg, agents-nder).

    WHY THE WALKERS MUST NOT GLOB THE FILESYSTEM: tests/ is not a frozen set of files during a run. The
    fast-gate probes in tests/test_fast_gate_mapping.py create and delete real test modules inside tests/,
    and the gate's own witness line says untracked files are NOT witnessed - a walker that enumerates the
    filesystem can therefore see a file that is deleted before it is read. That is measured, not theoretical:
    the full gate failed on union tree 906d415e7b89a1765c8277bf8ab4cd78754c7215 with
    "FileNotFoundError: .../tests/test_multi_a_probe_tmp.py" inside this module, because the glob and the
    read straddled the probe's delete. Enumerating what git TRACKS is the same set the gate witnesses, so
    the walkers and the gate agree about what the tree contains.

    `pattern` is a GIT PATHSPEC, not a shell glob: `*` matches across `/`, so `lib/*.py` also matches
    `lib/sinks/findings.py`. Ask for the directory ('lib/adapters') and filter the path components you
    meant when the answer has to be direct children only. `root` must be inside a git work tree - a
    synthetic temp root has no index at all (see has_git_index).
    """
    base = REPO_ROOT if root is None else pathlib.Path(root)
    out = subprocess.run(["git", "-C", str(base), "ls-files", "--", pattern],
                         capture_output=True, text=True, check=True).stdout.split()
    return [base / name for name in sorted(out)]


def tracked_test_paths(pattern: str = "tests/test_*.py") -> list:
    """The TRACKED test modules matching `pattern` - the test-module spelling of tracked_paths.

    Its own name because the test-tree walkers read it as "the tracked test set"; see tracked_paths for
    why a walker must not glob the filesystem (agents-4ieg).
    """
    return tracked_paths(pattern)


def has_git_index(path: pathlib.Path) -> bool:
    """True when `path` is inside a git work tree, so tracked_paths can answer for it (agents-nder).

    The walkers here enumerate from git's index because the gate witnesses tracked files only
    (agents-4ieg). A SYNTHETIC temp root built by a fixture is not inside any work tree, so there is no
    index to ask and tracked_paths would raise; a caller that accepts such a root must fall back to the
    filesystem there and SAY SO, because in that case the filesystem is the whole tree rather than a
    second, wider notion of it. A SUBDIRECTORY of the repository IS inside a work tree - git answers for
    it, relative to it - which is why this asks "is this inside a work tree" and not "is this the root".
    """
    res = subprocess.run(["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"],
                         capture_output=True, text=True)
    return res.returncode == 0 and res.stdout.strip() == "true"
