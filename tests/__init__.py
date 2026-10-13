"""Hermetic test package initialization (agents-v1a2).

Establishes a deterministic test environment across all test modules:
clears ambient operator tool pins (FACTORY_TOOL_PINS) and sets the
dev/test opt-in (FACTORY_ALLOW_UNPINNED_TOOLS=1) so that tests run
against the repository tree rather than ambient host machine state.
"""

import pathlib

from tests import hermetic_env

hermetic_env.isolate_operator_config()


def tracked_test_paths(pattern: str = "tests/test_*.py") -> list:
    """The TRACKED test modules matching `pattern`, in path order (agents-4ieg).

    WHY THE WALKERS MUST NOT GLOB THE FILESYSTEM: tests/ is not a frozen set of files during a run. The
    fast-gate probes in tests/test_fast_gate_mapping.py create and delete real test modules inside tests/,
    and the gate's own witness line says untracked files are NOT witnessed - a walker that enumerates the
    filesystem can therefore see a file that is deleted before it is read. That is measured, not theoretical:
    the full gate failed on union tree 906d415e7b89a1765c8277bf8ab4cd78754c7215 with
    "FileNotFoundError: .../tests/test_multi_a_probe_tmp.py" inside this module, because the glob and the
    read straddled the probe's delete. Enumerating what git TRACKS is the same set the gate witnesses, so
    the walkers and the gate agree about what the tree contains.
    """
    import subprocess
    root = pathlib.Path(__file__).resolve().parent.parent
    out = subprocess.run(["git", "-C", str(root), "ls-files", pattern],
                         capture_output=True, text=True, check=True).stdout.split()
    return [root / name for name in sorted(out)]
