"""Run-directory retention for the Software Factory (agents-ped).

Every `factory run` writes a run directory under ``FACTORY_ROOT/runs/`` holding the
run record (``policy.json``), raw scanner matches (``candidates.json``,
``prompt.txt``) and model output (``model_output.txt``, ``rejected_report.json``).
Those artifacts can embed matched secret values and raw model output, so they must
not accumulate without bound. Retention is applied when a new run directory is
created: keep the most recent ``N`` run directories and prune any run directory
older than a TTL.

The policy is bounded and predictable:

- ``FACTORY_RUN_RETENTION`` sets the maximum number of run directories to keep
  (default 20). The count bound is the hard guarantee: however fast runs are
  produced, at most this many run directories survive.
- ``FACTORY_RUN_RETENTION_AGE_DAYS`` sets a time-to-live in whole days (default 30).
  A run directory older than this is pruned even if it is within the count bound.

Safety (never lose a live run, never escape ``runs/``):

- The in-progress run directory is passed as ``exclude`` and is never pruned.
- Only real directories are considered; symlinks and non-directory files are
  skipped, so pruning can never follow a symlink out of ``runs/``.
- A directory that cannot be stat'ed or removed is skipped with a warning to
  stderr; one unruly entry never aborts the run.

Mid-run crash: retention runs once, immediately after the new run directory is
created and before the pre-pass/model work. If the run later crashes, its (partial)
directory is still the newest entry and is excluded from that pass, so it survives
for inspection. On a later run it is pruned once it is old enough or falls past the
count bound — never while it is the directory being written.
"""

import os
import shutil
import sys
import time
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

# Sane, bounded defaults. Overridable per operator via the environment.
RETAIN_COUNT_DEFAULT = 20
RETAIN_AGE_DAYS_DEFAULT = 30

_ENV_RETAIN_COUNT = "FACTORY_RUN_RETENTION"
_ENV_RETAIN_AGE_DAYS = "FACTORY_RUN_RETENTION_AGE_DAYS"

# The hill-climb path stages git worktrees under this name; it is not a run
# directory and must never be swept as one.
_WORKTREES_DIRNAME = "worktrees"

_SECONDS_PER_DAY = 86400


def retention_config(env: Optional[dict] = None) -> Tuple[int, float]:
    """Return ``(retain_count, max_age_seconds)`` from the environment.

    Unset or unparseable values fall back to the bounded defaults. ``env`` is
    injectable for tests; it defaults to ``os.environ``.
    """
    env = os.environ if env is None else env
    retain = RETAIN_COUNT_DEFAULT
    age_days = RETAIN_AGE_DAYS_DEFAULT

    raw_retain = env.get(_ENV_RETAIN_COUNT)
    if raw_retain is not None:
        try:
            retain = int(raw_retain)
        except ValueError:
            pass

    raw_age = env.get(_ENV_RETAIN_AGE_DAYS)
    if raw_age is not None:
        try:
            age_days = int(raw_age)
        except ValueError:
            pass

    return retain, age_days * _SECONDS_PER_DAY


def run_directories(runs_dir: Path) -> Iterable[Path]:
    """Yield run directories (real directories, never symlinks) under ``runs_dir``.

    A symlink is a leaf and is never followed or returned: deleting through it
    could touch a directory outside ``runs/``. Non-directory files (e.g. the
    scheduler's ``schedule-*.stdout.log``) are not run directories. The hill-climb
    ``worktrees/`` staging directory is likewise excluded.
    """
    if not runs_dir.is_dir():
        return
    for entry in sorted(runs_dir.iterdir()):
        if entry.name == _WORKTREES_DIRNAME:
            continue
        if entry.is_symlink():
            continue
        if entry.is_dir():
            yield entry


def prune_run_dirs(runs_dir: Path, *, now: Optional[float] = None,
                   retain: Optional[int] = None,
                   max_age_seconds: Optional[float] = None,
                   exclude: Iterable[Path] = ()) -> List[Path]:
    """Prune old run directories so secret-bearing artifacts stay bounded.

    Keeps the ``retain`` most-recent directories (by mtime) and removes any
    directory older than ``max_age_seconds``. Directories in ``exclude`` are never
    removed. Returns the list of directories that were removed.

    ``now`` is injectable for deterministic TTL tests; it defaults to the current
    wall-clock time. ``retain`` and ``max_age_seconds`` default to the module's
    bounded defaults when ``None``.
    """
    now = time.time() if now is None else now
    retain = RETAIN_COUNT_DEFAULT if retain is None else retain
    max_age_seconds = (RETAIN_AGE_DAYS_DEFAULT * _SECONDS_PER_DAY
                       if max_age_seconds is None else max_age_seconds)

    exclude_resolved = {Path(p).resolve() for p in exclude}

    # (resolved_path, mtime, name) — the resolved path is the pruning identity, so
    # the in-progress run is recognised however the caller spells it. The name is
    # only a deterministic tiebreak when two runs share an mtime.
    dirs: List[Tuple[Path, float, str]] = []
    for directory in run_directories(runs_dir):
        try:
            mtime = directory.stat().st_mtime
        except OSError as exc:
            sys.stderr.write(f"[retention] skipping {directory}: cannot stat ({exc})\n")
            continue
        dirs.append((directory.resolve(), mtime, directory.name))

    if not dirs:
        return []

    # Oldest first; the newest are the tail of the list.
    dirs.sort(key=lambda item: (item[1], item[2]))

    pruned: List[Path] = []

    # Age bound: any directory older than the TTL is pruned, regardless of count.
    for resolved, mtime, _ in dirs:
        if resolved in exclude_resolved:
            continue
        if max_age_seconds is not None and (now - mtime) > max_age_seconds:
            pruned.append(resolved)

    # Count bound: of the survivors, keep only the ``retain`` most recent.
    survivors = [r for r, _, _ in dirs
                 if r not in exclude_resolved and r not in pruned]
    if retain is not None and len(survivors) > retain:
        overflow = survivors[: len(survivors) - retain]
        pruned.extend(overflow)

    removed: List[Path] = []
    for directory in pruned:
        try:
            shutil.rmtree(directory)
            removed.append(directory)
        except OSError as exc:
            sys.stderr.write(f"[retention] could not remove {directory}: {exc}\n")

    return removed
