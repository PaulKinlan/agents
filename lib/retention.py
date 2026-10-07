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
  produced, at most this many *settled* run directories survive (a directory that
  is still actively being written is exempt — see the active-run guard below).
- ``FACTORY_RUN_RETENTION_AGE_DAYS`` sets a time-to-live in whole days (default 30).
  A run directory older than this is pruned even if it is within the count bound.

Safety (never lose a live run, never escape ``runs/``):

- The in-progress run directory is passed as ``exclude`` and is never pruned.
- An active run directory (one whose ``.active`` marker is younger than
  ``FACTORY_RUN_ACTIVE_GRACE_SECONDS``) is skipped entirely, so a concurrent
  scheduled run that overflows the count bound cannot sweep a long-running run.
- The hill-climb proposal/staging directories (``runs/hillclimb-*/``) are not run
  directories and are never swept.
- Only real directories are considered; symlinks and non-directory files are
  skipped, so pruning can never follow a symlink out of ``runs/``.
- A directory that cannot be stat'ed or removed is skipped with a warning to
  stderr; one unruly entry never aborts the run.

Mid-run crash: retention runs once, immediately after the new run directory is
created and before the pre-pass/model work. The ``.active`` marker protects the live
run for the grace window; if the process is hard-killed the marker stays behind and
is swept once it goes stale, so a crashed run's partial directory is kept for
inspection and pruned on a later run — never while it is being written.
"""

import os
import shutil
import stat
import sys
import time
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

# Sane, bounded defaults. Overridable per operator via the environment.
RETAIN_COUNT_DEFAULT = 20
RETAIN_AGE_DAYS_DEFAULT = 30

_ENV_RETAIN_COUNT = "FACTORY_RUN_RETENTION"
_ENV_RETAIN_AGE_DAYS = "FACTORY_RUN_RETENTION_AGE_DAYS"

# The hill-climb path stages its proposal under runs/hillclimb-<target>-<run_id>/
# (holding the live disposable worktree and the accumulated session.patch). That is a
# proposal artifact, not a run record, and must never be swept as one.
_HILLCLIMB_PREFIX = "hillclimb-"

# An in-progress run carries this marker file. Pruning skips a directory whose marker
# is younger than the active grace, so a concurrent run cannot sweep a live run.
ACTIVE_MARKER_NAME = ".active"
ACTIVE_GRACE_SECONDS_DEFAULT = 3600  # one hour: comfortably above any station budget
_ENV_ACTIVE_GRACE_SECONDS = "FACTORY_RUN_ACTIVE_GRACE_SECONDS"

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


def active_grace_seconds(env: Optional[dict] = None) -> float:
    """Return the active-run grace in seconds from the environment.

    Pruning skips a run directory whose ``.active`` marker is younger than this many
    seconds. Unset, unparseable or non-positive values fall back to the bounded
    default (one hour); ``env`` is injectable for tests and defaults to ``os.environ``.
    """
    env = os.environ if env is None else env
    raw = env.get(_ENV_ACTIVE_GRACE_SECONDS)
    if raw is not None:
        try:
            value = float(raw)
            if value > 0:
                return value
        except ValueError:
            pass
    return ACTIVE_GRACE_SECONDS_DEFAULT


def run_directories(runs_dir: Path) -> Iterable[Path]:
    """Yield run directories (real directories, never symlinks) under ``runs_dir``.

    A symlink is a leaf and is never followed or returned: deleting through it
    could touch a directory outside ``runs/``. Non-directory files (e.g. the
    scheduler's ``schedule-*.stdout.log``) are not run directories. The hill-climb
    ``runs/hillclimb-*/`` proposal/staging directories are likewise excluded.
    """
    if not runs_dir.is_dir():
        return
    for entry in sorted(runs_dir.iterdir()):
        if entry.name.startswith(_HILLCLIMB_PREFIX):
            continue
        if entry.is_symlink():
            continue
        if entry.is_dir():
            yield entry


def _marker_is_active(directory: Path, now: float, grace: float) -> bool:
    """True when ``directory`` carries a fresh ``.active`` marker.

    A fresh marker means a run is still allocating/completing inside ``directory``,
    so pruning must skip it. Only a regular file counts (a symlink or a directory
    named ``.active`` is not a marker), and ``grace`` bounds how long a stale marker
    (from a hard-killed run) keeps its directory protected.
    """
    marker = directory / ACTIVE_MARKER_NAME
    try:
        st = marker.lstat()
    except OSError:
        return False
    if not stat.S_ISREG(st.st_mode):
        return False
    return (now - st.st_mtime) < grace


def prune_run_dirs(runs_dir: Path, *, now: Optional[float] = None,
                   retain: Optional[int] = None,
                   max_age_seconds: Optional[float] = None,
                   active_grace: Optional[float] = None,
                   exclude: Iterable[Path] = ()) -> List[Path]:
    """Prune old run directories so secret-bearing artifacts stay bounded.

    Keeps the ``retain`` most-recent directories (by mtime) and removes any
    directory older than ``max_age_seconds``. Directories in ``exclude`` are never
    removed, and directories carrying a fresh ``.active`` marker (younger than
    ``active_grace`` seconds) are skipped entirely, so a concurrent run cannot sweep
    a still-running directory. Returns the list of directories that were removed.

    ``now`` is injectable for deterministic TTL tests; it defaults to the current
    wall-clock time. ``retain``, ``max_age_seconds`` and ``active_grace`` default to
    the module's bounded defaults when ``None``.
    """
    now = time.time() if now is None else now
    retain = RETAIN_COUNT_DEFAULT if retain is None else retain
    max_age_seconds = (RETAIN_AGE_DAYS_DEFAULT * _SECONDS_PER_DAY
                       if max_age_seconds is None else max_age_seconds)
    active_grace = ACTIVE_GRACE_SECONDS_DEFAULT if active_grace is None else active_grace

    exclude_resolved = {Path(p).resolve() for p in exclude}

    # (resolved_path, mtime, name) — the resolved path is the pruning identity, so
    # the in-progress run is recognised however the caller spells it. The name is
    # only a deterministic tiebreak when two runs share an mtime.
    dirs: List[Tuple[Path, float, str]] = []
    for directory in run_directories(runs_dir):
        if _marker_is_active(directory, now, active_grace):
            continue
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
