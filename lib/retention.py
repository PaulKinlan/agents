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

Pruned-directory tombstones (agents-dm8n): beads cite run directories by path as
evidence, and a prune used to delete the target of such a citation with nothing
joining the two — the citation then dangled. Every removal of a run directory
therefore goes through ``remove_recorded``, the single recorded-removal choke
point: it deletes the directory AND appends one JSON tombstone line to
``retention-ledger.jsonl`` BESIDE the runs root (not inside it), so a citation to
a pruned run directory resolves to an explanation instead of a missing path.

The harm a tombstone answers is "a cited FILE cannot be resolved" — a citation
points at a file inside a run directory — so the tombstone records at file
granularity: the exact list of files that disappeared with the removal. A removal
that fails PART WAY (e.g. a permission bound leaves the directory present but its
contents deleted) cannot satisfy the record falsely: the tombstone is written
with ``outcome: "partial"`` listing exactly the files that were lost, computed as
the pre-removal file set minus the post-removal file set. A removal that fails
without losing anything writes nothing: a tombstone must never claim a loss that
did not happen.

The record tells the truth about its own limits (agents-dm8n round 3):

- The ledger records ONLY removals made through it. Beads sync across VMs and
  containers; the ledger does not — it is local to the filesystem that holds
  it. A cited directory with no tombstone in THIS ledger was not removed by a
  prune writing to it — not that the run never existed. The ledger names no
  machine (agents-dm8n round 4, finding 4): inside an ephemeral container a
  hostname is a random ID that reads as a stable machine identity while
  meaning none, so the honest noun is "this ledger" — all the record can
  stand behind.
- The file list is a pre-removal snapshot and CANNOT be complete in principle:
  a file created inside the directory after the snapshot and before the removal
  finishes is destroyed without ever being observed, and no snapshot ordering
  closes that window. So every line carries ``record_scope`` saying the list is
  best-effort — the record reads as best-effort where it is best-effort rather
  than claiming a completeness the mechanism cannot have.
- Symlinks are recorded with their targets (``symlinks``): os.walk YIELDS a
  symlink to a directory but does not traverse it, so a citation to a file
  reachable only THROUGH a link would otherwise dangle while the record looked
  complete. ``outside_tree`` is THREE-VALUED (agents-dm8n round 4, findings
  1-2): ``true`` means the target resolved outside the removed tree — its
  contents were NOT removed and are NOT covered; ``false`` means it resolved
  inside, so the evidence is covered by ``files`` under the target's real
  paths; ``null`` means the target COULD NOT BE FULLY RESOLVED — a symlink
  loop, a permission boundary, or more links than the resolution bound — and
  the record then claims NEITHER survival NOR destruction. Resolution is
  bounded and loop-safe (``_resolve_bounded``): the round-3 code called
  ``Path.resolve()``, which raised ``RuntimeError`` on a loop (crashing the
  prune) and silently STOPPED at an unreadable boundary, returning a
  half-resolved path that could invert ``outside_tree`` into claiming the
  evidence survived while ``rmtree`` destroyed it. An unresolvable target must
  never be recorded as survived — that inverted claim is unrepresentable now.

The ledger lives at ``<factory root>/retention-ledger.jsonl`` — beside the runs
root, outside every swept subtree (the automatic prune only removes run
directories, and a human clearing ``runs/`` to reclaim disk cannot reach it). A
tombstone answers a question a BEAD asks, and beads outlive the run root, so the
record must outlive the thing it explains. Discovery runs from the citation
side: ``runs/README.md`` (written by the prune, never swept — it is a regular
file, not a run directory) points a reader standing on a dead citation at the
ledger, and the repository README's retention section is the fallback when the
run root itself was cleared. The ledger is a plain append-only file, written by
the removal itself — no caller has to remember to record anything, and
tests/test_retention.py's deletion-inventory guard fails the gate if any other
deletion primitive appears in the shipped source without being enumerated.
"""

import errno
import json
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

# The pruned-directory tombstone ledger (agents-dm8n): one append-only JSON line
# per removal, written by remove_recorded itself at the moment of removal. It
# lives BESIDE the runs root (``runs/../retention-ledger.jsonl``, i.e. the
# factory root), never inside it: the automatic prune only sweeps run
# directories, and a HUMAN clearing ``runs/`` to reclaim disk must not take the
# record with the evidence — a tombstone answers a question a bead asks, and
# beads outlive the run root, so the record must outlive the thing it explains.
LEDGER_NAME = "retention-ledger.jsonl"

# Discovery from the citation side (agents-dm8n round 2): a reader who followed a
# bead citation into ``runs/`` and found the path dead is standing HERE, not in
# the source. This pointer file, maintained by the prune, says where the
# explanations live. It is a regular file, so run_directories never yields it and
# the automatic prune can never sweep it; a human clear of the run root removes
# it, and the repository README's retention section is the fallback for that case
# (the pointer is rewritten on the next run).
RUNS_POINTER_NAME = "README.md"

_RUNS_POINTER_TEXT = """\
# runs/ — transient run directories

Run directories under here are pruned by bounded retention (count and age — see
`lib/retention.py`); do not treat any path under here as permanent.

**Following a dead citation?** A bead or report citing `runs/<dir>/<file>` that
no longer exists: every removal is tombstoned in `../retention-ledger.jsonl`
(beside this directory, at the factory root — it survives a full clear of
`runs/` precisely so the record outlives the evidence). Search that ledger for
the directory name: each line records the directory, the reason (`age`/`count`/
`apply-worktree-failure`), the UTC time, the outcome (`removed`, `moved` or `partial`),
and the exact list of files that disappeared with it.

**This ledger records only removals made through it.** Beads sync across VMs
and containers; this ledger does not — it is local to the filesystem that
holds it. A cited directory with no tombstone in THIS ledger was not removed
by a prune writing to it — NOT that the run never existed. The ledger
deliberately names no machine: inside an ephemeral container a hostname is a
random ID that reads as a stable machine identity while meaning none, so the
honest noun is THIS LEDGER — all the record can stand behind.

**A cited directory with NO tombstone here admits three readings the record
cannot distinguish**: it was never pruned at all; it was pruned through
ANOTHER ledger (ledgers are local and do not sync); or it was pruned before
this ledger existed. Absence is not evidence of absence, and the record says
so rather than letting the three readings collapse into one.

**What a line does and does not claim.** `files` is the pre-removal snapshot
and the line says so (`record_scope`): a file created inside the directory
DURING the removal window may be destroyed without being listed — the record is
best-effort, not a completeness guarantee. Equally, a listed file is one the
removal saw disappear BETWEEN its two observations: destroyed by the removal,
or moved or renamed out of the snapshot by a concurrent writer — the record
cannot tell which, so `listed` must never be read as `destroyed`. A `symlinks`
entry records a link and its raw target; `outside_tree` is three-valued.
`true`: the target resolved OUTSIDE the removed tree — its contents were NOT
removed and are NOT covered by this record (the evidence moved or was never in
this tree). `false`: the target resolved INSIDE — the evidence is gone,
covered by `files` under the target's real paths. `null`: the target could not
be fully resolved — a symlink loop, a permission boundary, or more links than
the resolution bound — so the record claims NEITHER survival NOR destruction,
and `null` must never be read as `it survived`.

If this whole `runs/` directory was cleared and this pointer is new, see the
repository README's \"Run Artifact Retention\" section — the ledger itself is
never inside `runs/`.
"""

# What a tombstone's file list IS (agents-dm8n round 3, finding 2): the files
# observed present when the removal BEGAN. The list cannot be complete in
# principle — a file created inside the directory after the pre-removal snapshot
# and before the removal finishes is destroyed without ever being observed, and
# no snapshot ordering closes that window — so every line carries its scope
# rather than letting a bare ledger line read as a guarantee. Round 4, finding
# 3: the same honesty applies in the other direction — a LISTED file left the
# snapshot between the snapshots, and the removal cannot tell "destroyed by
# rmtree" from "moved or renamed out of the snapshot by a concurrent writer",
# so the scope says that too: listed must never read as destroyed.
RECORD_SCOPE = ("best-effort: files observed when the removal began; a file "
                "created during the removal window may not be listed, and a "
                "listed file left the snapshot between the two observations — "
                "destroyed by the removal, or moved or renamed out of it by a "
                "concurrent writer; the record cannot tell which, so listed "
                "must never be read as destroyed")

_SECONDS_PER_DAY = 86400

# The symlink resolution bound (agents-dm8n round 4, finding 1): resolution on
# the prune path is BOUNDED and LOOP-SAFE. The kernel itself gives up after 40
# follows (ELOOP); matching that bound keeps a pathological chain cheap, and
# the explicit seen-set in ``_resolve_bounded`` makes a loop a named outcome
# (an unresolvable-and-therefore-uncertain record) rather than an uncaught
# RuntimeError crashing the factory's prune path.
_MAX_SYMLINK_DEPTH = 40


def _resolve_bounded(path: Path) -> Optional[Path]:
    """Fully resolve ``path``, or return None when that cannot be known.

    Unlike ``Path.resolve(strict=False)`` this NEVER half-resolves: a symlink
    loop, a chain longer than ``_MAX_SYMLINK_DEPTH``, an unreadable component
    (a permission boundary) or an unreadable link all return None —
    unresolvable — rather than a path that merely LOOKS resolved. That is the
    difference between the record saying "I could not determine" and the
    record asserting the opposite of reality (agents-dm8n round 4, findings
    1-2: ``Path.resolve()`` raised ``RuntimeError`` on a loop, and stopped
    silently at an unreadable boundary, so a link whose true target was INSIDE
    the removed tree could be recorded as outside it).

    The work is bounded: at most ``_MAX_SYMLINK_DEPTH + 1`` passes over the
    path, each pass expanding the first symlink component; a link seen twice
    is a loop and ends resolution immediately. No recursion, no unbounded
    traversal.
    """
    seen = set()
    current = os.path.abspath(path)
    for _ in range(_MAX_SYMLINK_DEPTH + 1):
        parts = current.split(os.sep)
        prefix = os.sep
        expanded = False
        for index, part in enumerate(parts):
            if not part:
                continue
            candidate = os.path.join(prefix, part)
            try:
                st = os.lstat(candidate)
            except OSError:
                # A component we cannot even lstat — a permission boundary, or
                # a dangling final component: claim nothing rather than
                # half-resolve. (os.path.islink would SWALLOW the OSError and
                # answer False, which is exactly how the round-3 code turned a
                # permission boundary into an inverted claim.)
                return None
            if not stat.S_ISLNK(st.st_mode):
                prefix = candidate
                continue
            key = os.path.normpath(candidate)
            if key in seen:
                return None  # an explicit loop, named rather than raised
            seen.add(key)
            try:
                target = os.readlink(candidate)
            except OSError:
                return None
            if not os.path.isabs(target):
                target = os.path.join(prefix, target)
            current = os.path.join(target, *parts[index + 1:])
            expanded = True
            break
        if not expanded:
            # Every component is verified non-symlink, so a lexical normpath
            # is exact: no `..` can cross a link.
            return Path(os.path.normpath(current))
    return None  # more links than the bound: claim nothing

# Findings-directory retention (agents-0ti): the per-target evidence files under
# ``findings/`` (delta/latest/summary markdown, append-only history and hillclimb
# ledgers, threat-model documents) accumulate without bound. A byte budget bounds
# the whole directory: when it is exceeded, the oldest regenerable reports are
# pruned first, while the authoritative findings store (``<target>.json`` + its lock)
# and the committed config (``.gitkeep``, ``suppressions.yaml``) are never touched.
FINDINGS_RETENTION_BYTES_DEFAULT = 10 * 1024 * 1024  # 10 MiB
_ENV_FINDINGS_RETENTION_BYTES = "FACTORY_FINDINGS_RETENTION_BYTES"

# Committed or authoritative names inside ``findings/`` that retention must never prune.
_FINDINGS_PROTECTED_NAMES = frozenset({".gitkeep", "suppressions.yaml"})

# Hill-climb proposal retention (agents-0ti): ``runs/hillclimb-*/`` is a proposal
# artifact (live disposable worktree + session.patch), not a run record, so it is
# excluded from the run-directory count/age bound. It still needs a bound: a stale
# proposal (crashed/abandoned) is swept once it is older than this TTL.
HILLCLIMB_RETENTION_AGE_DAYS_DEFAULT = 7
_ENV_HILLCLIMB_RETENTION_AGE_DAYS = "FACTORY_HILLCLIMB_RETENTION_AGE_DAYS"


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


def retention_ledger_path(runs_dir: Path) -> Path:
    """The tombstone ledger for ``runs_dir``: BESIDE the runs root, never inside it.

    The record must outlive the thing it explains (agents-dm8n round 2): inside
    ``runs/`` the ledger survived the automatic prune but not a human clearing the
    run root to reclaim disk — the deletion that actually happens. Beside the root
    it survives both, and beads (which ask the question a tombstone answers)
    outlive the run root.
    """
    return runs_dir.parent / LEDGER_NAME


def _snapshot_files(root: Path) -> set:
    """Relative POSIX paths of every regular file and symlink under ``root``.

    Best-effort: an unreadable subdirectory contributes nothing (os.walk's
    onerror skips it). That is sound for the removal record because the same
    walk produces the pre- and post-removal snapshots — and what the walk cannot
    read, ``rmtree`` cannot remove either (both must read a directory to affect
    its contents), so the recorded loss equals the actual loss in exactly the
    universe either tool can reach. Symlinks are recorded as leaf entries, never
    followed.
    """
    entries = set()
    if not root.is_dir() or root.is_symlink():
        return entries
    for dirpath, dirnames, filenames in os.walk(root):
        base = Path(dirpath)
        for name in filenames:
            entries.add((base / name).relative_to(root).as_posix())
        for name in dirnames:
            if (base / name).is_symlink():
                entries.add((base / name).relative_to(root).as_posix())
    return entries


def _snapshot_symlinks(root: Path) -> dict:
    """Relative POSIX path -> {"target", "outside_tree"} for every symlink under ``root``.

    The record must be honest about what it saw (agents-dm8n round 3, finding
    3; round 4, findings 1-2): os.walk YIELDS a symlink to a directory but
    does not traverse it, so a citation to a file reachable only THROUGH a
    link resolves to nothing in the tombstone while the disappeared==recorded
    equality holds. Recording the link's target — and whether that target
    lived inside the removed tree — lets a reader tell "this evidence is gone"
    from "this evidence moved or was never in this tree".

    ``outside_tree`` is THREE-VALUED: True (resolved outside — NOT removed,
    NOT covered), False (resolved inside — covered by ``files`` under the
    target's real paths), or None — UNRESOLVABLE-AND-THEREFORE-UNCERTAIN: the
    resolution could not complete (a loop, a permission boundary, more links
    than the bound, an unreadable link), so the record claims NEITHER survival
    NOR destruction. A two-valued answer is what forced an unknown into a
    claim in round 3: ``Path.resolve()`` stopped at an unreadable boundary and
    the half-resolved path looked outside the tree, so the ledger claimed the
    evidence survived while rmtree destroyed it. The third value makes that
    inversion unrepresentable. Best-effort like the file snapshot: claim
    nothing the walk could not establish.
    """
    symlinks = {}
    if not root.is_dir() or root.is_symlink():
        return symlinks
    resolved_root = _resolve_bounded(root)
    for dirpath, dirnames, filenames in os.walk(root):
        base = Path(dirpath)
        for name in list(dirnames) + list(filenames):
            entry = base / name
            if not entry.is_symlink():
                continue
            rel = entry.relative_to(root).as_posix()
            try:
                target = os.readlink(entry)
            except OSError:
                symlinks[rel] = {"target": None, "outside_tree": None}
                continue
            resolved = _resolve_bounded(entry)
            if resolved is None or resolved_root is None:
                outside = None
            else:
                outside = (resolved != resolved_root
                           and resolved_root not in resolved.parents)
            symlinks[rel] = {"target": target, "outside_tree": outside}
    return symlinks


def _append_tombstone(ledger: Path, record: dict) -> None:
    """Append one tombstone line to the ledger; a write failure warns, never aborts.

    Retention bounds secret-bearing artifacts, so a full disk must not turn the
    ledger into a reason to keep them — the removal has already happened either
    way, and a warning on stderr beats stranding the bytes.
    """
    try:
        with open(ledger, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    except OSError as exc:
        sys.stderr.write(f"[retention] could not write {ledger}: {exc}\n")


def _ensure_runs_pointer(runs_dir: Path) -> None:
    """Write ``runs/README.md`` (the citation-side discovery pointer) if absent.

    Best-effort and never fatal: the pointer helps a reader standing on a dead
    citation find the ledger; it is not itself the record.
    """
    pointer = runs_dir / RUNS_POINTER_NAME
    try:
        if not pointer.exists():
            pointer.write_text(_RUNS_POINTER_TEXT, encoding="utf-8")
    except OSError as exc:
        sys.stderr.write(f"[retention] could not write {pointer}: {exc}\n")


def remove_recorded(directory: Path, *, reason: str,
                    now: Optional[float] = None) -> bool:
    """Remove ``directory`` (a direct child of a runs root) and record what vanished.

    THE recorded-removal choke point (agents-dm8n round 2): the only sanctioned
    way to delete a citation-bearing directory under the runs root. The record
    follows the behaviour because they are the same code path — and
    tests/test_retention.py's deletion-inventory guard fails the gate if any
    other deletion primitive appears in the shipped source without being
    enumerated there, so a FUTURE deleter cannot bypass this function silently.

    The record is at FILE granularity, in the harm's own terms: the tombstone
    lists exactly the files that disappeared (the pre-removal file set minus the
    post-removal file set), so a bead citation to a FILE inside the directory
    resolves to an explanation. Four outcomes:

    - ``removed``: the directory is gone and rmtree succeeded. Tombstone lists
      everything it held.
    - ``moved``: the directory disappeared because it was moved or renamed externally
      during removal (rmtree failed with ENOENT). The files were not destroyed by
      this pass. Tombstone records ``outcome: "moved"`` with ``files: []`` and
      ``moved_files`` listing the pre-removal snapshot (agents-5qz7).
    - ``partial``: the removal failed part way (e.g. a permission bound) — the
      directory survives but some contents are gone. Tombstone lists exactly the
      lost files with ``outcome: "partial"`` and records any newly appeared files
      (``appeared``), so the loss and within-directory renames are VISIBLE instead of
      silently satisfying a directory-level check (the round-1 defect: the
      directory survived, so "directories removed == directories tombstoned"
      held while the cited file was already destroyed).
    - ``failed``: nothing disappeared or changed. NO tombstone — the record must never
      claim a loss that did not happen.

    Every tombstone states what the record can stand behind and no more: the
    ledger is local state that records only removals made through it (beads
    sync across VMs and containers; the ledger does not), so it names NO
    machine — inside an ephemeral container a hostname is a random ID that
    reads as a stable identity while meaning none (agents-dm8n round 4,
    finding 4). Every tombstone also states its own scope (``record_scope``:
    the file list is best-effort — a file created DURING the removal window is
    destroyed without ever being observed and cannot be listed), and records
    each disappeared symlink with its target
    (``symlinks``), ``outside_tree`` being three-valued: ``true`` = the target
    resolved outside the removed tree (NOT removed, NOT covered), ``false`` =
    resolved inside (covered by ``files`` under the target's real paths),
    ``None`` = unresolvable (a loop, a permission boundary, or too many links)
    — the record then claims NEITHER survival NOR destruction.

    Returns True only when the directory is gone. Refuses symlinks and missing
    directories (warns, returns False): the choke point never follows a link out
    of the runs root and never records a removal of something that was not there.
    """
    now = time.time() if now is None else now
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        sys.stderr.write(f"[retention] refusing to remove {directory}: "
                         "not a real directory\n")
        return False
    before = _snapshot_files(directory)
    before_symlinks = _snapshot_symlinks(directory)
    rmtree_err: Optional[OSError] = None
    try:
        shutil.rmtree(directory)
    except OSError as exc:
        rmtree_err = exc
        sys.stderr.write(f"[retention] could not remove {directory}: {exc}\n")
    if directory.is_dir():
        after = _snapshot_files(directory)
        after_symlinks = _snapshot_symlinks(directory)
    else:
        after, after_symlinks = set(), {}
    disappeared = sorted(before - after)
    appeared = sorted(after - before)
    disappeared_symlinks = [
        {"path": rel, **before_symlinks[rel]}
        for rel in sorted(set(before_symlinks) - set(after_symlinks))
    ]
    moved_files: List[str] = []
    if directory.is_dir():
        outcome = "partial" if (disappeared or appeared) else "failed"
    elif rmtree_err is not None and getattr(rmtree_err, "errno", None) == errno.ENOENT:
        # A directory rename or move during removal (agents-5qz7): rmtree failed
        # with ENOENT and the directory is gone. The ENOENT guarantees that files
        # were moved or renamed externally before removal rather than destroyed
        # by this pass. Over-claiming ignorance by reporting outcome "removed"
        # and listing files as disappeared would be false; record outcome "moved",
        # leave files empty, and preserve moved_files as the pre-removal snapshot.
        outcome = "moved"
        moved_files = disappeared
        disappeared = []
        disappeared_symlinks = []
    else:
        outcome = "removed"
    if outcome == "failed":
        return False
    record = {
        "name": directory.name,
        "path": str(directory),
        "pruned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "reason": reason,
        "outcome": outcome,
        "files": disappeared,
        "appeared": appeared,
        "symlinks": disappeared_symlinks,
        "record_scope": RECORD_SCOPE,
    }
    if outcome == "moved":
        record["moved_files"] = moved_files
    _append_tombstone(retention_ledger_path(directory.parent), record)
    return outcome == "removed"


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

    Every removal goes through ``remove_recorded`` (agents-dm8n): each directory
    actually removed — and each removal that failed PART WAY, losing files but
    leaving the directory — is recorded as a tombstone line in the ledger BESIDE
    the runs root (``retention_ledger_path``), at file granularity, so a citation
    to a pruned run directory (or to a file inside one) resolves to an explanation
    rather than dangling. Only fully removed directories are returned; a partial
    removal is recorded with ``outcome: "partial"`` and retried by a later prune.

    ``now`` is injectable for deterministic TTL tests; it defaults to the current
    wall-clock time. ``retain``, ``max_age_seconds`` and ``active_grace`` default to
    the module's bounded defaults when ``None``.
    """
    now = time.time() if now is None else now
    retain = RETAIN_COUNT_DEFAULT if retain is None else retain
    max_age_seconds = (RETAIN_AGE_DAYS_DEFAULT * _SECONDS_PER_DAY
                       if max_age_seconds is None else max_age_seconds)
    active_grace = ACTIVE_GRACE_SECONDS_DEFAULT if active_grace is None else active_grace

    # The citation-side discovery pointer (agents-dm8n round 2): a reader standing
    # on a dead citation inside runs/ finds the way to the ledger from here.
    if runs_dir.is_dir():
        _ensure_runs_pointer(runs_dir)

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

    # (resolved_path, reason) — the reason (age or count bound) is what a tombstone
    # records so a dead citation resolves to WHY the directory went away.
    pruned: List[Tuple[Path, str]] = []

    # Age bound: any directory older than the TTL is pruned, regardless of count.
    for resolved, mtime, _ in dirs:
        if resolved in exclude_resolved:
            continue
        if max_age_seconds is not None and (now - mtime) > max_age_seconds:
            pruned.append((resolved, "age"))

    pruned_paths = {path for path, _ in pruned}

    # Count bound: of the survivors, keep only the ``retain`` most recent.
    survivors = [r for r, _, _ in dirs
                 if r not in exclude_resolved and r not in pruned_paths]
    if retain is not None and len(survivors) > retain:
        overflow = survivors[: len(survivors) - retain]
        pruned.extend((r, "count") for r in overflow)

    removed: List[Path] = []
    for directory, reason in pruned:
        # The record IS the behaviour (agents-dm8n): remove_recorded deletes and
        # tombstones in one code path, per directory, at the moment of removal —
        # so the explanation cannot drift from the deletion, and a partial removal
        # is recorded at file granularity instead of passing a directory-level check.
        if remove_recorded(directory, reason=reason, now=now):
            removed.append(directory)

    return removed


def findings_retention_config(env: Optional[dict] = None) -> int:
    """Return the findings/ byte budget from the environment.

    Unset or unparseable values fall back to the bounded default (10 MiB). ``env`` is
    injectable for tests; it defaults to ``os.environ``.
    """
    env = os.environ if env is None else env
    budget = FINDINGS_RETENTION_BYTES_DEFAULT
    raw = env.get(_ENV_FINDINGS_RETENTION_BYTES)
    if raw is not None:
        try:
            parsed = int(raw)
            if parsed > 0:
                budget = parsed
        except ValueError:
            pass
    return budget


def _findings_file_is_prunable(name: str) -> bool:
    """True when a ``findings/`` entry is a regenerable report, not the state.

    The authoritative findings store (``<target>.json``) and the machine reports
    (``<target>-line.json``, ``<target>-bundle-baseline.json``) are rewritten in place
    on every run, so they are bounded and must never be pruned; the same goes for the
    store lock (``<target>.json.lock``) and the committed config. The unbounded
    artifacts are the append-only ledgers (``.jsonl``) and the regenerable markdown
    reports (``.md``) — those are pruned oldest-first. An unrecognised extension is
    left alone (fail-safe: under-prune, never touch something we cannot classify).
    """
    if name in _FINDINGS_PROTECTED_NAMES:
        return False
    if name.endswith(".json") or name.endswith(".json.lock"):
        return False
    if name.endswith(".jsonl") or name.endswith(".md"):
        return True
    return False


def prune_findings(findings_dir: Path, *, budget_bytes: Optional[int] = None,
                   exclude: Iterable[Path] = ()) -> List[Path]:
    """Prune the oldest regenerable findings/ reports so the directory stays bounded.

    The budget bounds the *whole* ``findings/`` directory, so protected bytes (the
    authoritative store, its lock and the committed config) count as already-spent and
    are never removed. When the total exceeds ``budget_bytes``, the oldest prunable
    files (by mtime, name as a deterministic tiebreak) are unlinked until the total is
    within budget or no prunable files remain. Symlinks and non-regular files are
    skipped, and a file in ``exclude`` is never removed. Returns the list of removed
    files. ``budget_bytes`` defaults to the module's bounded default when ``None``.
    """
    budget = (FINDINGS_RETENTION_BYTES_DEFAULT if budget_bytes is None else budget_bytes)
    exclude_resolved = {Path(p).resolve() for p in exclude}

    if not findings_dir.is_dir():
        return []

    total = 0
    candidates: List[Tuple[Path, float, int, str]] = []
    for entry in findings_dir.iterdir():
        if entry.is_symlink() or not entry.is_file():
            continue
        try:
            st = entry.stat()
        except OSError as exc:
            sys.stderr.write(f"[retention] skipping {entry}: cannot stat ({exc})\n")
            continue
        total += st.st_size
        resolved = entry.resolve()
        if resolved in exclude_resolved:
            continue
        if _findings_file_is_prunable(entry.name):
            candidates.append((resolved, st.st_mtime, st.st_size, entry.name))

    if total <= budget or not candidates:
        return []

    # Oldest first; the name is only a deterministic tiebreak when two files share an mtime.
    candidates.sort(key=lambda item: (item[1], item[3]))

    removed: List[Path] = []
    for resolved, _mtime, size, _name in candidates:
        if total <= budget:
            break
        try:
            resolved.unlink()
            total -= size
            removed.append(resolved)
        except OSError as exc:
            sys.stderr.write(f"[retention] could not remove {resolved}: {exc}\n")
    return removed


def hillclimb_retention_ttl(env: Optional[dict] = None) -> float:
    """Return the hill-climb proposal TTL in seconds from the environment.

    Unset, unparseable or non-positive values fall back to the bounded default (7 days).
    ``env`` is injectable for tests; it defaults to ``os.environ``.
    """
    env = os.environ if env is None else env
    age_days = HILLCLIMB_RETENTION_AGE_DAYS_DEFAULT
    raw = env.get(_ENV_HILLCLIMB_RETENTION_AGE_DAYS)
    if raw is not None:
        try:
            parsed = int(raw)
            if parsed > 0:
                age_days = parsed
        except ValueError:
            pass
    return age_days * _SECONDS_PER_DAY


def prune_hillclimb_dirs(runs_dir: Path, *, max_age_seconds: Optional[float] = None,
                         now: Optional[float] = None,
                         exclude: Iterable[Path] = ()) -> List[Path]:
    """Sweep stale ``runs/hillclimb-*/`` proposal directories.

    A hill-climb proposal is a live disposable worktree plus session patch, not a run
    record, so it is exempt from the run-directory count/age bound (a concurrent run must
    never sweep a live proposal). It is still bounded: a proposal whose directory is older
    than ``max_age_seconds`` (default 7 days) is a crashed/abandoned leftover and is
    removed. Directories in ``exclude`` and directories carrying a fresh ``.active`` marker
    are never removed; symlinks are skipped. Returns the list of removed directories.
    """
    now = time.time() if now is None else now
    max_age_seconds = (HILLCLIMB_RETENTION_AGE_DAYS_DEFAULT * _SECONDS_PER_DAY
                       if max_age_seconds is None else max_age_seconds)
    exclude_resolved = {Path(p).resolve() for p in exclude}

    if not runs_dir.is_dir():
        return []

    removed: List[Path] = []
    for entry in sorted(runs_dir.iterdir()):
        if not entry.name.startswith(_HILLCLIMB_PREFIX):
            continue
        if entry.is_symlink() or not entry.is_dir():
            continue
        resolved = entry.resolve()
        if resolved in exclude_resolved:
            continue
        if _marker_is_active(entry, now, ACTIVE_GRACE_SECONDS_DEFAULT):
            continue
        try:
            mtime = entry.stat().st_mtime
        except OSError as exc:
            sys.stderr.write(f"[retention] skipping {entry}: cannot stat ({exc})\n")
            continue
        if max_age_seconds is not None and (now - mtime) > max_age_seconds:
            try:
                shutil.rmtree(entry)
                removed.append(resolved)
            except OSError as exc:
                sys.stderr.write(f"[retention] could not remove {entry}: {exc}\n")
    return removed
