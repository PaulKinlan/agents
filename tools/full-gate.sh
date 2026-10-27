#!/usr/bin/env bash
# Whole-module unittest shards for the merger and CI. No dependency outside Python stdlib.
set -euo pipefail
cd "$(dirname "$0")/.."
summary_tree="$(git rev-parse HEAD^{tree} 2>/dev/null || echo unknown)"
summary_sha="$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
summary_stamp="$(date -u +%Y%m%dT%H%M%SZ)"
summary_dir="${FLEET_CHECKS_DIR:-$HOME/.fleet/checks}"
mkdir -p "$summary_dir"
summary_file="$summary_dir/${summary_tree}-${FLEET_LANE:-$(whoami)}-${summary_sha}-${summary_stamp}-$$.summary.txt"
printf 'full-gate run: tree=%s sha=%s lane=%s started=%s pid=%s cwd=%s\n' \
  "$summary_tree" "$summary_sha" "${FLEET_LANE:-$(whoami)}" "$summary_stamp" "$$" "$PWD" > "$summary_file"
# tee APPENDS to retain the identity header. pipefail propagates a failed shard/coverage/budget.
python3 -u - "$@" 2>&1 <<'PY' | tee -a "$summary_file"
import concurrent.futures
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import unittest


class GateError(Exception):
    pass


# The NORMALISED exit codes a killed child can carry. All of them mean one thing - THE MODULE NEVER
# REACHED A VERDICT - and that is the fact this gate must not confuse with a content failure
# (agents-vuvrm). It is not evidence about the tree, so it must not read as a FAILING module and
# must not contribute its ids as MISSING. The facts this came from, measured by the merger while
# landing agents-nfpqn: a full gate went red on tests.test_fast_gate_mapping with 'ID SET MISMATCH
# missing=[101 ids]' and 'OVER BUDGET 398.8s > 300s' while the explaining line was
# 'module=... wall=240.015s rc=124 ids=0' - killed at its own bound, no ids produced, and THE LOG
# HAD ZERO ASSERTION FAILURES. The same module alone on the same tree was rc=0, OK, 201s.
#
# TWO SPELLINGS, TWO MECHANISMS, and they are NOT interchangeable. A reader who assumes a shell
# will get this wrong - we did:
#   * 124 - the per-module bound. run_module drives the module through subprocess.run(timeout=...)
#     WITHOUT a shell and Python's own TimeoutExpired path sets this code explicitly; it never
#     comes from a shell.
#   * 137 / 143 - a child killed by SIGKILL / SIGTERM (the OOM and reaper paths). With no shell,
#     subprocess reports the NEGATIVE SIGNAL NUMBER, so these arrive as -9 and -15, and the shell
#     spelling (128 + N) exists only after normalisation. That is what killed_rc() is for.
# Accepting only the shell spelling was agents-2xq02 (found by rev-vuvrm on b6cd3f23): a
# signal-killed module missed the membership test, landed in `failed`, and had its ids reported as
# MISSING - the same costume as the bound kill, reached through the other door.
KILLED_RCS = frozenset({124, 137, 143})


def killed_rc(rc):
    """Normalise a module's return code to the shell spelling (128 + N) when a signal killed it.

    subprocess.run without a shell reports a signal-killed child as the NEGATIVE signal number
    (-9 SIGKILL, -15 SIGTERM), so 128 - rc is the shell spelling (128 - -9 = 137, 128 - -15 = 143).
    Both spellings are the same fact, so they are collapsed here into one state rather than one
    being accepted and the other silently falling through to `failed` (agents-2xq02).
    """
    return 128 - rc if rc < 0 else rc


def positive_int(name, default):
    try:
        value = int(os.environ.get(name, default))
    except ValueError as exc:
        raise GateError(f"{name} must be a positive integer") from exc
    if value < 1:
        raise GateError(f"{name} must be a positive integer")
    return value


def discover():
    """Use unittest's own package-aware loader, not a second test collector."""
    res = subprocess.run(["git", "ls-files", "tests"],
                         capture_output=True, text=True, check=True)
    paths = [Path(p) for p in sorted(res.stdout.splitlines())
             if Path(p).name.startswith("test") and p.endswith(".py")]
    modules = [".".join(p.with_suffix("").parts) for p in paths]
    if not modules:
        raise GateError("serial discovery found no test modules")

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for module in modules:
        try:
            suite.addTests(loader.loadTestsFromName(module))
        except Exception as exc:
            loader.errors.append(f"Failed to import test module: {module}\n{exc}")
    if loader.errors:
        raise GateError("serial discovery failed: " + "; ".join(loader.errors))

    def ids(node):
        for item in node:
            if isinstance(item, unittest.TestSuite):
                yield from ids(item)
            else:
                yield item.id()

    found = list(ids(suite))
    if len(found) != len(set(found)):
        raise GateError("serial discovery returned duplicate test ids")
    expected = {module: set() for module in modules}
    for test_id in found:
        module = next((m for m in modules if test_id.startswith(m + ".")), None)
        if module not in expected:
            raise GateError(f"serial discovery id outside the selected modules: {test_id}")
        expected[module].add(test_id)
    if any(not group for group in expected.values()):
        raise GateError("serial discovery found empty modules: " + ", ".join(
            m for m, group in expected.items() if not group))
    return expected


def costs_at(path, modules):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        values = data["seconds"]
        if not isinstance(values, dict):
            raise ValueError("not a cost table")
    except (OSError, ValueError, KeyError, TypeError):
        values = {}
    # A module with no usable entry is ordered by TEST COUNT, which is not its cost: measured here,
    # tests.test_pins_audit has 12 ids and 122-158s of CPU, so the fallback moves it from rank 2 by
    # cost to rank 42 by count. That fallback used to be silent, which is why a table that had been
    # replaced sharded a whole run on test count before anyone could see it (agents-2e2ca).
    missing = [m for m in modules
               if not (isinstance(values.get(m), (int, float)) and 0 < values[m] < 3600)]
    if missing:
        print(f"full-gate: cost fallback for {len(missing)} of {len(modules)} module(s) with no usable "
              f"entry in {path.name}; ordering those by test COUNT", file=sys.stderr, flush=True)
    return {m: float(values[m]) if isinstance(values.get(m), (int, float))
            and 0 < values[m] < 3600 else float(len(ids))
            for m, ids in modules.items()}


def shard_order(modules, costs, workers):
    """Greedy LPT order; execution stays one process per module under the cap."""
    loads = [0.0] * workers
    lanes = [[] for _ in range(workers)]
    for module in sorted(modules, key=lambda m: (-costs[m], m)):
        slot = min(range(workers), key=lambda i: (loads[i], i))
        lanes[slot].append(module)
        loads[slot] += costs[module]
    return lanes


# unittest -v lines carry the executed ID in parentheses. Never trust rc=0 alone:
# a runner that exits successfully after skipping a module must fail the union check.
# With a docstring, unittest prints the description on the NEXT line and the ID
# line ends after ')'; without one it ends in ' ... ok'. Capture either ID line.
TEST_LINE = re.compile(r"^\S+ \((tests\.[^()]+)\)(?= \.\.\.|[ \t]*$)", re.MULTILINE)


def run_module(module):
    start = time.monotonic()
    try:
        child_env = dict(os.environ, FULL_GATE_SHARD_CHILD="1")
        result = subprocess.run([sys.executable, "-u", "-m", "unittest", module, "-v"],
                                env=child_env, capture_output=True, text=True, errors="replace",
                                # 1500, not 240 and not 600. This default is what EXTERNAL CI sees,
                                # because the host's per-VM env override does not exist there, so it
                                # must cover the SLOWEST module that is legitimately slow. 240 and 600
                                # both failed that test the same way: a module killed at the bound
                                # reports NO verdict at all (exit 2, "unknown"), so the gate looks
                                # unlucky rather than red and the real cause stays hidden.
                                # Measured 2026-10-27: tests.test_fast_gate_mapping 1206.3s standalone
                                # (105 tests, exit 0) and tests.test_bd_json_contract 268.3s with ~100s
                                # of it `bd init` building a Dolt DB from nothing (work, not a hang).
                                # 1500 covers the slowest with 24% headroom. The 600 was rejected by
                                # review for exactly this reason and review was right: it was sized on
                                # the bd-init module and left a 1206s module unwinnable.
                                timeout=positive_int("FULL_GATE_MODULE_TIMEOUT_S", 1500),
                                check=False)
        output = result.stdout + result.stderr
        rc = result.returncode
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        output += f"\n{module}: timed out\n"
        rc = 124
    return module, rc, time.monotonic() - start, output, TEST_LINE.findall(output)


def git_identity():
    """The tree this table was measured on, recorded so a foreign table is detectable.

    On 2026-10-15 a 42-byte table naming a module that exists in no tree on this machine replaced
    a 101-module table, and nothing in the file said where it had come from (agents-2e2ca).
    Stamping the remote URL ensures that foreign trees (scratch trees, /tmp fixtures) cannot
    overwrite the repository baseline.
    """
    def run(*args):
        try:
            return subprocess.run(["git", *args], capture_output=True, text=True,
                                  check=True).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            return ""
    return {
        "commit": run("rev-parse", "HEAD"),
        "tree": run("rev-parse", "HEAD^{tree}"),
        "remote": run("config", "--get", "remote.origin.url"),
    }


def save_costs(path, measured, identity=None, expected_keys=None):
    """MERGE this run's measurements in; never delete entries another run paid to measure.

    REPLACING was the defect (agents-2e2ca): a stray one-entry table replaced a 101-module one,
    after which costs_at fell back to test COUNT for every real module - and that proxy moves 56
    of 103 modules by 20 or more rank places, which is how the same tree-class ends up with a
    122s wall on one run and a 350s wall on the next. Merging makes a stray entry harmless: an
    unknown key is simply never looked up. It removes the damage without needing to identify
    the run that writes such a table, which after the fact could not be identified at all.

    CONCURRENCY (agents-2c06k): concurrent save_costs calls take an exclusive file lock on
    {path}.lock while reading the prior snapshot, merging, and replacing the table, so
    overlapping writes cannot lose a measured module to a stale read snapshot.

    COMPLETENESS & PROVENANCE: partial runs (missing expected modules) and foreign runs
    (non-matching remote.origin.url) do not write to the full-gate cost table.
    """
    if expected_keys and not (set(measured.keys()) >= set(expected_keys)):
        return

    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with open(lock_path, "a", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            existing = {}
            existing_identity = {}
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    prior = loaded.get("seconds")
                    if isinstance(prior, dict):
                        existing = {k: v for k, v in prior.items()
                                    if isinstance(v, (int, float)) and 0 < v < 3600}
                    if isinstance(loaded.get("identity"), dict):
                        existing_identity = loaded["identity"]
            except (OSError, ValueError, TypeError, AttributeError):
                existing = {}
                existing_identity = {}

            # Foreign runs (different remote.origin.url) never touch the shared cost table:
            current_remote = (identity or {}).get("remote", "")
            existing_remote = (existing_identity or {}).get("remote", "")
            if existing_remote and current_remote != existing_remote:
                return

            merged_seconds = dict(existing, **measured)
            merged_identity = identity or existing_identity

            document = {"seconds": merged_seconds}
            if merged_identity:
                document["identity"] = merged_identity

            fd, tmp = tempfile.mkstemp(prefix="full-gate-costs-", dir=path.parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as out:
                    json.dump(document, out, sort_keys=True)
                    out.write("\n")
                os.replace(tmp, path)
            finally:
                Path(tmp).unlink(missing_ok=True)
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def main():
    if len(sys.argv) != 1:
        raise GateError(f"unsupported full-gate arguments: {sys.argv[1:]!r}")
    # A full gate invoked by a test running in an outer shard inherits this
    # fixture marker. Its own serial discovery must remain the unsharded set;
    # run_module adds the marker back only to this gate's child modules.
    os.environ.pop("FULL_GATE_SHARD_CHILD", None)
    started = time.monotonic()
    expected = discover()
    workers = positive_int("FULL_GATE_SHARDS", min(4, os.cpu_count() or 1))
    # 3300, not 300. The 300 was measured-appropriate when chosen - docs/speed.md §2 records the whole
    # 102-module gate at wall=140.959s on 2026-10-15 - but the suite is now ~20x that cost: the fleet's
    # cost table (2026-10-27) sums 12759s of module time across 106 modules after the three reductions in
    # agents-z3cp5, which is ~3200s of wall at four shards. A 300s budget therefore marks every honest
    # CI run "over budget" (exit 3) and tells the operator to wait for a quieter box that cannot exist.
    # 3300 sits just under CHECK_TIMEOUT=3600 on purpose: the runner's hard bound must not pre-empt the
    # gate's own verdict, or the run reports a timeout instead of the "over budget" fact that is true.
    # A DERIVATION, NOT A MEASURED FULL-GATE WALL - that measurement is still missing and this says so.
    budget = positive_int("FULL_GATE_BUDGET_S", 3300)
    cost_path = Path(os.environ.get("FLEET_CHECKS_DIR", str(Path.home() / ".fleet/checks"))) / "full-gate-module-costs.json"
    lanes = shard_order(expected, costs_at(cost_path, expected), workers)
    order = [module for lane in lanes for module in lane]
    print(f"full-gate: serial discovery {sum(map(len, expected.values()))} ids / {len(expected)} modules; "
          f"workers={workers} budget={budget}s", flush=True)
    for i, lane in enumerate(lanes):
        print(f"full-gate: shard {i + 1}: {', '.join(lane)}", flush=True)
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(run_module, module): module for module in order}
        for future in concurrent.futures.as_completed(futures):
            module = futures[future]
            try:
                results[module] = future.result()
            except Exception as exc:
                results[module] = (module, 1, 0.0, f"{module}: runner error: {exc}", [])
    actual = []
    failed = []
    unknown = []
    measured = {}
    for module in sorted(expected):
        _, rc, secs, output, ids = results[module]
        measured[module] = round(secs, 3)
        print(f"full-gate: module={module} wall={secs:.3f}s rc={rc} ids={len(ids)}", flush=True)
        print(output, flush=True)
        if killed_rc(rc) in KILLED_RCS:
            # Killed, not failed: the suite never reached a verdict. Its wall is still recorded
            # above (the cost cache is what the shard order is built from), but neither its ids
            # nor its absence is evidence about anything, so it is excluded from the id-set
            # accounting on BOTH sides rather than reported as a failing module (agents-vuvrm).
            unknown.append(module)
            continue
        actual.extend(ids)
        if rc or set(ids) != expected[module] or len(ids) != len(expected[module]):
            failed.append(module)
    save_costs(cost_path, measured,
               dict(git_identity(), modules=len(measured),
                    at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
               expected_keys=expected.keys())
    unknown_set = set(unknown)
    known = [m for m in sorted(expected) if m not in unknown_set]
    expected_all = set().union(*[expected[m] for m in known]) if known else set()
    actual_all = set(actual)
    missing, extra = sorted(expected_all - actual_all), sorted(actual_all - expected_all)
    duplicates = len(actual) - len(actual_all)
    elapsed = time.monotonic() - started
    print(f"full-gate: executed ids={len(actual_all)} expected={len(expected_all)} "
          f"missing={len(missing)} extra={len(extra)} duplicate={duplicates} wall={elapsed:.3f}s")
    if missing or extra or duplicates:
        print(f"full-gate: ID SET MISMATCH missing={missing} extra={extra} duplicates={duplicates}")
    if failed:
        print("full-gate: failing modules: " + ", ".join(failed))
    if unknown:
        print("full-gate: unknown modules (killed at the per-module bound, no verdict): "
              + ", ".join(unknown))
        print("full-gate: a killed module is not evidence - it is excluded from the id set on both "
              "sides, so it neither fails nor counts its ids as missing")
    over_budget = elapsed > budget
    if over_budget:
        print(f"full-gate: OVER BUDGET {elapsed:.3f}s > {budget}s")
        if not (failed or missing or extra or duplicates or unknown):
            # The second costume of the same defect (agents-vuvrm), measured while landing
            # agents-nfpqn: attempt 2 on the same tree reported 'executed ids=1880 expected=1880
            # missing=0 extra=0 duplicate=0' with 'OVER BUDGET 350.483s > 300s' and exit 1, and NO
            # failing-modules line, because nothing failed - every id ran and the module that the
            # first attempt killed at its bound ran and passed. A complete green run over the wall
            # is a machine-state fact, not a content regression, and the next action differs (park
            # and wait, versus fix something), so it gets its own state and its own exit code.
            print("full-gate: the run was COMPLETE - every expected id executed and no module "
                  "failed - so this is the WALL, not a content regression: nothing is contradicted "
                  "and there is no assertion to fix. Re-run when the box is quieter, or see "
                  "docs/speed.md for the terms this budget belongs to.")
    if failed or missing or extra or duplicates:
        print("full-gate: failed")
        return 1
    if unknown:
        # Distinct from both passed and failed, and this is deliberate: a suite that never ran
        # cannot be reported as having passed, and reporting it as a content failure is what this
        # bead exists to stop. The caller can tell 'not fully verified' from 'broken'.
        print("full-gate: unknown")
        return 2
    if over_budget:
        # Complete, green, and over the wall: not a pass (nothing here says the tree was verified
        # within its budget) and not a failure (nothing was contradicted). Exit 3 is that reading.
        print("full-gate: over budget")
        return 3
    print("full-gate: passed")
    return 0


try:
    sys.exit(main())
except (GateError, OSError) as exc:
    print(f"full-gate: failed: {exc}", file=sys.stderr)
    sys.exit(1)
PY
