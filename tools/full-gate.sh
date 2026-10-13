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
    loader = unittest.TestLoader()
    suite = loader.discover("tests", top_level_dir=".")
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
    paths = sorted(Path("tests").rglob("test*.py"))
    modules = [".".join(p.with_suffix("").parts) for p in paths]
    if not modules:
        raise GateError("serial discovery found no test modules")
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
                                timeout=positive_int("FULL_GATE_MODULE_TIMEOUT_S", 240),
                                check=False)
        output = result.stdout + result.stderr
        rc = result.returncode
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        output += f"\n{module}: timed out\n"
        rc = 124
    return module, rc, time.monotonic() - start, output, TEST_LINE.findall(output)


def save_costs(path, measured):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix="full-gate-costs-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump({"seconds": measured}, out, sort_keys=True)
            out.write("\n")
        os.replace(tmp, path)
    finally:
        Path(tmp).unlink(missing_ok=True)


def main():
    if len(sys.argv) != 1:
        raise GateError(f"unsupported full-gate arguments: {sys.argv[1:]!r}")
    started = time.monotonic()
    expected = discover()
    workers = positive_int("FULL_GATE_SHARDS", min(4, os.cpu_count() or 1))
    budget = positive_int("FULL_GATE_BUDGET_S", 300)
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
    measured = {}
    for module in sorted(expected):
        _, rc, secs, output, ids = results[module]
        measured[module] = round(secs, 3)
        actual.extend(ids)
        print(f"full-gate: module={module} wall={secs:.3f}s rc={rc} ids={len(ids)}", flush=True)
        print(output, flush=True)
        if rc or set(ids) != expected[module] or len(ids) != len(expected[module]):
            failed.append(module)
    save_costs(cost_path, measured)
    expected_all = set().union(*expected.values())
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
    if elapsed > budget:
        print(f"full-gate: OVER BUDGET {elapsed:.3f}s > {budget}s")
    if failed or missing or extra or duplicates or elapsed > budget:
        print("full-gate: failed")
        return 1
    print("full-gate: passed")
    return 0


try:
    sys.exit(main())
except (GateError, OSError) as exc:
    print(f"full-gate: failed: {exc}", file=sys.stderr)
    sys.exit(1)
PY
