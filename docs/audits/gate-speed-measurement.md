# Gate speed: what the `-t .` "regression" was

**Status:** internal measurement for `agents-sdrp` (hub item `fleet-1ojy.4`). Internal material
under `docs/audits/`; not a published page.
**Snapshot:** 2026-10-13 15:06 UTC, over the
313 full-gate records this VM then held. Re-run the snippet below for
the current corpus; the medians move with it, the finding does not.

## The answer

The flag cost nothing. The hub read a rise in the gate's median duration as a regression in how the
suite runs; it is the suite getting **bigger**. The arithmetic that settles it is one line: at the
older invocation's own per-test cost (234.4 ms/test), the current median test count
(1525) costs **357s** — the hub's quoted after-median (358s) to within
1s — with the flag contributing nothing to it.

Two measurements below support that directly and independently: the deployment sits inside the
record with no step between the records either side of it, and both forms discover the identical
test set. The flag is nonetheless load-bearing for something else, so it is not a trade to make.

## Method: form is read off each record, not inferred from its date

Every full-gate run leaves a record under `~/.fleet/checks` whose first line names the run
(`full-gate run: tree=… sha=… lane=… started=…`) and whose body is the verbose unittest output
ending in `Ran N tests in D s`. This note reads those files and nothing else.

Package-aware discovery (`-s tests -t .`) imports modules as `tests.<module>`, so a verbose line
reads `test_x (tests.test_y.Class.test_x)`; flat discovery (`-s tests`) imports them top-level and
reads `test_x (test_y.Class.test_x)`. The two spellings never co-occur in one record, so the form
is a reading of the record rather than an assumption about when it ran — and a record with
neither spelling (a killed run whose body stops before the first test line) is reported as `?`,
never assigned the form of its neighbours.

Records written before the run header existed (before 2026-10-12 15:12) carry no stamp; for those
the table shows the file's mtime, which is the run's END, not its start — close enough to order two
records 20 minutes apart, and named here rather than silently blended in.

**The gate this corpus measures, stated because the mechanism changed underneath it:** the deployed
`CHECK_CMD` on this VM is now bash tools/full-gate.sh (SHARDED), last installed 2026-10-13 14:09 UTC. Records whose own body names
the sharded mechanism (`full-gate: shard …`, `workers=…`) are EXCLUDED and counted separately
(8 of them): a sharded gate runs 4 workers in parallel, so its seconds are not comparable
with the serial seconds this note is about, and the serial corpus therefore ends at the switch. The
shard runner's own wall-time figures are the shard work's subject (`agents-e4ho`, `agents-e6lf`,
`agents-s603`), not this note's - what this note contributes to it is Finding 5, the partition
property the split needs, and Finding 7, the queue the split does not remove.

Three selection rules, each earned by reading something that was not a run:

1. **A run record is a run record by its SHAPE**: `<tree>.log` or
   `<tree>-<lane>-<sha>-<stamp>-<pid>.summary.txt`. Beside them sit the verdict cache (`.json`) and
   a `.lock`; the cache EMBEDS the run's log tail, so taking it for a record both double-counts the
   run and reads a nested inner gate's output as the outer gate's - measured as three phantom
   "16 tests in 0.0s" runs before the rule was added.
2. **One run leaves two files** that both contain its `Ran` line (the `.log` and the
   `.summary.txt`), so the aggregation counts each `(tests, duration)` pair once; without that,
   every run after 2026-10-12 15:12 is counted twice.
3. **A sharded record is excluded by the mechanism its own body names**, never by date (see below).

## Finding 1: the two medians are medians of different suites

| form | runs | median duration | median tests | median ms/test | tests range |
|---|---|---|---|---|---|
| flat | 208 | 195s | 689 | 234.4 | 287–1474 |
| pkg | 105 | 408s | 1525 | 270.6 | 1480–1586 |

One population: every full-gate record this VM kept (313 runs),
split by the invocation the record itself shows. The `208` flat records are the suite as
it grew (287 to 1474 tests, median 689 — the hub's "200s" era); the
`105` package-aware records begin at 1480 tests, because the flag landed after
the suite had already grown. The "after" median duration is therefore a median over a suite
**2.2x larger** than the "before" median, and the two durations are not a
comparison of anything.

A duration median cannot separate "the suite got slower" from "the suite got bigger". A count
beside a per-test rate can: 1525 x 234.4 ms = 357s, which is the whole of the
difference and none of the flag.

## Finding 2: the deployment sits inside the record

The deployed `CHECK_CMD` changed from the flat form to `-t .` between the last flat record and the
first package-aware one. These are real runs of the real gate, minutes apart, on this VM, at
near-identical content:

| started (UTC) | form | tests | duration | ms/test |
|---|---|---|---|---|
| 10-11T07:18Z | flat | 1469 | 355.8s | 242.2 |
| 10-11T07:50Z | flat | 1473 | 362.1s | 245.8 |
| 10-11T08:07Z | flat | 1474 | 362.5s | 245.9 |
| 10-11T08:27Z | pkg | 1480 | 354.9s | 239.8 |
| 10-11T08:35Z | pkg | 1482 | 355.9s | 240.1 |
| 10-11T08:46Z | pkg | 1483 | 358.3s | 241.6 |
| 10-11T08:59Z | pkg | 1487 | 368.6s | 247.9 |

Read the lines either side of the switch: 242.2 ms/test flat, then
239.8 ms/test package-aware, with *more* tests and a *shorter* duration. There is no
step here for the flag to hide in.

## Finding 3: the flag does not change which tests run

Discovery only, both forms, same tree, no test executed: **1575 test ids flat, 1575
package-aware**, and the sets are equal once the `tests.` module prefix is stripped. `-t .` is a
module-naming change, not a selection change.

## Why the flag is there, since it is not speed

`tests/__init__.py` establishes the hermetic tool-pin environment for the package: it removes the
operator's `FACTORY_TOOL_PINS` and sets `FACTORY_ALLOW_UNPINNED_TOOLS=1`. Flat discovery never
imports the package, so under flat discovery that declaration does not run *at all* — the suite's
result then depends on what the operator's shell exported. The records here show one flat-era
full-gate failure carrying `ToolPinError` (2 errors, 10-11T01:53), and
`docs/proposals/hermetic-test-environment-declaration.md` §3, which introduced the flag, records the
same failure mode properly; it names the per-gate scrub
(`env -u FACTORY_TOOL_PINS FACTORY_ALLOW_UNPINNED_TOOLS=1`) as the equivalent that does the job at
the gate instead of in the package.

**Measured on the current tree, and reported because it limits the above rather than confirming
it:** the pin-sensitive modules also import `tests.hermetic_env` themselves, so they scrub
independently of discovery. With `FACTORY_TOOL_PINS` exported (`/home/exedev/.config/factory/tools.pins.yaml`),
`tests/test_sandbox.py` — the module the `hermetic_env` docstring names — is
**OK (skipped=1) under both forms**: 68 tests in 3.65s flat,
68 tests in 3.65s package-aware. So on this tree the flag is defence
in depth rather than the only barrier. Either way it costs nothing measurable, so reverting it to
save time is not a trade worth making.

## What is left of the difference, and what that implies for sharding

Two parts, and only one of them is a suite property:

* **the suite grew** — median 689 → 1525 tests, which at the flat era's per-test rate is
  the 357s;
* **per-test cost drifted upward** — 234.4 → 270.6 ms/test — *and that is not a
  property of the suite either*: 11 of the 105 package-aware records run at
  1480-1515 tests for at or within 5% of the flat era's per-test rate, while other records of
  comparable size cost up to 790 ms/test (234–790
  across the corpus). The spread tracks the machine, not the code: the same suite at the same size
  has been measured at both ends within hours.

That matters for the shard runner rather than against it. `tools/full-gate.sh` (`agents-e4ho`)
landed as a module-granular parallel shard runner and the per-VM `CHECK_CMD` was switched to it
(2026-10-13 14:09 UTC, `agents-3mj3` closed), so the serial corpus ends at that switch and this note cannot
price a sharded run: sharded records are excluded by mechanism, above. What this note does say about it is directional and
load-bearing: the per-test spread is dominated by contention, so the win from sharding comes from
actually using idle cores (this VM has 8) and not from splitting a contended workload into more
contended pieces — `FLEET_HEAVY_SLOTS=1` already serialises heavy jobs, so the shards have to run
*inside* one heavy job. Finding 5 above is the safety property that split needs.

## Finding 4 (item (a), confirmation): a paired A/B on one tree

The natural experiment in Finding 2 is real but it is not a controlled pair: the two runs either
side of it are different content. This is the controlled version - one tree (tree 47b588b9b0fe,
the pre-shard tree this branch is based on), seconds apart, the same 114-test subset under both
invocations, interleaved, with the child CPU time beside the wall time (so a wall difference can be
told from a busy machine):

| run | form | tests | wall | child CPU | ms/test | CPU/wall | result |
|---|---|---|---|---|---|---|---|
| 1 | flat | 114 | 60.3s | 22.8s | 529.0 | 0.38 | OK |
| 2 | pkg | 114 | 60.2s | 22.7s | 528.4 | 0.38 | OK |
| 3 | flat | 114 | 60.7s | 23.1s | 532.8 | 0.38 | OK |
| 4 | pkg | 114 | 59.9s | 22.6s | 525.8 | 0.38 | OK |

Wall ms/test: flat 530.9, package-aware 527.1 (-0.7%). Child-CPU ms/test: flat 201.3, package-aware 198.7 (-1.3%). The CPU column is the one that survives a contended machine, and this machine was contended during the pair (child-CPU/wall 0.38-0.38): the flag's cost is the CPU difference, not the wall one.

## Finding 5 (item (c)): the suite is partitionable at module granularity

ITEM (c) ON THE BEAD IS ORDER DEPENDENCE, "a finding rather than a reason to stay serial". The
property the shard work (`agents-e4ho`) actually consumes is weaker and cheaper to test directly:
does each module's result survive being run in a process that did not run the others? Every test
module was split across 4 groups and each group run in its own process; a module whose result
depends on another module having gone first fails here. Run on tree 47b588b9b0fe, this branch's
base and therefore PRE-SHARD: it says the suite CAN be split, not that the landed shard runner is
free of its own review history (`agents-e6lf`, `agents-s603`).

| group | modules | tests | wall | rc | result |
|---|---|---|---|---|---|
| group1 | 23 | 406 | 45.3s | rc=0 | OK |
| group2 | 23 | 370 | 118.6s | rc=0 | OK |
| group3 | 23 | 333 | 120.7s | rc=0 | OK |
| group4 | 22 | 441 | 129.5s | rc=0 | OK |

Group test counts sum to 1550 against a discovery count of 1550 - the partition covers the suite exactly once.

## Finding 6 (item (b)): what an implementer pays per iteration

The bead asks for the fast-gate path FIRST because it is the cost every implementation step pays,
while a full gate is paid once per landing. Fast gate on representative changed paths:

| changed path(s) | modules selected | wall | child CPU | rc | tests run |
|---|---|---|---|---|---|
| lib/tool_pins.py | 6 | 60.4s | 53.0s | 0 | 181 tests |
| lib/findings.py | 13 | 62.0s | 38.6s | 0 | 250 tests |
| tools/fast-gate.sh | 6 | 49.8s | 44.0s | 0 | 109 tests |
| tools/check.conf | 4 | 8.2s | 8.4s | 0 | 52 tests |
| docs/INTEGRATION.md | 5 | 7.5s | 7.7s | 0 | 75 tests |
| tests/test_containment_adapters.py | 5 | 22.7s | 9.8s | 0 | 54 tests |
| lib/tool_pins.py + lib/findings.py + docs/INTEGRATION.md | 19 | 102.9s | 73.9s | 0 | 436 tests |

Median wall across these 7 representative changes on tree 47b588b9b0fe: **49.8s**; slowest 102.9s. The CPU column beside each wall says how much of it is contention rather than work. Compared with Finding 7's corpus median of 12s of suite work, these are the EXPENSIVE arms by construction: a security-sensitive lib module or the gate's own arm table, not a docs-only change (the docs row is 7.5s).

Driven through `bash tools/fast-gate.sh` with `GIT_CHANGED` set to the path, so the arm selection is
the deployed one; the module count in the first column is the dry run's selection, which costs no
test time.

One thing this measurement cost, recorded because it is a trap in the instrument rather than in the
gate: `GIT_CHANGED` is read one path per LINE, as `git diff --name-only` prints it. A
space-separated list of three mapped paths is reported, every one of them, as "match no mapping arm
- add an arm to tools/fast-gate.sh", which is the file most landings already touch. Measured and
filed as `agents-dtml` (P3, fail-closed); the multi-file row above is newline-separated for that
reason.

## Finding 7 (item (b), and the larger number): the iteration cost is the QUEUE

`fastgate` above is what the gate's SELECTED SUITE costs. This is what an implementer actually
waits, from the same corpus - each record carries the split the gate itself measured:

| population | records | median | p75 | max |
|---|---|---|---|---|
| suite work (run_s) | 728 | 12s | 35s | 281s |
| waiting for a heavy slot (wait_s) | 728 | 1s | 226s | 1356s |

Aggregate over all 728 fast-gate records on this VM: 20316s of suite work against 103411s of waiting, so **84% of every iteration second is spent waiting for a heavy slot**, not running tests. It is bimodal rather than uniform - 49% of iterations waited 0s (median suite work 12s), while the 41% that waited 60s or more spent a median of 289s waiting for a median 11s of work.

The consequence is a design statement, not a test-suite one: shrinking the selected suite further cannot recover those seconds - the work is already ~12s median - so the iteration cost an implementer pays is the QUEUE, and the lever is how fast checks are scheduled against the heavy slot (this VM runs one, `FLEET_HEAVY_SLOTS=1`, and a full gate holds it for 400-500s).

## Reproducing this

Findings 1-3 come from one aggregation over the gate's own records; it is published verbatim below,
and the generator that wrote this note ran this same text to build those tables:

```bash
#!/usr/bin/env bash
# Reproduce the tables in this note from the gate's own records.
# Written for bash so the placement of the embedded python3 gets a heredoc, not a quote puzzle.
CHECKS="${1:-$HOME/.fleet/checks}" python3 <<'PY'
import glob, os, re, statistics as st, sys, time
rows, seen = [], set()
sharded = 0
for f in glob.glob(os.path.join(os.environ["CHECKS"], "*")):
    if os.path.isdir(f):
        continue
    base = os.path.basename(f)
    if ".fast." in base:                  # a fast-gate arm is not a full gate
        continue
    # A full-gate RUN leaves a .log (the fleet-check log) and, since agents-qtnv, a
    # <tree>-<lane>-<sha>-<stamp>-<pid>.summary.txt. A .json is the VERDICT CACHE and a .lock is
    # not a run at all - and the cache EMBEDS the log tail, so reading it as a record double-counts
    # a run and reads inner nested-gate output as if it were this gate's.
    if not (base.endswith(".log") or base.endswith(".summary.txt")):
        continue
    text = open(f, encoding="utf-8", errors="replace").read()
    # A SHARDED full gate is a different mechanism (4 workers), not a different invocation form:
    # reading its aggregate as a serial run would compare 4-way-parallel seconds with serial ones.
    # Its own body names the mechanism, so it is excluded by that marker and counted separately.
    if "full-gate: shard " in text or "workers=" in text:
        sharded += 1
        continue
    m = re.search(r"Ran (\d+) tests in ([\d.]+)s", text)
    if not m:
        continue
    n, dur = int(m.group(1)), float(m.group(2))
    if (n, dur) in seen:            # the .log and the .summary.txt of ONE run
        continue
    seen.add((n, dur))
    pkg = len(re.findall(r"^test\S* \(tests\.test_[\w]+", text, re.M))
    flat = len(re.findall(r"^test\S* \(test_[\w]+", text, re.M))
    form = "pkg" if pkg > 5 and flat == 0 else "flat" if flat > 5 and pkg == 0 else "?"
    head = re.search(r"^full-gate run: .*started=(\S+)", text, re.M)
    mtime = os.path.getmtime(f)
    # Records written before the run header existed carry no stamp; their mtime is their END.
    stamp = head.group(1) if head else "mtime:" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(mtime))
    rows.append((mtime, stamp, form, n, dur, dur / n * 1000))
rows.sort()
for whole, stamp, form, n, dur, ms in rows:
    print("run %s %s %d %.1f %.1f" % (stamp, form, n, dur, ms))
print("sharded %d" % sharded)
for form in ("flat", "pkg", "?"):
    v = [r for r in rows if r[2] == form]
    if not v:
        continue
    d = sorted(r[4] for r in v); nn = sorted(r[3] for r in v); ms = sorted(r[5] for r in v)
    print("summary %s runs=%d median_dur=%.0f median_n=%d median_ms_per_test=%.1f n_min=%d n_max=%d"
          % (form, len(v), d[len(d) // 2], nn[len(nn) // 2], ms[len(ms) // 2], nn[0], nn[-1]))
PY
```

Finding 7's headline (the wait/run split) is the same corpus read a different way, so it gets its own
snippet rather than a claim:

```bash
#!/usr/bin/env bash
# Finding 7: where an implementer's iteration seconds go, from the split the gate itself records.
python3 <<'PY'
import glob, json, os, statistics as st
recs = []
for f in glob.glob(os.path.expanduser("~/.fleet/checks/*.fast.json")):
    try:
        d = json.load(open(f, encoding="utf-8"))
    except Exception:
        continue
    if isinstance(d, dict) and "run_s" in d and "wait_s" in d:
        recs.append(d)
run = sum(r["run_s"] for r in recs); wait = sum(r["wait_s"] for r in recs)
zero = sum(1 for r in recs if r["wait_s"] == 0)
long = [r for r in recs if r["wait_s"] >= 60]
print("records=%d run=%ds wait=%ds wait_share=%.0f%% zero_wait=%d long_wait=%d"
      % (len(recs), run, wait, 100.0 * wait / (run + wait), zero, len(long)))
print("median run=%ds median wait=%ds | long-waiters: median wait=%ds behind median run=%ds"
      % (st.median([r["run_s"] for r in recs]), st.median([r["wait_s"] for r in recs]),
         st.median([r["wait_s"] for r in long]), st.median([r["run_s"] for r in long])))
PY
```

Findings 4, 5 and 6 are NOT reproducible from a snippet, and saying otherwise would be the defect this
note is about: they are the results of probes run once, and their raw per-step outputs are kept with
the corpus as machine state rather than in the repo:

| Finding | raw output | what it holds |
|---|---|---|
| 4 (paired A/B) | `/tmp/impl-tdot-measure2/ab-[0-3]-*.json` | per-run wall, child CPU, test count, result, tree |
| 5 (partition) | `/tmp/impl-tdot-measure2/group[1-4].json`, `summary.txt` | per-group counts, wall, CPU, rc, result; and the `partition_covers_suite` verdict |
| 6 (fast gate) | `/tmp/impl-tdot-fastgate/cases.json` | per-case selection, wall, CPU, rc, ran-line |

Each Finding names the command and inputs that produced it, so the three probes are rerunnable; and the
coverage verdict in Finding 5 is the probe's OWN check, so the table is not read as green unless the
group counts sum to the discovery count.

## What this instrument cannot see

* the corpus is machine state: it holds the records this VM kept and cannot see runs recorded
  elsewhere, so the counts are a floor, not a census;
* a record with no `Ran …` line is skipped, so an aborted gate is absent rather than counted as
  fast;
* a record whose body was truncated before the first test line is counted as `?` and excluded
  from both groups;
* there is no CPU-time history, so the contention component is bounded by the spread of ms/test
  at fixed content — it is not attributed to any process.
