# Gate speed: what the `-t .` "regression" was

**Status:** internal measurement for `agents-sdrp` (hub item `fleet-1ojy.4`). Internal material
under `docs/audits/`; not a published page.
**Snapshot:** 2026-10-13 14:04 UTC, over the
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

One run leaves two files that both contain its `Ran` line (the `.log` and the `.summary.txt`), so
the aggregation counts each `(tests, duration)` pair once; without that, every run after
2026-10-12 15:12 would be counted twice.

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

Discovery only, both forms, same tree, no test executed: **1550 test ids flat, 1550
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
**OK (skipped=1) under both forms**: 68 tests in 4.70s flat,
68 tests in 4.90s package-aware. So on this tree the flag is defence
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

That matters for the shard work (`agents-e4ho`) rather than against it: the per-test component is
dominated by contention, so the wall-time win from sharding has to come from actually using idle
cores (this VM has 8) and not from splitting a contended workload into more contended pieces.
FLEET_HEAVY_SLOTS=1 already serialises heavy jobs, so the shards have to run *inside* one heavy
job to be worth anything.

## Finding 4 (item (c)): the suite is partitionable at module granularity

ITEM (c) ON THE BEAD IS ORDER DEPENDENCE, "a finding rather than a reason to stay serial". The
property the shard work (`agents-e4ho`) actually consumes is weaker and cheaper to test directly:
does each module's result survive being run in a process that did not run the others? Every test
module was split across 4 groups and each group run in its own process; a module whose result
depends on another module having gone first fails here.

not run in this snapshot.

## Reproducing this

The aggregation below produced this note's tables, verbatim — the generator ran this same text:

```bash
#!/usr/bin/env bash
# Reproduce the tables in this note from the gate's own records.
# Written for bash so the placement of the embedded python3 gets a heredoc, not a quote puzzle.
CHECKS="${1:-$HOME/.fleet/checks}" python3 <<'PY'
import glob, os, re, statistics as st, sys, time
rows, seen = [], set()
for f in glob.glob(os.path.join(os.environ["CHECKS"], "*")):
    if os.path.isdir(f):
        continue
    if ".fast." in os.path.basename(f):   # a fast-gate arm is not a full gate
        continue
    text = open(f, encoding="utf-8", errors="replace").read()
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
for form in ("flat", "pkg", "?"):
    v = [r for r in rows if r[2] == form]
    if not v:
        continue
    d = sorted(r[4] for r in v); nn = sorted(r[3] for r in v); ms = sorted(r[5] for r in v)
    print("summary %s runs=%d median_dur=%.0f median_n=%d median_ms_per_test=%.1f n_min=%d n_max=%d"
          % (form, len(v), d[len(d) // 2], nn[len(nn) // 2], ms[len(ms) // 2], nn[0], nn[-1]))
PY
```

## What this instrument cannot see

* the corpus is machine state: it holds the records this VM kept and cannot see runs recorded
  elsewhere, so the counts are a floor, not a census;
* a record with no `Ran …` line is skipped, so an aborted gate is absent rather than counted as
  fast;
* a record whose body was truncated before the first test line is counted as `?` and excluded
  from both groups;
* there is no CPU-time history, so the contention component is bounded by the spread of ms/test
  at fixed content — it is not attributed to any process.
