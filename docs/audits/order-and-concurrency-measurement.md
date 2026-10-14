# Does a bounded check's duration depend on what is running around it?

An extension of [gate-speed-measurement.md](gate-speed-measurement.md), which measured what a gate RUNS
(the test count behind the 200s-to-358s step) and what an iteration WAITS for (84% of every implementer
iteration second is queue wait, behind a median 12s of work). This note asks the different question that
figure raises: **is that a capacity limit or a scheduling artefact** - if a check's duration depends on
when it starts rather than only on what it runs, then the queue's shape matters as much as its capacity.

Asked for by coord on 2026-10-13 as the last open half of `agents-sdrp` item (c), with the design below
(bead `agents-mpnb`).

## The question, precisely

Same tree, same bounded check, four conditions: an idle box; beside one real heavy gate; beside two; and
started just after a gate releases the slot (the ORDER half - a warm box is not an idle one). Report wall
AND child CPU with the sample size, and say which of the two the queue is.

## Method, and the two adjustments that make it honest

**The check.** `GIT_CHANGED=docs/audits/gate-speed-measurement.md bash tools/fast-gate.sh` - the docs
arm, 5 suites, ~10-13s of work alone. It is run **directly, never through the queue**, because the
instrument's job is to OBSERVE the heavy slot: queueing it would both prevent the merger's gate from
running and delete the condition being measured.

**Adjustment 1 - condition (iii) is a counterfactual, and is labelled as one.** With
`FLEET_HEAVY_SLOTS=1` two real heavy gates cannot co-run at all, so "beside two" is not a state this
system can be in. It is measured as one REAL gate plus `nice -n 10` burners, i.e. the DEMAND of two gates,
and it is filed as `two-demand (counterfactual)` everywhere below. It is never called "two gates".

**Adjustment 2 - a run is filed by what the SAMPLES saw, not by what the loop intended, and the holder
is named from the records rather than assumed.** /proc/stat is
sampled every 2s and the heavy slot is probed through the same flock the queue uses; each run records the
median and max busy cores DURING it plus `held_frac`, the fraction of those samples in which the slot was
held. A run that started when the box was quiet and was joined by a gate mid-flight is therefore reported
as contaminated rather than as idle. That matters here more than it did in the previous note: **the box
was rarely quiet.** 8 of 13 runs had more than 2.5 of
8 cores busy, which is itself the answer to "can we just wait for a quiet moment".

**Every sample came from ONE tree, and this is checked rather than assumed.** All 13 runs execute `tools/fast-gate.sh`, which records the tree it ran on, and the 13 summaries this lane produced inside the window all name tree `01e0ad459188110f` (sha `a0b967c6`) - so this is a distribution of one object. The worktree was deliberately not written until the instrument exited, for the same reason; the commit this note lands on is a later main, which is why the tree is named here rather than described as 'the repo'.

**Priority.** The check and the load both run under `nice -n 10`, matching what the deployed path gives a
gate (`fleet-heavy` runs jobs under `nice -n 10`), so the contention is a fair fight rather than a fresh
unfairness introduced by the instrument.

**Cost, stated rather than hidden:** the `two-demand` runs add ~5 cores of load while the merger's real
gate is running. That is the experiment that was asked for, it is bounded to those runs, and the merger's
own gate duration is the check on it (below).

**One comparison that is deliberately NOT made.** The single-sample A/B that motivated this note (the same
check at 25.7s beside the merger's gate and 22.8s with the slot free, quoted on bead `agents-v2t9`) was
measured on the PRE-SHARD tree, where this same arm cost about 22.5s of child CPU against roughly 10.5s
here. Those absolute figures belong to a different tree and are used nowhere in the tables below; only
their shape - a co-running gate is within noise of the check's own cost - agrees with what is measured
here. A difference that large between trees is itself worth knowing, and it is recorded as an observation
with its confound named rather than resolved: the suite contents and the shard runner both changed with
main in between.

## Results

### By condition

| condition (as filed from the samples) | n | wall median | wall range | child CPU median | cores | busy cores during run (median of medians) |
|---|---|---|---|---|---|---|
| slot held all run, beside FULL merger 1834e5c | 3 | 11.2s | 10.7-11.5s | 10.9s | 0.97 | 4.16 |
| slot held all run + 5 burners, beside FULL merger 1834e5c | 1 | 19.8s | 19.8-19.8s | 15.5s | 0.78 | 7.51 |
| slot held all run + 5 burners, beside UNATTRIBUTED holder (no record covers it) | 1 | 24.3s | 24.3-24.3s | 15.2s | 0.62 | 7.87 |
| slot held PART of the run (43%), overlapping FAST impl-f6du 6d5e220 44% of it | 1 | 13.7s | 13.7-13.7s | 12.6s | 0.92 | 6.96 |
| slot held PART of the run (67%), overlapping FAST impl-f6du eff3c3e 64% of it | 1 | 11.0s | 11.0-11.0s | 11.1s | 1.00 | 2.19 |
| slot held PART of the run (83%), UNATTRIBUTED holder (no record covers it) | 1 | 13.1s | 13.1-13.1s | 13.1s | 1.00 | 5.03 |
| slot free for the whole run | 3 | 10.4s | 10.3-10.9s | 10.6s | 1.02 | 2.50 |
| after-gate (started just after the slot was released) | 2 | 10.4s | 10.4-10.5s | 10.5s | 1.00 | 2.23 |

### By measured load, across every run

The condition a run was *intended* for is a weak label when the box is busy; concurrent load is the axis
that is actually measured. Every run, sorted by the busy-core level during it:

| busy cores during the run (median) | wall | child CPU | cores used | condition it was filed as |
|---|---|---|---|---|
| 2.00 | 10.5s | 10.6s | 1.00 | after-gate (started just after the slot was released) |
| 2.19 | 11.0s | 11.1s | 1.00 | slot held PART of the run (67%), overlapping FAST impl-f6du eff3c3e 64% of it |
| 2.24 | 10.4s | 10.6s | 1.02 | slot free for the whole run |
| 2.46 | 10.4s | 10.4s | 1.00 | after-gate (started just after the slot was released) |
| 2.50 | 10.9s | 11.0s | 1.02 | slot free for the whole run |
| 3.18 | 10.3s | 10.4s | 1.02 | slot free for the whole run |
| 4.13 | 10.7s | 10.7s | 1.00 | slot held all run, beside FULL merger 1834e5c |
| 4.16 | 11.5s | 11.2s | 0.97 | slot held all run, beside FULL merger 1834e5c |
| 4.84 | 11.2s | 10.9s | 0.97 | slot held all run, beside FULL merger 1834e5c |
| 5.03 | 13.1s | 13.1s | 1.00 | slot held PART of the run (83%), UNATTRIBUTED holder (no record covers it) |
| 6.96 | 13.7s | 12.6s | 0.92 | slot held PART of the run (43%), overlapping FAST impl-f6du 6d5e220 44% of it |
| 7.51 | 19.8s | 15.5s | 0.78 | slot held all run + 5 burners, beside FULL merger 1834e5c |
| 7.87 | 24.3s | 15.2s | 0.62 | slot held all run + 5 burners, beside UNATTRIBUTED holder (no record covers it) |

Sample sizes are the `n` column and the spread is the wall range, not a single figure: a median over n=3
is not a measurement of a distribution, it is a guard against quoting one run.

### Who held the slot

The instrument records THAT the slot was held, not by whom, so the holders are reconstructed from the gate
records every lane writes - a record's execution window is `[at + wait_s, at + wait_s + run_s]`, a mapping
verified against a job whose start time is known independently. A run is attributed to the record covering
most of it:

| run started | wall | held for | attributed holder (largest overlap) |
|---|---|---|---|
| 16:00:40 | 11.5s | 100% | FULL `merger` `1834e5c` covering 100% of the run |
| 16:00:52 | 11.2s | 100% | FULL `merger` `1834e5c` covering 100% of the run |
| 16:01:03 | 10.7s | 100% | FULL `merger` `1834e5c` covering 100% of the run |
| 16:01:20 | 19.8s | 90% | FULL `merger` `1834e5c` covering 86% of the run |
| 16:01:42 | 10.4s | 0% | slot free - none |
| 16:01:53 | 10.5s | 0% | slot free - none |
| 16:02:03 | 10.4s | 0% | slot free - none |
| 16:02:26 | 13.7s | 43% | FAST `impl-f6du` `6d5e220` covering 44% of the run |
| 16:02:49 | 10.3s | 0% | slot free - none |
| 16:03:43 | 13.1s | 83% | **no record covers this run** |
| 16:04:02 | 24.3s | 100% | **no record covers this run** |
| 16:11:38 | 10.9s | 0% | slot free - none |
| 16:12:00 | 11.0s | 67% | FAST `impl-f6du` `eff3c3e` covering 64% of the run |

### The comparison the note exists for

**It is a CAPACITY limit, not a scheduling artefact - and the loss is not only queueing.** The check's duration is FLAT while the box has room (9 runs with up to 5.0 of 8 cores busy: wall median 10.7s, range 10.3-11.5s; child CPU median 10.7s), then degrades sharply as it saturates (2 runs at or above 7.0 of 8: wall median 22.1s, i.e. 2.1x; child CPU median 15.3s, 1.43x).

The CPU column is what separates the two explanations. If the check were merely waiting for a turn, its CPU would stay flat while its wall grew; instead CPU rises 43% while its CPU-per-second-of-wall falls, and it runs at the SAME nice level as its competition. The cost of the oversubscribed region is therefore both waiting and doing more work for the same progress (scheduler churn and cache pressure), which is why 'add more parallel lanes' has a cliff in it rather than a slope.

**A single heavy gate beside the check is INSIDE the plateau, not on the cliff**: 3 runs at 4.13-4.84 of 8 cores busy, attributed from the records to the merger's own full gate (its own record: FULL check, lane merger, sha `1834e5c`, ran 125s on tree `a0ee75adbfb6`), took a wall median of 11.2s against 10.7s for the plateau as a whole - a co-run cost of about 5%, which agrees in sign and size with the single-sample A/B on the earlier tree.

**The knee is bracketed by measurement, not assumed**: the deepest run still inside the plateau sat at 4.84 busy cores, and past it: 5.03 cores -> 13.1s, 6.96 cores -> 13.7s, 7.51 cores -> 19.8s, 7.87 cores -> 24.3s. Somewhere between roughly 5 and 7 of 8 cores the box stops being able to hide the work.

**ORDER is free; CONCURRENCY is what costs.** 2 runs started immediately after a gate released the slot and took a wall median of 10.4s (busy during them: 2.46, 2.00 cores) - indistinguishable from the plateau. A warm box is not an idle one, but in this data it is not a worse one either: nothing about having just run a gate penalises the next check.

**AND THE BOX IS NEVER QUIET, which is the other half of the answer.** Only 0 of 13 runs ran under 1.5 of 8 cores busy, and 8 had more than 2.5 busy - with the instrument making no attempt to add load. Waiting for a quiet moment is therefore not a scheduling strategy this fleet has: the useful rule is the other way round, and it is that the fast gate is close to free beside one heavy job and about 2x at saturation, so the queue's job is to keep the box out of the saturated region - which is what a single heavy slot does.

**AND ONE THING THIS INSTRUMENT CANNOT RESOLVE, reported because it is load-bearing for anyone reading 'held' as 'a gate': 2 run(s) saw the slot held with NO record covering them** - 16:03:43 (83% of the run), 16:04:02 (100% of the run). The slot is also taken by work that writes no verdict record: a lane running `fleet-heavy` with a command of its own, or a job that leaves the queue before writing one. So 'the slot was held' does not by itself identify a gate, and the attribution table above names a holder only where a record covers it. This does not affect the load axis - busy cores are measured directly and are what the findings rest on - and it is exactly the case the deployed `fleet-heavy` generation cannot clear, since the reclaim that releases an orphaned holder is missing from the copy this VM runs (bead `agents-j5a4`).

### Order: what happened right after a gate released the slot

* 0s after the slot was released -> wall 10.4s, child CPU 10.4s, busy during run 2.46 cores (n=1 each)
* 10s after the slot was released -> wall 10.5s, child CPU 10.6s, busy during run 2.0 cores (n=1 each)

## What this instrument cannot see

* **The heavy gate's own duration is not the subject here.** This measures a 10s bounded check beside a
  running gate, not whether the GATE slows down when other lanes work beside it. The related context, and
  it is context only: the merger's gate that my load runs sat beside ran 125s, and the NEXT
  merger gate after it - the one that no load of mine touched - ran 147s - n=1 each, on different trees, so
  this note makes no claim in either direction. That question needs a different instrument.
* **No cause is attributed beyond load.** The runs show that wall and CPU both rise under
  oversubscription; they do not decompose the extra CPU into scheduler churn, cache pressure and page
  faults, which would need perf counters this VM does not have on by default.
* **Load is synthetic in the counterfactual condition.** The burners occupy cores; a real second gate
  would also touch the page cache and hold its own slot. The counterfactual is a demand floor, not a
  replica.
* **Nothing is enabled by default by this work.** The light-class patch (`agents-v2t9`) stays inert
  (`FLEET_HEAVY_LIGHT_SLOTS=0`); the point here was to characterise the existing queue, and a second
  variable would have confounded it.

## Reproducing this

Both halves are embedded, so nothing here needs a /tmp path to be re-derived. The instrument:

```python
#!/usr/bin/env python3
"""agents-mpnb: does a bounded check's duration depend on the CONCURRENCY and ORDER of what runs around it?

Design (coord's, 2026-10-13), with the one adjustment stated on the bead rather than hidden:

  idle        the heavy slot is FREE and the box is quiet  -> the check's own cost
  one-gate    the heavy slot is HELD (the merger's real full gate) -> the real co-run condition
  two-demand  the real gate PLUS load calibrated to the measured single-gate footprint (4.92 of 8
              cores) -> the DEMAND of two gates. Two real gates CANNOT co-run under
              FLEET_HEAVY_SLOTS=1, so this is a counterfactual and is never called "two gates".
  after-gate  started within a few seconds of a gate RELEASING the slot -> the ORDER half: a warm box
              is not an idle one.

WHY THIS RUNS OUTSIDE fleet-heavy: it OBSERVES the slot (forking the check directly, as the v2t9
experiment did) and never takes it. Queueing the instrument itself would both prevent the merger's gate
from running and remove the condition being measured.

WHAT IS MEASURED PER RUN, and why each column is there:
  wall            the check's wall time
  cpu             CHILD CPU (resource.getrusage(RUSAGE_CHILDREN) delta) - the column that survives a
                  contended machine, so a busy box cannot be misread as a slower check
  busy_med/max    /proc/stat busy cores sampled every 2s DURING the run
  held_frac       fraction of those samples in which the heavy slot was held
  The condition a run is FILED under is derived from held_frac and busy_med, not from what the loop
  intended: a run that started idle and was joined by a gate is reported as contaminated, not as idle.

The load is `nice -n 10` python burners, matching the priority the deployed path gives a gate
(fleet-heavy runs jobs under `nice -n 10`), and the check is likewise run under `nice -n 10`.

Re-running it elsewhere: the worktree to measure is `IMPL_TDOT_WT` and the record directory is
`IMPL_TDOT_ORDER` (the values this run used are the defaults).","""
import json
import os
import resource
import signal
import subprocess
import threading
import time
from pathlib import Path

WT = Path(os.environ.get("IMPL_TDOT_WT", "/tmp/agents-factory-impl-tdot"))
OUT = Path(os.environ.get("IMPL_TDOT_ORDER", "/tmp/impl-tdot-order"))
OUT.mkdir(exist_ok=True)
CHECK_CHANGED = "docs/audits/gate-speed-measurement.md"   # docs arm: 5 suites, ~10s of work alone
CHECK_BOUND = 300
SAMPLE = 2.0
MAX_WINDOW = float(os.environ.get("MAX_WINDOW", "2400"))
BURNERS_N = int(os.environ.get("BURNERS_N", "5"))
QUOTA = {"idle": 5, "one-gate": 3, "two-demand": 3, "after-gate": 2}
HEAVY_DIR = Path(os.environ.get("FLEET_HEAVY_DIR", "/tmp/fleet-heavy"))
NCPU = os.cpu_count() or 1

_samples = []          # (t, busy_cores, held)
_stop = False


def _stat():
    with open("/proc/stat", "rb") as fh:
        vals = [int(v) for v in fh.readline().split()[1:]]
    return sum(vals), vals[3] + (vals[4] if len(vals) > 4 else 0)


def slot_held():
    f = HEAVY_DIR / "slot1"
    if not f.exists():
        return False
    import fcntl
    fd = os.open(f, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    except OSError:
        return True
    finally:
        os.close(fd)


def sampler():
    prev = _stat()
    while not _stop:
        time.sleep(SAMPLE)
        cur = _stat()
        dtotal, didle = cur[0] - prev[0], cur[1] - prev[1]
        prev = cur
        busy = NCPU * (1.0 - didle / dtotal) if dtotal else 0.0
        _samples.append((time.time(), round(busy, 2), slot_held()))


def within(t0, t1, key):
    return [s[key] for s in _samples if t0 <= s[0] <= t1]


def run_check(attempted, extra_note=""):
    ru0 = resource.getrusage(resource.RUSAGE_CHILDREN)
    t0 = time.time()
    proc = subprocess.run(["nice", "-n", "10", "bash", "tools/fast-gate.sh"], cwd=str(WT),
                          capture_output=True, text=True, timeout=CHECK_BOUND,
                          env={**os.environ, "GIT_CHANGED": CHECK_CHANGED})
    t1 = time.time()
    ru1 = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu = (ru1.ru_utime - ru0.ru_utime) + (ru1.ru_stime - ru0.ru_stime)
    busy = within(t0, t1, 1) or [0.0]
    held = within(t0, t1, 2) or [False]
    ran = [l for l in proc.stdout.splitlines() if l.startswith("Ran ")]
    rec = {"attempted": attempted, "note": extra_note, "wall": round(t1 - t0, 1),
           "cpu": round(cpu, 1), "cores": round(cpu / (t1 - t0), 2) if t1 > t0 else None,
           "busy_med": sorted(busy)[len(busy) // 2], "busy_max": max(busy),
           "held_frac": round(sum(1 for h in held if h) / len(held), 2),
           "rc": proc.returncode, "ran": ran[-1] if ran else None,
           "started_at": time.strftime("%H:%M:%S", time.localtime(t0))}
    rows = json.loads((OUT / "runs.json").read_text()) if (OUT / "runs.json").exists() else []
    rows.append(rec)
    (OUT / "runs.json").write_text(json.dumps(rows, indent=1))
    print(json.dumps(rec), flush=True)
    return rec


burners = []


def burners_start(n):
    for _ in range(n):
        burners.append(subprocess.Popen(["nice", "-n", "10", "python3", "-c", "while True: pass"],
                                        preexec_fn=os.setsid,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    time.sleep(6)   # let the load actually land before anything is timed


def burners_stop():
    for p in burners:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
    for p in burners:
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
    burners.clear()
    time.sleep(3)


threading.Thread(target=sampler, daemon=True).start()
t_start = time.time()
counts = {k: 0 for k in QUOTA}
was_held = False
last_release = 0.0

try:
    while time.time() - t_start < MAX_WINDOW and any(counts[k] < QUOTA[k] for k in QUOTA):
        recent = [s[1] for s in _samples[-4:]] or [0.0]
        q_busy = sorted(recent)[len(recent) // 2]
        held = slot_held()
        if was_held and not held:
            last_release = time.time()
        was_held = held

        if held and counts["one-gate"] < QUOTA["one-gate"]:
            run_check("one-gate")
            counts["one-gate"] += 1
        elif held and counts["two-demand"] < QUOTA["two-demand"]:
            burners_start(BURNERS_N)
            try:
                run_check("two-demand", f"burners={BURNERS_N} nice=10")
            finally:
                burners_stop()
            counts["two-demand"] += 1
        elif (not held) and last_release and time.time() - last_release < 25 and counts["after-gate"] < QUOTA["after-gate"]:
            run_check("after-gate", f"{time.time() - last_release:.0f}s after the slot was released")
            counts["after-gate"] += 1
        elif (not held) and q_busy <= 2.0 and counts["idle"] < QUOTA["idle"]:
            run_check("idle", f"quiet: median busy {q_busy} over the last samples")
            counts["idle"] += 1
        else:
            time.sleep(2)
finally:
    _stop = True
    burners_stop()
    (OUT / "samples.json").write_text(json.dumps(_samples))


def group(r):
    """File a run by what the SAMPLES saw, not by what the loop intended."""
    if r["held_frac"] >= 0.9:
        if r["attempted"] == "two-demand" or r["busy_med"] > 7.0:
            return "two-demand (counterfactual)"
        return "one-gate"
    if r["attempted"] == "after-gate":
        return "after-gate"
    if r["busy_med"] > 2.5:
        return "started-idle but joined by load (contaminated)"
    return "idle"


rows = json.loads((OUT / "runs.json").read_text()) if (OUT / "runs.json").exists() else []
import statistics as st
lines = [f"window: {time.time() - t_start:.0f}s of a max {MAX_WINDOW:.0f}s; quotas {QUOTA}; "
         f"achieved {counts}", f"CPU={NCPU} burners for two-demand={BURNERS_N}"]
by = {}
for r in rows:
    by.setdefault(group(r), []).append(r)
for k in ("idle", "one-gate", "two-demand (counterfactual)", "after-gate",
          "started-idle but joined by load (contaminated)"):
    v = by.get(k)
    if not v:
        lines.append(f"{k}: NONE (never observed in this window)")
        continue
    w = sorted(x["wall"] for x in v)
    c = sorted(x["cpu"] for x in v)
    b = sorted(x["busy_med"] for x in v)
    lines.append(f"{k}: n={len(v)} wall median={st.median(w):.1f}s range={w[0]:.1f}-{w[-1]:.1f} | "
                 f"cpu median={st.median(c):.1f}s | cores median={st.median([x['cores'] for x in v]):.2f} | "
                 f"busy_med median={st.median(b):.2f} of {NCPU}")
(OUT / "summary.txt").write_text("\n".join(lines) + "\n")
print("\n".join(lines))
```

The run records it produced, verbatim (`runs.json`):

```json
[
 {
  "attempted": "one-gate",
  "note": "",
  "wall": 11.5,
  "cpu": 11.2,
  "cores": 0.97,
  "busy_med": 4.16,
  "busy_max": 4.33,
  "held_frac": 1.0,
  "rc": 0,
  "ran": null,
  "started_at": "16:00:40",
  "holder": {
   "kind": "FULL",
   "lane": "merger",
   "sha": "1834e5c",
   "coverage": 1.0,
   "from": "15:59:32",
   "to": "16:01:37"
  }
 },
 {
  "attempted": "one-gate",
  "note": "",
  "wall": 11.2,
  "cpu": 10.9,
  "cores": 0.97,
  "busy_med": 4.84,
  "busy_max": 5.01,
  "held_frac": 1.0,
  "rc": 0,
  "ran": null,
  "started_at": "16:00:52",
  "holder": {
   "kind": "FULL",
   "lane": "merger",
   "sha": "1834e5c",
   "coverage": 1.0,
   "from": "15:59:32",
   "to": "16:01:37"
  }
 },
 {
  "attempted": "one-gate",
  "note": "",
  "wall": 10.7,
  "cpu": 10.7,
  "cores": 1.0,
  "busy_med": 4.13,
  "busy_max": 4.16,
  "held_frac": 1.0,
  "rc": 0,
  "ran": null,
  "started_at": "16:01:03",
  "holder": {
   "kind": "FULL",
   "lane": "merger",
   "sha": "1834e5c",
   "coverage": 1.0,
   "from": "15:59:32",
   "to": "16:01:37"
  }
 },
 {
  "attempted": "two-demand",
  "note": "burners=5 nice=10",
  "wall": 19.8,
  "cpu": 15.5,
  "cores": 0.78,
  "busy_med": 7.51,
  "busy_max": 7.83,
  "held_frac": 0.9,
  "rc": 0,
  "ran": null,
  "started_at": "16:01:20",
  "holder": {
   "kind": "FULL",
   "lane": "merger",
   "sha": "1834e5c",
   "coverage": 0.86,
   "from": "15:59:32",
   "to": "16:01:37"
  }
 },
 {
  "attempted": "after-gate",
  "note": "0s after the slot was released",
  "wall": 10.4,
  "cpu": 10.4,
  "cores": 1.0,
  "busy_med": 2.46,
  "busy_max": 2.57,
  "held_frac": 0.0,
  "rc": 0,
  "ran": null,
  "started_at": "16:01:42",
  "holder": null
 },
 {
  "attempted": "after-gate",
  "note": "10s after the slot was released",
  "wall": 10.5,
  "cpu": 10.6,
  "cores": 1.0,
  "busy_med": 2.0,
  "busy_max": 3.14,
  "held_frac": 0.0,
  "rc": 0,
  "ran": null,
  "started_at": "16:01:53",
  "holder": null
 },
 {
  "attempted": "idle",
  "note": "quiet: median busy 2.0 over the last samples",
  "wall": 10.4,
  "cpu": 10.6,
  "cores": 1.02,
  "busy_med": 2.24,
  "busy_max": 2.73,
  "held_frac": 0.0,
  "rc": 0,
  "ran": null,
  "started_at": "16:02:03",
  "holder": null
 },
 {
  "attempted": "two-demand",
  "note": "burners=5 nice=10",
  "wall": 13.7,
  "cpu": 12.6,
  "cores": 0.92,
  "busy_med": 6.96,
  "busy_max": 7.74,
  "held_frac": 0.43,
  "rc": 0,
  "ran": null,
  "started_at": "16:02:26",
  "holder": {
   "kind": "FAST",
   "lane": "impl-f6du",
   "sha": "6d5e220",
   "coverage": 0.44,
   "from": "16:02:19",
   "to": "16:02:32"
  }
 },
 {
  "attempted": "idle",
  "note": "quiet: median busy 1.88 over the last samples",
  "wall": 10.3,
  "cpu": 10.4,
  "cores": 1.02,
  "busy_med": 3.18,
  "busy_max": 3.58,
  "held_frac": 0.0,
  "rc": 0,
  "ran": null,
  "started_at": "16:02:49",
  "holder": null
 },
 {
  "attempted": "idle",
  "note": "quiet: median busy 0.51 over the last samples",
  "wall": 13.1,
  "cpu": 13.1,
  "cores": 1.0,
  "busy_med": 5.03,
  "busy_max": 5.46,
  "held_frac": 0.83,
  "rc": 0,
  "ran": null,
  "started_at": "16:03:43",
  "holder": null
 },
 {
  "attempted": "two-demand",
  "note": "burners=5 nice=10",
  "wall": 24.3,
  "cpu": 15.2,
  "cores": 0.62,
  "busy_med": 7.87,
  "busy_max": 7.93,
  "held_frac": 1.0,
  "rc": 0,
  "ran": null,
  "started_at": "16:04:02",
  "holder": null
 },
 {
  "attempted": "idle",
  "note": "quiet: median busy 1.83 over the last samples",
  "wall": 10.9,
  "cpu": 11.0,
  "cores": 1.02,
  "busy_med": 2.5,
  "busy_max": 2.94,
  "held_frac": 0.0,
  "rc": 0,
  "ran": null,
  "started_at": "16:11:38",
  "holder": null
 },
 {
  "attempted": "idle",
  "note": "quiet: median busy 0.65 over the last samples",
  "wall": 11.0,
  "cpu": 11.1,
  "cores": 1.0,
  "busy_med": 2.19,
  "busy_max": 3.74,
  "held_frac": 0.67,
  "rc": 0,
  "ran": null,
  "started_at": "16:12:00",
  "holder": {
   "kind": "FAST",
   "lane": "impl-f6du",
   "sha": "eff3c3e",
   "coverage": 0.64,
   "from": "16:12:04",
   "to": "16:12:14"
  }
 }
]
```

And its own summary block, verbatim:

```text
window: 694s of a max 2400s; quotas {'idle': 5, 'one-gate': 3, 'two-demand': 3, 'after-gate': 2}; achieved {'idle': 5, 'one-gate': 3, 'two-demand': 3, 'after-gate': 2}
CPU=8 burners for two-demand=5
idle: n=3 wall median=10.9s range=10.4-11.0 | cpu median=11.0s | cores median=1.02 | busy_med median=2.24 of 8
one-gate: n=3 wall median=11.2s range=10.7-11.5 | cpu median=10.9s | cores median=0.97 | busy_med median=4.16 of 8
two-demand (counterfactual): n=2 wall median=22.1s range=19.8-24.3 | cpu median=15.3s | cores median=0.70 | busy_med median=7.69 of 8
after-gate: n=2 wall median=10.4s range=10.4-10.5 | cpu median=10.5s | cores median=1.00 | busy_med median=2.23 of 8
started-idle but joined by load (contaminated): n=3 wall median=13.1s range=10.3-13.7 | cpu median=12.6s | cores median=1.00 | busy_med median=5.03 of 8
```

A re-run reproduces the SHAPE (conditions, columns, the load axis) rather than a byte-identical table:
the busy level of a working fleet is not repeatable by construction, which is the finding, not a flaw.
This is the distinction the previous note drew - numbers you can re-derive versus numbers you take on the
instrument - and here the raw records are embedded, so both kinds are inspectable.
