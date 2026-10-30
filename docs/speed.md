# Speed: the gate budgets, the shape they are paid by, and how to re-measure

`tools/full-gate.sh` sends every reader of its over-budget message here — "see docs/speed.md for the terms
this budget belongs to" — and `tests/test_tree_guards.py` and `tests/test_adapter_auth_failure.py` cite this
file for the machine-state pathology by name. It did not exist until `agents-vy4g6`: the gate pointed at
terms nobody had written down, so the numbers were re-derived from scratch each time and the same premise was
filed three times (`agents-9iyf`, `agents-62ia`, `agents-vy4g6`). This is the missing contract.

Nothing here is a promise about a number; §2 is a **dated snapshot** and §7 is how to take a new one. The
constants in §1 are the part that is enforced, and they are pinned against the code by
`tests/test_check_conf_consistency.py`.

## 1. The numbers, as enforced by the code

```text
FULL_GATE_BUDGET_S=4800
FULL_GATE_MODULE_TIMEOUT_S=3600
CHECK_TIMEOUT=5400
CHECK_FAST_TIMEOUT=2400
```

| Constant | Default | Declared in | Enforced by |
|---|---|---|---|
| `FULL_GATE_BUDGET_S` | 4800 | `tools/full-gate.sh` (`positive_int`, env-overridable) | the gate itself, against its own elapsed wall — the worst **completed** run measured, 3923s (§2), plus 22%; kept under `CHECK_TIMEOUT` |
| `FULL_GATE_MODULE_TIMEOUT_S` | 3600 | `tools/full-gate.sh` (`positive_int`, env-overridable) | the per-module subprocess bound — the slowest **legitimate** module inside a sharded gate, 3096.9s at rc=0 (§2), plus 16% |
| `CHECK_TIMEOUT` | 5400 | `tools/check.conf` | the fleet runner's hard bound (outside this repo); must exceed both `FULL_GATE_BUDGET_S` and `CHECK_FAST_TIMEOUT` |
| `CHECK_FAST_TIMEOUT` | 2400 | `tools/check.conf` | the same runner's bound for `tools/fast-gate.sh` — the worst measured fast run, 2000s (§2), plus 20% |

All four are **measurements now, and pinned as such**: `tests/test_check_conf_consistency.py`
(`TestTheEnforcedBoundsCoverTheWallsTheContractRecords`) reads the worst walls §2 records and fails if a
bound is shorter than the wall beside it, or if the ordering `module < budget < CHECK_TIMEOUT` breaks.
Before `agents-2rv7c` three of the four were derivations or sized on a standalone run, and one was not.
`FULL_GATE_MODULE_TIMEOUT_S` 1500 was sized on the module's 1206.3s **standalone** wall, which is why it
was short inside a sharded gate; `FULL_GATE_BUDGET_S` 3300 was the derivation its own comment named ("A
DERIVATION, NOT A MEASURED FULL-GATE WALL ... that measurement is still missing"), summed from the cost
table; `CHECK_TIMEOUT` 3600 was self-declared too ("DERIVATION, NOT A MEASUREMENT ... the durable fix is to
measure one and pin THIS number to it"). Nothing compared any of them with the host, so the numbers that
actually produced verdicts lived only in an untracked per-VM `~/.fleet/check.conf` that `install.sh`'s
`--install --global` reverts. `CHECK_FAST_TIMEOUT` 2400 is the one that did not move, because it was
already sized on measured inputs - mapping's 1206.3s run plus its eleven siblings' measured 981.9s, which
the 117 fast gates in this window agree with (worst `run_s` 2000s). Re-measure with §7 and move the bounds
**in the same commit**.

`FULL_GATE_SHARDS` (default `min(4, os.cpu_count())`) is not a budget but the divisor the wall is paid
through; §4 is its arithmetic.

**Reading the full gate's exit code.** These are four different facts about a run, not four shades of red:

| Code | Meaning |
|---|---|
| 0 | every expected test id executed, no module failed, inside the wall — `full-gate: passed` |
| 1 | content: a failing module, or an id mismatch (missing / extra / duplicate) — `full-gate: failed` |
| 2 | a module was **killed at `FULL_GATE_MODULE_TIMEOUT_S`**: it reached no verdict, so it is excluded from the id set on both sides — `full-gate: unknown`. Not a pass and not a failure |
| 3 | complete and green but over `FULL_GATE_BUDGET_S` — `full-gate: over budget`. A machine-state fact, so the next action is to wait for a quieter box, not to fix an assertion |

The fast gate has no budget of its own; `CHECK_FAST_TIMEOUT` is the outer bound, and the fleet runner
caches its verdict per commit tree.

## 2. Where the wall actually goes (snapshot: 2026-10-30)

Two sources, measuring different things. The **cost table**
(`${FLEET_CHECKS_DIR:-$HOME/.fleet/checks}/full-gate-module-costs.json`) carries per-module walls from the
last full gate that wrote it. The **verdict records** beside it (`<tree>.json`, plus the `<tree>.log` each
one names) carry the whole-run wall and every module's wall for every run: **47 completed full gates** (38
PASS, 9 FAIL) and **117 fast gates** on this VM between 2026-10-23 and 2026-10-30. §7 prints both.

- whole-run walls across those 47: min 372s, **p50 1562s**, worst PASS **3352s** (tree `49a20346`,
  2026-10-29T03:39), worst completed run of any state **3923s** (sha `3c920ecb`, 2026-10-27T08:51, FAIL on
  content — a red run still has to finish to say *what* is red, which is why the runner's bound is sized on
  this number and not on the worst PASS).
- **the spread is the finding.** The same tree shape ran in 372s and in 3352s, 9x apart, because this VM's
  vCPUs are descheduled by its host (`agents-a7w8z` measured steal 19.9% at 76.9% idle). A bound sized for
  the good day kills the bad one, and a killed module is state 2 — no verdict at all, so a merge cannot land.
- **the cost table is one run's contention, and it moves faster than the suite does.** The same 106-module
  shape summed **5851.2s** at `at=2026-10-29T12:40:12Z` (tree `0703a195`, largest module
  `tests.test_fast_gate_mapping` 717.2s) and **1881.5s** at `at=2026-10-30T01:38:01Z` (tree `4be3f163`,
  largest 240.7s) — 3.1x apart in thirteen hours. Its balance arithmetic still holds run by run
  (`5851.2 / 4 = 1462.8s` against that tree's 1507s wall, so §4 is right: the wall is the shard balance plus
  run overhead), but a *bound* sized on the table is sized on whichever run happened to write it last.
- so §1's module bound comes from the **per-run walls in the verdict logs**. 36 of the 47 runs still have
  logs; across those, `tests.test_fast_gate_mapping` spans 165.4s to **3096.9s at rc=0** — 18.7x. Six runs
  carried a green module over the previous 1500s bound: 1630.3s, 1878.8s, 1985.4s, 2143.6s, 2175.6s,
  3096.9s. `rc=0` is what makes them legitimate: a module killed at its bound reports `rc=124` and no
  verdict, which is evidence about the bound, not about the work.
- that worst case is 2.6x the same module's **standalone** measurement (1206.3s, 2026-10-27, 105 tests,
  exit 0), because a sharded run has eleven other modules competing for two vCPUs. A bound derived from a
  standalone run is a bound that only holds on an idle box — which is exactly how the previous 1500 was
  derived, and why it was short by 1597s.
- fast gate, 117 runs in the same window: `run_s` min 10s, p50 244s, **worst 2000s** against a 2400s bound.
  `wait_s` — heavy-slot queueing, measured separately (`agents-5n28`) — reached 2242s, so what a lane
  experiences as a slow fast gate is mostly queue, and the bound is about the run.

The three walls §1's bounds have to cover, recorded as integers so
`tests/test_check_conf_consistency.py` can pin the bounds to them (rounded **up**: a floor rounded down is a
floor that quietly stops being one):

```text
MEASURED_WORST_MODULE_WALL_S=3097
MEASURED_WORST_FULL_GATE_WALL_S=3923
MEASURED_WORST_FAST_GATE_RUN_S=2000
```

Re-measure with §7 and change these three lines **in the same commit as the bounds they drive**. The pin
fails when a bound is *shorter* than the wall recorded beside it — the direction that costs a verdict; an
over-generous bound is not a test failure, it is §5's "say so with the measurement". That pin is the
mechanism the bounds never had: until `agents-2rv7c` they were derivations whose own comments said the
measurement was missing (`tools/full-gate.sh`: "A DERIVATION, NOT A MEASURED FULL-GATE WALL";
`tools/check.conf`: "the durable fix is to measure one and pin THIS number to it"), and the host's real
numbers lived only in an untracked per-VM `~/.fleet/check.conf` that the next `install.sh` would revert.

### The previous snapshot (2026-10-15), kept because §3 argues from it

Read with `fleet-check --status 8a018ce86bc8104ce662c45d7748597c0ee4bf0d` and from the cost table at
`${FLEET_CHECKS_DIR:-$HOME/.fleet/checks}/full-gate-module-costs.json`:

- record `state=PASS`, `secs=142`; log: `serial discovery 1906 ids / 102 modules; workers=4 budget=300s`,
  then `executed ids=1906 expected=1906 missing=0 extra=0 duplicate=0 wall=140.959s` (sha `0c08206f`).
- cost table (identity stamped on that same tree and commit, `at=2026-10-15T15:03:59Z`): **102 modules,
  module-wall sum 562.374s**. `562.374 / 4 = 140.594s` against `140.959s` observed, so the landing wall is
  the shard balance plus ~0.4s of run overhead — the gate is balance-limited, not slack.
- the six largest modules are `tests.test_fast_gate_mapping` 53.445s, `tests.test_pins_audit` 45.581s,
  `tests.test_tool_pins` 42.726s, `tests.test_factory_truth` 39.272s, `tests.test_credential_broker`
  30.791s and `tests.test_factory_core` 30.271s — **242.086s, 43.0% of all module wall**.
- fast gate, same day: the last recorded PASS on a multi-path delta was 68s against a 180s bound (tree
  `b1a37982…`, sha `1fe39a42`); narrow deltas are ~12s. One record shows `run_s=12, wait_s=109`: the budget
  is about the run, and heavy-slot queueing is measured separately (`agents-5n28`).
- **what changed by 2026-10-30 is mostly the box, and the suite a little.** Discovery grew 1906 → 2298 ids
  over 102 → 106 modules (1.21x the tests), while the measured module-wall sum for that shape went
  562.374s → 1881.5s or 5851.2s depending on the hour (3.3x-10.4x). A 21% larger suite does not explain a
  3-10x wall, and `tests.test_fast_gate_mapping` alone spans 53.445s → 165.4s..3096.9s across the window.
  §1's bounds had to move with the host, and the guard now makes the next move a measured one.

**The premise this replaces.** The description on `agents-vy4g6` reads "1487 tests at 0.235 s/test, budget
blown, growing ~60 s/day". On this tree the suite is 1906 tests and the landing wall is 141s: 28% more tests
and a wall 2.13x inside the 300s budget. Serial cost per test is `562.374 / 1906 = 0.295 s` of module wall,
and landing cost per test is `0.074 s` because four modules run at once — the test count grew while the wall
fell, because the unit of parallelism became the test module (ADR 0003). Growth is not established as a
trend on the sharded gate and is recorded as unestablished rather than asserted (`agents-62ia`).

## 3. The shape: three tiers, and the merge gate runs everything

1. **Always-on tier.** `tests/test_tree_guards.py` (invariants over the repository tree itself) and
   `tests/test_fast_gate_consumer_coverage.py` (symbol and mapping consumers of a change) are appended to
   every mapped and smoke fast-gate run. Kept in two modules on purpose: the tree tier stays pure, the
   consumer tier is not a tree property (ADR 0001 §5).
2. **Arm-selected tier.** `tools/fast-gate-arms.d/*.sh` maps a changed path to the suites that must run for
   it; first match wins, by numeric prefix. A changed path that matches no arm and no ignore entry **fails
   the gate loudly**, naming the file — there is no silent default suite (ADR 0002).
3. **Module-shard tier.** The full gate loads every tracked `tests/test_*.py` module, plans by the measured
   cost table into `FULL_GATE_SHARDS` lanes (LPT), runs **one process per module**, and refuses to read a
   module that executed no test ids as a pass (ADR 0003).

**Why the merge gate runs every module.** It is the only run over the merged union; the fast gate's
selection is a per-delta optimisation whose omissions are each named in an arm. Removing a suite from the
merge gate's default run is a **coverage** decision, not a speed one — and it is not what bought the 141s.
The 141s came from sharding (ADR 0003), not from skipping anything.

## 4. What a change costs a landing

While the shards balance, `landing wall ≈ module-wall sum / FULL_GATE_SHARDS`. An extra 2s test module
therefore costs **every subsequent landing 0.5s of wall** at four shards, and the fast gate 2s whenever the
arm that selects it matches. That is cheap; it is also the reason the cost is stated out loud.

Two consequences worth carrying:

- **Splitting a module does not shorten the wall** while the lanes balance (the total is unchanged) —
  `agents-oxhq`, closed with NO SPEED CLAIM after measuring exactly that. Making a suite *cheaper* does.
- **A test that can fail for a reason that is not its subject** turns your change red for everyone. The
  named pathologies: asserting on machine state (what happens to be on disk while it ran), reading files
  another lane writes, and order dependence between tests. Independent tests are a speed property here, not
  tidiness.

## 5. Rules for a change

- **If your change makes the gate slower, say so with the measurement** — in the hand-off and in the
  `LAND-SUMMARY`. A gate that gets slower quietly is a gate that gets re-filed.
- **Place a new test by ADR 0001's criterion**: can the domain your invariant asserts over grow or change
  through a file the fast gate resolves *without* selecting your suite? If yes, it belongs in the
  always-on tree-guard tier (measure it: under 0.5s per test, tier total under 5.0s). If it is a symbol or
  mapping consumer, the consumer-coverage tier. Otherwise its own arm.
- **A new suite needs an arm** for the paths it guards, or the fast gate fails loudly the first time one of
  those paths changes. That loud failure is deliberate; do not add a catch-all arm to silence it.
- **Never a silent skip.** No suite may be skipped by a tier setting and still be reported as part of a
  verdict. The gate's own accounting refuses to call a module that executed nothing a pass for exactly this
  reason.

## 6. If the budget is ever broken: the levers, in measured order

1. **`FULL_GATE_SHARDS`** — the wall divides by the worker count while the lanes balance. On this shared VM
   that is an operator decision, not a lane's: more workers take CPU from co-tenant lanes, and the
   heavy-slot queue already starves gates (`agents-5n28`: 18s of fast gate behind 629s of queued work).
2. **Make the largest suites cheaper** — §2's snapshots put the largest four-to-six modules at 35-43% of
   module wall, and one module (`tests.test_fast_gate_mapping`) at up to 3096.9s of a sharded run, which is
   what §1's module bound is sized on. Splitting does not help while balanced (§4); reducing work does.
3. **Only then, coverage.** Moving a suite out of the merge gate's default run needs the same evidence an
   arm needs (a named selection rule), an independent reviewer's clearance, and it must never be a skip that
   the gate's accounting cannot see.

## 7. Re-measuring, instead of re-filing

```bash
# the cached full-gate verdict for a tree, and the log it belongs to
fleet-check --status "$(git rev-parse origin/main^{tree})"

# the per-module wall this VM last measured (sum, shard mean, largest modules)
python3 - <<'PY'
import json, os
d = json.load(open(os.path.expanduser("~/.fleet/checks/full-gate-module-costs.json")))
s = d["seconds"]
print("identity:", d.get("identity"))
print("modules:", len(s), "module-wall sum:", round(sum(s.values()), 3),
      "shard mean (4):", round(sum(s.values()) / 4, 3))
for name, secs in sorted(s.items(), key=lambda kv: -kv[1])[:6]:
    print(f"  {secs:8.3f}  {name}")
PY

# the DISTRIBUTION behind §1's bounds, which the cost table alone cannot give: whole-run walls from the
# verdict records, and per-module walls from the log each record names. This is the recipe §2's snapshot was
# taken with (agents-2rv7c). Move `since` to re-measure; expect the counts to grow while the three maxima
# only move when a slower run happens - which is when the bounds have to move with it.
python3 - <<'PY'
import glob, json, os, re, statistics
since = "2026-10-23"
checks = os.path.expanduser(os.environ.get("FLEET_CHECKS_DIR", "~/.fleet/checks"))
wall = re.compile(r"([\w.]+)\s+wall=([\d.]+)s\s+rc=(\d+)")
full, fast, worst_module, worst_pass, worst_run = [], [], (0.0, "", ""), 0, 0
for path in glob.glob(os.path.join(checks, "*.json")):
    if path.endswith("module-costs.json"):
        continue
    try:
        rec = json.load(open(path))
    except Exception:
        continue
    if not isinstance(rec, dict) or rec.get("at", "") < since or rec.get("state") not in ("PASS", "FAIL"):
        continue
    if path.endswith(".fast.json"):
        fast.append(rec.get("run_s") or 0)
        continue
    full.append((rec["at"], rec["state"], rec.get("secs") or 0))
    worst_run = max(worst_run, rec.get("secs") or 0)
    if rec["state"] == "PASS":
        worst_pass = max(worst_pass, rec.get("secs") or 0)
    log = rec.get("log") or ""
    if os.path.exists(log):
        for module, secs, rc in wall.findall(open(log, errors="replace").read()):
            # rc=0 is what makes a slow module LEGITIMATE: one killed at its bound reports rc=124 and no
            # verdict, so it is evidence about the bound rather than about the work.
            if rc == "0" and float(secs) > worst_module[0]:
                worst_module = (float(secs), module, rec["at"])
walls = sorted(w for _, _, w in full)
print(f"full gates in window: {len(walls)}")
if walls:
    print(f"  whole-run wall  min {walls[0]}s  p50 {statistics.median(walls):.0f}s  "
          f"worst PASS {worst_pass}s  worst completed {worst_run}s")
print(f"  worst legitimate module wall  {worst_module[0]:.1f}s  ({worst_module[1]} at {worst_module[2]})")
if fast:
    print(f"fast gates in window: {len(fast)}  run_s p50 {statistics.median(fast):.0f}s  max {max(fast)}s")
PY

# and the fast tier for the current delta
bash tools/fast-gate.sh
```

Quote a verdict with the sha and tree it belongs to: the record is cached per commit tree, and a PASS for
another tree is not a PASS for yours. When a re-measurement moves one of §2's `MEASURED_WORST_*` lines,
`tests/test_check_conf_consistency.py` fails until the bound beside it moves too. That failure is the point:
it is the only thing standing between a host that got slower and a merge gate that quietly stops being able
to reach a verdict (`agents-a7w8z`).
