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
FULL_GATE_BUDGET_S=3300
FULL_GATE_MODULE_TIMEOUT_S=1500
CHECK_TIMEOUT=3600
CHECK_FAST_TIMEOUT=2400
```

| Constant | Default | Declared in | Enforced by |
|---|---|---|---|
| `FULL_GATE_BUDGET_S` | 3300 | `tools/full-gate.sh` (`positive_int`, env-overridable) | the gate itself, against its own elapsed wall (derived from the measured cost table, kept under `CHECK_TIMEOUT`) |
| `FULL_GATE_MODULE_TIMEOUT_S` | 1500 | `tools/full-gate.sh` (`positive_int`, env-overridable) | the per-module subprocess bound (slowest legitimate module measured: 1206.3s) |
| `CHECK_TIMEOUT` | 3600 | `tools/check.conf` | the fleet runner's hard bound (outside this repo); must exceed `CHECK_FAST_TIMEOUT` |
| `CHECK_FAST_TIMEOUT` | 2400 | `tools/check.conf` | the same runner's bound for `tools/fast-gate.sh` (a registry-touching fast gate runs the 1206.3s mapping validator) |

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

## 2. Where the wall actually goes (snapshot: 2026-10-29)

Two sources, measuring different things. The **cost table**
(`${FLEET_CHECKS_DIR:-$HOME/.fleet/checks}/full-gate-module-costs.json`) carries per-module walls from the
last full gate. The **verdict records** beside it (`<tree>.json`, plus the `<tree>.log` each one names)
carry the whole-run wall and every module's wall for every run: 46 completed full gates and 115 fast gates
on this VM between 2026-10-23 and 2026-10-29. §7 has the recipe for both.

- cost table (`at=2026-10-29T12:40:12Z`, tree `0703a195`, commit `c0d4f348`): **106 modules, module-wall
  sum 5851.2s**. `5851.2 / 4 = 1462.8s` against a p50 observed landing wall of 1540s, so §4's arithmetic
  still holds — the wall is the shard balance plus run overhead, not slack.
- the four largest modules are `tests.test_fast_gate_mapping` 717.2s,
  `tests.test_candidate_batching_end_to_end` 709.6s, `tests.test_factory_truth` 421.3s and
  `tests.test_redaction` 203.1s — **2051.2s, 35.1% of all module wall**.
- whole-run walls across those 46: min 372s, **p50 1540s**, worst PASS **3352s** (tree `49a20346`,
  2026-10-29T03:39), worst completed run of any state **3923s** (sha `3c920ecb`, 2026-10-27T08:51, FAIL on
  content — a red run still has to finish to say *what* is red, which is why the runner's bound is sized on
  this number and not on the worst PASS).
- **the spread is the finding.** The same tree shape ran in 372s and in 3352s, 9x apart, because this VM's
  vCPUs are descheduled by its host (`agents-a7w8z` measured steal 19.9% at 76.9% idle). A bound sized for
  the good day kills the bad one, and a killed module is state 2 — no verdict at all, so a merge cannot land.
- the slowest **legitimate** module wall in that window was `tests.test_fast_gate_mapping` at **3096.9s with
  module rc=0** (2026-10-27T08:51), and six runs since 2026-10-25 had a green module over 1500s: 1630.3s,
  1878.8s, 1985.4s, 2143.6s, 2175.6s, 3096.9s. That worst case is 2.6x the 1206.3s *standalone* measurement
  `tools/full-gate.sh` quotes, because a sharded run has eleven other modules competing for two vCPUs — so a
  bound derived from a standalone run is a bound that only holds on an idle box.
- fast gate, 115 runs in the same window: `run_s` min 10s, p50 245s, **worst 2000s** against a 2400s bound.
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
mechanism the bounds never had: until
`agents-2rv7c` they were derivations whose own comments said the measurement was missing
(`tools/full-gate.sh`: "A DERIVATION, NOT A MEASURED FULL-GATE WALL"; `tools/check.conf`: "the durable fix
is to measure one and pin THIS number to it"), and the host's real numbers lived only in an untracked
per-VM `~/.fleet/check.conf` that the next `install.sh` would have reverted.

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
- **what changed by 2026-10-29 is the box, not the suite.** The module-wall sum went 562.374s → 5851.2s
  (10.4x) while the id count grew far less; `tests.test_fast_gate_mapping` alone went 53.445s → 717.2s
  (13.4x) on the same four shards. §1's bounds had to move with that, and the guard now makes the next move
  a measured one.

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
2. **Make the largest suites cheaper** — the top six modules are 43% of module wall. Splitting does not help
   while balanced (§4); reducing work does.
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

# and the fast tier for the current delta
bash tools/fast-gate.sh
```

Quote a verdict with the sha and tree it belongs to: the record is cached per commit tree, and a PASS for
another tree is not a PASS for yours.
