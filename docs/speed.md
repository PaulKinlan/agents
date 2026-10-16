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
FULL_GATE_BUDGET_S=300
FULL_GATE_MODULE_TIMEOUT_S=240
CHECK_TIMEOUT=2400
CHECK_FAST_TIMEOUT=180
```

| Constant | Default | Declared in | Enforced by |
|---|---|---|---|
| `FULL_GATE_BUDGET_S` | 300 | `tools/full-gate.sh` (`positive_int`, env-overridable) | the gate itself, against its own elapsed wall |
| `FULL_GATE_MODULE_TIMEOUT_S` | 240 | `tools/full-gate.sh` (`positive_int`, env-overridable) | the per-module subprocess bound |
| `CHECK_TIMEOUT` | 2400 | `tools/check.conf` | the fleet runner's hard bound (outside this repo) |
| `CHECK_FAST_TIMEOUT` | 180 | `tools/check.conf` | the same runner's bound for `tools/fast-gate.sh` |

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

## 2. Where the wall actually goes (snapshot: 2026-10-15)

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
