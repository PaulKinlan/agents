# ADR 0003: The Unit of Test Parallelism Is the Test Module — Both Gates Shard by Module

- **Status:** Accepted (Adopted in `76a06b51` for the full gate and `8f7663f8` — bead `agents-8ibx` — for the fast gate; ratified 2026-10-14)
- **Deciders:** Software Factory Architecture, Core Coordination, Tooling Implementers
- **Context:** Bead `agents-5fy0` (this record), `agents-s5ug` (the bound overrun that forced the fast gate), `agents-8ibx` (implementation), `agents-ukk2` (the defect its review found), `agents-oxhq` (a single module measured as 54% of a full-gate wall), `agents-oskn` (adjacent landing in the same file)
- **Updated:** 2026-10-14

---

## 1. Context and Problem Statement

The fleet standard (`~/fleet/docs/speed.md`, R5 lever 1, quoted in `agents-5fy0`) requires that *"independent suites run in parallel processes, not sequentially inside one process. A test file is the unit of parallelism"*. This repository had adopted it in neither gate.

**The full gate was one process.** `python3 -m unittest discover -s tests -t . -v` — 1541 tests across 85 modules — measured on this VM at **418 s** (sha `4dfb031`) and **441 s** (sha `37dc6f2`), against a fleet target of ≤180 s. The identical command was the deployed CI invocation, so CI paid it on every push and pull request.

**The fast gate was cheap at the median and heavy in the tail.** Across 450 parsed cached runs: **p50 10 s, p90 68 s, max 276 s**, against the repo's own `CHECK_FAST_TIMEOUT=180`. The bound was not enforced by anything that records a verdict — 10 of 696 cached fast verdicts carried `run_s > 180` and still recorded PASS — and a run that sits at ~90% of its bound does not fail safely: it is killed the moment a priority job arrives, and each kill holds the VM's single heavy slot for its full bound (~210 s) while producing no verdict. Measured twice (`agents-s5ug`) before the fast gate could be trusted to report on large deltas at all.

**The wall is genuine work, and micro-optimisation is not the lever.** The cost is real subprocesses, real bubblewrap wraps and real git worktrees. Checked against the standard's R8 (lever 4) as its own checklist asks: the per-test world-rebuild in `tests/containment_harness.py` costs 3.5 ms with `copyfile`+`copytree` and 0.8 ms with `os.link`, so the entire 235-test copy-using family would save **0.6 s of a ~420 s gate**. R8 is compliant here; the only coverage-preserving lever left was to run modules at the same time.

## 2. Decision

**The test module is the unit of parallelism, in both gates.** Concretely:

1. **One process per selected test module**, run concurrently under a worker cap. The cap defaults to `min(4, nproc)` and is overridable by the operator (`FULL_GATE_SHARDS`, `FAST_GATE_SHARDS`). The cap is a shared-VM restraint, not a tuning knob: this VM runs seven lanes with a single heavy slot, so concurrency happens *inside* one heavy job and never by holding several.
2. **A run invoked from inside a shard stays serial** (`FAST_GATE_SHARD_CHILD`). Without it, four lanes × four nested workers is ~16 processes where the unsharded shape had four — measured: one fast-gate run wrote **eight** nested summaries from the suites that invoke the gate.
3. **Executed test IDs are the evidence, never the exit code alone.** The full gate compares its executed IDs against a serial discovery set and refuses imports that fail; the fast gate checks that every selected module executed at least one test, because it cannot afford a second traverse of the suite. A module that ran nothing fails the run however its child exited.
4. **The wall floor of any delta is its longest single module.** Sharding cannot make a delta faster than its heaviest suite, and this ADR does not pretend otherwise.

## 3. Adopted instances (the evidence this decision already has)

### The full gate — `76a06b51` (2026-10-13)

Serial discovery's ID set is preserved and compared against the executed IDs of every whole-module subprocess; failed imports are refused. Landed result on the `agents-8ibx` merge (`8f7663f8`, tree `75aa2c7a`): **1787/1787 tests in 129.5 s** — against 418 s and 441 s measured for the same suite in one process.

### The fast gate — `agents-8ibx`, landed `8f7663f8` (2026-10-14)

The runner is a pool that drives `python3 -m unittest -v` once per module. Same delta, verified by dry run to resolve to the identical 24-module selection:

| | wall | modules | tests | rc |
|---|---|---|---|---|
| before (serial) | 162.5 s | 24 | 597 | 0 |
| after (4 workers) | **52 s** | 24 | 598 | 0 |

The work did not shrink to buy the speed: the **sum of per-module process walls is 167.2 s** across the same modules, so the same suites ran, in parallel. (598 vs 597 is one test added by a landing between the two measurements; the runner's ID counter and `unittest`'s own per-module `Ran` totals both report 598.)

### CI inherits the decision — `.github/workflows/ci.yml:39`

CI runs `bash tools/full-gate.sh`, so the sharded full gate is what CI executes; this is why the serial figure above is historical rather than current.

## 4. Remaining candidates, scored

- **The fast gate's heaviest module.** A delta selecting `tests/test_fast_gate_mapping.py` lands at that module's own runtime — measured at 82.575 s for the whole serial 8-suite selection of such a delta, so the module is at most that. Sharding removes the rest of the selection's contribution and leaves this floor. `agents-oxhq` measured the same module at 107.7 s of a full-gate wall, i.e. 54% of it.
- **The CI pre-passes.** Secret scan, docs drift and dependency audit run as separate serial steps after the gate. Untouched by this decision; a different lever.
- **The fast gate's selection work** (the arm loader, the registry guards, the unmapped check). Cheap at the median, and a different problem from runtime parallelism.

## 5. Costs (paid, not hypothetical)

- **Nested fan-out**, which arrived the moment the fast gate sharded and is now bounded by `FAST_GATE_SHARD_CHILD` (decision 2). The measurement is not hypothetical: one own-delta run produced eight nested summaries.
- **The summary write path had to keep two properties at once**, and the first version of the fast-gate port lost one. The runner's stream must be **appended** to the summary rather than truncated onto the header already in it, and it must arrive **while the run is going**. Python-side buffering satisfied the first and broke the second, so a preempted or hung run left the summary and the log with only a header — the 461-byte, header-only file recorded on `agents-8ibx`'s first attempt. `tee -a` on the runner's invocation restores both; `agents-ukk2` is the finding, and the property is pinned on the runner *command* by `tests/test_summary_identity.py`.
- **An arm gap that hid the above**: `tools/fast-gate-arms.d/020-tools_fast_gate_sh.sh` did not select `tests/test_summary_identity.py` for a `tools/fast-gate.sh` delta, so no fast-gate run could see the contract test for the gate's own runner. It is now selected; cost measured at 3 tests / 0.006 s.
- **A green sharded run is one sample.** Independence was audited before the port landed rather than argued: the suite that writes a transient probe into the live `tests/` directory runs concurrently with the always-on tree guard, and the guards read git's index, which is what the earlier `agents-kb0y`, `agents-zf2p` and `agents-4ieg`/`agents-jq78` fixes established.

## 6. What this decision does NOT fix

- **The floor** (decision 4). A mapping-dominant delta's fast-gate wall stays near that module's runtime.
- **The size or speed of any individual test.** The same tests with the same assertions run; only *when* they run changed.
- **The fast gate's selection cost**, and **CI's remaining serial steps** (section 4).
- **Micro-optimisation**, because it is not where the time is (section 1).

## 7. Alternatives considered

- **One process per test rather than per module.** Rejected: a module is the natural independence boundary — it owns its fixtures, its temporary directories and its imports — while per-test processes pay interpreter startup 1787 times and turn fixture sharing into a coordination problem.
- **Micro-optimisation first** (the R8 items). Measured and rejected as the lever: 0.6 s of a ~420 s gate.
- **Shard the full gate only.** Rejected because the fast gate is the tier that runs on every iteration, and it was the tier being killed at ~90% of its bound with no verdict.
- **Split the heavy modules** (e.g. `tests/test_fast_gate_mapping.py`). The right next lever for the floor, but a refactor rather than a parallelism decision, so it is recorded as residual rather than folded in here.

## 8. Method (so the numbers can be re-derived rather than trusted)

- **Fast gate**: the runner reports one line per module on stderr — `----- <module> rc=<rc> <secs>s ids=<ids> -----` — followed by a union line naming the module count, the total executed IDs, and how many failed or produced none. The wall is the job's; the sum of the per-module lines is the work.
- **Full gate**: per-module costs are cached in `full-gate-module-costs.json` beside the check records, and the worker cap is `FULL_GATE_SHARDS`.
- **Running a gate on a delta**: `GIT_CHANGED` is read **one path per line**, the shape `git diff --name-only` prints. A space-separated list arrives as a single path and is refused in about a second with a notice that says so — worth knowing before blaming a selection.
- **Every figure above is attributed**: `agents-5fy0` for the standard and the pre-shard gate measurements, `agents-s5ug` for the tail and bound-kill measurements, `agents-8ibx` for the fast-gate receipt, `agents-ukk2` for the streaming defect, and the landing commits for the full-gate result.

## 9. Consequences

- **A large fast-gate delta gets its verdict in about a third of the wall** (52 s where 162.5 s was measured), which moves that delta from ~10% bound headroom to ~70% and removes the preemption-by-bound-kill failure mode it was living with.
- **The gate's output is per module and streamed**, so a killed or hung run still shows what finished rather than only a header.
- **Operators have one knob** (`FAST_GATE_SHARDS`, `FULL_GATE_SHARDS`) and one restraint (nested runs serial by default); lanes running the fast gate do not need to know more.
- **The decision is now enforced by tests rather than by intent**: the fast-gate runner's contract — stdout purity, the failure marker's payload, one warning per exit, the append-and-stream summary — is asserted, and the gate selects those tests for changes to itself.
