## `fleet-heavy-light-class.patch` (agents-v2t9)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/fleet-heavy` — a LIGHT pool (`light1..lightN`) for jobs that declare themselves bounded-small,
    with `--status` reporting it and `prune_stale_labels` cleaning it. Inert unless
    `FLEET_HEAVY_LIGHT_SLOTS` is set, so a small VM keeps today's behaviour by doing nothing.
  - `bin/fleet-check` — one assignment at the `fleet-heavy` call site (line 722): a `--fast` gate
    declares itself light.
  - `tests/fleet-heavy-light-class.test.sh` — **new**, 12 assertions, runnable as
    `bash tests/fleet-heavy-light-class.test.sh` with `FLEET_HEAVY_OVERRIDE` to point it at another
    revision of the tool.
- **Baseline file hashes:**
  `33ecf140e615852a9d374b27b6e4b956365b80f3e942f25a6a5d897db0617e58  bin/fleet-heavy`
  `d6f98be853d343b0749f22726bc5d178f7da728fdf6ef7f33bd1c09ba04213f0  bin/fleet-check`
- **Patched file hashes:**
  `b466376eba23a7d29565d7641d9b2816755d011e5b6deb450419037776918a0f  bin/fleet-heavy`
  `9d5defa6faf65a3397a8de94a24d8ef47bd394a6b183ded1e9866079ca176d1d  bin/fleet-check`
- **WHICH `bin/fleet-heavy` THIS IS BUILT ON — read before applying.** On 2026-10-13 this VM carried two
  generations of the tool, and they are not the same file: `~/fleet/fleet-heavy` (252 lines, 14378
  bytes, sha256 `33ecf140…`, with `slot_fd_holders`/`reclaim_abandoned_slot`) and
  `~/fleet/bin/fleet-heavy` (154 lines, 7850 bytes, sha256 `0f95ccd3…`, **lacking the reclaim**), which
  is what `command -v fleet-heavy` resolves to here. The patch is built on the **reclaim generation**
  (`33ecf140…`) because that is what the hub has and the VM's `bin/` run has: this VM's own
  `tests/fleet-heavy-reclaim.test.sh` pins the reclaim behaviour, and the pending sibling delivery
  `patches/fleet-heavy-holder-identity.patch` names `bin/fleet-heavy` at 14378 bytes / `33ecf140…` as
  its base and does not apply to the 154-line copy. Reproduce the base with
  `sha256sum bin/fleet-heavy`. The fleet-check side has only one generation here, so it is built from
  `~/fleet/bin/fleet-check` and its hunk is two context lines at one call site.

- **Problem statement (agents-v2t9).** An implementer's iteration cost on this fleet is dominated by
  waiting for the heavy slot, not by the suite the gate runs. Across the 724 fast-gate records that
  carry the gate's own `run_s`/`wait_s` split: **20219s of suite work against 103026s of waiting — 84%
  of every iteration second is queue.** It is bimodal, and saying only "the queue dominates" would be
  wrong in the other direction: 49% of iterations waited 0s, while the 41% that waited ≥60s waited
  behind a median **11s** of work. The fast gate's own work is already cheap; no amount of test-suite
  shrinking recovers those seconds.

- **Established, by reading (the mechanism, not a correlation):**
  1. `bin/fleet-heavy:13` — `slots=${FLEET_HEAVY_SLOTS:-1}`; the slot is a `flock` held for a job's whole
     run, and `~/.fleet/local.conf:6` sets `FLEET_HEAVY_SLOTS=1` on this VM.
  2. `bin/fleet-check:722` — ONE call site, and both kinds use it: `CHECK_CMD` and `--fast`'s
     `CHECK_FAST_CMD` enter the same queue. Nothing distinguishes a 500s full gate from a 12s fast check
     except the command that runs after the slot is granted.
  3. `bin/fleet-heavy`'s `ticket_take` gives the merger's arrivals priority (`-merger` tickets sort ahead
     of every implementer's, which are offset by 1e9), and its PREEMPTION block kills a non-merger
     holder's process group so the merger never waits. An implementer's fast check therefore does not
     merely queue behind a full gate — it pays the full gate's queueing cost *and* is killed and re-run
     if the merger arrives.
  4. The fast gate IS bounded: `~/.fleet/check.conf:12`, `CHECK_FAST_TIMEOUT=180`. That bound is the
     property the pool requires, and it is why `--fast` is what gets marked, not "any small command".

- **Measured, on the VM whose policy this changes** (8 vCPU). The merger's own `bash tools/full-gate.sh`
  held the slot; `/proc/stat` sampled in 5s buckets, the slot's state read through the same `flock`
  authority `fleet-heavy` uses:

  | what | cores busy (of 8) |
  |---|---|
  | full gate holding the slot (median over 34 buckets, 170s) | **5.20** (p90 6.05, max 6.21) |
  | the 30s immediately before a light check ran | 4.92 (4.62–5.58) |
  | the same window with a light check beside it | 5.91 |
  | the light check's marginal cost | **1.00 core** |

  The full gate leaves **~2.8 cores idle** while it holds the slot: the exclusivity is policy, not
  physics. The direct A/B — same command, same tree, same changed path, differing only in whether the
  full gate was running:

  | run | wall | child CPU | cores | result |
  |---|---|---|---|---|
  | `--fast` beside the running full gate | 25.7s | 24.8s | 0.97 | passed (5 suites) |
  | `--fast` with the slot free | 22.8s | 22.5s | 0.99 | passed (5 suites) |

  **+12.7% wall (2.9s) to co-run**, and the full gate was still holding the slot when the check
  finished. For comparison, the queue made that same check wait **170s** for ~22s of work (`[check]` on
  this lane, 2026-10-13) — the cost the pool removes.

- **Changes.** `fleet-check` marks its `--fast` gate `FLEET_HEAVY_LIGHT=1`. `fleet-heavy` gains a light
  path, taken *before* `ticket_take`, which contends for `light1..lightN` instead of the main slot:
  `nice -n 19` (a co-running full gate is `nice 10` and keeps the cores it needs), no arrival ticket (a
  ticket is how the merger cannot be overtaken for the **main** slot; taking one here would put a light
  job in the same priority class as a plain implementer's and delay that job's FIFO turn while the light
  job runs), and not a preemption target (it does not hold the slot the merger needs, and keeping
  running through a full gate is the point). A light waiter leaves a `lightwait.<pid>` marker, because
  it holds no ticket and `waiting: N` would otherwise report an idle pool with a job queued in it; the
  marker is pruned by pid liveness, which is advisory — the flock stays the authority on the slots.
  `--status` reports the pool, but only to a caller that passes the pool size, exactly as it already
  does for `FLEET_HEAVY_SLOTS`.

- **Verification, on a copy — never on the live tool.** `~/fleet` is synced and every lane on this VM
  depends on `fleet-heavy`, so the patch was built against copies and driven with `FLEET_HEAVY_DIR`
  pointed at a throwaway directory; that the live queue directory is untouched is assertion 7 of the
  delivered test. **12/12 assertions pass**, and the test ships in this patch, applies cleanly
  (`git apply --check -p1`), and passes from the applied tree against the applied tool:

  ```
  1. no pool sized: a light job behaves exactly as before (the default is inert)
  2. a plain MAIN job still queues (exclusivity and FIFO preserved)
  3. with a pool sized, a light job runs NOW, beside the held slot (waited 0s)
  3. the job held a light slot (its own label was in light1.who)
  3. the light path did not touch the main slot's label
  3. a light job takes NO main-slot arrival ticket (main-slot FIFO is untouched by it)
  4. --status reports the light pool (asked with the pool size, as the main slots need too)
  4. a second light job waited: the cap is real, not unlimited concurrency
  4. a waiting light job leaves a lightwait marker
  5. the main job runs once the slot frees
  6. re-entrancy: an OUTER light job (pool size 1) runs an inner fleet-heavy, which completes because the
     outer exports FLEET_HEAVY_HELD, so the inner call does not queue on the slot its own parent holds
  7. the live queue dir has no light slots
  ```

  Round trip: `git apply --check -p1` passes against pristine copies and, after applying, all three
  files are **byte-identical** to the copies the test ran against (hashes above).

- **Defects this verification found in its own work, each fixed and each kept visible:**
  1. The first version put the light branch *after* `ticket_take`, so a light job took a main-slot
     arrival ticket it never used — delaying a plain implementer's FIFO turn for as long as the light job
     ran. Assertion 3 now pins the fix, and it is why the branch sits where it does.
  2. The first builder inserted the waiter's marker *inside* a command substitution (its anchor line
     contains `tr '\n' ';'`), which the shell parsed as part of the `echo`; and its patch headers came out
     as `abin/fleet-heavy`, which no tool would apply. Both were caught by reading the generated
     artefacts rather than trusting the builder.
  3. The first test held the main slot on the test shell's own fd, and every child it spawned inherited
     it — so the fixture kept the slot held after it "released" it. The reclaim path in `fleet-heavy`
     reported exactly that (`descendants still held slot1 after the job finished … killing them`) and
     killed them. The fixture is now a dedicated holder process released by its own process group.
  4. The test's status checks piped into `grep -q`. Under fleet-heavy's `set -o pipefail`, `grep -q`
     exits at the first match, the writer takes SIGPIPE, and the pipeline's status becomes non-zero
     **even though grep matched** — so every check silently read as "not held". They are `case` matches
     on captured output now.
  5. **Found by REVIEW, not by me (agents-ltpg), and recorded differently for that reason.** Assertion 6
     was a FALSE GREEN: it invoked the tool only ONCE, inside `bash -c`, so no outer invocation ever held
     a slot and re-entry was never exercised — it printed "a nested call ran directly" for a run with no
     nested call at all. The reviewer applied the patch to copies, ran the delivered test, and proved it.
     The assertion is now an OUTER light job holding `light1` (pool size 1) whose job invokes the tool
     again, and it is **verified by MUTATION rather than by passing**: delete the re-entrancy guard from
     the patched tool and the assertion FAILS (rc=124, the inner call blocked on the slot its parent
     holds); restore it and 12/12 pass. A test for a deadlock that cannot deadlock is worse than no test,
     because it gets quoted as coverage.

- **Enabling it (the whole change, on this VM):**

  ```sh
  export FLEET_HEAVY_LIGHT_SLOTS=2   # ~/.fleet/local.conf
  ```

  A size of 2 is what the measurement supports here: two light jobs cost 2 of the ~2.8 cores a full gate
  leaves idle, and the pool caps concurrency rather than admitting every lane's check at once. **The
  default is 0**, so this patch changes nothing until a VM's operator sets it; the same sizing that made
  this VM 8-vCPU is what justifies a pool here, and a 2-CPU VM keeps the old behaviour by doing nothing.

- **The alternative that was not taken.** `FLEET_HEAVY_SLOTS=2` (one line, no code) also removes the
  wait, but it lets two **heavy** jobs run together — the exact thing the queue exists to prevent on a
  small VM — and it gives a light job no smaller a share than a full gate. The light pool keeps heavy
  jobs strictly serialized and only loosens the policy for jobs the caller has bounded.

- **Limits, stated rather than implied.** The headroom figure is one VM, one gate, one arm (the docs
  arm: 5 suites, 75 tests). A heavy arm costs the same ~1 core but ~100s of wall, and its behaviour
  under a co-running full gate was NOT measured — the pool's cap and `nice 19` bound that risk, they do
  not eliminate it. Nothing here measures a 2-CPU VM, where the idle-core argument does not hold and the
  pool must stay at 0. And the pool does not make the queue free: it removes the 84% that is one job
  waiting for a *differently-sized* job, and leaves the serialization that protects the VM intact.
