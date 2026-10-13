# Fleet Beads lock: queue contended callers (agents-nbka)

- **Target:** `PaulKinlan/fleet`, `bin/bd` and new `tests/bd-lock-queue.test.sh`.
- **Prerequisite:** apply the reviewed `fleet-bd-lock-holder.patch` (agents-elu6) first. This patch's `bin/bd` base SHA-256 is `5fc55aed8ea42865892e8c5bfd1c5d29c3db5ef6a4427d3a9b602a89c49e9e3f`; it does not apply to the old installed shim. Do not edit the deployed `~/fleet` directly from this project lane.
- **Delivery:** hub applies `patches/fleet-bd-fair-queue.patch` to its fleet checkout, runs `bash tests/bd-lock-queue.test.sh` and `bash tests/bd-lock-holder.test.sh`, then rolls out normally.

## Evidence and choice

During active landing on 2026-10-13, a read-only 30-second `/proc/locks` sample at 100ms resolution saw 299 samples, 99.7% held, mean 3.46 waiters (max 5), and 9 completed holder turnovers. Median observed turnover was about 2.12s, max 13.85s; first/last holds were censored. The observed new waiter/holder PIDs by lane totaled at least 15 in 30s (fast calls between samples were missed). Four earlier calls each failed a 90s wait despite continuous service. Increasing the timeout cannot fix a waiter that polls after other callers have reacquired the lock.

The uncontended `flock -n` fast path is unchanged. Under contention, the shim now queues **blocking** `flock` on the existing lock fd *before* first-holder diagnostics; `timeout` bounds the blocking child, while a reporter with its own lock fd closed preserves the elu6 first/periodic holder messages. The parent and blocking child share the open-file description, so a successful lock remains held by the parent and `bd` payload after the `flock` child exits. Expiry remains exit 75 without executing `bd`; zero and malformed bounds cannot turn `timeout 0` into an unbounded wait. The existing nested `FLEET_BD_LOCKED` path remains unchanged.

This joins the Linux kernel's lock wait queue instead of the one-second `sleep`/`flock -n` polling loop. It removes polling-order starvation; **it does not promise strict FIFO priority** across all kernels or a maximum queue wait under overload. Batching related bead calls under a single short hold still reduces demand and should continue. A hard FIFO requirement would need a separate ticket protocol with stale-ticket recovery, not an undocumented claim about this patch.

## Verification (scratch copy; live host untouched)

- On the reviewed elu6 baseline, `tests/bd-lock-holder.test.sh`: **63/63 PASS**; after this patch: **63/63 PASS**. It covers holder diagnostics, timeout/refusal, fd inheritance across shim SIGKILL, and data redaction.
- Existing `bd-guard.test.sh`: **85/85 PASS**; `bd-shim.test.sh`: **15/15 PASS**; `bd-worktree-decoy.test.sh`: **13/13 PASS**.
- New hermetic `bd-lock-queue.test.sh` uses a stub bd and throwaway HOME: an older blocked waiter and a later raw lock caller. **Old elu6 loop fails** (older rc 75); **new blocking waiter passes** before its one-second bound. Five additional runs passed. It also asserts that zero/malformed bounds return 75 without calling bd.
- No real Beads database, default branch, or deployed `~/fleet/bin/bd` was modified by these tests.
