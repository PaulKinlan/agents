## `fleet-bd-reporter-lifecycle.patch` — Fleet Beads reporter lifecycle (agents-u2st)

- **Hub target:** `PaulKinlan/fleet` `bin/bd` and new `tests/bd-lock-reporter.test.sh`.
- **Prerequisites, in order:** reviewed agents-elu6 holder diagnostics, then cleared agents-nbka bounded kernel-queued lock patch. The **post-nbka** `bin/bd` base SHA-256 is `d9270c1042fbd160467f28990164b07152948d3c03380efafbffafd2a61b1681`. This patch is independent of the agents repo's runtime and must not be applied to the old installed shim or before nbka.
- **Hub delivery:** apply `patches/fleet-bd-reporter-lifecycle.patch` to the fleet checkout after the two prerequisites, run `bash tests/bd-lock-reporter.test.sh` and the existing `bash tests/bd-lock-holder.test.sh` and `bash tests/bd-lock-queue.test.sh`, then install using the hub's normal process. The author did not edit `~/fleet`.

## Failure and fix

On a contended call, nbka starts a reporter subshell that periodically sleeps. Its normal cleanup kills the subshell while it is blocked in foreground `sleep "$every"`; Bash does not kill that child, leaving **one orphan `sleep 30` per contended acquisition**. The reviewer reproduced exactly one such child using a unique throwaway HOME. At the measured ~23 acquisitions/minute and 30-second report interval, roughly a dozen short-lived sleeping processes can accumulate, even though none holds the lock fd.

The reporter now starts its timer as a tracked child and waits for it. Its TERM/INT trap kills and reaps that timer before exiting. The parent continues to kill and wait for the reporter. The reporter still **closes its inherited lock fd first**; the parent and `bd` payload keep the same open-file-description lock across shim SIGKILL, and the existing 300s bounded acquisition and holder reports remain unchanged. A SIGKILLed reporter cannot execute a trap; the fd is closed independently so even that failure does not retain the lock.

## Hermetic verification (composed scratch tree, no host edit)

- New isolated fixture: old nbka code **FAIL** (`orphan_sleeps=1` after a successful contended call); patched code **PASS** (`orphan_sleeps=0`). It counts only `sleep 8` processes carrying its unique HOME, and cleanup kills only processes from that HOME.
- The same fixture pins the substantive fd condition: SIGKILL the shim while its flock child is queued behind a raw holder; after the holder releases, a fresh caller gets the lock within **1s**, and the killed shim never runs its stub `bd`. A mutant that removes only the reporter's fd close **FAILS** this test.
- Existing composed suites: elu6 holder/timeout/security **63/63 PASS**, nbka queue red-before/green-after plus full-device-key heavy fixture **12/12 ordered, zero timeout**, wait min 5.002s / max 6.025s, bd guard **85/85 PASS**, shim **15/15 PASS**, worktree-decoy **13/13 PASS**.
- Scope: two hub files only; no real Beads database, default branch, or installed fleet shim changed.
