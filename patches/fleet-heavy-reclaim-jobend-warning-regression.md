## patches/fleet-heavy-reclaim-jobend-warning-regression.patch — a regression test for the job-end sweep: a clean job must be SILENT, and a real leaked husk must still be named (agents-s7vx)

The job-end holder-attribution fix (agents-lhnb) had **no test that would fail if it came back**. The only test
touching that path is section 6 of `tests/fleet-heavy-reclaim.test.sh` ("the release sweep must NOT kill its own
command substitution", fleet-91fr), which asserts `case "$out" in *INNER_OK*)` — that the substitution SURVIVES
— and the deployed file contains **not one occurrence of the string `warning`**. The defect was a warning plus a
spurious TERM at job end, so a regression that reintroduced it would still pass section 6 as long as the
substitution's output survived.

## The four hub-delivery fields

| field | value |
| **Artifact sha** | `patches/fleet-heavy-reclaim-jobend-warning-regression.patch` — **2360 bytes**, sha256 `f61782f3f5b903e144ad46b38d9fef9b`, 1 hunk, 1 file-section |
| **Exact base it expects** | `tests/fleet-heavy-reclaim.test.sh` = **6858 bytes**, sha256 `a65b35600ad2b56dbac42c507a1c7eac` (measured on the deployed `~/fleet` copy on this VM; the artifact targets nothing else) |
| **Applies** | `patch -p1 --fuzz=0` from a fleet checkout: rc 0, no `.rej`, no `.orig`; the result is **8826 bytes**, sha256 `60c973872a1ef48eeb4982822695d02b`, and `bash -n` is clean |
| **What it adds** | section 8, **six** assertions (the file's summary constant goes `14` → `20`) |

## What section 8 asserts, and why both halves are needed

Two properties, because either one alone is satisfied by a broken tool:

* **8a/8b — a clean job must be SILENT.** With a private `FLEET_HEAVY_DIR`, `bash bin/fleet-heavy true` must exit
  0 and print **no** `descendants still held` warning. A sweep that warns about its own instrument fails this.
* **8c/8d/8e/8f — a real leak must still be NAMED.** A job-spawned `setsid` husk must produce the warning, the
  warning must contain **that husk's pid** (read from the fixture, not hard-coded), and the slot must be free
  afterwards. A sweep that was deleted, or that stays silent about real leaks, fails this half.

## Evidence: the assertion goes RED without the fix and GREEN with it

Driven in a **complete tree** (real `bin/` and `tests/`, sibling directories symlinked), with only
`bin/fleet-heavy` swapped between the two generations:

| tool generation | 8a | 8b | 8c | 8d | 8e | 8f | suite |
| base `bin/fleet-heavy` 14378 B sha256 `33ecf140e615852a` (the fix ABSENT) | ok | **FAIL** | ok | ok | ok | ok | 17 passed, 3 failed |
| integrated tip, **322 lines** sha256 `9e30db1f62c2ac4f` | ok | ok | ok | ok | ok | ok | 18 passed, 2 failed |

The RED→GREEN delta is **exactly one assertion, 8b**. On the base the failure names three instrument pids —
`warning - descendants still held slot1 after the job finished (2784938 2784939 2784940)` — which is the defect
itself: the sweep listing the fork and its own `grep -v`/`tr` pipeline as leaked descendants.

**The integrated tip was built, not assumed.** Applying `fleet-heavy-jobend-holder-attribution.patch`, then
`fleet-heavy-reclaim-live-pid-vs-holder.patch`, then `fleet-heavy-holder-identity.patch` — the order
`patches/fleet-heavy-delivery-ledger.md` states — to that 252-line base yields **322 lines, sha256
`9e30db1f62c2ac4f`**, byte-identical to the hash the fix's own write-up records for the integrated file. A hash
reproduced by applying the thing that produces it is stronger than the same hash read twice.

## Two caveats, both measured, neither caused by this patch

1. **The suite is red at baseline in this environment, independently of my change.** `tests/fleet-heavy-reclaim
   .test.sh` reports **12 passed, 2 failed** on the UNMODIFIED file in a complete tree: section 7's `two runs
   write two archives (0 archive(s))` and `one.txt is gone`. Those same two fail in both rows above, so the
   red/green delta above isolates 8b — but a reviewer who runs the whole file will see two failures that are
   NOT this artifact's. Section 7 drives `$HERE/bin/fleet-disk-hygiene`, and the deployed 16145-byte
   `fleet-disk-hygiene` does have the evidence-archive feature (`EVIDENCE_ARCHIVE_KEEP_DAYS`), so this looks like
   a fixture/generation mismatch between this unlanded test file and the deployed tool rather than live data
   loss. It is out of scope for agents-s7vx and worth its own bead.
2. **Run it in a tree, not against a file pair.** Section 7 calls `$HERE/bin/fleet-disk-hygiene`; a copy holding
   only `bin/fleet-heavy` and the test file will make sections 7 fail for want of a sibling tool. I measured
   that failure mode first and it is an artifact of a stripped copy, not of the suite.

## Boundary

This is a patch **delivery artifact** in `patches/`, not installed `~/fleet` code: it was cut against the
deployed file's exact bytes and verified in /tmp copies only. Nothing was installed under `~/fleet`, and this
artifact must land **with** the reclaim family it guards (agents-zwtx: the family's base is the VM's 14378-byte
generation, which canon does not have), because the tool generations it distinguishes are supplied by that same
delivery.
