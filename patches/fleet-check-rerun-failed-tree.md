## DRIVEN AND VERIFIED against coord's ruling of 2026-10-14 (attempt-N attribution, one-re-run bound, disagreement is RED).

The three ruled behaviours the pre-ruling patch lacked are now demonstrated red-first, with the harness fix that
made it possible (point FLEET_HEAVY_DIR at a private directory, so the stubbed gate stops contending for this
VM's real heavy slot - the contention is what made the earlier drive inconclusive, not the code):
  FAIL attempt 1, then a re-run whose stub PASSES
  -> a cached read serves "attempt 2 on this tree - re-run by impl-b at <t> (reason: the flake the merger
     measured)" AND "RED - the attempts on this tree DISAGREE: attempt 2 passed, but the recorded FAIL was
     re-run rather than fixed", exiting 1                                            [requirements (2) and (4)]
  -> a second re-run without an authoriser: "refusing a SECOND re-run of this tree: at most one is allowed
     without authorisation", exit 2                                                  [requirement (3)]
  -> a third attempt with --rerun-authorised-by=coord PROCEEDS and records
     "authorised_by=coord reason=third go, authorised" in the preserved record       [requirements (1), (6)]
  -> and the disagreement rule still holds on that attempt's result: RED again, exit 1

Known limitation, disclosed rather than glossed: a later request on the same record overwrites the earlier
request's reason in that record (the attempt RECORDS are all retained, each with its verdict, but a record
carries only the most recent re-run attribution). Retaining a per-attempt attribution list would need a new
array key - an ADDITION, not a field-type change - so it is a decision for coord, not something to smuggle in.

## patches/fleet-check-rerun-failed-tree.patch

**agents-5q0w (second half): a deliberate, recorded re-run of a FAILED tree.**

### The gap

`bin/fleet-check` caches a verdict per commit TREE, and a cached FAIL is served as a FAIL: *"Re-running
cannot change a deterministic failure: fix and commit."* That sentence is false. The merger measured a
load-sensitive test that fails once in 244 cached logs while the same error text appears in 26 logs as
expected output of passing runs, and the gate's own parallel shards are what trigger it. With no re-run
path, one transient failure reds that tree permanently: the only ways out are a re-cut, landing inside a
larger union, or carrying a known-flaky verdict by hand. The fleet's scarcest resource — a single full-gate
run — is converted into a permanent block, and after the fact a flake is indistinguishable from a regression.

### What the patch does

1. **`--rerun=<reason>`** — a re-run must carry a reason. Invoked as a bare `--rerun` it refuses with a named
   message and exit 2, because a re-run that records no reason is indistinguishable from hiding a regression.
   The flag uses the `=` form because that is this file's own idiom for a valued flag (`--repo=<dir>`); its
   argument parser is a `for _a in "$@"` loop, where a following word cannot be consumed.
2. **A guard above the verdict dispatch** for state FAIL, which falls through to run the gate instead of
   exiting on the cached verdict. A cached PASS is refused (exit 2): re-running a passing tree would spend the
   single heavy slot to learn nothing.
3. **The attribution goes into the record in place** — `reruns`, `rerun_by`, `rerun_reason`, `rerun_at` — using
   the same single-`jq`-plus-`mv` idiom the tool already uses, and deliberately with **no `2>/dev/null`** so a
   failed write cannot hide itself.
4. **The false sentence is replaced**, keeping "fix and commit" first and adding the recorded route.

### Why a regression cannot be wished away

The prior verdict is preserved **by construction**: the existing `fleet-0cxr` rotation already moves the old
record and its log aside as `<record>.1` before a new run is recorded, and the attribution is written into that
record before the rotation happens. A re-run therefore leaves the failing verdict, the reason, the lane and the
count in the cache as evidence, and a re-run that passes cannot erase that the tree had failed.

### Base and apply

- Applies to `bin/fleet-check` with **`patches/fleet-check-reserve-attribution.patch` (agents-dbit) already
  applied**: `patch -p1 --fuzz=0`, rc 0, no rejects, result byte-identical to the tree this was driven on.
- Base (dbit-applied): 53752 bytes, sha256 `db61bbaa6bf58c24`; patched: 55740 bytes, sha256 `65d67b0a7622fcd9`.
- **It REJECTS against today's deployed `bin/fleet-check`** (dry-run rc 1). That is deliberate: dbit's hunk
  covers base lines 291..303 and this patch edits the same cached-FAIL message line, so the only legal order is
  **dbit first, then this**, and a wrong-order application is refused rather than half-applied.

### Testing

Driven red-first against a stubbed gate and private HOMEs, all four cases:

- **A (base tool, `--rerun=<reason>`)**: rc 2, no attribution anywhere, the tree still caches its FAIL and 0
  mentions of rerun — the re-run path does not exist.
- **B (patched, `--rerun=<reason>`)**: the first ask serves the cached FAIL (rc 1); the re-run returns 0, prints
  `re-running the gate for this tree at impl-b's request (reason: …)`, the new record is RUNNING, and
  `<record>.1` reads `state=FAIL reruns=1 rerun_by=impl-b rerun_reason=…` — prior verdict and attribution both kept.
- **C (`--rerun` with no reason)**: rc 2, `refusing --rerun without a reason`.
- **D (`--rerun=` on a cached PASS)**: rc 2, `refusing --rerun: this tree has a cached PASS…`.

### Residual

The original verdict's *log* is preserved as `<record>.1`'s rotated log, which the existing rotation already
handles; nothing here adds a new key to the record's schema beyond the four attribution fields, and no consumer
needs changing to read them.
