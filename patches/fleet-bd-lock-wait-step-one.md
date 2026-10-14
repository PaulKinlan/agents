## patches/fleet-bd-lock-wait-step-one.patch

HUB-DELIVERY PATCH for `bin/bd`, answering `agents-atom`. **STEP ONE ONLY: this artifact RECORDS the observation a
derivation needs. IT DOES NOT CHANGE THE BOUND.** The bound stays `-w 300`, no threshold moves, no verdict string
changes, and the guarantee is identical to the line it replaces.

## Why the record is missing, and what the review asked for

The review of `agents-nbka` found four points, three of which hold; the fourth asked for the lock bound to come from
**"the measured p99 of successful runs rather than from taste"**. `bin/bd:257` is `flock -w 300 "$HOME/.fleet/bd.lock"
"$real" "$@"` - a literal 300. **The prescribed remedy cannot be implemented today, and not because nobody has done
it: no wait time is recorded anywhere.** Measured: `bin/bd` has no instrumentation of the wait; there is no timing or
latency artefact under `~/.fleet`; the lock file is 0 bytes because `flock` uses it as a target, not a record; and no
fleet log carries lock waits. There is no sample from which to take a p99.

## The distribution point, which decides whether the samples are usable at all

**THE p99 THAT GOVERNS A WAIT BOUND IS THE p99 OF THE WAIT, NOT OF THE RUN.** `flock -w` blocks, so a successful run
can include a long wait; a p99 taken over run durations would include the work done after acquiring and would set the
bound from the wrong population. This is not a nicety - it is why the first version of this patch was **discarded**:

> `flock -w 300 <lockfile> <command>` **runs the command under the lock**, so a timer around that line measures
> **WAIT + PAYLOAD**. Measured: a 150ms payload on an **uncontended** lock recorded **155ms**. The same code with the
> lock held for 2s recorded **1850ms**, which confirms the timer measures blocking - and also that it sums the work.
> A p99 built from those numbers would be a p99 of (wait + run): **true, about the wrong thing, and plausible enough
> to be believed**, which is worse than no measurement.

The shipped form therefore takes the lock on a **descriptor** and times only the acquisition, while guaranteeing
exactly what the old line guaranteed - the payload still runs under the lock, the exit code is unchanged, and nested
calls still bypass via `FLEET_BD_LOCKED`:

    exec 9>"$HOME/.fleet/bd.lock"
    _bd_t0="${EPOCHREALTIME:-}"
    flock -w 300 9            # <- the WAIT is here and nothing else is inside it
    ... record wait_ms and rc ...
    if [ "$rc" -eq 0 ]; then "$real" "$@"; rc=$?; fi

## Driven, including the control that caught the first version

| drive | expectation | measured |
|---|---|---|
| uncontended, payload sleeps 150ms | the WAIT, so near 0 - **not** 150 | **wait_ms=1** (first version: 155) |
| **control**: lock held for 2s | the blocking IS captured, payload still excluded | **wait_ms=1697** |
| payload exits 7 | the shim must not swallow it | **shim rc=7** |

Counts are unchanged from the original: `check_push_failure` appears 3 times, `exit "$rc"` twice, and the
payload-inclusive `flock` form occurs **zero** times. `bash -n` clean.

## How a derivation is meant to consume this

**A sample is only a WAIT sample when the call ACQUIRED the lock.** `rc != 0` is a timeout and says nothing about how
long a successful acquisition took, so `rc` is recorded on every line and a derivation must filter on `rc=0`.
The log is bounded at 1999 lines by the fleet's own idiom (`tail -n`), and every step is best-effort, so a broken log
can never break `bd`.

**The bound itself is a LATER step.** Once enough `rc=0` samples exist, the bound can be set from their p99 with the
sample size and the date recorded on the artifact. Choosing a different number now would be a number from taste -
indistinguishable in a diff from a fix, which is exactly the defect the review is about.

| | |
|---|---|
| algorithm | `sha256` |
| preimage | `f0e2f7c79b51819bed188af45ea8aa207cbe4843` (`~/fleet/bin/bd`) |
| result | `fea408eef024857108e7ccb03eea2505167dff6f` - **differs from the preimage**, asserted |
| patch | **2233 bytes, 1 hunk**, non-empty asserted |
| apply | `patch -p1 --fuzz=0` -> rc 0, zero rejects, byte-identical |

**ADVISORY:** the preimage was read from this VM's `~/fleet` mirror, which is behind the hub's origin
(`agents-x8ud`); verify by the chain you observe.
