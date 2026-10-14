## patches/fleet-path-idle-name-the-cause.patch

HUB-DELIVERY PATCH for `bin/fleet-path-idle.py`, answering `agents-b68h`. It is the IMPLEMENTATION OF A DECISION
that was measured first, and it deliberately does **not** weaken the safety property of `agents-pm4q`.

## The decision, answering the question as a decision

**`cannot prove idle` remains an UNCONDITIONAL SKIP for every candidate.** The named-narrow-relaxation option was
considered and **declined**, and the reason is that the only relaxations available are keyed to something about the
candidate - its age, or which process owns it - and both are heuristics rather than measurements. "mtime far beyond
any plausible run" cannot exclude a non-dumpable process holding a file in a directory whose mtime is old, which is
exactly the case the oracle exists to catch; and "provably unrelated" is unavailable because that is precisely what
`dumpable=0` hides. So the bound stays the same in both directions, and **nothing in this patch touches
`bin/fleet-tmp-clean` or its `safe_remove`.**

## The measurement that decided it, taken before any patch

| measurement | value |
|---|---|
| same-user processes scanned | **19** |
| with unreadable `/proc/<pid>/fd` | **1** - pid 390, comm `(sd-pam)`, ppid 386, state `S` |
| control (the scanning shell) | readable |
| `/proc` mount options | `rw,relatime` - **no `hidepid`** |
| for that pid | `/proc/390/status` unreadable, directory listable, `/proc/390/comm` **readable** |

**It is ONE PROCESS CLASS, NOT A GENERAL CONDITION.** The mechanism is `dumpable=0`: a process that dropped
privileges has `/proc/<pid>/fd` made root-only **even against its own uid**, permanently. That is the signature the
table shows - no `hidepid`, one process, and `comm` readable where `status` is not.

## What the patch changes, and what it deliberately does not

**Unchanged:** the exit status (still 2 on a fail-closed condition), the retry after a 0.02s sleep, the Z/X/x
handling, and `FileNotFoundError`/`ProcessLookupError` continuing silently. **Changed:** two things only.

1. **Attribution.** The fail-closed line becomes
   `uninspectable pid=390 comm=(sd-pam) reason=permission state=S`, where before it was
   `uninspectable pid=390 state=S`. `comm` is readable exactly when `fd/` is not, so this is one field of
   information that the oracle already had access to and was discarding.
2. **The documented mechanism**, in the module docstring: what `dumpable=0` is, that it is permanent rather than a
   race, and - the part a future reader most needs - that **while such a process exists, every liveness-bound
   consumer of this oracle will fail closed and reclaim NOTHING, and that this is EXPECTED rather than a fault.**

## Evidence, and one correction of my own

Driven on a **locally created** non-dumpable same-user process (`prctl(PR_SET_DUMPABLE, 0)` via ctypes), so the
class is reproduced on demand rather than depending on the ambient one:

| case | old oracle | new oracle |
|---|---|---|
| a real non-dumpable same-user process exists | `uninspectable pid=390 state=S` | `uninspectable pid=390 comm=(sd-pam) reason=permission state=S` |
| exit status with such a process present | **2** | **2** (identical - the decision did not move) |
| path exists, nothing holds it | **0** | **0** (the normal path does not regress) |
| path exists, a live process holds a file in it | **2** | **2** (still fail-closed) |

The probe cannot be the process *named* in the message, because the oracle exits on the **first** offending pid and
the ambient `sd-pam` is scanned first. What the probe proves is the `comm`-readability that makes the new field
possible, and that a non-dumpable process reproduces the condition rather than being a quirk of one `sd-pam`.

**A CORRECTION I OWE, RECORDED BECAUSE I MADE IT IN WRITING FIRST.** My opening comment on this bead claimed the
oracle *"conflates two causes and the message doesn't say which"*. **That was wrong.** The function already
classifies: `FileNotFoundError`/`ProcessLookupError` continue silently before the permission branch is reached, and
the permission branch retries and only then fails closed. The inference came from reading the printed line instead
of the code - the same error this lane has made three times - and the real gap was the smaller, specific one this
patch closes: attribution, and the reason the permission persists.

## Preimage and scope

| | |
|---|---|
| algorithm | `sha256` |
| preimage | `3faa3c10a8d7493f0abe069c1e0d4ca38b3e429664be730389132e05a651662f` |
| resulting | `008a8d23d9c19a69af9749387f8a94f52b2e8a924036a9e3fbcd0fb0721df267` |
| apply | `patch -p1 --fuzz=0` -> rc 0, zero rejects, byte-identical re-application; `py_compile` clean |

**`agents-pm4q`'s safety property is NOT weakened by this patch**, which is the boundary the bead set: this changes
what the oracle *reports*, not what it *decides*. **Install order is unconstrained** against `agents-pm4q` and the
`bin/fleet-check` patches: no file is shared with any of them.
