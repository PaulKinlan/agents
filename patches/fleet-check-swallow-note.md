## patches/fleet-check-swallow-note.patch

HUB-DELIVERY PATCH for `bin/fleet-check`. It is the **deployed half** of `agents-xxgk`, tracked as `agents-o7b8`: the
in-repo half (`tools/check-cmd.sh`) flags a swallowing config **where the config is read**; this half puts a **note in
the record after a PASS**, because that is where a false green travels.

## The problem, and why it is not merely hidden

A config command that **swallows its own failure AND prints output** is recorded as **PASS with no diagnostic**. By the
time the verdict is recorded there is **no exit status left to observe** - the information is **gone, not hidden**:

    CHECK_FAST_CMD="echo gate-started; false || true"

`false` fails, `|| true` discards the status, and `echo` prints a line that looks like the gate ran. The runner sees
`rc=0`. The silent-only variant (`... 2>/dev/null || true`) is already caught by `fleet-opl3`, which turns a PASS with
nothing after the marker into UNKNOWN, so **the residual needs swallowing AND output**.

## Driven, on the deployed binary, in three directions

Each run used a throwaway repo, a private `HOME`, and a **private `FLEET_HEAVY_DIR`** so **no live heavy slot** was
touched. The runner is detached, so each record was read after its worker reached a terminal state.

| binary | config | record | `swallow_note` |
|---|---|---|---|
| **deployed** (preimage below) | `echo gate-started; false \|\| true` | `state=PASS rc=0` | **absent** - the defect as reported |
| **patched** | `echo gate-started; false \|\| true` | `state=PASS rc=0` | **present**, naming the swallowing tail |
| **patched** | `echo gate-started; false` (CONTROL: no swallow) | `state=FAIL rc=1` | **empty - stays silent** |

The control matters in both directions: it shows the note is not a blanket annotation on every PASS, and that the same
harness still records a real failure as a failure. The note quotes the **TAIL** (`'true'` in the example above), not the
whole command, because that is what the reference implementation prints - `tools/check-cmd.sh`'s `swallowing_tail()`,
which the detector here is a port of, "prints the swallowing TAIL, or nothing".

## What the patch changes

Three hunks, all inside `bin/fleet-check`:

1. A **self-contained** detector inside `finish()`, with `swallowing_note` computed from the record's own `cmd` field.
   It is deliberately not factored into a helper: `finish()` is **extracted and run in isolation by an arm**, and the
   file's own comment records that a dependency on anything outside the fragment is the defect that family finds.
2. `.swallow_note=$swnote` on **both** record writers (the `cov_ok` and non-`cov_ok` paths), so a reader of the record
   sees it and not only a reader of the notification.
3. The note in the **notification body**, beside `$note` and `$cov_note` (`:621`), which is where an operator reads
   `[check] ... : PASS (...)`.

It is a **note**: nothing is refused, no verdict changes, and a config that does not swallow produces an empty string.
This follows the ruling on `agents-xxgk` - do not resurrect the pre-run parser; **flag the shape, change no value**.

## Preimage, by algorithm and by value

| | |
|---|---|
| algorithm | `sha256` |
| preimage | `455e3b05d2dc172c2d2149dd47b33ac4d77266b57d45765506d2e2b362c10498` |
| resulting | `d2cf41c7c0cea9f4...` |
| apply | `patch -p1 --fuzz=0` -> rc 0, **zero rejects**, and the re-applied file is byte-identical to the copy this patch was generated from |

**ADVISORY:** this preimage was measured on **this VM's `~/fleet` mirror, which is behind the hub's origin**
(`agents-x8ud`: `bin/bd` `8b1e345` vs the hub's `d07d805`). The local drive above is the evidence; the hub should
confirm the preimage hash before applying and **verify by the chain it observes**, not against a stored number.

## Install order (measured, not assumed)

`agents-dbit` (`patches/fleet-check-reserve-attribution.patch`) documents the **same** raw preimage, so the two were
applied in both orders on identical copies of the deployed binary:

| order | rc | rejects | resulting sha256 (first 16) |
|---|---|---|---|
| this patch alone | 0 | 0 | `d2cf41c7c0cea9f4` |
| `agents-dbit` alone | 0 | 0 | `db61bbaa6bf58c24` |
| this patch, then `agents-dbit` | 0, 0 | 0 | `c85c2993c4751a0d` |
| `agents-dbit`, then this patch | 0, 0 | 0 | `c85c2993c4751a0d` |

**The two orders produce the IDENTICAL result hash**, which is commutativity shown by content rather than by the
absence of a reject message - so this patch may be installed **before or after** `agents-dbit`, and either order
lands on `c85c2993c4751a0d`. The hunks are disjoint by construction: `agents-dbit` works around `:339` and this one
around `:511`. The patch that **does** require a fixed position is `patches/fleet-check-rerun-failed-tree.patch`,
which needs `agents-dbit` first. Note that the **rerun-ruling patch**
(`patches/fleet-check-rerun-failed-tree.patch`) is the one that **requires** `agents-dbit` first.
