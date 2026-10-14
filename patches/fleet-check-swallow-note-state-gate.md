## patches/fleet-check-swallow-note-state-gate.patch

HUB-DELIVERY PATCH, **STACKED ON** `patches/fleet-check-swallow-note.patch` (the `agents-o7b8` artifact, landed in
`cd567f30`) - it is not a re-cut of it, so the landed artifact's bytes and blob are untouched. Closes the gap
`agents-nuyw` records, filed by the merger from that landing: the note was keyed to the **command shape** and never
to the **state**, so a row that is not a PASS could carry a sentence saying *"a PASS here may be unfounded"*.

## The shape/state relationship, MEASURED rather than argued

`bin/fleet-check` decides the state from the exit status alone:

    case $rc in 0) st=PASS;; 124|137|143|126|127|254|255) st=KILLED;; *) st=FAIL;; esac      # :430

and **every shape the detector accepts exits 0** (`true`, `:`, `/bin/true`, `exit 0`, a trailing `echo`, a trailing
`printf`). So **FAIL + swallowing shape is unreachable by construction** - and that is worth stating rather than
assuming, because the bead asks for exactly that row. Driven attempt: a config whose tail is a shape (`exit 0`)
records **UNKNOWN**, never FAIL, because the shape forces `rc=0` and the post-pass check then turns a silent PASS
into UNKNOWN.

**What IS reachable is the same defect on a different non-PASS state**, and it is what makes the fix necessary rather
than cosmetic:

| binary | `CHECK_FAST_CMD` | record state | `swallow_note` |
|---|---|---|---|
| **pre-fix** (this patch's base) | `true` | **UNKNOWN** | **PRESENT** - the defect, on a row that is not a PASS |
| post-fix | `true` | UNKNOWN | **absent** |
| post-fix | `echo gate-started; false \|\| true` | PASS | **present** - the row this note exists for, unchanged |
| post-fix | `echo gate-started; false` | FAIL | absent |

Each row is a real run against a temp repo, a private `HOME` and a private `FLEET_HEAVY_DIR`, read from the record's
own fields so state, command shape and note are visible together.

## The change

One line: `if [ -n "$_st_tail" ]; then` becomes `if [ -n "$_st_tail" ] && [ "$st" = PASS ]; then`, with the reason in
the comment above it.

**No reworded variant is emitted for the non-PASS states, deliberately.** The sentence exists to stop a **false
green**; a FAIL, KILLED, UNKNOWN, INCONCLUSIVE or STALE row is already not a green, so a second sentence there would
be noise where the signal is already correct - and the table above shows those rows are silent, which is the wanted
behaviour rather than a gap.

## Preimage, by algorithm and by value

| | |
|---|---|
| algorithm | `sha256` |
| preimage (this patch's DIRECT base: the `agents-o7b8` result, i.e. the deployed binary with `patches/fleet-check-swallow-note.patch` applied) | `d2cf41c7c0cea9f419e74a95cd40cdf6be4cebe4f46428de0e312fd8a9428ae7` |
| resulting | `0ea04af89f316f9789c5eb026134ef084d46b25bb438710c9a5e9b42315ca3d9` |
| apply | `patch -p1 --fuzz=0` -> rc 0, **zero rejects**, byte-identical re-application |

**Install order:** this stacks on `agents-o7b8`'s patch, which itself may sit on either side of `agents-dbit` (the two
commute - both orders produce the identical result `c85c2993c4751a0d`). Measured on the three-high stack:
`dbit -> o7b8 -> this` gives `7e6fdd0f4816bad0` and `o7b8 -> this -> dbit` gives `7e6fdd0f4816bad0` - the SAME hash, so
the commutativity survives the third patch rather than being assumed from the absence of rejects. The only fixed
requirement is **this patch after `fleet-check-swallow-note.patch`**.

**ADVISORY:** the underlying preimage was read from this VM's `~/fleet` mirror, which is behind the hub's origin
(`agents-x8ud`). The local drive is the evidence; confirm the hash before applying, and verify by the chain you
observe rather than against a stored number.

## A correction to my own earlier bound

The `agents-o7b8` hand-off said a clean reproduction must "clear `FLEET_LANE`". **That is wrong as written and I
measured it**: with `FLEET_LANE` unset the runner dies at `line 186: FLEET_LANE: FLEET_LANE not set`. The working form
is to point it at a lane that is not delivering - every row above ran with `FLEET_LANE=<sink>` - so the bound is
"point the fallback at a sink", not "unset it".
