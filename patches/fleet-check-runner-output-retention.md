## patches/fleet-check-runner-output-retention.patch — the gate record carries the runner's own output, or says it could not (agents-50p7)

A gate record names its runner output in `.log`, and the record's `tail` is a **positional 1200-byte slice** of
that log (`tail -c 1200`). Reproduced on the three trees this bead names (bf0e0f26, 8e9b4d39, ea353f7a): the
`.log` path each record names is **MISSING for all three**, and whether the runner's own `Ran N tests in Xs`
line happened to survive inside the tail was **luck** - the 077acd1c record has it, the other two do not (their
last 1200 bytes are preemption and re-queue chatter). So a reader could neither read the measurement nor
recover it: the record named a file that no longer existed AND did not carry the facts. Coord's shape decision:
make the record **self-contained**, or have it **say "runner output rotated"** - not "keep logs N days",
because retention is a promise someone else can break.

## The four hub-delivery fields

| field | value |
| **Artifact sha** | `patches/fleet-check-runner-output-retention.patch` — **4033 bytes**, sha256 `291eb792976b047c8ee4245501c8fbbf`, 2 hunks, 2 file-sections |
| **Exact base it expects** | `bin/fleet-check` = **51977 bytes**, sha256 `455e3b05d2dc172c2d2149dd47b33ac4`; `tests/fleet-gate-check.test.sh` = **181092 bytes**, sha256 `f3919068e04d9127` (both measured on the deployed `~/fleet` copies on this VM) |
| **Applies** | `patch -p1 --fuzz=0` from a fleet checkout: rc 0, no `.rej`, no `.orig`; result `bin/fleet-check` **53201 bytes** sha256 `c9d265cefe1b18d8f8aeba0dd25ba0d0`, `tests/fleet-gate-check.test.sh` **183027 bytes** sha256 `36cf49dbaa5c9ec0`; both `bash -n` clean |
| **What it does** | composes a bounded `RUNNER OUTPUT` block into the record's existing `tail` at write time, and adds three assertions to the suite (section 23-50p7) |

## The change, in the record's existing idiom

The writer already composes a synthetic tail for the FAIL case (`tail="FAILURES:\n…\n\nTAIL:\n…"`), so this
extends that idiom rather than adding a field or a reader: at write time, read the `runner output -> <path>`
line the runner itself printed, take the last `Ran N tests in Xs` line and the `OK`/`FAILED` verdict out of that
file, and append them to `tail` as

```
RUNNER OUTPUT (<path>):
Ran 7 tests in 1.234s
OK
```

When the runner named a path that is now gone, the block says **`RUNNER OUTPUT: rotated (the log named <path>,
which no longer exists)`**; when the log names no runner-output path at all, **`RUNNER OUTPUT: not captured (the
log names no runner-output path)`**. No new JSON key, no new consumer, bounded growth: measured tails go from
1199 bytes to 1273 (carrying the measurement) and 1297 (saying rotated).

## Evidence: red without the fix, green with it, in the same fixture

Driven through the suite's own seams - `CHECK_OVERRIDE` to swap the tool, `check()` (which sets a PRIVATE
`FLEET_HEAVY_DIR` and priority 0), and `HOME="$ROOT/home"` so no shared cache is touched - with a stubbed
runner that writes 60 lines of chatter after its `runner output ->` line, which is exactly the shape that
defeats the positional tail:

| tool | record `tail` | carries `Ran 7 tests in 1.234s` | says `rotated` |
| pristine (fix absent) | 1199 B | **no** | no |
| patched | 1273 B | **yes** | no |
| patched, runner output deleted | 1297 B | - | **yes** |
| **the three assertions** | | **pristine: 0 passed, 3 failed** | **patched: 3 passed, 0 failed** |

So the assertion fails by name without the fix (`23-50p7-a`), and the CONTROL that stops it being satisfied by
a tool that never reports anything is `23-50p7-c`, the rotated case.

## Composition with the in-review branch-provenance patch

`patches/fleet-check-branch-provenance.patch` (agents-npyn) touches the same two files and is in review. Applied
in **both** orders to a fresh tree, npyn and this artifact both return rc 0 with no rejects and no residue, and
the combined `bin/fleet-check` passes `bash -n`; their hunks are in different regions (npyn's at the `--status`
overlay and the start record, this one at the tail composition). Byte-identical results either way, so the hub
may install them in whichever order it prefers.

## Boundary

A patch **delivery artifact** in `patches/`, not installed `~/fleet` code: cut against the deployed files' exact
bytes and verified in /tmp copies only. Nothing was installed under `~/fleet`, and the fixture records lived
under a private `HOME` so the shared cache was never written.
