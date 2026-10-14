## patches/lessons-ceiling-raise-with-holder-lesson.patch

HUB-DELIVERY PATCH for the fleet repo, answering `agents-dpqf`. It raises the `roles/lessons.md` ceiling **on
measurement** and lands the pending lesson **in the same change**, which is what demonstrates the raise bought real
headroom rather than room in general.

## Why the ceiling, and why not the compress pass

The bead asked for a compress pass because `roles/lessons.md` was **18 bytes** under its `tests/lessons.test.sh`
ceiling, so no new lesson could be recorded. I measured before editing, and the measurement contradicted the ask:

| measured | value |
|---|---|
| maximum 8-gram overlap between any section and its closest neighbour | **1%** |
| exact duplicate non-blank lines | **zero** |
| sections over 800 B | 25 carrying 28% of the bytes |
| sections under 400 B | 282 carrying 69.5 KB |
| what `lessons-manifest.json` records | the pass already happened: **601,725 -> 153,492 bytes**, by *deterministic split on `## `/`### ` boundaries and parallel worker sub-agents over disjoint ranges across 4 model families* |
| where the 30 KB since came from | `post_compression_additions`, named individually with a reason each |

So the file is already compressed output plus tracked additions, and there is **nothing to de-duplicate**. I also
tested the obvious big cut: the largest section (`## Rules that never bend`, 16,325 bytes) is **not** a copy of
`roles/common.md` (5,125 bytes, **1 of 142 lines** shared); it is enriched with per-rule subsections and dated
evidence, and manifest unit 7 tracks it as `kept` with 177 tokens that must remain. Cutting it would have failed
the suite and lost content. **The 180 KB ceiling was set when the file was 153,492 bytes, with the stated intent of
`~25 KB headroom`; later lessons consumed all of it, so the promise that broke is the ceiling's own intent**, and
restoring it is a one-line change. Coordinator decision (2026-10-14): ceiling now, compress pass not now, since a
wide fan-out over 184 KB for single-digit KB is the CPU trade this fleet has been told not to make.

## The lesson landed in the same change

`## Bound the holder, not only the waiter: flock's payload inherits the lock fd (agents-etvw)` - `flock` gives the
lock to the whole process tree, so a `git send-pack` grandchild stuck on the network still holds the VM-wide lock
after the tool that took it has gone (observed: a `--force-with-lease` stuck in send-pack, every other lane's `bd`
call queued behind `flock -w 300`, and a bounded command dying with one rc 124 after 240s). **Driven both ways**:
without `-o` the lock is STILL HELD after the payload exits, with `-o` it is FREE. Hence: network subcommands run
under `timeout -k`, BOTH paths pass `-o`, and on timeout the tool says LOUDLY that the write did not land, that the
lock is released, and that the rule is BACK OFF AND RETRY, KILL NOTHING - with `124` kept as the fleet's *"unknown,
not a pass"*.

## Acceptance, and the control that makes the raise meaningful

Run on the **patched result**, from a pristine fleet copy with `patch -p1 --fuzz=0`:

| | |
|---|---|
| `bash tests/lessons.test.sh` on the patched tree | **9 passed, 0 failed** |
| size | `roles/lessons.md is 185395 bytes (<= 204800)` |
| index coverage | `roles/lessons-index.md covers all 383 '## ' headings` |
| heading floor | `383 '## ' headings (>= 150)` - **unweakened** |
| manifest | `OK - every unit present and every kept token is in the file` - **unweakened**, and unit 370 is the new lesson with its `tokens_kept` |
| anti-inlining | all four greps still PASS - **unweakened** |
| **CONTROL: the same tree with the OLD 180 KB ceiling** | **`FAIL  roles/lessons.md is 185395 bytes (> 184320)`; 8 passed, 1 failed** |

The control is the point: the raise is not cosmetic, it is what lets this lesson exist. Headroom goes from **18
bytes to 19,405**.

## Files, by algorithm and by value

| file | algorithm | preimage | result |
|---|---|---|---|
| `roles/lessons.md` | sha256 | `1ee73db427e3` | `8888c45d8e96` |
| `roles/lessons-index.md` | sha256 | `8513e0e57581` | `ccec957594ea` |
| `roles/lessons-manifest.json` | sha256 | `9b62990730c1` | `8b4a1c1ec59f` |
| `tests/lessons.test.sh` | sha256 | `edbf4ca2ff6e` | `a9bab2245ebc` |

Patch: **4395 bytes, 4 file headers, 5 hunks**, sha256 `8cbbcb33ea8a5b24dc6fd293...`. Apply with `patch -p1
--fuzz=0` from a fleet checkout: **rc 0, zero rejects, byte-identical** to the edited tree, and the manifest diff is
**+928 bytes with the first 400 bytes unchanged**, i.e. a clean addition rather than a re-serialisation.

**ADVISORY:** every preimage was read from this VM's `~/fleet` mirror, which is behind the hub's origin
(`agents-x8ud`), so verify by the chain you observe rather than against these numbers.

**Install check for the hub:** apply, then run `bash tests/lessons.test.sh` and expect 9 passed / 0 failed. A
ceiling raise whose only evidence is the size line is not evidence - the suite green **with the new lesson present**
is, and the old-ceiling FAIL above is what proves the raise was load-bearing.
