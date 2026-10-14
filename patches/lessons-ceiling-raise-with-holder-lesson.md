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

RE-CUT 2026-10-14, BEFORE THE HUB APPLIED THE FIRST VERSION, because the first version of this lesson encoded the
OPPOSITE of the ruling: it said BOTH paths pass `-o`. The hub held its append, measured its own applied tree, and
found that `bin/bd` in the elu6 -> nbka -> u2st chain has exactly two `flock` calls - `flock -n "$fd"` and a
backgrounded `timeout -k 2 "$wait" flock "$fd" waiter` - and that NEITHER passes `-o`; the file documents the fd
inheritance as INTENTIONAL and the waiter as never owning the fd. So the measurement in this lesson was right and
the conclusion drawn from it was wrong, and the corrected lesson is the harder sentence. The ceiling raise, the
index entry, the manifest unit and the four unweakened checks are unchanged; the corrected text is 2725 bytes
against the first version's 1093, which is why the size and control rows below are re-measured rather than carried
over.

`## Bound the holder, not only the waiter: flock's payload inherits the lock fd (agents-etvw)` - `flock` gives the
lock to the whole process tree, so a `git send-pack` grandchild stuck on the network still holds the VM-wide lock
after the tool that took it has gone (observed: a `--force-with-lease` stuck in send-pack, every other lane's `bd`
call queued behind `flock -w 300`, and a bounded command dying with one rc 124 after 240s). **The inheritance is what
makes the lock an exclusion, so it is the thing to keep rather than tidy away**: the payload runs in its OWN process
group and the bound kills that group, so the last fd closes BY CONSTRUCTION and the release is real rather than
announced. **`-o` is the tempting wrong answer**, and the measurement is exactly why it tempts - driven both ways,
WITHOUT `-o` the lock is still held after the payload exits and WITH `-o` it is free; that passes the BOUND test
while removing the guarantee the lock exists for (agents-ttxh). **A stale lock that believes it is free is a lock
nobody reclaims.** `timeout -k` bounds the WAITER; the WORK holds the fd; on timeout the tool says loudly that the
write did not land, that the lock is released (true by construction: the group is dead), and that the rule is BACK
OFF AND RETRY, KILL NOTHING - with `124` kept as the fleet's *"unknown, not a pass"*.

The lesson also carries the general form of the mistake that produced the leak, because the same shape appeared
three times in one day: **a control is built for the case that prompted it, and the case that prompts it is always
the FAILURE** - so the SUCCESS path is the one nobody drives. The three instances: a gate fixture that retained its
evidence only on FAILURE and therefore proved nothing about the runs that passed; a disk-hygiene timer reporting
success while `/tmp` filled; and this lock, released correctly on the timeout path and LEAKED BY A SUCCESSFUL PUSH
(the watchdog's `sleep` inherited the fd, and killing a subshell does not kill its child). The lesson names the CHECK
rather than only the hazard: after a push that returns 0, the lock must be free immediately and no fixture process
may still hold the fd.

## Acceptance, and the control that makes the raise meaningful

Run on the **patched result**, from a pristine fleet copy with `patch -p1 --fuzz=0`:

| | |
|---|---|
| `bash tests/lessons.test.sh` on the patched tree | **9 passed, 0 failed** |
| size | `roles/lessons.md is 187027 bytes (<= 204800)` |
| index coverage | `roles/lessons-index.md covers all 383 '## ' headings` |
| heading floor | `383 '## ' headings (>= 150)` - **unweakened** |
| manifest | `OK - every unit present and every kept token is in the file` - **unweakened**, and unit 370 is the new lesson with its `tokens_kept` |
| anti-inlining | all four greps still PASS - **unweakened** |
| **CONTROL: the same tree with the OLD 180 KB ceiling** | **`FAIL  roles/lessons.md is 187027 bytes (> 184320)`; 8 passed, 1 failed** |

The control is the point: the raise is not cosmetic, it is what lets this lesson exist. Headroom goes from **18
bytes to 17,773**. The control was re-run for THIS recut rather than carried over, and its failing line is quoted
above verbatim: the same tree under the old ceiling fails on SIZE, in the same run in which the patched tree passes.

AND ONE THING ABOUT HOW THE MANIFEST FIGURES WERE UPDATED, because a value-based edit would have corrupted another
lesson: `"bytes_after": 1093` occurred THREE times in `roles/lessons-manifest.json`, and one of them belongs to a
different unit (id 104, "Runaway CPU hogs inside a lane's tree...", whose bytes_before AND bytes_after are both
1093 by coincidence). Matching on the value would have rewritten an unrelated record, so the two figures belonging
to this lesson were matched by their HEADING context instead, and id 104 still reads 1093. That is the same family
as the rest of tonight's corrections: a match that depends on a value rather than on the thing the value describes.

## Files, by algorithm and by value

| file | algorithm | preimage | result |
|---|---|---|---|
| `roles/lessons.md` | sha256 | `1ee73db427e3edb018f966c57b80aa8b61ece9c99b7a48a3dc9755f3391856f1` | `6b0b29709bd338c16ad5cd1204eab92c87913ab675449e4b485501400b5d90c4` |
| `roles/lessons-index.md` | sha256 | `8513e0e575819e10f87dc6ebb5e93678b4701ba30500cac418d90f5b030d798f` | `ccec957594ead98093985608b321c4986e371bfe1e364034922109ff4531d68a` |
| `roles/lessons-manifest.json` | sha256 | `9b62990730c14bf304fbe1adbc1209b79a1322a78bcc1c5c77680e2bad7ee722` | `ccf9610df099bc9bd35916ab3ff1223edd05cea00636aca185dcde0819cb9b98` |
| `tests/lessons.test.sh` | sha256 | `edbf4ca2ff6e372cf986bfb2536413c1643176ac7eb9d58467b6e368cfc6e9d6` | `a9bab2245ebcb4c140e809bc6b00c2fc27d893c4338615ffbb1a7ed679edf740` |

Patch: **5755 bytes, 4 file headers, 5 hunks**, sha256
`d63851260ea8c7c22674ebee63c1011d47dd87ecb674aff65ad9d3f656f6ed3b`. Apply with `patch -p1
--fuzz=0` from a fleet checkout: **rc 0, zero rejects, byte-identical** to the edited tree (re-verified for this
recut, not carried over), and the manifest diff is **+928 bytes with the first 400 bytes unchanged**, i.e. a clean
addition rather than a re-serialisation. The preimages above are the SAME preimages the first version recorded
(`1ee73db427e3`, `8513e0e57581`, `9b62990730c1`, `edbf4ca2ff6e` when shortened), which is how this cut is known to
have been made against the same base rather than a moved one.

**ADVISORY:** every preimage was read from this VM's `~/fleet` mirror, which is behind the hub's origin
(`agents-x8ud`), so verify by the chain you observe rather than against these numbers.

**Install check for the hub:** apply, then run `bash tests/lessons.test.sh` and expect 9 passed / 0 failed. A
ceiling raise whose only evidence is the size line is not evidence - the suite green **with the new lesson present**
is, and the old-ceiling FAIL above is what proves the raise was load-bearing.
