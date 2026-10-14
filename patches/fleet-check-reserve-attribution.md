## patches/fleet-check-reserve-attribution.patch — a cache re-serve is recorded inside the record, and absence says UNRECORDED (agents-dbit)

A cached verdict could be re-served to any number of lanes without the record saying so. `bin/fleet-check`
prints the provenance it knows (`ran by <lane> at <at>`) at the cache-hit branch (`:294`, and the FAIL branch
below it) and then writes **nothing** to the record: `reserves` did not exist. So one lane's evidence silently
became another's - the defect coord decided the semantics for, choosing the vocabulary the line already prints
and requiring the attribution **inside the existing record** rather than a parallel optional field, with
absence **explicit**.

## The four hub-delivery fields

| field | value |
| **Artifact sha** | `patches/fleet-check-reserve-attribution.patch` — **3186 bytes**, sha256 `def4441cea3e2b7666a94f09a2f6cc1f`, **1 hunk**, one file-section |
| **Exact base it expects** | `bin/fleet-check` = **51977 bytes**, sha256 `455e3b05d2dc172c2d2149dd47b33ac4` (measured on the deployed `~/fleet` copy on this VM) |
| **Applies** | `patch -p1 --fuzz=0`: rc 0, no `.rej`, no `.orig`, producing **53752 bytes**, sha256 `db61bbaa6bf58c24` - byte-for-byte the tree the evidence below was driven on; `bash -n` clean |
| **What it does** | both cached-verdict branches now write `.reserves` / `.reserved_by` / `.reserved_last` into the record in place, and the line they print names the re-serves. Adds fields only: **no existing field changes type** |

## The change, in the file's own idiom

The in-place write is not invented: the `RUNNING` branch three lines below already mutates the record with
`jq '<filter>' "$rec" > "$rec.tmp" && mv "$rec.tmp" "$rec"`. The new write is the same shape, one line, with a
single-quoted filter. The fields mirror the vocabulary the cached line already prints (`lane`, `at`):

```json
"reserves": 2, "reserved_by": {"impl-b": 1, "impl-c": 1}, "reserved_last": {"lane": "impl-c", "at": "..."}
```

`reserves` counts re-serves **this record was able to record**; the printed line therefore says "recorded",
because a count that is true but misleading is the same defect as no count. When the record carries no count
the line prints **`UNRECORDED`** with both ways that arises named - because absence must not read as zero.

## Evidence: red first, then green, driven rather than read

Stub harness, private `HOME` (never the shared cache), one fixture repo asked twice so both asks share a tree:

| case | tool | record | printed line |
| A | pristine | `reserves` **ABSENT** | no attribution at all (one plain cached-PASS line) |
| B | patched, 2nd lane | `reserves=1, by={impl-b:1}` | `Re-serves recorded: 1 time(s) by impl-b=1, last by impl-b at …` |
| B | patched, 3rd lane | `reserves=2, by={impl-b:1, impl-c:1}` | `Re-serves recorded: 2 time(s) by impl-b=1, impl-c=1, …` |
| C | `--status` on B | the same fields | any reader sees them, with no parallel store to drift |
| D | patched, record dir unwritable | write cannot happen | `Re-serves recorded: UNRECORDED (no reserve count in this record: it was written before reserve attribution, or the record could not be updated)` - and the cached verdict is still reported, because the verdict is valid and only the attribution is unrecorded |

## Two faults in my own first attempt, both found by driving it

1. **The write silently failed and my own `2>/dev/null` hid it.** The first patch built the redirect as part
   of the `jq` argument, so `jq` received the target path as a file argument; `bash -x` traced it and the line
   reported `No such file or directory`. The suppression is gone from the final patch for that reason: a write
   this important must not be able to fail quietly.
2. **Its absence message was false in one of the two cases.** With the record unwritable the first version
   printed "this record predates reserve attribution", which is untrue there - the record is not old, the
   update failed. The final wording names both causes, and D above is the case that shows it.

## Composition and what is deliberately absent

Composes with `patches/fleet-check-branch-provenance.patch` (agents-npyn, not in main) in **both orders**: rc
0, rc 0, no rejects either way, different regions of the same file. This artifact touches `bin/fleet-check`
**only**. It adds no assertion to `tests/fleet-gate-check.test.sh` even though that file is the natural home,
because `patches/fleet-check-runner-output-retention.patch` (agents-50p7, in the hub's install queue) inserts
its own section immediately before the same summary line - two insertions at one anchor are not
order-independent, and an artifact that silently half-applies is worse than one that says what it leaves out.
The control for this change is therefore the driven table above, red first; a suite assertion can follow once
50p7 is installed, against its result, as a small follow-up rather than a collision.
