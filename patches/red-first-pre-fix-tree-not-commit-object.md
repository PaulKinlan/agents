## patches/red-first-pre-fix-tree-not-commit-object.patch

REPO WORK for `tools/red-first.sh`, answering `agents-erft` (P2, driven by impl-f6du in a read-only sweep and handed
over rather than patched). Tooth 2's marker derivation queried the wrong revision object.

**STATE OF THIS DELIVERY: the FIX is verified and driven both ways; the DISCRIMINATING TEST is not yet written, and
this write-up says why rather than implying coverage it does not have.**

## The defect, confirmed at the line

`tools/red-first.sh:450`, inside the `EXPECT_ABSENT` auto-derivation, read:

    if ! git show "$PRE_FIX_SHA" | grep -Fq "$cleaned" 2>/dev/null; then

`git show <sha>` prints the commit **MESSAGE** and the diffstat/diff, so this asks whether the marker appears anywhere
in the commit object - not whether it is in the **PRE-FIX SOURCE TREE** that tooth 2 claims to check. A pre-fix commit
message that happens to mention a line the delta adds LATER therefore makes that valid marker look present pre-fix;
when every candidate is rejected that way, `EXPECT_ABSENT` stays empty and the tool prints at `:563`
*"no allow-listed implementation-source delta to verify (pure test addition)"* for a change that really does alter the
implementation source - **a false statement about what was checked, printed alongside `VERDICT: PASS` at `:736`.**

## Driven with a control, and the drive was corrected twice before it was trusted

Two fixtures with **IDENTICAL file contents**, differing **only in the pre-fix commit message**:

| arm | token in pre-fix **TREE** | old form (`git show`) | new form (`git grep` on the tree) |
|---|---|---|---|
| **control** - honest message | 0 | ABSENT → marker accepted (correct) | not in tree → accepted |
| **mutant** - message mentions it | **0** (identical contents) | **FOUND → marker rejected, `EXPECT_ABSENT` empty (the defect)** | not in tree → **accepted (the fix)** |

**Provenance, which is what makes it the defect rather than a coincidence: `message=1 tree=0`** - the old form's
match comes from the message, and the tree never contained the token. f6du's named falsifier was tested rather than
assumed: plain `git show` does **not** exclude the message, so the finding is not wrong on that axis.

**Two of my own drive failures, recorded because they are the reason the result is trustworthy:** the first drive used
an **empty pattern** (`"$cleaned"` where the variable is `CLEANED`), so `grep -Fq ""` matched everything and reported
the defect for the wrong reason; the second put the token in the **change** commit's message rather than the
**pre-fix** commit's, which made the falsifier appear to fire. Both were caught by reading my own output rather than
its verdict.

## The fix: two parts

1. **Ask the PRE-FIX TREE, bounded to the same implementation paths the candidates came from:**
   `git grep -Fq "$cleaned" "$PRE_FIX_SHA" -- "${IMPL_PATH_FILTERS[@]}"`.
2. **A positive control at the `:563` site:** "pure test addition" is a claim about the CHANGE, so it may only be made
   when there was no allow-listed implementation-source delta at all. If the bounded impl-source diff is non-empty
   (`${diff_additions:-}`, computed at `:442`) and `EXPECT_ABSENT` is still empty, the DERIVATION failed - fail
   loudly instead of printing the false phrase. `${diff_additions:-}` is deliberate: when `--expect-absent` is
   supplied the block that sets it never runs, and this file executes under `set -u`.

| | |
|---|---|
| algorithm | `sha256` |
| preimage | `c4dd988304df95821a083255c3da9962abf95839...` (`tools/red-first.sh`, 31776 bytes) |
| result | `62539e5d50989eef6809d88bd6bf1910620dce2e...` - **differs from the preimage**, asserted |
| patch | **2370 bytes, 2 hunks**, non-empty asserted |
| syntax | `bash -n` on the patched file: clean |
| driven | patched predicate: **mutant arm now ACCEPTED** (was wrongly rejected), **control arm unchanged** |

## Why the discriminating test is NOT here yet, in detail

The acceptance criterion is a test that **fails before and passes after**. My first attempt passed on **both** the
patched and the unpatched tool, so I reverted it rather than shipping a test that reads as coverage while proving
nothing. Diagnosing that produced a fact worth recording, because it decides what such a fixture must contain:

    tools/red-first.sh:442   sed -n 's/^+[^+[:space:]].*/&/p'

The candidate filter **admits only NON-INDENTED added lines** - the added top-level `def`s - and **excludes indented
bodies**. So the marker a fixture must arrange to be "mentioned by the pre-fix message" is the added **`def` line**
(`+def multiply(a, b):`), not the indented body line. Both my python test and my second shell fixture nominated the
indented line, which is why neither reproduced the defect: the sole real candidate was still absent from the commit
object and the tool behaved correctly.

The next step is therefore narrow and known: build the fixture whose pre-fix message mentions the added **`def`**
line, run the real tool with **no `--expect-absent`**, and assert on the tool's **observed stdout** that
"pure test addition" does not appear - then confirm it fails against `origin/main`'s tool. That belongs in
`tests/test_red_first.py`, whose fixture already copies the real tool into a temporary repo and whose fast-gate arm
records a measured 2.5s cost for the suite.
