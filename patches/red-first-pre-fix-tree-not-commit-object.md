## patches/red-first-pre-fix-tree-not-commit-object.patch

REPO WORK for `tools/red-first.sh`, answering `agents-erft` (P2, driven by impl-f6du in a read-only sweep and handed
over rather than patched). Tooth 2's marker derivation queried the wrong revision object.

**STATE OF THIS DELIVERY: the FIX is verified and driven both ways, AND the DISCRIMINATING TEST is written and
already driven three ways - it is in `tests/test_red_first.py`, and the section "The discriminating test IS included,
and it was driven three ways" below records the drive. This line previously read "the DISCRIMINATING TEST is not yet
written", which was true mid-delivery and false once the test landed (agents-7mp1); a stale "not yet written" sends a
reader away from the very evidence this artifact is built on, so it now states what was delivered rather than what
was still outstanding.**

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

## The discriminating test IS included, and it was driven three ways

It lives in `tests/test_red_first.py`, in the suite that is the tool's only one and whose fast-gate arm records a
measured **2.5s** - so it costs no heavy slot. The fixture is the point, and the candidate set is narrower than it
looks: the derivation filters added lines with

    tools/red-first.sh:442   sed -n 's/^+[^+[:space:]].*/&/p'

which admits **ONLY NON-INDENTED added lines** - the added top-level `def`s - and **excludes indented bodies**. So the
marker the pre-fix MESSAGE must mention is the added **`def` line**, not the indented body line. Both my first python
test and my second shell fixture nominated the indented line, which is exactly why neither reproduced the defect: the
sole real candidate stayed absent from the commit object and the tool behaved correctly.

**Driven three ways, all on the same fixture (identical file contents; only the pre-fix commit message differs):**

| drive | tool | result |
|---|---|---|
| 1 | **patched** | **OK** - no "pure test addition", marker derived from the tree, verdict PASS |
| 2 | **`origin/main`'s tool** | **FAILED** - and it printed `VERDICT: PASS (all four teeth satisfied)` while the assertion failed |
| 3 | **patched, whole suite** | **OK** - the pre-existing cases stay green, so the fix is not bought with a regression |

Drive 2 is the one that matters: the failing run shows the tool asserting a **PASS** for a change whose implementation
source it never checked - the false statement about what was checked, in the same run as the false verdict.

The fixture carries its own defensive assertion that it is testing what it claims: exactly **one** non-indented added
implementation line, and it is `def multiply(a, b):`. A test whose fixture cannot be shown to contain the candidate is
a test about nothing, so the fixture proves itself before the behaviour is asserted.
