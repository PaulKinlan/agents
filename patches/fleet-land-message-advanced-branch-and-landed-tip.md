# fleet-land-message: name which side moved, and accept the tip that was actually gated

- **Bead:** `agents-wwss`. **Status:** PARKED HUB DELIVERY - the payload targets `~/fleet`, so the hub applies
  it; it is not for landing in the agents repo.
- **Patch:** `patches/fleet-land-message-advanced-branch-and-landed-tip.patch` (145 lines, sha256
  `cd9776a4d828b007…`), against pristine `~/fleet` copies (`bin/fleet-land-message`,
  `tests/fleet-land-message.test.sh`). Applies with `patch -p1 --fuzz=0`.

## The bead's premise is wrong, and this patch does not implement it

The bead says `--gate` refuses a batch union because "the helper appears to expect the gate sha to BE the
branch tip, whereas a batch landing's sha is a MERGE whose SECOND PARENT is the tip". The helper does not do
that. Its first check is an **ancestor** check:

    if git merge-base --is-ancestor "$target_ref" "$gate_commit"; then
      gate_identity="commit ref $target_ref (ancestor of $gate_commit)"

A merge that contains the branch tip passes it - that is exactly the batch-union shape.

Reproduced hermetically in a throwaway repo:

| case | shape | `git merge-base --is-ancestor <branch> HEAD` |
|---|---|---|
| **A** | union merge of the branch into main | **TRUE** - `HEAD^2` is the branch tip, so the helper accepts it |
| **B** | one commit added to the branch AFTER the merge | **FALSE** - and that produces the message the merger saw |

**So the real cause is a branch that ADVANCED past the merge, not a batch union.** In the measured instance the
batch landing of merge `2b23cbb` had second parent `743000b` while the branch tip was `056c1e3`, with the ryw9
split, the h006/3avt parked-delivery patches and merges of other lanes in between. The guard was RIGHT to
refuse. (And part of that was lane hygiene rather than tooling: parked-delivery passengers were riding the lane
branch - the problem that was fixed by re-cutting that work onto a clean branch.)

What *is* wrong is that the refusal cannot be told apart from having named the wrong branch, and that a valid
gate record cannot be written at all once the branch has moved.

## The change (two edits)

### 1. Name which side moved

The refusal now prints the evidence instead of one line that covers three different situations:

    fleet-land-message: REFUSING: --gate <sha> does not contain <branch> (<ref>)
    fleet-land-message:   branch tip: 056c1e3
    fleet-land-message:   the gate commit is a MERGE whose landed tip is 743000b
    fleet-land-message:   <branch> is 17 commit(s) beyond that landed tip
    fleet-land-message:   -> THE BRANCH ADVANCED after that merge. Name the branch you actually landed, or
                            pass --landed-tip 743000b to record the gate for the tip that was gated.

Diagnosis, not policy: the guard is unchanged, and it now says which of the three situations you are in.

### 2. `--landed-tip <sha>` - record the gate for the tip that was gated

When the caller names the tip it actually merged, the containment check is performed against **that** tip
instead of the branch's current tip:

    fleet-land-message --gate <merge-sha> --landed-tip <tip> <bead> <branch> [...]

**The guarantee is unchanged**: the gate commit must still contain the tip being recorded. What changes is that
a branch moving *after* the merge no longer makes a correct gate record impossible to write. The record says
`explicit landed tip <sha> (ancestor of …)` so the basis of the claim stays visible.

## Verification (driven, and a discriminator rather than a pin born green)

- **No regression**: the full fleet suite is **280 passed / 0 failed** on pristine and **290 passed / 0 failed**
  with the patch (the ten new assertions included).
- **Discriminator**: against the PRISTINE helper the suite reports **283 passed / 7 failed**, and all seven
  failures are this patch's new cases - the diagnosis lines (40b-40e), the accepted `--landed-tip` (40f, 40g)
  and the still-refused bad tip (40i). 40a and 40h are guards that pass on both revisions by design.
- **Applies and is byte-identical**: `patch -p1 --fuzz=0` on a fresh copy of the pristine files reproduces my
  working copies byte for byte, and the patched verification tree's suite is 290/0.
- **Independence**: the new cases build their own throwaway repository, so they cannot be affected by the state
  the earlier cases leave behind - and they run *inside* the suite's counted region (an earlier draft appended
  them after the summary line, where a failure would not have been counted; that was fixed before this patch).

## What this does NOT do

- **It does not make the guard permissive.** `--landed-tip` is not an override: a tip that is not in the gate
  commit is still refused (case 40i).
- **It does not fix the second half of the bead.** "A refusal from the amend step must STOP THE SCRIPT" is about
  the **caller's** lines (the merger's wrapper), not this helper - the helper neither amends nor pushes. That
  half needs a process bead against the wrapper, and a patch here could not enforce it.
- **It does not weaken the gate-record property.** The record still names a commit that was gated.

## Rollout

1. Apply the patch to a checkout of `~/fleet` (`patch -p1 < patches/fleet-land-message-advanced-branch-and-landed-tip.patch`).
2. Run the suite: `bash tests/fleet-land-message.test.sh` - expect 290 passed, 0 failed (with
   `LM_OVERRIDE=/tmp/<copy>/bin/fleet-land-message` if you want to test against a copy before deploying).
3. Nothing else changes: no config, no per-repo install (unlike `agents-kxbv`, this is one file in the fleet
   checkout that every lane already uses).
