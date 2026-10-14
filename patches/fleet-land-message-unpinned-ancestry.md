## patches/fleet-land-message-unpinned-ancestry.patch (agents-qzy3)

A clearance that was CONSUMED BY LANDING must not be invalidated because the branch was deleted afterwards. The
UNPINNED arm applies `rm_labels` and refuses; it is reached both when a verdict genuinely named no commit and when it
named one but `origin/$BRANCH` no longer resolves - and only the second of those is a branch deleted after its work
landed, where the reviewed commit is usually still reachable on the default branch and spent-ness is therefore
DECIDABLE. This patch asks the ancestry question where it can be answered, and names the object actually missing where
it cannot.

## What changes

1. **The UNPINNED arm distinguishes its two sub-routes.** If the verdict named no SHA at all, there is nothing to ask
   and the clearance is invalidated exactly as before. If it named one and the branch is gone, the reviewed commit is
   tested against `refs/remotes/origin/<default>`: an ancestor means SPENT, so both label families are KEPT and a
   `clearance SPENT (measured)` comment is written instead of a rejection.
2. **Ancestry is asked only where it can be answered.** If `refs/remotes/origin/<default>` is absent the patch prints,
   on stderr, the question it could not answer, and treats the clearance as UNVERIFIABLE rather than spent - it does
   not refuse on that basis, because a missing remote-tracking ref is evidence absent, not adverse.
3. **The messages name the object that is actually missing.** Both the refusal text and the `rev_line` printed in the
   review section said the verdict "named no commit SHA" on a route where it named one and the BRANCH was gone. They
   now say which object is absent, on each sub-route.
4. **The UNRESOLVED arm names its missing object too**, and keeps its route-A wording verbatim, because a shipped case
   asserts it (`11u`).

## What is deliberately NOT changed

The wording asserted by `11q` - `review verdict was PASS but named no commit SHA` - is preserved EXACTLY, on the
sub-route where it is true. Two shipped cases pin these strings (`11q`, `11u`) and both were re-driven after the patch:
`292 passed, 0 failed` on the deployed suite. A patch that improved a message by breaking the case that pins its
truthful use would be trading one false statement for another.

## Measured

Every revision staged BESIDE its sibling files (`fleet-land-message` reads `fleet-verdict-words.sh` from its own
directory; a tool copied out alone refuses to run and any number from such a staging is meaningless).

| revision | deployed suite | with case 36 | case 38 |
|---|---|---|---|
| `a96f732b` (preimage) | 292/0 | 298/0 | **38a FAIL, 38b FAIL, 38c FAIL**, 38d/38e/38f ok |
| this patch (`181393fd`) | 292/0 | 298/0 | **all six ok** |

`38e` is a control in the opposite direction from the usual one: it does not go red on the defect, it goes red on a LAZY
FIX. An UNSPENT clearance must still be invalidated, so a patch that simply stopped stripping in this arm would satisfy
38a-38c and fail 38e. That is what makes the others evidence rather than a description.

| | |
|---|---|
| preimage | `a96f732be676df0b4f34c04bf3909c72f66671e0` (canon + p1c2 + the urh9 ancestry fix + the v7vw corrections) |
| result | `181393fd963f73fbb5dc0a2c5307f54b564684da` - differs from the preimage, asserted |
| patch | **5647 bytes, 3 hunks** (sha256 `41f8501ed2b30227b4be81cbb6716fa3...`), non-empty asserted |
| apply | `patch -p1 --fuzz=0`: rc 0, zero rejects, byte-identical to the driven revision |

## Anchors, re-measured rather than reused

The fix shifts every line below it, so the numbers recorded against the preimage are superseded:

    UNRESOLVED arm :805      UNPINNED arm :821      new ancestry test :832
    rm_labels applications: :800 (STALE|DIVERGED), :816 (UNRESOLVED), :847 (UNPINNED), :875 (review-failed)

## Two corrections this patch carries in its own history, recorded because both were mine

**The arm was misattributed, twice, by tracing rather than driving.** The bead and my first two analyses put this in
the UNRESOLVED arm. A probe showed the branch-deleted case reaches UNPINNED: when the branch is gone from both
`origin` and locally, `target_ref` is empty, `tip` becomes the literal string `unknown`, and the guard requiring
`tip != "unknown"` fails - so nothing below it is reached and the fall-through is the UNPINNED arm.

**The first version of the accompanying case failed on the fixed revision for a fixture reason.** It set
`origin/main` to `main`'s own tip, which does NOT make the reviewed commit an ancestor, because that commit is a
DESCENDANT of main. The fixture now sets `origin/main` to the reviewed commit for the spent case. A case that fails on
the ground truth is testing its own fixture - and this one was caught by running it against the fixed revision, not by
reading it.
