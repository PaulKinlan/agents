## patches/fleet-land-message-ancestry-inside-stale-arm.patch

HUB-DELIVERY PATCH on top of `agents-p1c2`, the successor to `f2a72a17`, answering P1 `agents-esh6`/`agents-7jco` and the P2
housekeeping `agents-2hlw`. SCOPE IS FROZEN AT THREE THINGS and nothing else is in this diff:

1. **THE REF-ABSENT PATH FOLLOWS p1c2 AND PRINTS A WARN** (P1 `agents-esh6`, and this follows the coordinator's ruling,
   which overrides the `agents-zlz4` ruling I had written earlier).
2. **ONLY THE CURRENT PATCH PAIR SHIPS FOR THIS CHANGE** (P2 `agents-2hlw`): the superseded
   `patches/fleet-land-message-spent-ancestry-on-p1c2-base.{patch,md}` - carried in from the failed `6dea718c` - is DELETED, so
   this branch holds ONE artifact pair for this change rather than two that conflict on the same hunk. The other
   `patches/fleet-land-message-*.patch` files are pre-existing artifacts from other work, not duplicates of this one.
3. **EVERYTHING VERIFIED IN THE PREVIOUS TIPS STANDS** - the placement fix and the measured suite scores are unchanged.

## What changed, and why

**PLACEMENT.** The ancestry check sat at OUTER SCOPE, before `if [ "$rev_state" = "STALE" ] || [ "$rev_state" = "DIVERGED" ]; then`,
so it ran on EVERY invocation: a normal CURRENT landing aborted with exit 1 when `refs/remotes/origin/<default>` was absent,
and printed a spurious NOTE when it was present. The whole block now lives INSIDE the arm. Verified by line order in the
result: the arm is at line 775 and the ancestry test at 779, inside it.

**REF ABSENT PROCEEDS, IT DOES NOT REFUSE.** `f2a72a17` made a missing `refs/remotes/origin/<default>` a REFUSAL with exit 1.
The coordinator's ruling, which I agree with and which corrects my own earlier one: that invents an outcome the shipped
suite does not have, nine tests encode the old behaviour (`11f`, `11g`, `11g2`, `11h`, `11h2`, `11z`, `12g`, `12h`, `12k`),
and worse it makes A MISSING REMOTE-TRACKING REF A HARD STOP FOR LANDING, so an operator on a fresh clone could not land
at all. The ancestry test is SUPPLEMENTARY evidence: with no ref we cannot tell whether a clearance was spent, but the
bead's `merged` label still governs exactly as `agents-p1c2` has it. So a missing ref now names the question on **stderr**
and follows the p1c2 path:

    fleet-land-message: NOTE: could not answer: has <sha> landed on origin/<default>? - that ref does not exist here,
    so ancestry cannot be established; following the p1c2 path (the bead's merged label still governs whether the
    clearance was spent), not refusing.

THE CONTRACT, AS IT STANDS AFTER THE RULING:

| ancestry answer | behaviour |
|---|---|
| **YES** - an ancestor of `refs/remotes/origin/<default>` | SPENT: keep `merge-queue` AND every `cleared:` label, print SPENT, refuse the unreviewed delta |
| **NO** - not an ancestor (the ref exists) | NOT proof it did not land: follow the p1c2 path, with the WARN naming the assumption |
| **REF ABSENT** | follow the p1c2 path, with the WARN naming the question that could not be answered |

## Measured, by driving the deployed suite

Each revision is staged BESIDE its sibling files: `fleet-land-message` reads `fleet-verdict-words.sh` from its OWN
directory, so a tool copied out alone refuses with "cannot read the shared verdict vocabulary" and every number taken from
such a staging is meaningless. That error produced an earlier claim of mine that the 63 failures belonged to `p1c2`; they
do not.

| revision | deployed suite |
|---|---|
| canon (`f6de0939`) | 292 passed, 0 failed |
| p1c2 base (`9266c334`) | 292 passed, 0 failed - p1c2 was always clean |
| ancestry at outer scope (`cec22d8f`) | 229 passed, 63 failed - the reviewer's 63, reproduced exactly |
| `f2a72a17` (`ea45f630`) | 283 passed, 9 failed - the nine `agents-esh6` names |
| **this patch (`a96f732b`)** | **292 passed, 0 failed** |

With the offered regression case added to a copy of the suite, this patch scores **298 passed, 0 failed**, while canon and
p1c2 score 298/0, the outer-scope revision fails 4 of that case's 6 assertions, and `f2a72a17` passes the case but still
shows the nine. The case catches the PLACEMENT defect; the nine are caught by the existing tip-moved cases. Both are
needed - one case would have missed the second defect.

| | |
|---|---|
| algorithm | `sha256` |
| preimage | `9266c3340ff6172c5629a508698ce2695d1ebb7d` (canon + p1c2) |
| result | `a96f732be676df0b4f34c04bf3909c72f66671e0` - differs from the preimage, asserted |
| patch | **3627 bytes, 1 hunk** (sha256 `5a1731d5f53a1210fddc4ecea8456b82...`), non-empty asserted. Applied with
`patch -p1 --fuzz=0`: rc 0, zero rejects, byte-identical to the driven revision. |
| apply | `patch -p1 --fuzz=0` -> rc 0, zero rejects, byte-identical |
| artifacts | ONE pair for THIS change. The superseded `spent-ancestry-on-p1c2-base` pair is deleted (its hunk collided at 759 when both were applied in sequence). A count of every patch under `patches/` that touches this file is NOT one - there are pre-existing artifacts from other work - so that broader number would be true and misleading. |

## The third defect, found by the final round (`agents-v7vw`), and fixed here

The revision at `28d1a0d7` emitted **two consecutive contradictory NOTEs** whenever
`refs/remotes/origin/<default>` was absent. The ref-absent note fired, and then the pre-existing ancestry `else` branch
fired as well, because `git merge-base --is-ancestor` also fails when the ref does not exist. The second note carried a
grammar slip - `has landed on of refs/remotes/origin/main` - and the contract comment above the arm still said
`REF ABSENT -> REFUSE`, contradicting the settled contract.

Three changes, all inside the ancestry block, none of them widening the frozen scope:

1. The ref check is now the FIRST ARM of the ancestry test (`if ! git rev-parse ...; then ... elif git merge-base ...;
   then already_landed=2; else ...; fi`) instead of an independent block before it, so exactly ONE note can fire.
2. The grammar is corrected to `has landed on refs/remotes/origin/<default>`.
3. The comment states the settled rule - `REF ABSENT -> the p1c2 path, with the same loud NOTE` - rather than the
   overruled one, because a comment contradicting the code is exactly the kind of false statement the beads on this
   file keep being about.

MEASURED, WITH A CONTROL THAT GOES RED. The suite captures the tool's combined output, so the note count was measured
by wrapping the tool and capturing stderr per invocation while the deployed suite ran: 121 invocations each way, same
suite, same scenarios.

| revision | invocations by note count |
|---|---|
| `28d1a0d7`'s file (`1feb45dc`) | `{0: 114, 2: 7}` - seven invocations emitted TWO notes |
| this patch (`a96f732b`) | `{0: 114, 1: 7}` - the same seven emit ONE |

THE SAME SEVEN INVOCATIONS, two notes to one, and both revisions score 292 passed / 0 failed. **The suite is blind to
this defect.** My own gate could never have caught it, so "292/0" never meant "no defects" here - a reviewer
reproducing the behaviour is what found it, and that is the difference between a green gate and a working change.

## Provenance: this pair is a FOLLOW-UP, and it keeps its filenames on purpose

The first revision of this pair landed as `28d1a0d7` (merged to main as `432bc5f6`). The three `agents-v7vw` corrections
above are carried as a FOLLOW-UP commit on top of that landed tip, and the artifact filenames are deliberately
UNCHANGED, so that main ends with ONE pair for this change whose content is the corrected one. Introducing a second,
differently-named pair for the same change is precisely the `agents-2hlw` defect this change removed - an applier could
take the wrong one - so the correction REPLACES the content rather than adding a sibling beside it.
