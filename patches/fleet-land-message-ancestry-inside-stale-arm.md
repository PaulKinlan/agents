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
| **this patch (`1feb45dc`)** | **292 passed, 0 failed** |

With the offered regression case added to a copy of the suite, this patch scores **298 passed, 0 failed**, while canon and
p1c2 score 298/0, the outer-scope revision fails 4 of that case's 6 assertions, and `f2a72a17` passes the case but still
shows the nine. The case catches the PLACEMENT defect; the nine are caught by the existing tip-moved cases. Both are
needed - one case would have missed the second defect.

| | |
|---|---|
| algorithm | `sha256` |
| preimage | `9266c3340ff6172c5629a508698ce2695d1ebb7d` (canon + p1c2) |
| result | `1feb45dc619ab49d6a3592c8962e761083ea9928` - differs from the preimage, asserted |
| patch | **3626 bytes, 1 hunk**, non-empty asserted |
| apply | `patch -p1 --fuzz=0` -> rc 0, zero rejects, byte-identical |
| artifacts | ONE pair for THIS change. The superseded `spent-ancestry-on-p1c2-base` pair is deleted (its hunk collided at 759 when both were applied in sequence). A count of every patch under `patches/` that touches this file is NOT one - there are pre-existing artifacts from other work - so that broader number would be true and misleading. |
