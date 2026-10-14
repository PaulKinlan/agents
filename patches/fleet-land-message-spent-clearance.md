## patches/fleet-land-message-spent-clearance.patch

HUB-DELIVERY PATCH for `bin/fleet-land-message`, answering `agents-urh9` (the deliberate second half of `agents-p1c2`).
One hunk, one predicate, and an explicit statement of which reading of the contract it implements.

## The defect, located by line rather than described

`bin/fleet-land-message:751` (`if [ "$rev_state" = "STALE" ] || [ "$rev_state" = "DIVERGED" ]`) is reached when the
branch tip moved after the review. Inside it, `:752-753` build and apply `rm_labels`, which removes **both**
`merge-queue` **and every `cleared:` label**, and `:754` posts *"merge-queue clearance invalidated: branch tip $tip
moved after review for $rev_sha"*. **There is no test of whether that work already landed.** So: landing happens,
someone moves the tip afterwards, the tool runs, and a clearance that was **consumed** is stripped and reported as
**invalidated** - which is why the label had to be put back by hand.

The doctrine the code should already be honouring is in the same file at `:263-264` (*"Clearance is attached to a
COMMIT or DELTA, not a branch name"*) and in `roles/lessons.md:1691` (*"Attach landing clearance strictly to the
reviewed commit SHA, not the branch name"*), whose recorded incident is precisely the case the tip-move rule exists
to catch.

## Which reading of the contract, and why

**CHOSEN: (c) refuse to strip a clearance whose reviewed commit is already an ancestor of the default branch, worded
as (b) - the report says SPENT, not invalidated.** The predicate is one ancestry test placed immediately before the
strip. I did **not** choose (a) "make the consumption irreversible", which is a lifecycle change touching the state
model, when the decision point already exists and the evidence for a spend is one git question. And I did **not**
settle for "only the report is wrong": the strip itself is the harm the bead reports, so a wording fix alone would
still remove a correctly-earned label from landed work.

**The predicate is deliberately NOT "is the reviewed commit an ancestor of the TIP".** A branch cut from the default
branch satisfies that without anything having landed, which a control drive confirmed when I mis-specified it. The
question that separates a spend from an invalidation is whether the **reviewed commit is an ancestor of the default
branch**.

## Driven, and what I could NOT drive - stated rather than implied

| state | `reviewed sha ancestor of the default branch` | correct behaviour |
|---|---|---|
| before any landing (tip == reviewed) | **NO** | strip, as today |
| **the reported sequence**: landed first, tip moved after | **YES** | **SPENT - do not strip** |
| control: tip moved and nothing landed | **NO** | strip, as today |

That table is the drive, run on real repositories for all three states, including the control. **I did not summon the
full sequence end to end, and I will not claim I did:** the tool has no `--dry-run` (checked), and a real run
**mutates the bead** (`bdf update --remove-label`, `bdf comments add`) and is on the path that merges - so driving it
against production to reproduce a report would be the change, not a test of it. The predicate the fix depends on is
therefore what is driven, with a control, and nothing above rests on the unsummoned half.

**A note so nobody repeats my two slipped instruments:** `$DEFAULT` does not exist in this tool and it runs under
`set -uo pipefail`, so a predicate referencing an undefined name would pass `bash -n` and die at runtime - the
fragment therefore reads the default branch with the fleet's own idiom (`cat "$HOME/.fleet/default-branch" || echo
main`) and introduces exactly one new name, `DFLT`. And the patched fragment is **not** syntactically standalone when
sliced out of the `if` block, so an isolated-slice run of it proves nothing either way; `bash -n` on the whole
patched file is the syntax evidence.

## Preimage, result, and the checks that make them non-vacuous

| | |
|---|---|
| algorithm | `sha256` |
| preimage | `f6de093900f6b059af938c2bfc9613d9b66cdcbad8ad5195eb752a7d712be3ee` (`~/fleet/bin/fleet-land-message`, 64670 bytes, mode 755) |
| result | `65ea94924dcdb378ae63012a819f19ab12a9c5dc2695cb46f21f5cb62dfd9397`, 66536 bytes - **and the applied result is not the preimage**, asserted |
| patch | **2353 bytes, 1 hunk**, measured from the committed artifact; **non-empty asserted**, so a zero-byte "clean apply" cannot read as a pass here |
| apply | `patch -p1 --fuzz=0` on the COMMITTED artifact -> rc 0, **zero rejects**, **byte-identical** to the intended result |
| syntax | `bash -n` on the whole patched (applied) file: clean |

A correction of my own, since it is the same family as the defect this bead is about: the first revision of this
table asserted that the preimage differs from the result by comparing the **patch file** against the **preimage
file**, which is not a comparison of those two things at all - a check that cannot fail is not a check. The rows
above are re-measured from the committed artifact, and the assertion is now that the **applied result** differs
from the **preimage**, which is the claim that matters.

**ADVISORY:** the preimage was read from this VM's `~/fleet` mirror, which is behind the hub's origin
(`agents-x8ud`), so verify by the chain you observe rather than against these numbers.

## Placement, checked before proposing anything

`bin/fleet-land-message` is **fleet canon in the provisioned mirror** - not ours to edit from a project VM, with no
repo route - and `roles/merger.md` and `roles/lessons.md` are likewise canon; this repository has **zero** `roles/`
files. So this patch is the whole of what we can ship, the hub applies it, and the existing
`patches/fleet-land-message-clearance-*` artifacts are the precedent for the shape.

**A finding from that check:** the bead's "WHERE TO LOOK" names a `ref-flow` component, and **`ref-flow` does not
exist on this VM** - not as a file under `~/fleet` and not as a mention in any shell, python or markdown file. The
strip is performed by `fleet-land-message` itself, at the lines above. If `ref-flow` is a far-side service or a name
used elsewhere, the hub should say so; on this VM the mechanism is the one patched here.
