# Patches

This directory holds patches to **this repository's own files** only, each next to its write-up:

    patches/<artifact>.patch   the diff
    patches/<artifact>.md      why it exists, what it changes, how it was verified

`ls patches/` is the index.

## A patch is a plan with an expiry, not a deliverable

A diff against a repository that moves has a shelf life measured in hours, so an artifact here has exactly
three states, and `tests/test_tree_guards.py` (`TestPatchArtifactsAreNotRotted`) decides which one it is on
every fast-gate run, against the committed tree rather than your working copy:

| State | Meaning | What to do |
|---|---|---|
| **applies** | a plan someone can install today | leave it; it is a live proposal |
| **installed** | `git apply --reverse --check` succeeds: the change is already in the tree | leave it as the record, and make sure the write-up's delivery-state line says so |
| **neither** | the tree has moved past it: it cannot be applied or reversed, and never will be | regenerate it against the current tree, or delete the artifact and its write-up and record the closure on the bead |

The refused state is **neither**, and the reason it is a gate rather than a tidy-up: 13 of 14 artifacts once
accumulated here in exactly that state, and a human reading the folder found them because nothing looked.
The record of a change is its bead and its write-up - the patch is an implementation detail of the delivery,
regenerated at install time against whatever the tree looks like then.

## Fleet tooling is not delivered from here

The fleet's tooling (`~/fleet`: `bin/fleet-*`, `remote/`, `roles/`, `inbox/`, `watchdog/`, ...) has one
owner, the hub. Do not write patches, branches or long messages for it from this repository. When a
fleet tool gets in your way, file it in one line and carry on with this repo's work:

    fleet-defect "<what is wrong>" --where <file:line>

That files a deduplicated bead in the fleet's tracker without waking anyone. The inbox rejects diffs
sent to the hub. `tests/test_patch_writeups.py` fails if a patch here touches a fleet path.
