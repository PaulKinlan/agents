# Patches

This directory holds patches to **this repository's own files** only, each next to its write-up:

    patches/<artifact>.patch   the diff
    patches/<artifact>.md      why it exists, what it changes, how it was verified

`ls patches/` is the index.

## Fleet tooling is not delivered from here

The fleet's tooling (`~/fleet`: `bin/fleet-*`, `remote/`, `roles/`, `inbox/`, `watchdog/`, ...) has one
owner, the hub. Do not write patches, branches or long messages for it from this repository. When a
fleet tool gets in your way, file it in one line and carry on with this repo's work:

    fleet-defect "<what is wrong>" --where <file:line>

That files a deduplicated bead in the fleet's tracker without waking anyone. The inbox rejects diffs
sent to the hub. `tests/test_patch_writeups.py` fails if a patch here touches a fleet path.
