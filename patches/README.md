# Fleet Patches

This directory holds patches for fleet-level infrastructure and tooling that cannot be committed
directly to `PaulKinlan/fleet` from this project VM because `~/fleet` is a synced, read-only copy
without git remote push credentials on project VMs.

## Finding a patch

Each patch has its own write-up, named after the `.patch` artifact it belongs to, so the artifact
and its explanation sit next to each other:

    patches/<artifact>.patch   the diff
    patches/<artifact>.md      why it exists, what it changes, how it was verified

`ls patches/` is the index. There is deliberately no list of files here: a list would be the same
shared append point this split exists to remove, and it would go stale the first time someone
forgot to update it. A delivery adds its `.patch` and its `.md` and edits nothing that another
delivery is also editing.

(One write-up can cover more than one artifact when they were delivered together as a single
change; the filename then joins the artifact names with `+`.)

