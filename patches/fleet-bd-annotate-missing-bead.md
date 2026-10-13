## `fleet-bd-annotate-missing-bead.patch`

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/bd` (the `annotate_missing_bead` helper, plus lookup call paths at the end of the shim)
- **Baseline file hashes:**
  - Pristine `/home/exedev/fleet/bin/bd`
- **Prerequisite sequence:**
  Independent; applies directly to pristine `PaulKinlan/fleet` or sequentially with other fleet bundle patches.
- **Problem Statement:**
  A lane is told to claim its bead first, so the FIRST bd command in a fresh lane is a lookup of a bead
  someone else just created. That lookup can fail with `no issue found matching <id>` in two worlds whose
  remedies are opposite, and the text does not say which one you are in:
  1. **The database resolved is the wrong one** (a per-worktree `.beads/embeddeddolt` becomes
     authoritative while the shared ledger is not consulted). The bead exists; the lane is reading a
     different, empty ledger — and a push from there would publish that ledger over the shared one.
  2. **The ledger is the right one and does not hold the bead yet.** Beads are written on the hub and reach
     a project VM after a pull, so a bead created seconds ago may not have arrived.
  The induced behaviour is worse than the failure: a lane concludes the bead is gone, then creates a
  duplicate or reports it missing, and both look like new facts afterwards.

- **Measured basis:**
  - The text does NOT come from `show` (which says `Issue <id> not found` with a history hint); it comes from
    the paths a lane uses to CLAIM and annotate: `bd update <id> --claim`, `bd comments <id>`, `bd close <id>`.
  - A fresh LINKED worktree does not by itself produce it: bd resolves through the SHARED GIT COMMON DIR to
    the canonical checkout (`bd info`: 494 issues, nothing created locally).
  - An independent clone fails differently and LOUDLY (`no beads database found`, with a hint naming
    `bd where`, `bd init` and `BEADS_DIR`) — so bd can say it cannot see a database, and the ambiguous text
    comes only from a database that is visible, authoritative, and lacks the bead.
  - The one-command discriminator is `bd where` (or `bd info`): the worktree path means (1), the canonical
    path means (2).

- **Changes:**
  1. **Annotate, never act.** For the six subcommands a lane can run first that emit this text (`show`,
     `comments`, `update`, `close`, `dep`, `delete`), the shim captures stderr into a temp file, re-emits it
     verbatim, and — only when the call FAILED and the text contains `no issue found matching` — appends the
     resolved database path plus the remedy for each world.
  2. **Derived canonical path,** not hardcoded: `git rev-parse --git-common-dir` locates the checkout that
     owns the ledger, so the annotation is also correct in the journal and on the hub.
  3. **Scoped stderr capture.** `dolt`/`pull`/`push`/`list` keep writing straight through, so a long pull's
     progress is not buffered behind a temp file.
  4. **Exit status untouched.** No fetch, no repair, no re-resolution.

- **Verification:**
  - The patch applies cleanly against the shim as deployed (`git apply --check`), reproducing the
    tested draft byte for byte (`diff` identical, `bash -n` clean).
  - rc fidelity against the unpatched shim on four shapes: full output `0`; piped-to-head `141`; failing
    lookup `1`; failing claim `1` — identical in every case.
  - Silent where it should be: no annotation on success, and none for `list`.
  - Zero internal bead IDs in patch or writeup.

- **Relationship to the worktree guard:**
  Both this patch and the per-worktree beads guard (`fleet-worktree-beads-guard.patch`) touch the same target
  file (`bin/bd`), but are orthogonal: this patch changes WHAT bd says when an issue is missing (which happens on
  every missing issue, everywhere); the other guards against a per-worktree database becoming authoritative.
  Whichever lands second must resolve against the first.

- **Hub Application:**
  ```bash
  cd ~/fleet
  patch -p1 < /path/to/fleet-bd-annotate-missing-bead.patch
  ```
