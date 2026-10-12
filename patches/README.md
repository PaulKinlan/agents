# Fleet Patches

This directory holds patches for fleet-level infrastructure and tooling that cannot be committed directly to `PaulKinlan/fleet` from this project VM because `~/fleet` is a synced, read-only copy without git remote push credentials on project VMs.

## `fleet-bd-annotate-missing-bead.patch` (agents-oryd)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/bd` (the `annotate_missing_bead` helper, plus the two call paths at the end of the shim)
- **Problem Statement (agents-oryd, with agents-5br9 as the state it reports):**
  A lane is told to claim its bead first, so the FIRST bd command in a fresh lane is a lookup of a bead
  someone else just created. That lookup can fail with `no issue found matching <id>` in two worlds whose
  remedies are opposite, and the text does not say which one you are in:
  1. **The database resolved is the wrong one** (`agents-5br9`: a per-worktree `.beads/embeddeddolt` becomes
     authoritative while the shared ledger is not consulted). The bead exists; the lane is reading a
     different, empty ledger — and a push from there would publish that ledger over the shared one.
  2. **The ledger is the right one and does not hold the bead yet.** Beads are written on the hub and reach
     a project VM after a pull, so a bead created seconds ago may not have arrived.
  The induced behaviour is worse than the failure: a lane concludes the bead is gone, then creates a
  duplicate or reports it missing, and both look like new facts afterwards.

- **Measured, on a project VM, 2026-10-12:**
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
  - The patch `git apply --check`s cleanly against the shim as deployed, and applying it reproduces the
    tested draft **byte for byte** (`diff` identical, `bash -n` clean).
  - rc fidelity against the unpatched shim on four shapes: full output `0`; piped-to-head `141`; failing
    lookup `1`; failing claim `1` — identical in every case.
  - Silent where it should be: no annotation on success, and none for `list`.
  - Cost: one `mktemp` + `cat` per lookup = 5.0 ms measured, against bd's own 0.6-2.8 s per call.

- **Ownership boundary (do not let two changes claim the same line):** `agents-5br9` owns the STATE (the
  guard against a per-worktree database being authoritative) and this patch owns the REPORTING. They are
  separate changes to the same file: whoever lands second resolves against the first rather than replacing
  it. This patch deliberately does not re-resolve, fetch or repair anything — it only makes the failure say
  which condition it observed, which is what a lane needs while 5br9's guard does not exist yet.

## `fleet-land-message-tree-identity.patch` (agents-19jh)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/fleet-land-message` (lines 755-835, 935-950, 980-990)
  - `tests/fleet-land-message.test.sh` (tests 10w-10z)
- **Problem Statement (agents-yk6m, agents-19jh):**
  When landing a branch with `fleet-land-message --gate <merged-sha> <bead> <branch>`, the helper previously verified branch containment with `git merge-base --is-ancestor "$target_ref" "$gate_commit"`. If the branch author rebased or amended the branch after the merger created the merge commit (moving the branch ref without altering its tree), this ref-ancestry check failed with `REFUSING: --gate <sha> does not contain <branch>`, even though the merged tree and the branch tree were identical.

- **Changes:**
  1. **Tree identity on no-op rebase:** When `target_ref` is not an ancestor of `gate_commit`, the helper inspects the commits merged into `gate_commit` from the branch (`commit_has_tree`). If an ancestor with matching tree identity is found, the no-op rebase is accepted.
  2. **Accepted identity reporting:** Emits `Identity <accepted-identity>` under the `GATE` section of the landing message and inside `.gate.identity` in `--print-json`, recording whether commit ref ancestry or tree identity was verified and that the gate tree matches the landing HEAD tree.
  3. **Strict refusal on genuine tree mismatch:** If the branch tree changed after the merge or the gate tree does not match HEAD tree, the command exits 1 with a descriptive refusal on stderr.
  4. **Deliberate-failure control:** Confirmed that the failure/refusal path writes zero bytes to stdout. Attempting to pipe a failed message into `git commit --amend -F <(...)` aborts with `Aborting commit due to empty commit message`, leaving the default branch HEAD untouched.

- **Verification:**
  - Tested against `/home/exedev/fleet-copy`: all 280 test assertions in `tests/fleet-land-message.test.sh` pass (257 existing + 23 new assertions in 10w-10ab).
  - Fast-forward landed branch tip with no-op rebase tested and verified (test 10aa).
  - Branch-side search in merge commits starts at `$p2` to exclude the merge commit itself; branch matching the merge union tree is strictly refused (test 10za).
  - Unrelated unmerged branch matching an old historical main commit tree strictly refused (test 10ab).
  - Deliberate-failure control directly verifies failure stdout is 0 bytes (via file byte count) and feeding failure stdout into `git commit --amend -F` aborts with empty commit message (test 10z).
  - Clean patch application verified via `git apply --check`.

- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-land-message-tree-identity.patch
  bash tests/fleet-land-message.test.sh
  ```

## `fleet-check-lock-classification.patch` (agents-bc2s)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/fleet-check` (lines 125-180, 250)
  - `tests/fleet-check-lock.test.sh` (new unit tests)
- **Baseline file hash:**
  `0b88ef1e275bfc2e1bb8cdcd1ce793d30daecafac173e937e8b9fe2ea7112d5d  bin/fleet-check`
- **Problem Statement (agents-82qr, agents-bc2s):**
  When a 0-byte `.lock` file exists in `~/.fleet/checks` without a verdict JSON file (e.g. from an interrupted, killed, or dead run), `fleet-check --status` previously returned `{"state":"NONE"}`, indistinguishable from a tree that was never gated. Conversely, if a gate was actively running (lock held by flock) before the JSON record was written, `--status` also returned `NONE` (a live gate reported as no gate).
- **Changes:**
  1. **LOCKED-RUNNING:** When a lock file exists and is held (`! flock -n <lock> true`), `--status` outputs `state: "LOCKED-RUNNING"`, discovers the holding PID via `lsof`/`fuser`, and does not degrade to `NONE`. The detached worker holds the lock descriptor (`flock 9`) throughout its lifetime until exit.
  2. **LOCKED-STALE:** When a 0-byte lock file exists and is free (or a `RUNNING` JSON has a dead PID and free lock), `--status` outputs `state: "LOCKED-STALE"`, reports the mtime of the stale lock, and explains the dead run.
  3. **COMPLETED:** When a verdict JSON exists with a finished verdict (`PASS`, `FAIL`, `KILLED`, `UNKNOWN`, `INCONCLUSIVE`), the lock is irrelevant and the verdict's own status is reported.
  4. **NONE:** Only when neither verdict JSON nor lock file exists is `state: "NONE"` reported.
- **Verification:**
  - Unit tests in `tests/fleet-check-lock.test.sh` pass all assertions covering `NONE`, `LOCKED-STALE` (free 0-byte lock), `LOCKED-RUNNING` (held lock with active pid), `COMPLETED` (`PASS` verdict ignores lock), fast-gate lock isolation (`.fast.lock` without fallback to full lock, test 5a-d), live PID without held lock yielding `LOCKED-STALE` (test 6a-c), and status check during a real detached worker run reporting `LOCKED-RUNNING` and completing to `PASS` (test 7a-c).
  - Regression check: `fleet-check-scope.test.sh` passes 7/7.
  - Clean patch application verified via `git apply --check`.
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-check-lock-classification.patch
  bash tests/fleet-check-lock.test.sh
  ```
