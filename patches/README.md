# Fleet Patches

This directory holds patches for fleet-level infrastructure and tooling that cannot be committed directly to `PaulKinlan/fleet` from this project VM because `~/fleet` is a synced, read-only copy without git remote push credentials on project VMs.

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

## `fleet-worktree-beads-guard.patch` (agents-5br9)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/bd` (lines 208-242)
  - `tests/bd-worktree-decoy.test.sh` (new unit tests)
- **Baseline file hash:**
  `359962a02e19a94b664c6193ec415e22ad00242998264f0515e86ebb0c7956ea  bin/bd`
- **Problem Statement (agents-5br9):**
  When a linked git worktree has a local `.beads/embeddeddolt` (or `.beads/dolt`), upstream `bd`'s `FindBeadsDir` resolves the local `.beads` as authoritative because `hasBeadsDatabase` returns true, bypassing the git-common-dir fallback. `bd` then operates against an empty ledger. Any subsequent `bd dolt push` risks publishing the empty database over the shared remote.
- **Changes:**
  1. **Worktree decoy guard:** `guard_worktree_beads_decoy` function in `bin/bd` shim checks if current toplevel (or `-C <dir>`) is a linked git worktree (`[ -f "$toplevel/.git" ]`).
  2. **Loud actionable refusal:** If `.beads/embeddeddolt` or `.beads/dolt` exists in the linked worktree, refuses the command with exit code 2 and actionable diagnostic:
     `bd: REFUSED: a worktree should hold no database; a decoy here means bd will report an empty ledger and a push from it would overwrite the shared one - move <path> aside and re-run.`
  3. **Canonical checkout exemption:** The canonical checkout (`.git` is a directory) legitimately holds the database and is completely exempt.
- **Verification:**
  - `tests/bd-worktree-decoy.test.sh` passes 13/13 assertions covering canonical checkout exemption, clean worktree pass-through, worktree decoy refusal, `-C` worktree decoy refusal, and recovery after moving decoy aside.
  - Regression check: `tests/bd-guard.test.sh` passes 85/85 assertions; `tests/bd-shim.test.sh` passes 11/11 assertions.
  - Clean patch application verified via `git apply --check`.
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-worktree-beads-guard.patch
  bash tests/bd-worktree-decoy.test.sh
  ```

