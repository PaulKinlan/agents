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

## `fleet-reviewer-worktree-tip.patch` (agents-6b3k)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `roles/reviewer.md` (lines 20-30, 36-44, 115-122)
  - `tests/reviewer-worktree-tip.test.sh` (new unit tests)
- **Problem Statement (agents-6b3k):**
  Reviewer lanes spawn in a worktree cut from `origin/main` (`lanes.sh spawn <name> "" <bead> reviewer`), not at the tip under review. If a reviewer executes reproduction or mutant tests directly in its worktree without materializing the reviewed tip, it tests `origin/main` instead of the commit under review.
  Measured in live sessions:
  - `rev-dso1`: Ran tests directly in worktree; executed against `origin/main` and ran 4 tests instead of 8. The reviewer caught the discrepancy only because the count looked wrong and had to re-run against `git show 837bb7b`.
  - 100% of reviewer worktrees spawn at `origin/main`. Competent reviewers independently invented manual workarounds: `rev-pdth` unpacked to `/tmp/rev-pdth-tip`, `rev-pdth2` read via `git show`, while `rev-undf`, `rev-azi1`, and `rev-teg3` manually ran `git checkout --detach <sha>`.
- **Changes:**
  1. **Boot Checkout Instruction:** In `roles/reviewer.md` Step 3, explicitly instruct reviewers to check out the reviewed tip via `git checkout --detach "$tip"` immediately after fetching and pinning the delta.
  2. **Reproduction Loud Guard:** In `roles/reviewer.md` Step 2 ("The behaviour under review, reproduced"), add the precondition guard:
     `[ "$(git rev-parse --short HEAD)" = "$tip" ] || { echo "ERROR: worktree HEAD ($(git rev-parse --short HEAD)) does not match review tip $tip - check out tip before measuring (agents-6b3k)" >&2; exit 1; }`
     ensuring any attempt to measure while still at main fails loudly with the mismatched SHAs.
  3. **Finish Restoration:** In `roles/reviewer.md` Step "Finish", instruct restoring the lane branch (`git checkout -q "fleet/${FLEET_LANE}" 2>/dev/null || true`) prior to retirement.
  4. **Contract & Behavioral Tests:** In `tests/reviewer-worktree-tip.test.sh`, assert both the static role prompt requirements and the behavioral transition of a reviewer worktree from main to the detached reviewed tip with disk content verification and explicit nonzero exit code assertion on mismatch (9/9 tests pass).
- **Verification:**
  - `tests/reviewer-worktree-tip.test.sh`: 9/9 tests pass.
  - Regression: `tests/lanes.test.sh` passes 151/151 tests; `tests/review-cadence.test.sh` passes 203/203 tests.
  - Clean patch application verified via `git apply --check`.
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-reviewer-worktree-tip.patch
  bash tests/reviewer-worktree-tip.test.sh
  ```

## `fleet-verdict-transcribed-run.patch` (agents-m6fr)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/fleet-verdict-words.sh` (one new function, appended after `fleet_verdict_model_family`)
  - `bin/fleet-land-message` (the class documentation block, one new classification, one new refusal arm
    in the existing `case` gate)
  - `tests/fleet-verdict-transcribed-run.test.sh` (new; 8 unit cases, isolated fixtures)
- **Baseline file hashes:**
  `ff0f056338d5324964279b8296ae6992f261dc6c3073575a5e28845237a60396  bin/fleet-land-message`
  `b28dde10d67426316c9809fb314f26673c19fcbc15b5cbe402340b5f2416852b  bin/fleet-verdict-words.sh`
- **Problem statement (agents-m6fr).** `fleet-land-message` decides whether a branch may land. For a verdict
  posted by the branch author's **own lane** it requires a NAMED reviewer model whose family differs from the
  author's (`fleet-ry7m`, because a reviewer subagent inherits its parent lane's actor — `fleet-15b5`). That named
  model is **a claim written on the comment, not evidence**: a lane can write any different-family model string on
  its own verdict and be classified `cross-family` and cleared. The reader already parses a **run id** from the
  verdict comment (`rev_run_id`) and emits it as `review.run_id` — it simply never used it. Meanwhile subagent run
  directories are retained on disk with a `recovery-descriptor.json` naming the agent and the model, so the claim
  is checkable.
- **The live instance this was measured on** is this project's own lane: `agents-oeza` carried a verdict posted by
  `agents-factory-impl-3a8a` where `branch_author` was **also** `agents-factory-impl-3a8a`, cleared as
  `cross-family` on the strength of the model string in its own comment. The review was genuine — but the reader
  could not tell that from the comment, and would have cleared an invented string identically.
- **Changes:**
  1. `fleet_verdict_transcribed_run_status <run-id> <named-model> [root]` resolves the run id against
     `<root>/pi-subagents-*/async-subagent-runs/`, requires the descriptor to record `agent=reviewer`, and compares
     the recorded model's **family** (via the existing `fleet_verdict_model_family`) with the named one. It prints
     `verified: …`, `unverified: <reason>` or nothing at all when there is no run id, so the caller owns the
     no-id decision.
  2. `fleet-land-message` gains two classes — `transcribed-verified` and `transcribed-unverified` — reached
     **only** when the verdict's author is the branch author (`rev_who == src_who`) and the class would otherwise
     be `cross-family`. `transcribed-unverified` joins the existing refusal `case`, so it cannot clear and says why.
     A verdict from another lane (`other-lane`) is untouched.
- **Verification:**
  - **Unit, isolated fixtures:** `bash tests/fleet-verdict-transcribed-run.test.sh` → **8 passed, 0 failed**:
    1 real reviewer run; 2 same family/different version (a deliberate leniency, stated in the test); 3 a fabricated
    run id does NOT verify; 4 a `worker` run is not a review; 5 a reviewer run of another family does not back a
    claim of a different one; 6 a run directory with no descriptor is not evidence; 7 no run id → silence from the
    helper; 8 roots are searched rather than assumed (a hardcoded path would pass 1-7 and fail here).
  - **The whole chain, pristine vs patched, on three REAL beads** (`--print-json`, same repo, same comments):

    | bead | verdict author | pristine | patched |
    |---|---|---|---|
    | `agents-oeza` | the branch author's own lane | `cleared=True  cross-family` | `cleared=True  transcribed-verified` |
    | `agents-k8hh` | another lane | `cleared=True  other-lane` | **unchanged** |
    | `agents-flgz` | another lane | `cleared=False other-lane` | **unchanged** |

  - **The falsifiable direction, end to end on the same real bead with no comment mutated:** pointing the helper's
    root at an empty directory (only the environment differs) makes the real run id unresolvable, and
    `agents-oeza` becomes `cleared=False independence=transcribed-unverified`, with the reader printing the reason
    — `run id ffc6fb50-… does not resolve to a retained run directory (these are retention-managed…)`. Restoring
    the real root returns `transcribed-verified`. Same bead, same comment, one variable apart.
  - **Round trip:** `git apply --check` passes against pristine copies, and the applied patch reproduces the
    measured tree byte-for-byte (`diff -r` clean); patched hashes
    `4006d5a84bf2bac8e934936c58f8dc48651bb32ed0dda1feb8184ab409fbaf89  bin/fleet-land-message`,
    `c8b0a819080ae63485227002767c08c78c4432762386f2bfa7ed3931e001449f  bin/fleet-verdict-words.sh`.
  - **An operator-visible side effect, found while measuring it:** in message mode the reader does not only print,
    it ENFORCES — a refused clearance strips `merge-queue` and marks the bead `review-failed`. That is pre-existing
    behaviour, but this patch adds a new way to reach it, so it is stated here rather than discovered later.
- **Stated limit, not hidden:** the check proves the run exists, is a `reviewer` run, and is of the named family.
  It does **not** prove that run reviewed *this* diff — the descriptor records agent and model, not the bead or the
  branch — so a lane willing to point at an unrelated reviewer run would still pass. That is a smaller hole than an
  unbacked model string, and it is the hole that remains. It also cannot check a review old enough to have been
  pruned: run directories are retention-managed, which is exactly why this check belongs at landing time.
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-verdict-transcribed-run.patch
  bash tests/fleet-verdict-transcribed-run.test.sh      # 8 passed
  # the reader needs a repo to resolve the branch against, and ~/fleet is not a git checkout:
  fleet-land-message --print-json --repo <a project checkout> <bead> <branch> \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["review"])'
  ```
