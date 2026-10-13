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