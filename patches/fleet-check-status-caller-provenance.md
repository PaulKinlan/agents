## `fleet-check-status-caller-provenance.patch` (agents-999b)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/fleet-check` (lines 170-175, 190, 347-350)
  - `tests/fleet-gate-check.test.sh` (section 23l/23m contract alignment, section 26 unit tests)
- **Baseline file hashes:**
  - `7e3b0b06137b629ad65ec8da77e525afff02425e69eaf788421d6b06fe994e62  bin/fleet-check`
  - `ca8bffa7991eddfc07480c90a4e1deb6e6019a52bae53dee030cbc258caecba2  tests/fleet-gate-check.test.sh`
- **Problem Statement (agents-999b):**
  1. In `bin/fleet-check --status`, asking for the status of a cached record from another worktree previously overwrote the record's own `repo` field with the caller's worktree (`$top`) and stamped the caller's branch (`$branch`) onto the output.
  2. When a reviewer or coordinator queried the status of a commit checked by another lane, they saw their own worktree and branch attributed to the producing lane's run.
  3. The record's true origin was hidden: `repo` became the caller's path and `branch` became the caller's branch label.
- **Changes:**
  1. **Preserve Producing Checkout Provenance:** In `bin/fleet-check --status`, `.repo` and `.branch` are preserved from the record itself. `produced_in` is maintained as the producing checkout path.
  2. **Distinct Caller Context Keys:** When the caller's checkout or branch differs from the record, they are reported distinctly as `caller_repo` and `caller_branch` rather than overwriting the record's own keys.
  3. **Record Branch on Gate Execution:** In `bin/fleet-check`, capture `cur_branch=$(git rev-parse --abbrev-ref HEAD)` when starting the gate and persist it in the `RUNNING` record.
  4. **Unit Tests:** In `tests/fleet-gate-check.test.sh`:
     - Section 23l/23m contract alignment: 23l asserts `"caller_repo":"$S8_WT"` ('asking checkout is reported as caller_repo') and 23m asserts `"repo":"$S8_REPO"` ('checkout that actually ran is preserved as repo').
     - Section 26: defined `eq()` test helper and added assertions 26a–26i:
       - 26a–26e: Querying a record from a different worktree and branch preserves the producing checkout's `repo` and `branch`, reports the caller's checkout as `caller_repo`, and reports the caller's branch as `caller_branch`.
       - 26f–26i: Querying from the same worktree and branch preserves `repo` and `branch` while omitting `caller_repo` and `caller_branch`.
- **Verification:**
  - `tests/fleet-gate-check.test.sh` sections 23 and 26: 23/23 assertions pass (14/14 in section 23, 9/9 in section 26).
  - Clean patch application verified via `git apply --check` against pristine `~/fleet`.
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-check-status-caller-provenance.patch
  bash tests/fleet-gate-check.test.sh
  ```

