## `fleet-land-message-true-none-line.patch`

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/fleet-land-message` (line 679)
  - `tests/fleet-land-message.test.sh` (line 1035)
- **Baseline file hashes:**
  - Pristine `/home/exedev/fleet/bin/fleet-land-message`
  - Pristine `/home/exedev/fleet/tests/fleet-land-message.test.sh`
- **Prerequisite sequence:**
  Independent; applies directly to pristine `PaulKinlan/fleet` or sequentially after stack items.
- **Problem Statement:**
  In `bin/fleet-land-message:679`, when no parseable review verdict comment is found on a bead, `rev_line` was set to:
  `NONE: no review verdict found on bead $BEAD`
  This statement is emitted into the merge commit message body under the `REVIEW` section. It is true about the bead comments, but false about actual review activity: reviews may have been executed in subagent runs (such as multiple review rounds) without being transcribed as bead comments in the recognised format. Emitting "no review verdict found" falsely claims in the permanent git history that no review ever took place.
- **Changes:**
  1. In `bin/fleet-land-message`, updated `rev_line` in the fallback branch from:
     `NONE: no review verdict found on bead $BEAD`
     to:
     `NONE: no parseable review verdict comment found on bead $BEAD`
     accurately reporting the tool's observation (absence of a parseable comment on the bead) rather than asserting an untrue claim about whether a review occurred.
  2. In `tests/fleet-land-message.test.sh`, added unit test assertion `14w1` verifying that emit prints `NONE: no parseable review verdict comment found on bead tk-1`.
- **Verification:**
  - `tests/fleet-land-message.test.sh`: 281/281 passed.
  - Zero internal bead IDs in patch or writeup.
- **Hub Application:**
  ```bash
  cd ~/fleet
  patch -p1 < /path/to/fleet-land-message-true-none-line.patch
  bash tests/fleet-land-message.test.sh
  ```
