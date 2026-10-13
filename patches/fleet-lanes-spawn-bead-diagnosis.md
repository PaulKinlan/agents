## `fleet-lanes-spawn-bead-diagnosis.patch`

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `remote/lanes.sh` (lines 277-295)
  - `tests/lanes.test.sh` (lines 77-95, 986-1008)
- **Baseline file hashes:**
  - `1888587...  remote/lanes.sh`
  - `8a2d1c1...  tests/lanes.test.sh`
- **Problem Statement:**
  1. In `remote/lanes.sh` `spawn`, checking bead existence previously treated any failure of `bd show "$bead"` as "bead not found". Under database contention or transient lock during `bd dolt push`, `bd show` fails or times out, producing a false refusal that a bead does not exist when it is demonstrably present.
  2. The failure mode invited operators to bypass tracking via `none` or blocked lanes from starting.
- **Changes:**
  1. **Transient Lock Retry:** In `remote/lanes.sh`, retry `bd show "$bead"` once after a 0.5s pause if the first attempt fails before refusing.
  2. **Three-Way Failure Discrimination:** Distinguish between:
     - Genuinely absent bead (`bd show: bead does not exist`),
     - Database timeout (`bd show timed out after 10s`),
     - Database error/lock (`bd show failed: <stderr detail>`).
  3. **Unit Tests:** In `tests/lanes.test.sh`, expanded Section 26 asserting:
     - 26o–26q: Database timeout is reported as timeout (not "not found") and cites rule.
     - 26r–26u: Database lock/error is reported with stderr details (not "not found") and cites rule.
     - 26v–26w: Transient database error recovers on retry and completes spawn.
- **Verification:**
  - `tests/lanes.test.sh`: 209/209 passed (9 new assertions pass).
  - Clean patch application verified via `git apply --check` against pristine `~/fleet`.
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-lanes-spawn-bead-diagnosis.patch
  bash tests/lanes.test.sh
  ```
