## `fleet-hub-delivery-lifecycle.patch` (agents-945e)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `watchdog/watchdog.mjs` (lines 206)
  - `dashboard/lifecycle.mjs` (lines 6-18, 25)
  - `inbox/lifecycle.mjs` (lines 6-18, 25)
  - `vmui/lifecycle.mjs` (lines 6-18, 25)
  - `inbox/beads.mjs` (lines 305-325, 345-355)
  - `bin/fleet-park` (lines 2-7, 42-49)
  - `tests/watchdog-drivers.test.sh` (lines 75-84)
- **Problem Statement (agents-945e):**
  Work delivered to `PaulKinlan/fleet` via patch artifacts is labelled `hub-delivery` on the project beads board.
  Because `hub-delivery` was missing from:
  1. `watchdog/watchdog.mjs`'s `EXCUSED` set (`/^(blocked|merge-blocked|parked|no-auto|merge-queue|waiting|needs-paul|review)$/`),
  2. `dashboard/lifecycle.mjs` and `inbox/lifecycle.mjs`'s parked stage filter (`/^(no-auto|parked|merge-blocked|waiting|needs-paul|paul-decision)$/`), and
  3. `inbox/beads.mjs`'s blocked IDs set (`["merge-blocked", "parked"]`),
  beads labelled `hub-delivery` were treated by the watchdog as active in-flight work and repeatedly triggered idle nudges. On the dashboard, they showed as active unlanded work, prompting merger sweeps to hunt for local landing branches that do not exist.
  Additionally, parking a branch without a readable bead label left the park state invisible to the watchdog and dashboard.
- **Changes:**
  1. **Watchdog Excusal:** Added `hub-delivery` to `EXCUSED` in `watchdog/watchdog.mjs`.
  2. **Lifecycle Stages:** Added `hub-delivery` to the parked regex in `dashboard/lifecycle.mjs`, `inbox/lifecycle.mjs`, and `vmui/lifecycle.mjs`.
  3. **Beads Queue Exclusion:** Added `hub-delivery` to the blocked/parked label filter in `inbox/beads.mjs` so hub deliveries do not populate the local repository's merge queue.
  4. **Fleet-Park Bead Labeling:** In `bin/fleet-park`, document that the readable parked state derived by dashboard and watchdog is the bead label; when a bead is provided, automatically add the `parked` label to the bead.
  5. **Unit Tests:** Added assertions in `tests/watchdog-drivers.test.sh` verifying `hub-delivery` presence in the watchdog and lifecycle modules (9/9 tests pass).
- **Verification:**
  - `tests/watchdog-drivers.test.sh`: 9/9 tests pass.
  - `tests/fleet-park.test.sh`: 45/45 tests pass.
  - Clean patch application verified against pristine `~/fleet` via `git apply --check`.
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-hub-delivery-lifecycle.patch
  bash tests/watchdog-drivers.test.sh
  bash tests/fleet-park.test.sh
  ```
