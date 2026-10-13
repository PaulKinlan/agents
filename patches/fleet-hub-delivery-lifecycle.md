## `fleet-hub-delivery-lifecycle.patch` (agents-945e)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `watchdog/watchdog.mjs` (lines 206, 348, 364)
  - `dashboard/lifecycle.mjs` (lines 6-18, 25)
  - `inbox/lifecycle.mjs` (lines 6-18, 25)
  - `vmui/lifecycle.mjs` (lines 6-18, 25)
  - `inbox/beads.mjs` (lines 305-325, 345-355)
  - `bin/fleet-park` (lines 2-7, 15-40, 50-80)
  - `tests/fleet-park.test.sh` (lines 475-485, 690-715)
  - `tests/watchdog-drivers.test.sh` (lines 30-36, 75-85)
- **Problem Statement (agents-945e):**
  Work delivered to `PaulKinlan/fleet` via patch artifacts is labelled `hub-delivery` on the project beads board.
  Because `hub-delivery` was missing from:
  1. `watchdog/watchdog.mjs`'s `EXCUSED` set (`/^(blocked|merge-blocked|parked|no-auto|merge-queue|waiting|needs-paul|review)$/`),
  2. `watchdog/watchdog.mjs`'s idle-holder driver and alert cleanup, which ignored `EXCUSED` labels entirely,
  3. `dashboard/lifecycle.mjs` and `inbox/lifecycle.mjs`'s parked stage filter (`/^(no-auto|parked|merge-blocked|waiting|needs-paul|paul-decision)$/`), and
  4. `inbox/beads.mjs`'s blocked IDs set (`["merge-blocked", "parked"]`),
  beads labelled `hub-delivery` were treated by the watchdog as active in-flight work and repeatedly triggered idle nudges. On the dashboard, they showed as active unlanded work, prompting merger sweeps to hunt for local landing branches that do not exist.
  Furthermore, `fleet-park` previously had no mechanism to restore bead eligibility on `--unpark`, and ran `bd update` without resolving the bead's project database directory from `~/.fleet/beads-dbs`.
- **Changes:**
  1. **Watchdog Excusal & Alert Cleanup:**
     - Added `hub-delivery` to `EXCUSED` in `watchdog/watchdog.mjs`.
     - Filtered `EXCUSED` labels in the idle-holder driver (line 348) and alert cleanup (line 364) so beads with `hub-delivery`, `parked`, `waiting`, etc. are ignored by idle nudges and clear active alerts.
  2. **Lifecycle Stages:** Added `hub-delivery` to the parked regex in `dashboard/lifecycle.mjs`, `inbox/lifecycle.mjs`, and `vmui/lifecycle.mjs`.
  3. **Beads Queue Exclusion:** Added `hub-delivery` to the blocked/parked label filter in `inbox/beads.mjs` so hub deliveries do not populate the local repository's merge queue.
  4. **Fleet-Park Database Resolution & Unpark Restoration:**
     - In `bin/fleet-park`, added `resolve_bead_dir()` searching `~/.fleet/beads-dbs` (and `.beads` in cwd) to execute `bd update` in the bead's owning database.
     - On park with `bead`, labels the bead `parked` in its resolved database, warning loudly on resolution or update failure.
     - On `--unpark <branch>`, retrieves `prev_bead` from `~/.fleet/parked` and removes the `parked` label, restoring landing eligibility, with explicit resolution warning on failure.
  5. **Unit Tests:**
     - Extended `tests/watchdog-drivers.test.sh` asserting `hub-delivery` recognition and `EXCUSED` label filtering in the idle-holder driver (9/9 tests pass).
     - Extended `tests/fleet-park.test.sh` asserting bead label updates on park and unpark, as well as failure warnings on unresolvable beads (47/47 tests pass).
- **Verification:**
  - `tests/watchdog-drivers.test.sh`: 9/9 tests pass.
  - `tests/fleet-park.test.sh`: 47/47 tests pass.
  - Clean patch application verified against pristine `~/fleet` via `git apply --check` (exited 0).
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-hub-delivery-lifecycle.patch
  bash tests/watchdog-drivers.test.sh
  bash tests/fleet-park.test.sh
  ```
