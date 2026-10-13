## `fleet-hub-delivery-lifecycle.patch` (agents-945e)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `watchdog/watchdog.mjs` (lines 206, 348)
  - `dashboard/lifecycle.mjs` (lines 6-18, 25)
  - `inbox/lifecycle.mjs` (lines 6-18, 25)
  - `vmui/lifecycle.mjs` (lines 6-18, 25)
  - `inbox/beads.mjs` (lines 305-325, 345-355)
  - `bin/fleet-park` (lines 2-7, 15-40, 50-78)
  - `tests/watchdog-drivers.test.sh` (lines 30-36, 75-85)
- **Problem Statement (agents-945e):**
  Work delivered to `PaulKinlan/fleet` via patch artifacts is labelled `hub-delivery` on the project beads board.
  Because `hub-delivery` was missing from:
  1. `watchdog/watchdog.mjs`'s `EXCUSED` set (`/^(blocked|merge-blocked|parked|no-auto|merge-queue|waiting|needs-paul|review)$/`),
  2. `watchdog/watchdog.mjs`'s idle-holder driver (`mine = b.in_flight.filter(i => i.assignee === id)`), which ignored `EXCUSED` labels entirely,
  3. `dashboard/lifecycle.mjs` and `inbox/lifecycle.mjs`'s parked stage filter (`/^(no-auto|parked|merge-blocked|waiting|needs-paul|paul-decision)$/`), and
  4. `inbox/beads.mjs`'s blocked IDs set (`["merge-blocked", "parked"]`),
  beads labelled `hub-delivery` were treated by the watchdog as active in-flight work and repeatedly triggered idle nudges. On the dashboard, they showed as active unlanded work, prompting merger sweeps to hunt for local landing branches that do not exist.
  Furthermore, `fleet-park` previously had no mechanism to restore bead eligibility on `--unpark`, and ran `bd update` without resolving the bead's project database directory from `~/.fleet/beads-dbs`.
- **Changes:**
  1. **Watchdog Excusal:** Added `hub-delivery` to `EXCUSED` in `watchdog/watchdog.mjs`, and updated the idle-holder driver at line 348 to filter out beads carrying `EXCUSED` labels:
     `const mine = b.in_flight.filter((i) => i.assignee === id && !(i.labels || []).some((x) => EXCUSED.test(x)));`
  2. **Lifecycle Stages:** Added `hub-delivery` to the parked regex in `dashboard/lifecycle.mjs`, `inbox/lifecycle.mjs`, and `vmui/lifecycle.mjs`.
  3. **Beads Queue Exclusion:** Added `hub-delivery` to the blocked/parked label filter in `inbox/beads.mjs` so hub deliveries do not populate the local repository's merge queue.
  4. **Fleet-Park Database Resolution & Unpark Restoration:**
     - In `bin/fleet-park`, added `resolve_bead_dir()` searching `~/.fleet/beads-dbs` (and `.beads` in cwd) to execute `bd update` in the bead's owning database.
     - On park with `bead`, labels the bead `parked` in its resolved database, warning loudly on failure.
     - On `--unpark <branch>`, retrieves `prev_bead` from `~/.fleet/parked` and removes the `parked` label, restoring landing eligibility.
  5. **Unit Tests:** Extended `tests/watchdog-drivers.test.sh` asserting `hub-delivery` recognition and `EXCUSED` label filtering in the idle-holder driver (9/9 tests pass).
- **Verification:**
  - `tests/watchdog-drivers.test.sh`: 9/9 tests pass.
  - `tests/fleet-park.test.sh`: 45/45 tests pass.
  - Clean patch application verified against pristine `~/fleet` via `git apply --check` (exited 0).
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-hub-delivery-lifecycle.patch
  bash tests/watchdog-drivers.test.sh
  bash tests/fleet-park.test.sh
  ```
