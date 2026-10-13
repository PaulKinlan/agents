## `fleet-lanes-pull-bead-before-spawn.patch`

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `remote/lanes.sh` (the `spawn)` argument line, immediately after the bead id is parsed)
- **Baseline file hashes:**
  - Pristine `/home/exedev/fleet/remote/lanes.sh`
- **Prerequisite sequence:**
  Independent; applies directly to pristine `PaulKinlan/fleet`.
- **Problem Statement:**
  A new lane's first act is to claim the bead it was handed, so a bead that has not reached this VM's ledger
  yet fails with `no issue found matching <id>` — text indistinguishable from the bead not existing, after
  which the lane creates a duplicate or reports the bead missing. That is a property of the SPAWN SHAPE
  rather than of bd, and the bead id is already known at spawn time, so the spawn path is the layer where the
  condition can be removed instead of reported.
- **Measured basis:**
  A fresh LINKED worktree resolves through the shared git common dir to the canonical ledger
  (`bd info`: 494 issues, nothing created locally), so visibility is bead arrival, not the worktree;
  the failing text comes from the claim path, not from `show`.
- **Changes:**
  1. At spawn, if the bead is not visible in the project checkout (`repo_dir`, reading the ledger the lane will read
     rather than the journal's), pull once and retry.
  2. If it is still not visible after the pull, print a warning saying so — that is a different problem
     (a wrong id, or a different ledger) and the lane must not be told the bead is missing.
  3. The pull is non-fatal: a failed or offline pull still leaves the warning in place and does not abort the
     spawn.
- **Verification:**
  - `git apply --check` clean against deployed `lanes.sh`; `bash -n` clean.
  - The inserted block was exercised against the real bd with a logging shim in three cases:
    bead visible → one `bd show`, no pull, no warning;
    bead missing → `show`, `dolt pull`, `show`, then warning;
    pull failing → non-fatal, warning still printed, exit status unaffected.
  - **Limitation stated rather than hidden:** the spawn path itself was NOT executed, because running
    `lanes.sh spawn` creates a lane on the VM — a side effect this artifact does not need. The reviewer of
    the delivery should treat the three cases above as the evidence and the integration as unproven until it
    runs on a VM where spawning is expected.
  - Zero internal bead IDs in patch or writeup.
- **Relationship to the other changes:**
  `fleet-bd-annotate-missing-bead.patch` makes the failure say which database world it is in for every caller and path;
  this patch removes the cause for the spawned-lane case; the worktree beads guard protects against a per-worktree
  database becoming authoritative. Deliberately separate changes touching different files and reviewable in isolation.
- **Hub Application:**
  ```bash
  cd ~/fleet
  patch -p1 < /path/to/fleet-lanes-pull-bead-before-spawn.patch
  ```
