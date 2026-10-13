## `fleet-verdict-transcribed-run-binding.patch`

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/fleet-land-message` (lines 278, 655-660)
  - `bin/fleet-verdict-words.sh` (lines 110-185)
  - `tests/fleet-verdict-transcribed-run.test.sh` (lines 28-50, 110-135)
- **Baseline file hashes:**
  Applies sequentially on top of:
  1. `fleet-verdict-transcribed-run.patch`
- **Prerequisite sequence:**
  This patch builds on `fleet-verdict-transcribed-run.patch`.
- **Problem Statement:**
  1. In `bin/fleet-land-message`, `c_run_id` extraction previously used `grep -oE <uuid> | head -1`, selecting the first UUID anywhere in the comment body. When a comment quoted an earlier scout run UUID or referenced an external run before the reviewer run UUID, the wrong run ID was parsed, causing valid reviews to misreport as `transcribed-unverified`.
  2. In `fleet_verdict_transcribed_run_status` (`bin/fleet-verdict-words.sh`), the verification checked only agent type (`reviewer`), terminal status (`complete`), and model identity (`provider/model`), but did not verify whether the run had any relevance to the claimed bead or branch. Consequently, an arbitrary completed reviewer run of the same model could verify an unrelated bead verdict claim.
- **Changes:**
  1. **Cued `run_id` Parsing:**
     In `bin/fleet-land-message`, parses cued run patterns (`(run <id>)`, `run id <id>`, `run_id = <id>`) before falling back to the last UUID (`tail -1`), ensuring the actual reviewer run ID is extracted even when previous scout or foreign UUIDs are quoted.
  2. **Bead & Branch Relevance Binding:**
     - In `bin/fleet-land-message`, passes `$BEAD` and `$BRANCH` to `fleet_verdict_transcribed_run_status`.
     - In `bin/fleet-verdict-words.sh`, `fleet_verdict_transcribed_run_status` accepts optional `[expected-bead]` and `[expected-branch]` arguments.
     - When specified, inspects the run's `output-0.log`, `recovery-descriptor.json`, and `events.jsonl` to verify the run references the expected bead or branch. If no reference is found, returns `unverified: run <id> does not reference bead <bead> or branch <branch> - an unrelated reviewer run cannot back this claim`.
  3. **Unit Tests:**
     In `tests/fleet-verdict-transcribed-run.test.sh`:
     - Updated `mkrun` helper to support optional log content.
     - Added test case 11: verifies that a run referencing the expected bead passes verification.
     - Added test case 12: verifies that an unrelated reviewer run missing bead/branch references returns `unverified`.
- **Verification:**
  - `tests/fleet-verdict-transcribed-run.test.sh`: 13/13 passed.
  - Cued parsing verified with foreign scout run UUID prefixes.
  - Zero internal bead IDs in patch or writeup.
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-verdict-transcribed-run.patch
  git apply /path/to/fleet-verdict-transcribed-run-binding.patch
  bash tests/fleet-verdict-transcribed-run.test.sh
  ```
