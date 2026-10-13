## `fleet-verdict-transcribed-run-binding.patch`

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/fleet-land-message` (lines 278, 655-680)
  - `bin/fleet-verdict-words.sh` (lines 110-190)
  - `tests/fleet-verdict-transcribed-run.test.sh` (lines 28-50, 110-145)
- **Baseline file hashes:**
  Applies sequentially on top of:
  1. `fleet-verdict-transcribed-run.patch`
- **Prerequisite sequence:**
  This patch builds on `fleet-verdict-transcribed-run.patch`.
- **Problem Statement:**
  1. In `bin/fleet-land-message`, `c_run_id` extraction previously selected UUIDs without disambiguating reviewer citations from quoted scout or foreign UUIDs. If multiple UUIDs or multiline/same-line citations occurred, a prior cued scout UUID, trailing foreign UUID, or greedy pattern match could select the wrong run. Furthermore, ambiguous citations should report unknown rather than guessing another run as verified.
  2. In `fleet_verdict_transcribed_run_status` (`bin/fleet-verdict-words.sh`), the verification checked agent type (`reviewer`), terminal status (`complete`), and model identity (`provider/model`), but did not verify relevance to the claimed bead or branch. In addition, substring matching against bead identifiers allowed bead prefixes (such as `tk-1` matching `tk-10`) to falsely verify unrelated runs.
- **Changes:**
  1. **Disambiguated `run_id` Parsing:**
     - In `bin/fleet-land-message`, inspects all UUIDs in the comment.
     - Single UUID is accepted directly.
     - Multiple UUIDs partition clauses on delimiter boundaries (newline, semicolon, pipe, "and") so distinct run references do not greedily conflate across UUIDs.
     - Ambiguous, competing, or uncued multiline/same-line citations leave `c_run_id` empty so report-only unknown is safely preserved.
  2. **Bead & Branch Whole-Identifier Relevance Binding:**
     - In `bin/fleet-land-message`, passes `$BEAD` and `$BRANCH` to `fleet_verdict_transcribed_run_status`.
     - In `bin/fleet-verdict-words.sh`, `fleet_verdict_transcribed_run_status` checks `output-0.log`, `recovery-descriptor.json`, and `events.jsonl` using whole-identifier word boundaries (`(^|[^a-zA-Z0-9_-])$bead([^a-zA-Z0-9_-]|$)`) so bead prefixes (e.g. `tk-1` vs `tk-10`) do not falsely match.
     - If no reference is found, returns `unverified: run <id> does not reference bead <bead> or branch <branch> - an unrelated reviewer run cannot back this claim`.
  3. **Unit Tests:**
     In `tests/fleet-verdict-transcribed-run.test.sh`:
     - Updated `mkrun` helper to support optional log content.
     - Added test case 11: verifies that a run referencing the expected bead passes verification.
     - Added test case 12: verifies that an unrelated reviewer run missing bead/branch references returns `unverified`.
     - Added test case 13: verifies whole-identifier matching where a run for `tk-10` does not verify a claim for `tk-1`.
     - Added test case 13b: verifies that `tk-10` matches `tk-10`.
- **Verification:**
  - `tests/fleet-verdict-transcribed-run.test.sh`: 15/15 passed.
  - Multiline and same-line scout/reviewer disambiguation verified (cases 26f-26j pass).
  - Zero internal bead IDs in patch or writeup.
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-verdict-transcribed-run.patch
  git apply /path/to/fleet-verdict-transcribed-run-binding.patch
  bash tests/fleet-verdict-transcribed-run.test.sh
  ```
