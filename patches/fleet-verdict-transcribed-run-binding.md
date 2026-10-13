## `fleet-verdict-transcribed-run-binding.patch`

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/fleet-land-message` (lines 278, 655-680)
  - `bin/fleet-verdict-words.sh` (lines 135-230)
  - `tests/fleet-verdict-transcribed-run.test.sh` (lines 28-50, 110-185)
- **Baseline file hashes:**
  Applies sequentially on top of:
  1. `fleet-verdict-transcribed-run.patch`
- **Prerequisite sequence:**
  This patch builds on `fleet-verdict-transcribed-run.patch`.
- **Problem Statement:**
  1. In `bin/fleet-land-message`, `c_run_id` extraction previously selected UUIDs without disambiguating reviewer citations from quoted scout, foreign, or quoted prior UUIDs. Clause partitioning previously split on `and`, which stripped cue associations from second runs (e.g. `reviewer runs <id1> and <id2>`) or allowed foreign cues in earlier clauses to pick foreign runs. Ambiguous, competing, or uncued citations must leave `c_run_id` empty so report-only unknown is safely preserved.
  2. In `fleet_verdict_transcribed_run_status` (`bin/fleet-verdict-words.sh`), the verification checked agent type (`reviewer`), terminal status (`complete`), and model identity (`provider/model`), but did not verify relevance to the claimed bead or branch. In addition, substring matching against bead identifiers allowed bead prefixes (such as `tk-1` matching `tk-10`) to falsely verify unrelated runs, and unescaped regex metacharacters in branch names (such as `.`) allowed wildcard matches.
- **Changes:**
  1. **Disambiguated `run_id` Parsing (`fleet_verdict_extract_run_id`):**
     - Implemented `fleet_verdict_extract_run_id` in `bin/fleet-verdict-words.sh` and wired into `bin/fleet-land-message`.
     - Authoritative verdict-line check: if the verdict line itself carries `(run <uuid>)`, that UUID is authoritative.
     - Single UUID in comment text is accepted directly.
     - Multiple UUIDs: evaluates clauses while filtering out quoted or prior review citations (`(quoted|prior|earlier|foreign|previous)...(verdict|review|run|comment)`). UUIDs explicitly attached to an operative reviewer run cue (e.g. `reviewer run <uuid>`, `reviewer: <uuid>`, `reviewer (run <uuid>)`) are extracted. Plural citations (`reviewer runs`), competing reviewer runs, or quoted prior runs leave `c_run_id` empty so report-only unknown is preserved.
  2. **Bead & Branch Whole-Identifier Relevance Binding with Escaped Metacharacters:**
     - In `bin/fleet-land-message`, passes `$BEAD` and `$BRANCH` to `fleet_verdict_transcribed_run_status`.
     - In `bin/fleet-verdict-words.sh`, `fleet_verdict_transcribed_run_status` checks `output-0.log`, `recovery-descriptor.json`, and `events.jsonl` using whole-identifier word boundaries (`(^|[^a-zA-Z0-9_-])${esc_bead}([^a-zA-Z0-9_-]|$)`) with regex metacharacters escaped (`sed 's/[.[\*^$()+?{}|]/\\&/g'`).
     - Prevents bead prefix aliasing (e.g. `tk-1` matching `tk-10`) and branch wildcard matching (e.g. `fleet/feat-1.0` matching `fleet/feat-1X0`).
     - If no reference is found, returns `unverified: run <id> does not reference bead <bead> or branch <branch> - an unrelated reviewer run cannot back this claim`.
  3. **Unit Tests:**
     In `tests/fleet-verdict-transcribed-run.test.sh`:
     - Updated `mkrun` helper to support optional log content.
     - Test 11: verifies that a run referencing the expected bead passes verification.
     - Test 12: verifies that an unrelated reviewer run missing bead/branch references returns `unverified`.
     - Test 13: verifies whole-identifier matching where a run for `tk-10` does not verify a claim for `tk-1`.
     - Test 13b: verifies that `tk-10` matches `tk-10`.
     - Test 13c: verifies branch with dot matches exact dot.
     - Test 13d: verifies branch with dot does not wildcard match other character.
     - Test 14: single UUID extracted directly.
     - Test 15: competing reviewer runs joined by "and" leave `run_id` empty.
     - Test 16: quoted prior run alongside another run leaves `run_id` empty (no foreign pick).
     - Test 17: scout run alongside reviewer run correctly extracts the reviewer run.
     - Test 18: inline verdict line cue overrides quoted foreign run in comment body.
     - Test 19: quoted prior review with scout run leaves `run_id` empty.
- **Verification:**
  - `tests/fleet-verdict-transcribed-run.test.sh`: all 23 tests pass.
  - Zero internal bead IDs in patch lines and writeup.
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-verdict-transcribed-run.patch
  git apply /path/to/fleet-verdict-transcribed-run-binding.patch
  bash tests/fleet-verdict-transcribed-run.test.sh
  ```
