## `fleet-verdict-pool-sha-relevance.patch`

This is the write-up for the artifact beside it. It was previously an edit to `patches/README.md`; main replaced
that file with a convention (one `.md` per artifact, no shared index), so the same content now lives here and the
artifact itself is BYTE-IDENTICAL to the cleared object (`86d3a682942a8781...`) - a documentation move, not a
payload re-cut, which is why the byte-identity proof survives it.

In the composed delivery this is step 3 of 5; the composition and its ordering are described in
`patches/fleet-land-message-composition.md` (lands separately, with that stack).

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/fleet-land-message` (lines 418-435, 692-705, 733-750, 958-985)
  - `tests/fleet-land-message.test.sh` (new unit tests, section 37)
- **Baseline file hashes:**
  - `5d0b20d...  bin/fleet-land-message`
  - `cd6d1c5...  tests/fleet-land-message.test.sh`
- **Prerequisites:** Applies on top of `fleet-verdict-transcription-scanner.patch` and `fleet-verdict-model-families-filter.patch`.
- **Problem Statement:**
  1. The verdict pool reader previously evaluated reviewer independence before pin quality / sha-relevance. Upfront filtering discarded all author-lane comments across the entire bead if any non-author candidate existed, even if that non-author verdict was for a dead, superseded commit SHA. Consequently, an author-lane transcribed review for the current branch tip was discarded in favor of a dead non-author review on an older commit, reporting `DIVERGED` (+0 unreviewed commits) and stripping `merge-queue`.
  2. When the delta-identity fallback refused after a rebase, it emitted only `delta_identical: false` without distinguishing whether the file set changed, the content changed, or only the hunk position/line offset moved.
- **Changes:**
  1. **Rank-Scoped Independence (Sha-Relevance First):** In `bin/fleet-land-message`, retain all candidate comments when building candidate pools, evaluating sha-relevance first (`POOL_TIP` before `POOL_OWN`). Evaluate non-author precedence strictly within the selected rank pool so an older non-author comment cannot mask a current tip verdict.
  2. **Delta Mismatch Reason Reporting:** In `bin/fleet-land-message`, analyze why delta identity refused (`files changed`, `content changed`, or `position/offset moved (added/removed lines identical)`). Expose `delta_mismatch` in the JSON output, `rev_line`, and `REFUSING` notification.
  3. **Unit Tests:** In `tests/fleet-land-message.test.sh`, added Section 37 asserting:
     - 37a–37c: An author-lane verdict for the current tip is not masked by a dead non-author verdict for an older SHA.
     - 37d–37f: Within the same tip pool, a non-author verdict outranks an author-lane verdict.
     - 37g–37j: Delta mismatch reason is accurately reported for content changes vs position/offset shifts.
- **Verification:**
  - `tests/fleet-land-message.test.sh` section 37: 10/10 assertions pass (324/324 total in suite when applied in sequence).
  - Clean three-step patch application verified via `git apply --check` against pristine `~/fleet`.
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-verdict-transcription-scanner.patch
  git apply /path/to/fleet-verdict-model-families-filter.patch
  git apply /path/to/fleet-verdict-pool-sha-relevance.patch
  bash tests/fleet-land-message.test.sh
  ```
