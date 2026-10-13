## `fleet-land-message-delta-identity-boundary.patch`

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/fleet-land-message` (lines 226, 360-395, 410-440, 690-705, 965-1025)
  - `tests/fleet-land-message.test.sh` (lines 1495-1560)
- **Baseline file hashes:**
  Applies sequentially on top of:
  1. `fleet-verdict-transcription-scanner.patch`
  2. `fleet-verdict-model-families-filter.patch`
  3. `fleet-verdict-pool-sha-relevance.patch`
- **Prerequisite sequence:**
  This patch must be applied after `fleet-verdict-transcription-scanner.patch`, `fleet-verdict-model-families-filter.patch`, and `fleet-verdict-pool-sha-relevance.patch`.
- **Problem Statement:**
  1. In `bin/fleet-land-message`, the pure rebase delta-identity fallback previously required raw byte-identical diffs (`rev_diff = tip_diff`).
  2. When a branch was rebased onto an updated base, line numbers in hunk headers shifted (`@@ -X,Y +X,Z @@`), causing `delta_match` to fail even when the added/removed payload was identical.
  3. Furthermore, when base commits advanced, hunk boundaries could shift such that a trailing or leading blank line changed from context (` `) to an added line (`+`) or vice-versa (the `f5a5` case: identical 5566-byte extracted section text, but 29 vs 30 diff lines).
  4. Both cases produced false-negative `DIVERGED` refusals on valid pure rebases, invalidating review clearances and forcing unnecessary re-reviews.
- **Changes:**
  1. **Hunk Normalization (`flm_normalize_diff`):** Strips hunk headers (`@@ ... @@`), trims boundary blank lines per file, and preserves binary patch content, postimage blob identities (`POSTIMAGE:<hash>`), and file mode lines so altered binary payloads or file mode changes refuse delta identity while pure offset moves and boundary whitespace shifts evaluate as content-identical.
  2. **Normalized Delta Fallback:** When raw diffs differ, evaluates normalized diffs (`rev_norm = tip_norm`). If normalized content matches, marks `delta_match=true`, sets `rev_delta_identical=true` and `rev_delta_normalized=true`, and accepts the clearance.
  3. **Diagnostics & Auditability:** Distinguishes genuine divergences (`files changed` vs `content changed`). When cleared via normalization, reports `[normalized]` in the `PASS` line and exposes `review.delta_normalized=true` in JSON.
  4. **Unit Tests:** In `tests/fleet-land-message.test.sh`:
     - Updated assertions 37i–37j to verify that moved position/offset clears via normalized delta identity (`delta_identical=true`, `delta_normalized=true`).
     - Added assertions 37k–37n testing the `f5a5` hunk boundary blank line shift case, verifying it clears with `delta_normalized=true`.
     - Added assertions 37o–37q testing that altered binary payloads refuse delta identity and report `content changed`.
- **Verification:**
  - `tests/fleet-land-message.test.sh`: 335/335 passed (11 new/updated assertions pass).
  - Sequence verification: applied cleanly on top of `0hjf` + `f5a5` + `9lew` with zero fuzz.
  - Zero internal bead IDs in patch or writeup.
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-verdict-transcription-scanner.patch
  git apply /path/to/fleet-verdict-model-families-filter.patch
  git apply /path/to/fleet-verdict-pool-sha-relevance.patch
  git apply /path/to/fleet-land-message-delta-identity-boundary.patch
  bash tests/fleet-land-message.test.sh
  ```
