## `fleet-land-message-delta-identity-boundary.patch`

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/fleet-land-message` (lines 226, 360-440, 690-705, 965-1025)
  - `tests/fleet-land-message.test.sh` (lines 1495-1650)
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
  3. Furthermore, when base commits advanced, hunk boundaries could shift such that a trailing or leading blank line changed from context (` `) to an added line (`+`) or vice-versa (the `f5a5` case: identical extracted section text, but diff hunks conflate context lines with added lines).
  4. Heuristic diff normalization proved fragile across edge cases (stripping `--`-leading removals, dropping newline markers, leaking binary state across files, or collapsing trailing blank additions).
- **Changes (Shape A: Object/Section Comparison):**
  1. **Direct Object Comparison (`flm_compare_rebased_objects`):** Instead of normalizing derived diff text, directly compares underlying git objects and sections:
     - **Postimage Blob Identity:** Compares `git rev-parse "$rev_full:$file"` with `git rev-parse "$tip_full:$file"`. Newly added files (such as patch artifacts and companion writeups), untouched binaries, and identical file trees are verified byte-for-byte.
     - **Structured Section Extraction (`flm_extract_md_section`):** For markdown files (such as `patches/README.md`) where `## <heading>` sections are appended or inserted, extracts the section header-to-next-header from both `rev_full` and `tip_full` and asserts exact byte equality. Verifies no unrelated lines were modified outside the added sections.
     - **Pure Appends:** For text files where content was appended at the end of the file, extracts the appended tail lines and verifies exact byte equality and unmutated base prefixes.
     - **Fail Closed:** Any unclassified difference, altered text, altered binary, or unrecognized modification immediately fails closed with `delta_mismatch="content changed"`.
  2. **Normalized Delta Fallback:** When raw diffs differ, evaluates object/section identity via `flm_compare_rebased_objects`. If identical, marks `delta_match=true`, sets `rev_delta_identical=true` and `rev_delta_normalized=true`, and accepts clearance.
  3. **Diagnostics & Auditability:** Distinguishes genuine divergences (`files changed` vs `content changed`). When cleared via normalization, reports `[normalized]` in the `PASS` line and exposes `review.delta_normalized=true` in JSON.
  4. **Unit Tests:** In `tests/fleet-land-message.test.sh`:
     - Assertions 37i–37j: Pure offset moves clear via normalized delta identity (`delta_identical=true`, `delta_normalized=true`).
     - Assertions 37k–37n: The `f5a5` boundary blank shift clears with `delta_normalized=true`.
     - Assertions 37o–37q: Altered binary payloads refuse delta identity and report `content changed`.
     - Assertions 37r–37t: Real trailing blank additions refuse delta identity and report `content changed`.
     - Assertions 37u–37w: Context blank flip (blank is context in rev, added in tip) clears via Shape A section extraction.
     - Assertions 37x–37z: Different `--`-leading line removals refuse delta identity and report `content changed`.
     - Assertions 37aa–37ac: Trailing newline presence differences refuse delta identity and report `content changed`.
     - Assertions 37ad–37af: Binary before text refuses on binary mismatch without state leak.
- **Verification:**
  - `tests/fleet-land-message.test.sh`: 347/347 passed (23 new/updated assertions pass).
  - Sequence verification: applied cleanly on top of `0hjf` + `f5a5` + `9lew` with zero fuzz.
  - Real commit verification: `504c1b1` vs `f855e8f` clears (PASS); `ab2a47c..0ce75ef` vs `64fb51c..3e0bd59` refuses (PASS).
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
