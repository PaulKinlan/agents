## `fleet-verdict-tip-precedence.patch` (agents-3vmb, fleet-il4d)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/fleet-land-message` (lines 275-295, 510-580)
  - `tests/fleet-land-message.test.sh` (new unit tests, section 38)
- **Baseline file hashes:**
  Applies sequentially on top of the stacked deliveries:
  1. `fleet-verdict-transcription-scanner.patch` (0hjf)
  2. `fleet-verdict-model-families-filter.patch` (f5a5)
  3. `fleet-verdict-pool-sha-relevance.patch` (9lew)
  4. `fleet-verdict-transcribed-run-binding.patch` (0wc7+ohot)
  5. `fleet-land-message-true-none-line.patch` (h0we)
- **Problem Statement (fleet-il4d, agents-3vmb):**
  When multiple review verdicts occur on the same commit tip, `bin/fleet-land-message` suffered two related precedence defects:
  1. **Supersession references rejected as conflicting tokens:** A verdict comment stating `VERDICT: PASS (supersedes the earlier FAIL)` was treated as containing conflicting verdict tokens (`c_has_pos=1` and `c_has_neg=1`), emptying `c_verdict` and forcing the review state to `AMBIGUOUS`.
  2. **Conservative negative override:** In tip disagreement resolution (`flm_have_pos=1` and `flm_have_neg=1`), the code unconditionally forced any negative candidate to win over a positive one (`flm_select "$flm_neg"`), even if the positive verdict was newer or explicitly superseded the earlier negative verdict.
- **Precedence Rule (tip-scoped):**
  1. **Line grammar claim vs reference:** When a verdict line contains both positive and negative vocabulary, check if the secondary word occurs within an explicit supersession clause (`supersedes`, `superseding`, `replaces`). If so, extract the primary claim token and treat the comment as explicitly superseding; if no supersession keyword is present (e.g. `PASS: FAIL`, `PASS/FAIL`), keep the compound conflict unparseable.
  2. **Explicit supersession:** A verdict explicitly naming another as superseded wins over the referenced verdict regardless of order.
  3. **Recency:** In the absence of an explicit supersession, the newest verdict on the tip wins.
  4. **Tie-break:** If timestamps and indices are identical with no supersession, falls to negative (conservative).
- **Changes:**
  - In `bin/fleet-land-message:280`: allow verdict lines with both positive and negative vocabulary to parse the primary token when an explicit supersession keyword (`supersedes`, `superseding`, `replaces`, `replacing`) is present.
  - In `bin/fleet-land-message:515`: replace the unconditional negative override in tip disagreement resolution with the four-part precedence rule (explicit supersession first, recency second, conservative tie-break third).
  - In `tests/fleet-land-message.test.sh`: added Section 38 (38a–38k) testing superseding line grammar, superseding PASS over older FAIL, recency-based PASS over older FAIL, superseding FAIL over newer PASS, and unparseable compound conflict rejection.
- **Verification:**
  - `tests/fleet-land-message.test.sh`: all 336 tests pass (including 11/11 in Section 38).
  - Clean patch application verified via `git apply --check` against the prerequisite-stacked tree.
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-verdict-tip-precedence.patch
  bash tests/fleet-land-message.test.sh
  ```
