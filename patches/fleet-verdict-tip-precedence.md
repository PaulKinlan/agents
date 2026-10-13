## `fleet-verdict-tip-precedence.patch`

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/fleet-land-message` (lines 275-305, 510-580)
  - `tests/fleet-land-message.test.sh` (new unit tests, section 38)
- **Baseline file hashes:**
  Applies sequentially on top of the stacked deliveries:
  1. `fleet-verdict-transcription-scanner.patch`
  2. `fleet-verdict-model-families-filter.patch`
  3. `fleet-verdict-pool-sha-relevance.patch`
  4. `fleet-verdict-transcribed-run-binding.patch`
  5. `fleet-land-message-true-none-line.patch`
- **Problem Statement:**
  When multiple review verdicts occur on the same commit tip, `bin/fleet-land-message` suffered two related precedence defects:
  1. **Supersession references rejected as conflicting tokens:** A verdict comment stating `VERDICT: PASS (supersedes the earlier FAIL)` was treated as containing conflicting verdict tokens (`c_has_pos=1` and `c_has_neg=1`), emptying `c_verdict` and forcing the review state to `AMBIGUOUS`.
  2. **Conservative negative override:** In tip disagreement resolution (`flm_have_pos=1` and `flm_have_neg=1`), the code unconditionally forced any negative candidate to win over a positive one (`flm_select "$flm_neg"`), even if the positive verdict was newer or explicitly superseded the earlier negative verdict.
- **Precedence Rule (tip-scoped):**
  1. **Structural claim vs. reference parsing:** When a verdict line contains both positive and negative vocabulary, the parser splits the line into the claim part and the supersession clause (introduced by `supersedes`, `superseding`, `replaces`, `replacing`).
     - If the claim part itself contains compound conflicting tokens (e.g. `PASS: FAIL (supersedes earlier BLOCK)`), the line is rejected as unparseable `AMBIGUOUS`.
     - If the claim part is pure (e.g. `PASS`) and the supersession clause explicitly references an opposing token (`FAIL` or `BLOCK`), the primary token is extracted as the verdict claim and marked superseding.
     - Unrelated prose in the comment body (e.g. `Findings: replaces old implementation`) never triggers supersession.
     - Compound conflicts without supersession (e.g. `PASS: FAIL`, `PASS/FAIL`) remain rejected as unparseable.
  2. **Explicit supersession:** A verdict line explicitly naming an opposing verdict as superseded wins over the referenced verdict regardless of comment order.
  3. **Recency:** In the absence of an explicit supersession, the newest verdict on the tip wins. Recency is determined by timestamp first, breaking ties by comment index.
  4. **Tie-break:** If both timestamps and comment indices are identical with no supersession, falls to negative (conservative).
- **Changes:**
  - In `bin/fleet-land-message:280`: implement structural parsing separating the primary claim from the supersession clause on the verdict line.
  - In `bin/fleet-land-message:515`: replace the unconditional negative override in tip disagreement resolution with the four-part precedence hierarchy, tracking recency via `flm_is_newer` (comparing timestamp then index).
  - In `tests/fleet-land-message.test.sh`: added Section 38 (38a–38n) testing:
    - 38a–38c: Single-line parsing of `PASS (supersedes earlier FAIL)` as `PASS`.
    - 38d–38f: Newer `PASS (supersedes earlier FAIL)` on the same tip clearing over older `FAIL`.
    - 38g–38h: Recency-based resolution where a newer plain `PASS` beats an older `FAIL`.
    - 38i–38j: Older explicit supersession `FAIL (supersedes earlier PASS)` overriding a newer plain `PASS`.
    - 38k: Compound conflicting tokens without supersession (`PASS: FAIL`) remaining `AMBIGUOUS`.
    - 38l: Compound conflicting claim with supersession (`PASS: FAIL (supersedes earlier BLOCK)`) remaining `AMBIGUOUS`.
    - 38m: Unrelated comment body prose mentioning `replaces` not triggering supersession over newer `FAIL`.
    - 38n: Non-superseded tie falling to conservative negative verdict.
- **Verification:**
  - `tests/fleet-land-message.test.sh`: all 340 tests pass (including 14/14 in Section 38).
  - Clean patch application verified via `git apply --check` against the prerequisite-stacked tree.
  - Zero internal bead IDs in patch artifact or write-up.
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-verdict-tip-precedence.patch
  bash tests/fleet-land-message.test.sh
  ```
