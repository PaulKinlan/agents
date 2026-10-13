## `fleet-verdict-transcription-scanner.patch` (agents-0hjf)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `roles/reviewer.md` (lines 80-105)
  - `bin/fleet-land-message` (lines 215-270, 480-535, 930-990)
  - `tests/fleet-land-message.test.sh` (new unit tests, section 36)
- **Baseline file hashes:**
  - `ff0f056338d5324964279b8296ae6992f261dc6c3073575a5e28845237a60396  bin/fleet-land-message`
  - `ad225a927e292365019947390c1b9275fc2eeb9f434e23e0e237fd4d17f001a8  roles/reviewer.md`
- **Problem Statement (agents-0hjf, agents-r6tc, agents-74qx, agents-vt7w, agents-5br9):**
  1. Builtin subagent reviewers cannot comment on beads directly; their review verdicts must be transcribed by implementer/parent lanes. When reviews were posted with inline prefixes such as `Independent Reviewer: <model> (run <id>) -> VERDICT: PASS` (as in `agents-74qx` and `agents-vt7w`), the merger scanner's `REV_CAND` filter and `flm_select` rejected them completely because `VERDICT:` was not the first token on the line. The merge commit consequently recorded `REVIEW / NONE: no review verdict found on bead` despite verified cross-family reviews existing on the bead.
  2. The authorship demotion filter in `fleet-ry7m` previously partitioned the candidate pool globally upfront (`REV_POOL="$_nonauth"`). If an older non-author review existed on the bead (e.g. `rev-5br9b` reviewing `19c7260`), and the author subsequently rebased and transcribed a fresh cross-family review on the new tip (`783bd53`), the author's valid tip review was discarded upfront. The scanner fell back to the older non-author review, failed with `DIVERGED`, and silently masked the author's valid review on the new tip (occurring three times on `agents-5br9`).
  3. Demotions and author-lane transcriptions were silent or lacked clear attribution in the final landing message.
- **Changes:**
  1. **Codified Transcribed Verdict Template:** In `roles/reviewer.md`, codified the rule-27 Transcribed verdict comment template for implementers posting on behalf of builtin subagents: standalone comment, verifier model, subagent run UUID, transcriber lane, source path or task from which the verdict was recovered, explicit on-behalf statement, Delta as a pair (`merge-base..tip`), Gate naming the verified tree, and checkability invariants prohibiting silent SHA disagreement.
  2. **Extended Verdict Scanner Prefix Recognition:** In `bin/fleet-land-message`, updated `REV_CAND` and `VPFX` to parse inline reviewer prefixes (`Independent Reviewer: <model> (run <id>) -> VERDICT: PASS`), establishing the semantic rule that words before the arrow are context about the subject (model plus optional run-id parenthetical) and the arrow introduces the verdict. Arbitrary tokens or verdict words before the arrow are prohibited, and model provider family must match known fleet families (`FLEET_VERDICT_MODEL_FAMILIES`).
  3. **Rank-Scoped Author-Lane Demotion:** In `bin/fleet-land-message`, moved author-lane demotion inside rank evaluation (`POOL_TIP` and `POOL_OWN`). A non-author review only demotes author-lane verdicts *for that specific rank/tip*. If no non-author review exists for the rebased tip, the author's transcribed cross-family review is eligible and recognized.
  4. **Name the Survivor and Surface Warnings:** When an author-lane transcription is selected as operative, the landing message explicitly adds a warning: `(WARNING: operative review is an author-lane transcription from comment #$rev_idx; no non-author review operative for this tip)`. In JSON, `selected_comment_index`, `selected_comment_author`, and `author_lane_transcription: true` are emitted. When a non-author review demotes author verdicts, the demoted comment count and indices are legibly reported.
  5. **Unit Tests:** In `tests/fleet-land-message.test.sh`, added Section 36 asserting:
     - 36a: Inline `Independent Reviewer: <model> (run <id>) -> VERDICT: PASS` is recognized with `state: CURRENT`, `verdict: PASS`, reviewer model, run ID, and `author_lane_transcription: true`.
     - 36b: An author-transcribed review on a rebased tip clears even when an older non-author review exists on a pre-rebase commit.
     - 36c: The landing message carries the author-lane transcription warning naming the survivor.
     - 36d: A non-author review on the same tip takes precedence and demotes author-lane reviews with full reporting.
     - 36e: Demoted author-lane FAIL comments cannot override an operative non-author PASS on the same tip via disagreement scanning.
     - 36f: Conflicting inline verdicts (e.g. FAIL -> VERDICT: PASS) bounded at first arrow, refusing as AMBIGUOUS.
     - 36g: Pre-arrow verdict words (in model slot, before model, after model, or slash-joined e.g. FAIL/PASS) prohibited, failing to match as inline prefix.
     - 36h: Non-author PASS on tip followed by newer author-lane unparseable verdict on old commit does not trigger AMBIGUOUS.
- **Verification:**
  - `tests/fleet-land-message.test.sh`: 287/287 tests pass.
  - Measured against `agents-74qx` in `agents-factory`: unpatched scanner reported `state: NONE`, `verdict: ""`; patched scanner correctly recognizes `state: UNPINNED`, `verdict: "PASS"`, reviewer `openai-codex/gpt-6-sol`, run ID `f2ab3169-3a74-408d-af18-343734dd2bf0`, `author_lane_transcription: true`.
  - Clean patch application verified via `git apply --check` against pristine `~/fleet`.
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-verdict-transcription-scanner.patch
  bash tests/fleet-land-message.test.sh
  ```
