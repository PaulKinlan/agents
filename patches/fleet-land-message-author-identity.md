## `fleet-land-message-author-identity.patch` (agents-2tov)

- **Target repository:** `PaulKinlan/fleet`
- **Base it was cut against - the APPLIED STATE, and the order matters:** `~/fleet` is not a repo, so the base is
  named by the patches already delivered for this file, applied in this order, and by the content of the live
  files they start from:
  1. the live bundle: `~/fleet/bin/fleet-land-message` sha256 `980899b73c2cbd87...` (first 16 hex, measured
     2026-10-13) and `~/fleet/tests/fleet-land-message.test.sh` sha256 `647694f31286dce3...`;
  2. `patches/fleet-verdict-transcription-scanner.patch`;
  3. `patches/fleet-verdict-model-families-filter.patch`;
  4. `patches/fleet-verdict-pool-sha-relevance.patch` (agents-9lew);
  5. **this patch**, which applies on top of all four.
  Measured on a fresh copy of the live files: steps 2-4 apply with no failures and the bundle's own suite passes
  **324/0**, then this patch applies with no failures and the suite passes **341/0**. Applying this patch before
  step 4 is what FAILS (2 of 9 hunks), which is why the order above is part of the delivery and not a footnote.
- **Problem Statement (agents-2tov):** the independence check classified a review by comparing the reviewer's
  family with the *author's*, and it took the author from the ACTOR OF THE OPERATIVE LAND-SUMMARY COMMENT
  (`pick` -> `src_who`, and `branch_author` was that value) rather than from the branch. A summary appended by a
  different lane - a coordinator replacing a block whose author's `bd` writes were timing out, which the helper
  explicitly supports, and which that landing's own replacement block had to warn about - therefore made the
  APPENDER the author. Measured on `agents-jb8m`: the merger refused with `independence: same-family (reviewer
  model: deepseek/deepseek-flash; author model: deepseek/deepseek-flash)`, because the operative block is coord's
  and `~/.fleet/lanes/coord.model` reads deepseek - while the branch is `fleet/impl-f6du-jb8m` and
  `~/.fleet/lanes/impl-f6du.model` reads `openai-codex/gpt-6-sol`, i.e. genuinely cross-family. Reproduced, not
  reasoned about: `fleet-land-message --print-json agents-jb8m fleet/impl-f6du-jb8m` returned
  `summary.author=agents-factory-coord`, `branch_author=agents-factory-coord`,
  `reviewer_model=deepseek/deepseek-flash`, `author_model=deepseek/deepseek-flash`, `independence=same-family`,
  `cleared=false`.
  - **THE SAME WRONG OBJECT IS WORSE IN THE OTHER DIRECTION, AND THIS IS THE ARGUMENT FOR THE FIX:** the
    author-lane verdict filter (`REV_POOL`) discounted verdicts authored by `src_who`, so with an appender whose
    family differs from the reviewer's, the APPENDER's verdicts were discounted and the AUTHOR's own verdict
    counted as independent evidence. That is a false POSITIVE - it AUTHORISES a landing, which no reviewer sees
    again - whereas the jb8m case was a false negative, which merely blocks one.
  - Note the check is a *comparison of two objects*: the reviewer's model is cued on the verdict at review time,
    while the author's was read from a file that any restart or rotation overwrites. A check whose two sides are
    read at different times is not an independence check.

- **WHICH THEORY SURVIVED MEASUREMENT (the bead's own theory did not):** agents-2tov was filed with the
  hypothesis that the check reads `~/.fleet/lanes/<lane>.model`, a file overwritten when a lane is restarted or
  rotated, so the two sides of the comparison are read at different times. That file is real and that risk is
  real, but it is NOT what produced this refusal: the lane file was read correctly and the wrong OBJECT was
  attributed to it. The measured cause is the author being taken from the ACTOR of the operative LAND-SUMMARY
  instead of from the branch, which is reproducible in one command and does not require a lane to have been
  restarted at all - the appender's record is simply the wrong record. The mutable-model risk remains as the
  residual case that `--author-model` covers; the wrong-object attribution is what the branch-name derivation
  fixes.

- **REVIEW, STATED PLAINLY SO NOBODY WAITS FOR ONE:** this delivery needs a CROSS-FAMILY REVIEW ON THE HUB SIDE
  before it is applied to `~/fleet`. **No review on this project VM is pending and none will be requested**: the
  specialist slot here is held by other work, the reviewer lane that had this branch (round 1, tip 5295b3e) was
  retired without posting a verdict, and the branch moves again after it (rounds 2-4 are the remedy naming, the
  base/ownership documentation and the record of which theory survived measurement, all prose except the remedy
  text). The change was reviewed by ME only in the sense that I drove both directions of its test; that is not a
  verdict and is not offered as one.

- **Changes:**
  1. **The author of a branch is derived from the branch** (`fleet_author_lane_from_branch`): the longest lane
     name recorded as `~/.fleet/lanes/<lane>.model` that matches `fleet/<lane>-<bead>` at a name boundary, so
     `fleet/impl-l2xb-followup2` resolves to `impl-l2xb` and not `impl`. The operative summary's actor is kept
     only as a LABELLED fallback for a branch that names no known lane.
  2. **The derivation names its source**, because a confidently wrong derivation must not be indistinguishable
     from a right one: `author_lane`, `author_source` (`branch-name` / `summary-author`) and
     `author_model_source` (`comment cue` / `lane record <lane> (branch-name author)` / `supplied by the lander`)
     are emitted in `--print-json`, and the `same-family` and `incomplete-provenance` refusals now say where the
     author model came from.
  3. **`--author-model <provider/id>` supplies the OPERAND, not a bypass of the rule, and the refusals NAME it
     as the remedy.** When no object on the VM
     records the authoring model (a lane restarted or rotated since the work was authored), the lander who holds
     the evidence supplies the value; the comparison still runs (a same-family value still refuses) and the
     provenance is recorded as supplied. This is deliberately NOT an `--independence-override`: suppressing the
     refusal would trade a false negative for a false positive and put the fleet's core rule behind a trust-me.
  4. **The author-lane verdict filter asks the same question** (`src_author` instead of the summary's actor), so
     the discounted verdicts are the BRANCH LANE's, which is what that filter means.

- **MANDATORY CASE, AND IT IS THE ONE THAT BIT US:** an APPENDED SUMMARY BY A THIRD PARTY - coord or a
  reviewer - must not change the derived author. That is the live shape of `agents-jb8m` (the operative block is
  coord's replacement) and it is fixture case 36 in `tests/fleet-land-message.test.sh`: the trap is a
  `~/.fleet/lanes/coord.model` recording a family that MATCHES the reviewer while the branch's own lane records a
  different one, so a derivation that still read the appender would refuse. Case 36 asserts the author lane,
  author source, resolved author, author model, the classification, `cleared`, the refusal's provenance, the
  author-lane verdict filter and the transcribed-subagent path.

- **Verification (measured, and both directions):**
  - GREEN on the applied-state base, on two independent trees: `bash tests/fleet-land-message.test.sh` ->
    **341 passed, 0 failed** (the earlier patches' 324 assertions unchanged, plus this change's 17).
  - BASE WITHOUT THIS CHANGE, for the difference: the same suite on the applied state without this patch ->
    **324 passed, 0 failed**, and this change's fixture produces no author-identity JSON at all there.
  - RED against the plain-live helper (the same test file, so the pin is shown to be aimed at the defect):
    `LM_OVERRIDE=~/fleet/bin/fleet-land-message bash tests/fleet-land-message.test.sh` -> **rc=1, 284 passed /
    13 failed**, the thirteen being the new case: `author_lane`, `author_source`, `branch_author`, `author_model`,
    `independence`, `cleared`, the refusal's provenance, the author-lane filter, the transcribed-subagent
    cross-family path, and the three `--author-model` assertions (the unpatched helper rejects the flag).
  - Guard on the guard: the new case asserts that clearing WITH the supplied operand and refusing the SAME tree
    WITHOUT it are different outcomes, so the pin cannot pass by accident.
  - The `.patch` applies to the pristine live files with `patch -p1` (checked with a dry run against copies of
    `~/fleet/bin/fleet-land-message` and `~/fleet/tests/fleet-land-message.test.sh`), and `git am` accepts it.
  - Repro of the live defect on this VM, before the patch:
    `cd <a checkout>; fleet-land-message --print-json agents-jb8m fleet/impl-f6du-jb8m` (the fields are quoted in
    the Problem Statement).

- **Ownership of the other patches to this same file (one writer per file, coord 2026-10-13):** `agents-9lew`
  (verdict-pool sha-relevance, `patches/fleet-verdict-pool-sha-relevance.patch`) is owned by this lane now;
  `agents-m6fr` (clearance shape) is assigned to a lane that is not on this VM, so it is a HUB-SIDE item and
  deliberately not coordinated from here. **`agents-9lew` does NOT need a re-cut** - I first reported that it did
  after measuring it against the live bundle WITHOUT its declared prerequisites (1 of 5 hunks fails at :985);
  applied in its declared order it applies cleanly and the suite is green, so that report is corrected here.
- **INTEGRATION ON THE APPLIED STATE, which the base above is the reason for:** two things this change had to
  adapt to once the earlier patches are present. (1) Its test case is **38**, not 36: the scanner patch owns 36
  (with 36a-36i) and the pool patch owns 37, so the old number collided - a duplicate assertion id is the same
  class of defect as an id that is never selected. (2) The **pre-rank filter block is deliberately NOT
  reintroduced**: against plain live this change edited that block in place, but the rank-scoped pool patch
  supersedes it, and carrying the old block over reverts that fix - measured, not assumed: the first merge of
  these two patches reintroduced it and broke SIX of the earlier patches' assertions (36b1-36b4, 36c, 37c), all
  returning to green once the block was dropped. (3) Case 38j asserts the demotion of an author-lane verdict by
  **which verdict is selected** rather than by `author_lane_verdicts_ignored`, which is 0 in that fixture under
  the rank-scoped pool.
- **Composition with the other outstanding patches to this file:** the LAND-SUMMARY block parser and its
  mention/rejection bookkeeping, the verdict-pool ranking (`agents-9lew`), the clearance shape check
  (`agents-m6fr`), the `--gate` path (`agents-wwss`), the withdrawal behaviour and the verdict-word vocabulary
  are all untouched. One semantic change is worth flagging to anything outside the bundle that reads the JSON:
  `branch_author` previously carried the summary comment's actor and now carries the resolved author identity
  (nothing else in the bundle reads it; no existing test asserted it).
