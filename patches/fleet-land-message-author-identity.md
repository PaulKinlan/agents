## `fleet-land-message-author-identity.patch` (agents-2tov)

- **Target repository:** `PaulKinlan/fleet`
- **Base it was cut against (the live bundle is not a git repo, so the base is named by content):**
  `~/fleet/bin/fleet-land-message` sha256 `980899b73c2cbd87...` and `~/fleet/tests/fleet-land-message.test.sh`
  sha256 `647694f31286dce3...` (first 16 hex each, measured with sha256sum on 2026-10-13).
  It applies with `patch -p1` (or `git am`) to copies of those exact files; if the live files have moved since,
  the hunk contexts below are the thing to re-cut against.
- **Target files:**
  - `bin/fleet-land-message` (author resolution inserted before the verdict-pool filter; the independence block; the `--print-json` emit)
  - `tests/fleet-land-message.test.sh` (new case 36, 12 assertions)
  - `bin/fleet-verdict-words.sh` is deliberately **untouched** (the verdict vocabulary is shared with other
    patches of this same file, so this change does not go near it)
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
  - GREEN with the patch applied: `bash tests/fleet-land-message.test.sh` -> **297 passed, 0 failed**
    (280 pre-existing assertions unchanged, plus the 13 new ones).
  - RED against the unpatched helper:
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
  deliberately not coordinated from here. `agents-9lew`'s patch declares prerequisites
  (`fleet-verdict-transcription-scanner.patch`, `fleet-verdict-model-families-filter.patch`) and its hunk in
  `bin/fleet-land-message` no longer applies to the live file, i.e. it needs a re-cut; that is a separate
  delivery, not this one.

- **Composition with the other outstanding patches to this file:** the LAND-SUMMARY block parser and its
  mention/rejection bookkeeping, the verdict-pool ranking (`agents-9lew`), the clearance shape check
  (`agents-m6fr`), the `--gate` path (`agents-wwss`), the withdrawal behaviour and the verdict-word vocabulary
  are all untouched. One semantic change is worth flagging to anything outside the bundle that reads the JSON:
  `branch_author` previously carried the summary comment's actor and now carries the resolved author identity
  (nothing else in the bundle reads it; no existing test asserted it).
