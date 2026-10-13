## `fleet-land-message-author-identity.patch` (agents-2tov)

- **Target repository:** `PaulKinlan/fleet`
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
  - **The same wrong object was used a second time, in the unsafe direction:** the author-lane verdict filter
    (`REV_POOL`) discounted verdicts authored by `src_who`, so with an appender of a different family the
    APPENDER's verdicts were discounted and the AUTHOR's own verdict counted as independent evidence.
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
  3. **`--author-model <provider/id>` supplies the OPERAND, not a bypass of the rule.** When no object on the VM
     records the authoring model (a lane restarted or rotated since the work was authored), the lander who holds
     the evidence supplies the value; the comparison still runs (a same-family value still refuses) and the
     provenance is recorded as supplied. This is deliberately NOT an `--independence-override`: suppressing the
     refusal would trade a false negative for a false positive and put the fleet's core rule behind a trust-me.
  4. **The author-lane verdict filter asks the same question** (`src_author` instead of the summary's actor), so
     the discounted verdicts are the BRANCH LANE's, which is what that filter means.

- **Verification (measured, and both directions):**
  - GREEN with the patch applied: `bash tests/fleet-land-message.test.sh` -> **296 passed, 0 failed**
    (280 pre-existing assertions unchanged, plus the 12 new ones).
  - RED against the unpatched helper:
    `LM_OVERRIDE=~/fleet/bin/fleet-land-message bash tests/fleet-land-message.test.sh` -> **rc=1, 284 passed /
    12 failed**, the twelve being the new case: `author_lane`, `author_source`, `branch_author`, `author_model`,
    `independence`, `cleared`, the refusal's provenance, the author-lane filter, the transcribed-subagent
    cross-family path, and the three `--author-model` assertions (the unpatched helper rejects the flag).
  - Guard on the guard: the new case asserts that clearing WITH the supplied operand and refusing the SAME tree
    WITHOUT it are different outcomes, so the pin cannot pass by accident.
  - The `.patch` applies to the pristine live files with `patch -p1` (checked with a dry run against copies of
    `~/fleet/bin/fleet-land-message` and `~/fleet/tests/fleet-land-message.test.sh`), and `git am` accepts it.
  - Repro of the live defect on this VM, before the patch:
    `cd <a checkout>; fleet-land-message --print-json agents-jb8m fleet/impl-f6du-jb8m` (the fields are quoted in
    the Problem Statement).

- **Composition with the other outstanding patches to this file:** the LAND-SUMMARY block parser and its
  mention/rejection bookkeeping, the verdict-pool ranking (`agents-9lew`), the clearance shape check
  (`agents-m6fr`), the `--gate` path (`agents-wwss`), the withdrawal behaviour and the verdict-word vocabulary
  are all untouched. One semantic change is worth flagging to anything outside the bundle that reads the JSON:
  `branch_author` previously carried the summary comment's actor and now carries the resolved author identity
  (nothing else in the bundle reads it; no existing test asserted it).
