# Fleet Patches

This directory holds patches for fleet-level infrastructure and tooling that cannot be committed directly to `PaulKinlan/fleet` from this project VM because `~/fleet` is a synced, read-only copy without git remote push credentials on project VMs.

## `fleet-land-message-tree-identity.patch` (agents-19jh)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/fleet-land-message` (lines 755-835, 935-950, 980-990)
  - `tests/fleet-land-message.test.sh` (tests 10w-10z)
- **Problem Statement (agents-yk6m, agents-19jh):**
  When landing a branch with `fleet-land-message --gate <merged-sha> <bead> <branch>`, the helper previously verified branch containment with `git merge-base --is-ancestor "$target_ref" "$gate_commit"`. If the branch author rebased or amended the branch after the merger created the merge commit (moving the branch ref without altering its tree), this ref-ancestry check failed with `REFUSING: --gate <sha> does not contain <branch>`, even though the merged tree and the branch tree were identical.

- **Changes:**
  1. **Tree identity on no-op rebase:** When `target_ref` is not an ancestor of `gate_commit`, the helper inspects the commits merged into `gate_commit` from the branch (`commit_has_tree`). If an ancestor with matching tree identity is found, the no-op rebase is accepted.
  2. **Accepted identity reporting:** Emits `Identity <accepted-identity>` under the `GATE` section of the landing message and inside `.gate.identity` in `--print-json`, recording whether commit ref ancestry or tree identity was verified and that the gate tree matches the landing HEAD tree.
  3. **Strict refusal on genuine tree mismatch:** If the branch tree changed after the merge or the gate tree does not match HEAD tree, the command exits 1 with a descriptive refusal on stderr.
  4. **Deliberate-failure control:** Confirmed that the failure/refusal path writes zero bytes to stdout. Attempting to pipe a failed message into `git commit --amend -F <(...)` aborts with `Aborting commit due to empty commit message`, leaving the default branch HEAD untouched.

- **Verification:**
  - Tested against `/home/exedev/fleet-copy`: all 280 test assertions in `tests/fleet-land-message.test.sh` pass (257 existing + 23 new assertions in 10w-10ab).
  - Fast-forward landed branch tip with no-op rebase tested and verified (test 10aa).
  - Branch-side search in merge commits starts at `$p2` to exclude the merge commit itself; branch matching the merge union tree is strictly refused (test 10za).
  - Unrelated unmerged branch matching an old historical main commit tree strictly refused (test 10ab).
  - Deliberate-failure control directly verifies failure stdout is 0 bytes (via file byte count) and feeding failure stdout into `git commit --amend -F` aborts with empty commit message (test 10z).
  - Clean patch application verified via `git apply --check`.

- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-land-message-tree-identity.patch
  bash tests/fleet-land-message.test.sh
  ```

## `fleet-check-lock-classification.patch` (agents-bc2s)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/fleet-check` (lines 125-180, 250)
  - `tests/fleet-check-lock.test.sh` (new unit tests)
- **Baseline file hash:**
  `0b88ef1e275bfc2e1bb8cdcd1ce793d30daecafac173e937e8b9fe2ea7112d5d  bin/fleet-check`
- **Problem Statement (agents-82qr, agents-bc2s):**
  When a 0-byte `.lock` file exists in `~/.fleet/checks` without a verdict JSON file (e.g. from an interrupted, killed, or dead run), `fleet-check --status` previously returned `{"state":"NONE"}`, indistinguishable from a tree that was never gated. Conversely, if a gate was actively running (lock held by flock) before the JSON record was written, `--status` also returned `NONE` (a live gate reported as no gate).
- **Changes:**
  1. **LOCKED-RUNNING:** When a lock file exists and is held (`! flock -n <lock> true`), `--status` outputs `state: "LOCKED-RUNNING"`, discovers the holding PID via `lsof`/`fuser`, and does not degrade to `NONE`. The detached worker holds the lock descriptor (`flock 9`) throughout its lifetime until exit.
  2. **LOCKED-STALE:** When a 0-byte lock file exists and is free (or a `RUNNING` JSON has a dead PID and free lock), `--status` outputs `state: "LOCKED-STALE"`, reports the mtime of the stale lock, and explains the dead run.
  3. **COMPLETED:** When a verdict JSON exists with a finished verdict (`PASS`, `FAIL`, `KILLED`, `UNKNOWN`, `INCONCLUSIVE`), the lock is irrelevant and the verdict's own status is reported.
  4. **NONE:** Only when neither verdict JSON nor lock file exists is `state: "NONE"` reported.
- **Verification:**
  - Unit tests in `tests/fleet-check-lock.test.sh` pass all assertions covering `NONE`, `LOCKED-STALE` (free 0-byte lock), `LOCKED-RUNNING` (held lock with active pid), `COMPLETED` (`PASS` verdict ignores lock), fast-gate lock isolation (`.fast.lock` without fallback to full lock, test 5a-d), live PID without held lock yielding `LOCKED-STALE` (test 6a-c), and status check during a real detached worker run reporting `LOCKED-RUNNING` and completing to `PASS` (test 7a-c).
  - Regression check: `fleet-check-scope.test.sh` passes 7/7.
  - Clean patch application verified via `git apply --check`.
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-check-lock-classification.patch
  bash tests/fleet-check-lock.test.sh
  ```

## `fleet-worktree-beads-guard.patch` (agents-5br9)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/bd` (lines 208-242)
  - `tests/bd-worktree-decoy.test.sh` (new unit tests)
- **Baseline file hash:**
  `359962a02e19a94b664c6193ec415e22ad00242998264f0515e86ebb0c7956ea  bin/bd`
- **Problem Statement (agents-5br9):**
  When a linked git worktree has a local `.beads/embeddeddolt` (or `.beads/dolt`), upstream `bd`'s `FindBeadsDir` resolves the local `.beads` as authoritative because `hasBeadsDatabase` returns true, bypassing the git-common-dir fallback. `bd` then operates against an empty ledger. Any subsequent `bd dolt push` risks publishing the empty database over the shared remote.
- **Changes:**
  1. **Worktree decoy guard:** `guard_worktree_beads_decoy` function in `bin/bd` shim checks if current toplevel (or `-C <dir>`) is a linked git worktree (`[ -f "$toplevel/.git" ]`).
  2. **Loud actionable refusal:** If `.beads/embeddeddolt` or `.beads/dolt` exists in the linked worktree, refuses the command with exit code 2 and actionable diagnostic:
     `bd: REFUSED: a worktree should hold no database; a decoy here means bd will report an empty ledger and a push from it would overwrite the shared one - move <path> aside and re-run.`
  3. **Canonical checkout exemption:** The canonical checkout (`.git` is a directory) legitimately holds the database and is completely exempt.
- **Verification:**
  - `tests/bd-worktree-decoy.test.sh` passes 13/13 assertions covering canonical checkout exemption, clean worktree pass-through, worktree decoy refusal, `-C` worktree decoy refusal, and recovery after moving decoy aside.
  - Regression check: `tests/bd-guard.test.sh` passes 85/85 assertions; `tests/bd-shim.test.sh` passes 11/11 assertions.
  - Clean patch application verified via `git apply --check`.
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-worktree-beads-guard.patch
  bash tests/bd-worktree-decoy.test.sh
  ```

## `fleet-reviewer-worktree-tip.patch` (agents-6b3k)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `roles/reviewer.md` (lines 20-30, 36-44, 115-122)
  - `tests/reviewer-worktree-tip.test.sh` (new unit tests)
- **Problem Statement (agents-6b3k):**
  Reviewer lanes spawn in a worktree cut from `origin/main` (`lanes.sh spawn <name> "" <bead> reviewer`), not at the tip under review. If a reviewer executes reproduction or mutant tests directly in its worktree without materializing the reviewed tip, it tests `origin/main` instead of the commit under review.
  Measured in live sessions:
  - `rev-dso1`: Ran tests directly in worktree; executed against `origin/main` and ran 4 tests instead of 8. The reviewer caught the discrepancy only because the count looked wrong and had to re-run against `git show 837bb7b`.
  - 100% of reviewer worktrees spawn at `origin/main`. Competent reviewers independently invented manual workarounds: `rev-pdth` unpacked to `/tmp/rev-pdth-tip`, `rev-pdth2` read via `git show`, while `rev-undf`, `rev-azi1`, and `rev-teg3` manually ran `git checkout --detach <sha>`.
- **Changes:**
  1. **Boot Checkout Instruction:** In `roles/reviewer.md` Step 3, explicitly instruct reviewers to check out the reviewed tip via `git checkout --detach "$tip"` immediately after fetching and pinning the delta.
  2. **Reproduction Loud Guard:** In `roles/reviewer.md` Step 2 ("The behaviour under review, reproduced"), add the precondition guard:
     `[ "$(git rev-parse --short HEAD)" = "$tip" ] || { echo "ERROR: worktree HEAD ($(git rev-parse --short HEAD)) does not match review tip $tip - check out tip before measuring (agents-6b3k)" >&2; exit 1; }`
     ensuring any attempt to measure while still at main fails loudly with the mismatched SHAs.
  3. **Finish Restoration:** In `roles/reviewer.md` Step "Finish", instruct restoring the lane branch (`git checkout -q "fleet/${FLEET_LANE}" 2>/dev/null || true`) prior to retirement.
  4. **Contract & Behavioral Tests:** In `tests/reviewer-worktree-tip.test.sh`, assert both the static role prompt requirements and the behavioral transition of a reviewer worktree from main to the detached reviewed tip with disk content verification and explicit nonzero exit code assertion on mismatch (9/9 tests pass).
- **Verification:**
  - `tests/reviewer-worktree-tip.test.sh`: 9/9 tests pass.
  - Regression: `tests/lanes.test.sh` passes 151/151 tests; `tests/review-cadence.test.sh` passes 203/203 tests.
  - Clean patch application verified via `git apply --check`.
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-reviewer-worktree-tip.patch
  bash tests/reviewer-worktree-tip.test.sh
  ```
## fleet-oracle-partial-consumers.patch + fleet-check-partial-clause.patch (agents-ul9v)

- **Target repo:** the fleet tree (hub-owned) — NOT this repository.
- **Target files:** `remote/check-coverage.py` (the coverage oracle) and `bin/fleet-check` (its consumer).
- **Problem:** an omitted consumer is only ever reported INSIDE the `unmapped` bucket. The oracle appends a
  changed file to its `unmapped` list whenever candidate suites were omitted, so a file whose arm IS mapped and
  executed but which omits a consumer is published to a lane as an unmapped file —
  `COVERAGE WARNING: 1 unmapped changed file(s): lib/sandbox.py (omitted: ...)`. The label is wrong in the common
  case, and the genuine finding is demoted to a parenthesis under a false heading.
- **Measured basis:** one variable apart on REAL gate logs (same log, same repo dir, same sha; only the oracle
  file differing). On `tests/test_sandbox.py`-style logs the mapped file leaves `unmapped` and lands in the new
  `partial` field WITH AN IDENTICAL OMITTED LIST (19 = 19 on one log, 20 = 20 on another), and the entry that is
  GENUINELY unmapped on the same log (a changed test file that did not execute) is untouched. The patch relabels;
  it does not widen and it does not silence.
- **Changes:** (1) `check-coverage.py` initialises `partial = {}`, records `partial[f] = sorted(omitted_c)` in
  mode (b) INSTEAD OF `unmapped.append(f)`, publishes `partial` in the result dict, and clears it in the UNKNOWN
  branch (an absence of evidence must not become a partial claim either). (2) `bin/fleet-check` reads `.partial`
  and renders it as its OWN clause in BOTH note-building paths — the fresh path and the previous-attempt path —
  and its warning condition fires on `num_partial > 0` as well. The unmapped clause is OMITTED when its count is
  zero, because otherwise the sentence reads `0 unmapped changed file(s)` while the real finding is an incomplete
  arm, trading one mislabel for another.
- **THE TWO RULES, WHICH IS WHY THIS IS ONE FINDING RATHER THAN TWO:** `find_candidate_tests_for_file` carries
  its OWN import matcher (the walk adds files under a comment reading "Candidate by import/require reference"),
  and it is NOT `has_import_reference`. So the tool has TWO rules for "does this suite consume this module": the
  loose one decides the candidate set and OVER-REPORTS (agents-hbz3's five phantom consumers of `lib/sandbox.py`),
  and the naming fallback then UNDER-REPORTS when the loose rule finds nothing (the silent true filed as
  `agents-0xm2`). THE PHANTOM AND THE SILENT TRUE ARE THE SAME BUG FACING OPPOSITE WAYS, which is why the
  reporting split (`partial`) and the candidate-rule consolidation are one instrument's problem.
- **Consequences for every project using the oracle, named rather than left to be discovered:** consolidating on
  `has_import_reference` makes the candidate set STRICTER about name-adjacent files and BROADER about real
  importers — fewer phantom omissions, and in the narrow case an omission that was previously invisible. Neither
  direction can silently drop an existing warning: a real importer is a real importer under either rule. The
  rejected alternative was to publish "omissions unknown" instead, and the exchange rate is what rules it out: it
  would report unknown for files that ARE genuinely covered by a namesake suite which imports them, so THE ORACLE
  WOULD LOSE CONFIDENCE WHERE IT IS CURRENTLY RIGHT — trading a rare silent true for common noise, and A CHECK
  THAT CRIES UNKNOWN OFTEN ENOUGH TO BE IGNORED PROTECTS NOTHING.
- **Why these two files travel together, and must not be split to make a smaller diff:** shipping the oracle alone
  renders `COVERAGE WARNING: 0 unmapped changed file(s): (omitted: ...)` — a sentence that is FALSE IN A NEW WAY
  rather than merely incomplete, so the half-patch trades one mislabel for another and the net is negative. The
  artefact is the oracle plus the consumer clause, one shared vocabulary, or nothing.
- **Rendering evidence, four variable states through the real clause:** partial only →
  `1 mapped changed file(s) with omitted consumers: lib/sandbox.py (19 omitted)` with NO unmapped clause;
  unmapped only → unchanged wording; both → both clauses; neither → no warning. `omitted > 0` implies a non-zero
  clause, because the omission is recorded in the same branch that now populates `partial`.
- **Verification recipe:** apply both patches to pristine copies of the two files, then run the oracle twice on one
  real gate log — once as-is and once with the omitted suites appended to the `passed:` line — and diff the two
  result dicts. Both directions must hold: a mapped file with omitted consumers appears in `partial` and NOT in
  `unmapped`, and a fully executed candidate set produces NEITHER. Direction (d), the decider that this is not a
  widening: no name-adjacent non-importer (e.g. a `tests/sandbox_fixtures` consumer) appears in the reported set.
  `git apply --check` round-trips byte-identically, which is how these two files were verified before commit.
- **Status of the evidence, with (b) still owed:** (a), (c) and (d) are measured on real gate logs and are
  quoted from the runs that produced them. (b) — a log in which the omitting suite actually executed, so that the
  signal is shown FIRING rather than merely absent-in-the-right-place — is NOT yet measured. It is guaranteed by
  construction (the `partial` entry is created only inside `if omitted_c:`), and three of the four directions
  prove the patch does not misreport while (b) is the one that proves it reports. It is owed before this lands,
  and the blocker is mechanical: the oracle resolves the changed-file set from the worktree's git state, and with
  a gate measuring the current tree the lid log's own sha cannot be checked out without moving the tree under the
  gate. The plan is to re-run the pair in a scratch worktree at the log's sha, or by supplying the changed-file
  set through the environment if the oracle honours it; whichever route is used gets recorded here with its output.
- **Ownership and routing:** these files are outside this VM's write access; the hub owns the fleet tree and is the
  only route. The related correctness bead is `agents-0xm2` (the silent true: the candidate discovery misses a real
  importer, the naming fallback matches a namesake suite, and `covered=True` is published). Its fix is the SAME
  rule consolidation — the candidate path delegating to `has_import_reference`, the rule the pin mirrors — and it
  is deliberately NOT included here: it changes the candidate set for every project using the oracle, and it
  should land as its own measured change. Neither patch closes `agents-0xm2`.
