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
- **Evidence: all four directions measured, on real gate logs.** One variable apart throughout — same log,
  same tree, same commit; only the oracle file differs.
  **(a)** On a real gate log whose ground truth is the gate's own warning (`unmapped ['tools/fast-gate.sh']`,
  three omitted consumers): the unpatched oracle reports `unmapped=['tools/fast-gate.sh']` with 3 omitted, and the
  patched oracle reports `unmapped=[]` with `partial={'tools/fast-gate.sh': [the same three]}` — THE FILE CHANGES
  BUCKET WITH AN IDENTICAL OMITTED COUNT (3 = 3). The identical count is what shows the patch relabels rather than
  widening or silencing.
  **(b)** The same log with the same three consumers reported as EXECUTED — one variable changed: BOTH versions
  report neither field, so the signal is absent exactly when there is no omission, and the patch introduces no
  noise the unpatched oracle does not also produce.
  **(c)** A fully covered file stays silent: in the same runs the other changed file is reported in neither field.
  **(d)** The decider that this is not a widening: the reported set contains only real consumers
  (`tests/test_coverage_contract.py`, `tests/test_gate_entrypoint_config.py`, `tests/test_hermetic_env.py`) — no
  name-adjacent non-importer and no fixture consumer.
- **The recipe is runnable by a reviewer, and here is the part that made it work.** The oracle resolves its
  changed-file set from the (log, repo_dir, sha) triple, and a sha that does not pair with the repo's state yields
  `changed=[]` / `coverage='NONE'` / `no changed files to cover` — an EMPTY RESULT THAT READS AS "COVERAGE IS
  FINE", which is this bead's theme in miniature. Use the sha the log belongs to, with the repository it was taken
  from; then (a) is the two-oracle comparison above, and (b) is the same comparison after appending the omitted
  suite paths to the log's `passed:` line.
- **Ownership and routing:** these files are outside this VM's write access; the hub owns the fleet tree and is the
  only route. The related correctness bead is `agents-0xm2` (the silent true: the candidate discovery misses a real
  importer, the naming fallback matches a namesake suite, and `covered=True` is published). Its fix is the SAME
  rule consolidation — the candidate path delegating to `has_import_reference`, the rule the pin mirrors — and it
  is deliberately NOT included here: it changes the candidate set for every project using the oracle, and it
  should land as its own measured change. Neither patch closes `agents-0xm2`.

### Revision 2 — corrections after the first review (agents-keaf, agents-oeza)

- **agents-keaf (P2, fixed): the cached-PASS serve path.** Revision 1 claimed the clause was rendered in "both
  note-building paths" and that claim did NOT reproduce on the path most lanes actually read: the record assembly
  (`.state=... .suites=$cov[0].suites | .unmapped=$cov[0].unmapped | .omitted=$cov[0].omitted`) copied three fields
  and NOT `partial`, so on a cache hit the new signal was absent — and the old `${unm_str:-files unmapped}` fallback
  then printed a FALSE "files unmapped" clause for a partial-only record, which is the very bug this patch exists to
  remove. FIXED: the assembly now carries `.partial=$cov[0].partial`, and every path builds the sentence one way,
  with each clause printed only when its own count is non-zero. THAT CLAIM IS DELIBERATELY LEFT ABOVE UNCHANGED: it
  is the sentence whose failure a reader could see, and a revision note that hides it would remove the evidence that
  the hole was findable. The correction is the additional site, not a repaired wording.
- **The field has four consumers, and every one of them must render it or the mislabel is merely relocated:** the
  fresh note path, the previous-attempt note path, the cached-PASS serve path (all in `bin/fleet-check`; all three
  fixed), and `fleet-budget`, whose R5 rollup reads `unmapped` and therefore drops a partially-mapped file out of
  its count after the relabel (**agents-oeza**, deliberately still OPEN: a different tool's own semantics decide
  whether a partial file is counted as an unmapped one was or gets its own line, and that is decided by reading it
  rather than by taste). A rollup is read as a summary rather than a detail, so a consumer that silently drops the
  file is worse than one that prints the old word.
- **(b) IS NO LONGER OWED, AND IT IS NO LONGER THE AUTHOR'S CLAIM:** the reviewer independently reproduced it from
  the recipe in this file, on a scratch clone, in the revision under review — which is the standard that makes a
  stated recipe worth more than a stated limit. Everything in the evidence section above therefore has a second
  reader.
- **Gate note:** these are PATCH ARTEFACTS, so no cached gate run applies to them; the evidence standard is a
  reviewer reproducing the directions from the recipe. The in-tree fast gate for this branch passes because the
  branch adds files under `patches/` only, and NOTHING in the patched files can be exercised by this repository's
  suite, because neither file is in it.
- **What revision 2 changes in the diff:** the fleet-check patch only — the record assembly line and the serve-path
  sentence. The oracle patch is untouched, so its four measured directions and the reviewer's reproduction stand as
  they were.

## `fleet-budget-partial-rollup.patch` (agents-oeza + agents-fwlf)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/fleet-budget` (record load at 62, summary returns at 82 and 90, the R5 coverage lines at 163-164)
- **Baseline file hash:**
  `7c29e69ee563d47b00d6302970ebb3e15b16908c1538c546dc6db172021ae5df  bin/fleet-budget`
- **Problem statement — two faces of ONE question, which is why this is one patch and not two.** The question is
  *what does this number mean, and whose is it.*
  1. **agents-oeza — a field whose MEANING was narrower than its label.** The coverage oracle publishes `partial`
     for a changed file whose arm IS mapped and executed but which OMITS a consumer. `fleet-budget` read only
     `unmapped`, so such a file left the R5 rollup entirely. Because the oracle no longer describes that file as
     unmapped, the report's only trace of it became silence: *nobody covers this* and *the arm covers it
     incompletely* were the same zero, and they need different remediations.
  2. **agents-fwlf — a field whose SOURCE was a different RECORD from the one its label named.** The R5 line is
     labelled `fast-gate coverage`, and R5 is defined as the *fast* gate's affected-only selection map
     (`docs/speed.md` R5: "selection is affected-only, driven by a changed-path -> suite map, and the map fails
     loudly on an unmapped file"). The value it printed was `full["unmapped"]` — the *full* gate's count. On a
     fixture where the fast gate has zero unmapped files and the full gate has three, the report claimed three.
- **Changes:**
  1. `partial` is read from each record's `coverage` beside `unmapped` (line 62) and carried through BOTH summary
     returns (82, 90) with the same `max()` treatment — so the JSON output and the NOT-CONFIGURED path expose it
     as well. Every consumer of `unmapped` now has a `partial` counterpart; a field with several consumers is not
     fixed until each of them renders it.
  2. The R5 line reads the FAST record (`fast["unmapped"]`, guarded on `fast`) instead of the full one, so the
     number and its own label finally describe the same gate. The repair could equally have been to relabel the
     line, and that is a decision for the reader of the surrounding intent: what is not acceptable is words and
     number disagreeing about which record they describe, because the number is the part that looks authoritative.
  3. A second line reports partial files on their own terms: `up to N changed file(s) whose mapped arm omitted a
     consumer (R5)`. R5 keeps its exact meaning and wording for unmapped files, and an omitted consumer is still
     a consumer that did not run, so it is reported rather than dropped.
- **Verification — fixture-driven, pristine vs patched on the SAME fixture HOME (one variable apart):**
  Four cases, because a fix that only goes quiet has not been shown to work. `full`/`fast` records are written with
  KNOWN DIFFERENT counts, so the source of the printed number is visible rather than inferred:

  | case | full.unmapped | fast.unmapped | fast.partial | pristine R5 line | patched R5 line | patched partial line |
  |---|---|---|---|---|---|---|
  | A | 3 | 0 | 1 file | claims **3** (false) | silent (correct) | **1** file |
  | B | 3 | 2 | 1 file | claims **3** (wrong record) | claims **2** (correct) | **1** file |
  | C | 1 | 0 | none | claims **1** (false) | silent | silent (no noise) |
  | D | none configured (no `check.conf`) | | | silent | silent | silent, JSON `partial=0` |

  Case B is the falsifiable direction: had the patch still read the full record, it would print 3 there, so the
  fix is caught rather than merely quiet. Case C is the unmutated control. Case D exercises the NOT-CONFIGURED
  return, the other place the summary dict is built.

  Reproduction (the fleet tree itself is never modified — the patched copy is built in a temp root):
  ```bash
  HOME=$(mktemp -d); mkdir -p "$HOME/.fleet/checks"
  printf 'CHECK_CMD="full-cmd"\nCHECK_FAST_CMD="fast-gate.sh"\n' > "$HOME/.fleet/check.conf"
  cat > "$HOME/.fleet/checks/full.json" <<'JSON'
  {"state":"PASS","kind":"full","cmd":"full-cmd","secs":280,"at":"2026-10-12T18:00:00","lane":"merger",
   "coverage":{"suites":["tests/a.py"],"unmapped":["src/one.py","src/two.py","src/three.py"],"partial":{}}}
  JSON
  cat > "$HOME/.fleet/checks/deadbeef.fast.json" <<'JSON'
  {"state":"PASS","kind":"fast","cmd":"fast-gate.sh","secs":40,"at":"2026-10-12T18:00:00","lane":"merger",
   "coverage":{"suites":["tests/a.py"],"unmapped":[],"partial":{"tools/fleet-y.sh":["tests/c.py"]}}}
  JSON
  HOME=$HOME bin/fleet-budget          # pristine: claims "up to 3 ... no mapped suite", and no partial line at all
  ROOT=$(mktemp -d); mkdir -p "$ROOT/bin"; cp bin/fleet-budget "$ROOT/bin/"
  cp /path/to/fleet-budget-partial-rollup.patch "$ROOT/"
  (cd "$ROOT" && git apply -p1 fleet-budget-partial-rollup.patch)   # the fleet tree itself is left untouched
  HOME=$HOME "$ROOT/bin/fleet-budget"  # patched: R5 silent (the fast gate has 0), one partial line, JSON partial=1
  ```
  - Clean patch application verified with `git apply --check`, and the applied patch reproduces the MEASURED
    `bin/fleet-budget` byte-for-byte (`sha256 2d8d89f44d1a2691...`).
  - Stated limit of the fixture: `fleet-budget` is read-only and counts records, so the fixture's records are
    hand-written rather than produced by a real gate run; the oracle's own `partial` field is exercised as a
    shape, not as an end-to-end gate. The end-to-end half is covered by the patch that publishes `partial`.
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-budget-partial-rollup.patch
  bin/fleet-budget          # the R5 lines now describe the fast gate; partial files appear on their own line
  ```

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

## `fleet-oracle-candidate-rule.patch` (agents-0xm2)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `remote/check-coverage.py` (lines 649-655, 670-675)
  - `tests/check-coverage.test.sh` (new unit tests, section 8)
- **Baseline file hash:**
  `64b25262dbbec0357cc896f1663a64ce3f200cd23294930bef0b0183e52d91a3  remote/check-coverage.py`
- **Problem Statement (agents-0xm2, agents-hbz3):**
  The coverage oracle (`remote/check-coverage.py`) previously maintained two divergent consumer identification rules:
  1. `find_candidate_tests_for_file()` restricted import checking with `elif len(stem) >= 4:`, completely skipping `has_import_reference()` for short-stem modules (e.g. `api`, `cli`, `db`, `fs`, `io`, `ui`, `log`). When a short-stem module changed and its namesake suite ran, candidate discovery missed real importing test suites, causing `omitted_c` to be empty and the oracle to fall back to name correspondence. The oracle reported `covered=True` and published `unmapped=[]`, silently concealing unexecuted real importers (a silent true, not a false alarm).
  2. Simultaneously, `find_candidate_tests_for_file()` used a loose subprocess matching regex `subp_pattern` matching bare `\b<stem>\b` within any subprocess or `run(...)` argument. For `lib/sandbox.py`, this falsely harvested any test passing the flag `--sandbox` to commands (e.g. `bwrap --sandbox`), producing 5 phantom omitted suites in `agents-hbz3` (`test_hermetic_env.py`, `test_path_security.py`, `test_pr_fixer_prepass.py`, `test_prepass_pin_boundary.py`, `test_vuln_verify_prepass.py`) that do not import `lib/sandbox.py`.
- **Changes:**
  1. **Consolidated Candidate Import Discovery:** In `remote/check-coverage.py`, remove the `len(stem) >= 4` gate in `find_candidate_tests_for_file()`, delegating all import-based candidate discovery directly to `has_import_reference(content, stem)` across all stem lengths. Short-stem modules now discover all real importing test suites.
  2. **Bounded Subprocess Invocation Matching:** In `subp_pattern`, constrain matching to actual execution of `file_path`, `base`, or bare stem bounded by `(?<![\w-])` and `(?![a-zA-Z0-9_])` (`(?<![\w-])<stem>(?:\.[a-z]+)?(?![a-zA-Z0-9_])`). This excludes command-line argument flags (e.g. `--sandbox` or `-sandbox`) from falsely creating phantom omissions while preserving genuine module-style (`python -m lib.sandbox`), extensionless (`scripts/api`), or transpiled (`scripts/sandbox.js`) invocations.
  3. **Unit Tests:** In `tests/check-coverage.test.sh`, add Section 8 asserting:
     - 8a: Short-stem module (`lib/api.py`, length 3) with an omitted importer (`tests/test_client.py`) is accurately recognized as an omitted candidate rather than reporting a silent true.
     - 8b: Short-stem file is flagged as unmapped when its importing suite is omitted.
     - 8c: Subprocess option flag `--sandbox` does not create phantom omitted consumers for `lib/sandbox.py`.
     - 8d: `lib/sandbox.py` is flagged as unmapped when module-style runner (`python3 -m lib.sandbox`) is omitted.
     - 8e: Module-style subprocess invocation (`python3 -m lib.sandbox`) is detected as omitted candidate.
     - 8f: Extensionless subprocess invocation (`node scripts/api`) is detected as omitted candidate.
- **Consequences for Every Project Using the Oracle:**
  - **Separation from agents-ul9v:** This patch addresses candidate discovery and subprocess invocation matching in `find_candidate_tests_for_file()`. It is strictly separate from the reporting/relabeling changes proposed in `agents-ul9v` (partial omission label distinction). Neither change depends on the other.
  - **Candidate Set Shift:** Because candidate discovery now delegates to `has_import_reference` for all stem lengths and bounds subprocess invocations against argument flags, the candidate set changes:
    - *Short-stem modules (`len < 4`)* gain candidate suites for all tests that actually import them. Fast gates across fleet projects will now loudly report previously hidden omissions when importers are skipped.
    - *Flag-named modules* (like `sandbox`) lose phantom candidate suites, eliminating false omission warnings on unrelated test files that merely pass command-line argument flags (e.g. `--sandbox`).
    - *Module-style and extensionless executors* (e.g. `python3 -m lib.sandbox`, `node scripts/api`) retain candidate recognition without being swallowed or over-narrowed.
  - **Harmonization with In-Repo Pins:** The oracle's candidate discovery rule now uses the exact same definition of module consumption as `tests/test_fast_gate_consumer_coverage.py` (`has_import_reference`), resolving cross-tool divergence permanently.
- **Verification:**
  - `tests/check-coverage.test.sh`: 27/27 tests pass.
  - Measured against `agents-factory` commit `371b0bc` (`lib/sandbox.py`): unpatched oracle reported 20 omitted suites (including the 5 phantoms); patched oracle reports exactly 15 omitted suites matching `has_import_reference` and `agents-pdth`'s allowlist 100%.
  - Clean patch application verified via `git apply --check` against pristine `~/fleet`.
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-oracle-candidate-rule.patch
  bash tests/check-coverage.test.sh
  ```

## `fleet-verdict-transcribed-run.patch` (agents-m6fr)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/fleet-verdict-words.sh` — a run may only back a claim if it **COMPLETED**, and models are compared as
    provider/model
  - `bin/fleet-land-message` — the transcribed path **reports**; it does not refuse
  - `tests/fleet-verdict-transcribed-run.test.sh` (new)
- **Baseline file hashes** (a baseline is only meaningful for the file version it was taken from; these are
  current as of this patch):
  `980899b73c2cbd87774d45d96c326364cfc322d11e190f197fec6d06c1838716  bin/fleet-land-message`
  `b28dde10d67426316c9809fb314f26673c19fcbc15b5cbe402340b5f2416852b  bin/fleet-verdict-words.sh`
- **Patched:**
  `105975ec83d4c8084b8fdf4ba32faceb6cf9b798579bc76676e9e598c5713c1e  bin/fleet-land-message`
  `c3ea2f33d1ea8a7482cf9376fb5e1b654ca85ecf863df1199a5ac1d589abedc1  bin/fleet-verdict-words.sh`
- **Problem.** A verdict posted by the branch author's own lane cannot be told from a reviewer subagent's by its
  actor, because reviewer subagents inherit the parent lane's actor (fleet-15b5). The reader therefore accepts
  such a verdict on the strength of a NAMED reviewer model of another family — a claim written on the comment,
  not evidence.
- **THE FIRST VERSION OF THIS PATCH WAS WITHDRAWN, AND THE REASON IS THE IMPORTANT PART.** It made an
  unresolvable claim a **refusal**: the landing was blocked and `merge-queue` stripped from the bead. An
  independent review found that it broke four legitimate flows:
  1. a reviewer on another VM, whose run directory is not local to the merger's VM;
  2. a verdict relayed from a human operator, where no subagent UUID exists at all;
  3. a review run through a CLI or tmux, which produces no async run directory;
  4. **the fleet's own recorded standard** — the foza convention says a transcription that names its transcriber
     and its source is *"a complete record of the verdict: it is not grounds to re-review the work, to doubt the
     verdict, or to refuse the landing"*, and its precedent cited a **file path** (`~/.fleet/lanes/rev-hay8.events.log`),
     because the first version only understood UUIDs.
  There was a retention race on top: run directories are pruned, so a bead waiting for a heavy slot could have
  its clearance stripped for a review that genuinely happened. The rule that came out of it, and the reason this
  revision is shaped as it is: **an instrument that refuses must be able to name what a correct flow would look
  like, or it will refuse one.**
- **What this version does instead: it reports.** The class (`transcribed-verified` / `transcribed-unverified`)
  and its reason reach the PASS line and the JSON, so a merger or coordinator can see **which** clearance rests
  on a claim rather than an artefact. `rev_cleared` is not touched by this path at all, and the absence of a
  refusal is checkable: `grep -c 'transcribed-unverified)' bin/fleet-land-message` returns `0`.
- **Two defects the review found in the check itself, both fixed:**
  1. `recovery-descriptor.json` is written at **LAUNCH** and carries no status, so a failed, timed-out or
     abandoned reviewer run would have verified a transcribed PASS exactly as well as a successful one. The
     check now requires `status.json`'s `.state` to be `complete` — measured on real run directories, where
     `process-terminal.json` carries `state: "observed"`, which is *not* a completion indicator.
  2. The comparison was on the **provider alone**, so a `gemini-3.8-flash` run verified a claim of a
     `gemini-3.9-pro` run — and the first version asserted exactly that in a test case and called the leniency
     deliberate. It now compares provider/**MODEL** with only the thinking suffix stripped, because the whole
     content of the claim is that a *particular* reviewer ran.
- **Verification:**
  - Unit suite **11 passed, 0 failed**, including the **inverted case 2** (the first version asserted that a
    different version under the same provider verifies; it is now asserted to fail, and the inversion is kept
    visible in the test rather than silently flipped) and two new cases for non-completion.
  - On real beads, the revised reader is **byte-identical in behaviour to the pristine one** for `other-lane`
    verdicts — same instrument, same instant, one variable apart — which is the check that only the transcribed
    path moved.
  - Round trip: the patch applies to pristine copies and reproduces the measured tree exactly.
- **Stated limit.** No live same-lane clearance existed to exercise end to end at the time of writing: the fleet
  now posts clearances from dedicated reviewer lanes, so current clearances are `other-lane`. The transcribed
  path is therefore evidenced at the helper level (unit cases) and structurally (no refusal arm), and the
  end-to-end same-lane case is the one a reader should re-run if it matters.
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-verdict-transcribed-run.patch
  bash tests/fleet-verdict-transcribed-run.test.sh     # 11 passed, 0 failed
  ```

## `fleet-check-no-notify.patch` (agents-94j9)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/fleet-check` (the notifier guard: one condition added)
  - `tests/fleet-check-scope.test.sh` (sets `FLEET_NO_NOTIFY=1`, with the reason written beside it)
- **Baseline file hashes:**
  `1d35baf378a3f71ecb4a65e0dece7ddc0fb91d4e87f172a69a237540c646c4b3  bin/fleet-check`
  `0bc00b917b0f217eef7b1f11d4b32f31c1a687c3fac00cf37ae2cdead0cd9b50  tests/fleet-check-scope.test.sh`
- **Problem statement (agents-94j9).** A lane receives a `[check]` message that names it as the asker and carries
  a sha that resolves nowhere. The `[check]` channel is how a lane learns its gate finished and the fleet's rules
  say to act on it, so a synthetic message wearing a real result's clothes is a silent-green hazard, not noise.
- **Established, by reading:**
  1. `RAN_FULL_MARKER` exists in exactly one place: `tests/fleet-check-scope.test.sh:39` writes a stub
     `check.conf` (`CHECK_CMD="echo RAN_FULL_MARKER"`). That is what attributes the observed message to this test.
  2. That test calls the **real** `bin/fleet-check` (resolved from its own directory), so the run is real and so
     is its notification. The notifier (`bin/fleet-check:592-608`) curls the VM's inbox directly for every waiter
     (`http://localhost:${FLEET_INBOX_PORT:-7777}/msg`), so shadowing `fleet-send` on PATH cannot intercept it,
     and a test that does not set the port talks to the live inbox.
  3. The sha is real but foreign: the test runs in its own temp git repo, so `4eaff45` is a commit *there* and
     resolves nowhere in the repo the message appears to describe. That is why resolving the sha is the defence.
  4. The sender **cannot** recognise the stub: to `fleet-check`, `echo RAN_FULL_MARKER` is a check command like
     any other, and heuristics (a temp cwd, a marker-shaped command) would be guesswork in the one place
     guesswork is least acceptable. So the fix belongs in the test: **a test must not deliver results.**
  5. The worker inherits the environment: `:684` spawns it with plain `setsid nohup bash "$worker_script" …`, and
     nothing in `bin/fleet-check` uses `env -i` or unsets variables, so a variable set by the test reaches the
     notifier.
- **Changes:** the notifier's guard gains `&& [ -z "${FLEET_NO_NOTIFY:-}" ]` — a test suppresses the
  **notification** without suppressing the **run** — and `tests/fleet-check-scope.test.sh` sets the variable
  beside its stub gate, with the reason written there for the next reader.
- **Verification, on an instrument that was checked rather than assumed:**
  - A capture listener impersonating the inbox was bound to a private port and **probed with a known POST before
    anything was concluded from it**, because a capture that records nothing is equally consistent with "no
    message was sent" and "the listener was never up". The author's first attempt made exactly that mistake, and
    a second attempt killed its own shell twice with `pkill -f` patterns that matched the command line doing the
    killing.
  - Pristine suite with the inbox pointed at the verified capture: **12/12 passed, 0 messages delivered**.
  - Patched suite on the same instrument: **12/12 passed, 0 messages delivered** — the knob is inert when nothing
    notifies, which is the control.
  - Round trip: `git apply --check` passes against pristine copies and the applied patch reproduces the measured
    tree byte-for-byte; patched hashes
    `78de460f5f43be84a48a311d3e6ac14e1d7b6d86a31d9f2b03f3d1a13ca1e169  bin/fleet-check`,
    `3e1696352519cf0e4c0786ef497d01f180c6991f05f6311a79b227142373ffc2  tests/fleet-check-scope.test.sh`.
  - **TWO claims the author got wrong, both kept visible rather than tidied away, because the sequence is the
    point.** The first was that the scope test *delivers* the observed message. The second, offered in the first
    version of this section as the correction, was that the notifier sits on a **queued worker** path so the escape
    needs the gate to have *waited for a heavy slot* - which would explain why it was seen once under load and
    never on a quiet VM. **The second was also wrong, and wrong in the more instructive way:** it was a plausible
    mechanism that no measurement had supported, and it survived until an independent review reproduced the defect
    instead of reasoning about it.
  - **The mechanism the reviewer PROVED - a race the test loses to itself.** There is no unqueued path: every gate
    spawns a worker and every worker calls `finish()`. `bin/fleet-check:504` makes `finish()` return early **and
    silently** when the record file is gone. The test's `await_record` returns in about ten milliseconds, because
    the record is written *before* the worker is spawned, so the test races ahead into its own `trap ... rm -rf`
    on the fixture directory. A worker that finishes while the fixture is still alive NOTIFIES; one that finishes
    after the cleanup finds no record and says nothing. Hence load-dependence rather than any queue requirement:
    under CPU load the worker's near-instant `echo RAN_FULL_MARKER` wins the race and the message escapes.
  - **The reproduction, which closes the limit stated in the first version of this section.** Pristine received
    count **1**, with the message captured verbatim - `to: merger`, `[check] full gate for b1e5a41 (asked by
    merger, job 0212e9c1...) : PASS (exit 0, ran 4s after 0s waiting for the heavy slot)` - and patched, on the
    same instrument with a probe POST confirming the listener was live, **0**. The knob is therefore verified on
    the real path rather than reasoned about, and the first version's "not reproduced end to end" is superseded
    by evidence. The first version's recipe (occupy `FLEET_HEAVY_DIR`, then run against the capture) was a
    reasonable route to this and is kept in the bead rather than here.
  - **What the review also settled, so the next reader does not re-open it:** the knob is the right LAYER - the
    test exists precisely to exercise `fleet-check`'s gatekeeping CLI, so stubbing the CLI would destroy the
    subject - and the opt-in polarity is the right trade-off, because inverting it would break every production
    lane's wake-up. A shared test prelude exporting the knob is a follow-up bead, not part of this patch.
- **What this does NOT fix, stated so it is not oversold:** the knob is **opt-in**, THREE test files invoke the
  real `fleet-check` — the other four either stub it (`fleet-land-gate-coverage`, `fleet-land-message`) or
  only mention it (`review-cadence` has the string in JSON fixtures and never executes it;
  `fleet-check-worker-quoting` inspects heredocs statically and runs no gate) — and of those three,
  `fleet-gate-check` isolates the inbox on port 9999 and `fleet-check-scope` now sets the knob. That leaves
  `tests/fleet-check-tree-stability.test.sh` as the remaining caller that talks to the live inbox, and it is
  the one worth adopting the knob: a future test can still forget, exactly as this one did.
  (The first version of this paragraph said "seven test files invoke the real `fleet-check`". That was a count
  of grep hits, not of invocations — a pattern hit is not evidence of behaviour, and the number a fleet-side
  README reports is the number future lanes will read.)
  The only defence that does not depend on test hygiene is receiver-side — resolve the sha (`git cat-file -t`) and
  check the tree is the one you asked to be gated before acting on a `[check]` — and that belongs in the prompts,
  where it costs prompt budget, so it is a coordinator decision rather than part of this patch.
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-check-no-notify.patch
  bash tests/fleet-check-scope.test.sh      # 12/12, and no notification is delivered
  ```

## `fleet-check-status-caller-provenance.patch` (agents-999b)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/fleet-check` (lines 170-175, 190, 347-350)
  - `tests/fleet-gate-check.test.sh` (new unit tests, section 26)
- **Baseline file hashes:**
  - `7e3b0b06137b629ad65ec8da77e525afff02425e69eaf788421d6b06fe994e62  bin/fleet-check`
  - `ca8bffa7991eddfc07480c90a4e1deb6e6019a52bae53dee030cbc258caecba2  tests/fleet-gate-check.test.sh`
- **Problem Statement (agents-999b):**
  1. In `bin/fleet-check --status`, asking for the status of a cached record from another worktree previously overwrote the record's own `repo` field with the caller's worktree (`$top`) and stamped the caller's branch (`$branch`) onto the output.
  2. When a reviewer or coordinator queried the status of a commit checked by another lane, they saw their own worktree and branch attributed to the producing lane's run.
  3. The record's true origin was hidden: `repo` became the caller's path and `branch` became the caller's branch label.
- **Changes:**
  1. **Preserve Producing Checkout Provenance:** In `bin/fleet-check --status`, `.repo` and `.branch` are preserved from the record itself. `produced_in` is maintained as the producing checkout path.
  2. **Distinct Caller Context Keys:** When the caller's checkout or branch differs from the record, they are reported distinctly as `caller_repo` and `caller_branch` rather than overwriting the record's own keys.
  3. **Record Branch on Gate Execution:** In `bin/fleet-check`, capture `cur_branch=$(git rev-parse --abbrev-ref HEAD)` when starting the gate and persist it in the `RUNNING` record.
  4. **Unit Tests:** In `tests/fleet-gate-check.test.sh`, added Section 26 asserting:
     - 26a–26e: Querying a record from a different worktree and branch preserves the producing checkout's `repo` and `branch`, reports the caller's checkout as `caller_repo`, and reports the caller's branch as `caller_branch`.
     - 26f–26i: Querying from the same worktree and branch preserves `repo` and `branch` while omitting `caller_repo` and `caller_branch`.
- **Verification:**
  - `tests/fleet-gate-check.test.sh` section 26: 9/9 assertions pass.
  - Clean patch application verified via `git apply --check` against pristine `~/fleet`.
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-check-status-caller-provenance.patch
  bash tests/fleet-gate-check.test.sh
  ```

## `fleet-verdict-model-families-filter.patch`

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/fleet-verdict-words.sh` (line 75)
  - `bin/fleet-land-message` (line 217)
  - `tests/fleet-land-message.test.sh` (new unit tests, section 36i)
- **Baseline file hashes:**
  `5d0b20d...` (applies on top of `fleet-verdict-transcription-scanner.patch`)
- **Prerequisite:** Applies on top of `fleet-verdict-transcription-scanner.patch`.
- **Problem Statement:**
  1. The provider-family allowlist `FLEET_VERDICT_MODEL_FAMILIES` was previously half-wired: `bin/fleet-land-message`'s `VPFX` expanded `"${FLEET_VERDICT_MODEL_FAMILIES:-...}"` (env-overridable), but `bin/fleet-verdict-words.sh` hardcoded `FLEET_VERDICT_MODEL_FAMILIES='...'` unconditionally on source, clobbering any external override.
  2. In `bin/fleet-land-message`, candidate comment discovery in `REV_CAND` hardcoded the literal list in two `jq` `select()` expressions, ignoring the environment variable. Comments with custom or extended families were filtered out before `flm_select` could inspect them.
- **Changes:**
  1. **Preserve External Override on Source:** In `bin/fleet-verdict-words.sh`, initialize with `FLEET_VERDICT_MODEL_FAMILIES="${FLEET_VERDICT_MODEL_FAMILIES:-...}"` so caller-exported values survive.
  2. **Wire Allowlist into REV_CAND:** In `bin/fleet-land-message`, pass `--arg fam "$FLEET_VERDICT_MODEL_FAMILIES"` to `jq` in `REV_CAND`, allowing the candidate filter to dynamically accept custom or extended model families.
  3. **Unit Tests:** In `tests/fleet-land-message.test.sh`, added Section 36i asserting:
     - 36i1: Off-list custom family is rejected by default.
     - 36i2–36i4: Custom family configured via `FLEET_VERDICT_MODEL_FAMILIES` is accepted by `REV_CAND` and `flm_select`, extracting verdict and marking author-lane transcription.
- **Verification:**
  - `tests/fleet-land-message.test.sh` section 36i: 4/4 assertions pass (314/314 total in suite).
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-verdict-transcription-scanner.patch
  git apply /path/to/fleet-verdict-model-families-filter.patch
  bash tests/fleet-land-message.test.sh
  ```
