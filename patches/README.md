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
- **Ownership and routing:** these files are outside this VM's write access; the hub owns the fleet tree and is the
  only route. The related correctness bead is `agents-0xm2` (the silent true: the candidate discovery misses a real
  importer, the naming fallback matches a namesake suite, and `covered=True` is published). Its fix is the SAME
  rule consolidation — the candidate path delegating to `has_import_reference`, the rule the pin mirrors — and it
  is deliberately NOT included here: it changes the candidate set for every project using the oracle, and it
  should land as its own measured change. Neither patch closes `agents-0xm2`.
