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
