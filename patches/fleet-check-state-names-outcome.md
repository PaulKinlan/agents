## `fleet-check-state-names-outcome.patch` (agents-lgdv)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/fleet-check` (the state assignment, the two cache-hit branches, the previous-attempt line, the wake text)
  - `bin/fleet-land-message` (the gate section: one validity condition added)
  - `tests/fleet-check-tree-stability.test.sh` (arms now assert the OUTCOME and the qualifier separately; one new arm)
  - `tests/fleet-gate-check.test.sh` (arm 20c3 asserts the label the tree is now given)
- **Baseline file hashes:**
  `455e3b05d2dc172c2d2149dd47b33ac4d77266b57d45765506d2e2b362c10498  bin/fleet-check`
  `f6de093900f6b059af938c2bfc9613d9b66cdcbad8ad5195eb752a7d712be3ee  bin/fleet-land-message`
  `8cc667daef33635fddcb648415df99defa329cc64f84dc4f860fdc4710b57067  tests/fleet-check-tree-stability.test.sh`
  `f3919068e04d91279cae093471ba7bf870146a8530bb8b304e0a2dedc31a56a0  tests/fleet-gate-check.test.sh`

---

## The question, and the answer

**One defect, one mechanism, one place.** The mechanism is a single assignment, and it is in the WRITER that
owns the state name: `finish()` in `bin/fleet-check`.

`finish()` derives the outcome from the command's exit status at `bin/fleet-check:430` — `0 -> PASS`, the
signal/bound codes `-> KILLED`, anything else `-> FAIL` — and then, at `:567-573`, the worktree witness, on
finding that the worktree moved during the run, **overwrote `st` with `STALE`**:

    st=STALE   (tree changed during the run)      :568
    st=STALE   (content changed during the run)   :571

The witness fires in BOTH directions, so **one line produced both faces**: a run that FAILED (`rc=1`, two real
suite failures) was recorded `state=STALE`, and a run that PASSED (`rc=0`) was also recorded `state=STALE`. The
record in the bead is the first: `state=STALE, rc=1, secs=18`, with `FAILED (failures=2)` in its own log.

The measurement was never wrong. `rc` carried the outcome in both cases. What was wrong is that `state` — the
field a reader triages on — said nothing about it, because the qualifier ("this run is not a verdict for the tree
it names") had been written into the field that carries the OUTCOME, deleting the outcome word. Quoting the one
word then said *"not a verdict"* about a red gate and *"failed"* about a green one. That is why the two faces are
not two defects: **they are one word in one position losing one of two facts**, and both are cured by separating
the facts rather than by choosing a preferred value.

### What genuinely IS a second thing, and why a single word could not cover both

There is a **different** fact that also used the word STALE, and it is *not* produced by the line above: the read
path `record_identity()` (`bin/fleet-check:54-69`) reports `state=STALE` in `fleet-check --status` output when the
cached record names **another tree** (or another gate kind). That is not "the run was unsettled"; it is "this
record is not about the tree you asked about", and its cure is different: fetch/ask for the tree the record names,
rather than re-run on a settled tree. Nothing in `finish()` writes that state, and nothing in `record_identity()`
writes the run's state, so they are two producers, not two faces of one.

They are, however, evidence for the same *axis*, which is why the fix is one change and not three:

> **A field must carry the fact it is named for, in the position a reader triages on.**

After this patch the word STALE has exactly one meaning in this tool — *the record is not a verdict for the tree
you asked about* — and it is only ever produced by the read path that means exactly that. The outcome lives in
`state` in every record `finish()` writes, and the run-validity fact lives beside it in `.settled`.

---

## The change

- **`state` names the outcome, always.** The witness sets `unsettled=1` and a `state_reason` instead of
  overwriting `st`.
- **`.settled` carries the validity**, in the same atomic terminal write as `.witnessed` (which names WHAT is
  watched; `.settled` says whether it held still). `.state_reason` keeps the prose.
- **The wake states the outcome first and the qualifier beside it** — one string, two surfaces: the wake now reads
  `FAIL (exit 1, ran 18s after 0s waiting for the heavy slot) - NOT A VERDICT FOR THIS TREE: <state_reason>`.
- **The three consumers in this component consult `.settled`**, because the fix would otherwise trade a
  mislabelled FAIL for a false GREEN:
  - the `PASS` cache-hit branch no longer serves an unsettled PASS as `PASS (cached)` — it re-runs;
  - the `FAIL` cache-hit branch no longer prints *"Re-running cannot change a deterministic failure"* for a run
    whose own reason says re-run on a settled tree — it re-runs;
  - `bin/fleet-land-message`'s `read_gate()` attaches the qualifier instead of putting a bare green into a
    landing message (the same argument `fleet-596p` made for coverage, one field along);
  - plus the `previous attempt on this tree:` line, which a lane reads exactly when the gate is re-run.
- **Absent `.settled` means settled, not unsettled.** Every read is `if has("settled") ... else "true"`, so records
  written before the field existed keep their old meaning (and arm 5 of `fleet-land-gate-coverage.test.sh` still
  pins that shape).

### Two smaller items from the same bead, fixed at the place that owns each fact

1. **The `suites` field held non-suites (`"1"`, `"exit"`, `"modules:"`).** The record's `suites` is the coverage
   extraction's output, and the extraction takes every whitespace token after `^fast-gate:\s*(failed|...):` as a
   suite name — the vocabulary fleet's own `tests/check-coverage.test.sh:161` pins with
   `fast-gate: failed: tests/thing_test.ts`. This repo's emitter put prose in that position:
   `fast-gate: failed: exit $rc (modules: $modules)` (`tools/fast-gate.sh:513`). The payload is now the module
   list, and the exit code is published on a line that is not a marker. **That half is fixed in THIS repo** (see
   `fleet/impl-tdot-lgdv` commit `707f654`, `tools/fast-gate.sh` + `tests/test_fast_gate_mapping.py`), because the
   emitter owns the payload shape it publishes.
2. **The wake named the cache key as an unlabelled "job".** The wake printed the 7-character short sha and, in
   the same parenthetical, the tree under the word `job` — so a reader holding only the wake could not match it to
   `~/.fleet/checks/<tree>.fast.json` without a lookup, which is the shape in which a misread state got attached
   to a real FAIL. The tree IS that key, so it is labelled as the tree: `(asked by <lane>, tree <tree>)`.
   `tests/fleet-gate-check.test.sh` arm 20c3 asserted the old label and is updated with the reason written beside
   it.

---

## Verification

**Red before, green after, same instrument, one variable changed** (`CHECK_OVERRIDE`, which the suite already
supports): the patched `tests/fleet-check-tree-stability.test.sh` run twice, once against a pristine copy of
`bin/fleet-check` and once against the patched one.

- pristine: **11 passed, 37 failed.** The bead's own case is arm `mutate-and-fail` (a command that mutates a
  tracked file and exits 3): `expected the outcome FAIL, not a qualifier: state=STALE ... (exit 3)` and
  `the wake must name the outcome, not a qualifier: ... : STALE (exit 3, ...)`.
- patched: **48 passed, 0 failed**, including arm `mutate-and-fail: the record names the OUTCOME FAIL`,
  `.settled=false`, the wake naming the outcome, the wake naming the tree, and the control arm
  (`clean-run: the record names the OUTCOME PASS`, `.settled=true`, `a settled run's wake carries no qualifier`).
- the read-side arm, `tests/fleet-land-gate-coverage.test.sh` (patched test file, pristine vs patched
  `bin/fleet-land-message`): red `FAIL lgdv: an unsettled PASS travelled as 'PASS (fast gate)'` /
  green `ok lgdv: an unsettled PASS is not quotable as a clean PASS` + `ok lgdv: a settled PASS is unchanged`.
- **round trip:** `git apply --check` passes against pristine copies, and applying the patch reproduces all four
  files byte-for-byte. Patched hashes: `bin/fleet-check`
  `9e3eec045c6a22ee2d2770971d9c0408041c43b35c6b5ed15ebbd498a8c6ee4d`, `bin/fleet-land-message`
  `df59066b8f5b00f04fc94faa57bf16374c72064a1be5fe8612c833c3e062274f`,
  `tests/fleet-check-tree-stability.test.sh`
  `a99135b50175be1516b7329d357b2f2c052ec65427578ccc770b18c4be4d832c`,
  `tests/fleet-gate-check.test.sh`
  `6104c8e219b8f4a143fff7e6ee45fd1608ad2d4e4bddfe1bd6763b2a762329f5`.

**On the suites item, measured against the real consumer rather than reasoned about:** the same gate run was
executed either side of the emitter fix (temporary clones, `GIT_CHANGED=tests/test_abort_probe_tmp.py`) and the
logs fed to fleet's `remote/check-coverage.py`. Pristine emitter: **8 suites for a 5-module run** — the extras
exactly `1`, `exit`, `modules:`. Fixed emitter: **5 suites, exactly the dispatched modules.** The bead's record
shows the same shape at scale: 13 entries for a 10-module run.

## What this does not cover

- **The `.settled` dispatch is not exhaustive.** `fleet-check` and `fleet-land-message` are the consumers this
  patch knows about; a consumer outside `PaulKinlan/fleet` that reads a check record's `.state` and treats `PASS`
  as clearance would need the same one-line condition. Nothing in this repo reads a gate record's state.
- **The witness itself is unchanged.** Whether the ctime-based content witness is the right instrument (the
  intermittent false-positive greens recorded on the bead) is a separate question and a separate patch; this
  patch makes the record honest about what that witness found, it does not make the witness more accurate.
- **`state=STALE` on the read path is unchanged** (a record that names another tree still reports STALE with its
  `.error`). That is deliberate: it is the one meaning the word keeps.
- **The wake's 7-character sha is still 7 characters.** The wake now carries BOTH identities — the short sha as the
  human tip name and the tree as the label the cache keys on — rather than replacing one with the other.
