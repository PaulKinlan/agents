## Fleet coverage provenance - `fleet-coverage-unmapped-provenance.patch` (agents-tpw5)
Patch: `patches/fleet-coverage-unmapped-provenance.patch` (5 files, 7 hunks, 11.8 KB).
Target: the hub's coverage reporter and every consumer of its state, which is why the rule and the
reader re-pins land together rather than as a rider on the false-positive fix.

### What changes, and what deliberately does not

`remote/check-coverage.py` already states the principle it half-implements. At the fleet-agch guard it says
*"publishing the changed files as 'unmapped' then asserts something the log never said"* - and it enforces
that only when there is NO suite evidence at all. There is no per-path equivalent, so when the reporter's
own PLACEMENT logic cannot place a path the gate DID run a suite for, the path is published in `.unmapped`
with `coverage: PARTIAL`: a fact about coverage, asserted from a fact about the reporter's own inference.

This patch records the **provenance** of each published entry - `unmapped_source` maps every path in
`.unmapped` to `"gate"` (the gate's own `fast-gate: unmapped:` marker: evidence) or `"inference"` (appended
by this script because it could not place the path: inference). **The state machine is untouched**: an
inferred omission still lands in `.unmapped`, still makes the record `PARTIAL`, and still fails loud. The
reader merely gains the ability to tell evidence from inference, which is the same distinction the rest of
the fleet has been enforcing as unreadable-vs-empty.

Two details worth a reviewer's attention. The map is derived from the list that is **actually published**, so
its keys cannot drift from `.unmapped`. And the `UNKNOWN` branch, which clears the list because an absence of
evidence must never be reported as a zero, now clears the map with it - a record naming sources for entries it
does not publish is the same "claim not derived from the object" defect that branch exists to prevent.

### Measured reproduction (installed reporter, before this patch)

Synthetic repo (a `main` branch plus a change branch, so the reporter's merge-base..sha delta resolves), a
log with a running/passed pair and deliberately **no** `fast-gate: unmapped:` marker:

| delta | log says | reporter published |
|---|---|---|
| `tools/docs-text-floor.sh` | `tests/test_docs_text_floor.py` ran | `PARTIAL`, `unmapped: [tools/docs-text-floor.sh]` |
| `tools/deploy-thing.sh` | `tests/test_ops_contract.py` ran | `PARTIAL`, `unmapped: [tools/deploy-thing.sh]` |

The second row is the one that makes this general: `tools/*.sh` is placed by an **arm** in the gate's registry,
so there is no import relation and no stem relation for the reporter to derive, however stems are normalised.
The first row is the shape `agents-a3p9`'s stem fix would reach; **nothing in `a3p9` and no stem fix can ever
reach the second**. With the patch, both rows report `unmapped_source: {path: "inference"}`, the gate's own
marker reports `"gate"`, and a no-evidence run reports `UNKNOWN` with `unmapped: []` and `unmapped_source: {}`.

### Consumers whose meaning changes (all re-pinned here, deliberately)

- `bin/fleet-check`, the **cached-record** reader (`~:284`): the PASS line's coverage note now says
  `" (N unplaced by the reporter, not named by the gate)"` when any entry is inference. In the RECORD the
  field is nested (`.coverage.unmapped_source`, per fleet-265v); the existing `Coverage warning: <files>
  unmapped` text is unchanged, so 14n's assertion still holds.
- `bin/fleet-check`, the **fresh-object** reader (`~:535`): the same note, byte-identical wording, reading the
  top-level field (`fleet-265v` keeps one string across two paths). `COVERAGE WARNING: N unmapped` is
  unchanged, so 14k's assertion still holds.
- **The rule and the reader are pinned by tests in the same patch**: `tests/check-coverage.test.sh` gains
  section 8 (both directions plus the UNKNOWN-clears-the-map invariant); `tests/fleet-gate-check.test.sh` gains
  14q2 (the gate marker records evidence), 14s (an unplaced path is still published and still fails loud),
  14t (it is recorded as inference) and 14u (the reader's cached output says so); `tests/project-template.test.sh`
  gains D17b, asserted as the invariant *the map covers exactly the published list* rather than as a value,
  because whether that fixture's orphan is gate-marked or reporter-inferred depends on the template's arms -
  while "the map describes the list and nothing else" must hold either way.

### Verification performed here, and what the hub must run

Run: `patch -p1 --fuzz=0 --dry-run` over all five files, no fuzz (rule 256). `python3 -m py_compile` on the
reporter and `bash -n` on the other four. `tests/check-coverage.test.sh` **executed against the patched
reporter**: 22 passed / 0 failed with the ORIGINAL file (no regression) and 26 passed / 0 failed with the
patched file, the four extra being section 8. The patched reader expression was executed against records in
both directions, and the substrings 14n and 14k assert were confirmed intact.

Not run here, and they are the hub's to run on install: the new cases in `tests/fleet-gate-check.test.sh`
(14q2/14s/14t/14u) and D17b, because they need the hub's own test harness and a project fixture. Everything
they assert was measured against the patched tool by hand, so a failure there means an environment
difference, not an unmeasured claim.

### Ordering

Apply **after** `agents-0xm2`'s oracle-candidate patch and **after** `agents-a3p9`'s fix, both of which
rewrite nearby lines in the same reporter. This patch's hunks are in the unmapped assembly, the result
object, the two readers and the tests, so it does not restate their work - only the sequencing matters.

### The alternative, for the hub's ratification

Coord is sending a distinct-`UNKNOWN`-for-placement-failure variant to the hub in parallel. If the hub prefers
that, only the spelling changes: the reporter's state machine gains a value, and the two readers and the tests
above must be re-decided for it. The reproduction above is the evidence either way.

### Strict preimages

SHA256 of the hub files this patch was cut against, so a reviewer can confirm the base rather than trust it:

```
remote/check-coverage.py           295a1ce47c4ff942
bin/fleet-check                    455e3b05d2dc172c
tests/check-coverage.test.sh       99406d19cf19f5b5
tests/fleet-gate-check.test.sh     f3919068e04d9127
tests/project-template.test.sh     0c82517f50aaa7fc
```
