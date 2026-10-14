## Every published coverage entry says where it came from, inside the entry - `fleet-coverage-unmapped-provenance.patch` (agents-tpw5)

Hub-side artifact: `remote/check-coverage.py` writes the record, and both `bin/fleet-check` readers are
re-pinned in the same patch. Five files, 23 hunks. Apply at the fleet repo root with `patch -p1 --fuzz=0`.

### The problem

When the fast gate reports a changed path as `unmapped`, the record does not say whether the gate's own
`fast-gate: unmapped:` marker named that path - EVIDENCE - or whether the reporter appended it because it
could not PLACE it - the reporter's own inference. Both appear in one voice, so the negative result is not
evidence: it cannot distinguish "no test covers this" from "coverage could not be computed".

Two reproductions were measured against the installed reporter:

| changed paths | result |
|---|---|
| `tools/docs-text-floor.sh` + `tests/test_docs_text_floor.py` | `PARTIAL`, `unmapped: [tools/docs-text-floor.sh]` |
| `tools/deploy-thing.sh` + `tests/test_ops_contract.py` | `PARTIAL`, `partial_reason "1 changed path(s) were not placed by any executed suite"` |

The second is not reachable by a naming fix: the file is placed by an arm, and there is no import or stem
relation to the suite that ran. The reader's own header states the stake: *a warning that always fires is a
warning everyone learns to ignore, and this one exists to catch a genuinely uncovered change.*

### The shape - the hub's refinement, and why it is the load-bearing part

Provenance lives **inside each entry of the published list**, not in a field beside it:

```json
"unmapped": [{"path": "tools/deploy-thing.sh", "source": "inference"}]
```

- `source` is `"gate"` when the gate's `fast-gate: unmapped:` marker named the path, `"inference"` when the
  reporter appended it because it could not place it.
- **There is no parallel field.** A field beside the list can be ABSENT, and then a reader cannot tell a gate
  marker from a record that predates the field - the `cleared:<tip>` label problem rebuilt inside `.unmapped`.
- **An entry always says where it came from.** For a record written before this patch, the entries are plain
  strings; both readers normalise that to **`UNRECORDED`** and SAY it, rather than staying silent. Measured,
  with the clause lifted from the patch rather than retyped:

  | record | reader clause |
  |---|---|
  | post-fix, one gate entry and one inference | `(1 unplaced by the reporter, not named by the gate marker)` |
  | **pre-fix, plain strings** | `(1 UNRECORDED - the record has no source for this entry, so this is not evidence of a gate marker)` |

- De-duplication is on the PATH, and the gate marker beats an inference for the same path: evidence outranks
  a guess. Sorting keeps the published order stable.
- **The state machine is deliberately untouched.** An orphan still lands in `.unmapped`, still makes the
  record `PARTIAL`, and still fails loud; the only change is that the record now says which kind of claim it
  is making. `unmapped` is cleared exactly as before when the run is `UNKNOWN`.

### The readers (both re-pinned here)

Both `bin/fleet-check` readers (the cached record and the fresh object) read the source FROM THE ENTRY, so
the provenance travels with the list that is copied - no nested lookup to drift. The existing message strings
are unchanged for a record that has entries (`COVERAGE WARNING: <paths> unmapped`, `Coverage warning: <path>
unmapped`, the `unplaced by the reporter` clause), so the assertions other beads own keep reading the same
way; the only added clause is the `UNRECORDED` one above, which fires only for a record that predates the
field. Both reader expressions are asserted to be one shared clause, not two that can drift apart.

### Tests

`tests/check-coverage.test.sh` 22 -> **27 passed, 0 failed**. New: `8e` asserts the invariant that every
published entry carries its own source AND that no parallel `unmapped_source` field exists; `8d` asserts
`UNKNOWN` publishes no entries at all. `tests/fleet-gate-check.test.sh` gains `14v`/`14w`, which rewrite the
record for a tree to the PRE-FIX shape and drive the real cached-record reader, asserting that the warning
says `UNRECORDED` and still names the path - the fail-loud half is unchanged.
`tests/project-template.test.sh` `D17b` is now that same invariant rather than "the parallel map covers the
list".

Fourteen existing assertions in `tests/check-coverage.test.sh` asked whether a path was unmapped by matching
a SUBSTRING of the serialized array (`case " $u " in *" path "*`). Because the entry is now an object, that
query is answered from the entry list by a helper, `unmapped_paths`, which is tolerant of both shapes. The
assertions themselves are unchanged - only how the path list is derived - and the helper is verified against
an object list, a pre-fix string list and an empty list.

### Evidence

- `patch -p1 --fuzz=0 --dry-run` clean for all five files, applied from the deployed pre-fix state, and all
  five results byte-identical to the copies verified here.
- The reporter suite, run against the copy the PATCH FILE produced: **27 passed, 0 failed**.
- `python3 -m py_compile remote/check-coverage.py` and `bash -n bin/fleet-check`.

### Ordering and provenance of the base

Apply AFTER `agents-0xm2` and `agents-a3p9` (the first touches the same readers, the second the
placement/stem logic this builds on). Strict preimages, hashed on this VM immediately before the patch was
cut, so the reviewer can confirm the base rather than trust it:

| file | SHA256 (first 16) | bytes |
|---|---|---|
| `remote/check-coverage.py` | `295a1ce47c4ff942` | 41946 |
| `bin/fleet-check` | `455e3b05d2dc172c` | 51977 |
| `tests/check-coverage.test.sh` | `99406d19cf19f5b5` | 15994 |
| `tests/fleet-gate-check.test.sh` | `f3919068e04d9127` | 181092 |
| `tests/project-template.test.sh` | `0c82517f50aaa7fc` | 29804 |

### Re-cut 2026-10-14: the four runner-discovery assertions, and one commit that re-keys the suite

Applied to canon, the first version of this artifact produced four failures in `tests/fleet-gate-check.test.sh` (385 PASSED):
`14s2`, `14t`, `14u`, and a trailing `timeout waiting for check record`. All four are runner-discovery assertions, and all
four come from one commit. The identification is by fingerprint: this artifact's test hunk is `@@ -760,7 +760,45 @@`, which
lands on canon at line 823 with offset 63 - so this is the pair member the hub applied, not the partial-clause artifact.

**The mechanism, stated for the next author.** A test block that COMMITS in the fixture repo re-keys every record lookup that
is keyed on the tree, because the tree hash was computed before the commit. Here the inserted block creates and commits
`tools/unplaced-probe.sh` in `$COV_REPO`, while the suite had already fixed `app_rec=$HOME/.fleet/checks/$app_tree.fast.json`.
So after that commit: `14s2` is a `hasnt` and reads the STALE record written by the `14q`/`14r` block, which by `14r`'s own
assertion CONTAINS `tests/auth.test.ts`; `14t` and `14u` read that same stale record while the suites the fake
`CHECK_FAST_CMD` would have produced went to the PROBE tree's record; and the trailing timeout is the full-gate block, whose
`full_rec` is the OLD tree's `.json` while the check now runs at the probe tree's HEAD, so that record is never written and
`wait_check` - which returns only on a non-empty record carrying `.notified`, or `.done` with a dead pid - waits forever.
This is the same shape as a control that changes the thing it measures, one level down: a FIXTURE that moves the ground under
the assertions that follow it.

**The fix in this re-cut.** The inserted block MOVES to after the runner-discovery blocks, so its commit can no longer
re-key the lookups that precede it; it records `pre_probe_sha` before the commit and restores the repo with
`git -C "$COV_REPO" reset --hard -q "$pre_probe_sha"` afterwards; and the five ids it re-used - `14s`, `14t`, `14u`, `14v`,
`14w` - are renamed `14s-rp`, `14t-rp`, `14u-rp`, `14v-rp`, `14w-rp`. The duplicate ids were a real second defect and are
fixed on their own merits: the originals assert runner results and the inserted ones assert provenance, so sharing a label
made a report of "14u failed" ambiguous to the hub. NOTHING IS DELETED: `14s2`, `14t`, `14u` and `14r` are intact, and every
id present in the preimage is still present.

**THE FOUR ASSERTIONS STAY, AND WHY.** They guard a property that still holds and are not asserting old behaviour:
`remote/check-coverage.py` has ZERO mentions of manifest - there is no manifest mechanism in this path - and `.suites` is
built from the GATE LOG (published at `check-coverage.py:420` as `suites_list = sorted(list(suites))`, read by
`is_suite_executed` at `:502`). Driven on the deployed oracle: a synthetic repo plus a gate log carrying exactly the three
shapes returned `suites = [tests/test_cls.py, tests/vitest.test.ts]` - vitest captured, class-qualified pytest captured,
zero-test deno line NOT captured, all three expectations in one run.

**DRIVEN RED-FIRST (this host, real oracle for suite discovery).** A fixture repo, a stub that writes the deployed oracle's
output as the record for the CURRENT tree, and the same predicates the four assertions use:
PRE-FIX - `14s2=FAIL 14t=FAIL 14u=FAIL 14v=FAIL`, REDS 4 of 4, reproducing the hub's report exactly.
POST-FIX - `14s2=PASS 14t=PASS 14u=PASS 14v=PASS`, REDS 0 of 4.
The stub substitutes only the record WRITER; the tree-keying mechanism and the oracle's suite discovery are the real ones.

**VERIFIED IN THIS TREE, AND THE BOUND STATED.** The test section is a single INSERT-ONLY hunk (it deletes nothing) and
applies to the pinned preimage under `patch -p1 --fuzz=0` at rc 0 with zero rejects and zero offsets; `bash -n` is clean;
`pre_probe_sha` and the restore are present; the probe block sits after the runner-discovery blocks and the restore before
the full-gate block; every preimage id survives and no id gains a second assertion; and the other four file sections are
byte-identical to the previous version. NOT driven here: the end-to-end `tests/fleet-gate-check.test.sh` run, which needs
canon - this host has no copy at the pinned preimages for `bin/fleet-check` or `remote/check-coverage.py`. The hub should
expect all four green.

## Where each entry's source is recorded, and what that costs - measured bounds

The provenance is recorded **inside each entry of the top-level `unmapped` list**, and nowhere else.
There is deliberately no parallel field, so a reader looking for the source under some other key in
the record finds nothing and cannot tell "the gate's marker named it" from "this record predates the
field". That distinction was measured rather than assumed: driving the patched oracle over a fixture
whose gate log carries its own `fast-gate: unmapped:` marker produces
`"unmapped": [{"path": "lib/extra.py", "source": "gate"}]`, while `coverage` in the same record is a
STATE STRING (`coverage: coverage_state`), so `coverage.unmapped[]` is a path that has never existed.
An assertion in the reader suite read that path and failed on a `jq` error for exactly that reason;
it now reads `.unmapped[]` and passes.

**Bounds.** The end-to-end reader-suite run against a hub install is the HUB's measurement, not this
artifact's: the hub tree is on the hub VM and is not reachable from the implementer worktree. What is
verified locally is (a) the driven fixture above, with the real oracle, and (b) the hunk arithmetic
against this artifact's own base, below. Nothing here should be read as a claim about the hub's
387/1 run.

## Rebase onto the same-region landing: moved hunks versus rewritten context

This artifact's base is the pre-`1v7aq` tree. On it every one of the artifact's hunks applies at its
**exact original line number**, with zero offsets - that is the evidence for the base's identity, not
an assumption about it. The hub's landing `1v7aq` edits the same two files in the same region, and
canon rewrote one line that this artifact uses as CONTEXT:

- `bad "7a the ran test file is still reported unmapped"` in the base,
- `ok "7c a changed test file the gate did NOT run is still flagged"` in canon.

The hunk that carries that line fails **at its own original line, not at an offset** - the tell that
separates a rewritten context line from ordinary drift, since offsets alone cannot reveal it. That
context line has been re-cut to canon's text; the artifact's other file sections are byte-identical.
Against a simulated post-`1v7aq` base the artifact applies **23 of 23 hunks with zero offsets and
zero rejects**. One of the two hunks that rejected against canon is identified by this divergence;
the other is not identifiable from the implementer's tree, and guessing at canon's text is worse than
asking for it.
