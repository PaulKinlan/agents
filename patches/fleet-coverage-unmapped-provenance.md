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
