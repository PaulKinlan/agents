## `fleet-check-branch-fields.patch` (agents-npyn, RE-CUT r2)

**This supersedes `fleet-check-branch-provenance.patch` (r1, tip 3c28a83c, branch `fleet/imp-dflt-npyn`).**
The hub chose the alternative field definition, so the field named `branch` is gone rather than relabelled.

- **Target repository:** `PaulKinlan/fleet` (`~/fleet` here is a synced, read-only copy and not a git
  repository, so this is delivered under `patches/` and is **NOT applied here**).
- **Target files:** `bin/fleet-check` and `tests/fleet-gate-check.test.sh`.
- **Prerequisite base hashes:** `bin/fleet-check` = `455e3b05d2dc172c2d2149dd47b33ac4d77266b57d45765506d2e2b362c10498`;
  `tests/fleet-gate-check.test.sh` = `f3919068e04d91279cae093471ba7bf870146a8530bb8b304e0a2dedc31a56a0`.
- **Apply:** from `~/fleet`, `git apply patches/fleet-check-branch-fields.patch`.
- **After applying:** `bin/fleet-check` = `f38803150ba06650a39cc95ae490d40b7107b925e0562cf88920cd77d082043c` and `tests/fleet-gate-check.test.sh` = `9b2e721fcb9ea087fc05eef4c903ab13656d1d1ad22bd1d2df353337c4ee1f62`,
  byte-identical to the tree both directions were measured on.
- **Prompt budget:** none (no `roles/` change).

### What changed from r1, and why

r1 kept a field named `branch` holding the ASKING checkout's branch, with the producer disclosed beside it as
`produced_branch`, mirroring `repo`/`produced_in`. The hub's decision: a field called `branch` living in a
**record** while it holds the **reader's** branch is the original defect in slower motion — a verdict record is
read by many actors, and each of them would see its own branch in that same field. So the name is **gone**, not
relabelled, and there are now two fields with one meaning each:

| field | meaning | when present |
|---|---|---|
| `produced_branch` | the branch the suite actually ran on — a property of the **record** | whenever the record knows it, **including when it equals the caller's**; **ABSENT** when it does not, never guessed |
| `caller_branch` | the branch of the checkout **asking** — a property of the **read** | whenever the asking checkout reports one |

The writer now records the producing branch as `produced_branch` (so the record itself never carries a field
whose name invites a reader's branch), the overlay adds only `caller_branch`, and the record's `produced_branch`
flows through the merge untouched — which is why there is no equality rule and no conditional logic left. The
internal variable is named `caller_branch` too, so nothing in the file invites the old definition back. The
`NONE` path (no record at all) reports `caller_branch` only.

### Measured, status path only, same record read from two checkouts

| record | reader | `caller_branch` | `produced_branch` | bare `branch` |
|---|---|---|---|---|
| knows the producer | on `main` | `main` | `fleet/producer` | **absent** |
| knows the producer | on `fleet/reader-tip` | `fleet/reader-tip` | `fleet/producer` | **absent** |
| pre-fix (no producer recorded) | on `fleet/reader-tip` | `fleet/reader-tip` | **absent** (no guess) | **absent** |

`grep -c '"branch":'` over every output path: **0**.

### Verification

- Tests `23-npyn-a`..`i` in `tests/fleet-gate-check.test.sh`, rewritten for this definition. **`23-npyn-b` is
  the RE-PINNED reversing assertion** — it asserts that no field named `branch` exists at all, and it is
  deliberately kept as the guard against the definition drifting back rather than deleted when it fails.
  `23-npyn-e`/`f` are re-pinned from r1's claim that `produced_branch` appears only when it differs from the
  caller's: it is a property of the record, not a difference.
- `git apply` to a pristine tree reproduces the tested bytes exactly (hashes above).
- Reduced r2 vs r1: **R2 is the re-cut; R1 is superseded and should not be applied or reviewed.**

### Left for the hub (unchanged from r1, and one addition)

1. The `NONE` and `record:{...}` refusal paths carry `caller_branch` only; neither has a record branch to
   disclose, so nothing there is wrong today.
2. Any human-readable printer of this JSON shows the two new field names as-is; no change was made to it.
