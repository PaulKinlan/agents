## `fleet-check-arm-source-witness.patch` (agents-6sgf)

**THE CONSUMER HALF.** The producer half is the ordinary commit `9e3e2d76` on this same branch
(`fleet/imp-dflt-6sgf`), which touches `tools/fast-gate.sh` and `tests/test_fast_gate_mapping.py`.

- **Target repository for THIS patch:** `PaulKinlan/fleet` (`~/fleet` here is a synced, read-only copy and not a
  git repository, so this is delivered under `patches/` and is **NOT applied here**).
- **Target file:** `bin/fleet-check` — the `.witnessed` field of the finish path.
- **Prerequisite base hash:** `455e3b05d2dc172c2d2149dd47b33ac4d77266b57d45765506d2e2b362c10498`
  (re-verified against the current `~/fleet/bin/fleet-check` when this patch was generated).
- **Apply:** from `~/fleet`, `git apply patches/fleet-check-arm-source-witness.patch`
  (`patch -p1 --fuzz=0` also works; no mode changes).
- **After applying:** `bin/fleet-check` = `81b820b2389139d7593b8f3c60208bca26d95a5223b861d80322c79380f53794`
  — byte-identical to the build both directions were measured on.
- **Prompt budget:** none. This changes `bin/fleet-check` and nothing under `roles/`.

### The defect

`bin/fleet-check` set `.witnessed` to a **static sentence** and published it with every terminal state:

> "…NOT witnessed: untracked files, or anything the gate's own command touches outside the repository."

For a run where the fast gate's arm loader took its **filesystem fallback** (no index for that tree, or an index
naming fragments the tree does not have — reachable in a real work tree by a staged deletion or rename of
`tools/fast-gate-arms.d`), that sentence is not merely imprecise: every `*.sh` in the registry **is read and
sourced** in that state, so untracked arm files *were* witnessed. `agents-wzmj` already made the gate *print* the
fallback notice for a human reading a log; what was missing is that the **record** carries it, and the consumer
cannot tell the two states apart from a log.

Measured on the pristine file, driving the witness decision through five arm states
(`index`, `fallback`, `garbage`, a foreign `schema`, and no file at all): **1 distinct sentence for all five**.

### What the consumer does now

The finish path reads `${rec%.json}.signal.json` with `jq` (already a dependency) and sets `.witnessed` **from
the state**:

| signal | `.witnessed` says |
|---|---|
| `arms_source: index` | the existing sentence — every clause of it is true in this state |
| `arms_source: fallback` | "…BUT the fast gate's arm registry took the FILESYSTEM FALLBACK (`<reason>`), so every `*.sh` in that registry WAS READ FROM DISK AND SOURCED: UNTRACKED ARM FILES WERE WITNESSED in this run…" |
| absent, unreadable, or any other value | **"NOT RECORDED: … makes NO CLAIM about untracked files — neither that they were witnessed nor that they were not."** |

`kind=full` is deliberately untouched: the arm registry does not arise in a full-gate command. And the launch
path **deletes any stale signal first**, because a file left over from an earlier run on the same record must
never be able to vouch for a new one.

### The producer half (commit `9e3e2d76`, in `PaulKinlan/agents`)

`fast_gate_report_ignored_arms()` — the gate's own "ONE place for the notice, so every exit path a lane can read
carries it" hook — now also writes **one JSON object** to the destination the caller names in
`FLEET_GATE_SIGNAL_FILE`, atomically (tmp + `mv`) via `python3` (that script has no `jq`):

```json
{"schema":"fleet-gate-signal/1","arms_source":"index"|"fallback"|"unknown","arms_reason":"<the fallback text, empty when indexed>"}
```

A caller that names no destination gets **no file**, so a human run stays silent. **`"unknown"` is an extension of
the spelling you ratified**, emitted when the loader has not run at all: claiming `"index"` there would be an
overclaim, and the consumer reads any unrecognised value as NO CLAIM, so it fails in the safe direction. If the
hub would rather the value set were exactly `index|fallback`, the honest alternative is to write nothing in that
case — one-line change, no other consequence.

### Cross-repo landing order (the reason this is two deliveries)

The consumer is `bin/fleet-check` (fleet repo, this patch, hub canon). The producer is `tools/fast-gate.sh`
(project repo, merge queue). No single `patches/*.patch` can carry both. **APPLY THIS PATCH FIRST**: with the new
consumer and the old gate, every record reads "NOT RECORDED" — weaker but true. With the new producer and the old
consumer, the false fallback claim stays live. So consumer-first is safe in every interleaving, and producer-first
is not.

### Verification

- **Producer, five controls, all measured:** a tree with the registry in its index reports `index` with an empty
  reason; a plain copy reports `fallback` with "this tree is not a git working tree"; no destination writes
  **no file**; an **unwritable** destination still leaves the gate at **exit 0**; and all of them exit 0.
- **A real bug caught by my own control, kept as the reason that control exists:** the first draft made the plain
  `python3` call and then tested `$?`. `tools/fast-gate.sh` runs under `set -e`, so a failing write **aborted the
  gate** — measured, the unwritable path exited 1 before the `$?` was read. The call is now an `if` condition.
- **Tests in the agents repo:** `TestArmSourceSignal` (4 assertions) in `tests/test_fast_gate_mapping.py`, passing
  in 0.8s. It builds **both** trees itself — a committed registry for the index state, a plain copy for the
  fallback — so it depends on nothing about the machine's own checkout.
- **Consumer:** the extracted witness decision measured at **1** sentence for all five states on the pristine
  file and the intended behaviour on the patched one, plus section `25a`–`25h` in `tests/fleet-gate-check.test.sh`
  driving the real path. The fleet suite's verdict for that section is still outstanding and will be run **once,
  alone**, so it does not contend for the single heavy slot.
