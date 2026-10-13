# tools/fast-gate-arms.d/ — the arm registry, one fragment per run of arms

`tools/fast-gate.sh` maps a changed file to the suites that must run for it. That mapping used to be a
single `case "$f" in` table inside the script, and the script was the most-collided file in the
repository: 144 landings touched `tools/fast-gate.sh`, 40 changed it on **both** sides, and **84** of
those changes were appends of one arm (ADR 0002 §4). Every delivery that needed a mapping edited the same
table, so deliveries collided on the gate itself. This directory is that registry as a set of fragments.

## The shape

```
<NNN>-<name>.sh      one fragment: a function holding one contiguous run of arms, plus its registration
README.md            this file
```

Each fragment is loaded by `fast_gate_arms_load()` in `tools/fast-gate.sh`, which sources every `*.sh`
here **in filename order** and then calls the registered stages in that same order for each changed path,
stopping at the **first** arm that matches — exactly the semantics the single `case` table had.

```bash
# Inside a fragment: the arms are VERBATIM from the old table, rationale comments included.
my_domain_arms() {
  case "$1" in
    lib/thing.py)
      # why this arm exists, in the words of the delivery that added it
      mapped="$mapped tests/test_thing.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES my_domain_arms"
```

## Adding an arm

**One new file.** Do not edit another fragment and do not edit `tools/fast-gate.sh`: a delivery that only
adds a mapping should touch exactly one file, which is the property this directory exists for.

1. Copy an existing fragment as the shape; name yours `NNN-<what-it-covers>.sh`.
2. **The number is the precedence.** Arms are matched in filename order and the first match wins, so a
   specific pattern must sit in a numerically earlier fragment than a general one — `lib/thing.py` before
   `lib/*.py`, `tests/test_tree_guards.py` before `tests/test_*.py`,
   `agents/x/report.schema.json` before `agents/*/report.schema.json`. Adding arms to the fragment whose
   number is nearest the patterns they belong with is the normal case; a number collision between two
   deliveries is a filename collision you resolve before pushing, not a merge conflict inside one file.
3. Keep the rationale **next to the arm** (the comment above the pattern). A reason that lives somewhere
   else rots silently the first time the arm changes (ADR 0001).
4. Both arm shapes are accepted: the pattern on its own line, or the single-line `    <pattern>) body ;;`.

## The guards (in `fast_gate_arms_load`, so a bad registry fails before any suite runs)

- **One pattern, one home.** A pattern declared by two fragments fails loudly. With precedence carried by
  filenames a duplicate would otherwise be resolved silently by position — both arm shapes are scanned,
  and the loader's own no-match fallback is excluded by its marker comment.
- **Every fragment must register exactly one stage, and that stage must exist.** A fragment whose
  registration line is missing or misspelled would be sourced and never called: present in the tree,
  absent from the gate.
- **An empty registry is an error**, not an empty suite list.
- **A dead arm is reported** by
  `tests/test_fast_gate_mapping.py::TestArmRegistryIsAFragmentDirectory`, which fails if a pattern matches
  no tracked path unless the pattern is named in that test's one documented exception list.

## Why the arms are `case` arms rather than a pattern→suite data table

The arms are shell: two of them accumulate `run=` as well as `mapped=`, one resolves `lib/<name>.py`
through a nested `case`, and each carries the prose of why it exists. A data format would have to
re-express all of that, and would change the semantics of the two that differ. Sourcing a function keeps
the arm text **verbatim**, which is what made this move provable: the fragments reassemble to the old
table byte for byte, and the dry-run suite set is identical before and after for a representative path of
every arm (agents-hr6q carries both measurements).

## What this directory is not

It is not the whole gate. `tools/fast-gate.sh` still owns the delta resolution, the always-on tiers
(`tests/test_tree_guards.py`, `tests/test_fast_gate_consumer_coverage.py`), the coverage-contract read,
the smoke fallback, the loud failure for an unmapped file, and the dry-run path. This directory is only
the mapping table.
