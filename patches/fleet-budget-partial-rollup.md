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
