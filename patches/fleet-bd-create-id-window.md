## `fleet-bd-create-id-window.patch` (agents-94ns)

- **Target repository:** `PaulKinlan/fleet` (a synced, read-only copy on this VM: `~/fleet` is **not** a git
  repository, so this patch is delivered as an artifact under `patches/` and is **NOT applied here**).
- **Target files:**
  - `bin/bd` (the fleet's bd shim - one new top-level argv block, no existing guard touched)
  - `tests/bd-create-id-window.test.sh` (new hermetic suite, 19 assertions)
- **Patch artifact byte size:** 7671 bytes (`patches/fleet-bd-create-id-window.patch`).
- **Baseline file hash:**
  `f0e2f7c79b51819bed188af45ea8aa207cbe4843b6008591faf82fbd7c8c2478  bin/bd`
- **Patched file hash:**
  `b3996fed563e97e84c970e23ee8e1bd8ec3db82a9cdf0f1f8b382db76c612790  bin/bd`
- **New file hash:**
  `cf52fc4c0173af2b22e38bde98987b0237577af95a6c3071dc9f4da8e3259eec  tests/bd-create-id-window.test.sh`
- **Diff:** `bin/bd` +20, `tests/bd-create-id-window.test.sh` +113 (133 insertions, 0 deletions).

---

## The question the bead asked, answered before any fix: TWO mechanisms, one axis - not one, not three

The bead's three measured shapes are not one defect and not three. Read from the object each one reports on,
shapes 1 and 2 are the **same** mechanism with a different field substituted, and shape 3 is a **second**
mechanism:

| | shape | the object the lane actually read, instead of the bead | mechanism |
|---|---|---|---|
| 1 | a `bd create` id cut by a pipe window | the pipeline's **last two stdout lines** | A: the pipe substitutes the observed object |
| 2 | a `bd comment` that silently did not land | the pipeline's **exit status** | A: the pipe substitutes the observed object |
| 3 | a hand-off file never created because its guard was keyed on a state not yet reached | a guard's **precondition**, read as the object's state | B: a precondition is read as the guarded object |

Shapes 1 and 2 fault at the same position - the pipe between the write and the reader - and differ only in
which field the pipe supplies (stdout window vs exit status). Shape 3 has no pipe at all: a write was placed
behind a guard that fires on `PASS` while the gate was still `RUNNING`, the write never ran, and the consumer
read the missing file as a comment failure rather than as a missing input. The bead's own one-sentence cause
("a piped **or** guarded write reports on the pipeline, not on the database") names the two mechanisms
itself.

The axis, in one sentence a future reader can use:

> **A quoted fact must come from the object it describes; a pipeline stage, or a guard's precondition, is a
> different object, and its report is not evidence about the first.**

### Measured for shape 1, on this VM (not inferred)

`bd create` (real bd 1.3.1, `bd version 1.3.1 (c1c4b642a)`) prints the id on the **first** of three lines.
Captured to a file, not a pipe (so the capture itself cannot be the defect):

```
Created issue: agents-wisp-vwn - 94ns measurement: bd create default output shape (scratch, ephemeral)
  Priority: P2
  Status: open
```

So `| tail -1` is `  Status: open`, `| tail -2` is the two trailing lines, and the id is in neither window -
exactly the bead's shape 1. The scratch bead's id was taken from a **`bd show <id>` readback**, not from the
create's stdout, which is this bead's own rule applied to itself. With `--silent` the create's whole stdout
is one line (`agents-wisp-po8`), which is the property the fix uses.

## What already exists (measured, with file and line) - and where the fix therefore belongs

1. **A bd wrapper already exists, and it is the chokepoint every bd call takes.** `~/fleet/bin/bd` is a
   shim (line 5: `real="$HOME/.local/bin/bd"`; every lane's `bd` resolves to the shim because
   `~/fleet/bin` precedes `~/.local/bin` on `PATH`). It already carries three bead-keyed guards fixed at
   this same place: `fleet-tm5/e10` (the `flock` serialisation), `fleet-w9ot` (**lines 7-34**: a bare `-`
   under `comment` is rewritten to bd's `--stdin`, or refused loudly), and `fleet-4vve` (lines 60-200, the
   reviewer's destructive-command refusal). A predecessor to *this* patch already exists in this repo:
   `patches/fleet-worktree-beads-guard.patch` (agents-5br9) adds a guard to `bin/bd` - so the delivery
   channel and the place are both established.
2. **The rule already exists, in several places, and is why a rule alone is not the fix.**
   `roles/lessons.md:1235` *"Do not truncate output needed for reuse (2026-10-07)"* - *"Capture full output
   to take values (`create`); avoid `tail`"*, evidence *"`bd create ... | tail -2` lost id"*;
   `roles/lessons.md:637` *"Piped `$?` is the pipe's"*; `roles/lessons.md:677` *"Write, push and readback
   belong to ONE command sequence"*; `roles/lessons.md:241` *"Read error text, not `$?` after a pipe"*;
   `roles/lessons.md:1427` *"`bd show --json` hides comments ... read back with `bd comments <id>`"*.
   The bead's own `agents-94ns`/`agents-oe2v` incidents happened **with those lessons already on the
   board**, which is the argument for a control that does not depend on remembering.
3. **A shim test suite already exists.** `tests/bd-shim.test.sh` (the `fleet-w9ot` guard), `tests/bd-guard.test.sh`
   (`fleet-4vve`), `tests/bd-worktree-decoy.test.sh` (agents-5br9). A new suite is the right tier: hermetic
   (a stubbed `$HOME/.local/bin/bd`), independent, and safe to re-run in a gate.
4. **No lint scans lane command lines for a piped bd.** Searched `~/fleet/bin` and `~/fleet/tests` for pipe
   detection over `bin/fleet-check` and `bin/fleet`: none. So "a rule plus an instrument" is not a form that
   exists yet, and it is discussed under *The instrument* below rather than built.

**Therefore the fix belongs in `bin/bd`, for mechanism A shape 1 only** - that is the single fact a fleet
component owns (the id on `bd create`'s stdout). Mechanisms A shape 2 and B are **not** shim-reachable: the
shim sits *upstream* of the lane's own pipe and *outside* the lane's own guard shell, so no argv rewrite can
stop a lane discarding its stdout or gating its own file on the wrong state. Their control is the
*read-the-object-back* rule, which already exists as the lessons above; this write-up records that rather
than inventing a second, unowned change.

## The fix

One top-level block in `bin/bd`, immediately after the `fleet-w9ot` block (the same place, the same shape of
change: rewrite the argv the shim already sees):

```bash
if [ "${1:-}" = "create" ] && [ ! -t 1 ]; then
  __machine=0
  for __a in "$@"; do
    case "$__a" in
      --silent|--json|--dry-run|--quiet|-q|--file|-f|--file=*|--graph|--graph=*) __machine=1 ;;
    esac
  done
  [ "$__machine" = 1 ] || set -- "$@" --silent
fi
```

Why this is the smallest correct change:

- When **stdout is not a terminal the caller is scripting**, so the shim runs `bd create` with bd's own
  documented `--silent` ("Output only the issue ID (for scripting)") and **the id is the whole stdout** - no
  `tail`/`head` window can cut it. It fixes the measured shape for a lane that has never read the lesson.
- It is **appended last**, so every existing argv substring still matches (verified against
  `tests/bd-guard.test.sh:3b`, which greps for `create -t bug -p 2 -l review-finding`).
- A **terminal** (human) invocation is untouched, and a caller that already asked for a machine format
  (`--silent`, `--json`) or for a form with no single id (`--file`/`-f`, `--graph`, `--dry-run`, `--quiet`)
  is left alone. No other subcommand changes.
- `--silent` is already the fleet's documented scripting form: `roles/architect.md:74` and
  `roles/designer.md:90` both call `bd create ... --silent`.

## Verification (the patch reproduced against the pristine shim, then reverted)

Measured against the pristine `bin/bd` and the patched `bin/bd` with the same suite:

```
$ bash tests/bd-create-id-window.test.sh        # patched shim
19 passed, 0 failed

$ BD_SHIM_OVERRIDE=~/fleet/bin/bd bash tests/bd-create-id-window.test.sh   # pristine shim (RED control)
13 passed, 6 failed        # 2a/2b/2c, 3a/3b, 2f - the id is cut by the window
```

The RED control is what makes the suite a discriminator rather than a description: on the pristine shim the
asserted window genuinely loses the id (`tail -2` = `  Priority: P2` / `  Status: open`), and section 1
measures the same loss against the raw stub with no shim in the path at all.

No regression in the shim's existing suites (patched shim in an isolated copy of the tree):

```
$ bash tests/bd-shim.test.sh            # 15 passed, 0 failed   (fleet-w9ot)
$ bash tests/bd-guard.test.sh           # 85 passed, 0 failed   (fleet-4vve)
$ bash tests/bd-worktree-decoy.test.sh  # 13 passed, 0 failed   (agents-5br9)
```

The patch applies cleanly to the pristine fleet tree (`git apply --check` OK) and the suite is green from
the applied patch; the patched `bin/bd` sha256 was identical in the generated and the applied copy
(`b3996fed...2790`).

## The instrument: what a lint could detect, and what it could not

A syntactic lint over lane command logs **can** detect the risky shape - a `bd` write whose stdout is
consumed by `tail`/`head` - and would have flagged the `bd create ... | tail -2` that produced shape 1.

It **cannot** detect the violation it would be named for. "A lane asserted an id it never read back" is not
a property of any single call: `id=$(bd create --silent ...)` and `id=$(bd create ... | head -1)` produce the
same token, and the read-back (`bd show "$id"`) may legitimately be in a *later* command. So such a lint
flags a **shape**, never a fact, and must not be read as a verdict that an id or a write was verified. That
is exactly the "a pair that agrees with itself is not evidence" family the bead's own 23:30 comment names -
so the durable control is the rewrite, not a detector.

## Hub application

```bash
cd ~/fleet
git apply /path/to/fleet-bd-create-id-window.patch
bash tests/bd-create-id-window.test.sh        # 19 passed, 0 failed
bash tests/bd-shim.test.sh                    # 15 passed, 0 failed
bash tests/bd-guard.test.sh                   # 85 passed, 0 failed
```

## What I did NOT verify

- The root cause of the shape-2 incident (a comment that did not land; the bead records it as inferred from a
  `comment_count` read-back). This patch does not claim to fix it; it is named here as mechanism A's second
  field, which no argv rewrite can reach.
- Whether `bd -C <dir> create ...` needs the same rewrite: the guard keys on `argv[1] = create`, matching the
  existing `fleet-w9ot` guard, so a leading global flag before `create` is not rewritten. No lane role doc
  uses that form (`roles/investigator.md:46`, `roles/architect.md:74`, `roles/designer.md:90` are all plain
  `bd create`).
- Whether a future bd release moves the id off line 1 of the default output. The guard would still hold:
  it triggers on `--silent`, which is documented as id-only, independent of the default layout.
