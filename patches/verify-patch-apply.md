## patches/verify-patch-apply.patch

# An apply check that asserts EFFECT, because an exit status is not evidence

Creates a new file, `bin/verify-patch-apply` (mode 755), in the tree the hub applies artifacts
into. `bin/` is not a guess: `patches/fleet-check-reserve-attribution.patch` (agents-dbit)
modifies `bin/fleet-check` in that tree, so `bin/` demonstrably exists there. If the apply step
lives somewhere else, the path is the one thing the hub's answer may adjust - see ORDERING below.

## What it checks, and why these three assertions

An "applied cleanly" verdict read from an exit status is not evidence, so the tool asserts effect:

1. **The artifact is NON-EMPTY.** A zero-byte artifact is not an artifact.
2. **Every target it names CHANGED BY HASH** (or, for a new-file artifact, now exists).
3. **Every marker it claims to introduce was ABSENT BEFORE and is PRESENT AFTER.**

Measured, each on a zero-byte artifact in a real repository, which is why assertion 1 exists:

| invocation | result on an empty artifact |
|---|---|
| `git apply` | **rc 128**, `No valid patches in input (allow with --allow-empty)` |
| `git apply --allow-empty` | **rc 0, file unchanged** - the flag git's own error message suggests |
| `patch -p1 --fuzz=0` | **rc 0, nothing done, no output** - the form our own hub-delivery discipline uses |
| a non-empty patch that applies | rc 0 **and the file changes** |

So rc carries no information on the route we use, and the hole is **live in the form we actually
apply artifacts with**.

## Which case the hub is in, stated so a reader can tell which one they have

- If the hub's check runs **plain `git apply`**, it **already rejects** the empty apply with rc 128 -
  so assertion 1 is covered there, and the artifact's marginal value is **assertions 2 and 3**:
  "the artifact changed nothing" and "the marker was already present" are both invisible to any exit
  status, including a clean `git apply`. Adopt the tool as the applier, or read it as the
  specification of what to assert; its `--self-test` is the regression test and ships with the check
  so the two cannot drift apart.
- If it runs **`patch -p1 --fuzz=0`** or **`git apply --allow-empty`**, the artifact **closes a live
  hole**: those return rc 0 having done nothing.

Either way the three assertions hold, because they are about effect rather than status.

## One hole, two triggers

A name quoted from memory makes `git show <wrong ref> > out.patch` leave a **zero-byte file**: the
shell truncates the output file before git fails, so the extraction's failure is recorded as an
empty artifact rather than an error. A pruned branch produces the same zero bytes. Both routes hand
**the same input to the same invocation**; the only variable is which invocation reads it. One hole
with two triggers, and one fix covers both - this is deliberately not written up as two defects.

## The marker subtlety, which is the difference between a real check and a decorative one

"The artifact's own marker is present" only means something if the marker is **absent before** and
present after. My own first attempt asserted a marker that already existed in the baseline and
**printed PASS while proving nothing**; the tool now refuses to proceed when a marker is already
present, with that reason named. A naive implementation of assertion 3 passes on every artifact and
is worse than no assertion, because it looks like coverage.

The tool also excludes the artifact itself from its marker scans: a patch stored inside the tree
would otherwise supply its own marker and pass its own check.

## The self-test's own lesson, recorded because it is the same defect again

The shipped `--self-test` runs five cases (one accept, four reject controls). Its first two versions
**passed for the wrong reason twice**: the generated artifact was empty, because `git diff` cannot
see an untracked file, and a later version asserted a rejection that came from the artifact not
existing. Both look green. The fix was to bind every case to its **reason**, not just its exit code -
each case now asserts the message it expects, so a case cannot pass by accident.

## Delivery contract, driven rather than assumed

- `patch -p1 --fuzz=0 < patches/verify-patch-apply.patch` -> **rc 0**, creates the file.
- `git apply patches/verify-patch-apply.patch` -> applies cleanly.
- **Both produce mode 755** from the `new file mode 100755` line. I expected `patch` to drop the
  exec bit and wrote that in a comment; the measurement showed otherwise and the comment was
  removed rather than left standing.
- The tool from the **applied** tree runs its own self-test green: all 5 cases behaved.

## ORDERING - the one thing that must travel with this artifact

A change to the judge must not land in the middle of a queue of judgments: if this were installed
while other artifacts are mid-flight, applies already validated by the old rule would suddenly be
judged by a stricter one. **Install this AFTER agents-dbit, agents-tpw5+zxdg and the agents-5q0w
re-run patch are in.** Its landing in main carries no such constraint.

Related: agents-p1gv is the same status-capture defect seen from the wrapper side - a sequence that
reports only the LAST command's status is exactly how a five-artifact run reports five clean. The
two beads are two faces of one defect and should be read together.
