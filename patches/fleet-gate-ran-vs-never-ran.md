## The gate wrapper must say whether the command RAN or NEVER RAN - `fleet-gate-ran-vs-never-ran.patch` (agents-wg7i)

Hub-side artifact: the patch edits the DEPLOYED wrapper `~/fleet/bin/fleet-gate` and adds its first test,
`tests/fleet-gate.test.sh`. Apply it at the fleet repo root with `patch -p1 --fuzz=0` (or `git apply`).

### The failure this closes

A gate was invoked with a positional `docs` instead of `--docs docs`; the tool exited 2 on its usage error,
and the wrapper's wake-up message read **`exit 0 after 0s`**. Only an elapsed marker in the author's own text
caught it. On the deployed side there was nothing to catch it with: `finish()` reported one number and one
duration, with no way to say *which* of two different things had happened.

The two things are not variants of one another:

- the command ran and the number is its status, or
- the command NEVER STARTED, the job returned on its own, and the number is the JOB's - and 0s elapsed with
  exit 0 then reads as a clean pass for a run that never happened.

`agents-p1gv` fixed the repo-side half of this and deliberately left this one, because it lives in `~/fleet`
rather than in the project.

### What was measured first (so the fix targets the real link)

`fleet-gate` runs `fleet-heavy timeout --foreground -k 30 "$t" $cmd`, waits on it, and reports `$?`. The
status chain from the tool up was measured sound before anything was changed:

| probe | result |
|---|---|
| `fleet-heavy timeout -k 30 5 bash -c 'exit 2'` | rc **2** - the tool status IS propagated |
| a tool that succeeds | rc 0, and the log holds only the tool's own output |

So the pipes were not the cause here: a *job that ran and failed* was already reported faithfully. The gap
was the second case, where the message had no vocabulary for "the command never started", and a genuine
`exit 0 after 0s` for such a job is indistinguishable from a pass.

### The change (4 hunks, 2 files)

1. **A runner records that the command started.** The outer script writes `$base.runner`, whose first act is
   to write `$base.ran`, then `exec`s the command. `exec` matters twice: it leaves no extra process for
   `timeout --foreground` to signal past, and it keeps the tool's status propagating. The runner is written
   in the OUTER script because nesting `bash -c '...'` inside the wrapper's single-quoted inner script is
   how bash quoting broke repeatedly while this was written.
2. **`finish()` distinguishes the two cases by observation, not by timing.** `$base.ran` is a fact about what
   happened, so the message says either `ran and exited $rc after ${elapsed}s` or
   `NEVER RAN the command: the job returned after ${elapsed}s with no start record, so this is the status of
   the JOB and NOT a verdict on the command`.
3. **A never-ran job no longer publishes 0.** Its `$base.exit` is **125**, and the header (which is also the
   usage text) documents 125 and the new `.ran` file.
4. **`set -uo pipefail` inside the inner script**, which does not inherit the outer `set` options through
   `bash -c`, so a pipeline there can no longer report the status of its last element rather than the tool.

The elapsed marker is untouched. It is load-bearing evidence, and case 4 of the test asserts it is still
there.

### Evidence

- `patch -p1 --fuzz=0 --dry-run`: clean, from the deployed pre-fix state, for both files.
- The patched result is byte-identical to the copy verified by hand: md5 `5ae3f39416dc5ea9922159ad328d3391`.
- **Discriminator, the same test file against both wrappers:**

  | wrapper | result |
  |---|---|
  | original (deployed) | **5 passed, 5 failed** - `1a`/`2a` report the old wording, `3a`/`3b` never say NEVER RAN, and **`3c` fails because the never-ran job writes exit 0** |
  | patched | **10 passed, 0 failed** |

  Case 1 is `agents-wg7i`'s instance 3 itself: a tool that exits 2 is asserted to be reported as exiting 2,
  and case 2 (`exit 0`) is the control that keeps case 3 honest.
- The test needs **no heavy slot**: `fleet-heavy` and `curl` are shims on `PATH`, so both cases are driven
  rather than hoped for. (The `curl` shim captures the message instead of POSTing it to a lane inbox.)

### What this does NOT do, and what it costs

- It does not change the path for a job that ran: same message shape, same status, same elapsed marker.
- It does not touch the state machine, `fleet-heavy`, or the preemption retry.
- 125 is a NEW code from this wrapper. It is documented in the header, distinguishable from 124/137/143
  (killed by the bound, not a verdict), and it exists precisely so that a never-run job cannot be read as 0.
- Cost: the added test file runs in **352ms measured** and takes no heavy slot, so it cannot queue behind
  the merger.

### Provenance of the base (strict preimages)

Hashed on this VM immediately before the patch was cut; the reviewer can confirm the base rather than trust
it:

- `bin/fleet-gate` - SHA256 `16ebc7b9ba14994076f31b24cdaa2efd8bd2969ad74a4e5b5dbf1cf2e2aa0c34`, 3679 bytes.
- `tests/fleet-gate.test.sh` - did NOT exist (the file is added by this patch).

Owner: hub canon (`~/fleet` is not a work tree on this VM). Not for this project's merger.
