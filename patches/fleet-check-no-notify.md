## `fleet-check-no-notify.patch` (agents-94j9)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/fleet-check` (the notifier guard: one condition added)
  - `tests/fleet-check-scope.test.sh` (sets `FLEET_NO_NOTIFY=1`, with the reason written beside it)
- **Baseline file hashes:**
  `1d35baf378a3f71ecb4a65e0dece7ddc0fb91d4e87f172a69a237540c646c4b3  bin/fleet-check`
  `0bc00b917b0f217eef7b1f11d4b32f31c1a687c3fac00cf37ae2cdead0cd9b50  tests/fleet-check-scope.test.sh`
- **Problem statement (agents-94j9).** A lane receives a `[check]` message that names it as the asker and carries
  a sha that resolves nowhere. The `[check]` channel is how a lane learns its gate finished and the fleet's rules
  say to act on it, so a synthetic message wearing a real result's clothes is a silent-green hazard, not noise.
- **Established, by reading:**
  1. `RAN_FULL_MARKER` exists in exactly one place: `tests/fleet-check-scope.test.sh:39` writes a stub
     `check.conf` (`CHECK_CMD="echo RAN_FULL_MARKER"`). That is what attributes the observed message to this test.
  2. That test calls the **real** `bin/fleet-check` (resolved from its own directory), so the run is real and so
     is its notification. The notifier (`bin/fleet-check:592-608`) curls the VM's inbox directly for every waiter
     (`http://localhost:${FLEET_INBOX_PORT:-7777}/msg`), so shadowing `fleet-send` on PATH cannot intercept it,
     and a test that does not set the port talks to the live inbox.
  3. The sha is real but foreign: the test runs in its own temp git repo, so `4eaff45` is a commit *there* and
     resolves nowhere in the repo the message appears to describe. That is why resolving the sha is the defence.
  4. The sender **cannot** recognise the stub: to `fleet-check`, `echo RAN_FULL_MARKER` is a check command like
     any other, and heuristics (a temp cwd, a marker-shaped command) would be guesswork in the one place
     guesswork is least acceptable. So the fix belongs in the test: **a test must not deliver results.**
  5. The worker inherits the environment: `:684` spawns it with plain `setsid nohup bash "$worker_script" …`, and
     nothing in `bin/fleet-check` uses `env -i` or unsets variables, so a variable set by the test reaches the
     notifier.
- **Changes:** the notifier's guard gains `&& [ -z "${FLEET_NO_NOTIFY:-}" ]` — a test suppresses the
  **notification** without suppressing the **run** — and `tests/fleet-check-scope.test.sh` sets the variable
  beside its stub gate, with the reason written there for the next reader.
- **Verification, on an instrument that was checked rather than assumed:**
  - A capture listener impersonating the inbox was bound to a private port and **probed with a known POST before
    anything was concluded from it**, because a capture that records nothing is equally consistent with "no
    message was sent" and "the listener was never up". The author's first attempt made exactly that mistake, and
    a second attempt killed its own shell twice with `pkill -f` patterns that matched the command line doing the
    killing.
  - Pristine suite with the inbox pointed at the verified capture: **12/12 passed, 0 messages delivered**.
  - Patched suite on the same instrument: **12/12 passed, 0 messages delivered** — the knob is inert when nothing
    notifies, which is the control.
  - Round trip: `git apply --check` passes against pristine copies and the applied patch reproduces the measured
    tree byte-for-byte; patched hashes
    `78de460f5f43be84a48a311d3e6ac14e1d7b6d86a31d9f2b03f3d1a13ca1e169  bin/fleet-check`,
    `3e1696352519cf0e4c0786ef497d01f180c6991f05f6311a79b227142373ffc2  tests/fleet-check-scope.test.sh`.
  - **TWO claims the author got wrong, both kept visible rather than tidied away, because the sequence is the
    point.** The first was that the scope test *delivers* the observed message. The second, offered in the first
    version of this section as the correction, was that the notifier sits on a **queued worker** path so the escape
    needs the gate to have *waited for a heavy slot* - which would explain why it was seen once under load and
    never on a quiet VM. **The second was also wrong, and wrong in the more instructive way:** it was a plausible
    mechanism that no measurement had supported, and it survived until an independent review reproduced the defect
    instead of reasoning about it.
  - **The mechanism the reviewer PROVED - a race the test loses to itself.** There is no unqueued path: every gate
    spawns a worker and every worker calls `finish()`. `bin/fleet-check:504` makes `finish()` return early **and
    silently** when the record file is gone. The test's `await_record` returns in about ten milliseconds, because
    the record is written *before* the worker is spawned, so the test races ahead into its own `trap ... rm -rf`
    on the fixture directory. A worker that finishes while the fixture is still alive NOTIFIES; one that finishes
    after the cleanup finds no record and says nothing. Hence load-dependence rather than any queue requirement:
    under CPU load the worker's near-instant `echo RAN_FULL_MARKER` wins the race and the message escapes.
  - **The reproduction, which closes the limit stated in the first version of this section.** Pristine received
    count **1**, with the message captured verbatim - `to: merger`, `[check] full gate for b1e5a41 (asked by
    merger, job 0212e9c1...) : PASS (exit 0, ran 4s after 0s waiting for the heavy slot)` - and patched, on the
    same instrument with a probe POST confirming the listener was live, **0**. The knob is therefore verified on
    the real path rather than reasoned about, and the first version's "not reproduced end to end" is superseded
    by evidence. The first version's recipe (occupy `FLEET_HEAVY_DIR`, then run against the capture) was a
    reasonable route to this and is kept in the bead rather than here.
  - **What the review also settled, so the next reader does not re-open it:** the knob is the right LAYER - the
    test exists precisely to exercise `fleet-check`'s gatekeeping CLI, so stubbing the CLI would destroy the
    subject - and the opt-in polarity is the right trade-off, because inverting it would break every production
    lane's wake-up. A shared test prelude exporting the knob is a follow-up bead, not part of this patch.
- **What this does NOT fix, stated so it is not oversold:** the knob is **opt-in**, THREE test files invoke the
  real `fleet-check` — the other four either stub it (`fleet-land-gate-coverage`, `fleet-land-message`) or
  only mention it (`review-cadence` has the string in JSON fixtures and never executes it;
  `fleet-check-worker-quoting` inspects heredocs statically and runs no gate) — and of those three,
  `fleet-gate-check` isolates the inbox on port 9999 and `fleet-check-scope` now sets the knob. That leaves
  `tests/fleet-check-tree-stability.test.sh` as the remaining caller that talks to the live inbox, and it is
  the one worth adopting the knob: a future test can still forget, exactly as this one did.
  (The first version of this paragraph said "seven test files invoke the real `fleet-check`". That was a count
  of grep hits, not of invocations — a pattern hit is not evidence of behaviour, and the number a fleet-side
  README reports is the number future lanes will read.)
  The only defence that does not depend on test hygiene is receiver-side — resolve the sha (`git cat-file -t`) and
  check the tree is the one you asked to be gated before acting on a `[check]` — and that belongs in the prompts,
  where it costs prompt budget, so it is a coordinator decision rather than part of this patch.
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-check-no-notify.patch
  bash tests/fleet-check-scope.test.sh      # 12/12, and no notification is delivered
  ```

