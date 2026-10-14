## The never-ran message should carry the JOB's status, not only 125 - `fleet-gate-never-ran-job-status.patch` (agents-lyrw)

Hub-side artifact: a follow-up to `agents-wg7i` (the RAN vs NEVER-RAN distinction, now landed here as
`fa964c00`). **Apply it AFTER `agents-wg7i`'s patch**: it edits `bin/fleet-gate` on top of that content and
adds a case to the test file that patch creates. Verified as a SEQUENCE from the deployed state: wg7i's patch,
then this one, both with `patch -p1 --fuzz=0`.

### The gap

`agents-wg7i` writes **125** to `.exit` for a job that never started the command, so it cannot read as a
pass, and its message says NEVER RAN. But 125 **replaces** the job's own status, and two different facts then
look identical:

- **143** - the job was killed while waiting for a heavy slot (observed on this VM: a gate log containing only
  `fleet-heavy: waiting for a heavy slot`, with the merger holding the slot)
- **0** - the job returned cleanly without ever starting the command

A lane reading `125` cannot tell which happened, and the difference matters: one is worth re-queueing, the
other says the command itself was never reached.

### The change

`finish()` keeps the job's status in `job_rc` before 125 replaces `rc`, and the never-ran message names it:

```
NEVER RAN the command: the job returned 143 after 17s with no start record, so 143 is the status of the JOB
and NOT a verdict on the command (125 is written to .exit so this cannot read as a pass)
```

`.exit` still carries **125**, and the header (which is also the usage text) documents both numbers. The
elapsed marker is untouched.

### Its own committed fixture (the agents-3gk3 lesson)

The fix ships with case 5 in `tests/fleet-gate.test.sh`, not just a transcript: a shim that exits **143**
(so the killed-while-waiting shape is driven, not described) and one that exits **0**, asserting that the
message names each, that NEVER RAN is still said, and that `.exit` stays 125.

### Evidence

- Sequenced application from the deployed state: wg7i's patch, then this one, both `--fuzz=0`, CLEAN.
- The suite, sequentially patched: **14 passed, 0 failed** (wg7i's 10 plus 4 new).
- Discriminator: the same suite against the PRE-`lyrw` file is **12 passed, 2 failed** - the two new
  status assertions fail there, which is what makes them tests of this change rather than decoration.
- Strict preimages (the content this patch expects, i.e. AFTER wg7i):
  `bin/fleet-gate` SHA256 `295d1b81e5132a66`; `tests/fleet-gate.test.sh` SHA256 `ccf017604e607fde`.
  The deployed pre-wg7i `bin/fleet-gate` is `16ebc7b9ba149940` (3679 bytes) and the test file does not
  exist until wg7i's patch creates it.

### A note for the next editor of this file

My first draft of the new comment contained an apostrophe ("JOB's") and that **terminated the single-quoted
script the inner half of this wrapper runs inside** - the identical trap `agents-wg7i` documents in its own
write-up, hit again by the author of that write-up. The wording now avoids apostrophes, and every line this
patch adds is checked mechanically for one.
