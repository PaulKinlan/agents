## The gate's wake should be OBSERVABLE, not inferred from absence - `fleet-gate-wake-observable.patch` (agents-rirf)

Hub-side artifact for `bin/fleet-gate`. **Apply after `agents-wg7i`'s and `agents-lyrw`'s patches**: it edits
the same `finish()` and adds a case to the test file those patches create.

### The premise, corrected by measurement

`agents-rirf` was filed on the belief that the wake was LOST - a `[check]` that never arrived, leaving the
result readable only from the record. The timestamps say otherwise: for the gate in question the log records
`gate started 12:59:54`, and the `[check]` message was sent at `13:00:02` - **eight seconds later**. The
wake was not lost; it was in flight while the record was already complete and I wrote "never reached me",
which is an INFERENCE FROM ABSENCE, the same defect as a label grep and a `0s/exit 0` pass.

The second question the bead asked - is the wake lost on preemption and re-queue - is also answered no, by the
record: the preempted job `db6775a2` carries `preempted by the merger; re-queued (attempt 2)` in its log and a
`state=PASS` receipt, and its wake did arrive.

So the buildable half is the first bead's other ask, which the correction makes MORE relevant, not less: a lane
must be able to tell "no wake yet" from "the wake was never posted" **without polling**, because the record
exists before the message arrives. That window is exactly where I went wrong.

### The change

`finish()` keeps the POST's status and records that the wake happened:

```
local wake_rc=0
curl ... >/dev/null || wake_rc=$?
printf "%s" "posted $(date +%s) rc=$wake_rc" > "$base.wake" 2>/dev/null || true
```

Three states become distinguishable from the files alone: **no record** (the gate may still be running),
**a record with `.wake`** (the wake was posted, and how it went), and **a record with no `.wake`** (the wake
was never posted - the real defect the bead was looking for). It is deliberately the same shape as
`agents-wg7i`'s `.ran`: an OBSERVED fact instead of an inference from absence.

### Evidence

- **Discriminator, the same test against both revisions:** PRE-`rirf` **14 passed, 3 failed** - 6a, 6b and 6c
  all fail because no marker exists. PATCHED **17 passed, 0 failed**, with cases 1-5 green on BOTH, so the
  change is additive and nothing about the ran/never-ran reporting moved.
- **Sequenced application from the deployed state:** `wg7i` then `lyrw` then this, each
  `patch -p1 --fuzz=0`, CLEAN, byte-identical to the intended result, and the suite passes on the chained
  tree.
- The test fixture now clears `$.wake` per case, for the same reason case 7 of `agents-shua` had to restore
  its model files: a case that reads a leftover marker measures the previous case.
- Strict preimages (the content this patch expects, i.e. AFTER wg7i and lyrw): `bin/fleet-gate` SHA256
  `e0c13f91b2280b97`; `tests/fleet-gate.test.sh` SHA256 `fc5a2104de377af8`. The deployed pre-wg7i `bin/fleet-gate` is
  `16ebc7b9ba149940` (3679 bytes).

### A note for the next editor

Any added line inside this wrapper must be apostrophe-free or use `'\''` escaping: the inner half of the
script is one single-quoted string. My own check for that caught a `printf '%s'` in this patch's first draft.
