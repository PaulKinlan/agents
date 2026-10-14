## `fleet-watchdog-idle-holder-declaration.patch` (agents-dbxo)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `watchdog/watchdog.mjs` (the EXCUSED predicate and the four consumers of `in_flight` that act on an idle lane)
  - `tests/watchdog-smoke.test.sh` (new section 14; four arms, three of them red against the pristine watchdog)
- **Baseline file hashes:**
  `5a7ef7289b438ced8711104f1efa516b08ad45ae82b0cb48055fc8e00b3b5735  watchdog/watchdog.mjs`
  `8ba1cb80dc90fb7f6baf7c6be394e07401d29765d1950872ec1748dae6df5f79  tests/watchdog-smoke.test.sh`
- **Patched file hashes:**
  `3ceaab246f93bbbe223d161c746722bc36079b1074de2c19656fccd395a43256  watchdog/watchdog.mjs`
  `4a618aaa9050c768e35e30b751d0812d287b54340d129a73dc51197e08a3c0d0  tests/watchdog-smoke.test.sh`

---

## The question, and the answer

**THREE mechanisms, one axis.** The bead offered three symptoms as possibly "one defect with three faces - a
record that fails to state the state it is actually in". Read from the code that assigns each state, they are
three **different** defects that share one axis and one place where they surface (the watchdog's "YOU ARE IDLE
WITH WORK CLAIMED" message), and no single change covers two of them. What distinguishes them is not the
symptom but the **position of the fault**:

| | symptom | position of the fault | owner |
|---|---|---|---|
| 1 | two clocks for lane liveness | **one predicate, two instruments**: the predicate "is this lane working?" is assigned twice, from two different records, and each reader sees only its own | `remote/lanes.sh` `lane_status()` **and** `inbox/status.mjs` `last_event_min` |
| 2 | `bd comment` does not bump `updated_at` | **a writer moves nothing**: the bead record's recency field is not written by the command that changes the bead | the `bd comment` writer (`bd`, outside `PaulKinlan/fleet`), read at `inbox/status.mjs:161` |
| 3 | the watchdog does not read `waiting` | **a consumer ignores a fact its own record carries**: two sibling consumers read the lane's declared label and two do not | `watchdog/watchdog.mjs` (the poll) |

Written as one sentence, the axis is:

> A liveness verdict is true only if it is produced from the record that carries the fact the verdict is about,
> and every consumer must read the fact its record already carries - silence in a proxy record is not evidence
> of the state it proxies for.

That axis is the *shared* thing. It is not one mechanism, and the code proves it in two independent ways:
the faults sit at three different positions (a duplicated predicate, an absent write, an unread field), and the
fixes do not overlap - changing the `bd comment` writer does not make `watchdog.mjs:377` read `waiting`; making
`watchdog.mjs:377` read `waiting` does not reconcile `lanes.sh list` with the watchdog's clock; and reconciling
the clocks does neither of the others. Three edits, three owners, in three components.

### Face 1 - one predicate, two instruments (and its premise has MOVED since the bead was filed)

The exact assignment sites:

- `remote/lanes.sh:178` `lane_status()` assigns the lane's state. The **current** code (`~/fleet`, mtime
  2026-10-13 21:16) reads `state.last_event_at` at `:186` into a variable that is then **never read** - the only
  occurrences of `ev` in the whole file are the declaration at `:184` and this assignment at `:186`. The
  `busy == false` branch is `remote/lanes.sh:220-223`, and it returns `idle` on the ground that `win_exists`
  (`:181`) found a live unit and a connectable socket, with the comment *"age alone cannot prove a dead session.
  Do not label it zombie or free its specialist slot based on a quiet work queue (fleet-ehyo)."*
- `inbox/status.mjs:76` `lastEvent = session-file mtimeMs`; `:89` `hostEv = state.last_event_at`;
  `:90` `act = Math.max(lastEvent, hostEv)`; `:127` `last_event_min = round((now - act)/60000)`. The watchdog
  consumes that clock at `watchdog/watchdog.mjs:226`, `:238-239`, `:376` and `:381`.

So the two readers use **different instruments for the same predicate**: `lanes.sh` asks *is there a live
session object?* (unit + socket), and `status.mjs` asks *how long since anything happened?* (max of session mtime
and RPC event). Bead-time they disagreed in the sharpest possible form: the snapshot at `fleet-copy` (2026-10-13
05:05) has the assignment *"state.last_event_at older than 3600s ⇒ `echo "zombie"`"* at
`remote/lanes.sh:214-220`, while the watchdog's `last_event_min` is `max(session mtime, RPC event)` - so a lane
whose session jsonl is fresh but whose RPC `last_event_at` is an hour old is `zombie` to one and `2 min` idle to
the other. That is the bead's measurement, and it is real.

**But it is no longer the code.** `fleet-ehyo` removed the `zombie` label from `lane_status()` (the change is
pinned by `tests/lanes.test.sh:310`, *"idle liveness: stale activity is not a zombie or a free specialist slot
(fleet-ehyo)"*), so what the list prints now is `idle` for every quiet lane, derived from **no clock at all** -
the stale `ev` read is the fossil of the removed branch. The divergence survives in a form the bead does not
describe: one reader states a verdict that consults no clock, and the other states a verdict that consults
`max(mtime, RPC)`. Fixing face 1 means giving the lane-liveness predicate one definition, and it necessarily
touches **two** components (`remote/lanes.sh` and `inbox/status.mjs`) - which is why it is not fixed here.

### Face 2 - a field the writer never moves (MEASURED)

`updated_at` is the bead's recency field and the board reads it as activity at `inbox/status.mjs:161`
(`in_flight[].updated_min`, surfaced in the nudge's own text at `watchdog/watchdog.mjs:382`: *"last touched
N min ago"*). Measured on a throwaway bead in an isolated beads DB (`bd init` in a temp dir; the value read
back from `bd show <id> --json`):

| write | did `updated_at` move? |
|---|---|
| `bd create` | sets it to `created_at` |
| **`bd comment <id> "a comment"`** | **NO** (`02:53:07` before and after) |
| `bd update <id> --claim` (status + assignee) | YES (`02:53:07` → `02:53:16`) |
| `bd assign <id> someone` | YES (`02:53:16` → `02:53:34`) |
| `bd label add <id> waiting` | **NO** |
| `bd note <id>` | YES |
| `bd close` / `bd reopen` | YES |
| `bd heartbeat` / `bd set-state` | NO |

The comment row was reproduced on a second bead (`02:54:14` before and after the comment). So the field tracks
**structural** writes (create/status/assignee/notes/close/reopen) and not the two writes the fleet treats as
activity: a comment, and a label. The DB does carry the fact - `bd comments <id> --json` returns each comment's
`created_at` (`2026-10-14T02:53:12Z` for a comment written at `02:53:12`) - but `bd list --json` (the ONE
beating query `status.mjs` makes, per `fleet-jqg/c7m`) exposes `comment_count` and no comment timestamp.

**The writer at fault is `bd comment`, and it is not in this repository.** `bin/bd` here is the serialisation
shim (`fleet-tm5/e10`); the command that fails to touch `updated_at` is the real `bd` behind it (the beads
project). So face 2's fix is either in beads, or a reader-side change in `inbox/status.mjs` that stops
presenting `updated_at` as activity (it would have to derive recency from `bd comments` per in-flight bead, or
from `comment_count` deltas, against a query whose cost was deliberately cut - a real decision, not made here).

### Face 3 - a consumer that ignores the fact the record carries (fixed here)

The nudge is at `watchdog/watchdog.mjs:365-395`. Its two sibling consumers of the same `in_flight` list read the
lane's declared label through `EXCUSED` (`:218`):

- `:237` `heldWork` - `!(b.labels||[]).some(x => EXCUSED.test(x))`
- `:255` `held` - same predicate

Four did not:

- `:273` `laneWork` (the big-context fresh session) - `assignee === ...` with no label test
- `:377` `mine` (the "YOU ARE IDLE WITH WORK CLAIMED" beam list) - `i.assignee === id` with no label test
- `:382` (the message) reads `i.updated_min` - face 2, above
- `:393` `stillHolds` (the escalation cleanup) - `i.assignee === klane` with no label test

Running the new arm 14a against the pristine watchdog reproduces the harm exactly: a lane whose only in-flight
bead carries `waiting` is nudged *"YOU ARE IDLE WITH WORK CLAIMED"*, and arm 14c shows the escalation then
asserting *"either the lane needs a fresh session (its context may be the problem), or the bead needs
reassigning"* about a lane that had **done what the nudge asked** - the same message at `:384` says *"add
`waiting` to the bead so the board shows it as parked rather than working"*. The nudge is a request to declare
and it did not read the declaration it requested, so its own remedy could not converge.

## The change

**One named predicate, used by every consumer that acts on an idle lane for holding work.** `watchdog.mjs`
gains `claimsWork(b, assignee)` beside `EXCUSED` (`:218`), and the five sites above use it. The two sites that
already read the label keep their behaviour byte for byte; `:273`, `:377` and `:393` change behaviour, because
a lane that has declared itself parked is not *holding work* for any consumer - the same statement the
siblings already make, and the same statement the big-context rule's own comment makes (*"refreshing the
context of a lane that is idle BY INSTRUCTION ... is churn with nothing to gain"* - a declared-waiting lane is
idle by declaration).

**One second line, in the same block, because the first is incomplete without it.** The escalation's cleanup at
`:394` deleted `state.alerts[\`idlehold:${k}\`]`, i.e. the key `idlehold:<vm>|<vm>-<lane>` - while `alert()` at
`:387` writes the escalation under `idlehold:<vm>:<vm>-<lane>` (the colon form every other alert key uses). The
clear therefore never matched the alert it was clearing, so an escalation about an idle holder could outlive the
condition. Measured in the red run (below): after the lane had excused every bead it held, `state.alerts` still
carried the escalation and the strike counter had climbed to `4`. `:394` now deletes `idlehold:${kvm}:${klane}`,
which is the key `:387` writes.

## Verification

**Red before, green after, same instrument, one variable changed** (`watchdog.mjs`; the test file is the
patched one in both runs):

- pristine watchdog + patched tests: **49 passed, 3 failed** - `14a waiting-declared lane was nudged (1) and
  armed (1)`, `14c mixed holder escalation wrong ... holding b-mix-keep, b-mix-wait`, `14d excused lane kept its
  escalation (nudges=4 ...)`.
- patched watchdog + patched tests: **52 passed, 0 failed**.
- The pre-existing suites are unchanged on the patched tree: `tests/watchdog-drivers.test.sh` **6/6**.

Command: `bash tests/watchdog-smoke.test.sh` from the fleet checkout root (the new section 14 is the arms to
read; the harness is hermetic - a mock inbox on an ephemeral loopback port and a `status.json` fixture per arm).

**Round trip:** `git apply --check` passes against pristine copies of both files, and applying the patch
reproduces both patched files byte-for-byte (hashes above).

Arms: **14a** a lane whose only in-flight bead is `waiting` is not nudged and arms nothing; **14b** CONTROL - an
undeclared idle holder is still nudged with the driver's own words, so the fix cannot pass by deleting the
driver; **14c** a mixed holder is still nudged and the escalation names only the bead it has not excused;
**14d** the strike count and the escalation clear once the lane has excused every bead it holds.

## What this does not cover

- **Face 1 is not fixed.** Giving lane liveness one definition spans `remote/lanes.sh` and `inbox/status.mjs`
  (two components), and `fleet-ehyo` has already changed the `lanes.sh` side deliberately. The bead's requested
  alternative - *"the watchdog's message names the LANE state"* - is a change to this same message and was
  deliberately not bundled: it is a second mechanism, and a fix written for one face is not evidence about
  another.
- **Face 2 is not fixed.** `bd comment` not bumping `updated_at` is a beads-side writer; the fleet-side
  alternative (derive bead recency from `bd comments`/`comment_count`) trades the query cost `fleet-jqg/c7m`
  deliberately removed, so it is a decision rather than a patch. The nudge still says *"last touched N min
  ago"* from a field that a commenting lane does not move.
- **The `waiting` label was not made to suppress the `heldWork` restart only - it always did.** The stalled-work
  restart (`:237-239`) already read `EXCUSED`; nothing here changes which lanes get a fresh session for holding
  *undeclared* stalled work.
- **A board-side label write still does not move `updated_at`** (measured above), so adding `waiting` is not
  itself visible to any recency reader - the label is visible to a label reader, which is what face 3 made the
  watchdog be.
- **The escalation's `alert()` key form (colon) and `state.idleHoldNudges`' key form (pipe) are still two
  forms.** Only the one deletion was corrected; unifying the keying scheme is a wider refactor.
