## `fleet-bd-lock-holder.patch` (agents-elu6, revised for agents-zoch)

**Applies on top of** `~/fleet/bin/bd` (14480 bytes, sha256 `f0e2f7c79b51819bed188af45ea8aa207cbe4843b6008591faf82fbd7c8c2478` — the shim
as deployed on `agents-factory` at 2026-10-12 21:11Z). **Also adds** `tests/bd-lock-holder.test.sh`.

It is **independent of** the one other patch in this directory that touches `bin/bd`:
`fleet-worktree-beads-guard.patch` replaces the worktree-decoy guard in the middle of the file, while this
one replaces the lock tail at the end. Verified in **both apply orders** on copies, and the composed shim
passes all three suites (below).

### Why

`bin/bd` is the shim every bd call on a VM goes through, because one embedded Dolt DB allows one writer at
a time. Its last three lines were:

```bash
export FLEET_BD_LOCKED=1
flock -w 300 "$HOME/.fleet/bd.lock" "$real" "$@"
rc=$?
```

`flock -w` waits **in silence** and then exits **1 with no output at all** — measured, not assumed:
`rc=1  output=[]`. On 2026-10-13 that cost a finished cross-family review more than four minutes: another
lane's `bd dolt push` held the lock for the whole network round-trip of its child
`git push --force-with-lease refs/dolt/data`, and the waiting lane produced nothing, so a lane holding a
finished result **looked idle** and the failure itself carried no reason. It is the zombie-lane and
silent-spawn failure shape one layer down, and the artefact it delays (a verdict) is what authorises a
landing. It hits hardest when the fleet is busiest, because that is when several lanes push at once.

The bead's three preferences were: (a) name the holder once the lock has been held past a threshold,
(b) make the write path resilient, (c) if the wait is unavoidable, fail fast with a retry rather than
blocking a tool call for minutes. This patch implements **(a) and (c)**, and points at (b) — which is lane
discipline, not tooling — in the failure message itself.

### What it changes

- **The holder names itself.** After taking the lock, the holder writes one record line into the lock
  *file* — `pid=… lane=… role=… since=… cmd=comment` — and clears it before releasing. The file is a lock
  **object**, never a data file: flock's lock lives on the fd/inode, so writing a record into it does not
  disturb the lock.
- **A waiter reports the holder** — lane, role, pid, operation, how long it has been held, and the holder's
  **whole descendant tree** (bounded to 4 levels), because that is where the minutes actually go: the shim
  runs bd, bd runs git, git runs the remote helper doing the round-trip.
- **A DIAGNOSTIC MUST NOT NEED THE CONTENT IT IS DIAGNOSING (agents-zoch).** The first version of this
  patch stored and reported the holder's full argument vector. rev-elu6 defeated it by **driving** it
  rather than reading it:

  ```
  HOME=$H FLEET_ROLE=implementer bash bin/bd comment issue-x SENTINEL-PRIVATE-PAYLOAD &
    → lock record: pid=… argv=bd comment issue-x SENTINEL-PRIVATE-PAYLOAD     ← LEAK in the shared file
    → waiter stderr: bd: running: bd comment issue-x SENTINEL-PRIVATE-PAYLOAD ← LEAK in another lane's log
  ```

  Both surfaces belong to someone else: the lock file is shared by every lane on the VM, and the report is
  written into a lane that did not type the text — and bead text can be anything an operator or an agent
  typed. The fix is not to filter that text but to stop needing it: **every reported word now comes from a
  fixed vocabulary** — the subcommand and the `dolt` operation (`fleet_bd_lock_shape`), and a process name
  (`fleet_bd_lock_procname`) — with anything outside it reported as the literal `unrecognised` / `other`,
  and `gone` for a process that has exited. That is the fail-closed shape the reviewer guard above already
  uses, so a spelling nobody has thought of yet cannot leak either, **including freeform text in the
  subcommand position** (`bd "<private text>" …`). No bead id, body or argument is stored or printed.
  Applying the same probe now:

  ```
  lock record: pid=… lane=impl-secret role=implementer since=… cmd=comment
  waiter stderr: holder: lane=impl-secret role=implementer pid=… since 13:43:59Z
                 running: bd comment    (operation only: arguments can hold bead text - agents-zoch)
                   3689496 bash
                   3689497 sleep
  LEAK in record: no      LEAK in waiter stderr: no
  ```

- **The wait is unbounded no longer, and never silent.** Patience stays at 300s (`FLEET_BD_LOCK_WAIT`
  overrides it); a report is emitted on first contention and then at most once per `FLEET_BD_LOCK_REPORT`
  seconds (default 30). On expiry the call **fails fast with `EX_TEMPFAIL` (75)**, holder named, having
  changed *nothing* — so a caller can retry in seconds instead of blocking a tool call for minutes.
- **Reports go to stderr.** stdout carries bd's JSON for callers such as `bd show --json`; a report there
  would corrupt a parse.
- **The lock fd is closed for the bd payload only** (`"$real" "$@" {fleet_bd_lock_fd}>&-`), so a child bd
  leaves behind cannot keep every lane on the VM queued behind it after bd has exited. `flock(1)`'s child
  inherits the fd (measured), so the old shim was exposed to this too; a shell rewrite loses even the
  attempt unless the fd is closed explicitly — mine did, until `tests/bd-lock-holder.test.sh` caught it.
- **An unannotated holder is not a mystery:** a holder from before this patch, a record-less holder, or a
  record naming a dead pid is reported as `UNNAMED` / `stale`, with the fact that the lock releases
  automatically when a holder exits.

The gate guards and the comment-dash guard above it are untouched; the nested `FLEET_BD_LOCKED` path is
unchanged (it must not take the lock again, and does not).

### How it was verified

`tests/bd-lock-holder.test.sh` is hermetic — a stub `$HOME/.local/bin/bd` and a throwaway home — so it
never contends with the fleet's real lock, and it can be re-run in a gate or a review. Three of its cases
are the reviewer's probe as a regression test: the shared record, the waiting lane's stderr, and a
descendant's argument vector must each contain **no** bead text, and a freeform subcommand must be
reported as `unrecognised`.

| rig | result |
| --- | --- |
| patched shim, new suite | **46 passed, 0 failed** (35 behaviour + 11 privacy/shape cases) |
| **pre-change shim, the same suite** | **23 passed, 23 failed** — the 23 are exactly the pre-existing behaviours (uncontended call, exit-code pass-through, nested bypass, stdout purity) |
| patched shim, existing `tests/bd-shim.test.sh` | **15 passed, 0 failed** (serialisation and the nesting escape still hold) |
| composed with `fleet-worktree-beads-guard.patch`, both orders | applies both ways; composed shim is valid bash; **46/46 + 15/15 + that patch's own 13/13** |
| the reviewer's probe, reviewed tip vs this fix | leak in record **YES → no**, leak in waiter stderr **YES → no** |

Live evidence on the **real** lock, with a **real** `bd dolt push` through the patched shim as the holder:

```
holder record while it held the lock:
  pid=3549921 lane=agents-factory-impl-ozmt role=implementer since=… cmd=dolt push
a second call with FLEET_BD_LOCK_WAIT=0:
  bd: WAITING 0m0s for the VM-wide bd lock (one Dolt write at a time; a dolt push holds it for its git
      round-trip to origin).
  bd:   holder: lane=agents-factory-impl-ozmt role=implementer pid=3549921 since 13:28:48Z
  bd:   running: bd dolt push    (operation only: arguments can hold bead text - agents-zoch)
  bd:     3549926 bd
  bd: TIMEOUT (agents-elu6): … held for 0m0s. THIS CALL DID NOT RUN and changed nothing.
  → exit 75 (and the holder block is printed once, not repeated by the timeout)
a third call with FLEET_BD_LOCK_WAIT=30:
  waited 9s for the real push, reported once, THEN RAN the real bd (exit 0, the real bead printed)
after the push released:  the record is cleared, the lock file is empty
```

The same probe against the **unpatched** holder (the shim as deployed) reports `UNNAMED` and says why —
which is the honest rollout behaviour, not a failure.

Cost on the path that never contends: **+0.47 ms per call** (8.23 → 8.70 ms, best of 6 interleaved
40-call runs against a stub; the earlier +10 ms I first measured was VM drift, and interleaving the two
shims is what showed it). The uncontended path stays silent, writes one short record line and truncates
it again.

### What is NOT claimed

- **It does not shorten the wait.** A Dolt push still holds the lock for its git round-trip, and other
  lanes still wait for it. This makes the wait *visible, nameable and boundable*; shortening it is the
  cross-VM push cost, not this shim.
- **No forensic copy of the arguments was kept, deliberately.** The finding suggested a lane-local file
  as an alternative home for them. It was not taken: every lane on a VM runs as the **same unix user**, so
  a lane-local 0600 file is readable by every lane (the shim's own reviewer guard says the same about
  itself — "a speed bump, not a boundary"). That would move the leak rather than close it, and the
  diagnostic need — *which operation is holding the lock* — is met by the vocabulary. If the fleet wants
  argument-level forensics later it should be its own bead with its own threat model.
- **The record is advisory, not authoritative.** It is written by the shim, so a holder that predates this
  patch (or anything else that takes the same flock without annotating it) is reported as `UNNAMED`. On a
  VM mid-rollout you get named and unnamed holders both.
- **Option (b) is not implemented here.** Posting the verdict as a COMMENT before the label writes remains
  lane discipline; the timeout message tells the caller to do it rather than doing it for them.
- **`flock` is still the only serialisation.** Nothing here changes the critical section, and nothing here
  makes a timed-out call retry — it tells the caller to.
- **The vocabulary is a maintenance point.** A new bd subcommand that holds the lock will be reported as
  `unrecognised` until it is added to `fleet_bd_lock_shape`, which is the correct direction to fail (the
  report degrades to an opaque label rather than starting to print arguments).
- **Not measured:** behaviour if the system clock jumps backwards mid-hold (`since` would then read wrong);
  the record is display-only, and every decision (contention, bound, liveness) comes from the lock and
  `/proc`, never from the record's clock.
