## `fleet-bd-lock-holder.patch` (agents-elu6)

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
  *file* — `pid=… lane=… role=… since=… argv=bd dolt push` — and clears it before releasing. The file is a
  lock **object**, never a data file: flock's lock lives on the fd/inode, so writing a record into it does
  not disturb the lock. `fleet_bd_lock_field` splits tokens before matching, so a field at the start of the
  line (`pid=`) parses like one in the middle — a regex needing a leading space made every holder report
  `UNNAMED` until the new test caught it.
- **A waiter reports the holder** — lane, role, pid, the bd command, how long it has been held, and the
  holder's **whole descendant tree** (bounded to 4 levels), because that is where the minutes actually go:
  the shim runs bd, bd runs git, git runs the remote helper doing the round-trip.
- **The wait is unbounded no longer, and never silent.** Patience stays at 300s (`FLEET_BD_LOCK_WAIT`
  overrides it); a report is emitted on first contention and then at most once per `FLEET_BD_LOCK_REPORT`
  seconds (default 30). On expiry the call **fails fast with `EX_TEMPFAIL` (75)**, holder named, having
  changed *nothing* — so a caller can retry in seconds instead of blocking a tool call for minutes.
- **Reports go to stderr.** stdout carries bd's JSON for callers such as `bd show --json`; a report there
  would corrupt a parse.
- **The lock fd is closed for the bd payload only** (`"$real" "$@" {fleet_bd_lock_fd}>&-`), so a child bd
  leaves behind cannot keep every lane on the VM queued behind it after bd has exited. `flock(1)` got this
  for free (measured: its child inherits the lock fd, but the command it runs does not leak it further);
  a shell rewrite loses the property silently and did — which is why the test pins it.
- **An unannotated holder is not a mystery:** a holder from before this patch, a records-less holder, or a
  record naming a dead pid is reported as `UNNAMED` / `stale`, with the fact that the lock releases
  automatically when a holder exits.

The gate guards and the comment-dash guard above it are untouched; the nested `FLEET_BD_LOCKED` path is
unchanged (it must not take the lock again, and does not).

### How it was verified

`tests/bd-lock-holder.test.sh` is hermetic — a stub `$HOME/.local/bin/bd` and a throwaway home — so it
never contends with the fleet's real lock, and it can be re-run in a gate or a review.

| rig | result |
| --- | --- |
| patched shim, new suite | **35 passed, 0 failed** |
| **pre-change shim, the same suite** | **15 passed, 18 failed** — and the 15 are exactly the pre-existing behaviours (uncontended call, exit-code pass-through, nested bypass, stdout purity) |
| patched shim, existing `tests/bd-shim.test.sh` | **15 passed, 0 failed** (serialisation and the nesting escape still hold) |
| composed with `fleet-worktree-beads-guard.patch`, order A then B | applies both ways (offset/fuzz, different regions); composed shim is valid bash; **35/35 + 15/15 + that patch's own 13/13** |

Live evidence on the **real** lock, with a **real** `bd dolt push` through the patched shim as the holder:

```
holder record while it held the lock:
  pid=3549921 lane=agents-factory-impl-ozmt role=implementer since=1791898128 argv=bd dolt push
a second call with FLEET_BD_LOCK_WAIT=0:
  bd: WAITING 0m0s for the VM-wide bd lock (one Dolt write at a time; a dolt push holds it for its git
      round-trip to origin).
  bd:   holder: lane=agents-factory-impl-ozmt role=implementer pid=3549921 since 13:28:48Z
  bd:   running: bd dolt push
  bd:     *3549926 /home/exedev/.local/bin/bd dolt push
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
- **The record is advisory, not authoritative.** It is written by the shim, so a holder that predates this
  patch (or anything else that takes the same flock without annotating it) is reported as `UNNAMED`. On a
  VM mid-rollout you get named and unnamed holders both.
- **Option (b) is not implemented here.** Posting the verdict as a COMMENT before the label writes remains
  lane discipline; the timeout message tells the caller to do it rather than doing it for them.
- **`flock` is still the only serialisation.** Nothing here changes the critical section, and nothing here
  makes a timed-out call retry — it tells the caller to.
- **Not measured:** behaviour if the system clock jumps backwards mid-hold (`since` would then read wrong);
  the record is display-only, and every decision (contention, bound, liveness) comes from the lock and
  `/proc`, never from the record's clock.
