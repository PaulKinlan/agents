## `fleet-bd-lock-holder.patch` (agents-elu6; revised for agents-zoch, agents-ttxh, agents-6e77)

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

### What NOT having this costs, measured on 2026-10-13

The defect is not a nuisance: it is a **lane-visible outage of the fleet's only channel for recording results**.
All of the following happened in one landing window on `agents-factory`:

- **Four lanes had bead writes time out.** For a lane, a bead write is how a verdict, a finding or a hand-off
  becomes durable; a refused write is not a slow operation, it is work that does not exist as far as the fleet
  is concerned.
- **One finding's sentence had to be recorded by ANOTHER actor to survive** — the lane that wrote it could not
  get the lock, so the record of it exists only because a second lane took it.
- **Multiple 300 s waits on the git pre-commit hook** (agents-vqwg): a `git commit` in a beads repo takes the
  same VM-wide lock, so commits - not just bead writes - queue behind unrelated lanes' pushes.
- **This lane measured starvation directly**: four consecutive calls refused at a 90 s bound (360 s of waiting,
  zero acquisitions) while the lock was continuously *served* to others, then one 240 s blocking acquisition that
  ran five operations nested. The refusal itself is a fairness defect in `flock -w`, which polls rather than
  queues (agents-nbka); the *silence* around it while work is fine is this patch's subject.

What this patch costs, for symmetry: one extra open file per bd call, one short record line written and cleared,
**+0.47 ms** on the uncontended path, and the loss of a holder's lane name (see the boundary section - a name
cannot be proved on a shared-uid VM). What it does not do is shorten any wait, and it does not make the lock
fair; it makes the wait **visible, nameable, bounded, and survivable**, so a lane can retry instead of
disappearing.

### What this patch promises, and where the boundary is (threat model)

This is stated as a BOUNDARY, not left for a reader to infer, because three successive reviews found the same
class in three successive positions.

**The property.** No lane's text reaches a shared file or another lane's log. Every value this shim writes to
the lock record and every value it prints is drawn from a **closed vocabulary** (bd operations, dolt
operations, roles, a process-name list) or is a **validated integer** (pid, timestamp). Nothing freeform is
copied, sanitised or escaped anywhere, and the reader re-validates every field it reads, so a record planted by
another process is no more dangerous than an honest one. Suffix after suffix was closed by *removing* the
content-bearing position rather than filtering it: the argument vector, then the environment-supplied lane
name, then a descendant's argv, then the lane name itself (below).

**The boundary, and it is a real one.** The lock file is 0644 and the lane registry is 0755, both owned by the
single unix user that **every lane runs as**. So a same-uid process can *write* anything it likes into the
record, and can create `~/.fleet/lanes/<anything>.model`. What this patch guarantees is therefore **not** that
the record is authentic — it is that **nothing a same-uid writer puts there is ever printed**. Concretely:

  * anything unparseable or out of vocabulary is reported as `unrecognised` / `other` / `UNNAMED`;
  * no field with an OPEN vocabulary is reported at all — that is why the lane name was removed rather than
    validated harder (agents-6e77): validating a name against a directory the attacker can write is not
    validation, and tightening the registry's permissions does not help when every lane is the same uid;
  * a diagnostic that *needs* the content it is diagnosing is refused as a design (agents-zoch);
  * a lane cannot prove its identity to another lane on this VM. Anything that must show a lane name to a human
    needs a trust boundary the fleet controls — per-lane uids, or a hub-attested registry — which is its own
    piece of work and deliberately not smuggled in here.

**What is explicitly NOT promised.** This patch does not shorten the wait. `flock -w` polls rather than queues,
so under load a caller can be refused for minutes while the lock is never idle; the shim now makes that
**visible, named and bounded** and fails fast with a retry hint, but the fairness defect is a separate finding
(agents-nbka) because a timeout cannot be tuned into a queue.

### What it changes

- **The holder names itself.** After taking the lock, the holder writes one record line into the lock
  *file* — `pid=… lane=… role=… since=… cmd=comment` — and clears it before releasing. The file is a lock
  **object**, never a data file: flock's lock lives on the fd/inode, so writing a record into it does not
  disturb the lock.
- **A waiter reports the holder** — lane, role, pid, operation, how long it has been held, and the holder's
  **whole descendant tree** (bounded to 4 levels), because that is where the minutes actually go: the shim
  runs bd, bd runs git, git runs the remote helper doing the round-trip.
- **THE DIAGNOSTIC NEEDS NO CONTENT, IN EVERY FIELD AND EVERY POSITION (agents-zoch).** The first version
  stored and reported the holder's full argument vector; rev-elu6 defeated it by **driving** it rather than
  reading it. Since a whitelist is the only shape that survives an adversary — a filter has to anticipate
  the payload, a vocabulary cannot express one — **every reported value is now one of: a vocabulary word**
  (bd operations, `dolt` operations, process names, roles), **a validated integer** (pid, timestamp), **or a
  lane name the fleet's own registry on this VM vouches for** — and then a second review (agents-6e77) showed
  that registry is **writable by every lane**, so it is NOT a trust boundary and the field had to go
  entirely: see "no lane name is claimed" below. Everything else becomes the literal
  `unrecognised` / `other` / `unknown`. Five positions had to be covered in all, and the last
  three were found by attacking this patch rather than the original defect:

  | position | attack | before | now |
  | --- | --- | --- | --- |
  | the **operation** | `bd comment issue-x SENTINEL-PRIVATE-PAYLOAD` | record + waiter stderr carried the text | `cmd=comment` / `running: bd comment` |
  | the **subcommand slot** | `bd "<private text>" …` | (would have been echoed) | `unrecognised` |
  | **`FLEET_LANE` / `FLEET_ROLE`** | env set by the holder's own actor | `lane=SENTINEL-PRIVATE-PAYLOAD` in the record **and** another lane's stderr | role: a closed vocabulary (`other`); **no lane field exists at all** |
  | **a self-registered lane name** (agents-6e77: the 0755 registry is writable by every lane) | create `~/.fleet/lanes/SENTINEL-PRIVATE-PAYLOAD.model`, set `FLEET_LANE` | the name was "vouched for" and reached the record **and** another lane's stderr | no lane field to vouch anything into |
  | a **planted record** (the 0644 lock file is writable by anyone) | arbitrary text in every field | echoed into another lane's stderr | `UNNAMED` before anything is printed |
  | a **descendant's argv** | `ps -o args=` on the holder's children | full argv (`git commit -m '<private text>'`) | pid + vocabulary process name |
  | a **descendant that renamed its executable** | `cp sleep SENTINEL-PRIV-BIN; ./SENTINEL-PRIV-BIN` | (would have echoed `comm`) | `other` — `comm` is filtered to the same vocabulary |

  Validation runs on **both sides**: the holder only writes validated values, the waiter re-validates
  everything it reads, so a planted record is no more dangerous than an honest one. No bead id, body or
  argument is stored or printed anywhere.
- **NO LANE NAME IS CLAIMED, ANYWHERE (agents-6e77).** An earlier revision of this patch reported the lane
  name of the holder, accepting it only when the VM's lane registry (`~/.fleet/lanes/<name>.model`) vouched
  for it. A second review found the flaw the whole branch is about, one layer out: **that registry is 0755
  and exedev-owned — every lane can write it** — so it is not an independent trust boundary, and a same-uid
  caller could create a file, set `FLEET_LANE`, and put chosen text into the shared record and from there
  into another lane's stderr. The repair is not to validate harder against a writable directory (that is
  polishing the bypass) but to **remove the field** — the boundary that forces this is stated in full above: on a shared-uid VM nothing proves a name — the registry
  is writable, `FLEET_LANE` is environment, and a process names itself. So the holder is described by what
  can be proved: `role` (a closed vocabulary), `pid` and age (integers), the operation (a closed
  vocabulary) and its descendant process names (the same closed vocabulary). Anything an attacker writes
  into the shared file is now *ignored* rather than filtered. Two consequences worth stating: the glob/order
  property the previous round pinned to that field is **moot** — the field it protected no longer exists,
  which answers the same class more strongly than a pin could — and a fleet that wants named holders needs a
  trust boundary it controls (per-lane uids, or a hub-attested registry), which is its own piece of work.
- **The wait is unbounded no longer, and never silent.** Patience stays at 300s (`FLEET_BD_LOCK_WAIT`
  overrides it); a report is emitted on first contention and then at most once per `FLEET_BD_LOCK_REPORT`
  seconds (default 30). On expiry the call **fails fast with `EX_TEMPFAIL` (75)**, holder named, having
  changed *nothing* — so a caller can retry in seconds instead of blocking a tool call for minutes.
- **Reports go to stderr.** stdout carries bd's JSON for callers such as `bd show --json`; a report there
  would corrupt a parse.
- **THE LOCK IS HELD BY THE WORK, NOT BY THIS SHELL'S LIFETIME (P1, found by review).** bd **inherits** the
  lock fd, so the lock survives this shim being SIGKILLed for as long as bd is still writing — and this
  fleet SIGKILLs shims all day (bounded gates, the reaper, lane restarts), so that is normal operation.
  An earlier revision of this patch closed the fd for bd (`{fleet_bd_lock_fd}>&-`) to stop a stray
  descendant holding the lock after bd exited; the reviewer's probe measured what that cost:

  | SIGKILL the shim while `bd` is still writing, then run a second call | result |
  | --- | --- |
  | as deployed (`flock(1)`'s child inherits the fd) | waits 5s for the work, then runs — **serialised** |
  | with the fd closed for the child (the earlier revision) | runs immediately, 0s, rc=0 — **BYPASS, two writers** |
  | this revision (bd inherits) | refused: rc=75 with a 1s bound, while the first bd was **still writing** |

  The two failure directions are not symmetric, and that is what decides it: **over-holding** (a descendant
  that outlives bd keeps the lock) delays other lanes, while **under-holding** (the lock released while bd
  writes) breaks the one invariant this shim exists for. So the inheritance stays and the over-hold is
  *reported* rather than prevented: a record whose pid is gone while the lock is still held is exactly that
  case, and the waiter says the record is stale and the lock is still held. `tests/bd-lock-holder.test.sh`
  case 9 pins it, and it is the only case that distinguishes this revision from the one it replaces
  (against the fd-closing revision exactly 9a and 9b fail, 54 passed / 2 failed).
- **An unannotated holder is not a mystery:** a holder from before this patch, a record written by
  something else, or a record with an unusable pid is reported as `UNNAMED`, with the fact that the lock
  releases automatically when a holder exits.

The gate guards and the comment-dash guard above it are untouched; the nested `FLEET_BD_LOCKED` path is
unchanged (it must not take the lock again, and does not).

### How it was verified

`tests/bd-lock-holder.test.sh` is hermetic — a stub `$HOME/.local/bin/bd`, a throwaway home and a
throwaway lock file — so it never contends with the fleet's real lock, and it can be re-run in a gate
or a review. Sixteen of its cases are the attacks above as regression tests: the shared record, the
waiting lane's stderr, a descendant's argument vector, a freeform subcommand, an environment-supplied lane
name, and a planted record must each carry no bead text (and a freeform subcommand must report
`unrecognised`, an unregistered lane `unregistered`).

| rig | result |
| --- | --- |
| patched shim, new suite | **63 passed, 0 failed** (42 behaviour + 21 privacy/shape cases) |
| **the revision this replaces** (lock fd closed for bd), the same suite | **54 passed, 2 failed** — and the two are exactly case 9a/9b, the killed-shim bypass |
| **the revision before this one** (it still reported a registry-vouched lane name), the same suite | **57 passed, 6 failed** — and the failures include exactly the reviewer's agents-6e77 probe: a self-registered name reaching the shared record and another lane's stderr (15a/15b/15c) |
| **shim as deployed, the same suite** | **32 passed, 31 failed** — the 32 are exactly the pre-existing behaviours (uncontended call, exit-code pass-through, nested bypass, stdout purity) |
| patched shim, existing `tests/bd-shim.test.sh` | **15 passed, 0 failed** (serialisation and the nesting escape still hold) |
| composed with `fleet-worktree-beads-guard.patch`, **both orders** | applies both ways; composed shim valid bash; **56/56 + 15/15 + that patch's own 13/13** |
| the three probes, first version vs this revision | operation **LEAK → no**, env lane/role **LEAK → no**, planted record **LEAK → no** |

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
- **No forensic copy of the arguments was kept, deliberately — an operator-invisible tradeoff.** The
  finding suggested a lane-local file as an alternative home for them. It was not taken: every lane on a
  VM runs as the **same unix user**, so a lane-local 0600 file is readable by every lane (the shim's own
  reviewer guard says the same about itself — "a speed bump, not a boundary"). That would move the leak
  rather than close it, and it would do so *while looking safe*, which is worse than the original. The
  trade is explicit: **argument-level forensics are given up, in exchange for the guarantee that no lane's
  text reaches a shared file or another lane's log.** If the fleet wants that forensics it should be its
  own bead with its own threat model.
- **The holder is not NAMED BY LANE, deliberately.** The report says `role=implementer pid=3730508` rather
  than a lane name, because no field on a shared-uid VM proves one (agents-6e77). A lane that wants to know
  whether a holder is itself can compare the pid; a lane that wants to name another lane to a human cannot
  get that from this shim, and should not — that is how the injection arrived.
- **The vocabularies are a maintenance point.** A new bd subcommand or a new process name is reported as
  `unrecognised` / `other` until it is listed. That is the correct direction to fail: the report degrades to
  an opaque label instead of starting to print arguments an attacker chose.
- **The record is advisory, not authoritative.** It is written by the shim, so a holder that predates this
  patch reports `UNNAMED`. On a VM mid-rollout you get named and unnamed holders both.
- **A stray descendant can hold the lock past bd's exit, and that is now the accepted direction to fail.**
  The alternative — releasing the lock when this shell dies — was measured to allow two concurrent writers,
  which is worse. The cost is a delay, not corruption, and the waiter reports it (a record whose pid is gone
  while the lock is still held reads as stale). A sweep that reclaims a lock held by an orphaned descendant
  would need its own bead: naming the real holder requires scanning other processes for the lock fd, which is
  a capability this patch deliberately does not add.
- **Option (b) from the review is NOT a fix for the P1.** Revalidating the record against the holder's
  liveness cannot close it: while the shim is dead and bd is writing, the lock is FREE, so a second call
  acquires it without ever seeing contention and nothing on the waiting side is consulted. Correctness comes
  from the fd, which is why the fix is the inheritance. (The record's liveness check stays useful for the
  stale-record case, and that is all it is.) Posting the verdict as a COMMENT before the label writes remains
  lane discipline; the timeout message tells the caller to do it rather than doing it for them.
- **`flock` is still the only serialisation.** Nothing here changes the critical section, and nothing here
  makes a timed-out call retry — it tells the caller to.
- **Not measured:** behaviour if the system clock jumps backwards mid-hold (`since` would then read wrong);
  the record is display-only, and every decision (contention, bound, liveness) comes from the lock and
  `/proc`, never from the record's clock.
