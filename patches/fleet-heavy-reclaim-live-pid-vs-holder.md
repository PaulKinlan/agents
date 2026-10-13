## `fleet-heavy-reclaim-live-pid-vs-holder.patch` (agents-5n28)

**Applies on top of** `~/fleet/bin/fleet-heavy` as of 2026-10-12 21:10 - 14378 bytes, sha256 33ecf140e615852a... - the
revision that carries `reclaim_abandoned_slot` (the 2026-10-12 orphan reclaim). One line of logic
changes, at `reclaim_abandoned_slot`, and it is independent of the `agents-nxj8` patch to the job-end
sweep even though both touch this file; the two edit different regions and can land in either order.

### Why

The heavy slot can be held for hours by an orphan while every waiter declines to touch it. The reclaim
that exists for exactly that case refuses on this line:

    [ -n "$hp" ] && kill -0 "$hp" 2>/dev/null && return 1

`$hp` is the pid recorded in the slot label. The comment above it says a live wrapper is never touched
because "a legitimately slow gate is exactly what this queue exists to protect" - and that reasoning is
right. The test is wrong: **a live PID is not a live WRAPPER**. Once the wrapper has died and its pid has
been reused, `kill -0` succeeds, the function concludes an honest slow gate holds the slot, and returns.
Nothing else in the reclaim can fire, because it returns before the orphan signatures and the grace are
even considered.

### What it changes

The discriminator is already computed three lines above: the holders list is the set of processes
actually holding the slot fd. **A live wrapper is always in that set** - it takes the flock and holds
it for the whole job. **A reused pid holds nothing.** So membership is the test, not liveness, and it
is a field the kernel maintains rather than a heuristic or a timeout guess. When the recorded pid is
alive but absent from the holders list, the function says so on stderr and falls through to the orphan
signatures and the grace, which is where an abandoned slot belongs.

### How it was verified

On a **copy in `/tmp`** of the file at exactly the revision named above (`~/fleet` is not writable from
a project host), with an isolated `FLEET_HEAVY_DIR`, a real `setsid`-detached holder that takes the
**flock** (not merely an fd), a reduced `FLEET_HEAVY_ORPHAN_GRACE`, and a second live process that
holds nothing:

| case | label names | today | patched |
| --- | --- | --- | --- |
| honest live wrapper | the fd-holder | not reclaimed (waited 50s) | **not reclaimed** (waited 50s) |
| reused-pid signature | a live pid holding nothing | **not reclaimed** (waited 45s) | **reclaimed, slot after 5s** |

The first row is the one that must not move, and it did not: a genuinely slow job is still protected,
because its wrapper is a holder. The second row is the defect: today's code cannot distinguish the two
and so protects the orphan.

### What is NOT claimed

I did not observe pid reuse happening on the hub and cannot show the pid that was reused - the husks
were dead before anyone could read them. What is measured is that a label naming a live pid that holds
nothing - the signature reuse produces - is *refused* by the current code and *reclaimed* by this patch,
while the honest case is unchanged. If the hub's 6,743-second hold was instead the arrival time of the
first waiter, the reclaim never ran and no pid comparison is involved; that ordering was not recorded.

### A separate follow-up, not part of this patch

`slot_fd_holders` is called from three sites, and two of them use it inside a `$( )` that inherits the
slot fd, so the substitution's own fork/grep/tr are holders by the function's own test. That is the
defect `agents-nxj8` patches at the job-end sweep call site; the durable fix is **inside**
`slot_fd_holders`, where it would cover all three callers at once. Filed separately so neither patch
has to be amended while it is under review.
