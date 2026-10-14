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

### agents-7saq (P1): the match was space-delimited, the holder list is one pid per line

The first cut of this patch tested membership with `case " $holders " in *" $hp "*)`. `slot_fd_holders`
emits **one pid per line** (`printf '%s\n'`), so that pattern can only ever fire for a SOLE holder: every
other pid sits between newlines and neither space matches. The reclaim therefore concluded the recorded
wrapper was not a holder, fell through to the orphan signatures and the grace, and TERMed an honest gate
that really did hold the slot - the worst direction this function can fail in, because it kills live work
rather than leaving a slot busy.

**Why the first cut's verification did not catch it:** row 1 of the table above planted a rig with
EXACTLY ONE visible holder, so the space-delimited pattern matched and the honest case "passed". A real
wrapper always coexists with its job tree on the fd, so a single-holder rig could not fail. The trigger
to vary was the COUNT (>=2 holders) and the LIST SHAPE - and the list shape was the defect.

The match now uses exact-line boundaries and no new subshell (a `$( )` here would inherit the slot fd
and become a holder itself):

    case "$holders" in
      "$hp"|"$hp"$'\n'*|*$'\n'"$hp"|*$'\n'"$hp"$'\n'*) return 1 ;;
    esac

**Driven on the reviewer's own 7saq rig** (`/tmp/rev-nxj8b-r2`, pristine 14378 bytes sha256
33ecf140e615852a), a live `flock`-holding wrapper named in the label, one waiter:

| binary | waiter exit | honest wrapper |
| --- | --- | --- |
| delivered (this patch before the fix) | 0 | **KILLED** - "alive but holding no fd - not our wrapper", then "reclaiming slot1 - holder is GONE" |
| fixed | **124** | **ALIVE** - "waiting for a heavy slot (busy: ... planted;)" |
| unpatched | 124 | ALIVE - the reviewer's control, from the `kill -0` liveness line this patch replaces |

And the pure-shell mechanism, driven directly: with `holders=$'111\n222\n333'`, the delivered pattern
matched none of first/middle/last, while the fixed one matches all four positions.

### agents-bz7j: the property and the deferral

The property, stated so a reader can check it rather than take it on trust: **a live recorded pid protects
the slot only when that pid is among the processes holding the slot fd**. A live wrapper is always in that
set - it takes the flock and holds it for the whole job. A reused pid is alive and holds nothing. The
`kill -0` liveness test this replaces cannot tell those apart.

**What this function does NOT do, stated rather than left implicit:** the reclaim has no process-group
test at all. It decides on two things only - whether the recorded pid is among the fd holders, and, if
not, whether the orphan signatures and the grace are satisfied. A holder that shares this script's own
process group is therefore treated exactly like any other holder: it is protected while it holds the
slot, and it is a candidate for reclamation once it is gone. (The process-group exclusion belongs to the
job-end SWEEP, which is a different path in the same file and has its own write-up; an earlier draft of
this section wrongly borrowed that idea, which is agents-qlok.)

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

### Re-cut for usable path headers (agents-2b5j, 2026-10-14)

**The change is identical; only the headers changed.** The delivered artifact carried
`--- /home/exedev/fleet/bin/fleet-heavy` (an ABSOLUTE path in one, `base` -> `x` placeholders in another,
`/tmp/lhow/...` scratch paths in the third) with a `+++` path pointing at a scratch copy, so the hub had
to reconstruct the target by hand. This re-cut has `--- a/bin/fleet-heavy` / `+++ b/bin/fleet-heavy`, so
`patch -p1` from a checkout root applies it.

* artifact: `fleet-heavy-reclaim-live-pid-vs-holder.patch`, 3302 bytes, sha256 `2553035d8d0f8c24f5f493a1040fdacb80924c207501d15702b32ef6e64369a3`, hunk `@@ -92,7 +92,27 @@`
* base, unchanged from the original write-up: `bin/fleet-heavy` 14378 bytes, sha256
  `33ecf140e615852a...` - present in the integration copy (`~/fleet-copy/bin/fleet-heavy`). It applies
  on top of the base file alone.
* **ACCEPTANCE, run against a COPY of that base** (not the deployed file - see the caveat below):
  `patch -p1 -F0 --dry-run` exits 0 with no fuzz and no offset, and the hunk lands at `@@ -92,7 +92,27 @@`.
* **The re-cut cannot be a different change:** the three originals applied in order to the base produce
  a file of 322 lines, sha256 `9e30db1f62c2ac4f...`; the three re-cuts applied in the same order produce
  a BYTE-IDENTICAL file. `bash -n` is clean and the structural anchors survive (`slot_state`,
  `ticket_take`, `ticket_drop`, `slot_fd_holders`, `reclaim_abandoned_slot`).
* **CAVEAT, measured:** this VM's `~/fleet/bin/fleet-heavy` is NOT the file these patches target - it is
  the older 154-line snapshot (sha `0f95ccd3...`), i.e. commit `3180e13` of the integration repo, while
  the write-ups' base `33ecf140...` is `0c69746` ("sync: match pristine ~/fleet baseline (2026-10-12
  21:10 update)"). Applying against the stale deployed copy fails every hunk because the reclaim
  machinery the patch edits (`reclaim_abandoned_slot`, `slot_fd_holders`) does not exist there at all.
  The base named above is the one the patch was cut against and the one the hub has.
