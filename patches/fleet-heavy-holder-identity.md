## `fleet-heavy-holder-identity.patch` (agents-lhow)

**Applies on top of** `~/fleet/bin/fleet-heavy` (14378 bytes, sha256 33ecf140e615852a...) **plus both settled patches**
in this directory: `fleet-heavy-jobend-holder-attribution.patch` first, then
`fleet-heavy-reclaim-live-pid-vs-holder.patch`, then this one. Order matters only in that this patch
removes a check the sweep patch added; the function change itself is independent of both.

### Why

`slot_fd_holders` walks `/proc` for processes holding the slot fd, and excludes "ourselves and our own
children" (fleet-91fr). The wording of that exclusion is narrower than the problem: this function is
almost always called from a command substitution, the `$( )` subshell inherits our open fd, and the
pipeline it runs - fork, `grep`, `tr` - are its children, which makes them GRANDCHILDREN of the shell.
The exclusion checks one level of parentage, so it caught the subshell and missed the rest of the
pipeline. Measured on this VM: the job-end warning named the fork, `grep -v ^<pid>$` and `tr \n`, in
that order, on every gate that ran.

### What it changes

The exclusion walks the parent chain instead of checking one level: a process is skipped when any
ancestor is `$$`. An abandoned holder is never a descendant - the wrapper is dead, so its children were
reparented to init - so the walk cannot hide the leak the sweep exists to find.

Because identity now excludes the instrument exactly, the sweep's own-process-group exclusion is removed.
That exclusion was a debt: it skipped a holder in OUR group whatever it was, and a job that backgrounds
a child without `setsid` leaves a genuine leak in exactly that group, so such a leak was deferred to
`reclaim_abandoned_slot` (agents-bz7j, about 65s with defaults) instead of being released at job end.

### How it was verified

On a copy in `/tmp` of the base described above, isolated `FLEET_HEAVY_DIR`, a forced refusal that runs
the real gate script in the worktree:

| binary | job | warned | pids named |
| --- | --- | --- | --- |
| settled (group test present) | forced refusal | YES | **3** |
| this patch (identity only, group test removed) | the same job | **no** | **0** |

Same job, same rig, one variable changed - so the identity exclusion covers what the group exclusion did
not, and the group test can go without the instrument coming back.

### What is NOT claimed

The second half of the rationale - that removing the group exclusion lets a same-group leak be killed at
job end - is **not** demonstrated here. My rig for it planted a backgrounded job child, and it died in
both binaries, so the case did not discriminate; I could not build one where the group test's deferral is
observable before cleanup. The reasoning is that the exclusion is gone and the ancestry walk cannot touch
a reparented process, which is sound but is an argument rather than a measurement, and it is recorded as
such. The first table's row is a measurement.

### Re-cut for usable path headers (agents-2b5j, 2026-10-14)

**The change is identical; only the headers changed.** The delivered artifact carried
`--- /home/exedev/fleet/bin/fleet-heavy` (an ABSOLUTE path in one, `base` -> `x` placeholders in another,
`/tmp/lhow/...` scratch paths in the third) with a `+++` path pointing at a scratch copy, so the hub had
to reconstruct the target by hand. This re-cut has `--- a/bin/fleet-heavy` / `+++ b/bin/fleet-heavy`, so
`patch -p1` from a checkout root applies it.

* artifact: `fleet-heavy-holder-identity.patch`, 3143 bytes, sha256 `cba88a95267cc5335dd9f4b06a5bbd3ff310a17f50ecdc78752b8fa04618d929`, hunk `@@ -53,14 +53,22 @@`
* base, unchanged from the original write-up: `bin/fleet-heavy` 14378 bytes, sha256
  `33ecf140e615852a...` - present in the integration copy (`~/fleet-copy/bin/fleet-heavy`). It applies
  on top of the base file PLUS the two other re-cut artifacts applied first and in this order:
  `fleet-heavy-jobend-holder-attribution.patch`, then `fleet-heavy-reclaim-live-pid-vs-holder.patch`.
* **ACCEPTANCE, run against a COPY of that base** (not the deployed file - see the caveat below):
  `patch -p1 -F0 --dry-run` exits 0 with no fuzz and no offset, and the hunk lands at `@@ -53,14 +53,22 @@`.
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
