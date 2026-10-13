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
