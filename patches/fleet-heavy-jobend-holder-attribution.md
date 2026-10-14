## `fleet-heavy-jobend-holder-attribution.patch` (agents-nxj8, round 2)

**Cut against an alternate, NOT INSTALLED generation**, 14,378 bytes, SHA-256
`33ecf140e615852a9d374b27b6e4b956365b80f3e942f25a6a5d897db0617e58`, found at
`~/fleet/fleet-heavy` (top level) and `~/fleet-copy/bin/fleet-heavy`, NOT the executable
`~/fleet/bin/fleet-heavy`. That generation carries `reclaim_abandoned_slot`. Replaces the round-1
delivery; round 1 was reviewed and
FAILED on `agents-z5pp`, and a re-cut tip needs a fresh verdict, so this file supersedes it rather than
amending it in place.

### Why

The sweep that runs when a job ends walks `/proc` for processes holding the slot fd and kills what it
finds. It was accused of two defects, and both are real.

**(1) It counted its own measurement as the leak (agents-nxj8).** The holder list is computed inside a
`$( )`, and that substitution INHERITS the open fd on the slot file - so its own fork, `grep` and `tr`
are holders by the function's own fd test. They are GRANDCHILDREN (their parent is the substitution's
subshell) and the fleet-91fr exclusion skips only `$$` and its DIRECT children. The sweep therefore
reported its own pipeline as leaked descendants. Measured repeatedly on this VM: the warning named the
fork, `grep -v ^<pid>$` and `tr \n`, in that order, on every gate that ran.

**(2) It widened a pid kill to a process group, and took bystanders (agents-z5pp).** Round 1 also
switched the job-end kill from the accused pids to their whole process groups, copying the preemption
path's technique. A group is a bigger population than the accusation: a process that shares the group
but holds no slot fd - a concurrent waiter's transient fd, or any sibling - dies without ever having
been named. The rule this fleet took from an earlier incident is exact: a cleanup pattern must match a
property the target has and the innocent does not.

### What it changes

* The holders are collected into a list, excluding only this script's own pid and its own process
  group. A leaked holder is `setsid`-detached with its own group, so the exclusion is precise; the
  instrument shares our group, so it is excluded by construction rather than by pattern.
* A group is signalled ONLY when every process in it is already among the accused; otherwise the accused
  pids are signalled directly, and a group is never signalled across the boundary of our own group.
  This is STRICTLY NARROWER than round 1 in every case: it cannot kill anything round 1 would have
  spared.
* `TERM` and `KILL` act on the same set, computed once.

### The citation, corrected (agents-bz7j)

Round 1 attributed the negative-pid kill to the orphan path. It is the **PREEMPTION** path - L221-224,
the merger ticket class, `if [ "$myticket" -lt 1000000000 ]` - which kills a whole group by design
because there the accused IS the whole job tree (fleet-uhxq). Read from the file, not inferred. A fix
whose argument is that two places should use the same treatment cannot afford to misname which place it
is copying.

### How it was verified

On a copy in `/tmp` of the file at the named revision, with an isolated `FLEET_HEAVY_DIR`:

| run | fixture | expected | observed |
| --- | --- | --- | --- |
| R1 | unpatched, forced refusal | the instrument fires | warns, naming the fork/grep/tr |
| R2 | round 2, same refusal | the instrument is silent | silent |
| R3 | round 2 + a **job-spawned** setsid husk | fires on the real leak only | warns naming EXACTLY the husk, slot free after |
| R4 | unpatched + same husk | fires on husk AND instrument | warns with both mixed together |
| P2 | **the reviewer's own z5pp rig**, verbatim | v1 kills the bystander; round 2 spares it | v1: innocent DEAD, warning named two pids, innocent not among them. round 2: innocent ALIVE, same two accused named. Holder gone in both. |

R3's fixture is a descendant that OUTLIVES the job, which is the incident's shape - my first attempt
planted the holder BEFORE the job, so the job never took the slot and nothing was swept. That null
result was the probe, not the code.

The P2 row was run with the invocation the reviewer kept in `/tmp/rev-l200-fh`, because my own
construction could not see the mechanism: mine ran a REAL GATE as the job, so the fd test had already
accused the innocent. Theirs uses a stub job and a SIBLING victim, so the innocent sits in the victim's
group while the job's own fd never reaches it. **When a fixture fails to reproduce, the trigger is the
thing to vary, not the assertion.**

### The setsid assumption, stated as an assumption (agents-bz7j)

The sweep treats a holder that is in THIS script's own process group as the measurement pipeline and
skips it. That is true of the pipeline - its fork, `grep` and `tr` are children of our own `$( )` - but
it is NOT a property of leaks, and the reviewer measured the counter-example: a job that backgrounds a
child WITHOUT `setsid` leaves that child in our group, holding the slot fd, reparented to init. It is a
genuine leak and the sweep will not kill it.

What happens to such a holder instead, so the cost is stated rather than implied: it is left to
`reclaim_abandoned_slot`, which finds it through the orphan signatures (ppid 1) once the grace has
passed. Measured on the reviewer's rig: `--status` reports the slot as `held:unknown` and the next
waiter reclaims it after grace plus one poll, about 65s with defaults, rather than at job end.

That is a debt, not a design. It is taken because the alternative - killing a whole process group that
contains our own instrument - is the agents-z5pp defect, which kills innocent bystanders. The durable fix
is to exclude the instrument by IDENTITY inside `slot_fd_holders` rather than by group membership at the
call site, which is agents-lhow; when that lands, this exclusion can be narrowed and a same-group leak
can be killed at job end again.

### What is NOT claimed

That the collateral kill was ever observed on the hub. It is reproduced on the reviewer's rig, which is
the strongest form available for a race of this shape. The bystander in that rig holds no slot fd; a
process that DOES hold one is accused and killed, which is intended.

### Re-cut for usable path headers (agents-2b5j, 2026-10-14)

**The change is identical; only the headers changed.** The delivered artifact carried
`--- /home/exedev/fleet/bin/fleet-heavy` (an ABSOLUTE path in one, `base` -> `x` placeholders in another,
`/tmp/lhow/...` scratch paths in the third) with a `+++` path pointing at a scratch copy, so the hub had
to reconstruct the target by hand. This re-cut has `--- a/bin/fleet-heavy` / `+++ b/bin/fleet-heavy`, so
`patch -p1` from a checkout root applies it.

* artifact: `fleet-heavy-jobend-holder-attribution.patch`, 3602 bytes, sha256 `9160e3eec2d6ef7361c06f76b0d7f558693495cf872f8ddcf085d225a9834547`, hunk `@@ -197,10 +197,52 @@`
* base, unchanged from the original write-up: `bin/fleet-heavy` 14378 bytes, sha256
  `33ecf140e615852a...` - present in the integration copy (`~/fleet-copy/bin/fleet-heavy`). It applies
  on top of the base file alone.
* **ACCEPTANCE, run against a COPY of that base** (not the deployed file - see the caveat below):
  `patch -p1 -F0 --dry-run` exits 0 with no fuzz and no offset, and the hunk lands at `@@ -197,10 +197,52 @@`.
* **The re-cut cannot be a different change:** the three originals applied in order to the base produce
  a file of 322 lines, sha256 `9e30db1f62c2ac4f...`; the three re-cuts applied in the same order produce
  a BYTE-IDENTICAL file. `bash -n` is clean and the structural anchors survive (`slot_state`,
  `ticket_take`, `ticket_drop`, `slot_fd_holders`, `reclaim_abandoned_slot`).
* **CAVEAT, measured on this VM:** the LIVE executable is `~/fleet/bin/fleet-heavy`, **154 lines,
  7,850 bytes**, SHA-256 `0f95ccd3c392b9736362713ce006f0b21f02f80e49951eda3da5ae1cf9863a91`.
  The **alternate 14,378-byte base is NOT installed in `bin/`**; it remains at the top-level
  `~/fleet/fleet-heavy` and `~/fleet-copy/bin/fleet-heavy`, SHA-256
  `33ecf140e615852a9d374b27b6e4b956365b80f3e942f25a6a5d897db0617e58`.
  On a COPY of the live 7,850-byte file the first patch's strict `patch -p1 --fuzz=0 --dry-run`
  fails rc 1 (hunk at 197); on a COPY of the alternate base the three ordered re-cuts apply
  strictly with no rejects and yield SHA-256
  `9e30db1f62c2ac4f8143353a6bf76afc2b1bb93eda563c008068fa6c1059310a`.
  Thus the live copy is not an obsolete copy of the declared base; they are different
  generations. **STOP before installing**: the hub must deliberately choose and establish the
  14,378-byte generation as the executable, validate that transition and then check each
  ordered prerequisite against its actual SHA-256. Neither a patch dry-run on the wrong path
  nor the presence of a top-level file constitutes a live `bin/` installation.
