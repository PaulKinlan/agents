## `fleet-heavy-jobend-holder-attribution.patch` (agents-nxj8, agents-5n28)

**Applies on top of** `~/fleet/bin/fleet-heavy` as of 2026-10-12 21:10 - 14378 bytes, sha256 33ecf140e615852a... - which is
the revision that carries `slot_fd_holders` (fleet-91fr) and the process-group kill in the orphan path
(fleet-uhxq). If that file has moved, re-read the two anchors named below before applying.

### Why

`fleet-heavy` warns that "descendants still held slotN after the job finished" and kills them. That
warning is firing on **fleet-heavy's own measuring pipeline**.

The job-end sweep computes its list with a command substitution:

    leaked=$(slot_fd_holders "$i" | grep -v "^$$\$" | tr '\n' ' ')

The substitution **inherits** fleet-heavy's open file descriptor on the slot file, so its forked bash,
its `grep` and its `tr` are holders by `slot_fd_holders`' own fd test. They are **grandchildren** of
fleet-heavy (their `ppid` is the substitution's subshell), and the fleet-91fr exclusion skips only `$$`
and its **direct** children. The sweep therefore reports its own pipeline as leaked descendants and
kills it.

Measured live on 2026-10-13 by a bounded `/proc` scan using the same fd test the code uses, with the
failure driven rather than inferred - a forced refusal through fleet-heavy (8.6s, no full gate):

    warning pids:   3286099  3286100  3286101
    cmdlines:       bash (the fork)   grep -v ^3286057$   tr \n

The sweep's accusation and the observed holder list are the same three processes, in the same order.
Reproduced three times; each run shared **one process group** - fleet-heavy's own.

The real leak this warning exists to catch is a **different** population: setsid-detached processes
that outlive a dead wrapper, which have their **own** process group. So the two populations differ in a
field the kernel maintains, which is why the fix can be a field test rather than a heuristic.

### What it changes

1. **The measurement is no longer counted.** Holders in fleet-heavy's **own** process group are skipped.
   The `$( )` subshell shares that group; a real leaked holder does not.
2. **The kill covers the group, not a pid list.** The orphan path already does this
   (`kill -TERM -$pg`, fleet-uhxq, with the reason recorded there: "a child that reparented, or one
   spawned between the walk and the kill, SURVIVED and went on burning CPU"). That correction was never
   carried to the job-end sweep. The `sleep 1` between TERM and KILL is unchanged.
3. A guard refuses to signal fleet-heavy's own group in both loops, so the sweep cannot kill itself.

### How it was verified

Both directions, on a **copy** in `/tmp` (the hub's copy under `~/fleet` is not writable here), driving
the failure rather than reasoning about it:

| run | warned? |
| --- | --- |
| unpatched fleet-heavy, forced refusal | **yes** - 3304307 3304308 3304309, the same fork/grep/tr shape |
| patched fleet-heavy, same forced refusal | **no** - the instrument no longer fires |
| patched fleet-heavy, with a planted `setsid` holder (`sleep 40` holding the slot fd, own pgid) | **yes** - and the holder's group was gone afterwards, so the group kill worked |

The third row is the one that matters most: a fix that stopped the noise by also missing real leaks
would be worse than the noise, and this one still catches the leak it is for.

### Not in the reaper

The finding invites an age- or resource-based rule. It does not belong there for this contributor: these
processes live for well under a second, so no resource watchdog can or should see them, and a rule
scoped to catch them would be a rule that fires on innocent work.
