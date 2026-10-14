## `fleet-heavy-recycled-pid.patch` (agents-7vbo)

Delivery record for the P1 recycled-pid kill in `fleet-heavy`'s slot sweep. The artifact is `patches/fleet-heavy-recycled-pid.patch`; this write-up is its record, and the patch is NEVER APPLIED HERE - it belongs to the hub, which owns `~/fleet`.

## What the defect is

In the slot sweep, after a job finishes, the leaked-slot branch collects the pids still holding the slot and signals them:

    leaked=$(slot_fd_holders "$i" | grep -v "^$$\$" | tr '\n' ' ')
    if [ -n "${leaked// /}" ]; then
      echo "fleet-heavy: warning - descendants still held slot$i ... " >&2
      kill -TERM $leaked 2>/dev/null; sleep 1; kill -KILL $leaked 2>/dev/null
    fi

Those pids come from the forks of the very pipeline that produced the list, so they are usually already dead by the time the kill runs - which is exactly the window in which the kernel may recycle one. Killing by a remembered pid is a claim about the past; the fix has to be a claim about the process in front of you.

## Which file, because the bead's line reference named the wrong one

    /home/exedev/fleet/bin/fleet-heavy   154 lines  sha 0f95ccd3  'leaked=' occurrences: 0  (NO sweep)
    /home/exedev/fleet/fleet-heavy       252 lines  sha 33ecf140  'leaked=' occurrences: 1  (THE hazard, at 200-203)

Two generations of one tool with confusingly similar names; this cost a round in review. The patch applies to the second file and is a unified diff against `33ecf140`.

## The keying, and the four cases that decide it

The guard records `<pid>:<pgrp>:<starttime>` per holder at SCAN time - process group from field 5 and start time from field 22 of `/proc/<pid>/stat`, the two fields this file already reads by number - and re-reads them at SIGNAL time, signalling only a match. A holder whose stat cannot be read is emitted with EMPTY fields, so the sweep NAMES and REFUSES it rather than silently forgetting it.

Start time is the key, with pgrp as corroboration, and PROCESS GROUP ALONE IS INVERTED FOR THIS PROBLEM. Four cases, all measured:

1. A gate that leaked NOTHING still lists about three already-dead pids - the scan's own pipeline forks. They must be skipped, not signalled.
2. A plain genuine leak shares the WRAPPER'S process group.
3. A `setsid` genuine leak has its OWN process group.
4. The phantom shares OUR process group.

So a pgid-keyed reclaim would REFUSE case 3, which is a real leak, while ACCEPTING case 4, which is the phantom - the inverse of what is wanted. Start time separates all four: a recycled pid has a different start time and cannot pass, and a dead pid has no `/proc` entry at all.

## Evidence

Verified by the implementer of this artifact: the fixture pair - a dead pid is named "gone, not signalling it", and a live unrelated pid that the before-code TERMed is now REFUSED by name and stays alive - and the CONTROL, that a genuine leaked descendant (same-group AND `setsid`) is still TERMed and the slot released. Delivered with a new test, `fleet-heavy-sweep-identity.test.sh`, a `before_after.sh` harness and a `measure.sh`.

Verified independently by the author of this write-up: the two-file measurement above, and the patch's keying quoted from the diff (field 22 as the key, field 5 as corroboration, empty fields on unreadable stat).

## What it does not cover

It does not make `bin/fleet-heavy` current: that file has no sweep at all, which is the separate face filed as `agents-j5a4`. Patching this copy while the deployed one stays stale leaves the VM on old behaviour, and promoting the deployed copy as it stands carries this hazard into the reclaim path - the two faces need ONE keying decision, which is why the four cases above are stated for both.
