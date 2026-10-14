## `fleet-heavy-recycled-pid.patch` (agents-7vbo, agents-g966)

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

## Two check-then-act windows, because a re-read alone cannot close either (agents-g966)

The first shape of this fix (agents-7vbo) re-read the pid's identity - process group, field 5, and start time, field 22, of `/proc/<pid>/stat` - at the moment of use, and signalled only a pid whose re-read still matched. Review agents-g966 showed that identity-by-re-read is still CHECK-THEN-ACT, with TWO windows:

  (a) SCAN-TO-CAPTURE: `slot_fd_holder_ids` collected the PID NUMBERS from `slot_fd_holders` FIRST and read `/proc/<pid>/stat` SEPARATELY AFTER. If the scanned process died and its pid was REUSED in between, the UNRELATED new process was recorded as the expected identity; the signal-time re-read then matched it and TERMed the innocent process. This is the reviewer's repro: `slot_fd_holders` overridden to return a live unrelated pid with `kill()` intercepted, which printed `INTERCEPTED_SIGNAL -TERM <pid>` and `-KILL <pid>` and falsely asserted a descendant held slot1.
  (b) CAPTURE-TO-SIGNAL: even a correctly captured identity is CHECKED, and then the kill lands; a pid that passed the check can still be recycled in that gap. Re-reading harder cannot close this window, because the read and the signal are different instants.

## The keying, and the five cases that decide it

The guard records `<pid>:<pgrp>:<starttime>` per holder at SCAN time - process group from field 5 and start time from field 22 of `/proc/<pid>/stat`, the two fields this file already reads by number - and the pidfd path validates that identity again at SIGNAL time, signalling only a match. Process group is corroboration, start time is the identity, and FIVE cases, all measured, decide the keying:

1. A gate that leaked NOTHING still lists about three already-dead pids - the scan's own pipeline forks. They must be skipped, not signalled.
2. A plain genuine leak shares the WRAPPER'S process group.
3. A `setsid` genuine leak has its OWN process group.
4. The phantom shares OUR process group.
5. A pid RECYCLED between the observation and the identity capture - the agents-g966 window. Before this change the number was collected first and `/proc/<pid>/stat` read afterwards, so the new process's identity was recorded and TERMed. It must be REFUSED, and it is: a candidate is given an identity only while it still holds the slot fd, so a replacement (which does not hold the slot) is named and refused.

So a pgid-keyed reclaim would REFUSE case 3, which is a real leak, while ACCEPTING case 4, which is the phantom - the inverse of what is wanted. Start time separates cases 1-4 for a single process, but it is NOT enough for case 5 on its own: the identity in case 5 is captured from the WRONG process, so it matches itself. The window is closed structurally (capture while the fd is in hand), not by a better field.

## The change

`slot_fd_holder_ids()` no longer reads `/proc/<pid>/stat` after a separate pid list. It re-observes the slot fd for each candidate and reads pgrp/start time IN THE SAME PASS, for a pid that still has the slot open; a candidate that does not hold the slot fd is REFUSED by name. `signal_leaked_holders()` then delivers each signal through `pidfd_open()` + `pidfd_send_signal()`, a handle to the PROCESS OBJECT rather than the number. Binding, validation (start time AND fd ownership on the bound object) and signalling happen in one helper pass, so the check and the signal cannot be separated by a recycle. When the primitive is absent the helper exits 2 and a fallback re-checked `kill` runs instead (see below).

## The pidfd path, measured rather than assumed

On this host: python3 3.12.3 has `os.pidfd_open` and `signal.pidfd_send_signal` (both present; checked). A pidfd whose process has exited answers ESRCH to signal 0, to SIGTERM and to SIGKILL (measured). The guarantee that makes the claim literal was measured directly: a pid was FORCED to be reused (`/proc/sys/kernel/ns_last_pid` inside a private PID namespace, via `unshare -pf --mount-proc`), and while a stale pidfd for the dead original was still held, `pidfd_send_signal` answered ESRCH for signal 0, SIGTERM and SIGKILL and the RECYCLED process stayed alive. The path taken is the pidfd one.

## The claim, stated so it can be checked for overstatement

    Once a pidfd is held, a recycled pid cannot be signalled: pidfd_send_signal() is delivered
    to the bound process object and answers ESRCH for one that has exited, so it never reaches
    the number's new owner. The sweep therefore signals only a process that held the slot fd
    when captured, still holds it when the pidfd is validated, and is the object the pidfd
    names. A pid that no longer names the process the sweep found is refused and named, not
    signalled.

## The fallback, if the primitive is absent

If `python3` or the pidfd primitive is missing, the helper exits 2 and a bash fallback re-reads the identity IMMEDIATELY before EACH signal, killing only a match. That fallback NARROWS but does NOT close window (b): between its check and its `kill` the pid can still be recycled and the kill would then hit the replacement. It also re-opens window (a) to the extent that its identity came from the same-pass capture but its signal is number-based. The pidfd path above is the one that runs when the primitive is available, and it is available on this host.

## Evidence

Both halves were run against the patched copy (`base` sha `33ecf140`, re-verified unchanged after applying the patch; `patch(1)` applies it and `bash -n` passes):

- Reviewer repro (agents-g966), red-first: against the agents-7vbo artifact it printed `INTERCEPTED_SIGNAL -TERM <pid>` and `-KILL <pid>`; against this artifact it prints `fleet-heavy: slot1: REFUSING pid <pid> - it does not hold the slot now ...`, returns 1, and the unrelated pid is never signalled.
- Control: a genuine leaked descendant, SAME group and `setsid`, is still TERMed and the slot is released; a clean job claims no kill and leaves the slot free.

The verification harnesses live beside the delivery record in `/tmp` (they are not part of this repository): a red-first reproduction of the reviewer's case and a control runner. Verified independently by the author of this write-up: the two-file measurement above, and the pidfd reuse measurement quoted here.

## What it does not cover

It does not make `bin/fleet-heavy` current: that file has no sweep at all, which is the separate face filed as `agents-j5a4`. Patching this copy while the deployed one stays stale leaves the VM on old behaviour, and promoting the deployed copy as it stands carries this hazard into the reclaim path - the two faces need ONE keying decision, which is why the five cases above are stated for both. The pidfd path also assumes a Linux kernel that implements `pidfd_open`/`pidfd_send_signal` and a python3 that exposes them; the fallback covers their absence but, as stated, keeps window (b).

## The fallback is load-bearing, not decorative

The pidfd path is feature-detected, so the bash fallback is not a curiosity kept for completeness: **it is the path that runs whenever `python3` is absent, or the pidfd primitive is unavailable, in the hub's environment** - and `python3` now sits on the hot leak path, which is a cost the hub is being asked to weigh against the window it closes. If the hub judges that spawn too expensive for a slot-recovery path, the fallback is what executes, unchanged and for real. It re-reads the identity immediately before EACH signal, which closes the observe-to-capture window (a) but **leaves the check-to-signal window (b) open**, because a pid that passes the start-time check can still be recycled before the kill lands. That residual window is STATED here rather than hidden: under the fallback the artifact gives a narrower guarantee than under pidfd, and anyone reading its output should read the path taken rather than the headline claim. Closing (b) without pidfd is not possible with check-then-act signalling, which is the reason the pidfd route is the primary one rather than a refinement.
