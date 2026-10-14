## `fleet-heavy-recycled-pid.patch` (agents-7vbo, agents-g966, agents-nyb1)

Delivery record for the P1 recycled-pid kills in `fleet-heavy`'s slot machinery. The artifact is
`patches/fleet-heavy-recycled-pid.patch`; this write-up is its record, and the patch is NEVER APPLIED HERE
- it belongs to the hub, which owns `~/fleet`.

## REVISION 3 — this revision VOIDS the earlier measurements as coverage (agents-nyb1)

**The coverage claims of Rounds 1 and 2 are VOIDED as evidence about this file.** Round 1 (agents-7vbo,
commit `655e3eae`) and Round 2 (agents-g966, commit `f6e7cf41`) measured and fixed exactly ONE signal
site - the JOB-END SWEEP at hub lines 200-203 - and their write-up read as if that site were the hazard.
The file has a SECOND signal site of the identical shape ONE FUNCTION OVER: `reclaim_abandoned_slot()`
(hub lines 117 and 120) still collected pids from `slot_fd_holders` and signalled them with a raw
`kill -TERM`/`kill -KILL`. The reviewer re-reported the race there as **agents-nyb1**. The earlier numbers
remain literally accurate about the sweep they measured, but they describe a revision whose SCOPE was
NARROWER THAN THE FILE, so any sentence that reads as coverage of "the recycled-pid kill in `fleet-heavy`"
is superseded by the per-site enumeration below. That enumeration is a **MAP, not a claim of coverage**:
S4 below is explicitly NOT covered.

## What the defect is

A pid is a reusable number. Every site that acts on a pid REMEMBERED from an earlier observation
(a `/proc` scan, or a written label) is making a claim about the past, and between the observation and the
signal the kernel may recycle the number onto an unrelated process. Two sites did exactly that:

    # JOB-END SWEEP (hub 200-203) - fixed in Round 2
    leaked=$(slot_fd_holders "$i" | grep -v "^$$\$" | tr '\n' ' ')
    if [ -n "${leaked// /}" ]; then
      echo "fleet-heavy: warning - descendants still held slot$i ... " >&2
      kill -TERM $leaked 2>/dev/null; sleep 1; kill -KILL $leaked 2>/dev/null
    fi

    # reclaim_abandoned_slot (hub 115-120) - THE CLASS, one function over - fixed in THIS revision
    # TERM the holders only: the fd lives in the PROCESS, so killing the holders releases the flock. ...
    kill -TERM $holders 2>/dev/null
    sleep 2
    local still; still=$(slot_fd_holders "$i")
    [ -n "$still" ] && { echo "fleet-heavy: slot$i holders ignored SIGTERM; sending SIGKILL" >&2; kill -KILL $still 2>/dev/null; sleep 1; }

Those pids come from the forks of the very pipeline that produced the list, so they are usually already
dead by the time the kill runs - which is exactly the window in which the kernel may recycle one. Killing
by a remembered pid is a claim about the past; the fix has to be a claim about the process in front of you.

## The enumeration: EVERY call site that signals a pid collected from a scan

The scan in this file is `slot_fd_holders()` (hub line 51): it enumerates `/proc/[0-9]*` and keeps a pid
whose open fd is the slot file. Line numbers are in `/home/exedev/fleet/fleet-heavy`, sha `33ecf140`.
"Probe" rows are `kill -0` (signal 0): they deliver nothing and are not signals.

| # | function (sha 33ecf140) | the signal | the pid comes from | class | measurement |
| --- | --- | --- | --- | --- | --- |
| S1 | `reclaim_abandoned_slot()` line 117 | `kill -TERM $holders` | scan `slot_fd_holders` (line 90) | **(c) → FIXED here** | code quoted above; RED repro §S1/S2 |
| S2 | `reclaim_abandoned_slot()` line 120 | `kill -KILL $still` | re-scan `slot_fd_holders` (line 119) | **(c) → FIXED here** | code quoted above; RED repro §S1/S2 |
| S3 | job-end leaked sweep line 203 | `kill -TERM $leaked` + `kill -KILL $leaked` | scan `slot_fd_holders` (line 200) | **(a)+(b)** since Round 2 | §S3 run + pidfd reuse run |
| S4 | preemption line 239 | `kill -TERM -"$pg"` | label pid `$hp` (line 226) → `ps -o pgid=` (line 237) | **(c) → RECORDED, NOT covered** | §S4 code + observation run |
| S5 | preemption line 244 | `kill -KILL -"$pg"` | same as S4 | **(c) → RECORDED, NOT covered** | same as S4 |
| P1 | `reclaim_abandoned_slot()` line 95 | `kill -0 "$hp"` (probe) | label pid | n/a (no delivery) | a false positive only REFUSES to reclaim |
| P2 | preemption line 228 | `kill -0 "$hp"` (probe) | label pid | n/a (no delivery) | gates the S4/S5 signal |
| P3 | preemption lines 242, 246 | `kill -0 -"$pg"` (probes) | pgid | n/a (no delivery) | gates the S5 escalation |

(a) = re-observes and captures identity in the SAME pass; (b) = binds via pidfd before signalling;
(c) = still has a check-to-signal window. Every classification carries the code quoted or a run below.

### S1 / S2 — `reclaim_abandoned_slot()` — FIXED in this revision

The reviewer's agents-nyb1 pattern, aimed at RECLAIM: `slot_fd_holders()` overridden to return a live
unrelated process, `ps()`/`sleep()` stubbed, `kill()` intercepted to print instead of signalling;
`FLEET_HEAVY_ORPHAN_GRACE=0`; `reclaim_abandoned_slot 1`. Against the CURRENT artifact (`old.functions.sh`,
extracted from the artifact patched at `fbe3aa34`):

    VICTIM 3602537
    fleet-heavy: reclaiming slot1 - held 100s with NO label (the holder died without releasing it): 3602537
    INTERCEPTED_SIGNAL -TERM 3602537
    fleet-heavy: slot1 holders ignored SIGTERM; sending SIGKILL
    INTERCEPTED_SIGNAL -KILL 3602537
    RETURN 0

Both signals land on the unrelated pid - RED. Against THIS revision (`new.functions.sh`):

    VICTIM 3602558
    fleet-heavy: reclaiming slot1 - held 100s with NO label (the holder died without releasing it): 3602558
    fleet-heavy: slot1: REFUSING pid 3602558 - it does not hold the slot now, so it is not the holder the scan saw (a stale or recycled pid)
    RETURN 0

No signal line: the candidate is refused because it does not hold the slot fd, which is the same-pass
identity capture. The reclaimed slot's TERM/KILL now go through `signal_leaked_holders`, the Round-2 helper,
so the reclaim path takes the pidfd branch (measured: with a `python3` probe first on `PATH`, the reclaim
control invokes it exactly once).

### S3 — the job-end sweep — already (a)+(b) since Round 2

Same pattern against `signal_leaked_holders` (`sweep.functions.sh`): the candidate is REFUSED and `RETURN 1`,
no `INTERCEPTED_SIGNAL`, victim alive. (Round 2's red baseline is the `INTERCEPTED_SIGNAL -TERM/-KILL` run
recorded in its own report.) The sweep is unchanged by THIS revision.

### S4 / S5 — preemption — RECORDED, NOT COVERED

    for w in "$dir"/slot*.who; do
      [ -f "$w" ] || continue; read -r hp hl _ < "$w"     # hub 226: a pid remembered from a label FILE
      case "$hl" in *-merger) continue;; esac
      [ -n "$hp" ] && kill -0 "$hp" 2>/dev/null || continue
      pg=$(ps -o pgid= -p "$hp" | tr -d ' ')              # hub 237: pgid derived from that number
      [ -n "$pg" ] || continue
      echo "fleet-heavy: preempting $hl (pid $hp, pgid $pg) for the merger" >&2
      touch "$dir/preempted.$pg"
      kill -TERM -"$pg" 2>/dev/null                       # hub 239: signal a GROUP derived from a number
      sleep 3
      if kill -0 -"$pg" 2>/dev/null; then kill -KILL -"$pg" 2>/dev/null; sleep 1; fi   # hub 242-244
    done

This is a different SOURCE and a different TARGET from S1-S3: the pid is the recorded job WRAPPER read out
of its own `.who` label (not a pid from the `/proc` scan), and the signal goes to that wrapper's process
GROUP because a detached or newly-spawned descendant would survive a per-pid kill (fleet-uhxq). It has the
same check-to-signal SHAPE: `$hp` is read, confirmed live with `kill -0`, its pgid derived with `ps`, and
the GROUP then signalled - a number recycled across any of those steps is signalled as that group. Observed
end-to-end on this VM (own-process-group job, so the group signal cannot reach the harness):

    slot label: 3630005 vm-impl 02:02:59 bash -c ...; sleep 300
    fleet-heavy: preempting vm-impl (pid 3630005, pgid 3630005) for the merger
    PREEMPT_WAITER
    (the job group received SIGTERM - marker written)

**NOT COVERED BY THIS PATCH.** The pidfd mechanism binds ONE process OBJECT and cannot address a process
group, and the group signal is the whole point of preemption; hardening it needs a group-aware keying
decision that is a different change from the class this finding names. It is named here with its
measurement rather than left implicit, per the "a map that says *not covered* is worth more" rule.
Mitigating, not closing, the window: it fires only from a PRIORITY (merger) ticket, and only after the
reclaim pass ran in the same poll and refused to touch a live wrapper.

## Two check-then-act windows, because a re-read alone cannot close either (agents-g966)

The first shape of this fix (agents-7vbo) re-read the pid's identity - process group, field 5, and start
time, field 22, of `/proc/<pid>/stat` - at the moment of use, and signalled only a pid whose re-read still
matched. Review agents-g966 showed that identity-by-re-read is still CHECK-THEN-ACT, with TWO windows:

  (a) SCAN-TO-CAPTURE: `slot_fd_holder_ids` collected the PID NUMBERS from `slot_fd_holders` FIRST and read
      `/proc/<pid>/stat` SEPARATELY AFTER. If the scanned process died and its pid was REUSED in between,
      the UNRELATED new process was recorded as the expected identity; the signal-time re-read then matched
      it and TERMed the innocent process. This is the reviewer's repro: `slot_fd_holders` overridden to
      return a live unrelated pid with `kill()` intercepted, which printed `INTERCEPTED_SIGNAL -TERM <pid>`
      and `-KILL <pid>` and falsely asserted a descendant held slot1.
  (b) CAPTURE-TO-SIGNAL: even a correctly captured identity is CHECKED, and then the kill lands; a pid that
      passed the check can still be recycled in that gap. Re-reading harder cannot close this window,
      because the read and the signal are different instants.

## The keying, and the five cases that decide it

The guard records `<pid>:<pgrp>:<starttime>` per holder at SCAN time - process group from field 5 and start
time from field 22 of `/proc/<pid>/stat`, the two fields this file already reads by number - and the pidfd
path validates that identity again at SIGNAL time, signalling only a match. Process group is corroboration,
start time is the identity, and FIVE cases, all measured, decide the keying:

1. A gate that leaked NOTHING still lists about three already-dead pids - the scan's own pipeline forks.
   They must be skipped, not signalled.
2. A plain genuine leak shares the WRAPPER'S process group.
3. A `setsid` genuine leak has its OWN process group.
4. The phantom shares OUR process group.
5. A pid RECYCLED between the observation and the identity capture - the agents-g966 window. Before this
   change the number was collected first and `/proc/<pid>/stat` read afterwards, so the new process's
   identity was recorded and TERMed. It must be REFUSED, and it is: a candidate is given an identity only
   while it still holds the slot fd, so a replacement (which does not hold the slot) is named and refused.

So a pgid-keyed reclaim would REFUSE case 3, which is a real leak, while ACCEPTING case 4, which is the
phantom - the inverse of what is wanted. Start time separates cases 1-4 for a single process, but it is
NOT enough for case 5 on its own: the identity in case 5 is captured from the WRONG process, so it matches
itself. The window is closed structurally (capture while the fd is in hand), not by a better field.

## The change

`slot_fd_holder_ids()` no longer reads `/proc/<pid>/stat` after a separate pid list. It re-observes the
slot fd for each candidate and reads pgrp/start time IN THE SAME PASS, for a pid that still has the slot
open; a candidate that does not hold the slot fd is REFUSED by name. `signal_leaked_holders()` then
delivers each signal through `pidfd_open()` + `pidfd_send_signal()`, a handle to the PROCESS OBJECT rather
than the number. **THIS REVISION extends that same mechanism to `reclaim_abandoned_slot()`**: its lines
117/120 raw kills are replaced by a single `signal_leaked_holders "$i"` call, so both the job-end sweep and
the reclaim path signal through one verified path. (`holders` is still read in reclaim to compute the GRACE
and to name the candidates in the log; it is no longer the list that is signalled.) When the primitive is
absent the helper exits 2 and a fallback re-checked `kill` runs instead (see below).

## The pidfd path, measured rather than assumed

On this host: python3 3.12.3 has `os.pidfd_open` and `signal.pidfd_send_signal` (both present; checked).
The guarantee that makes the claim literal was measured directly: inside a private PID namespace
(`unshare -Urpf --mount-proc`), a pid was FORCED to be reused (`/proc/sys/kernel/ns_last_pid`) while a
stale pidfd for the dead original was still held; `pidfd_send_signal` answered ESRCH for signal 0, SIGTERM
and SIGKILL, and the RECYCLED process stayed alive.

## The claim, stated per path so it cannot outrun its guarantee

    pidfd path (the path taken when the primitive is present - and it is present here, measured):
      Once a pidfd is held, a recycled pid CANNOT be signalled: pidfd_send_signal() is delivered to the
      bound process object and answers ESRCH for one that has exited, so it never reaches the number's new
      owner. Applied to S1, S2 (reclaim) and S3 (sweep): the site signals only a process that held the
      slot fd when captured, still holds it when the pidfd is validated, and is the object the pidfd names.

    bash fallback path (only when python3 or the primitive is absent):
      Window (a) is closed (identity is captured in the same pass), but window (b) REMAINS OPEN: the
      fallback re-reads the identity immediately before EACH `kill`, and between that check and the kill
      the pid can still be recycled, so the kill would then hit the replacement. Under the fallback the
      artifact gives a NARROWER guarantee than under pidfd.

    S4 / S5 (preemption): NO pidfd, NO same-pass capture. The window from reading the label pid `$hp` to
      signalling its group `-$pg` remains fully open (see §S4/S5). This revision does NOT make S4/S5 safe
      and does not claim to.

## The fallback, if the primitive is absent

If `python3` or the pidfd primitive is missing, the helper exits 2 and a bash fallback re-reads the identity
IMMEDIATELY before EACH signal, killing only a match. That fallback NARROWS but does NOT close window (b):
between its check and its `kill` the pid can still be recycled and the kill would then hit the replacement.
It also re-opens window (a) to the extent that its identity came from the same-pass capture but its signal
is number-based. The pidfd path above is the one that runs when the primitive is available, and it is
available on this host.

## Evidence

Both repro halves were run against copies of the hub file (base sha `33ecf140`, re-verified unchanged after
all work; `patch -p1` applies the artifact and `bash -n` passes). Every command was bounded by `timeout`;
every process used was spawned by the harness and reaped in its trap.

- **S1/S2 (reclaim) red-first:** against the current artifact, `INTERCEPTED_SIGNAL -TERM <pid>` and
  `-KILL <pid>`; against this revision, `fleet-heavy: slot1: REFUSING pid <pid> - it does not hold the slot
  now ...`, `RETURN 0`, no signal line.
- **S3 (sweep):** `REFUSING ...`, `RETURN 1`, no signal line, victim alive.
- **pidfd path taken in reclaim:** with a `python3` probe first on `PATH`, the reclaim control invokes it
  exactly once (`PYTHON3_INVOKED pidfd-path`).
- **pidfd reuse:** stale pidfd answered ESRCH to signal 0/SIGTERM/SIGKILL; the recycled process stayed alive.
- **Control (job-end sweep, unchanged):** same-group and `setsid` genuine leaks TERMed and the slot freed;
  a clean job claims no kill - `CONTROL PASS`.
- **Control (reclaim path, genuine orphan):** a job wrapper is SIGKILLed leaving an orphan holding the fd;
  the waiter prints `reclaiming slot1 - holder <pid> is GONE but 2 process(es) have held it 2s`, the orphan
  is TERMed, and the slot is freed - `RECLAIM CONTROL PASS`.

## What it does not cover

- **S4/S5, preemption (hub 239/244)** - named above with its measurement and its open window; NOT fixed
  here, because it signals a process GROUP and the pidfd mechanism binds a single object.
- The pidfd path adds a python3 dependency to `fleet-heavy`; python3 3.12.3 with both primitives is present
  here (measured), and the fallback keeps window (b) when it is not.
- It does not make `bin/fleet-heavy` current: that file has no sweep at all (separate face `agents-j5a4`),
  and promoting the deployed copy as it stands carries the reclaim hazard into the reclaim path.
- `slot_fd_holders` (the candidate scan) is unchanged; the sweep does not newly widen the notion of holder.
