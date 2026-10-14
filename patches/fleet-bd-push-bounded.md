## patches/fleet-bd-push-bounded.patch

SUPERSEDES 25426cc5, the close-the-fd (`flock -o`) cut of this same artifact, and the write-up it shipped with.
That cut bounded the holder and released the lock by *giving the fd up*, which is mutually exclusive with the
property this fleet needs more: the lock must stay with the WORK. `-o` was load-bearing for the bound and
incompatible with keeping the lock with the work, so the protocol changes from "close the fd" to "own the
group". 25426cc5 is preserved under `fleet/impl-eea2-etvw-prerewrite` so the previously reviewed object is
still recoverable and the change of design is visible rather than silent. The recut also carries the fix for
agents-5nho, which the reviewer found against 25426cc5: the bound was armed only for calls whose subcommand sat
in argv[1], so `bd -C <dir> dolt push` bypassed it entirely.

### The incident this answers (agents-etvw)

Measured on 2026-10-14: ONE `bd dolt push` whose `git push --force-with-lease` was stuck in
`git send-pack --stateless-rpc` held `$HOME/.fleet/bd.lock` - the lock every lane on this VM serialises on -
for about 16 minutes, with 8 waiters queued behind it. `flock -w 300` bounds how long a WAITER waits and says
nothing about how long a HOLDER holds, and the holder is a network operation. The symptom that made it
expensive was not the waiting but the silence: bead writes, labels and verdicts were reported as done while
the write had not landed.

### What changes, and where

- `bin/bd` gains a bounded network path. `bd_reaches_network` decides whether the call is `dolt push|pull|fetch`
  or `sync`; only those are bounded, so local subcommands are untouched (row 5 below).
- THE DECISION THAT ARMS THE BOUND IS NOT POSITIONAL (agents-5nho). It used to read $1, so
  `bd -C <dir> dolt push` and `bd --no-color dolt push` were classified as LOCAL calls: no bound was armed and
  the unbounded hold this patch exists to close was reachable through a flag (row 6). The subcommand is now
  found AFTER SKIPPING LEADING GLOBALS, and the network shape is ALSO SCANNED FOR ANYWHERE in argv - two
  layers, because which flags consume a value is knowledge that can only ever name the flags that already
  exist. That lesson is already recorded in this file: fleet-4vve's deny-list fell to
  `bd --no-color close <foreign>` for exactly this reason, and the reviewer's guard stopped trying to answer it.
- The payload runs in its OWN PROCESS GROUP (`setsid -w`, so its exit status still reaches us). NO `-o` is
  passed anywhere: the lock fd stays inherited by the payload, so the lock lives with the work and killing the
  HOLDER cannot let two bd runs touch the same Dolt DB.
- The bound kills THAT GROUP: `kill -TERM 0` then, after `FLEET_BD_PUSH_GRACE`, `kill -KILL 0` (`kill ... 0`
  signals the current process group, so no pgid arithmetic is needed). The `TERM` trap is what allows the grace
  phase to happen at all - without it the leader dies on the first signal and leaves anything that ignores
  TERM still holding the lock fd.
- NOTHING ELSE IS SIGNALLED. The group is the payload's own, so a neighbouring lane's processes and a second
  payload outside this group are untouched (row 3).
- On the bound the command exits 124 and prints, loudly, that THE WRITE DID NOT LAND, that the lock is
  released, and the operational rule BACK OFF AND RETRY, KILL NOTHING (row 1).

### The evidence, one row per property, all driven on the same fixture

(1) BOUND, at the incident's own shape - a REAL `git push` into a remote whose receive-pack never answers,
    through the installed shim: holder rc=124 after 2.2s (bound 1s + grace 1s), the next lane rc=0 and wrote
    freely, the report said the write did not land, and the lock was free when the command returned. The
    deployed shim on the same fixture: second lane rc=124, BLOCKED behind the holder, nothing said.
(2) MUTUAL EXCLUSION (agents-ttxh): with the holder SIGKILLed while the payload was still working, a second bd
    is BLOCKED (rc 124) - the work holds the fd. The holder is found by PROCESS NAME plus this fixture's own
    lock path, and the test asserts it was found AND died, because a kill that never lands reads exactly like
    exclusive access.
(3) NEIGHBOURS SURVIVE, which is what this design owes because it kills things: after the bound fired, a
    process from another lane and a second payload outside the group were both ALIVE.
(4) THE ORDINARY PATH: a fast push still succeeds (rc 0), prints nothing, and the lock is FREE as it returns.
    This row is a defect I found in my own drive of it and fixed here: the watchdog is a subshell, killing a
    subshell does not kill its `sleep`, and that `sleep` inherits the lock fd - measured, a successful push left
    `sleep 30` holding the VM-wide lock for the rest of the bound. Only a signal to the GROUP reaches it, which
    is why the same group signal is used on normal completion too.
(5) CLASSIFICATION: the exit code is normalised to 124 when the bound fired, from whichever signal surfaced
    (137/143 included), so the report does not depend on how the group died. A SUCCESSFUL command is never
    reclassified. 124 keeps its fleet meaning: the bound killed it, so this is unknown and NOT a pass.
(6) THE DETECTION (agents-5nho), on the reviewer's own repro, before and after. Before: with a hanging stub,
    `dolt push` was bounded at 2.0s, while `-C /dir dolt push`, `--no-color dolt push`,
    `--directory=/dir dolt push` and `-C /dir sync` each ran the FULL hang, held the VM-wide lock and said
    nothing. After: every one of those forms is bounded at rc=124 with the report. The negative control is that
    a NON-network subcommand with the same leading flags stays unbounded ON PURPOSE, and it is proved with a
    local call that HANGS FOR 3s and is not cut at a 1s bound - the row that would catch a fix shaped as "bound
    everything that carries a flag". The mutant is the PRE-FIX decision with both layers undone, so these rows
    are red-first rather than merely green.

### The vacuity, stated as a test rather than as an aside

An earlier drive of this change reported that the lock was still held after the holder was killed. It was
vacuous: the pgrep pattern had matched the caller's own wrapper and the kill never landed. The check that the
holder was FOUND and DID DIE is therefore part of the test (row 7b), not a convenience - it is what makes the
mutual-exclusion assertion mean anything, and the neighbouring assertion that a wrong target finds NOTHING
(row 7a) is there so the check cannot pass by finding any old process. Every mutant in the suite is built the
way `bd-guard.test.sh` builds them, and the two that matter here are red-first: removing the bound reproduces
the wedge and the silence; adding `-o` back reproduces agents-ttxh (two bd runs concurrently).

### The same mechanism class, and the second instance that is NOT fixed here

A tool whose RESULT depends on an ARGUMENT POSITION is the family this fleet keeps meeting; a grep run from the
wrong checkout is the same shape one level out. It was already fixed once in THIS FILE, for a deny-list that
`bd --no-color close <foreign>` walked straight through. `bd_reaches_network` repeated it, and the bound patch
would have shipped a bound that a leading flag could switch off.

A SECOND INSTANCE OF THE SAME SHAPE IS IN THIS FILE AND IS DELIBERATELY NOT FIXED HERE: `check_push_failure`
reads $2/$3 positionally, so `bd -C <dir> dolt push` loses its int-mirror hint (measured: hint YES for
`dolt push`, NO for `-C /dir dolt push`). It is pre-existing (3 occurrences in the preimage), it loses a
diagnostic rather than wedging the VM, and folding a missing hint into the change a reviewer must read for the
lock protocol would blur what is being verified. It is filed as agents-aryx, with the fix shape named.

### Hashes, by algorithm and value

ADVISORY for anything read from this VM's `~/fleet`: this mirror is a snapshot and has no reachable canon
(agents-x8ud). The patch itself is 342 lines over 2 files, sha256
6924ec739cc1ce78e40606c06a0ddc49280e2ebfaaec6a544c1dfb15d24ed132. `bin/bd` base blob 723856f, post-apply
9f58a2f; sha256 base f0e2f7c79b51819bed188af45ea8aa207cbe4843b6008591faf82fbd7c8c2478 (14480 B), post-apply
3ae241c0b4d477b2c4a7309591f4c6211876bf845dd0da25cffb69200f008ed1 (25095 B). `tests/bd-shim.test.sh` base blob
da473cd, post-apply 258b039; sha256 base 0612e2a811436e5d4af88f02f7ba176a2dedfedae039ef292434c8625d352520
(5181 B), post-apply 869c84eae871c6ff14e04fbecf1085bab8a89da87fb0149a28eabc29b3e49019 (16323 B). The agent's
own measured disagreement about this file's preimage is still open with the hub: agents-x8ud records blob
8b1e345 where this VM measures 723856f, and the hunks here are anchored on the `FLEET_BD_LOCKED` dispatch line
so a re-cut against canon is mechanical.

### The operational rule, and what this does NOT claim

BACK OFF AND RETRY, KILL NOTHING is printed with the failure rather than only recorded in
`roles/lessons.md`, because that file sits 18 bytes below its own test ceiling (measured) and a rule that
lives only in a doc is not there when an operator meets the failure.

This does not claim the lock can be removed from the network operation. `bd dolt push` commits to the local
embedded Dolt DB before pushing, and that DB is why the lock exists (fleet-tm5, fleet-e10); the hold is
BOUNDED rather than eliminated. Removing it is a future design with no safety claim made here. What this
changes is only that a stalled remote can no longer hold the lock past the bound, that the release it
announces is true by construction, and that killing a holder no longer breaks mutual exclusion.
