## `fleet-bd-push-bounded.patch` (agents-etvw)

- **Target repository:** `PaulKinlan/fleet`
- **Target files (two):** `bin/bd` — the shim **every** bd call on a fleet VM reaches through, and the only place
  the VM-wide lock is taken — and `tests/bd-shim.test.sh`, which already owns this file's lock and nesting
  behaviour (section 5).
- **Patch artifact hash:** `0b7531c958f12965c320b3e232578a8383d5c0c435d79e3800249fd1f9166f40` (157 lines,
  2 files, +126/−2).
- **No other patch in flight touches `bin/bd`** (checked against `patches/*.patch`), and **no other file on the VM
  references `bd.lock`** (checked across `remote/`, `bin/`, `tests/`, `dashboard/`, `roles/`), so the two changes
  below cannot collide with, or silently change the expectations of, another consumer.

### THE BASE THIS IS A CLAIM ABOUT

| file | algorithm | value | apparatus |
|---|---|---|---|
| `bin/bd` (preimage) | sha256 | `f0e2f7c79b51819bed188af45ea8aa207cbe4843b6008591faf82fbd7c8c2478` (14,480 B) | ADVISORY |
| `bin/bd` (preimage) | git blob | `723856f` | ADVISORY |
| `tests/bd-shim.test.sh` (preimage) | sha256 | `0612e2a811436e5d4af88f02f7ba176a2dedfedae039ef292434c8625d352520` (5,181 B) | ADVISORY |
| `bin/bd` (this patch applied) | sha256 | `6e97fc95094e996201e7b3ca44f044cc9866a91917b3bdf3641d3b8e056bc942` (18,968 B) | result |
| `bin/bd` (this patch applied) | git blob | `673fb39` | result |
| `tests/bd-shim.test.sh` (this patch applied) | sha256 | `087fc509a968a3453653173dd99310708d5fb1b459ca83912bb431bc1886bdc8` (9,160 B) | result |

**ADVISORY, AND HERE THAT WORD IS DOING REAL WORK.** `~/fleet` on this VM is a non-git copy and no fleet canon is
reachable from it (agents-x8ud). Worse, for `bin/bd` specifically there is a **disagreement in the record**:
agents-x8ud states this VM's `bin/bd` is `8b1e345`, while the preimage measured here hashes to `723856f` as a git
blob and `f0e2f7c7…` as sha256. The mirror is byte-identical to the copy this patch was cut against (re-checked
at hand-off) and its mtime is **2026-10-12 21:11** — the same date x8ud gives for the stale copy — so **the mirror
has not moved since x8ud measured it and the disagreement is about the instrument or the subject, not about
staleness.** I cannot settle that from here, so I am not asserting either value is canon. **The hub must
re-preimage `bin/bd` from its own canon before applying.** The hunks are therefore anchored at named, stable
places rather than at line numbers: the new block sits immediately above the `if [ -n "${FLEET_BD_LOCKED:-}" ]`
dispatch, and the dispatch itself is rewritten in place. If canon has moved, the re-cut is mechanical.

### Problem Statement

`bin/bd` serialises every bd call on the VM on one lock, because the embedded Dolt DB allows one process at a
time and concurrent lanes otherwise fail ambiguously with "database is locked" (fleet-tm5/e10).
**The code that decides it — cited by line, because a description of it is how three corrections happened
tonight.** In the preimage, `bin/bd:257` is the line that holds the lock, with the nested-dispatch guard above it
at `bin/bd:249` and the unknown-remote advice at `bin/bd:36`:

    flock -w 300 "$HOME/.fleet/bd.lock" "$real" "$@"          # bin/bd:257 (preimage)

In this patch the same dispatch is `bin/bd:305`–`bin/bd:325`, with the policy at `bin/bd:280`–`bin/bd:281`, the
network predicate at `bin/bd:283`, the timeout classifier at `bin/bd:291`, the report at `bin/bd:293`, the bounded
path at `bin/bd:316`, the loud exit at `bin/bd:318`, and the unbounded local path at `bin/bd:323`.

**`-w 300` bounds how long a WAITER waits. Nothing bounds how long a HOLDER holds** — and the holder is whatever
the caller asked bd to do, which can be a network operation. On 2026-10-14 that is exactly what happened: **one
`bd dolt push` whose `git push --force-with-lease` was stuck in `send-pack` held the VM-wide lock for about 16
minutes.** Every other lane's bd call queued behind it, so bead comments, labels, verdicts and clearances were
delayed or lost; the merger's bounded command hit its 900s ceiling **with its bead writes silently unrun**; and
coord saw two writes return nothing and one `rc 124` after 240 s.

**This is worse than a slow command, and that is the whole point of the bead.** bd is the fleet's ONLY ledger, so
while that lock is held *every* lane's record-keeping stops — and **a lost write looks exactly like a write that
succeeded until somebody reads it back.** Measured, in the same window, on this lane: `bd update agents-aaxx
--claim` printed `✓ Updated issue`, and the read-back immediately afterwards still showed
`Lease: expires expired (heartbeat 30 mins ago)`. That is the silent non-write, on the record.

First-hand evidence from this lane (not a retelling of the bead): the holder was `flock -w 300
~/.fleet/bd.lock /home/exedev/.local/bin/bd dolt push` (pid 2877938, `FLEET_LANE=impl-guard`) with `git push >
send-pack` (pid 2892919) below it; **8 further processes were queued on the same lock**; two of my own git
operations hit their own ceilings *because the git hooks queue behind the same lock*; and one of my commits was
left half-done holding a worktree index lock after its bounded wrapper was killed.

### Why bounding the payload is NOT enough on its own (measured, not argued)

GNU `flock`'s payload **inherits the lock's file descriptor**. So when the middle process is killed, the thing that
was actually stuck — here the `git` grandchild — can still be holding the lock. That is precisely what `-o` exists
for, and it is why the fix has two halves rather than one. Driven on this VM with a payload that detaches a child
and exits immediately:

| | after the payload exits |
|---|---|
| `flock -w 5 <lock> bash -c 'setsid sleep 25 & exit 0'` | **lock STILL HELD** (the descendant inherited the fd) |
| `flock -o -w 5 <lock> bash -c 'setsid sleep 25 & exit 0'` | **lock FREE** |

A fix that only added a timeout would have left a VM-wide lock held by an orphaned `git` process, with the
timeout's own message claiming the lock had been released.

### What it changes

1. **The holder is bounded — for the subcommands that can actually block on a remote.** `dolt push`, `dolt pull`,
   `dolt fetch` and `sync` now run as `timeout -k <grace> <bound> "$real" "$@"` under the lock
   (`FLEET_BD_PUSH_TIMEOUT`, default **180 s**; `FLEET_BD_PUSH_GRACE`, default **15 s**). **A purely local write
   keeps its unbounded path**: a local write cannot stall on a remote, and putting a bound on it would invent a
   new way for a legitimate write to fail. The nested path (`FLEET_BD_LOCKED`, bd → git hook → bd) takes no lock,
   so there is no hold there to bound.
2. **The lock fd is closed for the payload on both paths (`flock -o`)**, so only the `flock` process holds it and
   **no descendant can extend the hold past the bound.** Sections 5a (two concurrent calls still serialise, no
   interleaving) and 5b (the nesting escape still reaches bd) pin that this did not change what the lock is for.
3. **On timeout it fails LOUDLY, and the exit code is left alone.** The report says the command was killed, that
   **THE WRITE DID NOT LAND**, that the VM-wide lock is now released, and that **BACK OFF AND RETRY, KILL NOTHING**
   — never kill another lane's push, because a retry after the remote unblocks costs seconds while an orphaned
   lock holder costs every lane on the VM minutes. Codes 124/137/143 are kept rather than mapped, so the fleet's
   existing rule applies unchanged: *the bound killed it — unknown, not a pass*. The remote-advice path is skipped
   on a timeout, because advice about the remote is not the diagnosis when the remote is merely slow.
4. **Ask (3) — "whether the lock needs to be held across the network operation at all" — is answered, not
   implemented.** `bd dolt push` commits to the local embedded Dolt DB before it pushes, and that DB is why the
   lock exists; taking a push off the lock would reintroduce the concurrent-write failures the shim was built to
   prevent (fleet-tm5/e10). So the hold is **bounded rather than removed**, and the option (separate local commit
   from remote push) is left as a future design if the bound ever proves too coarse. I did not measure that
   alternative, and I am not claiming it is unsafe or safe — only that it is not this change.
5. **Ask (4) — recording the operational rule — landed with a measured obstacle.** `roles/lessons.md` is
   **184,302 bytes against its own 184,320-byte ceiling in `tests/lessons.test.sh`: 18 bytes of headroom.** Adding
   a 70-byte section took it to 184,372 and the suite to **2 failures** (measured). A new lesson therefore needs a
   compress pass first, and it would be wrong to widen that ceiling to fit this change. The rule is instead
   **printed by the failure itself**, which is where an operator meets it, and it is in this write-up — so it is
   recorded in the repo without breaking a guard.
6. **An observation this change does NOT explain, routed rather than left dangling:** the silent `--claim`
   non-write above was *not* accompanied by any timeout — bd printed success, and the stale field was the
   **lease**. That is the same class as the mechanism coord records on **agents-y9va**: `bd comment` and
   `--add-label` do not bump `updated_at`, so a correctly parked bead is indistinguishable from a stalled one,
   and a sweep cannot tell a held bead from an abandoned one. Both are "a write path whose record does not
   reflect the write", both cost a lane a wrong decision, and **y9va owns the fix** — this patch does not claim
   it. The rule it earned is the one now in force: one write, one read-back, and if the read-back disagrees, say
   so in the message and keep working rather than retrying in a loop.

### Verification

**The instrument is the repo's own suite plus a driven fixture**, both shims, same fixture, so the only variable is
the bound. `tests/bd-shim.test.sh` was already the file that owns this shim's lock behaviour, and it is extended
rather than replaced.

| fixture (stub `dolt push` hangs, a second lane then asks for the lock) | observed |
|---|---|
| **deployed shim** | holder runs its full 30 s; nothing is reported; the second lane waits behind it |
| **this patch, bound 2 s** | push exits **124 after 2.0 s**, prints *"THE WRITE DID NOT LAND"*, and the second lane's local write succeeds **immediately (0.0 s)** |
| **this patch, fd face**: payload detaches a child and exits | lock **FREE** |
| **deployed shim, fd face** | lock **STILL HELD** by the detached child |

**And the same thing again with the incident's OWN shape rather than a stub** — a real `git push` stalled in a
remote whose `receive-pack` never answers (`git config remote.origin.receivepack <script that sleeps>`), with the
shim wrapping `git -C <src> push origin HEAD` as its payload. The process chain captured while the holder was
stuck is the incident's chain, end to end:

    timeout 8 bash pristine/bd.shim dolt push                              # the call
    bash pristine/bd.shim dolt push                                        # the shim
    flock -w 300 .../home/.fleet/bd.lock .../home/.local/bin/bd dolt push  # the VM-wide lock, HELD
    bash .../home/.local/bin/bd dolt push                                  # the payload (a real git push)
    /bin/sh -c .../hang.sh '.../remote.git'                                # the remote, which never answers

(`git send-pack --stateless-rpc` appears here in the same shape it appears in the incident's own `ps`: the real
holder tonight was `git send-pack --stateless-rpc --helper-status --thin --no-progress
--force-with-lease=...`, pid 2892919, under `bd dolt push`, pid 2878690.)

| the real-remote fixture | holder | second lane **while the holder is stuck** | said "did not land" | lock after |
|---|---|---|---|---|
| **deployed shim** | rc 124 (only because my outer bound killed it) | **rc 124 — BLOCKED behind the holder** | no | FREE |
| **this patch, bound 1 s** | **rc 124 after 1.2 s** | **rc 0 — wrote freely** | **yes** | FREE |

The artifact's report, verbatim, is the whole answer to asks (1) and (2):

    bd: TIMED OUT (fleet-etvw): `bd dolt push` did not finish within 1s and was killed (rc=124).
    bd: THE WRITE DID NOT LAND. A local Dolt commit may exist; the REMOTE push definitely did not.
    bd: The VM-wide lock is RELEASED - every other lane on this machine can write again.
    bd: BACK OFF AND RETRY, KILL NOTHING. Never kill another lane's push: a retry after the remote
    bd: unblocks costs seconds, while an orphaned lock holder costs every lane on this VM minutes.
    bd: Nothing was retried automatically, and this is not a pass - 124 means the bound killed it.

**The suite uses a stub payload, on purpose:** it runs on every gate, so it must be deterministic and must not
depend on git's `receivepack` semantics; the real-remote fixture above is the reproduction a human runs once, and
it is written out here so it can be re-run rather than believed.

New assertions, all green, each with its own red-first control **inside the test** (mutants built the way this
suite already builds them in `bd-guard.test.sh`):

- `6a` a bounded network push exits 124 (unknown, not a pass) · `6b` another lane's local write still succeeds ·
  `6c` the failure says the write did not land · `6d` the message carries the operational rule ·
  `6e`/`6f` **RED-FIRST**: with the bound removed (the network predicate forced false) the SAME fixture blocks
  another lane's local write and says nothing · `6g` a local subcommand is not bounded and not made failable ·
  `6h` no timeout report on the local path.
- `7a` the payload's descendants do not hold the lock once it exits · `7b` **RED-FIRST**: with `-o` removed the
  detached child keeps the VM-wide lock held.

**Blast radius: `bin/bd` is the VM's global bd path, so this was controlled in both trees, not just its own
suite.** Every suite that invokes the shim was run against a pristine `bin/bd` and against this patch, with the
FAIL sets diffed.

| suite (every one of these invokes the shim) | control: pristine `bin/bd` (`723856f`) | this patch (`673fb39`) | FAIL-set delta |
|---|---|---|---|
| `bd-shim.test.sh` | 15 passed, 0 failed | **25 passed, 0 failed** (+10 new) | none |
| `bd-guard.test.sh` | 85 / 0 | 85 / 0 | none |
| `bd-worktree-decoy.test.sh` | 13 / 0 | 13 / 0 | none |
| `fleet-close-landed.test.sh` | 15 / 0 | 15 / 0 | none |
| `fleet-park.test.sh` | 45 / 0 | 45 / 0 | none |
| `fleet-land-message.test.sh` | 292 / 0 | 292 / 0 | none |
| `lanes.test.sh` | 198 / 0 | 198 / 0 | none |
| `provision.test.sh` | **not obtained** | 207 passed, 3 failed (observed earlier) | **UNATTRIBUTED — see below** |

- **The control half ran TWICE** (the first attempt was preempted by the merger mid-list, and fleet-heavy
  requeued it), with **identical numbers both times** — so the baseline is not a single lucky run.
- **`provision.test.sh` is the one honest gap, and I am not papering over it.** It is the only suite here whose
  control I could not obtain: the heavy slot was preempted twice by merger landing traffic (`exit 143`, which this
  fleet reads as *unknown, not a pass*), and a half-comparison would prove nothing about it either way. The figure
  in its row is from a direct run of the ARTIFACT tree, and **those three failures are unattributed**: I am not
  claiming they are pre-existing, and I am not claiming this patch caused them. Other suites on this VM do fail
  for environment reasons (a partial tooling tree gave `lanes.test.sh` 80 failures), so both readings are live.
  **The hub should run `provision.test.sh` in both trees when it applies this**, or ask me to and I will take the
  slot when the merger is quiet.
- Nothing here is a re-run of a cached verdict: these are the suites' own counts from runs made for this patch.

### Hub Application

    cd ~/fleet
    sha256sum bin/bd tests/bd-shim.test.sh      # compare with the preimage table above FIRST: ADVISORY, and
                                                # the record already disagrees about bin/bd's identity (x8ud)
    git apply --check patches/fleet-bd-push-bounded.patch    # expect clean, no fuzz
    git apply patches/fleet-bd-push-bounded.patch
    bash -n bin/bd && bash -n tests/bd-shim.test.sh
    bash tests/bd-shim.test.sh                  # the acceptance; expect 25 passed, 0 failed
    bash tests/bd-guard.test.sh tests/bd-worktree-decoy.test.sh   # 85/0 and 13/0 - the same files' other guards

To confirm the behaviour by hand, without the suite: point `$HOME/.local/bin/bd` at a stub that sleeps on
`dolt push`, then run the shim twice — once with `FLEET_BD_PUSH_TIMEOUT=2` and once with a payload that detaches a
child — and check that the first reports `THE WRITE DID NOT LAND` while a second shim call still succeeds, and
that the second leaves the lock free.

### Trade-offs, and what this does not do

- **A legitimate push that needs more than 180 s is now killed.** That is the deliberate trade: a bounded failure
  costs a retry, an unbounded hold costs every lane on the VM. One push measured 22–85 s wall on a contended
  2-vCPU VM, so 180 s is roughly 2× headroom, and `FLEET_BD_PUSH_TIMEOUT` raises it for a one-off.
- **The lock is still taken across the network operation.** The hold is bounded, not removed (see change 4).
- **`flock -o` and `timeout -k` are now hard requirements** (util-linux 2.39.3 and GNU coreutils 9.4 here). Neither
  is pinned anywhere in this repo, so this change introduces two tool dependencies that nothing checks for; if a
  provision image ever lacked them, the shim would fail rather than fall back.
- **The silent `--claim` non-write is not fixed here** (change 6).
- **No live push was used to reproduce this.** The fixture drives the shim's own boundary with a hanging stub,
  which is the mechanism the fix lives at; the real thing was observed, not induced, on 2026-10-14.

### What an operator should expect to change

A hung bd push no longer silently freezes every lane's ledger on the machine: it dies at a bound, **says the write
did not land**, releases the VM-wide lock, and tells the operator what to do next — back off and retry, kill
nothing. Local bead writes keep going. A push that is merely slow still succeeds, up to the bound.
