## `fleet-lanes-status-no-recency.patch` — `lane_status()` reads no recency field at all (agents-oi0x)

`remote/lanes.sh` `lane_status()` read `state.last_event_at` into a variable that was then **never read again**
(the only two occurrences of `ev` in the whole file were the declaration and the assignment). Its `busy == false`
branch returns `idle` from `win_exists` with **no recency input at all**, while `inbox/status.mjs` computes
`max(session-file mtime, state.last_event_at)` for the watchdog. A computed fact with no reader reads as *"a clock
decides this"*, so the next reader either trusts a field the branch ignores or wires a clock back into a decision
that was deliberately taken without one — which is how the divergence returns.

The fix: **the field is not part of the decision, so the read is deleted** (not wired up), and the property that
makes the deletion permanent is pinned — structurally, because dead code cannot be caught behaviourally.

## The four hub-delivery fields

| Field | Value |
| --- | --- |
| **Artifact sha** | `patches/fleet-lanes-status-no-recency.patch` — 6821 bytes, sha256 `0bd025b151d67ce698b9eabc2f86e02571bdc6dbd02a44fb195eff6670faf311`, 2 hunks, 2 file-sections |
| **Exact base it expects** | `remote/lanes.sh` = 40537 bytes, sha256 `7f0be21489db73e4d18821c58e6e669d22ec54f5192bc00bf158b5b9d422e4aa`; `tests/lanes.test.sh` = 64678 bytes, sha256 `bbe6c9339457e2144d63b59a612c7adb15443c84480b14919e7788f4abfa00d5` (both = the **deployed** `~/fleet` copies on this VM, measured, not assumed) |
| **Does the destination have that shape?** | Verified here against those deployed copies: `patch -p1 --dry-run` clean for **2/2** sections, and the applied files are **byte-identical** to the files that were tested (`remote/lanes.sh` → sha256 `09e34400ca8f6ca8…`, `tests/lanes.test.sh` → `8bdeee06e256b7d1…`). The hub must re-measure its own copy (`sha256sum ~/fleet/remote/lanes.sh`); if it differs, rebase the two hunks by context — the first is three lines in `lane_status()`, the second appends one test section. |
| **Prerequisites** | **None.** Nothing else in `patches/` must land first. No dependency added. |

## Question 1: is recency supposed to be part of the idle decision? **No — and that is already decided**

Answered from the code and the pins, not from preference:

* `tests/lanes.test.sh` section 11 (fleet-ehyo) is titled *"idle liveness: stale activity is not a zombie or a
  free specialist slot"* and pins exactly this: a live lane with `last_event_at` 90 minutes old and no children
  reports **idle** (`11c`), `lanes list` must not make a false process-death claim (`11d`), and `lanes start` must
  not restart it (`11d2`). Sections 11g/11h pin the same for SDK mode.
* The in-code reason, kept: *"An idle session can legitimately have no child processes or events for hours.
  `win_exists` already checked the live per-lane socket (and the unit/host PID); age alone cannot prove a dead
  session."*

So wiring the field into `busy == false` would reinstate the rule that was removed and break those pins. The read
is the fossil of the removed branch: **deleting it is the fix**, and the comment left in its place says why, cites
the bead, and names the test that keeps it deleted.

## Question 2: what makes the two readers agree — and where that stops

**Closed by construction, in the dimension this bead is about (the clock):**

* After this patch `lane_status()` consults **no activity timestamp at all** — not `last_event_at`, not the
  session file's mtime. Its inputs are the stop file, the socket, the pid, `busy`, `turn_start_at` and child
  attribution. This is pinned **structurally**, not by observation: a mutation test on the tool cannot see dead
  code, so the suite asserts the function body contains no read of the field.
* The recency fact now has **exactly one producer** (`remote/lane-host.mjs:162`, `sdk-host/host.mjs:140`) and
  **exactly one consumer** (`inbox/status.mjs:89-90` → `last_event_min` → the watchdog). One consumer cannot
  disagree with itself, and there is no second clock left in the classification path for it to drift against.

**Not closed here, and measured rather than waved through: the readers' *liveness predicate* still differs.**

Same state file — an SDK lane with a **live shared host pid**, a fresh `last_event_at`, and **no per-lane socket**
(the lane's session is gone) — driven through both readers:

```
$ HOME=$H bash remote/lanes.sh status des-x        →  stopped
$ HOME=$H node -e 'import("/tmp/oi0x/fleet/inbox/status.mjs")…'
  {"lane":"des-x","running":true,"pi_alive":true,"intercom":"idle","last_event_min":0}
```

`lanes.sh` requires the live per-lane socket here (`win_exists()`: `host == sdk` **and** `sock_live`), while
`status.mjs` derives it from `host_pid` alone (`hostState()`: `host_pid && alive(host_pid)`) and hardcodes
`pi_alive = true` for SDK lanes. One predicate, two instruments — this is the fault the sibling write-up in this
directory (*`fleet-watchdog-idle-holder-declaration.md`*) describes and deliberately left unfixed as "necessarily
touching two components".

It is **not fixed in this patch**, deliberately, and this is a policy call rather than a lane's choice — the
precedent is `agents-gezf`'s own instruction not to compensate a reader before a decision is made:

* Which predicate is right is a decision: make `status.mjs` socket-aware (3 lines in `hostState()`: return `null`
  for an SDK lane whose socket is not live — which then also makes `pi_alive`/`running` false), or relax
  `lanes.sh`. Both change what the dashboard and the watchdog see.
* The change would be invisible to the existing tests: `tests/watchdog-smoke.test.sh` builds `status.json`
  fixtures by hand, so it exercises the watchdog *given* a status, not `status.mjs`'s own derivation.
* Filed as its own bead with this exact measurement, so it is tracked rather than living in a write-up.

**Not compensated here either:** `agents-gezf` (Face 2) is the writer side — `bd comment` does not bump
`updated_at` — and this patch touches no bead field and no `updated_at` reader, by that bead's explicit
instruction.

## What changed

1. `remote/lanes.sh` `lane_status()`: `local busy ev turn_start` → `local busy turn_start`, and the
   `ev=$(jq -r '.last_event_at // empty' …)` line is deleted, replaced by a six-line comment that states the
   decided semantics, cites `fleet-ehyo`/`agents-oi0x`, and points at the pins.
2. `tests/lanes.test.sh` new section 30 — eight assertions, both directions:
   * **30a–30c invariance** — the same live lane with `last_event_at` at 2 minutes, 90 minutes and `null` must
     give the same `lanes status` **and** the same `lanes list` row.
   * **30d–30e alive with no structural field** — a live lane whose state file has no `busy`, no `turns` and no
     timestamp reads **alive** (`running`), and `lanes start` does not restart it.
   * **30f–30g dead stays dead** — a **dead pid** reads `stopped` even with a live socket and an event *seconds*
     old; in rpc mode a lane whose live socket is gone reads `stopped` with a fresh timestamp. *(A fix that makes
     everything look alive is worse than the bug.)*
   * **30h the structural pin** — the `lane_status()` body must contain no read of the field.

## Evidence

| Run | Result |
| --- | --- |
| Deployed `tests/lanes.test.sh` on the deployed `lanes.sh` (baseline) | **198 passed, 0 failed** |
| Patched pair | **206 passed, 0 failed** (+8) |
| New tests on the **pre-fix** `lanes.sh` (`LANES_OVERRIDE=~/fleet/remote/lanes.sh`) | 205 passed, **1 failed** — only `30h`. 30a–30g pass on both, which is the honest result: the read was dead, so no behaviour observes it. **This is why 30h exists.** |
| Mutant: the old read restored **and** a clock wired into the idle branch (the divergence returning with a new clock) | **30b, 30c, 30h fail** (plus existing 11c/11d/11d2) — the rails bite |
| Mutant: `win_exists()` made to return true unconditionally (everything looks alive) | **30f, 30g fail** (57 failures overall) — the other rail bites |
| `patch -p1` applied to fresh copies of the two bases | clean, byte-identical to the tested files |

## Applying it

```bash
cd ~/fleet
sha256sum remote/lanes.sh tests/lanes.test.sh   # must equal the two bases above
patch -p1 --dry-run < patches/fleet-lanes-status-no-recency.patch
patch -p1 < patches/fleet-lanes-status-no-recency.patch
bash tests/lanes.test.sh                        # expect: 206 passed, 0 failed
```

Contract to preserve if the hunks need rebasing: **`lane_status()` classifies from the stop file, the socket, the
pid, `busy`, `turn_start_at` and child attribution — never from an activity timestamp; recency is reported by
`status.mjs` as `last_event_min` and decides nothing about liveness.**
