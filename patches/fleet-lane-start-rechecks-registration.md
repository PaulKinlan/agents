## `fleet-lane-start-rechecks-registration.patch` (agents-h006)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `remote/run-lane.sh` (the guard: the start re-reads the registry at the decision point)
  - `remote/lanes.sh` (the readiness-timeout message now carries the lane's own last log line)
  - `tests/lanes.test.sh` (sections 30–32: the incident, the invariant, and the diagnostic)
- **Baseline file hashes:**
  `d792cd717997930a10e4a7441c9688d63a984cfefc1926623fefbca030776d12  remote/run-lane.sh`
  `a5dfb8b0faa6ce347ad9391d0d30d87ac134e506a46936dff7b69450ef5431c1  remote/lanes.sh`
  `2608e6e616a68910d510cc76d87c975cf0e54c2de0fe8f78ad120d8a0d212192  tests/lanes.test.sh`
- **Patched file hashes (the round trip reproduced these byte-for-byte):**
  `acaa74d0c0a83a0f49b43ac6b8a896a10e857cd637c1e7a1f8ab1e8fe7cef6ea  remote/run-lane.sh`
  `cdb67591a928019d3777196cbf6e68df8eb2b1ecff6539fe29c21ea4e693900d  remote/lanes.sh`
  `d5cfe75d196014a343416d2c3e7caa67c3728c09a08075ded9a6efdadaa5d9fe  tests/lanes.test.sh`

- **Problem statement (agents-h006).** A lane that has been retired can come back. On 2026-10-12 `rev-weekly`
  was spawned, failed readiness, was retired **and deregistered** by coord, and then started two minutes later
  under the bead it had been retired with, on a different model. The unlucky direction of that is not the
  duplicate work that was observed (two reviewers on one bead) but a resurrected lane acting on a stale bead id —
  re-claiming a bead another lane has since landed, or pushing a branch name that has been reused.

- **Established, by reading and from the incident's own artifacts, on the CURRENT tooling (`~/fleet` as synced
  to this VM on 2026-10-13; nothing here was reasoned from the bead text):**
  1. **What re-arms the lane is the start process its own spawn abandoned — not a timer, not the watchdog.**
     `lanes.sh spawn` waits 5 s for readiness (`remote/lanes.sh:402-410`) and then returns 1 **without waiting for
     what it started**. In `rpc` mode that is the systemd unit (`systemd/fleet-lane@.service:14`,
     `ExecStart=…/run-lane.sh %i`, `Type=simple`, so `systemctl --now` returns while the script is still running);
     in `sdk` mode it is `sdk-host/host.mjs:344` → `startLane` (`:314`) → `await prepare()` (`:72-74`, a 600 s
     timeout), which is still awaiting `run-lane.sh` long after the caller gave up on the socket exchange.
     `run-lane.sh`'s model-wait loop is 6 × 30 s (`remote/run-lane.sh:118-124`).
  2. **The timeline, from the artifacts, is exact.** `~/.fleet/lanes/rev-weekly.log` records
     `15:05:43Z … (4/6)`, `15:06:15Z … (5/6)`, `15:06:49Z … (6/6)`, `15:07:19Z start rev-weekly sid=1f873680-…
     model=antigravity/gemini-3.8-pro (headless rpc)`. `~/.fleet/sdk-host.log:1405` records
     `2026-10-12T15:07:19.528Z started rev-weekly`, the same millisecond as `rev-weekly.state.json`'s `since`, and
     `rev-weekly.turns.jsonl` shows it then ran a turn (161 s wall). Coord retired it at 15:05:23. **So the
     process that started the lane was already running at the moment of the retire, and the host was inside
     `prepare()` for it: the host log has no failure line for rev-weekly and records the lane as started only at
     15:07:19.528Z.**
  3. **The one guard it had was gone by then, and cannot be made to survive by itself.** The guard is
     `remote/run-lane.sh:125` — `[ -f "$LD/$lane.stop" ] && exit 0`. `retire` writes `.stop` and then
     `deregister()` (`remote/lanes.sh:443`) deletes it with the rest of the registration, deliberately: a retired
     lane must leave **nothing** behind for the watchdog to revive, and `tests/lanes.test.sh:600` (16d) and
     `:656` (16u) pin exactly that. `sdk-host/host.mjs:316` also unlinks `.stop` at the entry of every start. The
     durable fact is the **registration** (`.conf`), because it is the one `lanes list` reads too.
  4. **A second, independent trap in the same window: the diagnosis existed and the error did not carry it.** The
     same lane failed the 5 s readiness check three times, and the message said only
     `did not become ready within 5s` (`remote/lanes.sh:409`) while the lane's own log had been saying
     `waiting for model antigravity/gemini-3.8-pro to be available (1/6)` from its first second — a model that is
     not registered on this VM, which is the whole cause. Operators read the 5 s message as a slow VM.
  5. **The model mismatch in the incident is NOT a partially-updated spawn record.** The host failed the
     unregistered model over to `deepseek/deepseek-flash`, which is what `lane-host`/`host.mjs` do by design
     (`host.mjs:99-140`), and `rev-weekly.model` holds the failed-over value. That half of the incident is
     agents-tgi (the sticky `.model` file) and is not touched here.

- **Changes.**
  1. `remote/run-lane.sh`: immediately after the model-wait loop, the start re-reads the registry — `.stop` first
     (`exit 0`, unchanged semantics: a stop is not an error) and then the **registration**, which must still exist
     (`exit 1` if it does not), with the refusal written to `$LD/$lane.log`. A start therefore cannot complete for
     a lane that `lanes list` no longer names, whatever removed the registration and whenever it was removed. The
     guard covers both modes because it lives inside `run-lane.sh`, which is the process each mode leaves running.
  2. `remote/lanes.sh`: the readiness timeout now quotes the lane's last non-empty log line (bounded to 200
     characters) and names the log file. The timeout itself is unchanged, and the message deliberately does not
     claim to cancel the start — a start that has not finished after 5 s is still running, and (1) is what makes
     that safe.
  3. `tests/lanes.test.sh`: section 30 reproduces the incident; 31 pins the invariant through `lanes list` (the
     fleet's own answer to "does this lane exist", not a ps scan); 32 pins the diagnostic.

- **What this patch deliberately does NOT do, so it is not re-litigated.** It does not make `.stop` survive
  `deregister`: `tests/lanes.test.sh` 16u exists to assert that a retired lane leaves nothing behind, and that
  invariant is worth more than a second tombstone. It does not cancel the abandoned start, either — the fail-open
  design ("a lane on the right model a bit late beats a lane that never starts", `remote/run-lane.sh:115-117`) is
  intentional, and the residual cost of the abandoned process is a bounded model preflight, not a resurrection.

- **Verification, all of it measured on 2026-10-13 in a copy of `~/fleet` (`FLEET_*` and `HOME` fixtures only; no
  real lane was started, and the suite stubs `systemctl`/`sudo`/`bd`):**
  - **Baseline, before the change:** `bash tests/lanes.test.sh` → **197 passed, 0 failed** in **17.1 s**. (The
    run's own output is the evidence that it executed the pre-change test file: it ends at section 29 and the
    output was truncated to that point by the test file as read, so sections 30–32 did not exist for it.)
  - **Patched:** **212 passed, 0 failed** — the 197 plus 15 new assertions. Whole file, one process:
    `bash tests/lanes.test.sh`, exit 0.
  - **The new cases are not vacuous — the red run.** The same suite (new test file) against the **baseline**
    `remote/run-lane.sh` and `remote/lanes.sh` (hashes `d792cd71…` / `a5dfb8b0…`) → **206 passed, 6 failed**,
    exit 1, failing exactly the new-behaviour assertions and nothing else:
    `30b no lane is prepared for a lane retired mid-start`, `30c refusal exit code`,
    `30d the reason is in the lane's own log`, `30g and that refusal is logged too`,
    `32b and now carries the lane's own last log line, which is the diagnosis`, `32c and names the file to open`.
    The cases that pass in both directions are the controls and the invariant, and are labelled as such in the
    file: `30a` (the same fixture *does* prepare a start when nothing intervenes), `30e`, `30f`, `30h`, `31a-c`,
    `32a`, `32d`.
  - **How section 30 reproduces the incident rather than describing it.** `run-lane.sh` calls
    `$FLEET_ASK_RECORD_OVERRIDE` (if set) **after** it has read the lane's registration and **before** it decides
    to start — which is exactly where a retire lands — so the fixture sets it to a hook that removes `.conf` and
    `.stop` mid-start. That is the incident sequence: the state the process read is gone by the time it acts.
  - **Round trip:** `git apply --check` passes against a pristine copy, and the applied patch reproduces the
    measured tree byte-for-byte (the three patched hashes above).
  - **Cost, measured rather than estimated:** baseline `17.1 s` (197 assertions) against patched `23.5 s`
    (212 assertions) for the same suite — **+6.4 s, of which ~5.0 s is section 32's one real readiness wait**
    (5 × 0.25 s polling, the only way to observe that message end-to-end) and the rest of sections 30–32 the
    remainder. This is a test-only cost: nothing here adds work to any lane's start path — the guard is two
    `[ -f ]` tests on files the process has already opened.
