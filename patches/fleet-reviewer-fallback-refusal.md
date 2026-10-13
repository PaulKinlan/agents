## `fleet-reviewer-fallback-refusal.patch` (agents-kq0r part C / agents-szle)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/fleet-fallback-guard` — testable executable guard enforcing that a reviewer lane does not run on the implementer's model family after a runtime fallback.
  - `sdk-host/host.mjs` — invokes `fleet-fallback-guard` at the runtime fallback point (`actualModel !== p.model`), logging loud refusal, disposing session, and stopping start on same-family fallback; fails open with a note if the guard binary cannot be executed.
  - `tests/fleet-fallback-guard.test.sh` — regression tests covering refusal, valid cross-family fallback, role gating, missing implementer model, and unparseable model strings.
- **Baseline file hashes:**
  `b0616adde261c3f9a39559d4aa2960fd6c444289013816218d0416062832d813  sdk-host/host.mjs`
- **Patched file hashes:**
  `8a4acb597b2442cc0d0f5932179415abfa1bbdcf6346041139c78b8353c92d0e  bin/fleet-fallback-guard`
  `b277a5319e91808d61d0dc2317544cd3041a70f9d4c21f2f49f45124b7869afb  sdk-host/host.mjs`
  `cce07489454f6983e970c11982b58ceb78fdc66587be551fe43ecf9432ee5b87  tests/fleet-fallback-guard.test.sh`

### Problem statement (agents-szle / agents-kq0r)

A core invariant of the review cadence is that a reviewer must run an independent model family from the author/implementer to avoid self-review.

The spawn-time cross-family guard (`remote/lanes.sh:361-387`, `remote/pick-model.sh:192-209`) verifies the requested model against the implementer's model family when a reviewer lane is provisioned or re-picked. However, at runtime, the SDK host can fall back to another model when the requested model provider is unavailable locally (e.g. `pi-claude-code-provider` missing on this VM).

In `sdk-host/host.mjs:117-124`, when `actualModel !== p.model`, the host logged:
`ℹ runtime model fell back: <requested> -> <effective>`
and updated `<lane>.model` on disk. **Nothing re-evaluated the family constraint at that fallback point.** As a result, reviewer lanes requesting Claude fell back to DeepSeek and silently conducted same-family self-reviews.

**Measurement on this VM:** Across `~/.fleet/lanes/*.events.log`, 25 lanes have a runtime fallback line, and in all 25 the family changed. 22 of those were reviewer lanes that requested `pi-claude-code-provider/sonnet` and fell back to `deepseek/deepseek-flash`, matching the implementer's own family.

### Availability of Role and Implementer Model in Host Environment

Before relying on `FLEET_IMPL_MODEL` and `FLEET_ROLE` in `sdk-host/host.mjs`, their presence in the host was verified against the real runtime:
1. `remote/run-lane.sh:39` sources `<lane>.conf` and exports:
   `if [ -n "${IMPL_MODEL:-}" ]; then export FLEET_IMPL_MODEL="$IMPL_MODEL"; fi`
2. `remote/run-lane.sh:92` exports:
   `export FLEET_VM=$VM ... FLEET_ROLE=$ROLE ...`
3. `remote/run-lane.sh:185-194` (`FLEET_PREPARE_JSON=1`), which is invoked by `sdk-host/host.mjs:prepare()`, serializes both `role: $role` and the full `env -0` dump into the JSON payload returned to the host:
   ```json
   {
     "lane": "rev-ymh2",
     "role": "reviewer",
     "env": {
       "FLEET_ROLE": "reviewer",
       "FLEET_IMPL_MODEL": "deepseek/deepseek-flash",
       ...
     }
   }
   ```
4. Verification command on live lane `rev-ymh2`:
   ```bash
   $ FLEET_PREPARE_JSON=1 bash /home/exedev/fleet/remote/run-lane.sh rev-ymh2 2>/dev/null | jq '{role: .role, FLEET_ROLE: .env.FLEET_ROLE, FLEET_IMPL_MODEL: .env.FLEET_IMPL_MODEL}'
   {
     "role": "reviewer",
     "FLEET_ROLE": "reviewer",
     "FLEET_IMPL_MODEL": "deepseek/deepseek-flash"
   }
   ```
   Both fields are reliably present in `p.role` / `p.env` in `sdk-host/host.mjs`.

### Established Mechanism & Rules

1. **Loud Refusal That Stops the Caller:**
   Printing a warning and continuing is not a check ("a check whose failure does not stop the next line is not a check"). When `bin/fleet-fallback-guard` refuses (exit 1), `sdk-host/host.mjs` logs the refusal loudly to the lane's events log (`✖ REFUSE: ...`), logs to `sdk-host.log`, calls `session.dispose()`, and throws an `Error(refusal)` to abort `start()` immediately before socket listening, state saving, or message queuing occur.
2. **Read Effective Family, Not Requested:**
   The check compares the family (prefix before first `/`) of the *effective* model (`actualModel`) against the implementer's family (`FLEET_IMPL_MODEL`). The refusal message explicitly names both the requested and effective families and their evidence sources (`runtime fallback`, `FLEET_IMPL_MODEL`).
3. **Fail Open on Missing Fields (No False Red on Incomplete Records):**
   If the family cannot be established — `FLEET_IMPL_MODEL` is unset, or a model string is unparseable (lacking a `/` family prefix) — the guard outputs a `NOTE: ...` and proceeds (exit 0). A guard that refuses on incomplete records would block every legacy or partially-recorded lane.
4. **Fail Open on Missing or Unexecutable Tool (No False Red on Tool Absence):**
   In `sdk-host/host.mjs`, only a genuine refusal (`e.status === 1` and output containing `REFUSE:`) may abort lane start. If the guard binary cannot be executed (`e.code === 'ENOENT'`, `e.code === 'EACCES'`, or an abnormal non-refusal exit like shell 127), the host logs `ℹ NOTE: fallback guard ${why}; proceeding without guard` and allows the session to start. A partial deployment (updating `host.mjs` without `bin/fleet-fallback-guard`) must never brick every falling-back reviewer lane.
5. **Precedent Matched:**
   Recognisably matches `remote/run-lane.sh:63-65` ("reviewer $lane cannot start: the rotation has no model outside the implementer's family... (fleet-ccfq)"), citing `fleet-szle`.
6. **Durable Evidence Preserved:**
   The events-log fallback entry (`ℹ runtime model fell back: ...`) and the `<lane>.model` pointer write execute *before* invoking the guard so audit trails and evidence of the fallback are never lost.

### Changes

- `bin/fleet-fallback-guard`: New standalone script with signature `fleet-fallback-guard <role> <impl_model> <requested_model> <effective_model> [source]`. Implements family comparison, checks role gating, prints decisions, and exits 0 (proceed) or 1 (refuse).
- `sdk-host/host.mjs:116-145`: In `Lane.prototype.start()`, inside the `actualModel !== p.model` block, calls `fleet-fallback-guard`. Distinguishes a legitimate refusal (`e.status === 1` with `REFUSE:`) from an execution failure (`ENOENT`, `EACCES`, or abnormal exit):
  - On legitimate refusal: logs `✖ REFUSE: ...`, logs to host logger, disposes session, and throws `Error(refusal)`.
  - On execution failure / missing binary: logs `ℹ NOTE: fallback guard ...; proceeding without guard` and proceeds.
- `tests/fleet-fallback-guard.test.sh`: New regression test suite with 17 assertions verifying all refusal, proceed, and fail-open note cases.

### Red-First Verification of Missing-Tool Handling

Under the initial draft of the host catch block, any `execFileSync` error set `refusal = e.message`. When `bin/fleet-fallback-guard` was missing (`ENOENT`), `execFileSync` threw, `refusal` was populated with `"spawnSync ... ENOENT"`, and the host threw, bricking the reviewer lane.

#### 1. Unfixed Code (RED)

Running an assertion that a missing guard must proceed:

```bash
$ node test_unfixed_harness.mjs
UNFIXED RESULT: {
  "threw": true,
  "errorMsg": "spawnSync /nonexistent/bin/fleet-fallback-guard ENOENT",
  "logs": [
    "ℹ runtime model fell back: pi-claude-code-provider/sonnet -> deepseek/deepseek-flash",
    "✖ spawnSync /nonexistent/bin/fleet-fallback-guard ENOENT"
  ],
  "disposed": true
}
RED ASSERTION FAILED: expected lane to PROCEED when guard is missing, but it threw: spawnSync /nonexistent/bin/fleet-fallback-guard ENOENT
exit code: 1
```

#### 2. Fixed Code (GREEN)

Under the fixed catch block, `e.status === 1 && outText.includes("REFUSE:")` gates the refusal. Missing guard (`ENOENT`), unexecutable guard (`EACCES`), and abnormal non-refusal exits (127) log an informative NOTE and proceed without throwing:

```bash
$ node test_fixed_harness.mjs
1. Missing guard (ENOENT): {
  "threw": false,
  "errorMsg": "",
  "logs": [
    "ℹ runtime model fell back: pi-claude-code-provider/sonnet -> deepseek/deepseek-flash",
    "ℹ NOTE: fallback guard cannot execute (ENOENT); proceeding without guard"
  ],
  "disposed": false
}
2. Non-executable guard (EACCES): {
  "threw": false,
  "errorMsg": "",
  "logs": [
    "ℹ runtime model fell back: pi-claude-code-provider/sonnet -> deepseek/deepseek-flash",
    "ℹ NOTE: fallback guard cannot execute (EACCES); proceeding without guard"
  ],
  "disposed": false
}
3. Nonzero non-refusal (127): {
  "threw": false,
  "errorMsg": "",
  "logs": [
    "ℹ runtime model fell back: pi-claude-code-provider/sonnet -> deepseek/deepseek-flash",
    "ℹ NOTE: fallback guard exited 127; proceeding without guard"
  ],
  "disposed": false
}
4. Real refusal: {
  "threw": true,
  "errorMsg": "REFUSE: reviewer cannot run effective model family deepseek",
  "logs": [
    "ℹ runtime model fell back: pi-claude-code-provider/sonnet -> deepseek/deepseek-flash",
    "✖ REFUSE: reviewer cannot run effective model family deepseek"
  ],
  "disposed": true
}

ALL FIXED ASSERTIONS GREEN
exit code: 0
```

### TESTS

The following commands were executed and produced real output:

#### 1. Unit Tests of Fallback Guard

```bash
$ bin/fleet-fallback-guard reviewer deepseek/deepseek-flash pi-claude-code-provider/sonnet deepseek/deepseek-flash
exit code: 1
REFUSE: reviewer cannot run effective model family 'deepseek' (effective model 'deepseek/deepseek-flash', source: runtime fallback); matches implementer model family 'deepseek' (implementer model 'deepseek/deepseek-flash', source: FLEET_IMPL_MODEL); requested family was 'pi-claude-code-provider' (requested model 'pi-claude-code-provider/sonnet') (fleet-szle)

$ bin/fleet-fallback-guard reviewer deepseek/deepseek-flash pi-claude-code-provider/sonnet openai-codex/gpt-6-sol
exit code: 0
PROCEED: reviewer effective family 'openai-codex' differs from implementer family 'deepseek' (requested family 'pi-claude-code-provider', source: runtime fallback)

$ bin/fleet-fallback-guard implementer deepseek/deepseek-flash pi-claude-code-provider/sonnet deepseek/deepseek-flash
exit code: 0
PROCEED: role 'implementer' is not reviewer; cross-family guard does not apply

$ bin/fleet-fallback-guard reviewer "" pi-claude-code-provider/sonnet deepseek/deepseek-flash
exit code: 0
NOTE: implementer model (FLEET_IMPL_MODEL) is unset; cannot establish implementer family; proceeding without guard

$ bin/fleet-fallback-guard reviewer deepseek/deepseek-flash pi-claude-code-provider/sonnet unparseable
exit code: 0
NOTE: cannot establish effective model family from 'unparseable' (unparseable model string); proceeding without guard
```

#### 2. Fleet Regression Suite

```bash
$ bash tests/fleet-fallback-guard.test.sh
1. REFUSE: reviewer falling back to implementer model family
  ok   1a refuses with exit 1
  ok   1b message states REFUSE
  ok   1c message names requested family
  ok   1d message names effective family
  ok   1e message names source: runtime fallback
  ok   1f message names source: FLEET_IMPL_MODEL
2. PROCEED: reviewer falling back to cross-family model
  ok   2a proceeds with exit 0
  ok   2b message states PROCEED
3. PROCEED: implementer falling back to same family as FLEET_IMPL_MODEL
  ok   3a proceeds with exit 0
  ok   3b message states PROCEED
4. PROCEED WITH A NOTE: FLEET_IMPL_MODEL unset
  ok   4a proceeds with exit 0
  ok   4b message states NOTE
  ok   4c note mentions FLEET_IMPL_MODEL
5. PROCEED WITH A NOTE: unparseable model string
  ok   5a unparseable effective model proceeds with exit 0
  ok   5b message states NOTE
  ok   5c unparseable impl model proceeds with exit 0
  ok   5d message states NOTE

fleet-fallback-guard: 17 checks, 0 failed
```

#### 3. Host-Level Behavior

`sdk-host/host.mjs` is a long-running daemon that binds directly to the active system socket `~/.fleet/sdk-host.sock` and initializes live model credentials across all unstopped lanes on boot. Running the full unmocked daemon against live fleet state is non-hermetic and would disrupt active lanes on this VM.

Instead, the host-level behavior was tested hermetically via an isolated Node.js test harness (matching the method used in `tests/sdk-host-shutdown.test.sh` and `tests/failover-preflight.test.sh`) asserting the observable contract:
- On refusal: writes `<lane>.model` with effective model, logs fallback line, logs loud `✖ REFUSE:` line, calls `session.dispose()`, and throws `Error` aborting start.
- On valid cross-family fallback: writes `<lane>.model`, logs fallback, does not throw, does not dispose session.
- On non-reviewer fallback: does not throw, does not dispose session.
- On missing guard (`ENOENT`), non-executable guard (`EACCES`), or abnormal exit (127): writes `<lane>.model`, logs fallback, logs `ℹ NOTE: fallback guard ...; proceeding without guard`, does not throw, does not dispose session.

```bash
$ node harness_test.mjs
1. Host behavior: reviewer falling back to same family as implementer
  ok 1 - session start threw error on refusal
  ok 2 - session was disposed on refusal
  ok 3 - fallback model pointer written to disk before refusal
  ok 4 - events log records fallback line
  ok 5 - events log records refusal line
2. Host behavior: reviewer falling back to different family
  ok 6 - session start did not throw on valid fallback
  ok 7 - session was not disposed on valid fallback
  ok 8 - fallback model pointer written to disk
3. Host behavior: implementer falling back to deepseek
  ok 9 - implementer start did not throw
4. Host behavior: missing guard binary (ENOENT)
  ok 10 - session start did not throw on ENOENT
  ok 11 - session was not disposed on ENOENT
  ok 12 - events log records ENOENT note
5. Host behavior: non-executable guard (EACCES)
  ok 13 - session start did not throw on EACCES
  ok 14 - session was not disposed on EACCES
  ok 15 - events log records EACCES note
6. Host behavior: nonzero abnormal exit (127)
  ok 16 - session start did not throw on exit 127
  ok 17 - session was not disposed on exit 127
  ok 18 - events log records exit 127 note

Host harness: 18 checks, 0 failed
```

#### 4. Verification in Factory Repository

```bash
$ python3 -m unittest tests/test_fleet_reviewer_fallback_refusal.py
.........
----------------------------------------------------------------------
Ran 9 tests in 2.002s

OK

$ python3 -m unittest tests/test_patch_writeups.py
......
----------------------------------------------------------------------
Ran 6 tests in 0.005s

OK
```

### Hub Application

```bash
cd ~/fleet
git apply -p1 --check /path/to/patches/fleet-reviewer-fallback-refusal.patch
git apply -p1 /path/to/patches/fleet-reviewer-fallback-refusal.patch
node --check sdk-host/host.mjs
bash tests/fleet-fallback-guard.test.sh
```
