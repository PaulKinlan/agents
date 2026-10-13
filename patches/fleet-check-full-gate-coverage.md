## `fleet-check-full-gate-coverage.patch` (agents-5gcl)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/fleet-check` (lines 482-487)
  - `remote/check-coverage.py` (lines 270-275, 295-300, 304-308)
  - `tests/check-coverage.test.sh` (new Section 8, assertions 8a-8d)
  - `tests/fleet-gate-check.test.sh` (updated Section 14, assertions 14v, 14v2, 14v3, 14v4)
- **Baseline file hashes:**
  - `7e3b0b06137b629ad65ec8da77e525afff02425e69eaf788421d6b06fe994e62  bin/fleet-check`
  - `d60e9ad23d460ac1a3b8cb73c46c19eeb4b288719be339c1a2b134c34dc40892  remote/check-coverage.py`
  - `2757de4660c4a48f21f7fbba7a86c7008b595e432057b94da4441e203316b55b  tests/check-coverage.test.sh`
  - `ca8bffa7991eddfc07480c90a4e1deb6e6019a52bae53dee030cbc258caecba2  tests/fleet-gate-check.test.sh`
- **Problem Statement (agents-5gcl):**
  1. Full-gate records cached in `~/.fleet/checks/<tree>.json` carried no coverage accounting (`.coverage` missing, `suites=0`, `unmapped=null`, `omitted=null`). Across the cache, 326 full-gate records had zero `.coverage` objects.
  2. **Where marker is emitted:** The suite-marker line `fast-gate: passed: <suites>` (or `ran:`, `running:`, `failed:`) is emitted by project `tools/fast-gate.sh` (or `remote/fast-gate.sh` on the hub).
  3. **Why full gate does not emit it:** The full-gate `CHECK_CMD` runs the test runner directly (`python3 -m unittest discover -s tests -t . -v 2>&1 | tee -a ...`) without a wrapper or adapter emitting gate-prefixed markers.
  4. **The load-bearing gatekeeper in `fleet-check`:** `bin/fleet-check:485` explicitly restricted coverage extraction with `if [ -n "$fast" ]`. On full gates (`$fast` is empty), `cov_script` was never executed even though `check-coverage.py` already supports extracting suites from verbose unittest logs (`test_x (...) ... ok`), Deno, Jest/Vitest, Pytest, and Node test runners.
  5. **What test 14v was pinning:** Test 14v in `tests/fleet-gate-check.test.sh` originally asserted `hasnt ... '"coverage"' "14v full gate record omits coverage field"` because `fleet-1n0z` conceived coverage reporting exclusively as a fast-gate affected-test selection guard. That negative assertion codified an early design assumption that full gates run everything and do not need coverage records, leaving landing verdicts structurally blind to test execution and unmapped files.
- **Extraction Cost Measurement:**
  - Measured `check-coverage.py` directly across 5 real full-gate logs (~348KB–349KB).
  - Extraction took 8.4s–10.6s and extracted 65–66 suites cleanly.
  - Compared to full-gate bounds (2400s) and execution times (minutes to tens of minutes), an 8–10s extraction time run asynchronously in the finishing worker before inbox notification represents <1% of gate duration.
- **Scope & Back-fill:**
  - This change applies to **NEW** gate records going forward.
  - Back-filling existing historical cached records is explicitly out of scope.
- **Narrow Regex Pattern:**
  - Marker recognition in `remote/check-coverage.py` is widened only to the strictly anchored alternation `^(?:fast-gate|full-gate):\s*`.
  - Does not match loose `gate:` or un-anchored strings, preventing false positives from prose or test names.
- **Changes:**
  1. **`bin/fleet-check`:** In `finish()`, remove `[ -n "$fast" ] &&` from the `cov_script` execution predicate. Full gates now run `check-coverage.py` and populate `.coverage`, `.suites`, `.unmapped`, and `.omitted` in the gate record.
  2. **`remote/check-coverage.py`:** Update marker regex patterns from `^fast-gate:` to `^(?:fast-gate|full-gate):` for suite dispatch/pass/fail, unmapped files, and unknown coverage markers.
  3. **`tests/check-coverage.test.sh`:** Added Section 8 verifying `full-gate: passed:` and `full-gate: unknown:` markers parse identically to fast-gate markers (assertions 8a–8d pass).
  4. **`tests/fleet-gate-check.test.sh`:** Updated Section 14 with in-test rationale comments explaining the reversal of the legacy `fleet-1n0z` omission:
     - `14v`: Assert full-gate record carries `.coverage` (reversal of legacy omission).
     - `14v2`: Assert full-gate record without runner evidence records `coverage: "UNKNOWN"`.
     - `14v3`: Assert full-gate record with runner evidence captures executed suites.
     - `14v4`: Assert full-gate record with complete mapping reports 0 unmapped files.
- **Verification:**
  - `tests/check-coverage.test.sh`: 25/25 passed.
  - `tests/fleet-gate-check.test.sh` Section 14 (assertions 14v, 14v2, 14v3, 14v4): all passed.
  - `python3 -m unittest tests.test_patch_writeups`: 6/6 pass in 0.005s.
  - Clean patch application verified via `patch -p1 --dry-run` against deployed `~/fleet`.
  - Zero internal bead IDs (`agents-*`).
- **Hub Application:**
  ```bash
  cd ~/fleet
  patch -p1 < /path/to/fleet-check-full-gate-coverage.patch
  bash tests/check-coverage.test.sh
  bash tests/fleet-gate-check.test.sh
  ```
