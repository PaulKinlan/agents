## `fleet-verdict-model-families-filter.patch`

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `bin/fleet-verdict-words.sh` (line 75)
  - `bin/fleet-land-message` (line 217)
  - `tests/fleet-land-message.test.sh` (new unit tests, section 36i)
- **Baseline file hashes:**
  `5d0b20d...` (applies on top of `fleet-verdict-transcription-scanner.patch`)
- **Prerequisite:** Applies on top of `fleet-verdict-transcription-scanner.patch`.
- **Problem Statement:**
  1. The provider-family allowlist `FLEET_VERDICT_MODEL_FAMILIES` was previously half-wired: `bin/fleet-land-message`'s `VPFX` expanded `"${FLEET_VERDICT_MODEL_FAMILIES:-...}"` (env-overridable), but `bin/fleet-verdict-words.sh` hardcoded `FLEET_VERDICT_MODEL_FAMILIES='...'` unconditionally on source, clobbering any external override.
  2. In `bin/fleet-land-message`, candidate comment discovery in `REV_CAND` hardcoded the literal list in two `jq` `select()` expressions, ignoring the environment variable. Comments with custom or extended families were filtered out before `flm_select` could inspect them.
- **Changes:**
  1. **Preserve External Override on Source:** In `bin/fleet-verdict-words.sh`, initialize with `FLEET_VERDICT_MODEL_FAMILIES="${FLEET_VERDICT_MODEL_FAMILIES:-...}"` so caller-exported values survive.
  2. **Wire Allowlist into REV_CAND:** In `bin/fleet-land-message`, pass `--arg fam "$FLEET_VERDICT_MODEL_FAMILIES"` to `jq` in `REV_CAND`, allowing the candidate filter to dynamically accept custom or extended model families.
  3. **Unit Tests:** In `tests/fleet-land-message.test.sh`, added Section 36i asserting:
     - 36i1: Off-list custom family is rejected by default.
     - 36i2–36i4: Custom family configured via `FLEET_VERDICT_MODEL_FAMILIES` is accepted by `REV_CAND` and `flm_select`, extracting verdict and marking author-lane transcription.
- **Verification:**
  - `tests/fleet-land-message.test.sh` section 36i: 4/4 assertions pass (314/314 total in suite).
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-verdict-transcription-scanner.patch
  git apply /path/to/fleet-verdict-model-families-filter.patch
  bash tests/fleet-land-message.test.sh
  ```
