## `fleet-oracle-candidate-rule.patch` (agents-0xm2)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `remote/check-coverage.py` (lines 649-655, 670-675)
  - `tests/check-coverage.test.sh` (new unit tests, section 8)
- **Baseline file hash:**
  `64b25262dbbec0357cc896f1663a64ce3f200cd23294930bef0b0183e52d91a3  remote/check-coverage.py`
- **Problem Statement (agents-0xm2, agents-hbz3):**
  The coverage oracle (`remote/check-coverage.py`) previously maintained two divergent consumer identification rules:
  1. `find_candidate_tests_for_file()` restricted import checking with `elif len(stem) >= 4:`, completely skipping `has_import_reference()` for short-stem modules (e.g. `api`, `cli`, `db`, `fs`, `io`, `ui`, `log`). When a short-stem module changed and its namesake suite ran, candidate discovery missed real importing test suites, causing `omitted_c` to be empty and the oracle to fall back to name correspondence. The oracle reported `covered=True` and published `unmapped=[]`, silently concealing unexecuted real importers (a silent true, not a false alarm).
  2. Simultaneously, `find_candidate_tests_for_file()` used a loose subprocess matching regex `subp_pattern` matching bare `\b<stem>\b` within any subprocess or `run(...)` argument. For `lib/sandbox.py`, this falsely harvested any test passing the flag `--sandbox` to commands (e.g. `bwrap --sandbox`), producing 5 phantom omitted suites in `agents-hbz3` (`test_hermetic_env.py`, `test_path_security.py`, `test_pr_fixer_prepass.py`, `test_prepass_pin_boundary.py`, `test_vuln_verify_prepass.py`) that do not import `lib/sandbox.py`.
- **Changes:**
  1. **Consolidated Candidate Import Discovery:** In `remote/check-coverage.py`, remove the `len(stem) >= 4` gate in `find_candidate_tests_for_file()`, delegating all import-based candidate discovery directly to `has_import_reference(content, stem)` across all stem lengths. Short-stem modules now discover all real importing test suites.
  2. **Bounded Subprocess Invocation Matching:** In `subp_pattern`, constrain matching to actual execution of `file_path`, `base`, or bare stem bounded by `(?<![\w-])` and `(?![a-zA-Z0-9_])` (`(?<![\w-])<stem>(?:\.[a-z]+)?(?![a-zA-Z0-9_])`). This excludes command-line argument flags (e.g. `--sandbox` or `-sandbox`) from falsely creating phantom omissions while preserving genuine module-style (`python -m lib.sandbox`), extensionless (`scripts/api`), or transpiled (`scripts/sandbox.js`) invocations.
  3. **Unit Tests:** In `tests/check-coverage.test.sh`, add Section 8 asserting:
     - 8a: Short-stem module (`lib/api.py`, length 3) with an omitted importer (`tests/test_client.py`) is accurately recognized as an omitted candidate rather than reporting a silent true.
     - 8b: Short-stem file is flagged as unmapped when its importing suite is omitted.
     - 8c: Subprocess option flag `--sandbox` does not create phantom omitted consumers for `lib/sandbox.py`.
     - 8d: `lib/sandbox.py` is flagged as unmapped when module-style runner (`python3 -m lib.sandbox`) is omitted.
     - 8e: Module-style subprocess invocation (`python3 -m lib.sandbox`) is detected as omitted candidate.
     - 8f: Extensionless subprocess invocation (`node scripts/api`) is detected as omitted candidate.
- **Consequences for Every Project Using the Oracle:**
  - **Separation from agents-ul9v:** This patch addresses candidate discovery and subprocess invocation matching in `find_candidate_tests_for_file()`. It is strictly separate from the reporting/relabeling changes proposed in `agents-ul9v` (partial omission label distinction). Neither change depends on the other.
  - **Candidate Set Shift:** Because candidate discovery now delegates to `has_import_reference` for all stem lengths and bounds subprocess invocations against argument flags, the candidate set changes:
    - *Short-stem modules (`len < 4`)* gain candidate suites for all tests that actually import them. Fast gates across fleet projects will now loudly report previously hidden omissions when importers are skipped.
    - *Flag-named modules* (like `sandbox`) lose phantom candidate suites, eliminating false omission warnings on unrelated test files that merely pass command-line argument flags (e.g. `--sandbox`).
    - *Module-style and extensionless executors* (e.g. `python3 -m lib.sandbox`, `node scripts/api`) retain candidate recognition without being swallowed or over-narrowed.
  - **Harmonization with In-Repo Pins:** The oracle's candidate discovery rule now uses the exact same definition of module consumption as `tests/test_fast_gate_consumer_coverage.py` (`has_import_reference`), resolving cross-tool divergence permanently.
- **Verification:**
  - `tests/check-coverage.test.sh`: 27/27 tests pass.
  - Measured against `agents-factory` commit `371b0bc` (`lib/sandbox.py`): unpatched oracle reported 20 omitted suites (including the 5 phantoms); patched oracle reports exactly 15 omitted suites matching `has_import_reference` and `agents-pdth`'s allowlist 100%.
  - Clean patch application verified via `git apply --check` against pristine `~/fleet`.
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-oracle-candidate-rule.patch
  bash tests/check-coverage.test.sh
  ```
