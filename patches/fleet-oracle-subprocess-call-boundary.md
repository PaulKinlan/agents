## `fleet-oracle-subprocess-call-boundary.patch` (agents-3avt)

- **Target repository:** `PaulKinlan/fleet`
- **Target files:**
  - `remote/check-coverage.py` (the subprocess/CLI arm of `find_candidate_tests_for_file`,
    `subp_pattern` at lines 675-677; 9 lines added, 1 replaced)
  - `tests/check-coverage-subprocess.test.sh` (new, 181 lines - the arm's own suite)
- **Baseline file hash:**
  `d60e9ad23d460ac1a3b8cb73c46c19eeb4b288719be339c1a2b134c34dc40892  remote/check-coverage.py`
- **Problem Statement (agents-3avt, from investigator inv-4sbk's reading of the cached fast record
  `41cb00d9f7a87b903fdb1ebc4852fad968bf8657.fast.json`):**

  A test helper whose **signature or call site merely names the changed stem** was published as a
  *consumer* of the changed module. `subp_pattern`'s alternatives were unbounded, so `run` matched
  inside `_run(`, `exec` inside `_exec(`, and `store.process_run(` matched `run(`. Reproduced
  verbatim on this repo's own tree - `lib/findings.py` changed, the gate having run only
  `tests/test_findings.py`:

  ```
  BEFORE: omitted: [tests/test_factory_core.py, tests/test_path_security.py,
                    tests/test_perf_review.py, tests/test_pr_fixer_prepass.py]
          unmapped: [lib/findings.py]
  ```

  `tests/test_path_security.py` and `tests/test_pr_fixer_prepass.py` import nothing from
  `lib/findings.py` (`grep -nE 'import .*findings|from .*findings'` -> NO MATCH for both). Both are
  matched by one line only - `def _run(self, sandbox: Path, target: Path, findings) -> dict:` - which
  is a *parameter list*, not a call. `lib/findings.py` holds the publication boundary, so an inflated
  `omitted` there is the worst place to have it: the list is the only signal that says "this arm is
  incomplete", and a list containing non-consumers is a list readers learn to discount.

- **Changes (two rules, each with the case that fails without it):**
  1. **A call alternative must be a whole word.** `\b` before the alternatives group.
     `_run(`/`_exec(`/`store.process_run(` are no longer read as calls. This is the rule that fixes
     both reported cases: the signature *and* the call site `self._run(sandbox, target)` (whose
     argument is a variable that happens to be named `sandbox`).
  2. **A `def` parameter list is never an invocation.** The cleaned text is stripped of
     `def`/`async def` signatures before the scan, so a helper named exactly `run(...)` that merely
     takes the stem as a parameter is not a call either. Only the signature is removed; the body, and
     every genuine invocation anywhere else in the file, is untouched.
  3. **`tests/check-coverage-subprocess.test.sh`** pins both rules and the four true positives they
     must not lose: a genuine executor under a suffixed name (`self.go` ->
     `subprocess.run([sys.executable, "-m", "lib.findings"])`), a genuine importer, a *real* omission
     that must still read `unmapped`, and the verb list itself (`subprocess.check_output` is the
     least-used spelling, so it is the one a hand-edit is most likely to drop).

- **This is a boundary, not a narrowing** - and the distinction is measured, not asserted:
  - The **reference** alternative (`file_path | base | \bstem\b`) is untouched. Bounding the *stem*
    against `--sandbox`-style flags (`bwrap --sandbox`) is `fleet-oracle-candidate-rule.patch`'s
    separate, unapplied change; the two fix different phantom classes and neither subsumes the other.
  - Corpus-wide diff of the arm alone, over this repo's own suite files (the 85 `test_*.py` files
    under `tests/`, which is the oracle's own test-filename rule) against 43 modules (`tests/` +
    `lib/` + `agents/`): **63 match sites before, 9 pairs lost, 0 gained**, and
    every lost site is an identifier suffix - `def _run(`, `self._run(`, `store.process_run(`.
    `0` sites are of the shape "suffixed verb whose argument is a literal module path" (e.g.
    `self._run("lib/findings.py")`), which is the only loss class this boundary could have.

- **Measured before/after:**
  - The reported case: `omitted` **4 -> 2** (exactly the two non-consumers), while `unmapped` **keeps
    naming `lib/findings.py`** - the two genuine omissions that remain (`test_factory_core.py`,
    `test_perf_review.py`) are real, so the warning keeps its meaning. The patch removes the noise,
    not the signal.
  - This repo's real corpus (its own `tests/` and `lib/` trees copied whole - 89 `.py` files, 85 of
    them suites - `lib/findings.py` changed, namesake log only): `omitted` **12 -> 10**.
  - `tests/check-coverage.test.sh`: **21 passed / 0 failed** on both the pristine and the patched
    oracle - the change is invisible to the 21 existing cases.
  - `tests/check-coverage-subprocess.test.sh`: **9 passed / 0 failed** patched; **4 passed /
    5 failed** against the pristine oracle, and the five failures are the five defect cases (1b-1e,
    1h) - the suite fails for the right reason before it passes for the right reason after.
- **Cost, measured rather than asserted** (the oracle runs inside the fast gate, so this is stated):
  on that corpus with one changed file, 3 oracle runs take **1.39s -> 1.58s**, i.e. about
  +60ms per invocation for one extra regex pass per candidate file. On the 6-file fixture, 5 runs
  take 0.48s -> 0.58s.
- **Stated limits** (both measured at 0 sites in this repo; listed so a green is not overread):
  1. A suite whose *only* reference to a module is a literal path passed to a locally-defined helper
     (`self._run("lib/findings.py")`) is no longer counted by this arm. Import-based discovery is
     unaffected, so such a suite is still found when it imports the module - which is the normal case.
  2. The signature strip also removes a `def` parameter list that contains a *genuine* invocation as
     a default argument (`def f(x=run("lib/x.py"))`). No such site exists in this tree; it is
     pathological and would be surprising in a test.
- **Delivery interaction with `fleet-oracle-candidate-rule.patch` (agents-0xm2, pending): REAL, and
  stated here rather than left for the hub to discover.** Both deliveries change the same three-line
  statement, so they share three lines of context and cannot be applied blind in sequence - verified:
  applying `fleet-oracle-candidate-rule.patch` first and then this patch fails with
  `error: patch failed: remote/check-coverage.py:672 / patch does not apply`. **The two changes are
  textually independent (different lines) and the resolved result is verified to pass both suites.**
  See "Hub Application" below for the exact statement; the *test* files do not interact (this
  delivery adds a new file, that one appends section 8 to `tests/check-coverage.test.sh`).
- **Verification recipe:**
  ```bash
  # pristine oracle: the new suite must FAIL (5 defect cases)
  COV_OVERRIDE=~/fleet/remote/check-coverage.py bash tests/check-coverage-subprocess.test.sh
  # patched: both suites green
  bash tests/check-coverage.test.sh && bash tests/check-coverage-subprocess.test.sh
  # the reported case, before vs after: omitted 4 -> 2, unmapped unchanged
  python3 remote/check-coverage.py <log> <repo> <sha> ""
  ```
- **Hub Application:**
  ```bash
  cd ~/fleet
  git apply /path/to/fleet-oracle-subprocess-call-boundary.patch   # clean against pristine ~/fleet
  bash tests/check-coverage.test.sh && bash tests/check-coverage-subprocess.test.sh
  ```
  If `fleet-oracle-candidate-rule.patch` is applied **first** (or was already applied), this patch's
  single hunk will reject on context. The resolution is the three lines below - the only edit - and
  the result is verified green on both suites (27 + 9) *and* on the reported case (`omitted` = 2):

  ```python
                    subp_pattern = (
                        r'\b(?:subprocess|Popen|exec|spawn|run|fork|call|check_output|system)\s*\([^)]*?'
                        r'(?:' + re.escape(file_path) + r'|' + re.escape(base) + r'|(?<![\w-])' + re.escape(stem) + r'(?:\.[a-z]+)?(?![a-zA-Z0-9_]))'
  ```

  (Indentation is copied verbatim from the resolved file - 20 spaces for `subp_pattern = (`,
  24 for each alternative - so the block can be pasted as-is.)
  plus the one added line above it (`cleaned = re.sub(r'\b(?:async\s+)?def\s+[A-Za-z_]\w*\s*\([^)]*\)', ' ', cleaned)`)
  and the new test file, which applies without interaction in either order.
