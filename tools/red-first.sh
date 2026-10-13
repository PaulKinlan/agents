#!/usr/bin/env bash
# tools/red-first.sh — Four-teeth red-first verification gate for agents-factory.
#
# WHAT THIS TOOL DOES (four teeth, all four required):
#   1. GREEN: run the change's CHANGED test files at the tip; print the pass/fail COUNT and the tree.
#   2. RED: construct a tree at the MERGE-BASE implementation (merge-base vs the base ref, default origin/main)
#      WITH THE CHANGE'S TEST FILES APPLIED, and run the same changed tests there.
#      VERIFY THE CONSTRUCTED TREE BY CONTENT BEFORE TRUSTING ITS NUMBER, in BOTH directions:
#      a string that exists ONLY in the new implementation must be ABSENT (expect 0) and
#      a label that exists ONLY in the new tests must be PRESENT (expect > 0).
#      "A partially applied patch looks exactly like a passing pin."
#   3. REPORT: green count, red count, the DISCRIMINATOR set (cases that fail on red and pass on green)
#      and the GUARD set (cases that pass on both revisions). An assertion in NEITHER set did not run —
#      printed explicitly.
#      REJECT the three vacuous forms loudly:
#        • a red run with ZERO failures (every new case is a guard: nothing pins the fix);
#        • a passing assertion whose captured value is EMPTY (a harness that cannot see its subject;
#          reported as a failure, not a pass);
#        • a red that cannot name its pre-fix object as a GIT SHA (not an opaque /tmp path).
#   4. RE-CUT ARTIFACT DELTA & NAMED FEATURES (coordinator requirement):
#      For a re-cut patch artifact, the delta against the previously reviewed artifact, per line,
#      reporting every removal the change did not intend to make — plus the count of each
#      NAMED FEATURE the artifact is supposed to carry (e.g. section-7 cases present, 11s case present).
#      WHY IT IS NOT ALREADY COVERED BY THE RED RUN: a patch artifact's own test files live in the
#      FLEET tree, not in the repo, so the repo gate is structurally blind to lost artifact coverage.
#      Tonight the tip that had silently dropped 8 test lines PASSED the repo fast gate — exit 0,
#      54 tests, tree f2c2eceaecf037e7d8ba079de48b1007ec18388b — because every test that could have
#      caught the loss was in the coverage that had been removed.
#      DO NOT USE A SHRINKING TOTAL AS THE TELL, because it does not hold: that same artifact's
#      added-line count went 342 -> 346 while it was dropping those 8 lines, since it also gained a new case.
#      Count per named feature and diff per line against the previously reviewed artifact; a total can grow while coverage falls.
#
# COST, verbatim:
#   one extra run of the CHANGED tests only, never the full suite, cached per tree, ~11s against a ~24s fast gate;
#   and "IF A REPO'S RED RUN COSTS MORE THAN ITS GREEN RUN, THAT IS A FINDING ABOUT THE SUITE'S SHAPE RATHER THAN A REASON TO SKIP THE CHECK."
#
# TWO INSTANCES, cited as evidence it is a process finding rather than one delivery:
#   agents-kq0r increment 1: 14 added assertions -> 13 discriminators + 1 invariant (11n, passes on both revisions);
#   patches/fleet-land-message-author-identity.patch: 21 added -> 16 discriminators + 6 guards, one of which
#   (38q5) asserts the defect's own headline property while passing on both revisions.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BASE="${GIT_BASE:-origin/main}"
TEST_FILES=()
EXPECT_ABSENT="${EXPECT_ABSENT:-}"
EXPECT_PRESENT="${EXPECT_PRESENT:-}"
ARTIFACT_PATH="${ARTIFACT_PATH:-}"
NAMED_FEATURES="${NAMED_FEATURES:-}"
ALLOW_REMOVALS="${ALLOW_REMOVALS:-0}"
TIMEOUT_SECS="${RED_FIRST_TIMEOUT:-180}"
NO_CACHE="${RED_FIRST_NO_CACHE:-0}"
CACHE_DIR="${FLEET_CHECKS_DIR:-/tmp/fleet-checks}"
TREES_ROOT="/tmp/red-first-trees"
DRY_RUN=0
EXPECT_ABSENT_SUPPLIED=0
if [ -n "$EXPECT_ABSENT" ]; then
  EXPECT_ABSENT_SUPPLIED=1
fi
EXPECT_PRESENT_SUPPLIED=0
if [ -n "$EXPECT_PRESENT" ]; then
  EXPECT_PRESENT_SUPPLIED=1
fi

# Parse arguments
while [ $# -gt 0 ]; do
  case "$1" in
    --base)
      BASE="$2"
      shift 2
      ;;
    --base=*)
      BASE="${1#--base=}"
      shift
      ;;
    --expect-absent)
      EXPECT_ABSENT="$2"
      EXPECT_ABSENT_SUPPLIED=1
      shift 2
      ;;
    --expect-absent=*)
      EXPECT_ABSENT="${1#--expect-absent=}"
      EXPECT_ABSENT_SUPPLIED=1
      shift
      ;;
    --expect-present)
      EXPECT_PRESENT="$2"
      EXPECT_PRESENT_SUPPLIED=1
      shift 2
      ;;
    --expect-present=*)
      EXPECT_PRESENT="${1#--expect-present=}"
      EXPECT_PRESENT_SUPPLIED=1
      shift
      ;;
    --artifact)
      ARTIFACT_PATH="$2"
      shift 2
      ;;
    --artifact=*)
      ARTIFACT_PATH="${1#--artifact=}"
      shift
      ;;
    --named-features)
      NAMED_FEATURES="$2"
      shift 2
      ;;
    --named-features=*)
      NAMED_FEATURES="${1#--named-features=}"
      shift
      ;;
    --allow-removals)
      ALLOW_REMOVALS=1
      shift
      ;;
    --timeout)
      TIMEOUT_SECS="$2"
      shift 2
      ;;
    --timeout=*)
      TIMEOUT_SECS="${1#--timeout=}"
      shift
      ;;
    --no-cache)
      NO_CACHE=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -*)
      echo "red-first: FAIL: unknown option: $1" >&2
      exit 2
      ;;
    *)
      # If BASE is default and $1 is a valid git ref and NOT an existing file
      if [ "$BASE" = "origin/main" ] && [ ! -e "$1" ] && git rev-parse --verify --quiet "$1^{commit}" >/dev/null 2>&1; then
        BASE="$1"
      else
        TEST_FILES+=("$1")
      fi
      shift
      ;;
  esac
done

echo "red-first: initializing gate (base=$BASE)"

# Step 0: Vacuous form 3 check — pre-fix object must be resolvable as a GIT SHA
if ! git rev-parse --verify --quiet "${BASE}^{commit}" >/dev/null 2>&1; then
  echo "red-first: FAIL: cannot name pre-fix object as a GIT SHA (base '$BASE' is not a valid commit ref)" >&2
  exit 1
fi

MERGE_BASE="$(git merge-base "$BASE" HEAD 2>/dev/null || true)"
if [ -z "$MERGE_BASE" ] || ! git rev-parse --verify --quiet "${MERGE_BASE}^{commit}" >/dev/null 2>&1; then
  echo "red-first: FAIL: cannot name pre-fix object as a GIT SHA (merge-base between '$BASE' and HEAD failed)" >&2
  exit 1
fi
PRE_FIX_SHA="$(git rev-parse --verify "${MERGE_BASE}^{commit}")"
echo "red-first: pre-fix object (merge-base): $PRE_FIX_SHA"

# Step 0b: Resolve changed test files if not provided on CLI
if [ "${#TEST_FILES[@]}" -eq 0 ]; then
  mapfile -t TEST_FILES < <(git diff --name-only "$PRE_FIX_SHA...HEAD" -- 'tests/test_*.py' 'tests/**/test_*.py' 2>/dev/null || true)
fi

if [ "${#TEST_FILES[@]}" -eq 0 ]; then
  echo "red-first: FAIL: no test files provided and no changed test files found between $PRE_FIX_SHA and HEAD" >&2
  exit 1
fi

# Verify every test file exists at tip
for tf in "${TEST_FILES[@]}"; do
  if [ ! -f "$tf" ]; then
    echo "red-first: FAIL: test file '$tf' does not exist at tip" >&2
    exit 1
  fi
done

# Map test file paths to module names
MODULES=()
for tf in "${TEST_FILES[@]}"; do
  mod="${tf#./}"
  mod="${mod%.py}"
  mod="${mod//\//.}"
  MODULES+=("$mod")
done

GREEN_TREE="$(git rev-parse HEAD^{tree})"
echo "red-first: green tree: $GREEN_TREE"
echo "red-first: test modules: ${MODULES[*]}"

if [ "$DRY_RUN" -eq 1 ]; then
  echo "red-first: dry-run complete: base=$BASE prefix=$PRE_FIX_SHA green_tree=$GREEN_TREE modules=${MODULES[*]}"
  exit 0
fi

mkdir -p "$CACHE_DIR"

# Helper function to run tests in a target directory with timeout and empty capture detection
run_test_suite() {
  local target_dir="$1"
  local output_json="$2"
  shift 2
  local mods=("$@")

  timeout -k 10 "$TIMEOUT_SECS" python3 - "$target_dir" "$output_json" "${mods[@]}" <<'PY'
import sys, os, io, json, re, time, unittest

target_dir = sys.argv[1]
output_json = sys.argv[2]
modules = sys.argv[3:]

sys.path.insert(0, target_dir)
os.chdir(target_dir)

# Pattern check for empty captured values.
# Catch both explicit got-empty forms and TAP empty ok captures.
EMPTY_PATTERNS = [
    re.compile(r'\(got\s*\)'),
    re.compile(r'\(got\s*[\'\"]\s*[\'\"]\)'),
    re.compile(r'\(got\s*None\)'),
    re.compile(r'captured\s*[:=]\s*(?:None|[\'\"]{2}|\(\))'),
    re.compile(r'ASSERTION_EMPTY_CAPTURE'),
]

class CapturingResult(unittest.TestResult):
    def __init__(self):
        super().__init__()
        self.passes = []
        self.failures_list = []
        self.errors_list = []
        self.empty_captures = []
        self._cur_stdout = None
        self._cur_stderr = None

    def startTest(self, test):
        super().startTest(test)
        self._cur_stdout = io.StringIO()
        self._cur_stderr = io.StringIO()
        self._old_stdout = sys.stdout
        self._old_stderr = sys.stderr
        sys.stdout = self._cur_stdout
        sys.stderr = self._cur_stderr

    def stopTest(self, test):
        out = self._cur_stdout.getvalue() if self._cur_stdout else ""
        err = self._cur_stderr.getvalue() if self._cur_stderr else ""
        sys.stdout = self._old_stdout
        sys.stderr = self._old_stderr
        super().stopTest(test)
        combined = (out + "\n" + err).strip()
        for pat in EMPTY_PATTERNS:
            m = pat.search(combined)
            if m:
                matched_snippet = m.group(0)
                self.empty_captures.append((test.id(), matched_snippet, combined))
                break

    def addSuccess(self, test):
        super().addSuccess(test)
        self.passes.append(test.id())

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.failures_list.append((test.id(), self._exc_info_to_string(err, test)))

    def addError(self, test, err):
        super().addError(test, err)
        self.errors_list.append((test.id(), self._exc_info_to_string(err, test)))

loader = unittest.TestLoader()
suite = unittest.TestSuite()
for mod in modules:
    try:
        suite.addTests(loader.loadTestsFromName(mod))
    except Exception as exc:
        # Load failure recorded as an error
        res_data = {
            "modules": modules,
            "passes": [],
            "failures": [],
            "errors": [{"id": mod, "traceback": f"Import error loading {mod}: {exc}"}],
            "empty_captures": [],
            "elapsed": 0.0,
            "rc": 1,
        }
        os.makedirs(os.path.dirname(os.path.abspath(output_json)), exist_ok=True)
        with open(output_json, "w", encoding="utf-8") as f:
            json.dump(res_data, f, indent=2)
        sys.exit(1)

start_time = time.monotonic()
collector = CapturingResult()
suite.run(collector)
elapsed = time.monotonic() - start_time

# If an empty capture occurred on a passing test, convert that pass to a failure!
# Per requirement: "note explicitly that a fixture producing an empty capture must be reported as a failure, not a pass"
final_passes = []
empty_capture_fails = []
for p in collector.passes:
    empty_match = next((ec for ec in collector.empty_captures if ec[0] == p), None)
    if empty_match:
        test_id, pat, log = empty_match
        msg = f"FAIL (empty capture): passing assertion whose captured value is EMPTY: {pat}"
        empty_capture_fails.append({"id": test_id, "pattern": pat, "log": log, "message": msg})
    else:
        final_passes.append(p)

all_failures = [{"id": f[0], "traceback": f[1]} for f in collector.failures_list]
all_errors = [{"id": e[0], "traceback": e[1]} for e in collector.errors_list]
for ec in empty_capture_fails:
    all_failures.append({"id": ec["id"], "traceback": ec["message"], "empty_capture": True})

res_data = {
    "modules": modules,
    "passes": final_passes,
    "failures": all_failures,
    "errors": all_errors,
    "empty_captures": empty_capture_fails,
    "elapsed": elapsed,
    "rc": 0 if (len(all_failures) == 0 and len(all_errors) == 0) else 1,
}

os.makedirs(os.path.dirname(os.path.abspath(output_json)), exist_ok=True)
with open(output_json, "w", encoding="utf-8") as f:
    json.dump(res_data, f, indent=2)

sys.exit(res_data["rc"])
PY
}

# ==============================================================================
# TOOTH 1: GREEN RUN
# ==============================================================================
echo "--- Tooth 1: GREEN run at tip ---"
GREEN_CACHE_FILE="$CACHE_DIR/${GREEN_TREE}-green.json"
green_rc=0

if [ "$NO_CACHE" -eq 0 ] && [ -f "$GREEN_CACHE_FILE" ]; then
  echo "red-first: using cached green run ($GREEN_CACHE_FILE)"
else
  run_test_suite "$ROOT" "$GREEN_CACHE_FILE" "${MODULES[@]}" || green_rc=$?
fi

green_passes="$(jq -r '.passes | length' "$GREEN_CACHE_FILE")"
green_fails="$(jq -r '.failures | length' "$GREEN_CACHE_FILE")"
green_errors="$(jq -r '.errors | length' "$GREEN_CACHE_FILE")"
green_empty_caps="$(jq -r '.empty_captures | length' "$GREEN_CACHE_FILE")"
green_elapsed="$(jq -r '.elapsed' "$GREEN_CACHE_FILE")"

echo "red-first: green run: $green_passes passed, $green_fails failed, $green_errors errors (${green_elapsed}s) (tree: $GREEN_TREE)"

if [ "$green_empty_caps" -gt 0 ]; then
  echo "red-first: FAIL: vacuous pass detected in green run (passing assertion whose captured value is EMPTY):" >&2
  jq -r '.empty_captures[] | "  " + .id + ": " + .pattern' "$GREEN_CACHE_FILE" >&2
  exit 1
fi

if [ "$green_fails" -gt 0 ] || [ "$green_errors" -gt 0 ]; then
  echo "red-first: FAIL: green run failed at tip ($green_fails failures, $green_errors errors). Tip must pass to run red-first." >&2
  jq -r '.failures[] | "  FAIL: " + .id + "\n" + .traceback' "$GREEN_CACHE_FILE" >&2
  jq -r '.errors[] | "  ERROR: " + .id + "\n" + .traceback' "$GREEN_CACHE_FILE" >&2
  exit 1
fi

# ==============================================================================
# TOOTH 2: RED TREE CONSTRUCTION & CONTENT VERIFICATION
# ==============================================================================
echo "--- Tooth 2: RED tree construction at merge-base with test files applied ---"

# Construct tree object via git index
TMP_INDEX="$(mktemp /tmp/red-first-idx.XXXXXX)"
GIT_INDEX_FILE="$TMP_INDEX" git read-tree "$PRE_FIX_SHA"

for tf in "${TEST_FILES[@]}"; do
  # Entry from tip HEAD
  entry="$(git ls-tree HEAD "$tf" 2>/dev/null || true)"
  if [ -n "$entry" ]; then
    mode="$(awk '{print $1}' <<< "$entry")"
    blob="$(awk '{print $3}' <<< "$entry")"
    GIT_INDEX_FILE="$TMP_INDEX" git update-index --add --cacheinfo "$mode,$blob,$tf"
  elif [ -f "$tf" ]; then
    blob="$(git hash-object -w "$tf")"
    GIT_INDEX_FILE="$TMP_INDEX" git update-index --add --cacheinfo 100644,"$blob","$tf"
  fi
done

RED_TREE="$(GIT_INDEX_FILE="$TMP_INDEX" git write-tree)"
rm -f "$TMP_INDEX"

echo "red-first: red tree: $RED_TREE"

RED_DIR="$TREES_ROOT/$RED_TREE"
if [ ! -d "$RED_DIR" ]; then
  mkdir -p "$TREES_ROOT"
  RED_COMMIT="$(git commit-tree "$RED_TREE" -p "$PRE_FIX_SHA" -m "red-first-constructed-tree-$RED_TREE")"
  git worktree add "$RED_DIR" "$RED_COMMIT" --detach --quiet
fi

# Content verification in BOTH directions
echo "--- Content verification of constructed red tree ---"

# Direction 1: a string that exists ONLY in the new implementation must be ABSENT (expect 0)
if [ -z "$EXPECT_ABSENT" ]; then
  # Auto-derive candidate from git diff of non-test files
  diff_additions="$(git diff "$PRE_FIX_SHA...HEAD" -- . ':(exclude)tests*' ':(exclude)docs*' ':(exclude)reports*' "${TEST_FILES[@]/#/:(exclude)}" | sed -n 's/^+[^+[:space:]].*/&/p' || true)"
  if [ -n "$diff_additions" ]; then
    # Pick a non-trivial line or distinctive token
    while IFS= read -r line; do
      cleaned="${line#+}"
      cleaned="$(echo "$cleaned" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
      if [ ${#cleaned} -ge 8 ] && [[ ! "$cleaned" =~ ^(#|//|/\*|\*) ]]; then
        # Check that this string does not exist in PRE_FIX_SHA
        if ! git show "$PRE_FIX_SHA" | grep -Fq "$cleaned" 2>/dev/null; then
          EXPECT_ABSENT="$cleaned"
          break
        fi
      fi
    done <<< "$diff_additions"
  fi
fi

# Direction 2: a label that exists ONLY in the new tests must be PRESENT (expect > 0)
if [ -z "$EXPECT_PRESENT" ]; then
  # Auto-derive candidate from added test methods in the test files
  diff_test_additions="$(git diff "$PRE_FIX_SHA...HEAD" -- "${TEST_FILES[@]}" | sed -n 's/^+.*def \(test_[a-zA-Z0-9_]*\).*/\1/p' || true)"
  if [ -n "$diff_test_additions" ]; then
    EXPECT_PRESENT="$(echo "$diff_test_additions" | head -n 1)"
  else
    # Fallback to the test file name or a known test method inside the test file
    test_func="$(grep -rn "def test_" "${TEST_FILES[0]}" 2>/dev/null | head -n 1 | sed 's/.*def //; s/(.*//' || true)"
    EXPECT_PRESENT="${test_func:-${TEST_FILES[0]}}"
  fi
fi

# Exclusivity precondition checks:
# 1. Delta justification: caller-supplied markers must appear in added lines of their respective delta paths
# 2. Direction 1: absent marker must be PRESENT in the green tree (count > 0)
# 3. Direction 2: present marker must be ABSENT from the pre-fix test tree (count == 0)
precondition_failed=0

# Delta justification checks for caller-supplied markers
if [ "$EXPECT_ABSENT_SUPPLIED" -eq 1 ] && [ -n "$EXPECT_ABSENT" ]; then
  delta_non_test_additions="$(git diff -U0 "$PRE_FIX_SHA...HEAD" -- . ':(exclude)tests*' ':(exclude)docs*' ':(exclude)reports*' "${TEST_FILES[@]/#/:(exclude)}" 2>/dev/null | grep '^+' | grep -v '^+++' || true)"
  if ! grep -Fq "$EXPECT_ABSENT" <<< "$delta_non_test_additions"; then
    echo "red-first: FAIL: content verification precondition failed: absent marker '$EXPECT_ABSENT' is not justified by delta (not found in added lines of non-test paths)" >&2
    echo "red-first:   A caller-supplied marker must be justified by the delta; exclusivity precondition is unverified" >&2
    precondition_failed=1
  fi
fi

if [ "$EXPECT_PRESENT_SUPPLIED" -eq 1 ] && [ -n "$EXPECT_PRESENT" ]; then
  delta_test_additions="$(git diff -U0 "$PRE_FIX_SHA...HEAD" -- 'tests*' "${TEST_FILES[@]}" 2>/dev/null | grep '^+' | grep -v '^+++' || true)"
  if ! grep -Fq "$EXPECT_PRESENT" <<< "$delta_test_additions"; then
    echo "red-first: FAIL: content verification precondition failed: present marker '$EXPECT_PRESENT' is not justified by delta (not found in added lines of test paths)" >&2
    echo "red-first:   A caller-supplied marker must be justified by the delta; exclusivity precondition is unverified" >&2
    precondition_failed=1
  fi
fi

if [ -n "$EXPECT_ABSENT" ]; then
  green_absent_matches=0
  green_absent_output="$(git grep -n -F "$EXPECT_ABSENT" "$GREEN_TREE" -- . ':(exclude)tests*' ':(exclude)docs*' ':(exclude)reports*' "${TEST_FILES[@]/#/:(exclude)}" 2>/dev/null || true)"
  if [ -n "$green_absent_output" ]; then
    green_absent_matches="$(printf '%s\n' "$green_absent_output" | wc -l)"
  fi
  echo "red-first: content-verification precondition (expect > 0 in green): checking '$EXPECT_ABSENT' in green tree (excl tests/) -> count: $green_absent_matches"
  if [ "$green_absent_matches" -eq 0 ]; then
    echo "red-first: FAIL: content verification precondition failed: absent marker '$EXPECT_ABSENT' was NOT found in green tree (expected > 0 in green implementation, got 0)" >&2
    echo "red-first:   A marker that does not exist anywhere trivially satisfies absence; exclusivity precondition is unverified" >&2
    precondition_failed=1
  fi
fi

if [ -n "$EXPECT_PRESENT" ]; then
  prefix_present_matches=0
  prefix_test_output="$(git grep -n -F "$EXPECT_PRESENT" "$PRE_FIX_SHA" -- 'tests*' "${TEST_FILES[@]}" 2>/dev/null || true)"
  if [ -n "$prefix_test_output" ]; then
    prefix_present_matches="$(printf '%s\n' "$prefix_test_output" | wc -l)"
  fi
  echo "red-first: content-verification precondition (expect 0 in pre-fix): checking '$EXPECT_PRESENT' in pre-fix test tree -> count: $prefix_present_matches"
  if [ "$prefix_present_matches" -ne 0 ]; then
    echo "red-first: FAIL: content verification precondition failed: present marker '$EXPECT_PRESENT' exists in pre-fix test tree (expected 0 in pre-fix tests, got $prefix_present_matches)" >&2
    echo "red-first:   A marker present in both revisions does not prove new tests were applied; exclusivity precondition is unverified" >&2
    precondition_failed=1
  fi
else
  echo "red-first: FAIL: content verification failed: no test label specified or found for expect > 0 check" >&2
  exit 1
fi

if [ "$precondition_failed" -ne 0 ]; then
  echo "red-first: FAIL: content verification failed: neither-direction-verified (unverifiable marker preconditions)" >&2
  exit 1
fi

# Direction 1 check in red implementation tree (expect 0)
if [ -n "$EXPECT_ABSENT" ]; then
  absent_matches=0
  absent_output="$(grep -rn -F "$EXPECT_ABSENT" "$RED_DIR" --exclude-dir=tests --exclude-dir=docs --exclude-dir=reports --exclude-dir=.git 2>/dev/null || true)"
  if [ -n "$absent_output" ]; then
    absent_matches="$(printf '%s\n' "$absent_output" | wc -l)"
  fi
  echo "red-first: content-verification (expect 0): grep -rnF '$EXPECT_ABSENT' '$RED_DIR' (excl tests/) -> count: $absent_matches"
  if [ "$absent_matches" -ne 0 ]; then
    echo "red-first: FAIL: content verification failed: string '$EXPECT_ABSENT' exists in red implementation tree (expected 0, got $absent_matches)" >&2
    echo "red-first:   A partially applied patch looks exactly like a passing pin: new implementation leaked into red tree" >&2
    exit 1
  fi
else
  echo "red-first: content-verification (expect 0): no implementation changes to verify (pure test addition)"
fi

# Direction 2 check in red test tree (expect > 0)
present_matches=0
present_output="$(grep -rn -F "$EXPECT_PRESENT" "$RED_DIR/tests" 2>/dev/null || true)"
if [ -n "$present_output" ]; then
  present_matches="$(printf '%s\n' "$present_output" | wc -l)"
fi
echo "red-first: content-verification (expect > 0): grep -rnF '$EXPECT_PRESENT' '$RED_DIR/tests' -> count: $present_matches"
if [ "$present_matches" -eq 0 ]; then
  echo "red-first: FAIL: content verification failed: label '$EXPECT_PRESENT' was NOT found in red tree tests (expected > 0, got 0)" >&2
  echo "red-first:   A partially applied patch looks exactly like a passing pin: new tests failed to apply to red tree" >&2
  exit 1
fi

# Run the SAME tests on the RED tree
RED_CACHE_FILE="$CACHE_DIR/${RED_TREE}-red.json"
red_rc=0

if [ "$NO_CACHE" -eq 0 ] && [ -f "$RED_CACHE_FILE" ]; then
  echo "red-first: using cached red run ($RED_CACHE_FILE)"
else
  run_test_suite "$RED_DIR" "$RED_CACHE_FILE" "${MODULES[@]}" || red_rc=$?
fi

red_passes="$(jq -r '.passes | length' "$RED_CACHE_FILE")"
red_fails="$(jq -r '.failures | length' "$RED_CACHE_FILE")"
red_errors="$(jq -r '.errors | length' "$RED_CACHE_FILE")"
red_empty_caps="$(jq -r '.empty_captures | length' "$RED_CACHE_FILE")"
red_elapsed="$(jq -r '.elapsed' "$RED_CACHE_FILE")"

echo "red-first: red run: $red_passes passed, $red_fails failed, $red_errors errors (${red_elapsed}s) (tree: $RED_TREE)"

# Vacuous form 2 check in red run
if [ "$red_empty_caps" -gt 0 ]; then
  echo "red-first: FAIL: vacuous pass detected in red run (passing assertion whose captured value is EMPTY):" >&2
  jq -r '.empty_captures[] | "  " + .id + ": " + .pattern' "$RED_CACHE_FILE" >&2
  exit 1
fi

# Vacuous form 1 check: a red run with ZERO failures
total_red_failures=$((red_fails + red_errors))
if [ "$total_red_failures" -eq 0 ]; then
  echo "red-first: FAIL: vacuous red run: 0 failures on pre-fix tree (no test discriminates the fix; all are guards or ran nothing)" >&2
  exit 1
fi

# ==============================================================================
# TOOTH 3: REPORT DISCRIMINATOR, GUARD, AND NEITHER SETS
# ==============================================================================
echo "--- Tooth 3: REPORT ---"

# Extract sets using Python helper
python3 - "$GREEN_CACHE_FILE" "$RED_CACHE_FILE" <<'PY'
import sys, json

green_file, red_file = sys.argv[1], sys.argv[2]
with open(green_file, encoding="utf-8") as f:
    gdata = json.load(f)
with open(red_file, encoding="utf-8") as f:
    rdata = json.load(f)

g_passes = set(gdata.get("passes", []))
g_fails = {f["id"] for f in gdata.get("failures", [])}
g_errors = {e["id"] for e in gdata.get("errors", [])}
g_all = g_passes | g_fails | g_errors

r_passes = set(rdata.get("passes", []))
r_fails = {f["id"] for f in rdata.get("failures", [])}
r_errors = {e["id"] for e in rdata.get("errors", [])}
r_all_fails = r_fails | r_errors
r_all = r_passes | r_all_fails

# DISCRIMINATORS: failed on red, passed on green
discriminators = sorted(r_all_fails & g_passes)

# GUARDS: passed on both red and green
guards = sorted(r_passes & g_passes)

# NEITHER: executed but in neither set (e.g. failed on green, or ran on only one revision)
neither = sorted((g_all | r_all) - set(discriminators) - set(guards))

print(f"DISCRIMINATOR set ({len(discriminators)} cases):")
for d in discriminators:
    print(f"  • {d}")

print(f"\nGUARD set ({len(guards)} cases):")
for g in guards:
    print(f"  • {g}")

print(f"\nNEITHER set ({len(neither)} cases):")
if neither:
    for n in neither:
        print(f"  • {n} (did not run or failed on green)")
else:
    print("  none — all executed assertions are accounted for as discriminators or guards")

if len(discriminators) == 0:
    print("\nred-first: FAIL: DISCRIMINATOR set is empty (0 tests pin the fix)")
    sys.exit(1)
PY

# ==============================================================================
# TOOTH 4: RE-CUT ARTIFACT DELTA & NAMED FEATURE COUNTS
# ==============================================================================
echo "--- Tooth 4: Re-cut artifact delta & named feature check ---"

# Resolve patch artifact: either explicitly passed or changed under patches/
PATCH_ARTIFACTS=()
if [ -n "$ARTIFACT_PATH" ]; then
  PATCH_ARTIFACTS+=("$ARTIFACT_PATH")
else
  mapfile -t detected_patches < <(git diff --name-only --diff-filter=M "$PRE_FIX_SHA...HEAD" -- 'patches/*.patch' 2>/dev/null || true)
  if [ "${#detected_patches[@]}" -gt 0 ]; then
    PATCH_ARTIFACTS=("${detected_patches[@]}")
  fi
fi

if [ "${#PATCH_ARTIFACTS[@]}" -gt 0 ]; then
  for art in "${PATCH_ARTIFACTS[@]}"; do
    echo "red-first: inspecting patch artifact: $art"
    if [ ! -f "$art" ]; then
      echo "red-first: FAIL: patch artifact '$art' does not exist" >&2
      exit 1
    fi

    # Check per-line removals against the previously reviewed artifact at PRE_FIX_SHA
    if git cat-file -e "$PRE_FIX_SHA:$art" 2>/dev/null; then
      # The artifact existed in the pre-fix revision: compute per-line removals
      removed_lines="$(git diff -U0 "$PRE_FIX_SHA...HEAD" -- "$art" | grep '^-' | grep -v '^---' || true)"
      removed_count=0
      if [ -n "$removed_lines" ]; then
        removed_count="$(printf '%s\n' "$removed_lines" | wc -l)"
      fi
      echo "red-first: artifact delta for $art vs $PRE_FIX_SHA: $removed_count removed line(s)"
      if [ "$removed_count" -gt 0 ]; then
        echo "red-first: removed lines from previously reviewed artifact:"
        printf '%s\n' "$removed_lines" | sed 's/^/  /'
        if [ "$ALLOW_REMOVALS" -ne 1 ]; then
          echo "red-first: FAIL: unintended removal detected in re-cut artifact '$art' ($removed_count lines removed)." >&2
          echo "red-first:   A re-cut artifact must report every removal the change did not intend to make." >&2
          echo "red-first:   Pass --allow-removals if these removals were deliberate." >&2
          exit 1
        fi
      fi
    else
      echo "red-first: artifact $art is new in this branch (not a re-cut of an existing pre-fix artifact)"
    fi

    # Count each NAMED FEATURE the artifact is supposed to carry
    if [ -n "$NAMED_FEATURES" ]; then
      IFS=',' read -ra FEAT_LIST <<< "$NAMED_FEATURES"
      for feat in "${FEAT_LIST[@]}"; do
        feat="$(echo "$feat" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
        [ -z "$feat" ] && continue
        tip_feat_count="$(grep -c "$feat" "$art" 2>/dev/null || true)"
        echo "red-first: named feature '$feat' in $art: count = $tip_feat_count"
        if [ "$tip_feat_count" -eq 0 ]; then
          echo "red-first: FAIL: re-cut artifact '$art' is missing required named feature '$feat' (count: 0)" >&2
          exit 1
        fi
      done
    fi
  done
else
  echo "red-first: no patch artifacts changed or specified (tooth 4 skipped)"
fi

echo "======================================================================"
echo "red-first: VERDICT: PASS (all four teeth satisfied)"
echo "======================================================================"
exit 0
