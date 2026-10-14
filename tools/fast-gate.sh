#!/usr/bin/env bash
# Fast gate for agents-factory (agents-651): run only the tests a branch touches.
#
# The full gate (`python3 -m unittest discover -s tests -v`) is the merger's one-time
# per-landing job. Implementers run `fleet-check --fast`, which invokes this script via
# CHECK_FAST_CMD. It is deterministic and bounded (never the whole suite) and fails loudly
# (non-zero) when a change maps to a test file that does not exist, so a missing test cannot
# silently pass.
#
# Resolution (first applicable):
#   1. changed test files vs the base branch (default origin/main) run as-is;
#   2. changed lib/*.py map to tests/test_<name>.py (scheduler -> test_schedules.py), and
#      the `factory` dispatcher maps to the core + truth harnesses;
#   3. changed paths on the explicit ignore list (each a deliberate case arm with a
#      reason, agents-9nir) fall back to a bounded smoke subset
#      (tests/test_factory_core.py); a changed file matching NEITHER a mapping arm NOR
#      the ignore list fails loudly, named - a file nobody has mapped must be seen.
#
# A changed lib module whose mapped test file is absent exits non-zero. Override the base
# branch with GIT_BASE=<ref> (used by tests).
#
# Wiring (per-VM ~/.fleet/check.conf, alongside the full-gate CHECK_CMD):
#   CHECK_FAST_CMD="bash tools/fast-gate.sh"
#   CHECK_FAST_TIMEOUT=180
set -euo pipefail

# WHICH ENVIRONMENT THIS VERDICT IS ABOUT (agents-u4k7). Printed on STDERR, not stdout: the fast
# gate's stdout is a machine-readable contract - the dry run IS the resolved suite list, and
# tests/test_fast_gate_mapping.py asserts it is EMPTY for an ignored path or an empty delta
# (agents-9nir). A diagnostic line that must be visible before any exit path therefore goes to
# stderr, where the mapping suite only expects FAILURE messages. It is emitted before every
# exit path (including FAST_GATE_DRY_RUN), because a green fast gate is evidence about the
# arrangement it ran in - and after agents-u4k7 that arrangement is the CALLER's environment,
# with hermeticity supplied by the test package's declaration rather than by a shell scrub.
#
# agents-wzmj (F1): FAST_GATE_RESOLVE_PATHS=1 is the SECOND contract on that channel, and it is additive:
# one line per input path ('<path>\t<suites>', or '!<path>' when no arm matched) plus one ':always\t
# <suites>' line for the path-independent tier pins, so a caller needing N answers pays ONE startup
# instead of N. With it unset, stdout is exactly what it was - the union dry run's suite list.
#
# agents-wzmj: the arm registry's FILESYSTEM fallback (no index for this tree, or an index that names
# fragments this tree does not have) prints a WARNING to stderr, because in that state an untracked *.sh
# in the registry IS sourced and the run otherwise looks like a protected one.
echo "fast-gate: environment: the caller's, unmodified (no env scrub); hermeticity is declared" \
     "by tests/__init__.py -> tests/hermetic_env.isolate_operator_config() (agents-v1a2)" >&2

# agents-d081: THE POINT-OF-USE DRIFT WARNING, AND WHY IT IS HERE RATHER THAN IN A TEST OR A FAILURE.
#
# The per-VM ~/.fleet/check.conf is MACHINE-GLOBAL: a tracked change to tools/check.conf does not reach a
# host whose copy predates it, and until agents-d081 nothing could even say so - measured on this VM, the
# deployed file had no project stamp, no summary/tee wrapper in CHECK_CMD and a 360 s fast timeout against
# the tracked 180, while every gate on the host printed PASS. THIS FILE is the one surface in this repo
# that already runs on every lane, so the warning belongs here, where the lane about to be misled sees it.
#
# IT WARNS RATHER THAN FAILS, DELIBERATELY: the config is host-wide, so failing here would turn every lane
# red for a branch that is entirely innocent - a machine problem reported as a tree problem, which is the
# pathology this repo's own hermeticity work exists to remove. IT ALSO CANNOT PUT A VERDICT AT RISK: the
# exit status is untouched and the report goes to STDERR, because this file's stdout is a machine-readable
# contract (the dry run IS the resolved suite list).
#
# WHAT THIS WARNING CANNOT SEE, STATED SO IT IS NOT MISTAKEN FOR TOTAL: it is emitted by a file reached
# THROUGH the per-VM config, so if the drift is in CHECK_FAST_CMD itself - the deployed fast command no
# longer running this file at all - then no in-repo code runs and nothing in-repo can be loud. That case is
# visible only to provisioning (install.sh reports the drift it repairs) or to an external caller running
# `tools/check-cmd.sh --check`. And a branch that LEGITIMATELY changes tools/check.conf will see this
# warning; the text says so, because a warning that fires on correct work becomes wallpaper.
#
# COST, MEASURED RATHER THAN ASSUMED (agents-d081): `--check --quiet` is 0.02 s on this VM in both the
# drifted and the in-sync case - four greps and a subshell, against a gate that runs tens of seconds.
CHECK_CMD_SH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/check-cmd.sh"
if [ -f "$CHECK_CMD_SH" ]; then
  drift_rc=0
  drift_line="$(bash "$CHECK_CMD_SH" --check --quiet 2>&1)" || drift_rc=$?
  if [ "$drift_rc" -eq 1 ]; then
    drift_line="${drift_line#check-cmd: DRIFT keys: }"
    echo "fast-gate: WARNING (agents-d081): this host's per-VM gate config differs from the tracked tools/check.conf - differing keys: $drift_line" >&2
    # agents-p8lh: THE REPAIR IS ASKED FOR, NOT RESTATED. This line used to carry its own copy of the install
    # command, so when agents-0utp moved the default destination it went on naming a command that writes a
    # DIFFERENT file than the one drifting - the instruction was the defect. --repair-hint resolves the same
    # destination --check just reported on and prints the command that writes it, so this warning cannot drift
    # from the tool it is warning about (a missing hint degrades to the tracked command name, not to silence).
    drift_repair="$(bash "$CHECK_CMD_SH" --repair-hint 2>/dev/null)" || drift_repair=""
    # agents-e3aw (generalisation): the fallback names a command too, so it names the RESOLVED reader - this file
    # already resolved it above as CHECK_CMD_SH, and a relative path here would repeat, in the fallback, the
    # defect the resolved path exists to remove.
    [ -n "$drift_repair" ] || drift_repair="$(printf 'bash %q --install' "$CHECK_CMD_SH")"
    echo "fast-gate:   detail: bash $(printf '%q' "$CHECK_CMD_SH") --check - repair: $drift_repair - expected if THIS branch changes tools/check.conf, otherwise the host is running a gate command nobody chose" >&2
  fi
fi

# ENVIRONMENT POLICY (agents-u4k7): THIS GATE DOES NOT SCRUB ITS CALLER'S ENVIRONMENT.
#
# It used to, with `unset FACTORY_TOOL_PINS` + `export FACTORY_ALLOW_UNPINNED_TOOLS=1`. That
# achieved hermeticity by scrubbing the CALLER's shell rather than by the tests declaring
# their own environment - the same workaround class that was removed from ~/.fleet/check.conf
# once the hermeticity work made it unnecessary - and it made this gate blind to its own
# hermeticity declaration. MEASURED (agents-u4k7): with the scrub in place, making
# tests/__init__.py's declaration inert left tests/test_sandbox.py at `Ran 64 tests ... OK`
# (rc=0), so a green fast gate was not evidence that the declaration works.
#
# The FULL gate runs `python3 -m unittest discover -s tests -t . -v` with no env scrubbing and
# relies on the DECLARATION for this property. This gate now runs the caller's environment
# exactly as the full gate does and prints the policy before it runs (the environment line
# below), so a green fast-gate verdict is evidence about the same arrangement.
#
# THE DECLARATION IS tests/__init__.py -> tests/hermetic_env.isolate_operator_config()
# (agents-v1a2, agents-21ap): inside the test process it removes FACTORY_TOOL_PINS and
# re-asserts FACTORY_ALLOW_UNPINNED_TOOLS=1, because the harnesses plant SYNTHETIC binaries
# and the committed tools.yaml pins nothing.
#
# WHAT THAT OPT-IN DOES AND DOES NOT WAIVE (agents-xdmh, re-measured for agents-x2uw):
#   - it waives ONLY the requirement that a trusted tool HAVE a pin: _require_pin refuses an
#     entry with no sha256, and _unpinned_allowed() is consulted there and NOWHERE ELSE;
#   - it does NOT touch content verification: verify_pin never consults it, so a pin that is
#     PRESENT and MISMATCHED still refuses - measured, with the mismatch case as the control;
#   - the committed tools.yaml ships its pins COMMENTED OUT (0 active, 13 commented), so
#     inside these tests an unpinned trusted tool resolves BY PATH ORDER - which is what a
#     harness relies on when it plants a fake binary and asserts that the pin refuses it.
# Named by FUNCTION, not by line (agents-lh2f): the citations that used to be here moved more
# than a hundred lines in the oq3j landing, and a function name survives a rebase while a
# line number does not.
#
# The gate's own shell children (git, for the delta) do not consult pins at all, so leaving the
# caller's environment alone changes nothing for them; what matters is what the TESTS see, and
# the declaration governs that.

# Fail-visible abort diagnostics (agents-adhc).
# UNCOVERABLE BY CONSTRUCTION: SIGKILL (kill -9), kernel OOM-killer invocations,
# host power loss, or kernel panics terminate the process immediately at the OS level
# without executing userspace signal handlers or shell traps.
FAST_GATE_STAGE="initializing"
FAST_GATE_TERMINATED=0

_fast_gate_cleanup() {
  local rc=$?
  if [ "$FAST_GATE_TERMINATED" -eq 1 ]; then
    return 0
  fi
  if [ "$rc" -ne 0 ]; then
    echo "fast-gate: aborted: exit $rc (stage: $FAST_GATE_STAGE)" >&2
  fi
}
_fast_gate_term() {
  FAST_GATE_TERMINATED=1
  # agents-8ibx: the selection now runs as shard children, so a SIGTERM must reach them as well as this
  # script. Before this change there was one child; now a killed gate would otherwise leave four module
  # processes computing on a shared VM. The runner terminates its own pool on TERM (it installs a
  # handler), so signalling the direct child is enough - this only has to reach that far.
  pkill -TERM -P $$ 2>/dev/null || true
  echo "fast-gate: aborted: caught SIGTERM (stage: $FAST_GATE_STAGE)" >&2
  exit 143
}
_fast_gate_int() {
  FAST_GATE_TERMINATED=1
  pkill -TERM -P $$ 2>/dev/null || true
  echo "fast-gate: aborted: caught SIGINT (stage: $FAST_GATE_STAGE)" >&2
  exit 130
}
trap _fast_gate_cleanup EXIT
trap _fast_gate_term TERM
trap _fast_gate_int INT

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

FAST_GATE_STAGE="resolving changed files"
BASE="${GIT_BASE:-origin/main}"

# The branch delta. AN ERROR RESOLVING THE BASE IS NOT AN EMPTY DELTA (agents-c1z0, P1).
#
# This used to be `changed="${GIT_CHANGED:-$(git diff --name-only "$BASE"...HEAD 2>/dev/null || true)}"`,
# and the `|| true` was the hole: `git diff <bad-base>...HEAD` exits non-zero and prints
# nothing on stdout, so "I could not determine the delta" arrived here as "there is no
# delta". An empty delta then reaches the bounded smoke fallback below and the verdict
# reads PASS for a suite unrelated to the change - the same masking shape the *) arm was
# written to remove, one level up and one level quieter. It was reachable with a
# GIT_BASE naming a ref that does not exist, a shallow clone with no origin/main, or an
# unrelated history with no merge base, and it flipped a named refusal into a green pass
# on the SAME tree.
#
# So: A FALLBACK THAT SWALLOWS AN ERROR MUST PRODUCE A DISTINCT VALUE RATHER THAN AN
# EMPTY ONE. A base that is not a commit, and a diff that fails to compute, are both
# errors: they fail loudly and never reach the smoke fallback. Only a diff that genuinely
# succeeds and reports no paths is an empty delta, and only that takes the fallback.
#
# Override changed files directly with GIT_CHANGED (used by tests).
if [ -n "${GIT_CHANGED:-}" ]; then
  changed="$GIT_CHANGED"
else
  FAST_GATE_STAGE="resolving the branch delta vs $BASE"
  if ! git rev-parse --verify --quiet "${BASE}^{commit}" >/dev/null 2>&1; then
    echo "fast-gate: FAIL: base '$BASE' is not a commit in this repository." >&2
    echo "fast-gate: an unresolvable base is an ERROR, not an empty delta - the change set is UNKNOWN," >&2
    echo "fast-gate: so there is no honest verdict to report (set GIT_BASE to a real ref)." >&2
    exit 1
  fi
  if ! changed="$(git diff --name-only "${BASE}...HEAD")"; then
    echo "fast-gate: FAIL: 'git diff --name-only ${BASE}...HEAD' failed to compute the delta." >&2
    echo "fast-gate: the change set is UNKNOWN, not empty - refusing to fall back to the smoke subset." >&2
    exit 1
  fi
fi

run=""
mapped=""
unmatched=""
# agents-dtml: a SPACE-separated GIT_CHANGED list arrives here as ONE path (the input is read one path
# per line, the shape `git diff --name-only` prints), and the abort it produces points the reader at the
# arm table - the file agents-hr6q measured as edited by 20.2% of landings - for paths that already have
# arms. These two hold the shape so the abort can NAME it. Detection happens in the read loop, below,
# because that is the last place the RAW line still exists; it is a discriminator, not a parser.
ws_list_line=""
ws_list_tokens=""

# Contract-declared cross-file coverage dependencies (agents-1kzf)
if [ -e "tests/coverage-contract.json" ]; then
  if [ ! -f "tests/coverage-contract.json" ]; then
    echo "fast-gate: FAIL: tests/coverage-contract.json exists but is not a regular file" >&2
    exit 1
  fi
  if ! contract_suites=$(python3 -c "
import json, sys, os, fnmatch, glob
try:
    with open('tests/coverage-contract.json', encoding='utf-8') as f:
        data = json.load(f)
except Exception as e:
    print(f'fast-gate: FAIL: tests/coverage-contract.json is malformed: {e}', file=sys.stderr)
    sys.exit(1)
if not isinstance(data, dict):
    print('fast-gate: FAIL: tests/coverage-contract.json must be a JSON object mapping paths to suite lists', file=sys.stderr)
    sys.exit(1)
if len(data) == 0:
    print('fast-gate: FAIL: tests/coverage-contract.json must not be empty', file=sys.stderr)
    sys.exit(1)

for pat, suites in data.items():
    if not isinstance(pat, str) or not pat:
        print(f'fast-gate: FAIL: coverage-contract pattern must be non-empty string, got {pat!r}', file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(pat) and not glob.glob(pat):
        print(f'fast-gate: FAIL: coverage-contract target {pat!r} does not exist', file=sys.stderr)
        sys.exit(1)
    if isinstance(suites, str):
        suite_list = [suites]
    elif isinstance(suites, list):
        suite_list = suites
    else:
        print(f'fast-gate: FAIL: coverage-contract value for {pat!r} must be list of suite paths or string, got {type(suites).__name__}', file=sys.stderr)
        sys.exit(1)
    if len(suite_list) == 0:
        print(f'fast-gate: FAIL: coverage-contract suite list for {pat!r} must not be empty', file=sys.stderr)
        sys.exit(1)
    for s in suite_list:
        if not isinstance(s, str) or not s:
            print(f'fast-gate: FAIL: coverage-contract suite for {pat!r} must be non-empty string, got {s!r}', file=sys.stderr)
            sys.exit(1)
        if not os.path.isfile(s):
            print(f'fast-gate: FAIL: coverage-contract suite {s!r} for {pat!r} does not exist', file=sys.stderr)
            sys.exit(1)

changed = sys.argv[1:]
out = set()
for fp in changed:
    norm_fp = os.path.normpath(fp)
    for pat, suites in data.items():
        norm_pat = os.path.normpath(pat)
        if norm_fp == norm_pat or fnmatch.fnmatch(norm_fp, pat) or norm_fp.endswith(os.sep + norm_pat):
            if isinstance(suites, list):
                out.update(suites)
            elif isinstance(suites, str):
                out.add(suites)
print(' '.join(sorted(out)))
" $changed); then
    echo "fast-gate: aborting due to contract error" >&2
    exit 1
  fi
  if [ -n "$contract_suites" ]; then
    mapped="$mapped $contract_suites"
  fi
fi

FAST_GATE_STAGE="mapping changed files"

# agents-hr6q (ADR 0002 sections 2 and 4): THE ARM TABLE IS A DIRECTORY OF FRAGMENTS. It used to be one
# `case` table here - 144 landings touched this file, 40 of them changing it on both sides, and 84 of
# those changes were arm appends, so deliveries kept colliding on the gate itself. Each fragment in
# tools/fast-gate-arms.d/ holds one contiguous run of arms, VERBATIM (the rationale travels with the
# rule), wrapped in a function. The loader sources them in FILENAME ORDER - that order IS the pinned
# precedence, because a directory has no positional order and `case` resolved overlapping patterns by
# position (README.md in that directory states the rule for the next deliverer).
#
# THE GUARDS, because a directory of fragments is a registry and a registry without guards decays:
#   * every fragment must register EXACTLY ONE stage, and that stage must be a function the fragment
#     actually defines - otherwise a typo silently registers a stage that is never called;
#   * no two fragments may register the same stage;
#   * no PATTERN may appear in two fragments (agents-v8xv's obligation): with file order as precedence a
#     duplicate would be resolved silently by position, which is the accident this shape must not have.
# The other obligation from agents-v8xv - a dead arm (a pattern matching no tracked path) must be
# reported - lives in tests/test_fast_gate_mapping.py, where it costs the gate nothing: this file is on
# the critical path of every run, including every dry run.
# agents-es0y: THE FRAGMENT LIST COMES FROM GIT'S INDEX, NOT THE FILESYSTEM. The loader used to glob this
# directory, so a *.sh that git does not track was SOURCED - untracked input reaching an interpreter, in the
# process that decides what the gate runs - and the payload ran BEFORE the guards below validated the
# fragment. A fragment named below 010 also took precedence by filename order, because first match wins. The
# index is the same set the gate witnesses, and its order is the SAME filename order (measured identical over
# the 33 fragments), so precedence does not move. Anything on disk that git does not track is REPORTED and
# not sourced: an invisible skip is the same defect in a quieter voice. A root with no work tree - the
# synthetic fixture trees two suites build with copytree - has no index to ask, so there the filesystem IS
# the whole tree and the glob stays, the same rule tests/__init__.py states for has_git_index.
# Sets three globals from ONE listing of git's index (agents-es0y), and is called in the CALLER's shell:
#   FAST_GATE_ARM_FRAGMENTS - the TRACKED fragments that exist under this ROOT, one per line
#   FAST_GATE_ARM_TRACKED   - every TRACKED fragment path, whether or not it exists here (membership)
#   FAST_GATE_IGNORED_ARMS  - *.sh in the directory git does not track, one per line
# The caller must keep those lists: the ignored ones are REPEATED at the end of the gate, because the
# loader runs long before any suite and a receipt shows only the tail - a warning emitted here is invisible
# to exactly the lane it is for. stdout is not an option for it: stdout is the marker channel that
# remote/check-coverage.py parses.
fast_gate_arm_fragments() {
  local _rel _rest _frag _stray
  FAST_GATE_ARM_FRAGMENTS=""
  FAST_GATE_ARM_TRACKED=$'\n'
  FAST_GATE_IGNORED_ARMS=""
  FAST_GATE_ARMS_FALLBACK=""
  if git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    while IFS= read -r -d '' _rel; do
      _rest="${_rel#tools/fast-gate-arms.d/}"
      [ "$_rest" = "$_rel" ] && continue        # not under the arm registry
      case "$_rest" in */*) continue ;; esac     # a nested path is not a fragment
      case "$_rest" in *.sh) ;; *) continue ;; esac
      FAST_GATE_ARM_TRACKED="$FAST_GATE_ARM_TRACKED$_rel"$'\n'
      _frag="$ROOT/$_rel"
      [ -f "$_frag" ] || continue                # the index answered about ANOTHER tree
      FAST_GATE_ARM_FRAGMENTS="$FAST_GATE_ARM_FRAGMENTS$_frag"$'\n'
    done < <(git -C "$ROOT" ls-files -z -- 'tools/fast-gate-arms.d')
    # ONE read of the index, then pure-bash membership (agents-es0y, imp-dflt): a git process per stray
    # fragment on the gate's critical path is a cost the critical path should not pay.
    for _stray in "$ROOT"/tools/fast-gate-arms.d/*.sh; do
      [ -f "$_stray" ] || continue
      _rel="${_stray#"$ROOT"/}"
      case "$FAST_GATE_ARM_TRACKED" in *$'\n'"$_rel"$'\n'*) ;; *)
        FAST_GATE_IGNORED_ARMS="$FAST_GATE_IGNORED_ARMS$_rel"$'\n' ;;
      esac
    done
    if [ -n "$FAST_GATE_ARM_FRAGMENTS" ]; then
      return 0
    fi
    # The index named fragments and NOT ONE exists under this ROOT: the index answered about a different
    # tree - a copy of tools/ placed inside some other work tree. There is no index for THIS tree, so the
    # filesystem is the whole tree here, exactly as it is when there is no index at all.
    #
    # agents-wzmj: this is the state a STAGED DELETION OR RENAME of the registry reaches INSIDE A REAL
    # WORK TREE, where the glob below then sources whatever *.sh is on disk. The two fallback states are
    # distinguished so the notice can name which one engaged, which is the difference between 'untracked
    # input was reachable here' and 'no index was available to ask'.
    FAST_GATE_ARMS_FALLBACK="the index names arm fragments but none exist under this root"
  else
    # agents-wzmj: no work tree at all - the synthetic fixture trees two suites build with copytree.
    FAST_GATE_ARMS_FALLBACK="this tree is not a git working tree"
  fi
  FAST_GATE_ARM_FRAGMENTS="$(printf '%s\n' "$ROOT"/tools/fast-gate-arms.d/*.sh)"
  FAST_GATE_IGNORED_ARMS=""
  return 0
}

# agents-es0y: ONE place for the notice, so every exit path a lane can actually read carries it - the dry
# run prints it before it exits (a lane debugging why its new arm did not take effect reads that), and the
# end of the gate repeats it where a receipt's tail will show it.
# agents-wzmj: the FILESYSTEM fallback is a notice on the same footing, not a second reporting
# convention. It matters because in that state every *.sh in the registry is sourced, so an UNTRACKED
# fragment is executed and the run otherwise looks exactly like a protected one. stderr only, for the
# reason the loader states: stdout is the marker channel remote/check-coverage.py parses.
fast_gate_report_ignored_arms() {
  local _ignored_arm
  if [ -n "${FAST_GATE_ARMS_FALLBACK:-}" ]; then
    echo "fast-gate: WARNING (agents-wzmj): arm fragments are read from the FILESYSTEM ($FAST_GATE_ARMS_FALLBACK), so UNTRACKED fragments in tools/fast-gate-arms.d/ WILL be sourced" >&2
  fi
  : "${FAST_GATE_IGNORED_ARMS:=}"
  while IFS= read -r _ignored_arm; do
    [ -n "$_ignored_arm" ] || continue
    echo "fast-gate: WARNING: ignoring UNTRACKED arm fragment (not sourced): $_ignored_arm" >&2
  done <<< "$FAST_GATE_IGNORED_ARMS"
}

fast_gate_arms_load() {
  local _frag _fn _pat _stage
  local _before _new
  local _seen_stages=$'\n' _seen_patterns=$'\n'
  FAST_GATE_ARM_STAGES=""
  fast_gate_arm_fragments
  while IFS= read -r _frag; do
    [ -f "$_frag" ] || continue
    _stage="${_frag#"$ROOT"/}"
    _before="$FAST_GATE_ARM_STAGES"
    # shellcheck source=/dev/null
    . "$_frag" || {
      echo "fast-gate: FAIL: arm fragment failed to source: $_stage" >&2
      return 1
    }
    _new="${FAST_GATE_ARM_STAGES#"$_before"}"
    case "$_new" in
      " "?*) _new="${_new# }" ;;
      *) echo "fast-gate: FAIL: arm fragment registers no stage: $_stage" >&2; return 1 ;;
    esac
    case "$_new" in
      *" "*) echo "fast-gate: FAIL: arm fragment registers more than one stage ($_stage -> $_new)" >&2; return 1 ;;
    esac
    if ! declare -F "$_new" >/dev/null; then
      echo "fast-gate: FAIL: arm fragment $_stage registered $_new but defines no such function" >&2
      return 1
    fi
    case "$_seen_stages" in
      *$'\n'"$_new"$'\n'*) echo "fast-gate: FAIL: two arm fragments register the same stage: $_new" >&2; return 1 ;;
    esac
    _seen_stages="$_seen_stages$_new"$'\n'
    while IFS= read -r _pat; do
      [ -n "$_pat" ] || continue
      case "$_seen_patterns" in
        *$'\n'"$_pat"$'\n'*)
          echo "fast-gate: FAIL: duplicate arm pattern '$_pat' in $_stage - one pattern, one home (agents-v8xv)" >&2
          return 1
          ;;
      esac
      _seen_patterns="$_seen_patterns$_pat"$'\n'
    # Both arm shapes are scanned: `    <pattern>)` on its own line, and the single-line
    # `    <pattern>) body ;;`. Two things are deliberately NOT scanned: the loader's own no-match
    # fallback (its marker comment is matched, because `*)` is also a real arm in the ignore list - the one
    # case where a fallback and an arm share a pattern) and COMMENT lines, which are at the same indent and
    # routinely contain parentheses (a rationale citing its bead). A comment read as a pattern would make
    # the duplicate guard fire on prose.
    done < <(sed -n '/# no arm in this fragment matched/!s/^    \([^ #)][^)]*\))\s*\(.*\)$/\1/p' "$_frag")
  done <<< "$FAST_GATE_ARM_FRAGMENTS"
  case "$FAST_GATE_ARM_STAGES" in
    "") echo "fast-gate: FAIL: no arm stages were registered from tools/fast-gate-arms.d/" >&2; return 1 ;;
  esac
  return 0
}

# agents-71vj: THE LOADER'S OWN FAILURE IS ALSO A READER'S EXIT. A lane whose registry will not load is
# looking at the fragment it just added, and the two things it needs are "a fragment refused to load" and "an
# untracked fragment was never read". The ignored list is assembled by the ENUMERATION, which the loader only
# reaches as its first statement - so this exit has to ask for it, otherwise it reports an empty list and
# looks exactly like the defect. (Measured the hard way: reporting before the loader printed nothing, which is
# why the enumeration is called here.) fast_gate_arm_fragments early-returns when it has already run, so the
# loader's own call is untouched. warn-and-ignore stays non-fatal and this exit still fails for the loader's
# own reason - these two calls only ADD a line.
fast_gate_arm_fragments
fast_gate_report_ignored_arms
fast_gate_arms_load || exit 1

# A REPO-WIDE INVARIANT IS INVISIBLE TO A PER-PATH ARM (agents-wsiv), WHICH IS WHY IT IS KEYED HERE RATHER
# THAN IN THE REGISTRY. Arms are first-match-wins, so no fragment can express "this path ALSO needs suite X":
# the measured case is agents-ssyq's tool, which HAD its own exact-path arm at 300 and still never ran the
# retention inventory - an unenumerated rm -rf inside it passed the fast gate on two tips (be8a9aa2, d43470ab,
# 147 tests green) and was caught only by the full gate at merge. A blanket `tools/*.sh` arm was written and is
# strictly worse: it claims every tools path, so the loud unmatched failure above loses its prompt for a whole
# directory and a new tools script would go green against the inventory alone. The guard
# test_unmatched_gate_config_path_refuses_loudly_with_actionable_guidance (agents-ows4/dtj6/iwm5) caught that,
# correctly, which is why the classes are DECLARED ONCE AND READ here instead of claimed as paths.
#
# The suite is added only when SELECTION fires - not when a path is merely COVERED - so the check is paid at the
# moment it can be wrong rather than on every gate (a permanent 0.50s tax on every fast gate is a design smell).
# A COVERED-but-unselected path CAN still violate the invariant, which is exactly why it is covered; it is simply
# not THIS dispatch's job to pay for it (agents-3ixk: the earlier wording said the opposite).
#
# TWO FACTS, DECLARED TOGETHER AND READ SEPARATELY (agents-wsiv, coord's option (c)). COVERAGE and SELECTION are
# not the same question, and collapsing them is what made the first version of this change wrong:
#
#   COVERAGE  - which changed paths COULD violate the invariant - which is also the question the drift guard
#               asks: is this declared set COMPLETE against lib/retention.py's own scanner? Pointing the guard at
#               the selection set instead is how the pinned coverage property got weakened once already, and why
#               the two are separate constants rather than one.
#   SELECTION - which of those paths must THIS dispatch add the suite for? Only the ones nothing else reaches.
#
# THE SELECTION SET IS NARROW ON PURPOSE. Selection in this gate is IMPORT-DRIVEN and the arm table already does
# that correctly: a change under lib/ that the inventory's own suite imports is selected through its importer
# (lib/retention.py selects it today), while tests/test_fast_gate_importer_boundaries pins that a change to
# lib/egress_proxy.py must NEVER select tests/test_retention.py - it holds only a textual inventory entry, it
# does not import the module, and selecting it for every egress change spends full-gate time on the fast path
# (agents-6vev). So lib/egress_proxy.py is COVERED BUT NOT SELECTED. What NO arm and NO importer can reach is the
# shell scripts outside tests/ - exactly the measured failure (agents-ssyq's tool had its own exact-path arm at
# 300 and the inventory still never ran for it) - and that is what SELECTION adds here.
#
# The check is paid only when SELECTION fires, so the invariant is enforced at the moment it can be wrong rather
# than as a permanent 0.50s tax on every fast gate.
#
# THIS IS AN EDIT TO tools/fast-gate.sh, the file ADR 0002 section 4 singles out, deliberately rather than by
# avoidance: the registry cannot express the rule. It adds no arm, no fragment, and no path->suite pair, and
# changes no registry semantics. tests/test_fast_gate_mapping.py READS BOTH CONSTANTS OUT OF THIS FILE - so this
# is the single place the facts are declared - and asserts (a) coverage is COMPLETE against the inventory's own
# scanner, (b) selection is a SUBSET of coverage, and (c) the fail-closed guard above still fires for an
# unmatched path.
inventory_scanned_classes="factory lib agents tools .github"   # COVERAGE: what lib/retention.py scans
# SELECTION (agents-oskn): PER-CLASS SUFFIX RULES - the paths no arm and no importer can reach. tools/ any file;
# agents/ only *.py (an agent Python file can call os.unlink); .github/ only *.yml|*.yaml (a workflow can add
# rm -rf). The exclusions fall out of the SHAPE rather than needing special cases: agents/**/*.md is prose and is
# simply not .py, and lib/ is not in the selector at all, because selection is import-driven (agents-6vev) and
# the unconditional full gate is the backstop for everything the fast tier declines to spend on.
inventory_selected_any="tools"                                 # every file under these classes
inventory_selected_py="agents"                                 # only *.py under these classes
inventory_selected_yaml=".github"                              # only *.yml|*.yaml under these classes
inventory_script_suffix="sh"                                   # *.sh outside tests/ - true of BOTH sets
inventory=""

while IFS= read -r f; do
  [ -z "$f" ] && continue
  # agents-wzmj (F1): per-path resolve mode reports THIS path's contribution rather than the running
  # union, so what the accumulators held before this path is remembered here.
  _fast_gate_mapped_before="$mapped"
  _fast_gate_inventory_before="$inventory"
  # First match wins, across fragments in their pinned order - the semantics the single `case` had.
  #
  # THE UNMATCHED FALLBACK IS HERE, NOT A `*)` ARM IN THE REGISTRY, and that is a correctness requirement
  # rather than tidiness: a catch-all inside a numbered fragment swallows every arm a LATER delivery adds
  # (measured while building this - a probe fragment numbered after it could map nothing, and the gate
  # failed loudly on a path it had just been given an arm for). In the loader, the fallback is last by
  # construction, so a fragment may take any number.
  _fast_gate_matched=""
  for _fast_gate_arm in $FAST_GATE_ARM_STAGES; do
    if "$_fast_gate_arm" "$f"; then
      _fast_gate_matched=1
      break
    fi
  done
  if [ -z "$_fast_gate_matched" ]; then
    unmatched="$unmatched $f"
    # agents-dtml: is this ONE path, or several paths a caller joined with spaces? Report, never split:
    # a path MAY legally contain spaces, so the shape is only called out when the whole line is not a
    # path that exists AND at least two of its whitespace-separated tokens ARE paths that exist. For a
    # real path with spaces the first test is false; for `no such file.xyz` the second is.
    #
    # Written as a parameter expansion rather than a case statement over the changed path, because
    # tests/test_fast_gate_mapping.py forbids that shape in this file: the arm table lives in
    # tools/fast-gate-arms.d/ (ADR 0002), and that guard caught the first version of this line. The guard
    # is right - a case table over the changed path is how the arm table would come back - so the
    # whitespace test is spelled without one.
    if [ "$f" != "${f//[[:space:]]/}" ]; then
      if [ ! -e "$f" ]; then
        _ws_count=0
        _ws_exist=0
        for _ws_t in $f; do
          _ws_count=$((_ws_count + 1))
          [ -e "$_ws_t" ] && _ws_exist=$((_ws_exist + 1))
        done
        if [ "$_ws_count" -ge 2 ] && [ "$_ws_exist" -ge 2 ]; then
          ws_list_line="$f"
          ws_list_tokens="$_ws_count"
        fi
      fi
    fi
  fi
  # SELECTION (agents-oskn): per-class suffix rules, declared once above and read here. No `case` over the changed
  # path: the registry owns path->suite pairs and tests/test_fast_gate_mapping.py refuses that shape in this file.
  _fast_gate_top="${f%%/*}"
  _fast_gate_ext="${f##*.}"
  for _fast_gate_class in $inventory_selected_any; do
    if [ "$_fast_gate_top" = "$_fast_gate_class" ]; then
      inventory="tests/test_retention.py"
    fi
  done
  for _fast_gate_class in $inventory_selected_py; do
    if [ "$_fast_gate_top" = "$_fast_gate_class" ] && [ "$_fast_gate_ext" = "py" ]; then
      inventory="tests/test_retention.py"
    fi
  done
  for _fast_gate_class in $inventory_selected_yaml; do
    if [ "$_fast_gate_top" = "$_fast_gate_class" ]; then
      if [ "$_fast_gate_ext" = "yml" ] || [ "$_fast_gate_ext" = "yaml" ]; then
        inventory="tests/test_retention.py"
      fi
    fi
  done
  if [ "$_fast_gate_ext" = "$inventory_script_suffix" ] && [ "${f#tests/}" = "$f" ]; then
    inventory="tests/test_retention.py"
  fi
  # agents-wzmj (F1): the per-path line, printed only in resolve mode - so the union run's stdout is
  # byte-identical without it, which is the property tests/test_fast_gate_mapping.py asserts for the dry
  # run. A path no arm matched prints with a leading '!' and no suite list, because silence would be the
  # same signal a mode that resolves nothing produces.
  if [ -n "${FAST_GATE_RESOLVE_PATHS:-}" ]; then
    if [ -z "$_fast_gate_matched" ]; then
      printf '!%s\n' "$f"
    else
      _fast_gate_own="$(printf '%s\n' ${mapped#"$_fast_gate_mapped_before"} ${inventory#"$_fast_gate_inventory_before"} | awk 'NF && !seen[$0]++' | sort | tr '\n' ' ')"
      printf '%s\t%s\n' "$f" "${_fast_gate_own% }"
    fi
  fi
done <<< "$changed"

FAST_GATE_STAGE="checking unmapped files"
# Loud failure (agents-9nir): a changed file that matches neither a mapping arm nor the
# ignore list is exactly the case that must be seen - name every such file and fail,
# rather than quietly running tests/test_factory_core.py and reporting PASS for an
# unrelated suite. This must run before the dry-run print so tests exercise it too.
if [ -n "$unmatched" ]; then
  echo "fast-gate: FAIL: changed file(s) match no mapping arm and no ignore-list arm:" >&2
  for u in $unmatched; do
    echo "fast-gate:   $u" >&2
    case "$u" in
      tools/*.conf|tools/*.sh|*.conf|install.sh|.fleet/*)
        echo "fast-gate:     (gate/provisioning config: consider mapping to tests/test_check_conf_consistency.py, tests/test_gate_entrypoint_config.py, or tests/test_fast_gate_mapping.py)" >&2
        ;;
    esac
  done
  # agents-dtml: name the input shape BEFORE the arm-table instruction, or the reader edits the arm table
  # for paths whose arms already exist. Not a substitute for the failure above - rc is still 1.
  if [ -n "$ws_list_line" ]; then
    echo "fast-gate: NOTE (agents-dtml): one of the paths above is $ws_list_tokens whitespace-separated tokens and" >&2
    echo "fast-gate:   is not a path that exists, so it looks like a SPACE-separated list. GIT_CHANGED is read" >&2
    echo "fast-gate:   ONE PATH PER LINE, the shape \`git diff --name-only\` prints, so the whole line arrived as" >&2
    echo "fast-gate:   a single path. Write it one per line instead, e.g.:" >&2
    echo "fast-gate:     GIT_CHANGED=\$(printf '%s\\n' $ws_list_line)" >&2
    echo "fast-gate:   (A path MAY legally contain spaces, so this is named and never split.)" >&2
  fi
  echo "fast-gate: To fix, add an arm fragment under tools/fast-gate-arms.d/ - the registry tools/fast-gate.sh loads, whose README.md states the precedence and the guards - mapping the path to its test suite, or an ignore arm under '--- Ignore list (agents-9nir) ---' with documented search evidence (agents-9nir, agents-ows4, agents-dtj6)." >&2
  # agents-kfe8 (found by agents-factory-rev-es0y while reviewing agents-es0y): the lane reading THIS failure
  # has usually just ADDED an arm fragment, and an ignored UNTRACKED fragment is exactly why its arm did not
  # take effect - so the explanation is named here, in the same run that tells them to add one. This is the
  # last thing a reader sees about the change itself; the EXIT trap's abort notice follows it, which is why
  # the warning belongs at the end of the diagnostic block rather than last-in-the-stream.
  # Silent when nothing is ignored: FAST_GATE_IGNORED_ARMS is populated by the loader above (which reports
  # untracked fragments rather than sourcing them, agents-es0y) and the reporter prints nothing for an empty
  # list - so a clean tree's unmapped failure is byte-identical to before this line existed.
  fast_gate_report_ignored_arms
  exit 1
fi

# Union, dedupe, deterministic order.
#
# NO `|| true` HERE EITHER (agents-c1z0 review): this is the same error-masking shape as
# the base resolution above, one line later, and the reviewer constructed it. With the
# trailing `|| true` a failing element of this pipeline (a broken or OOM-killed `sort` or
# `awk`, a SIGPIPE) suppressed its exit status, `files` evaluated to the empty string, and
# the smoke fallback below reported PASS - discarding suites that HAD been mapped
# correctly. Reproduced with GIT_CHANGED="lib/sandbox.py" and a `sort` on PATH that exits 1:
# the correctly mapped tests/test_sandbox.py was thrown away and the verdict was green.
# A pipeline that cannot compute the suite list is an ERROR, not an empty suite list.
# Tree-guard tier (agents-dv23): repo-wide invariants run on every mapped and smoke run.
# Extracted from tests/test_budget.py (TestNoUnboundedSubprocess) per ADR agents-c07o.
tree_guards="tests/test_tree_guards.py"

# agents-undf: the consumer-coverage pin is the same tier shape, and agents-pdth moved it OUT of
# tests/test_tree_guards.py because agents-dv23 pins that file to hold exactly its tree-guard classes.
# It is added to every mapped and smoke run for the same reason the tier is: a pin that exists and is
# not selected is the same as no pin (the merger's check, and the gap that let agents-pdth be born red).
consumer_coverage="tests/test_fast_gate_consumer_coverage.py"

# Fall back to a bounded smoke subset when nothing maps (an all-ignored docs/config-only
# change, or no delta at all). Unmatched files never reach here - they fail loudly above.
if [ -z "$run" ] && [ -z "$mapped" ]; then
  if [ -n "${FAST_GATE_DRY_RUN:-}" ]; then
    FAST_GATE_TERMINATED=1
    fast_gate_report_ignored_arms
    exit 0
  fi
  mapped="tests/test_factory_core.py"
fi

if ! files="$(printf '%s\n' $run $mapped $tree_guards $consumer_coverage $inventory | awk 'NF && !seen[$0]++' | sort)"; then
  echo "fast-gate: FAIL: could not compute the suite list (the dedupe pipeline failed)." >&2
  echo "fast-gate: the suites that were mapped are UNKNOWN, not empty - refusing to fall back to the smoke subset." >&2
  exit 1
fi

# agents-wzmj (F1): PER-PATH RESOLVE MODE, and it is checked BEFORE the union dry run so it takes
# precedence when a caller sets both (it IS a dry run - one that answers per path instead of as a union).
#
# The union dry run answers 'what would this change set run'. A caller that needs that answer for twenty
# paths separately had to start the gate twenty times - each startup paying the whole preamble, including
# sourcing every arm fragment (measured: 0.194s each, so 4.07s for the 21 module paths the consumer-
# coverage mirror asks about). This mode answers each path from the SAME pass that already resolves them.
#
# The contract is additive and per-path EXACT: a path's set here is the set the union run computes when
# that path is the whole change set - its own line above plus the path-independent tier pins on the
# ':always' line. Refusals are not softened: an unmatched path still fails loudly above, exactly as it does
# for the union run, which is why a caller that sees no ':always' line must treat the batch as unanswered
# rather than as an empty selection.
if [ -n "${FAST_GATE_RESOLVE_PATHS:-}" ]; then
  FAST_GATE_TERMINATED=1
  fast_gate_report_ignored_arms
  printf ':always\t%s\n' "$(printf '%s\n' $run $tree_guards $consumer_coverage | awk 'NF && !seen[$0]++' | sort | tr '\n' ' ')"
  exit 0
fi

# Dry-run support for testing mapping resolution without invoking unittest.
if [ -n "${FAST_GATE_DRY_RUN:-}" ]; then
  FAST_GATE_TERMINATED=1
  fast_gate_report_ignored_arms
  printf '%s\n' $files
  exit 0
fi

FAST_GATE_STAGE="preparing runner"
modules="$(printf '%s\n' $files | sed 's#/#.#g; s#\.py$##' | tr '\n' ' ' | sed 's/ *$//')"

FAST_GATE_STAGE="running tests ($modules)"
# agents-8ibx: the runner below is still `python3 -u -m unittest`, one process per module instead of one for
# the whole selection, so this line keeps its shape (the stage-announcement handshake reads `running:` and
# the marker vocabulary is anchored on `fast-gate: running:` with the payload being suite names - neither is
# disturbed by the trailing qualifier, which is not on a marker line).
echo "fast-gate: base=$BASE; running: python3 -u -m unittest $modules (one process per module, sharded)"

# agents-6jmx: keep a copy of the RUNNER's output in a file the job writes itself. The gate log
# is the wrapper's file, and on a waited/preempted run the runner's output (which unittest writes
# to stderr - dots, "Ran N tests", OK/FAILED) did not reach it, while this script's own stdout
# lines did: five of this lane's logs split exactly that way, and the bead's two original
# examples are gone. The FULL gate already solved this for the same reason - CHECK_CMD tees to a
# per-tree summary (agents-j1te, "for stream legibility on preempt/requeue") - so this is that
# shape rather than a new one. A file the JOB writes does not depend on who owns the fd.
# BOTH STREAMS, ON PURPOSE (agents-6jmx, coord's requirement): the survivors in my logs were
# this script's stdout and the losses the runner's stderr, so a capture that took only ONE of
# the two would recreate the same defect facing the other way - a summary that is complete only
# when the fd that happens to be dropped is the other one. Each stream keeps its own channel
# (tee passes through), so stdout is not disturbed: the dry run, which exits before this block,
# stays byte-identical, and that is verified rather than assumed (agents-9nir/agents-ftf4).
summary_file=""
summary_dir="${FLEET_CHECKS_DIR:-$HOME/.fleet/checks}"
if mkdir -p "$summary_dir" 2>/dev/null; then
  # agents-qtnv: the name must say WHICH RUN the file came from. Tree and lane narrow a file to
  # a SET of runs (one tree carried 13 of these before this change), and the pid alone is opaque,
  # so the commit sha and a UTC start stamp are added. The sha is what PAIRS a file with a cached
  # record (the record carries `sha`); the stamp ORDERS for a human reading `ls` and is written by
  # this shell's clock, not the wrapper's, so it orders and does not pair. The tree-lane-pid shape
  # is kept as a prefix so existing <tree>-* globs still match.
  summary_tree="$(git rev-parse HEAD^{tree} 2>/dev/null || echo unknown)"
  summary_sha="$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
  summary_stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  summary_file="$summary_dir/${summary_tree}-${FLEET_LANE:-$(whoami)}-${summary_sha}-${summary_stamp}-$$.fast.summary.txt"
  # agents-qtnv: the file must ANSWER FOR ITSELF when there is no record to pair it with - 462 of 474
  # live summary files had none. Written straight to the file and never echoed, so the dry run, which
  # exits before this block, stays byte-identical (the constraint the comment above this block protects).
  {
    printf 'fast-gate run: tree=%s sha=%s lane=%s started=%s pid=%s\n' \
      "$summary_tree" "$summary_sha" "${FLEET_LANE:-$(whoami)}" "$summary_stamp" "$$"
    printf 'cwd=%s modules=%s\n' "$PWD" "${modules:-<none>}"
  } > "$summary_file"
  echo "fast-gate: runner output -> $summary_file" >&2
fi

# THE SUMMARY WRITE PATH LIVES AT THE INVOCATION BELOW, NOT INSIDE THE RUNNER (agents-ukk2, found by
# agents-factory-rev-8ibx reviewing this change). It has to hold two properties at once: the runner's stream
# is APPENDED to the summary rather than truncated onto the header already in the file (agents-qtnv), and the
# stream must reach the file WHILE the run is still going. Buffering it in the runner and appending at the
# end broke the second one - a preempted or hung run left the log and the summary with only the header, which
# is exactly what happened to this change's first receipt attempt and what I could not explain at the time.

# agents-8ibx: RUN THE SELECTION AS PARALLEL MODULE SHARDS. This block used to be one
# `python3 -u -m unittest $modules` over the whole selection, which on this VM (nproc=8, one heavy slot)
# used one core. Measured on an 8-path delta, 24 modules / 597 tests: 162.5s wall against 67.2s of child
# CPU - the wall was hardly work. Against a 180s bound that leaves ~10% headroom, and a run that close is
# bound-killed the moment a priority job arrives: two such kills held the single heavy slot for their full
# 210s each and produced no verdict.
#
# The unit of parallelism is the TEST MODULE (ADR 0002 / agents-5fy0), which is the shape
# tools/full-gate.sh already runs for the full gate - one process per module under a worker cap, longest
# module first, and the same refusal to trust an exit code: a module that produces no executed test id is
# a FAILURE even though its child exited 0. What is deliberately NOT copied from the full gate is its
# serial discovery pass: the fast path cannot afford a second traverse of the suite, so this checks that
# every selected module RAN SOMETHING (and reports the total), not that it ran an expected exact set.
#
# STDOUT IS NOT USED HERE, DELIBERATELY: it is the marker channel remote/check-coverage.py parses, and the
# dry run above prints the suite list on it. Every line below goes to stderr, which the caller pipes through
# `tee -a` into the summary file, so the dry run's stdout stays byte-identical - which is asserted, not assumed.
# The name matters beyond clarity: tests/test_summary_identity.py finds a writer's runner command by shape,
# and this call is the one carrying the append redirect, so the pin has to be able to see it (agents-8ibx).
_fast_gate_unittest_shards() {
FAST_GATE_RUN_MODULES="$modules" \
FAST_GATE_RUN_SHARDS="${FAST_GATE_SHARDS:-}" \
FAST_GATE_RUN_COST_CACHE="${FLEET_CHECKS_DIR:-$HOME/.fleet/checks}/full-gate-module-costs.json" \
python3 -u - <<'PY'
import json, os, re, signal, subprocess, sys, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed

# unittest -v carries the executed id in parentheses. Without -v there are only dots, and a module that
# executed nothing is indistinguishable from one that executed everything.
TEST_LINE = re.compile(r"^\S+ \((tests\.[^()]+)\)(?= \.\.\.|[ \t]*$)", re.MULTILINE)
modules = os.environ.get("FAST_GATE_RUN_MODULES", "").split()
cache = os.environ.get("FAST_GATE_RUN_COST_CACHE", "")


def say(line):
    print(line, file=sys.stderr, flush=True)


if not modules:
    # A gate that runs nothing must not report PASS. The selection falls back to the smoke subset before
    # here, so an empty selection means something upstream broke.
    say("fast-gate: FAIL: the shard runner was given no modules - refusing to report a pass for an empty selection")
    sys.exit(1)

try:
    workers = int(os.environ.get("FAST_GATE_RUN_SHARDS") or 0)
except ValueError:
    workers = 0
if workers < 1:
    if os.environ.get("FAST_GATE_SHARD_CHILD"):
        # A NESTED gate run: one invoked by a test that a shard is already running (the mapping and
        # consumer-coverage suites invoke the real gate repeatedly). It defaults to SERIAL, because the
        # outer run already holds the heavy slot's budget - without this, four lanes x up to four nested
        # workers is about sixteen processes where the unsharded gate had four, which is the restraint
        # coord's constraint (d) names. Measured motivation: one own-delta run wrote EIGHT nested summaries
        # from the mapping tests alone. tools/full-gate.sh marks its shard children (FULL_GATE_SHARD_CHILD)
        # for the same reason, and its test harness pops that marker for the same reason.
        workers = 1
    else:
        # Shared-VM restraint: this VM reports nproc=8 and runs seven lanes, and the single heavy slot is
        # the budget - so four is the default and FAST_GATE_SHARDS is the operator's override.
        workers = min(4, os.cpu_count() or 1)
workers = max(1, min(workers, len(modules)))


def costs():
    """Measured per-module seconds when the full gate already paid to measure them; else equal weights.

    Same cache file tools/full-gate.sh writes, so the two runners order their work the same way.
    """
    data = {}
    try:
        with open(cache, encoding="utf-8") as fh:
            loaded = json.load(fh)
        if isinstance(loaded, dict):
            data = loaded
    except (OSError, ValueError):
        data = {}
    out = {}
    for m in modules:
        v = data.get(m)
        out[m] = float(v) if isinstance(v, (int, float)) and 0 < v < 3600 else 1.0
    return out


COST = costs()
live = {}
live_lock = threading.Lock()


def run_module(module):
    start = time.monotonic()
    # FAST_GATE_SHARD_CHILD marks this process as a shard of a run that already holds the heavy slot, so a
    # gate a suite invokes from here stays serial instead of fanning out again (see the worker default).
    proc = subprocess.Popen([sys.executable, "-u", "-m", "unittest", "-v", module],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            env=dict(os.environ, FAST_GATE_SHARD_CHILD="1"))
    with live_lock:
        live[module] = proc
    try:
        out, _ = proc.communicate()
    finally:
        with live_lock:
            live.pop(module, None)
    return module, proc.returncode, time.monotonic() - start, out, TEST_LINE.findall(out)


def _terminate(signum, _frame):
    """A killed gate must not leave its shards running: they hold the machine, not just the slot.

    No announcement here on purpose. The gate's own trap prints `fast-gate: aborted: caught SIGTERM
    (stage: running tests (<modules>))`, and that message carries the stage AND the module list; a second
    abort line from this process would be a less informative duplicate of it.
    """
    with live_lock:
        procs = list(live.values())
    for p in procs:
        try:
            p.terminate()
        except OSError:
            pass
    sys.exit(143 if signum == signal.SIGTERM else 130)


signal.signal(signal.SIGTERM, _terminate)
signal.signal(signal.SIGINT, _terminate)

say("fast-gate: shards: %d module(s), %d worker(s)%s" % (
    len(modules), workers,
    "" if cache and os.path.exists(cache) else " (no measured cost cache: equal weights)"))

failed = []
empty = []
total_ids = 0
# STREAMED AS EACH MODULE FINISHES, not collected and printed at the end. The end-of-run form lost whatever a
# preempted or hung run had already produced - the summary and the log kept only the header - and that is not
# a cosmetic difference: it is the output a lane reads to see how far a killed gate got. The order here is
# therefore completion order, which is also what a live reader wants; the append itself is the caller's
# `tee -a`.
with ThreadPoolExecutor(max_workers=workers) as pool:
    futures = {pool.submit(run_module, m): m for m in sorted(modules, key=lambda m: (-COST[m], m))}
    for fut in as_completed(futures):
        m = futures[fut]
        try:
            module, rc_shard, secs, out, ids = fut.result()
        except Exception as exc:  # a shard that could not even start
            module, rc_shard, secs, out, ids = m, 1, 0.0, "%s: shard runner error: %s" % (m, exc), []
        total_ids += len(ids)
        say("----- %s rc=%s %.1fs ids=%d -----\n%s" % (module, rc_shard, secs, len(ids), out.rstrip()))
        if rc_shard != 0:
            failed.append((module, rc_shard))
        elif not ids:
            empty.append(module)

# Non-marker diagnostics, in the existing `fast-gate: FAIL:` form. The `fast-gate: failed:` marker is
# printed by the caller and its payload must stay SUITE NAMES ONLY (agents-lgdv), so the culprit is named
# here instead - and both the marker's payload and its form are unchanged by sharding.
for m, rc_shard in failed:
    say("fast-gate: FAIL: shard module failed: %s (rc=%s)" % (m, rc_shard))
for m in empty:
    say("fast-gate: FAIL: shard module executed no tests: %s (rc=0 is not evidence that it ran)" % m)
say("fast-gate: shards: %d module(s) ran, %d test id(s), %d failed, %d produced none" % (
    len(modules), total_ids, len(failed), len(empty)))
sys.exit(1 if (failed or empty) else 0)
PY
}

rc=0
if [ -n "$summary_file" ]; then
  # `tee -a` is load-bearing (agents-qtnv) and asserted on the RUNNER COMMAND by tests/test_summary_identity.py
  # - a comment containing those words once satisfied that pin, so it reads the command line (agents-undf).
  _fast_gate_unittest_shards 2> >(tee -a "$summary_file" >&2) || rc=$?
else
  _fast_gate_unittest_shards || rc=$?
fi

FAST_GATE_TERMINATED=1
# agents-es0y: THE IGNORED FRAGMENTS ARE REPEATED HERE, WHERE THE RECEIPT'S TAIL WILL SHOW THEM. The loader
# notices them thousands of lines earlier, and a lane reads a tail, so a warning emitted at load time is
# invisible to exactly the lane it is for. Keep warn-and-ignore rather than fatal: not sourcing the fragment
# already removes the execution path, so failing the gate would add no safety while turning a lane's
# transient mid-write into a fleet-wide landing outage. stdout is deliberately not used - it is the marker
# channel remote/check-coverage.py parses.
fast_gate_report_ignored_arms

if [ "$rc" -eq 0 ]; then
  passed_files="$(echo $files | tr '\n' ' ' | sed 's/ *$//')"
  echo "fast-gate: passed: $passed_files"
  exit 0
else
  # A MARKER'S PAYLOAD IS THE THING IT NAMES (agents-lgdv). The coverage reader matches this marker at
  # line start and takes EVERY whitespace token after it as a suite name - that is the vocabulary fleet's
  # remote/check-coverage.py parses, pinned by its own tests/check-coverage.test.sh:161
  # (`fast-gate: failed: tests/thing_test.ts`). The old payload `exit $rc (modules: $modules)` therefore
  # published three phantom "suites" - `exit`, `1` and `modules:` - ahead of the real module names: a fast
  # gate record held 13 entries for a 10-module run, and a reader counting suites counted the prose. The
  # exit code is a real fact and stays, on a line that is not a marker, so this field can only hold names.
  echo "fast-gate: failed: $modules" >&2
  echo "fast-gate: exit $rc" >&2
  exit "$rc"
fi
