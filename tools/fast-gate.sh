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
echo "fast-gate: environment: the caller's, unmodified (no env scrub); hermeticity is declared" \
     "by tests/__init__.py -> tests/hermetic_env.isolate_operator_config() (agents-v1a2)" >&2

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
  echo "fast-gate: aborted: caught SIGTERM (stage: $FAST_GATE_STAGE)" >&2
  exit 143
}
_fast_gate_int() {
  FAST_GATE_TERMINATED=1
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
while IFS= read -r f; do
  [ -z "$f" ] && continue
  case "$f" in
    tests/test_*.py)
      # agents-h17y: a changed test file also re-checks the CLASS-WIDE invariant that every
      # tests/test_*.py carries its `if __name__ == "__main__"` block LAST (agents-9lh8). The
      # defect that invariant catches is produced by appending a test BELOW the block, which is
      # precisely what a change to a test file is - and the file still passes under discovery, so
      # without this the fast gate is blind to it and only the merger's full gate would see it.
      # Measured cost: 0.67s for the suite (3 tests; the AST walk over 71 modules is 0.62s of it).
      run="$run $f"
      mapped="$mapped tests/test_direct_run_completeness.py"
      # agents-vim1: newly added or modified test files must audit the cross-module mock coverage contract
      mapped="$mapped tests/test_coverage_contract.py"
      ;;
    tests/containment_harness.py)
      # agents-3iog: the shared harness (setUp plus 11 helpers) the containment suites
      # inherit. It is not named test_*.py on purpose - discovery must not collect it - so it
      # needs its own arm, and it is the ONE entry in that family that legitimately names all
      # of them: a harness change reaches every inherited execution, and the shape test is
      # what catches a test method creeping into it (measured: with no arm the gate
      # fail-closed on this file as unmapped, which is how the omission was found).
      mapped="$mapped tests/test_containment.py tests/test_containment_declarations.py tests/test_containment_adapters.py tests/test_containment_engine_credentials.py tests/test_containment_prepass_pins.py tests/test_containment_egress.py tests/test_containment_shape.py"
      ;;
    tools/fast-gate.sh)
      # agents-8jx1: THE GATE'S OWN SCRIPT HAD AN ARM THAT MAPPED ONLY
      # tests/test_fast_gate_mapping.py. A change to tools/fast-gate.sh therefore selected the
      # mapping suite AND OMITTED tests/test_hermetic_env.py - the acceptance suite for the
      # gate's hermetic environment, which names fast-gate/CHECK_CMD seven times and can be
      # regressed by a gate edit. Found by the gate's own coverage warning on a green run.
      # (The old arm this replaces was deleted rather than left in place: the matcher is
      # FIRST-MATCH, so a second arm for the same path is unreachable dead code that a future
      # reader would have no way to identify as the stale one.)
      # agents-3a8a: tests/test_coverage_contract.py is THE SAME SHAPE one round later. The
      # contract parser THIS script owns is pinned by that suite's two *_aborts_fast_gate_loudly
      # tests (:143 and :164), each of which copies this script into a tmp tree and asserts the
      # parser's failure modes - consumers of this file, omitted from this arm. Because this file
      # IS mapped, no 'unmapped changed file(s)' warning fires for the omission: the gap is an
      # omitted consumer INSIDE a mapped arm.
      # HONEST MEASUREMENT, because the obvious mutant did NOT reproduce the feared hole intact
      # and the difference is the reason to name the suite anyway: with the contract validation's
      # `if not os.path.isfile(s):` changed to `if False:` (one non-equivalent mutant), the OLD
      # arm's own gate run ALSO went red (rc=1) - but only COLLATERALLY. tests/test_fast_gate_mapping.py
      # invokes this script against probe test files, whose own arm (tests/test_*.py, agents-vim1)
      # selects tests/test_coverage_contract.py, so the suite ran as a NESTED child and the outer
      # failures were assertions about the nested gate's rc (FAIL:
      # test_fast_gate_execution_emits_single_line_marker_naming_all_suites, FAIL:
      # test_fast_gate_execution_reports_passed_terminal_signal_on_success, FAIL:
      # test_fast_gate_runner_unsets_host_pins_for_child_suites) - not about this arm's declared
      # set. So the coverage depended on a probe's file NAME, not on this arm. With the suite in
      # this arm the same mutant is reported by a TOP-LEVEL module run and NAMES the assertion:
      # FAIL: test_invalid_coverage_contract_value_aborts_fast_gate_loudly
      #   (contract='{"lib/child_env.py": ["tests/nonexistent_suite_xyz.py"]}')
      #   AssertionError: 'does not exist' not found in ...
      # Unmutated control: green. Measured cost of the addition: 1.4s (5 tests), paid only when
      # this script changes.
      mapped="$mapped tests/test_fast_gate_mapping.py tests/test_hermetic_env.py tests/test_coverage_contract.py"
      ;;
    tools/stage_site.py)
      # agents-1n9i: THIS FILE MATCHED NO ARM AT ALL, so a change to it hit the unmatched
      # bucket and ABORTED THE GATE with exit 1 rather than skipping a suite - the one member
      # of this family the instrument can actually catch, because the changed file was
      # unmatched. tests/test_pages_publish_scope.py imports tools.stage_site directly (:18)
      # and exercises guard() and stage_site() plus the publication scopes. It is NOT the only
      # suite that can fail for this file, which the previous wording claimed ("the suite this
      # file's own changes must select"): agents-23jg measured that tests/test_retention.py pins
      # this file too, through its deletion inventory - :1207 carries
      # ("tools/stage_site.py", "shutil.rmtree(out)", 1, "NAMED", ...). MEASURED on 2026-10-12
      # with the non-equivalent mutant `shutil.rmtree(out) -> shutil.rmtree(out,
      # ignore_errors=True)`: the arm selected tests/test_pages_publish_scope.py ALONE and it
      # reported OK, while tests/test_retention.py reported FAILED (failures=2) without ever
      # being selected - a change to this file the fast gate could not catch. Both consumers are
      # therefore listed. Same mapping a docs/* or .github/* change uses.
      mapped="$mapped tests/test_pages_publish_scope.py tests/test_retention.py"
      ;;
    tests/__init__.py|tests/hermetic_env.py)
      # Centralized hermetic test package initialization (agents-v1a2) and shared helper.
      # A change to the package initialization or helper runs the acceptance suite
      # plus the primary sandbox and tool pin suites.
      mapped="$mapped tests/test_hermetic_env.py tests/test_sandbox.py tests/test_tool_pins.py"
      ;;
    tests/fixtures/*)
      # Checked-in test payloads (agents-28nn round 5): fake_engine.sh is the contained
      # engine-exfiltration attack asserted on by TestEngineCredentialPinning, which
      # agents-3iog moved into tests/test_containment_engine_credentials.py. Search
      # recorded: `grep -rln fixtures tests/ --include='*.py'` -> that module is the only
      # consumer of tests/fixtures/ (the other hits name tests/sandbox_fixtures.py or
      # tmp-tree dirs). Measured, not inferred (agents-3iog): removing `env` from the
      # payload turns THIS arm red and leaves the five sibling containment modules green.
      mapped="$mapped tests/test_containment_engine_credentials.py"
      ;;
    tests/coverage-contract.json)
      # Contract-declared cross-file coverage dependencies (agents-1kzf).
      mapped="$mapped tests/test_coverage_contract.py tests/test_fast_gate_mapping.py"
      ;;
    factory)
      # The dispatcher script; covered by the core runner, truth harnesses, auth failures, line andon, prompt exposure, and transient dir cleanup.
      mapped="$mapped tests/test_factory_core.py tests/test_factory_truth.py tests/test_factory_truth_2.py tests/test_adapter_auth_failure.py tests/test_line_andon.py tests/test_prompt_exposure.py tests/test_transient_dirs.py"
      # agents-oq3j: the promotion child is built by a call in THIS file (the dispatcher's
      # promote path), and tests/test_promotion.py MOCKS that call and asserts its exact shape -
      # so the dispatcher was changed and the assertion went stale while the arm that owns the
      # call site never ran the suite. Measured cost of the addition: 8.5 s (14 tests), paid only
      # when factory changes, against a full gate that found this defect at 1547 tests.
      mapped="$mapped tests/test_promotion.py"
      # agents-dm8n round 2: the deleter that escaped round 1 lived in FACTORY (the failed
      # --apply proposal_run_dir rmtree - the remove_recorded(proposal_run_dir, ...) call; agents-gioi:
      # cited by SYMBOL, not by line, because the number that used to be here, :2102, is a lone '}'),
      # not in lib/retention.py - so a factory
      # change must run the two suites that pin deletion under the runs root.
      # SEARCH PERFORMED: `grep -n "shutil\.rmtree(\|\.unlink(\|os\.remove(\|os\.unlink("
      # factory` enumerates every deletion site in the dispatcher; tests/test_retention.py's
      # TestRunRootDeletionInventory holds that enumeration and fails on any drift, and
      # tests/test_hillclimb.py is the only suite that drives the run_hillclimb --apply
      # failure path end-to-end (its test_worktree_creation_failure_after_add_is_cleaned_up
      # now asserts the tombstone lands). Neither was reachable from this arm before.
      mapped="$mapped tests/test_retention.py tests/test_hillclimb.py"
      ;;
    install.sh)
      # agents-3xqa: THE PROVISIONING ENTRYPOINT MATCHED NO ARM, so an implementer editing it
      # - the file where the gate-install step is wired (agents-l2xb) - could not pass its own
      # fast gate: the change fell to the *) arm and exited 1 ("match no mapping arm"). It is a
      # deliberate mapping arm, not an ignore arm, and THE SUITE IS THE CONSUMER RATHER THAN A
      # STAND-IN: tests/test_gate_entrypoint_config.py EXECUTES install.sh in a temp HOME and
      # reads back the per-VM config the deployed gate reads - delete the --install call site
      # from install.sh and it goes red - so it catches exactly the regression this arm exists
      # for. It is also already the suite pinning the tracked command's path to the deployed
      # entrypoint, which is the contract install.sh provisions.
      mapped="$mapped tests/test_gate_entrypoint_config.py"
      ;;
    lib/sinks/*.py)
      # Tracker-sink adapters (fleet-km8): covered by the sink harness, the bd contract, promotion, layering, and adapter registry/commands.
      mapped="$mapped tests/test_sinks.py tests/test_bd_json_contract.py tests/test_promotion.py tests/test_sink_layering.py tests/test_sink_adapters.py"
      ;;
    lib/findings.py)
      # The findings store and the delta renderer. Its own suite is not enough: the store's record
      # and stats shape is what the sink/record layers assert, and a change here broke
      # tests/test_sinks' exact stats expectation while the generic test_findings-only mapping ran
      # (agents-x9my step 2). tests/test_redaction.py is here for the same reason, learned again the
      # hard way: the fast gate passed 291 tests while the FULL gate caught a TypeError on a
      # non-scalar line_number, because the redaction contract suite was not in this mapping
      # (agents-q0mt) - the contract is fail-closed, so it is a real consumer of this module.
      # tests/test_suppressions.py asserts the committed suppressions register contract (agents-vt7w).
      mapped="$mapped tests/test_findings.py tests/test_sinks.py tests/test_bd_json_contract.py tests/test_promotion.py tests/test_sink_layering.py tests/test_model_rule_id.py tests/test_candidate_binding.py tests/test_redaction.py tests/test_suppressions.py"
      # The lock is only observable from OUTSIDE a single process, so this suite is the only one
      # that can see a regression to the unbounded wait (agents-4sij).
      mapped="$mapped tests/test_store_lock_timeout.py"
      ;;
    lib/candidate_identity.py)
      # Candidate identity generator (agents-rdyb) and pre-pass emission assertion (agents-vt7w).
      mapped="$mapped tests/test_candidate_identity.py tests/test_candidate_id_emission.py"
      ;;
    lib/credential_broker.py)
      # Credential broker plus end-to-end keyless broker test (agents-vt7w).
      mapped="$mapped tests/test_credential_broker.py tests/test_pi_keyless_broker.py"
      ;;
    lib/sandbox.py)
      # Bubblewrap sandbox (bwrap isolation, binds, proc/env masking) plus no-bwrap refusal contract (agents-vt7w).
      #
      # agents-oq3j: tests/test_station_trusted_tool_pins.py joins (measured 0.8 s). Its sandboxed
      # case drives sandbox_command with a dispatcher-built child env and the read-only pins bind,
      # which is exactly this module's child-side contract; the gate's coverage oracle named it as
      # an omitted consumer when the child channel moved, and it caught the regression.
      mapped="$mapped tests/test_sandbox.py tests/test_no_bwrap_guard.py tests/test_station_trusted_tool_pins.py"
      ;;
    lib/child_env.py)
      # This arm INCLUDES tests/test_credential_broker.py and tests/test_sink_adapters.py (agents-hay8).
      # It previously did not, and the reason is worth keeping, because it is the same principle in
      # both directions. They had always RECEIVED the builder's output - the broker suite calls
      # child_environment() directly in its two base-URL tests (agents-22kv: named by FUNCTION, not
      # by line, because the numbers that used to be here had already slipped one line) - but until
      # agents-a9lc they asserted nothing
      # about the credential boundary in it. MEASURED on 2026-10-12 for agents-6ujc: patching the
      # builder to leak an ambient AWS_SECRET_ACCESS_KEY left test_credential_broker at "80 tests,
      # 0 failures, 0 errors" and test_sink_adapters at "29 tests, 0 failures, 0 errors" - identical
      # to their unmutated baselines - while the SAME mutation failed six tests in the file's own
      # suite. Naming suites that cannot go red for the file they are named for is coverage that
      # lies, so they were excluded then; agents-a9lc then added assertNotIn("AWS_SECRET_ACCESS_KEY",
      # env) at every call site that consumes the builder, which makes them able to fail for this
      # file's property, so they are included now for exactly the reason they were excluded before.
      # The child environment builder. Its own suite plus the two consumers that resolve trusted
      # tools from the environment it constructs (agents-oq3j), and the promotion suite, whose
      # mock patches the BUILDER'S SIGNATURE: agents-oq3j added a `verified_pins` argument and
      # tests/test_promotion.py's expectation was the consumer nobody had migrated, so a mock of
      # this call is a consumer of this file whether or not the mock's file was touched.
      mapped="$mapped tests/test_child_env.py tests/test_station_trusted_tool_pins.py tests/test_sinks.py tests/test_promotion.py tests/test_credential_broker.py tests/test_sink_adapters.py"
      ;;
    lib/tool_pins.py)
      # Trusted-tool pinning (agents-7bj). Since agents-28nn this module also authenticates
      # bwrap itself, and the property that an unauthenticated bwrap is refused BEFORE it
      # executes lives in tests/test_sandbox.py (TestBwrapPinBoundary) — the pins contract
      # alone cannot see a sandbox-side regression.
      #
      # agents-oq3j: tests/test_station_trusted_tool_pins.py (measured 0.8 s) and
      # tests/test_sinks.py (measured 8.2 s) join, both named by the gate's own coverage oracle
      # as omitted consumers when the pins channels were separated. The first is THE handoff
      # contract (pre-pass child env, sandboxed and unsandboxed); the second is a sink child
      # resolving `gh` inside this module's fail-closed rule. Each caught a real regression in
      # that change, which is exactly what the oracle exists to find.
      mapped="$mapped tests/test_tool_pins.py tests/test_sandbox.py tests/test_station_trusted_tool_pins.py tests/test_sinks.py"
      ;;
    tools/generate-tool-pins.sh)
      # Operator-run pin generator (never invoked by the factory — its own header). SEARCH
      # PERFORMED (agents-28nn): `grep -rn "generate-tool-pins" tests/` named no suite before
      # this bead; agents-28nn adds the assertion that its TOOLS list covers every
      # TRUSTED_TOOLS entry to tests/test_tool_pins.py, which owns the pins contract.
      # agents-oc3q review P2: tests/test_pin_generator_hasher.py is added here because a
      # BEHAVIOURAL test of THIS script is what catches a re-introduction of the hole - the
      # suite pins that a planted hasher cannot supply the pin's reference value, and it only
      # runs on a generator change if this arm names it. Without this, a future edit putting
      # $PIN_LOOKUP_PATH back at the hasher call site would pass the fast gate.
      mapped="$mapped tests/test_tool_pins.py tests/test_pin_generator_hasher.py"
      ;;
    tools/audit-tool-pins.sh)
      # agents-5vun: the pins AUDIT - a detector that must be run to have any value, so the
      # suite that drives it (real forged files, real generator, exit codes) belongs here.
      # tests/test_pins_audit.py also PINS THE MEASURED LIMIT (a self-consistent forgery
      # whose path the lookup chooses passes), so the honest NOT-CHECKED text cannot be
      # quietly turned into a claim of security by a later edit.
      mapped="$mapped tests/test_pins_audit.py"
      ;;
    THREAT_MODEL.md)
      # Root markdown the docs-drift scanner WALKS (check_docs.py os.walk()s every committed
      # .md outside IGNORE_DIRS). SEARCH PERFORMED (agents-28nn): `grep -rn 'ROOT /
      # "THREAT_MODEL' tests/` finds no direct reader; the test_threat_model_prepass.py hits
      # are fixture strings for the findings-store recognizer, not the committed file.
      mapped="$mapped tests/test_docs_drift.py"
      ;;
    lib/yaml_mini.py)
      # Mini YAML parser plus GitHub Actions action.yml contract pin (agents-vt7w).
      mapped="$mapped tests/test_yaml_mini.py tests/test_ci_action.py"
      ;;
    lib/adapters/claude.sh)
      # Claude adapter session auth scrub and precedence (agents-vt7w), prompt guards (agents-9bp7), stderr read-back (agents-2iwf).
      mapped="$mapped tests/test_claude_adapter.py tests/test_prompt_exposure.py tests/test_adapter_stderr_readback.py"
      ;;
    lib/adapters/pi.sh)
      # Pi adapter keyless broker wireup, auth failure handling, containment policies, prompt guards, and factory core (agents-zak0).
      # agents-4ic0: ALSO the line-runner regression suite. The pi adapter is the engine that
      # drives the REAL line runner, which DISPATCHES adapters - so a pi.sh edit can change what
      # the line runner does, and tests/test_line_andon.py was reachable only through the
      # lib/adapters/*.sh wildcard (agents-yx7z), never through this dedicated arm. Measured with
      # the bead's own repro: GIT_CHANGED=lib/adapters/pi.sh selected six suites, none of them it.
      # agents-3iog split the containment suite: this arm keeps TWO of its modules - the
      # dispatcher suite (which drives the real adapter end to end) and the adapters suite
      # (which asserts the adapter argv/env shape). Measured: mutating pi.sh's engine-binary
      # variable turns tests/test_containment.py red.
      mapped="$mapped tests/test_pi_keyless_broker.py tests/test_adapter_auth_failure.py tests/test_factory_core.py tests/test_containment.py tests/test_containment_adapters.py tests/test_prompt_exposure.py tests/test_adapter_stderr_readback.py tests/test_line_andon.py"
      ;;
    lib/adapters/*.sh)
      # Other engine adapters (e.g. antigravity.sh, deepseek.sh) covered by auth failure, prompt guards, and core runner (agents-vt7w, agents-zak0). test_antigravity_prompt_content.py is listed EXPLICITLY (agents-nhf0): the wildcard arm already selected this file when the TEST changed, but NOT when the ADAPTER changed - so the suite protecting antigravity.sh's prompt guard did not run for the edits that could regress it. A suite gated only on its own edits is the half-fixed shape.
      # test_line_andon.py is listed here (agents-yx7z) because it drives the REAL LINE
      # RUNNER, which is what DISPATCHES adapters, so an adapter-only change can regress it. It
      # was mapped in the `factory)` arm above but not this one (agents-gioi: cited by PATTERN, not
      # by line - the number that used to be here, :129, is the GIT_CHANGED assignment).
      # Other engine adapters (e.g. antigravity.sh, deepseek.sh) covered by auth failure, prompt guards, and core runner (agents-vt7w, agents-zak0).
      mapped="$mapped tests/test_adapter_auth_failure.py tests/test_factory_core.py tests/test_prompt_exposure.py tests/test_adapter_stderr_readback.py tests/test_antigravity_prompt_content.py tests/test_line_andon.py"
      ;;
    lib/bench/*.py)
      # Bench measurement & runners (agents-uxt): covered by bench runner and hillclimb tests.
      mapped="$mapped tests/test_bench_runner.py tests/test_hillclimb.py"
      ;;
    lib/report_schema.py)
      # Report schema validation, post-filters (concurrency guard, unlocatable verdicts), and pipeline gate (agents-vt7w).
      mapped="$mapped tests/test_report_schema.py tests/test_perf_review.py tests/test_factory_truth_2.py tests/test_threat_model_prepass.py"
      ;;
    agents/bundle-size/scripts/measure_bundle.py)
      mapped="$mapped tests/test_bundle_size.py"
      ;;
    agents/threat-model/scripts/mine_history.py)
      mapped="$mapped tests/test_threat_model_prepass.py"
      ;;
    agents/perf-hillclimb/scripts/measure_and_context.py)
      mapped="$mapped tests/test_hillclimb.py"
      ;;
    agents/docs-write/scripts/prepare_docs_fixes.py)
      # agents-tdwv: ALSO the suite for THIS script's own error handling, same
      # one-token shape as the arm above.
      mapped="$mapped tests/test_prepass_exclusions.py tests/test_docs_write.py"
      ;;
    agents/docs-drift/scripts/check_docs.py)
      # agents-q0mt: also emits candidate ids now; the exclusion suite drives this script, and the
      # emission pin reads the id out of a real artefact.
      mapped="$mapped tests/test_docs_drift.py tests/test_prepass_exclusions.py tests/test_candidate_id_emission.py tests/test_prepass_pin_boundary.py"
      ;;
    agents/vuln-triage/scripts/triage.py)
      mapped="$mapped tests/test_vuln_triage_prepass.py"
      ;;
    agents/issue-triage/scripts/fetch_issues.py)
      mapped="$mapped tests/test_issue_triage_prepass.py tests/test_prepass_pin_boundary.py tests/test_redaction.py tests/test_docs_drift.py"
      ;;
    agents/release-notes/scripts/gather_commits.py)
      # agents-28nn round 4: gather_commits resolves git through the pin, pinned by
      # tests/test_prepass_pin_boundary.py. tests/test_redaction.py parses every agents/*/scripts/*.py,
      # and tests/test_docs_drift.py owns the prose.
      mapped="$mapped tests/test_prepass_pin_boundary.py tests/test_redaction.py tests/test_docs_drift.py"
      ;;
    tests/sandbox_fixtures.py)
      # Shared fixture builder for tests (agents-8ztd); its own suite pins the property that a new
      # lib import reaches a sandbox without a fixture change.
      mapped="$mapped tests/test_sandbox_fixtures.py"
      ;;
    agents/vuln-verify/scripts/prepare_verification.py)
      # The verifier's pre-pass: unknown-location handling (agents-fy26) and path confinement
      # (agents-075) are both pinned in this suite.
      mapped="$mapped tests/test_vuln_verify_prepass.py"
      ;;
    agents/pr-fixer/scripts/collect_failures.py)
      # The proposer's pre-pass: unknown lines must not reach int() (agents-fy26); pin resolution (agents-01qd).
      mapped="$mapped tests/test_pr_fixer_prepass.py tests/test_station_trusted_tool_pins.py"
      ;;

    agents/vuln-discovery/scripts/scan_surface.py)
      # The first station to EMIT a stable candidate identity (agents-rdyb): its own precision
      # suite plus the shared helper's property tests, which are what fail if the id stops being
      # deterministic or starts moving with the model's prose.
      mapped="$mapped tests/test_scan_surface.py tests/test_candidate_identity.py"
      ;;
    agents/secret-scan/scripts/scan.py)
      # The secret pre-pass. Both producer paths (gitleaks and the builtin fallback) meet at one
      # artefact assembly point, so the candidate-identity conversion is one call (agents-q0mt).
      # agents-28nn round 4: gitleaks is resolved through the pin (present-but-unauthenticatable
      # is loud; genuinely absent keeps the builtin fallback) - pinned by the boundary suite.
      mapped="$mapped tests/test_secret_scanner.py tests/test_candidate_id_emission.py tests/test_prepass_pin_boundary.py"
      ;;
    agents/modern-web/scripts/scan_modern_web.py)
      # agents-q0mt: the station now emits a candidate id; its own suite plus the pre-pass
      # exclusion suite, which exercises this script directly.
      mapped="$mapped tests/test_modern_web.py tests/test_prepass_exclusions.py tests/test_candidate_id_emission.py"
      ;;
    agents/deps-supply-chain/scripts/audit_deps.py)
      # agents-q0mt: emits candidate ids; the pre-pass exclusion suite exercises it too; pin resolution (agents-01qd).
      mapped="$mapped tests/test_audit_deps.py tests/test_prepass_exclusions.py tests/test_candidate_id_emission.py tests/test_station_trusted_tool_pins.py"
      ;;
    agents/ui-ux-audit/scripts/scan_ui_ux.py)
      # agents-q0mt: emits candidate ids; this station's output is pinned as the pre-pass truth
      # fixture, and the exclusion suite drives it directly.
      mapped="$mapped tests/test_prepass_truth.py tests/test_prepass_exclusions.py tests/test_candidate_id_emission.py"
      ;;
    agents/accessibility/scripts/audit_a11y.py)
      # agents-q0mt: emits candidate ids. The emission pin is this station's only executable
      # coverage of its artefact, so it is named here rather than left to the smoke subset.
      # agents-tdwv: ALSO its OWN suite - tests/test_audit_a11y.py tests THIS script's
      # CLI (no --output must drop candidate ids and matched line hashes from stdout),
      # so a change here could regress the suite written to test it. Same one-token
      # shape as agents-nhf0, agents-yx7z, agents-8jx1 and agents-4ic0; found by the
      # wildcard-set scoping pass rather than by the gate, which cannot see it.
      mapped="$mapped tests/test_candidate_id_emission.py tests/test_audit_a11y.py"
      ;;
    agents/memory-profile/scripts/scan_memory_leaks.py)
      # agents-q0mt: emits candidate ids; the binding suite drives this script.
      mapped="$mapped tests/test_candidate_binding.py tests/test_candidate_id_emission.py"
      ;;
    agents/perf-review/scripts/scan_perf_changes.py)
      # agents-q0mt: emits candidate ids; its own review suite plus the emission pin; pin resolution (agents-01qd).
      mapped="$mapped tests/test_perf_review.py tests/test_candidate_id_emission.py tests/test_station_trusted_tool_pins.py"
      ;;
    agents/qa-station/scripts/audit_factory_quality.py)
      # agents-q0mt: emits candidate ids. The truth harnesses assert its payload shape, which is
      # what a new key could disturb.
      mapped="$mapped tests/test_factory_truth_2.py tests/test_prepass_truth.py tests/test_candidate_id_emission.py"
      ;;
    agents/resilience/scripts/scan_resilience.py)
      # agents-q0mt: emits candidate ids; the emission pin is this station's only executable
      # coverage of its artefact today.
      mapped="$mapped tests/test_candidate_id_emission.py"
      ;;
    agents/test-gap/scripts/find_untested.py)
      # agents-q0mt: emits candidate ids; the emission pin is this station's only executable
      # coverage of its artefact today.
      mapped="$mapped tests/test_candidate_id_emission.py"
      ;;
    agents/vuln-verify/report.schema.json)
      # The verifier's output CONTRACT. Nothing else maps a JSON schema, and the case above has no
      # default arm - so without this a change to the contract maps to nothing and the gate goes
      # green having run nothing at all. Its own suite pins the schema subset the agents use; the
      # prepass suite feeds the pathless records the widened property exists for (agents-nhpb).
      mapped="$mapped tests/test_report_schema.py tests/test_vuln_verify_prepass.py"
      ;;
    agents/threat-model/report.schema.json)
      # Output contract for threat-model bootstrap slot (agents-uhru).
      mapped="$mapped tests/test_report_schema.py tests/test_factory_truth_2.py"
      ;;
    tools/gen_site.py)
      mapped="$mapped tests/test_gen_site.py"
      ;;
    tools/check.conf|tools/check-cmd.sh)
      # The gate's own command configuration and its resolver (agents-ia3p): the tracked
      # default, and the test that asserts the TRACKED config and the deployed CI
      # invocation agree. A change to either must run that test, or the drift guard is
      # decorative on exactly the edit that would break it.
      mapped="$mapped tests/test_check_conf_consistency.py tests/test_gate_entrypoint_config.py"
      ;;
    docs/*)
      # Documentation pages snapshot and publishing scope (agents-vt7w). tests/test_docs_drift.py
      # pins docs/INTEGRATION.md by content - and the numbers below are THAT SUITE'S lines, not the
      # page's: its Section 5 script-table test at :191 and its anchor filter at :485-492 (agents-xgha:
      # this used to read "docs/INTEGRATION.md ... its section anchors at :485-492", and
      # docs/INTEGRATION.md's own Section 5 does not begin until :408, so the sentence bound the
      # number to the wrong file). That is why it belongs in this union (agents-9nir review).
      mapped="$mapped tests/test_docs_design.py tests/test_pages_publish_scope.py tests/test_docs_drift.py"
      ;;
    lib/budget.py)
      # The station-command runner (agents-28nn round 8 grew on_spawn, the dispatcher's
      # engine-pid handoff to the credential broker's peer gate): its own unit suite, the
      # dispatcher suites that consume run_station_command, and the broker suite whose
      # peer-gate contract the handoff serves.
      #
      # agents-8z4z: tests/test_line_andon.py JOINS THIS UNION, AND THE EVIDENCE IS THE
      # GATE'S OWN COVERAGE ORACLE, NOT MY JUDGEMENT. On the change that wrapped the on_spawn
      # call, the fast gate PASSED while reporting `unmapped: ['lib/budget.py']` with
      # `omitted: ['tests/test_line_andon.py']` - the independent oracle had found this suite
      # as a consumer and caught that the union did not run it. It IS one: the line runner is
      # a run_station_command caller (the engine, pre-pass and findings dispatch call sites in
      # factory; agents-gioi: cited by ROLE, not by line - all three numbers that used to be here
      # have moved), and that suite imports StationTimeout from lib.budget (tests/test_line_andon.py:
      # :496 and :523) to drive the andon timeout path and COPIES lib/budget.py into its fixture tree
      # (tests/test_line_andon.py:112 - agents-xgha: all three numbers are THE SUITE'S, written bare
      # after "lib.budget" they read as lib/budget.py lines, where :112 is blank).
      # So a budget.py edit could change what the line runner does while the fast gate ran
      # only the three suites above - the same half-mapped shape agents-4ic0 fixed for
      # lib/adapters/pi.sh. Measured cost of the addition: 8.3 s (14 tests), against a 61 s
      # run for this arm's current union.
      mapped="$mapped tests/test_budget.py tests/test_factory_core.py tests/test_credential_broker.py tests/test_line_andon.py"
      ;;
    lib/containment.py)
      # agents-mo75. The generic lib/*.py arm below derives the suite from the changed file's
      # BASENAME, so this module mapped to tests/test_containment.py - and agents-3iog split the
      # containment suite into six modules, of which test_containment.py is the one that kept the
      # module's name. The THIN module was therefore what ran: measured, the name-based rule emitted
      # 2 suites and ran 55 tests, while the eight test files that import lib.containment run 151,
      # so five sibling modules and the child-env consumer were omitted and the gate still printed
      # PASS (the coverage oracle named them, which is how the omission was found). A name-based rule
      # cannot know a suite was split, so this one is a LIST - the same treatment
      # tests/containment_harness.py) gets above for the same reason. Measured cost of the addition:
      # about 8 s (61.5 s for the eight files against 53.3 s for the two the fallback chose).
      mapped="$mapped tests/test_containment.py tests/test_containment_declarations.py tests/test_containment_adapters.py tests/test_containment_engine_credentials.py tests/test_containment_prepass_pins.py tests/test_containment_egress.py tests/test_child_env.py"
      ;;
    lib/*.py)
      name="$(basename "$f" .py)"
      case "$name" in
        scheduler)     t="tests/test_schedules.py" ;;
        exclusions)    t="tests/test_prepass_exclusions.py" ;;
        *)             t="tests/test_${name}.py" ;;
      esac
      if [ -f "$t" ]; then
        mapped="$mapped $t"
      else
        echo "fast-gate: changed $f but $t does not exist — add that test file or extend the mapping" >&2
        exit 1
      fi
      ;;
    README.md|AGENTS.md|THREAT_MODEL.md|CLAUDE.md)
      # Root governance, architecture, and threat model documentation.
      # tests/test_docs_drift.py reads committed docs and checks drift, anchors, and references.
      mapped="$mapped tests/test_docs_drift.py"
      ;;
    .github/*)
      # CI definitions. tests/test_ci_action.py pins the committed .github/actions/**
      # (action.yml parse plus the untrusted-context guard over every run: body);
      # tests/test_pages_publish_scope.py reads the committed workflows/pages.yml. No
      # suite can EXECUTE a workflow, so this union is the bounded approximation.
      mapped="$mapped tests/test_ci_action.py tests/test_pages_publish_scope.py"
      ;;
    findings/suppressions.yaml)
      # The committed suppressions register; tests/test_suppressions.py reads it directly
      # (ROOT / "findings" / SUPPRESSIONS_FILENAME), so a change here is a contract change.
      mapped="$mapped tests/test_suppressions.py"
      ;;
    agents/*/SKILL.md)
      # The docs-drift scanner os.walk()s every committed .md outside IGNORE_DIRS (both walks live
      # in agents/docs-drift/scripts/check_docs.py, at :256 and :491; agents-xgha: the :466-478 range
      # cited here before is that file's markdown tree-block PREFIX parsing, which contains no walk)
      # and its real-tree suite pins the
      # agents/*/SKILL.md candidate set by count (tests/test_docs_drift.py:384-394). A path
      # grep cannot see this consumer - a walker consumes a CLASS of paths (agents-9nir review).
      mapped="$mapped tests/test_docs_drift.py"
      ;;
    agents/*/agent.yaml)
      # Station manifests are read off the real tree: tests/test_docs_design.py globs
      # agents/*/agent.yaml to check stations.html, and the credential-grant drift guard
      # globs them for the same reason (agents-9nir review). guards: agents-3iog moved that
      # guard into tests/test_containment_declarations.py, which is why this arm now runs 25
      # declaration tests instead of the whole 220-test containment suite; the dispatcher
      # suite holds no station-manifest consumer (its manifests are tmp trees), measured by
      # mutating agents/accessibility/agent.yaml: this arm red, the others green.
      mapped="$mapped tests/test_docs_design.py tests/test_containment_declarations.py"
      ;;
    agents/*/report.schema.json)
      # agents-9iyf. A MAPPING, not an ignore arm, and the chain is measured rather than
      # assumed: every agent.yaml names this file under output.schema (lib/report_schema.py:4),
      # lib/report_schema.py:38 validate() checks a model's report against that declared schema
      # subset at runtime, and tests/test_report_schema.py is that module's contract suite. So
      # the committed schema is not a test INPUT (see the search below) but the contract of the
      # code that consumes it is the honest thing to run.
      # SEARCH PERFORMED: `grep -rn report.schema.json tests/ lib/ tools/ factory` gives, apart
      # from agents/threat-model - which ALREADY had its own arm, the one beneath the
      # `agents/threat-model/report.schema.json)` pattern above (agents-22kv: cited by PATTERN, not
      # by line; the number that used to be here, :426, points at the tools/audit-tool-pins.sh arm)
      # and is why that file was never in the abort set (a first-match-wins case statement means my
      # duplicate arm for it was dead code, caught and removed before review):
      # test_adapter_auth_failure.py:128/:239, test_report_schema.py:107-123,
      # test_perf_review.py:945 - EVERY one writes a report.schema.json into a TMP fixture and
      # reads that back.
      # CONTRACT CHECK: tests/test_report_schema.py asserts every committed report.schema.json
      # stays inside the supported keyword subset and satisfies the report anatomy contract
      # (object type, required findings array with string rule_id and exact severity levels; agents-tz2y).
      # LIMITATION: structure is test-checked, but station-specific semantic fit still surfaces
      # only where the schema is consumed at runtime (agents-us59).
      mapped="$mapped tests/test_report_schema.py"
      ;;
    lines/*.yaml)
      # Line manifests are read off the real tree: tests/test_docs_design.py:78 globs
      # lines/*.yaml to check lines.html (agents-9nir review).
      mapped="$mapped tests/test_docs_design.py"
      ;;
    tools.yaml)
      # Runtime tool pins. lib/tool_pins.py reads the committed file at CONFIG_PATH when
      # FACTORY_TOOL_PINS is unset, and tests/test_child_env.py's resolve probes run against
      # the real repo WITHOUT the override, so the committed contents are asserted (a bd pin
      # would flip the fail-closed expectation); tests/test_tool_pins.py is the pins contract.
      mapped="$mapped tests/test_tool_pins.py tests/test_child_env.py"
      ;;
    targets/*.yaml)
      # Target inventory. lib/scheduler.py:140-144 GLOBS FACTORY_ROOT/"targets"/*.yaml, and
      # tests/test_schedules.py:200-213 and :311-360 spawn the REAL factory (FACTORY_ROOT is
      # derived from __file__, unmockable) as `schedule generate/list/--install --target
      # voicebox --agent secret-scan`, asserting "Generated (launchd):" - so the committed
      # targets/voicebox.yaml is load-bearing for that suite. Consumed WITHOUT BEING NAMED:
      # a subprocess with a default glob, invisible to a grep of the test file (agents-9nir
      # review round 2).
      mapped="$mapped tests/test_schedules.py"
      ;;
    reports/*.md)
      # Generated audit reports. reports/ is NOT in DEFAULT_IGNORE_DIRS (lib/exclusions.py:23-43
      # excludes findings/ and runs/ via FACTORY_ARTIFACT_DIRS at :11-15, not reports/), so the
      # docs-drift scanner DOES walk these files, and the real-tree fleet-resolution assertions
      # (tests/test_docs_drift.py:101-113) bind any walked .md that names a bare agent directory.
      mapped="$mapped tests/test_docs_drift.py"
      ;;
    agents/*/scripts/*.py)
      # agents-9iyf: THE CLASS ARM FOR STATION SCRIPTS. The table had only PER-FILE arms, so a
      # script nobody had enumerated (agents/log-check/scripts/parse_logs.py) failed the fast
      # gate and forced the lane to edit THIS shared file mid-branch - a merge hazard in a
      # parallel fleet, for 1 of the 30 aborting tracked files.
      # SEARCH PERFORMED AND ITS RESULT (the rule in the ignore block is that a reason must
      # record the search, never a judgement): `grep -rn parse_logs tests/` ->
      # tests/test_prepass_exclusions.py:126 imports it; and tests/test_redaction.py:757 is a
      # WALKER - `for path in sorted(ROOT.glob("agents/*/scripts/*.py"))` - so the redaction
      # contract is a property of the whole CLASS, which is exactly why this arm is class-wide.
      # tests/test_prepass_pin_boundary.py and tests/test_station_trusted_tool_pins.py are the
      # other class consumers (every station script's trusted-tool resolution is pinned there;
      # tests/test_fast_gate_mapping.py::test_station_trusted_tool_pins_mapped_for_prepass_scripts
      # holds that requirement and FAILED my first version of this arm, which omitted it -
      # evidence that the requirement is enforced rather than decorative).
      #
      # THE FIRST VERSION OF THIS ARM WAS A SILENT GREEN AND THE REVIEWER CAUGHT IT BY MUTATION
      # (rev-9iyf, agents-9iyf FAIL). It omitted tests/test_prepass_exclusions.py - the suite
      # that actually exercises agents/log-check/scripts/parse_logs.py - WHILE THE COMMENT TWO
      # LINES ABOVE RECORDED THAT VERY IMPORT (tests/test_prepass_exclusions.py:126; agents-xgha: the
      # bare `:126` written here before read as a parse_logs.py line, where :126 is blank). NOTING A CONSUMER IS NOT
      # COVERING IT: the omission reproduced exactly as measured -
      #   break parse_logs.py (find_logs -> return []):
      #     this arm's 3 suites      -> Ran 59 tests, OK (exit 0)   <-- THE GREEN
      #     tests.test_prepass_exclusions -> AssertionError: Lists differ: [] != ['app.log']
      # An arm that PASSES while the consumer fails is WORSE than the abort it replaced, because
      # the abort stopped the lane and named the file, and this converts a stop into a green.
      # THE METHOD THAT FINDS THIS CLASS, and the standard this arm is now held to: break one
      # file the arm covers and confirm AT LEAST ONE SUITE IN THE MAPPED SET GOES RED. Listing
      # the consumer is not the same as the arm going red, and a path grep cannot see a consumer
      # that is neither imported nor named (see the walker note in the ignore block above).
      #
      # DELIBERATELY THE LAST MAPPED ARM: first match wins in this case statement, so every
      # per-script arm above keeps its extra consumers, and this arm only catches scripts that
      # would otherwise abort. Measured cost: 69 tests, 7.1 s (verified: a script WITH its own
      # arm, agents/release-notes/scripts/gather_commits.py, still selects only that arm's three
      # suites, so this one neither shadows nor inflates them; and each suite is here for a
      # MEASURED reason - the red run above is what put test_prepass_exclusions.py in this list).
      mapped="$mapped tests/test_prepass_exclusions.py tests/test_redaction.py tests/test_prepass_pin_boundary.py tests/test_station_trusted_tool_pins.py"
      ;;
    # --- Ignore list (agents-9nir) -----------------------------------------------------
    # RULE: an ignore must be a DELIBERATE CASE ARM WITH A REASON, never a default.
    # "No arm" used to mean two different things - a considered exclusion and an
    # oversight - and they were indistinguishable, so every unmatched file was silently
    # masked by the smoke fallback below and the verdict read PASS for an unrelated
    # suite. The *) arm at the bottom fails loudly and NAMES any file no arm claims;
    # the smoke fallback after the loop is for ignored docs/config-only changes ONLY.
    # To exempt a path, add an arm here with the reason it needs no suite.
    # WARNING, learned the hard way (agents-9nir review, three instances in one bead): a
    # path grep cannot prove a path class is consumer-free, because a file can be consumed
    # WITHOUT BEING NAMED - by a WALKER (agents/*/SKILL.md via check_docs.py's os.walk),
    # by a GLOB (targets/*.yaml via lib/scheduler.py:140-144), and by a SUBPROCESS WITH A
    # DEFAULT PATH (tools.yaml via CONFIG_PATH / load_tool_pins in lib/tool_pins.py, read in
    # test_child_env.py's probes). Cited by SYMBOL, not by line: the line number this used to
    # name had drifted onto the FACTORY_TOOL_PINS override docstring (agents-lyqx).
    # So the reason in an ignore arm must record the SEARCH PERFORMED AND ITS RESULT,
    # never a judgement about who reads the path - a judgement is unfalsifiable, and that
    # is what made the original canvas `*.md` ignore arm's reason false.
    .beads/*)
      # The scanner never sees these: it skips dot dirs and .beads is in DEFAULT_IGNORE_DIRS
      # (lib/exclusions.py:23-43). Search performed: every .beads reference in tests mkdirs
      # its own tmp fixture (test_bd_json_contract.py:64, test_factory_core.py:727, test_sinks.py:92,
      # test_store_lock_timeout.py:277) - none reads the committed files. agents-xgha: the three
      # corrected numbers were 190/4/4 lines stale; the fourth (:64) held, and THAT is why this list
      # was reported at a different size every time it was scanned. Each number below is that suite's
      # own `.beads` fixture line.
      ;;
    findings/*.md)
      # findings/ is in FACTORY_ARTIFACT_DIRS (lib/exclusions.py:11-15), so the docs-drift
      # scanner never walks it; and findings/* is gitignored (only .gitkeep and
      # suppressions.yaml are force-tracked), so this arm only fires on a force-added file.
      ;;
    *.gitkeep)
      # Empty placeholders keeping otherwise-gitignored dirs (findings/, lines/,
      # schedules/) tracked. _FINDINGS_PROTECTED_NAMES in lib/retention.py protects
      # findings/.gitkeep by name (cited by SYMBOL, not by line: the number this used to name
      # had drifted onto unrelated symlink prose - agents-lyqx), but no suite reads the
      # committed files (test_retention.py uses tmp fixtures).
      ;;
    .gitignore)
      # VCS metadata, consumed only by git itself. Tests mention .gitignore only as
      # fixtures they write into tmp targets (test_containment.py, test_hillclimb.py).
      ;;
    patches/*)
      # Fleet tooling patches delivered to the hub (agents-19jh).
      # Consumed hub-side by PaulKinlan/fleet; not read by any factory suite or script.
      # Search performed: grep -rn "patches" across the codebase confirms no script, target,
      # runner, or test consumes this directory.
      ;;
    *)
      unmatched="$unmatched $f"
      ;;
  esac
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
  echo "fast-gate: To fix, add an arm to tools/fast-gate.sh (under 'mapping changed files') mapping the path to its test suite, or an ignore arm under '--- Ignore list (agents-9nir) ---' with documented search evidence (agents-9nir, agents-ows4, agents-dtj6)." >&2
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

# Fall back to a bounded smoke subset when nothing maps (an all-ignored docs/config-only
# change, or no delta at all). Unmatched files never reach here - they fail loudly above.
if [ -z "$run" ] && [ -z "$mapped" ]; then
  if [ -n "${FAST_GATE_DRY_RUN:-}" ]; then
    FAST_GATE_TERMINATED=1
    exit 0
  fi
  mapped="tests/test_factory_core.py"
fi

if ! files="$(printf '%s\n' $run $mapped $tree_guards | awk 'NF && !seen[$0]++' | sort)"; then
  echo "fast-gate: FAIL: could not compute the suite list (the dedupe pipeline failed)." >&2
  echo "fast-gate: the suites that were mapped are UNKNOWN, not empty - refusing to fall back to the smoke subset." >&2
  exit 1
fi

# Dry-run support for testing mapping resolution without invoking unittest.
if [ -n "${FAST_GATE_DRY_RUN:-}" ]; then
  FAST_GATE_TERMINATED=1
  printf '%s\n' $files
  exit 0
fi

FAST_GATE_STAGE="preparing runner"
modules="$(printf '%s\n' $files | sed 's#/#.#g; s#\.py$##' | tr '\n' ' ' | sed 's/ *$//')"

FAST_GATE_STAGE="running tests ($modules)"
echo "fast-gate: base=$BASE; running: python3 -u -m unittest $modules"

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

rc=0
if [ -n "$summary_file" ]; then
  # `tee -a` is load-bearing now: the header above is already in the file, and a plain tee would
  # truncate it away on the first byte of runner output (agents-qtnv).
  python3 -u -m unittest $modules > >(tee -a "$summary_file") 2> >(tee -a "$summary_file" >&2) || rc=$?
else
  python3 -u -m unittest $modules || rc=$?
fi

FAST_GATE_TERMINATED=1
if [ "$rc" -eq 0 ]; then
  passed_files="$(echo $files | tr '\n' ' ' | sed 's/ *$//')"
  echo "fast-gate: passed: $passed_files"
  exit 0
else
  echo "fast-gate: failed: exit $rc (modules: $modules)" >&2
  exit "$rc"
fi
