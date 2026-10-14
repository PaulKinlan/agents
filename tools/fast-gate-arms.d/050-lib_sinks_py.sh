# tools/fast-gate-arms.d/050-lib_sinks_py.sh — 8 arm(s), moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain (ADR 0001's assertion-consumer rule). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_050_lib_sinks_py() {
  case "$1" in
    lib/sinks/*.py)
      # Tracker-sink adapters (fleet-km8): covered by the sink harness, the bd contract, promotion, layering, and adapter registry/commands.
      mapped="$mapped tests/test_sinks.py tests/test_bd_json_contract.py tests/test_promotion.py tests/test_sink_layering.py tests/test_sink_adapters.py"
      ;;
    lib/line_numbers.py)
      # agents-g9e2 + agents-iwaj: THE ONE MODULE IN THIS FILE WHOSE ASSERTION-CONSUMERS ARE NOT ITS
      # IMPORTERS. The coverage oracle's rule is a CODE import (test_fast_gate_consumer_coverage.py,
      # _importing_suites), and it strips comments and docstrings on purpose - that stripping was
      # calibrated against the fleet oracle in agents-pdth, and without it the count was wrong by one.
      # So the oracle cannot see tests/test_redaction.py, which asserts this module's contract at line
      # 338 ("matching lib.line_numbers.usable_line_number") WITHOUT importing it: a comment is not an
      # import, and a behavioural contract need not be. These are the four suites that assert this
      # module's behaviour rather than merely naming it. Deliberately NOT here: tests/test_sinks.py and
      # tests/test_factory_core.py (whole-tree sweeps, Tier-3 business), tests/test_gen_site.py (names
      # line numbers as a redaction subject) and tests/test_line_numbers.py, which the generic lib/*.py
      # arm below already selects.
      mapped="$mapped tests/test_line_numbers.py tests/test_redaction.py tests/test_sandbox_fixtures.py tests/test_vuln_triage_prepass.py tests/test_vuln_verify_prepass.py"
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
      # tests/test_candidate_identity.py imports FindingsStore and load_candidate_index, so it asserts
      # this module's index/rekey expectations and moves with it - agents-l606 changed the store's
      # (new, rekeyed, fixed) counts and this suite's expected (2, 2) went RED while the fast gate stayed
      # green, because the suite sat in the consumer-coverage allowlist instead of in this arm; the author
      # only found it by running the omitted suites by hand. The allowlist entry is deleted with this
      # mapping (agents-ozmt), and the two-sided guard in tests/test_fast_gate_consumer_coverage.py keeps
      # it deleted: restoring the entry now fails as stale, and dropping this name fails as an omission.
      mapped="$mapped tests/test_candidate_identity.py"
      # The lock is only observable from OUTSIDE a single process, so this suite is the only one
      # that can see a regression to the unbounded wait (agents-4sij).
      mapped="$mapped tests/test_store_lock_timeout.py"
      # agents-w9ni: tests/test_station_candidate_accounting.py now IMPORTS this module - candidate_coverage,
      # read_presented_candidate_ids and write_line_report - to pin the identity-vs-count bound and to pin
      # that count-only is MARKED wherever the count is shown. An imported consumer the arm does not select
      # is a suite CI would skip the moment this module changes, which is exactly the omission the coverage
      # oracle reports. Its embargo-side claim (the dismissal vocabulary) stays mapped in
      # 140-lib_budget_py.sh, where agents-f8dj put it; one suite can belong to two arms.
      mapped="$mapped tests/test_station_candidate_accounting.py"
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
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_050_lib_sinks_py"
