# tools/fast-gate-arms.d/030-tests_init_py.sh — 4 arm(s), moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain (ADR 0001's assertion-consumer rule). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_030_tests_init_py() {
  case "$1" in
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
    tests/fast_gate_allowlists.d/*)
      # agents-nerv: the per-lane allowlist FRAGMENTS. Before this arm the gate REFUSED a change to one
      # of them ("changed file(s) match no mapping arm"), which would have made the fragments worse than
      # the single dict they replace: a lane that omits a consumer must be able to drop its own file and
      # get a gate, not a refusal. SEARCH PERFORMED: the fragments are read by exactly one suite - the
      # loader in tests/test_fast_gate_consumer_coverage.py is the only consumer of this directory (the
      # JSON is that test's allowlist, not part of the gate's own arm selection). That suite is also
      # added to every mapped run by the consumer_coverage pin below, so this arm's remaining job is to
      # make the path MAPPED at all: an unmapped path fails loudly before any runner starts.
      mapped="$mapped tests/test_fast_gate_consumer_coverage.py"
      ;;
    tests/coverage-contract.json)
      # Contract-declared cross-file coverage dependencies (agents-1kzf).
      mapped="$mapped tests/test_coverage_contract.py tests/test_fast_gate_mapping.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_030_tests_init_py"
