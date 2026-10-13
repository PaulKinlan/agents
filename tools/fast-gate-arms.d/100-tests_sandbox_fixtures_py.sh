# tools/fast-gate-arms.d/100-tests_sandbox_fixtures_py.sh — 1 arm(s), moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain (ADR 0001's assertion-consumer rule). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_100_tests_sandbox_fixtures_py() {
  case "$1" in
    tests/sandbox_fixtures.py)
      # Shared fixture builder for tests (agents-8ztd); its own suite pins the property that a new
      # lib import reaches a sandbox without a fixture change.
      mapped="$mapped tests/test_sandbox_fixtures.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_100_tests_sandbox_fixtures_py"
