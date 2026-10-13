# tools/fast-gate-arms.d/120-tools_gen_site_py.sh — 2 arm(s), moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain (ADR 0001's assertion-consumer rule). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_120_tools_gen_site_py() {
  case "$1" in
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
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_120_tools_gen_site_py"
