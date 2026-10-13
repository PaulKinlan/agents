# tools/fast-gate-arms.d/170-findings_suppressions_yaml.sh — 1 arm(s), moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain (ADR 0001's assertion-consumer rule). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_170_findings_suppressions_yaml() {
  case "$1" in
    findings/suppressions.yaml)
      # The committed suppressions register; tests/test_suppressions.py reads it directly
      # (ROOT / "findings" / SUPPRESSIONS_FILENAME), so a change here is a contract change.
      mapped="$mapped tests/test_suppressions.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_170_findings_suppressions_yaml"
