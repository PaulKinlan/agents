# tools/fast-gate-arms.d/190-lines_yaml.sh — 1 arm(s), moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain (ADR 0001's assertion-consumer rule). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_190_lines_yaml() {
  case "$1" in
    lines/*.yaml)
      # Line manifests are read off the real tree: tests/test_docs_design.py:78 globs
      # lines/*.yaml to check lines.html (agents-9nir review).
      mapped="$mapped tests/test_docs_design.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_190_lines_yaml"
