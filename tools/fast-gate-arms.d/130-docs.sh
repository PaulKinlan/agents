# tools/fast-gate-arms.d/130-docs.sh — 1 arm(s), moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain (ADR 0001's assertion-consumer rule). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_130_docs() {
  case "$1" in
    docs/*)
      # Documentation pages snapshot and publishing scope (agents-vt7w). tests/test_docs_drift.py
      # pins docs/INTEGRATION.md by content - and the numbers below are THAT SUITE'S lines, not the
      # page's: its Section 5 script-table test at :191 and its anchor filter at :485-492 (agents-xgha:
      # this used to read "docs/INTEGRATION.md ... its section anchors at :485-492", and
      # docs/INTEGRATION.md's own Section 5 does not begin until :408, so the sentence bound the
      # number to the wrong file). That is why it belongs in this union (agents-9nir review).
      mapped="$mapped tests/test_docs_design.py tests/test_pages_publish_scope.py tests/test_docs_drift.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_130_docs"
