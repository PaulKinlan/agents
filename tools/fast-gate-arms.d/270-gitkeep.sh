# tools/fast-gate-arms.d/270-gitkeep.sh — 1 arm(s), moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain (ADR 0001's assertion-consumer rule). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_270_gitkeep() {
  case "$1" in
    *.gitkeep)
      # Empty placeholders keeping otherwise-gitignored dirs (findings/, lines/,
      # schedules/) tracked. _FINDINGS_PROTECTED_NAMES in lib/retention.py protects
      # findings/.gitkeep by name (cited by SYMBOL, not by line: the number this used to name
      # had drifted onto unrelated symlink prose - agents-lyqx), but no suite reads the
      # committed files (test_retention.py uses tmp fixtures).
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_270_gitkeep"
