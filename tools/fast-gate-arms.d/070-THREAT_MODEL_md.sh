# tools/fast-gate-arms.d/070-THREAT_MODEL_md.sh — 1 arm(s), moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain (ADR 0001's assertion-consumer rule). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_070_THREAT_MODEL_md() {
  case "$1" in
    THREAT_MODEL.md)
      # Root markdown the docs-drift scanner WALKS (check_docs.py os.walk()s every committed
      # .md outside IGNORE_DIRS). SEARCH PERFORMED (agents-28nn): `grep -rn 'ROOT /
      # "THREAT_MODEL' tests/` finds no direct reader; the test_threat_model_prepass.py hits
      # are fixture strings for the findings-store recognizer, not the committed file.
      mapped="$mapped tests/test_docs_drift.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_070_THREAT_MODEL_md"
