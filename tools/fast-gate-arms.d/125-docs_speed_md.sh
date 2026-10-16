# tools/fast-gate-arms.d/125-docs_speed_md.sh — 1 arm. Read README.md in this directory before
# adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins. This fragment
# sits before 130-docs.sh so this SPECIFIC path is matched before the general `docs/*` arm.
fast_gate_arms_125_docs_speed_md() {
  case "$1" in
    docs/speed.md)
      # agents-vy4g6. docs/speed.md is the speed contract tools/full-gate.sh sends its over-budget reader
      # to (tools/full-gate.sh:343, "see docs/speed.md for the terms this budget belongs to"), so its
      # NAME=VALUE block is a statement about constants that live in tools/full-gate.sh and tools/check.conf
      # — it is an ASSERTION-CONSUMER of both (ADR 0001 §5), not prose. Without this arm a docs-only edit
      # to those numbers selects arm 130's page suites and nothing that reads the numbers, so the doc could
      # state a budget the code does not enforce and stay green: the silent-rot shape, in the one file that
      # exists to stop a premise being re-derived instead of read. The pin is one class in
      # tests/test_check_conf_consistency.py, which arms 015 and 120 already select when the CODE side of
      # the pair changes, so both directions are covered by naming the doc side here.
      mapped="$mapped tests/test_check_conf_consistency.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_125_docs_speed_md"
