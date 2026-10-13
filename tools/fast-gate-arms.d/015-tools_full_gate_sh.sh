# tools/fast-gate-arms.d/015-tools_full_gate_sh.sh — 1 arm, moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain. Read README.md in this directory before adding an arm: PRECEDENCE
# IS THE NUMERIC PREFIX, and the first matching arm wins. This fragment sits before
# 020-tools_fast_gate_sh.sh because that is where the arm sat in the old table.
fast_gate_arms_015_tools_full_gate_sh() {
  case "$1" in
    tools/full-gate.sh)
      # The full gate is the merger/CI entrypoint; exercise its synthetic shard
      # failures and the tracked wiring/summary identity whenever it changes.
      mapped="$mapped tests/test_full_gate_sharding.py tests/test_check_conf_consistency.py tests/test_summary_identity.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_015_tools_full_gate_sh"
