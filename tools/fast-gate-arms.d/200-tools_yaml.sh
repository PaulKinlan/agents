# tools/fast-gate-arms.d/200-tools_yaml.sh — 1 arm(s), moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain (ADR 0001's assertion-consumer rule). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_200_tools_yaml() {
  case "$1" in
    tools.yaml)
      # Runtime tool pins. lib/tool_pins.py reads the committed file at CONFIG_PATH when
      # FACTORY_TOOL_PINS is unset, and tests/test_child_env.py's resolve probes run against
      # the real repo WITHOUT the override, so the committed contents are asserted (a bd pin
      # would flip the fail-closed expectation); tests/test_tool_pins.py is the pins contract.
      mapped="$mapped tests/test_tool_pins.py tests/test_child_env.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_200_tools_yaml"
