# tools/fast-gate-arms.d/105-tests_cheap_tool_pins_py.sh — 1 arm. Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_105_tests_cheap_tool_pins_py() {
  case "$1" in
    tests/cheap_tool_pins.py)
      # The stand-ins for the tools the pin generator hashes, shared by every suite that runs the
      # generator (agents-z3cp5). It has no suite of its own to map to, so a change here must run the
      # three suites whose arms depend on it - otherwise a change to the stand-ins, or to the drift
      # contract the list carries with the generator's TOOLS line, reaches main unexercised. Mapped to
      # the consumers rather than to an ignore arm on purpose: the whole point of this file is the
      # arms' behaviour, so "no suite" would be a false economy.
      mapped="$mapped tests/test_pin_generator_hasher.py tests/test_pins_audit.py tests/test_tool_pins.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_105_tests_cheap_tool_pins_py"
