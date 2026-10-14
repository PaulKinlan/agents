# tools/fast-gate-arms.d/012-tools_red_first_sh.sh — 1 arm(s). Read README.md in this directory before
# adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins. The fragment is
# numbered 012 so this SPECIFIC path is matched before any general tools/ arm that may be added later.
fast_gate_arms_012_tools_red_first_sh() {
  case "$1" in
    tools/red-first.sh)
      # agents-ea8h: THE GATE FAIL-CLOSED ON THIS FILE AS UNMAPPED, and that is how the omission was found
      # ("changed file(s) match no mapping arm and no ignore-list arm: tools/red-first.sh", 20:55:28, the
      # 1-second FAIL on the branch that introduced it). tools/red-first.sh is the red-first verification
      # tool: given a change it runs the changed tests at the tip, then against a red tree built from the
      # pre-fix implementation with the change's tests applied, and reports the discriminator and guard
      # sets rather than a bare green count. tests/test_red_first.py is its ONLY suite and the one that
      # proves the four teeth, the three vacuous-form rejections and the bogus-marker negative control, so
      # without this arm a change to the tool runs GREEN on the fast gate while its own guarantees are
      # unchecked. Cost, measured: 2.5s for the suite.
      mapped="$mapped tests/test_red_first.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_012_tools_red_first_sh"
