# tools/fast-gate-arms.d/060-tools_generate_tool_pins_s.sh — 2 arm(s), moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain (ADR 0001's assertion-consumer rule). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_060_tools_generate_tool_pins_s() {
  case "$1" in
    tools/generate-tool-pins.sh)
      # Operator-run pin generator (never invoked by the factory — its own header). SEARCH
      # PERFORMED (agents-28nn): `grep -rn "generate-tool-pins" tests/` named no suite before
      # this bead; agents-28nn adds the assertion that its TOOLS list covers every
      # TRUSTED_TOOLS entry to tests/test_tool_pins.py, which owns the pins contract.
      # agents-oc3q review P2: tests/test_pin_generator_hasher.py is added here because a
      # BEHAVIOURAL test of THIS script is what catches a re-introduction of the hole - the
      # suite pins that a planted hasher cannot supply the pin's reference value, and it only
      # runs on a generator change if this arm names it. Without this, a future edit putting
      # $PIN_LOOKUP_PATH back at the hasher call site would pass the fast gate.
      mapped="$mapped tests/test_tool_pins.py tests/test_pin_generator_hasher.py"
      ;;
    tools/audit-tool-pins.sh)
      # agents-5vun: the pins AUDIT - a detector that must be run to have any value, so the
      # suite that drives it (real forged files, real generator, exit codes) belongs here.
      # tests/test_pins_audit.py also PINS THE MEASURED LIMIT (a self-consistent forgery
      # whose path the lookup chooses passes), so the honest NOT-CHECKED text cannot be
      # quietly turned into a claim of security by a later edit.
      mapped="$mapped tests/test_pins_audit.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_060_tools_generate_tool_pins_s"
