# tools/fast-gate-arms.d/240-agents_scripts_py.sh — 1 arm(s), moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain (ADR 0001's assertion-consumer rule). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_240_agents_scripts_py() {
  case "$1" in
    agents/*/scripts/*.py)
      # agents-9iyf: THE CLASS ARM FOR STATION SCRIPTS. The table had only PER-FILE arms, so a
      # script nobody had enumerated (agents/log-check/scripts/parse_logs.py) failed the fast
      # gate and forced the lane to edit THIS shared file mid-branch - a merge hazard in a
      # parallel fleet, for 1 of the 30 aborting tracked files.
      # SEARCH PERFORMED AND ITS RESULT (the rule in the ignore block is that a reason must
      # record the search, never a judgement): `grep -rn parse_logs tests/` ->
      # tests/test_prepass_exclusions.py:126 imports it; and tests/test_redaction.py:757 is a
      # WALKER - `for path in sorted(ROOT.glob("agents/*/scripts/*.py"))` - so the redaction
      # contract is a property of the whole CLASS, which is exactly why this arm is class-wide.
      # tests/test_prepass_pin_boundary.py and tests/test_station_trusted_tool_pins.py are the
      # other class consumers (every station script's trusted-tool resolution is pinned there;
      # tests/test_fast_gate_mapping.py::test_station_trusted_tool_pins_mapped_for_prepass_scripts
      # holds that requirement and FAILED my first version of this arm, which omitted it -
      # evidence that the requirement is enforced rather than decorative).
      #
      # THE FIRST VERSION OF THIS ARM WAS A SILENT GREEN AND THE REVIEWER CAUGHT IT BY MUTATION
      # (rev-9iyf, agents-9iyf FAIL). It omitted tests/test_prepass_exclusions.py - the suite
      # that actually exercises agents/log-check/scripts/parse_logs.py - WHILE THE COMMENT TWO
      # LINES ABOVE RECORDED THAT VERY IMPORT (tests/test_prepass_exclusions.py:126; agents-xgha: the
      # bare `:126` written here before read as a parse_logs.py line, where :126 is blank). NOTING A CONSUMER IS NOT
      # COVERING IT: the omission reproduced exactly as measured -
      #   break parse_logs.py (find_logs -> return []):
      #     this arm's 3 suites      -> Ran 59 tests, OK (exit 0)   <-- THE GREEN
      #     tests.test_prepass_exclusions -> AssertionError: Lists differ: [] != ['app.log']
      # An arm that PASSES while the consumer fails is WORSE than the abort it replaced, because
      # the abort stopped the lane and named the file, and this converts a stop into a green.
      # THE METHOD THAT FINDS THIS CLASS, and the standard this arm is now held to: break one
      # file the arm covers and confirm AT LEAST ONE SUITE IN THE MAPPED SET GOES RED. Listing
      # the consumer is not the same as the arm going red, and a path grep cannot see a consumer
      # that is neither imported nor named (see the walker note in the ignore block above).
      #
      # DELIBERATELY THE LAST MAPPED ARM: first match wins in this case statement, so every
      # per-script arm above keeps its extra consumers, and this arm only catches scripts that
      # would otherwise abort. Measured cost: 69 tests, 7.1 s (verified: a script WITH its own
      # arm, agents/release-notes/scripts/gather_commits.py, still selects only that arm's three
      # suites, so this one neither shadows nor inflates them; and each suite is here for a
      # MEASURED reason - the red run above is what put test_prepass_exclusions.py in this list).
      mapped="$mapped tests/test_prepass_exclusions.py tests/test_redaction.py tests/test_prepass_pin_boundary.py tests/test_station_trusted_tool_pins.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_240_agents_scripts_py"
