# tools/fast-gate-arms.d/170-agents_ui_ux_audit_SKILL_md.sh — 1 arm, agents-txhd. Read README.md in this
# directory before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_170_agents_ui_ux_audit_SKILL_md() {
  case "$1" in
    agents/ui-ux-audit/SKILL.md)
      # NUMBERED 170, i.e. BEFORE 180-agents_SKILL_md.sh, AND THAT IS THE WHOLE POINT: 180 matches
      # agents/*/SKILL.md, and because the first matching arm wins, an arm for this path numbered after
      # it would be DEAD CODE - green in review and never consulted in a gate (agents-9nir review's rule).
      # 180's CONSUMER IS PRESERVED HERE, NOT REPLACED, and it is listed first for that reason: the
      # docs-drift walker os.walk()s every committed .md and its real-tree suite pins the agents/*/SKILL.md
      # candidate set by count (tests/test_docs_drift.py:384-394, the citation 180 itself carries). A
      # change to this SKILL therefore still runs that suite.
      # THE SECOND CONSUMER IS THIS STATION'S OWN CONTRACT: the rule at SKILL.md:23 concedes a gap it
      # cannot decide from declarations (font_size_values_unparsed) and now names the rendered sweep that
      # closes it, so tests/test_ui_ux_station_contract.py asserts the route is named IN THAT BULLET and
      # that the tool it names exists. MEASURED RED-FIRST: with the bullet as it stood (no tool named) that
      # suite reports FAILED (failures=2) - the assertion itself and its own anti-vacuity control; naming the
      # sweep takes it to 3 passed.
      mapped="$mapped tests/test_docs_drift.py tests/test_ui_ux_station_contract.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_170_agents_ui_ux_audit_SKILL_md"
