# agents-xe24o: tests/test_redaction.py::RuleLabelShapeTest reads THIS station's SKILL.md from the
# real tree (the DOCS tuple at tests/test_redaction.py:952-966) and pins its documented `rule_id`
# example against lib/redaction.sanitise_identity, so an edit to the example here can turn that
# suite red without any arm selecting it. The generic agents/*/SKILL.md arm at 180 maps only the
# docs-drift walker suite; mapping test_redaction.py THERE would tax every station SKILL change the
# redaction contract suite's cost for a consumer only this station has - so it rides a narrow
# per-station arm ahead of 180, the same shape the log-check arm chose at 175. tests/test_docs_drift.py
# stays named HERE: first match wins, so this arm must carry the walker consumer the 180 arm would
# otherwise have provided for this path.
fast_gate_arms_176_agents_test_gap_SKILL_md() {
  case "$1" in
    agents/test-gap/SKILL.md)
      mapped="$mapped tests/test_docs_drift.py tests/test_redaction.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_176_agents_test_gap_SKILL_md"
