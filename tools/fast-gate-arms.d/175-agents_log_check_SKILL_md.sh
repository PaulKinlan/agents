# The log-check report example is an executable schema contract; keep this specific
# arm before the generic agents/*/SKILL.md arm at 180. Preserve its docs-drift consumer.
# tests/test_redaction.py:952-966 also reads this real SKILL.md example's rule_id;
# a changed documented label must reach its sanitise_identity contract (agents-qcggu).
fast_gate_arms_175_agents_log_check_SKILL_md() {
  case "$1" in
    agents/log-check/SKILL.md)
      mapped="$mapped tests/test_docs_drift.py tests/test_report_schema.py tests/test_redaction.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_175_agents_log_check_SKILL_md"
