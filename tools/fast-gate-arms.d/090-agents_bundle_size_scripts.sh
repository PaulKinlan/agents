# tools/fast-gate-arms.d/090-agents_bundle_size_scripts.sh — 8 arm(s), moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain (ADR 0001's assertion-consumer rule). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_090_agents_bundle_size_scripts() {
  case "$1" in
    agents/bundle-size/scripts/measure_bundle.py)
      mapped="$mapped tests/test_bundle_size.py"
      ;;
    agents/threat-model/scripts/mine_history.py)
      mapped="$mapped tests/test_threat_model_prepass.py"
      ;;
    agents/perf-hillclimb/scripts/measure_and_context.py)
      mapped="$mapped tests/test_hillclimb.py"
      ;;
    agents/docs-write/scripts/prepare_docs_fixes.py)
      # agents-tdwv: ALSO the suite for THIS script's own error handling, same
      # one-token shape as the arm above.
      mapped="$mapped tests/test_prepass_exclusions.py tests/test_docs_write.py"
      ;;
    agents/docs-drift/scripts/check_docs.py)
      # agents-q0mt: also emits candidate ids now; the exclusion suite drives this script, and the
      # emission pin reads the id out of a real artefact.
      mapped="$mapped tests/test_docs_drift.py tests/test_prepass_exclusions.py tests/test_candidate_id_emission.py tests/test_prepass_pin_boundary.py"
      ;;
    agents/vuln-triage/scripts/triage.py)
      mapped="$mapped tests/test_vuln_triage_prepass.py"
      ;;
    agents/issue-triage/scripts/fetch_issues.py)
      mapped="$mapped tests/test_issue_triage_prepass.py tests/test_prepass_pin_boundary.py tests/test_redaction.py tests/test_docs_drift.py"
      ;;
    agents/release-notes/scripts/gather_commits.py)
      # agents-28nn round 4: gather_commits resolves git through the pin, pinned by
      # tests/test_prepass_pin_boundary.py. tests/test_redaction.py parses every agents/*/scripts/*.py,
      # and tests/test_docs_drift.py owns the prose.
      mapped="$mapped tests/test_prepass_pin_boundary.py tests/test_redaction.py tests/test_docs_drift.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_090_agents_bundle_size_scripts"
