# tools/fast-gate-arms.d/220-reports_md.sh — 1 arm(s), moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain (ADR 0001's assertion-consumer rule). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_220_reports_md() {
  case "$1" in
    reports/*.md)
      # Generated audit reports. reports/ is NOT in DEFAULT_IGNORE_DIRS (lib/exclusions.py:23-43
      # excludes findings/ and runs/ via FACTORY_ARTIFACT_DIRS at :11-15, not reports/), so the
      # docs-drift scanner DOES walk these files, and the real-tree fleet-resolution assertions
      # (tests/test_docs_drift.py:101-113) bind any walked .md that names a bare agent directory.
      mapped="$mapped tests/test_docs_drift.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_220_reports_md"
