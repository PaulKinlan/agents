# tools/fast-gate-arms.d/260-findings_md.sh — 1 arm(s), moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain (ADR 0001's assertion-consumer rule). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_260_findings_md() {
  case "$1" in
    findings/*.md)
      # findings/ is in FACTORY_ARTIFACT_DIRS (lib/exclusions.py:11-15), so the docs-drift
      # scanner never walks it; and findings/* is gitignored (only .gitkeep and
      # suppressions.yaml are force-tracked), so this arm only fires on a force-added file.
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_260_findings_md"
