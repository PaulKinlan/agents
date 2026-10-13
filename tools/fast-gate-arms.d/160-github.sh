# tools/fast-gate-arms.d/160-github.sh — 1 arm(s), moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain (ADR 0001's assertion-consumer rule). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_160_github() {
  case "$1" in
    .github/*)
      # CI definitions. tests/test_ci_action.py pins the committed .github/actions/**
      # (action.yml parse plus the untrusted-context guard over every run: body);
      # tests/test_pages_publish_scope.py reads the committed workflows/pages.yml. No
      # suite can EXECUTE a workflow, so this union is the bounded approximation.
      mapped="$mapped tests/test_ci_action.py tests/test_pages_publish_scope.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_160_github"
