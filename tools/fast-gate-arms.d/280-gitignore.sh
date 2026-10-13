# tools/fast-gate-arms.d/280-gitignore.sh — 1 arm(s), moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain (ADR 0001's assertion-consumer rule). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_280_gitignore() {
  case "$1" in
    .gitignore)
      # agents-ah03 (rev-cqrm's weekly review): THIS ARM USED TO IGNORE .gitignore. Its reason was
      # "VCS metadata, consumed only by git itself. Tests mention .gitignore only as fixtures they
      # write into tmp targets (test_containment.py, test_hillclimb.py)" - and THAT EVIDENCE IS TRUE
      # BUT INCOMPLETE, which is the worst way for an ignore arm to be wrong: an ignore arm does not
      # merely omit a suite, it SUPPRESSES THE SMOKE FALLBACK (see the "nothing maps" branch below), so
      # a .gitignore change ran only tests/test_factory_core.py while a suite that pins the file's
      # CONTRACT existed and was never selected. The two fixtures cited above really do write their own
      # .gitignore into a tmp target; the missed consumer is a THIRD suite that reads the committed one:
      # tests/test_docs_drift.py::TestPlanFindingsStoreAgreement executes `git check-ignore -q --no-index`
      # against the repository and asserts findings/*.md IS ignored and findings/suppressions.yaml is NOT
      # ignored and IS tracked - all of which the committed .gitignore decides, so editing it can turn
      # that suite red. Cited by SYMBOL, not by line: the review named :579-636 and those numbers move.
      # (Measured: a grep of tests/*.py for .gitignore finds exactly these three, plus this file's own
      # mapping test, which no longer lists .gitignore as ignorable.)
      mapped="$mapped tests/test_docs_drift.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_280_gitignore"
