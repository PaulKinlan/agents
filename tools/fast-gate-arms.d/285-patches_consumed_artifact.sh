# tools/fast-gate-arms.d/285-patches_consumed_artifact.sh — 1 arm, added by agents-pgv9.
#
# WHY 285 AND NOT AN EDIT TO 290: the registry's rule is one new file per delivery, and precedence is the
# filename - the loader stops at the FIRST arm that matches. 290-patches_patch.sh holds the general
# `patches/*.patch` arm, so the specific artifact below has to be answered EARLIER or the general arm
# claims it and this one is never reached (README.md, "The number is the precedence").
fast_gate_arms_285_patches_consumed_artifact() {
  case "$1" in
    patches/red-first-pre-fix-tree-not-commit-object.patch)
      # agents-pgv9: DO SELECT WHAT CONSUMED IT. A changed or DELETED patches/ path must bring in the
      # suites that READ or NAME it, or a deletion passes a green gate while the tests that depended on
      # the deleted file sit unselected.
      #
      # MEASURED, NOT THEORETICAL: a boundary branch deleted 173 artifacts from patches/ and the fast
      # gate returned PASS on the same frozen tree where TWO of this repo's own suites failed
      # (tests/test_fleet_check_tree_stability_inbox.py and tests/test_fleet_reviewer_fallback_refusal.py,
      # both since removed with the artifacts they drove). The deletion selected nothing, so their failure
      # was invisible to the gate that exists to catch it.
      #
      # THE OTHER HALF OF THE CONTRACT, which is why this is one policy and not two patches: 290's general
      # arm is right - patches/*.patch is deliberately mapped to NOTHING because these are diff artifacts
      # consumed hub-side by git apply, NOT suites to run. What was missing is the rule for a path that no
      # longer exists:
      #   * agents-l7tk: a DELETED tests/*.py path WAS handed to the runner with no existence check, so the
      #     gate died with ModuleNotFoundError - THE DELETED FILE IS SELECTED. Fixed by the existence guard
      #     in 010-tests_test_tree_guards_py.sh.
      #   * agents-pgv9 (here): its CONSUMER IS NOT SELECTED.
      # Together: do not select what is gone, and do select what consumed it.
      #
      # WHO CONSUMES THIS, derived from a revision-pinned scan rather than a filesystem walk - a walk counts
      # __pycache__ build products, measured when this arm was written: `git grep` at a revision found 7
      # files naming patches/, `grep -rl` found 12, and 5 of those 12 were .pyc.
      #   tests/test_patch_writeups.py pins the write-up<->artifact pairing for every artifact in the
      #   directory, in BOTH directions: each artifact must be named by a write-up, and each artifact a
      #   write-up names must still exist. agents-pgv9 added that second direction, and it is what makes
      #   this suite able to FAIL on the deletion this arm selects it for - without it this arm would be
      #   selecting a suite that cannot fail, which is the same defect one layer up.
      #
      # DELIBERATELY NOT tests/test_fast_gate_mapping.py, although that suite names this path: its
      # assertion is about the MAPPING, so it cannot move when the artifact changes, and it measures 50.1s
      # (tools/fast-gate.sh calls a permanent 0.50s tax a design smell). Selecting it would trade a
      # selection gap for a per-change tax and buy no assertion about this file.
      #
      # COST, MEASURED: 0.09s for tests/test_patch_writeups.py, against a 0.21s dry-run baseline for this
      # path - so ~0.30s on a change to a patch artifact, and 0 on every other class of change.
      #
      # NOT A RETURN TO RUNNING EVERYTHING: the artifacts stay ignored, this is one arm for one consumed
      # artifact, and a patches/ path that NO suite reads or names still maps to nothing (pinned by
      # tests/test_fast_gate_mapping.py::test_a_patch_path_no_suite_reads_or_names_selects_nothing).
      mapped="$mapped tests/test_patch_writeups.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_285_patches_consumed_artifact"
