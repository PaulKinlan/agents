# tools/fast-gate-arms.d/230-patches_md.sh — 1 arm(s), moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain (ADR 0001's assertion-consumer rule). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_230_patches_md() {
  case "$1" in
    patches/*.md)
      # Fleet tooling documentation (agents-g1je). patches/ is NOT in DEFAULT_IGNORE_DIRS
      # (lib/exclusions.py:23-43), so the docs-drift scanner (agents/docs-drift/scripts/check_docs.py)
      # walks these markdown files, and tests/test_docs_drift.py asserts reference and anchor
      # validity across the real repository tree.
      #
      # Patch write-up structural shape (agents-2to0 / agents-hzug). tests/test_patch_writeups.py
      # asserts that each write-up starts with '## ' (section heading), has balanced code fences,
      # ends with a newline, and names its patch artifact. Closing clearance gap where write-ups
      # starting with '# ' passed fast gate but failed merger full gate.
      mapped="$mapped tests/test_docs_drift.py tests/test_patch_writeups.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_230_patches_md"
