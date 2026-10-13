# tools/fast-gate-arms.d/290-patches_patch.sh — 1 arm(s), moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain (ADR 0001's assertion-consumer rule). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_290_patches_patch() {
  case "$1" in
    patches/*.patch)
      # Fleet tooling patch diff artifacts delivered to the hub (agents-19jh, agents-g1je).
      # Consumed hub-side by git apply in PaulKinlan/fleet; not read by any factory suite or script.
      # Search performed:
      # - Walkers: check_docs.py only walks .md for documentation and specific code extensions
      #   (.py, .sh, etc.) for symbols; .patch files are skipped by extension.
      # - Globs: grep -rn "patches/" across lib/, agents/, tests/, and factory confirms no
      #   glob or script references these artifacts.
      # - Subprocesses: no runner or station subprocess defaults to patches/*.patch.
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_290_patches_patch"
