# tools/fast-gate-arms.d/300-tools_docs_text_floor_sh.sh — 1 arm(s). Read README.md in this directory before
# adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins. The fragment is
# numbered 300 (after every fragment present today) so this SPECIFIC path is matched before any general
# tools/ arm that may be added later.
fast_gate_arms_300_tools_docs_text_floor_sh() {
  case "$1" in
    tools/docs-text-floor.sh)
      # THE GATE FAIL-CLOSED ON THIS FILE AS UNMAPPED AND THAT IS HOW THE OMISSION WAS FOUND: "changed file(s)
      # match no mapping arm and no ignore-list arm: tools/docs-text-floor.sh", a 1-second FAIL on the branch that
      # introduced it - the same way agents-ea8h found tools/red-first.sh's missing arm. tools/docs-text-floor.sh
      # measures the RENDERED font size of every text-bearing leaf element on every docs page, which is the thing
      # a declaration-scanning rule cannot see (`.72rem` appeared four times in docs/css/factory.css and hit four
      # different rules). tests/test_docs_text_floor.py is its ONLY suite, and without this arm a change to the
      # tool runs GREEN on the fast gate while its own plumbing - which docs dir it resolves, that the injected
      # control site is the copy actually measured, and its three exit codes - goes unchecked. It drives the tool
      # with a stub chrome on PATH, so the fast gate never launches a browser: the real measurements (before: index
      # 5, lines 4, stations 113, use/help/install 1; after: every page below=0; control: below=1 with
      # p.__fifth_site=11.00px) were taken against real Chrome and are recorded with the change.
      # Cost, measured: 1.0s for the 13 tests (no browser is started; the stub is what makes it that cheap).
      mapped="$mapped tests/test_docs_text_floor.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_300_tools_docs_text_floor_sh"
