# tools/fast-gate-arms.d/210-targets_yaml.sh — 1 arm(s), moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain (ADR 0001's assertion-consumer rule). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_210_targets_yaml() {
  case "$1" in
    targets/*.yaml)
      # Target inventory. lib/scheduler.py:140-144 GLOBS FACTORY_ROOT/"targets"/*.yaml, and
      # tests/test_schedules.py:200-213 and :311-360 spawn the REAL factory (FACTORY_ROOT is
      # derived from __file__, unmockable) as `schedule generate/list/--install --target
      # voicebox --agent secret-scan`, asserting "Generated (launchd):" - so the committed
      # targets/voicebox.yaml is load-bearing for that suite. Consumed WITHOUT BEING NAMED:
      # a subprocess with a default glob, invisible to a grep of the test file (agents-9nir
      # review round 2).
      mapped="$mapped tests/test_schedules.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_210_targets_yaml"
