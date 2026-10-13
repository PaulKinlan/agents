# tools/fast-gate-arms.d/010-tests_test_tree_guards_py.sh — 3 arm(s), moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain (ADR 0001's assertion-consumer rule). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_010_tests_test_tree_guards_py() {
  case "$1" in
    tests/test_tree_guards.py)
      # agents-azi1 (found by the merger landing a union, not by anyone anticipating it): THE ALWAYS-ON
      # TIER FILE IS GUARDED BY ITS CONTENTS, AND ITS GUARD LIVES IN THE MAPPING SUITE. This file must
      # hold EXACTLY ['TestNoUnboundedSubprocess'] (agents-dv23), asserted by
      # tests/test_fast_gate_mapping.py::test_tree_guard_tier_module_holds_only_tree_property_tests
      # (cited by SYMBOL: a line number here drifts as that suite grows). Without the mapping suite
      # selected, ADDING A CLASS to this file runs GREEN on the fast gate and RED on the full gate - a
      # real verdict about the file under review that is BLIND to the rule governing it, which is worse
      # than an omission. It cannot ride the always-on tier (tree_guards= below, ~9s on EVERY run), and
      # the generic tests/test_*.py arm cannot cover it either: that arm adds direct_run_completeness and
      # coverage_contract, neither of which reads this file - measured, exactly ONE suite names it.
      # Cost, measured: 9.2s for the suite, 10.4s for the pinned delta, paid only on tier-file changes.
      run="$run $f"
      mapped="$mapped tests/test_fast_gate_mapping.py tests/test_direct_run_completeness.py tests/test_coverage_contract.py"
      ;;
    tests/test_*.py)
      # agents-h17y: a changed test file also re-checks the CLASS-WIDE invariant that every
      # tests/test_*.py carries its `if __name__ == "__main__"` block LAST (agents-9lh8). The
      # defect that invariant catches is produced by appending a test BELOW the block, which is
      # precisely what a change to a test file is - and the file still passes under discovery, so
      # without this the fast gate is blind to it and only the merger's full gate would see it.
      # Measured cost: 0.67s for the suite (3 tests; the AST walk over 71 modules is 0.62s of it).
      run="$run $f"
      mapped="$mapped tests/test_direct_run_completeness.py"
      # agents-vim1: newly added or modified test files must audit the cross-module mock coverage contract
      mapped="$mapped tests/test_coverage_contract.py"
      ;;
    tests/containment_harness.py)
      # agents-3iog: the shared harness (setUp plus 11 helpers) the containment suites
      # inherit. It is not named test_*.py on purpose - discovery must not collect it - so it
      # needs its own arm, and it is the ONE entry in that family that legitimately names all
      # of them: a harness change reaches every inherited execution, and the shape test is
      # what catches a test method creeping into it (measured: with no arm the gate
      # fail-closed on this file as unmapped, which is how the omission was found).
      mapped="$mapped tests/test_containment.py tests/test_containment_declarations.py tests/test_containment_adapters.py tests/test_containment_engine_credentials.py tests/test_containment_prepass_pins.py tests/test_containment_egress.py tests/test_containment_shape.py tests/test_containment_broker.py tests/test_containment_confinement.py tests/test_containment_hardening.py tests/test_containment_run_isolation.py tests/test_containment_session_patch.py tests/test_containment_write_grants.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_010_tests_test_tree_guards_py"
