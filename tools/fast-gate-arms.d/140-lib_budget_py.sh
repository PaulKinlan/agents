# tools/fast-gate-arms.d/140-lib_budget_py.sh — 7 arm(s), moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain (ADR 0001's assertion-consumer rule). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_140_lib_budget_py() {
  case "$1" in
    lib/budget.py)
      # The station-command runner (agents-28nn round 8 grew on_spawn, the dispatcher's
      # engine-pid handoff to the credential broker's peer gate): its own unit suite, the
      # dispatcher suites that consume run_station_command, and the broker suite whose
      # peer-gate contract the handoff serves.
      #
      # agents-8z4z: tests/test_line_andon.py JOINS THIS UNION, AND THE EVIDENCE IS THE
      # GATE'S OWN COVERAGE ORACLE, NOT MY JUDGEMENT. On the change that wrapped the on_spawn
      # call, the fast gate PASSED while reporting `unmapped: ['lib/budget.py']` with
      # `omitted: ['tests/test_line_andon.py']` - the independent oracle had found this suite
      # as a consumer and caught that the union did not run it. It IS one: the line runner is
      # a run_station_command caller (the engine, pre-pass and findings dispatch call sites in
      # factory; agents-gioi: cited by ROLE, not by line - all three numbers that used to be here
      # have moved), and that suite imports StationTimeout from lib.budget (tests/test_line_andon.py:
      # :496 and :523) to drive the andon timeout path and COPIES lib/budget.py into its fixture tree
      # (tests/test_line_andon.py:112 - agents-xgha: all three numbers are THE SUITE'S, written bare
      # after "lib.budget" they read as lib/budget.py lines, where :112 is blank).
      # So a budget.py edit could change what the line runner does while the fast gate ran
      # only the three suites above - the same half-mapped shape agents-4ic0 fixed for
      # lib/adapters/pi.sh. Measured cost of the addition: 8.3 s (14 tests), against a 61 s
      # run for this arm's current union.
      mapped="$mapped tests/test_budget.py tests/test_factory_core.py tests/test_credential_broker.py tests/test_line_andon.py"
      ;;
    lib/containment.py)
      # agents-mo75. The generic lib/*.py arm below derives the suite from the changed file's
      # BASENAME, so this module mapped to tests/test_containment.py - and agents-3iog split the
      # containment suite into six modules, of which test_containment.py is the one that kept the
      # module's name. The THIN module was therefore what ran: measured, the name-based rule emitted
      # 2 suites and ran 55 tests, while the eight test files that import lib.containment run 151,
      # so five sibling modules and the child-env consumer were omitted and the gate still printed
      # PASS (the coverage oracle named them, which is how the omission was found). A name-based rule
      # cannot know a suite was split, so this one is a LIST - the same treatment
      # tests/containment_harness.py) gets above for the same reason. Measured cost of the addition:
      # about 8 s (61.5 s for the eight files against 53.3 s for the two the fallback chose).
      mapped="$mapped tests/test_containment.py tests/test_containment_declarations.py tests/test_containment_adapters.py tests/test_containment_engine_credentials.py tests/test_containment_prepass_pins.py tests/test_containment_egress.py tests/test_child_env.py tests/test_containment_broker.py tests/test_containment_confinement.py tests/test_containment_hardening.py tests/test_containment_run_isolation.py tests/test_containment_session_patch.py tests/test_containment_write_grants.py"
      ;;
    lib/embargo.py)
      # agents-iqyz: this arm REPLACES the generic `lib/*.py` arm further down for this path, and must
      # therefore stay ABOVE it - the matcher is first-match, so a later arm for the same path is
      # unreachable. The generic arm derived the namesake suite from the basename; that suite is kept
      # here and listed FIRST, because an arm that replaces the generic one can otherwise pass while
      # DROPPING the module's own suite. Shape: agents-bwbe's (other families' consumers), not
      # agents-mo75's (a split family whose thin namesake ran).
      # Measured with the coverage oracle - before: 4 omitted consumer(s); after: 0.
      mapped="$mapped tests/test_embargo.py tests/test_factory_truth.py tests/test_model_rule_id.py tests/test_report_schema.py tests/test_threat_model_prepass.py"
      ;;
    lib/redaction.py)
      # agents-iqyz: this arm REPLACES the generic `lib/*.py` arm further down for this path, and must
      # therefore stay ABOVE it - the matcher is first-match, so a later arm for the same path is
      # unreachable. The generic arm derived the namesake suite from the basename; that suite is kept
      # here and listed FIRST, because an arm that replaces the generic one can otherwise pass while
      # DROPPING the module's own suite. Shape: agents-bwbe's (other families' consumers), not
      # agents-mo75's (a split family whose thin namesake ran).
      # Measured with the coverage oracle - before: 4 omitted consumer(s); after: 0.
      mapped="$mapped tests/test_redaction.py tests/test_findings.py tests/test_model_rule_id.py tests/test_secret_scanner.py tests/test_vuln_verify_prepass.py"
      ;;
    lib/retention.py)
      # agents-iqyz: this arm REPLACES the generic `lib/*.py` arm further down for this path, and must
      # therefore stay ABOVE it - the matcher is first-match, so a later arm for the same path is
      # unreachable. The generic arm derived the namesake suite from the basename; that suite is kept
      # here and listed FIRST, because an arm that replaces the generic one can otherwise pass while
      # DROPPING the module's own suite. Shape: agents-bwbe's (other families' consumers), not
      # agents-mo75's (a split family whose thin namesake ran).
      # Measured with the coverage oracle - before: 1 omitted consumer(s); after: 0.
      mapped="$mapped tests/test_retention.py tests/test_hillclimb.py"
    ;;
    lib/egress_proxy.py)
      # agents-bwbe (rev-cqrm's finding: the agents-mo75 class in a second instance). Without an arm
      # this module fell through to the generic lib/*.py arm below, whose BASENAME rule selects only
      # tests/test_egress_proxy.py - while six containment suites import lib.egress_proxy and assert
      # proxy isolation and network egress rules. Measured before this arm: the coverage oracle
      # reported unmapped ['lib/egress_proxy.py'] with those six omitted, and the gate still printed
      # PASS. NOTE THE SHAPE DIFFERENCE from the arm above: there the omitted consumers were the
      # changed module's OWN split family; here the module's own suite IS selected and the consumers
      # belong to a DIFFERENT family (containment covers egress rules) - so the index that finds them
      # is the IMPORT GRAPH, not the changed file's name.
      # tests/test_egress_proxy.py is listed explicitly because an EXPLICIT ARM REPLACES THE GENERIC
      # ONE: naming only the six would silently drop the module's own suite (agents-mo75's lesson).
      mapped="$mapped tests/test_egress_proxy.py tests/test_containment.py tests/test_containment_declarations.py tests/test_containment_adapters.py tests/test_containment_engine_credentials.py tests/test_containment_prepass_pins.py tests/test_containment_egress.py tests/test_containment_broker.py tests/test_containment_confinement.py tests/test_containment_hardening.py tests/test_containment_run_isolation.py tests/test_containment_session_patch.py tests/test_containment_write_grants.py"
      ;;
    lib/*.py)
      name="$(basename "$f" .py)"
      case "$name" in
        scheduler)     t="tests/test_schedules.py" ;;
        exclusions)    t="tests/test_prepass_exclusions.py" ;;
        *)             t="tests/test_${name}.py" ;;
      esac
      if [ -f "$t" ]; then
        mapped="$mapped $t"
      else
        echo "fast-gate: changed $f but $t does not exist — add that test file or extend the mapping" >&2
        exit 1
      fi
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_140_lib_budget_py"
