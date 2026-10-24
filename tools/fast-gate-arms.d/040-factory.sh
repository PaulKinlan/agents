# tools/fast-gate-arms.d/040-factory.sh — 2 arm(s), moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain (ADR 0001's assertion-consumer rule). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_040_factory() {
  case "$1" in
    factory)
      # The dispatcher script; covered by the core runner, truth harnesses, auth failures, line andon, prompt exposure, and transient dir cleanup.
      mapped="$mapped tests/test_factory_core.py tests/test_factory_truth.py tests/test_factory_truth_2.py tests/test_adapter_auth_failure.py tests/test_line_andon.py tests/test_prompt_exposure.py tests/test_transient_dirs.py"
      # agents-5grx0: the CLI's EXIT CODE for a failed station lives in this file's __main__ handler, and
      # tests/test_line_andon.py cannot see it because it calls run_line() in-process - so flipping
      # sys.exit(2) to sys.exit(0) on the (StationTimeout, StationError) branch left the andon suite green
      # (reviewer-measured). This suite drives `factory run` as a SUBPROCESS and asserts the code: measured
      # mutant, sys.exit(2)->0 reddens both of its tests; cost 3.0 s for 2 tests, paid only when this file
      # changes.
      mapped="$mapped tests/test_station_exit_codes.py"
      # agents-rw6z: the opt-in payload context and absent-key byte-identity prompt contract
      # are exercised through the real dispatcher and retained prompt, not a formatting stub.
      mapped="$mapped tests/test_factory_context_channel.py"
      # agents-oq3j: the promotion child is built by a call in THIS file (the dispatcher's
      # promote path), and tests/test_promotion.py MOCKS that call and asserts its exact shape -
      # so the dispatcher was changed and the assertion went stale while the arm that owns the
      # call site never ran the suite. Measured cost of the addition: 8.5 s (14 tests), paid only
      # when factory changes, against a full gate that found this defect at 1547 tests.
      mapped="$mapped tests/test_promotion.py"
      # agents-dm8n round 2: the deleter that escaped round 1 lived in FACTORY (the failed
      # --apply proposal_run_dir rmtree - the remove_recorded(proposal_run_dir, ...) call; agents-gioi:
      # cited by SYMBOL, not by line, because the number that used to be here, :2102, is a lone '}'),
      # not in lib/retention.py - so a factory
      # change must run the two suites that pin deletion under the runs root.
      # SEARCH PERFORMED: `grep -n "shutil\.rmtree(\|\.unlink(\|os\.remove(\|os\.unlink("
      # factory` enumerates every deletion site in the dispatcher; tests/test_retention.py's
      # TestRunRootDeletionInventory holds that enumeration and fails on any drift, and
      # tests/test_hillclimb.py is the only suite that drives the run_hillclimb --apply
      # failure path end-to-end (its test_worktree_creation_failure_after_add_is_cleaned_up
      # now asserts the tombstone lands). Neither was reachable from this arm before.
      mapped="$mapped tests/test_retention.py tests/test_hillclimb.py"
      # agents-uxiks (rn0ky port): the dispatcher's bounded-batching loop lives in THIS file - the batch
      # prompt header, one engine call per batch, per-batch parsing/validation and the truncation
      # classification - and tests/test_candidate_batching_end_to_end.py drives it through `factory run`
      # with a stub engine. agents-tq1lt made the bound POLICY rather than an opt-in declaration, so the
      # arm's old control ("returning None from max_candidates_per_call disables batching") no longer
      # exists: that function always returns the resolved bound. The equivalent control now is the
      # ceiling itself - raising MAX_CANDIDATES_PER_BATCH above the candidate count in the suite stops it
      # splitting - and the suite carries which bound applies to whom (undeclared station -> ceiling,
      # declaration above the ceiling -> capped), so a dispatcher that stops applying the policy fails
      # it either way. Cost, MEASURED on this VM under load: the agents-tq1lt test adds ONE 2-call
      # dispatcher run, ~13 s (a second dispatcher-run case was cut for exactly that reason - it pushed
      # this gate to its 600 s bound and got KILLED at 631 s). The module was ~8.0 s for 5 tests on a
      # quiet box before it, so read the cost as "a handful of engine-free dispatcher runs", not as a
      # fixed number.
      mapped="$mapped tests/test_candidate_batching_end_to_end.py"
      ;;
    install.sh)
      # agents-3xqa: THE PROVISIONING ENTRYPOINT MATCHED NO ARM, so an implementer editing it
      # - the file where the gate-install step is wired (agents-l2xb) - could not pass its own
      # fast gate: the change fell to the *) arm and exited 1 ("match no mapping arm"). It is a
      # deliberate mapping arm, not an ignore arm, and THE SUITE IS THE CONSUMER RATHER THAN A
      # STAND-IN: tests/test_gate_entrypoint_config.py EXECUTES install.sh in a temp HOME and
      # reads back the per-VM config the deployed gate reads - delete the --install call site
      # from install.sh and it goes red - so it catches exactly the regression this arm exists
      # for. It is also already the suite pinning the tracked command's path to the deployed
      # entrypoint, which is the contract install.sh provisions.
      mapped="$mapped tests/test_gate_entrypoint_config.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_040_factory"
