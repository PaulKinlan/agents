# tools/fast-gate-arms.d/020-tools_fast_gate_sh.sh — 2 arm(s), moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain (ADR 0001's assertion-consumer rule). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_020_tools_fast_gate_sh() {
  case "$1" in
    tools/fast-gate.sh)
      # agents-8jx1: THE GATE'S OWN SCRIPT HAD AN ARM THAT MAPPED ONLY
      # tests/test_fast_gate_mapping.py. A change to tools/fast-gate.sh therefore selected the
      # mapping suite AND OMITTED tests/test_hermetic_env.py - the acceptance suite for the
      # gate's hermetic environment, which names fast-gate/CHECK_CMD seven times and can be
      # regressed by a gate edit. Found by the gate's own coverage warning on a green run.
      # (The old arm this replaces was deleted rather than left in place: the matcher is
      # FIRST-MATCH, so a second arm for the same path is unreachable dead code that a future
      # reader would have no way to identify as the stale one.)
      # agents-3a8a: tests/test_coverage_contract.py is THE SAME SHAPE one round later. The
      # contract parser THIS script owns is pinned by that suite's two *_aborts_fast_gate_loudly
      # tests (:143 and :164), each of which copies this script into a tmp tree and asserts the
      # parser's failure modes - consumers of this file, omitted from this arm. Because this file
      # IS mapped, no 'unmapped changed file(s)' warning fires for the omission: the gap is an
      # omitted consumer INSIDE a mapped arm.
      # HONEST MEASUREMENT, because the obvious mutant did NOT reproduce the feared hole intact
      # and the difference is the reason to name the suite anyway: with the contract validation's
      # `if not os.path.isfile(s):` changed to `if False:` (one non-equivalent mutant), the OLD
      # arm's own gate run ALSO went red (rc=1) - but only COLLATERALLY. tests/test_fast_gate_mapping.py
      # invokes this script against probe test files, whose own arm (tests/test_*.py, agents-vim1)
      # selects tests/test_coverage_contract.py, so the suite ran as a NESTED child and the outer
      # failures were assertions about the nested gate's rc (FAIL:
      # test_fast_gate_execution_emits_single_line_marker_naming_all_suites, FAIL:
      # test_fast_gate_execution_reports_passed_terminal_signal_on_success, FAIL:
      # test_fast_gate_runner_unsets_host_pins_for_child_suites) - not about this arm's declared
      # set. So the coverage depended on a probe's file NAME, not on this arm. With the suite in
      # this arm the same mutant is reported by a TOP-LEVEL module run and NAMES the assertion:
      # FAIL: test_invalid_coverage_contract_value_aborts_fast_gate_loudly
      #   (contract='{"lib/child_env.py": ["tests/nonexistent_suite_xyz.py"]}')
      #   AssertionError: 'does not exist' not found in ...
      # Unmutated control: green. Measured cost of the addition: 1.4s (5 tests), paid only when
      # this script changes.
      # agents-d081: tests/test_gate_entrypoint_config.py IS THE SAME SHAPE AGAIN, and this one was
      # created by the same change that had to name it: the drift-detection work added a class there
      # (TestTheFastGateWarnsAboutPerVmDriftAtThePointOfUse) that DRIVES THIS SCRIPT in a temp HOME to
      # assert the point-of-use warning, which makes that suite a consumer of this file. The gate's own
      # coverage oracle named it as omitted on the first gate run of that change
      # (omitted=['tests/test_gate_entrypoint_config.py'] with unmapped=['tools/fast-gate.sh']), and the
      # base tree reports neither, so the omission arrived with the consumer rather than having been
      # there all along. Cost of naming it, measured: the suite is 17 tests / ~1.2 s and already runs
      # green in the gate environment (it was selected for that same change by the tools/check-cmd.sh
      # arm), so it adds a suite this arm can afford and no new environment sensitivity.
      mapped="$mapped tests/test_fast_gate_mapping.py tests/test_hermetic_env.py tests/test_coverage_contract.py tests/test_gate_entrypoint_config.py"
      ;;
    tools/stage_site.py)
      # agents-1n9i: THIS FILE MATCHED NO ARM AT ALL, so a change to it hit the unmatched
      # bucket and ABORTED THE GATE with exit 1 rather than skipping a suite - the one member
      # of this family the instrument can actually catch, because the changed file was
      # unmatched. tests/test_pages_publish_scope.py imports tools.stage_site directly (:18)
      # and exercises guard() and stage_site() plus the publication scopes. It is NOT the only
      # suite that can fail for this file, which the previous wording claimed ("the suite this
      # file's own changes must select"): agents-23jg measured that tests/test_retention.py pins
      # this file too, through its deletion inventory - :1207 carries
      # ("tools/stage_site.py", "shutil.rmtree(out)", 1, "NAMED", ...). MEASURED on 2026-10-12
      # with the non-equivalent mutant `shutil.rmtree(out) -> shutil.rmtree(out,
      # ignore_errors=True)`: the arm selected tests/test_pages_publish_scope.py ALONE and it
      # reported OK, while tests/test_retention.py reported FAILED (failures=2) without ever
      # being selected - a change to this file the fast gate could not catch. Both consumers are
      # therefore listed. Same mapping a docs/* or .github/* change uses.
      mapped="$mapped tests/test_pages_publish_scope.py tests/test_retention.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_020_tools_fast_gate_sh"
