# tools/fast-gate-arms.d/080-lib_yaml_mini_py.sh — 6 arm(s), moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain (ADR 0001's assertion-consumer rule). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_080_lib_yaml_mini_py() {
  case "$1" in
    lib/yaml_mini.py)
      # Mini YAML parser plus GitHub Actions action.yml contract pin (agents-vt7w).
      mapped="$mapped tests/test_yaml_mini.py tests/test_ci_action.py"
      ;;
    lib/adapters/claude.sh)
      # Claude adapter session auth scrub and precedence (agents-vt7w), prompt guards (agents-9bp7), stderr read-back (agents-2iwf).
      mapped="$mapped tests/test_claude_adapter.py tests/test_prompt_exposure.py tests/test_adapter_stderr_readback.py"
      ;;
    lib/adapters/pi.sh)
      # Pi adapter keyless broker wireup, auth failure handling, containment policies, prompt guards, and factory core (agents-zak0).
      # agents-4ic0: ALSO the line-runner regression suite. The pi adapter is the engine that
      # drives the REAL line runner, which DISPATCHES adapters - so a pi.sh edit can change what
      # the line runner does, and tests/test_line_andon.py was reachable only through the
      # lib/adapters/*.sh wildcard (agents-yx7z), never through this dedicated arm. Measured with
      # the bead's own repro: GIT_CHANGED=lib/adapters/pi.sh selected six suites, none of them it.
      # agents-3iog split the containment suite: this arm keeps TWO of its modules - the
      # dispatcher suite (which drives the real adapter end to end) and the adapters suite
      # (which asserts the adapter argv/env shape). Measured: mutating pi.sh's engine-binary
      # variable turns tests/test_containment.py red.
      mapped="$mapped tests/test_pi_keyless_broker.py tests/test_adapter_auth_failure.py tests/test_factory_core.py tests/test_containment.py tests/test_containment_adapters.py tests/test_prompt_exposure.py tests/test_adapter_stderr_readback.py tests/test_line_andon.py"
      ;;
    lib/adapters/*.sh)
      # Other engine adapters (e.g. antigravity.sh, deepseek.sh) covered by auth failure, prompt guards, and core runner (agents-vt7w, agents-zak0). test_antigravity_prompt_content.py is listed EXPLICITLY (agents-nhf0): the wildcard arm already selected this file when the TEST changed, but NOT when the ADAPTER changed - so the suite protecting antigravity.sh's prompt guard did not run for the edits that could regress it. A suite gated only on its own edits is the half-fixed shape.
      # test_line_andon.py is listed here (agents-yx7z) because it drives the REAL LINE
      # RUNNER, which is what DISPATCHES adapters, so an adapter-only change can regress it. It
      # was mapped in the `factory)` arm above but not this one (agents-gioi: cited by PATTERN, not
      # by line - the number that used to be here, :129, is the GIT_CHANGED assignment).
      mapped="$mapped tests/test_adapter_auth_failure.py tests/test_factory_core.py tests/test_prompt_exposure.py tests/test_adapter_stderr_readback.py tests/test_antigravity_prompt_content.py tests/test_line_andon.py"
      ;;
    lib/bench/*.py)
      # Bench measurement & runners (agents-uxt): covered by bench runner and hillclimb tests.
      mapped="$mapped tests/test_bench_runner.py tests/test_hillclimb.py"
      ;;
    lib/report_schema.py)
      # Report schema validation, post-filters (concurrency guard, unlocatable verdicts), and pipeline gate (agents-vt7w).
      mapped="$mapped tests/test_report_schema.py tests/test_perf_review.py tests/test_factory_truth_2.py tests/test_threat_model_prepass.py"
      ;;
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_080_lib_yaml_mini_py"
