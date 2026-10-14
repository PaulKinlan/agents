# The github sink's promote path has a store-lock contract outside the generic sink suites.
# Match this path before 050's lib/sinks/*.py arm; preserve that arm's five suites.
fast_gate_arms_045_lib_sinks_github() {
  case "$1" in
    lib/sinks/github.py)
      # agents-5jjf: tests/test_store_lock_timeout.py directly imports lib.sinks.github
      # and pins its promote-path lock error and no-reopen behaviour. Running it costs
      # 18.771s for 10 tests, paid only for this sink, not every lib/sinks/*.py edit.
      mapped="$mapped tests/test_sinks.py tests/test_bd_json_contract.py tests/test_promotion.py tests/test_sink_layering.py tests/test_sink_adapters.py tests/test_store_lock_timeout.py"
      ;;
    *) return 1 ;;  # no match: let the generic sinks fragment decide
  esac
  return 0
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_045_lib_sinks_github"
