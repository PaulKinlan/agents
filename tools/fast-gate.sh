#!/usr/bin/env bash
# Fast gate for agents-factory (agents-651): run only the tests a branch touches.
#
# The full gate (`python3 -m unittest discover -s tests -v`) is the merger's one-time
# per-landing job. Implementers run `fleet-check --fast`, which invokes this script via
# CHECK_FAST_CMD. It is deterministic and bounded (never the whole suite) and fails loudly
# (non-zero) when a change maps to a test file that does not exist, so a missing test cannot
# silently pass.
#
# Resolution (first applicable):
#   1. changed test files vs the base branch (default origin/main) run as-is;
#   2. changed lib/*.py map to tests/test_<name>.py (scheduler -> test_schedules.py), and
#      the `factory` dispatcher maps to the core + truth harnesses;
#   3. anything else (docs, config, tools, …) falls back to a bounded smoke subset
#      (tests/test_factory_core.py).
#
# A changed lib module whose mapped test file is absent exits non-zero. Override the base
# branch with GIT_BASE=<ref> (used by tests).
#
# Wiring (per-VM ~/.fleet/check.conf, alongside the full-gate CHECK_CMD):
#   CHECK_FAST_CMD="bash tools/fast-gate.sh"
#   CHECK_FAST_TIMEOUT=180
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BASE="${GIT_BASE:-origin/main}"

# The branch delta. Empty when the base is absent/unknown -> smoke fallback.
changed="$(git diff --name-only "$BASE"...HEAD 2>/dev/null || true)"

run=""
mapped=""

while IFS= read -r f; do
  [ -z "$f" ] && continue
  case "$f" in
    tests/test_*.py)
      run="$run $f"
      ;;
    factory)
      # The dispatcher script; covered by the core runner + the truth harness.
      mapped="$mapped tests/test_factory_core.py tests/test_factory_truth.py"
      ;;
    lib/sinks/*.py)
      # Tracker-sink adapters (fleet-km8): covered by the sink harness, the bd contract, promotion, and layering.
      mapped="$mapped tests/test_sinks.py tests/test_bd_json_contract.py tests/test_promotion.py tests/test_sink_layering.py"
      ;;
    lib/findings.py)
      # The findings store and the delta renderer. Its own suite is not enough: the store's record
      # and stats shape is what the sink/record layers assert, and a change here broke
      # tests/test_sinks' exact stats expectation while the generic test_findings-only mapping ran
      # (agents-x9my step 2).
      mapped="$mapped tests/test_findings.py tests/test_sinks.py tests/test_bd_json_contract.py tests/test_promotion.py tests/test_sink_layering.py tests/test_model_rule_id.py tests/test_candidate_binding.py"
      ;;
    lib/bench/*.py)
      # Bench measurement & runners (agents-uxt): covered by bench runner and hillclimb tests.
      mapped="$mapped tests/test_bench_runner.py tests/test_hillclimb.py"
      ;;
    agents/docs-drift/scripts/check_docs.py)
      mapped="$mapped tests/test_docs_drift.py"
      ;;
    agents/vuln-triage/scripts/triage.py)
      mapped="$mapped tests/test_vuln_triage_prepass.py"
      ;;
    agents/vuln-verify/scripts/prepare_verification.py)
      # The verifier's pre-pass: unknown-location handling (agents-fy26) and path confinement
      # (agents-075) are both pinned in this suite.
      mapped="$mapped tests/test_vuln_verify_prepass.py"
      ;;
    agents/pr-fixer/scripts/collect_failures.py)
      # The proposer's pre-pass: unknown lines must not reach int() (agents-fy26).
      mapped="$mapped tests/test_pr_fixer_prepass.py"
      ;;
    agents/vuln-discovery/scripts/scan_surface.py)
      # The first station to EMIT a stable candidate identity (agents-rdyb): its own precision
      # suite plus the shared helper's property tests, which are what fail if the id stops being
      # deterministic or starts moving with the model's prose.
      mapped="$mapped tests/test_scan_surface.py tests/test_candidate_identity.py"
      ;;
    tools/gen_site.py)
      mapped="$mapped tests/test_gen_site.py"
      ;;
    lib/*.py)
      name="$(basename "$f" .py)"
      case "$name" in
        scheduler)  t="tests/test_schedules.py" ;;
        exclusions) t="tests/test_prepass_exclusions.py" ;;
        *)          t="tests/test_${name}.py" ;;
      esac
      if [ -f "$t" ]; then
        mapped="$mapped $t"
      else
        echo "fast-gate: changed $f but $t does not exist — add that test file or extend the mapping" >&2
        exit 1
      fi
      ;;
  esac
done <<< "$changed"

# Union, dedupe, deterministic order.
files="$(printf '%s\n' $run $mapped | awk 'NF && !seen[$0]++' | sort || true)"

# Fall back to a bounded smoke subset when nothing maps (docs-only / config-only / new tools).
if [ -z "$files" ]; then
  files="tests/test_factory_core.py"
fi

modules="$(printf '%s\n' $files | sed 's#/#.#g; s#\.py$##' | tr '\n' ' ' | sed 's/ *$//')"
echo "fast-gate: base=$BASE; running: python3 -m unittest $modules"
python3 -m unittest $modules
