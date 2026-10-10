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
# Override changed files directly with GIT_CHANGED (used by tests).
changed="${GIT_CHANGED:-$(git diff --name-only "$BASE"...HEAD 2>/dev/null || true)}"

run=""
mapped=""

while IFS= read -r f; do
  [ -z "$f" ] && continue
  case "$f" in
    tests/test_*.py)
      run="$run $f"
      ;;
    factory)
      # The dispatcher script; covered by the core runner, truth harnesses, auth failures, line andon, prompt exposure, and transient dir cleanup.
      mapped="$mapped tests/test_factory_core.py tests/test_factory_truth.py tests/test_factory_truth_2.py tests/test_adapter_auth_failure.py tests/test_line_andon.py tests/test_prompt_exposure.py tests/test_transient_dirs.py"
      ;;
    lib/sinks/*.py)
      # Tracker-sink adapters (fleet-km8): covered by the sink harness, the bd contract, promotion, layering, and adapter registry/commands.
      mapped="$mapped tests/test_sinks.py tests/test_bd_json_contract.py tests/test_promotion.py tests/test_sink_layering.py tests/test_sink_adapters.py"
      ;;
    lib/findings.py)
      # The findings store and the delta renderer. Its own suite is not enough: the store's record
      # and stats shape is what the sink/record layers assert, and a change here broke
      # tests/test_sinks' exact stats expectation while the generic test_findings-only mapping ran
      # (agents-x9my step 2). tests/test_redaction.py is here for the same reason, learned again the
      # hard way: the fast gate passed 291 tests while the FULL gate caught a TypeError on a
      # non-scalar line_number, because the redaction contract suite was not in this mapping
      # (agents-q0mt) - the contract is fail-closed, so it is a real consumer of this module.
      # tests/test_suppressions.py asserts the committed suppressions register contract (agents-vt7w).
      mapped="$mapped tests/test_findings.py tests/test_sinks.py tests/test_bd_json_contract.py tests/test_promotion.py tests/test_sink_layering.py tests/test_model_rule_id.py tests/test_candidate_binding.py tests/test_redaction.py tests/test_suppressions.py"
      ;;
    lib/candidate_identity.py)
      # Candidate identity generator (agents-rdyb) and pre-pass emission assertion (agents-vt7w).
      mapped="$mapped tests/test_candidate_identity.py tests/test_candidate_id_emission.py"
      ;;
    lib/credential_broker.py)
      # Credential broker plus end-to-end keyless broker test (agents-vt7w).
      mapped="$mapped tests/test_credential_broker.py tests/test_pi_keyless_broker.py"
      ;;
    lib/sandbox.py)
      # Bubblewrap sandbox (bwrap isolation, binds, proc/env masking) plus no-bwrap refusal contract (agents-vt7w).
      mapped="$mapped tests/test_sandbox.py tests/test_no_bwrap_guard.py"
      ;;
    lib/yaml_mini.py)
      # Mini YAML parser plus GitHub Actions action.yml contract pin (agents-vt7w).
      mapped="$mapped tests/test_yaml_mini.py tests/test_ci_action.py"
      ;;
    lib/adapters/claude.sh)
      # Claude adapter session auth scrub and precedence (agents-vt7w).
      mapped="$mapped tests/test_claude_adapter.py"
      ;;
    lib/adapters/pi.sh)
      # Pi adapter keyless broker wireup and auth failure handling (agents-vt7w).
      mapped="$mapped tests/test_pi_keyless_broker.py tests/test_adapter_auth_failure.py tests/test_factory_core.py"
      ;;
    lib/adapters/*.sh)
      # Other engine adapters (e.g. antigravity.sh, deepseek.sh) covered by auth failure and core runner (agents-vt7w).
      mapped="$mapped tests/test_adapter_auth_failure.py tests/test_factory_core.py"
      ;;
    lib/bench/*.py)
      # Bench measurement & runners (agents-uxt): covered by bench runner and hillclimb tests.
      mapped="$mapped tests/test_bench_runner.py tests/test_hillclimb.py"
      ;;
    lib/report_schema.py)
      # Report schema validation, post-filters (concurrency guard, unlocatable verdicts), and pipeline gate (agents-vt7w).
      mapped="$mapped tests/test_report_schema.py tests/test_perf_review.py tests/test_factory_truth_2.py"
      ;;
    agents/bundle-size/scripts/measure_bundle.py)
      mapped="$mapped tests/test_bundle_size.py"
      ;;
    agents/threat-model/scripts/mine_history.py)
      mapped="$mapped tests/test_threat_model_prepass.py"
      ;;
    agents/perf-hillclimb/scripts/measure_and_context.py)
      mapped="$mapped tests/test_hillclimb.py"
      ;;
    agents/docs-write/scripts/prepare_docs_fixes.py)
      mapped="$mapped tests/test_prepass_exclusions.py"
      ;;
    agents/docs-drift/scripts/check_docs.py)
      # agents-q0mt: also emits candidate ids now; the exclusion suite drives this script, and the
      # emission pin reads the id out of a real artefact.
      mapped="$mapped tests/test_docs_drift.py tests/test_prepass_exclusions.py tests/test_candidate_id_emission.py"
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
    agents/secret-scan/scripts/scan.py)
      # The secret pre-pass. Both producer paths (gitleaks and the builtin fallback) meet at one
      # artefact assembly point, so the candidate-identity conversion is one call (agents-q0mt).
      mapped="$mapped tests/test_secret_scanner.py tests/test_candidate_id_emission.py"
      ;;
    agents/modern-web/scripts/scan_modern_web.py)
      # agents-q0mt: the station now emits a candidate id; its own suite plus the pre-pass
      # exclusion suite, which exercises this script directly.
      mapped="$mapped tests/test_modern_web.py tests/test_prepass_exclusions.py tests/test_candidate_id_emission.py"
      ;;
    agents/deps-supply-chain/scripts/audit_deps.py)
      # agents-q0mt: emits candidate ids; the pre-pass exclusion suite exercises it too.
      mapped="$mapped tests/test_audit_deps.py tests/test_prepass_exclusions.py tests/test_candidate_id_emission.py"
      ;;
    agents/ui-ux-audit/scripts/scan_ui_ux.py)
      # agents-q0mt: emits candidate ids; this station's output is pinned as the pre-pass truth
      # fixture, and the exclusion suite drives it directly.
      mapped="$mapped tests/test_prepass_truth.py tests/test_prepass_exclusions.py tests/test_candidate_id_emission.py"
      ;;
    agents/accessibility/scripts/audit_a11y.py)
      # agents-q0mt: emits candidate ids. The emission pin is this station's only executable
      # coverage of its artefact, so it is named here rather than left to the smoke subset.
      mapped="$mapped tests/test_candidate_id_emission.py"
      ;;
    agents/memory-profile/scripts/scan_memory_leaks.py)
      # agents-q0mt: emits candidate ids; the binding suite drives this script.
      mapped="$mapped tests/test_candidate_binding.py tests/test_candidate_id_emission.py"
      ;;
    agents/perf-review/scripts/scan_perf_changes.py)
      # agents-q0mt: emits candidate ids; its own review suite plus the emission pin.
      mapped="$mapped tests/test_perf_review.py tests/test_candidate_id_emission.py"
      ;;
    agents/qa-station/scripts/audit_factory_quality.py)
      # agents-q0mt: emits candidate ids. The truth harnesses assert its payload shape, which is
      # what a new key could disturb.
      mapped="$mapped tests/test_factory_truth_2.py tests/test_prepass_truth.py tests/test_candidate_id_emission.py"
      ;;
    agents/resilience/scripts/scan_resilience.py)
      # agents-q0mt: emits candidate ids; the emission pin is this station's only executable
      # coverage of its artefact today.
      mapped="$mapped tests/test_candidate_id_emission.py"
      ;;
    agents/test-gap/scripts/find_untested.py)
      # agents-q0mt: emits candidate ids; the emission pin is this station's only executable
      # coverage of its artefact today.
      mapped="$mapped tests/test_candidate_id_emission.py"
      ;;
    tools/gen_site.py)
      mapped="$mapped tests/test_gen_site.py"
      ;;
    tools/fast-gate.sh)
      # Fast gate mapping verification test (agents-vt7w).
      mapped="$mapped tests/test_fast_gate_mapping.py"
      ;;
    docs/*)
      # Documentation pages snapshot and publishing scope (agents-vt7w).
      mapped="$mapped tests/test_docs_design.py tests/test_pages_publish_scope.py"
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
  esac
done <<< "$changed"

# Union, dedupe, deterministic order.
files="$(printf '%s\n' $run $mapped | awk 'NF && !seen[$0]++' | sort || true)"

# Dry-run support for testing mapping resolution without invoking unittest.
if [ -n "${FAST_GATE_DRY_RUN:-}" ]; then
  printf '%s\n' $files
  exit 0
fi

# Fall back to a bounded smoke subset when nothing maps (docs-only / config-only / new tools).
if [ -z "$files" ]; then
  files="tests/test_factory_core.py"
fi

modules="$(printf '%s\n' $files | sed 's#/#.#g; s#\.py$##' | tr '\n' ' ' | sed 's/ *$//')"
echo "fast-gate: base=$BASE; running: python3 -m unittest $modules"
python3 -m unittest $modules
