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
#   3. changed paths on the explicit ignore list (each a deliberate case arm with a
#      reason, agents-9nir) fall back to a bounded smoke subset
#      (tests/test_factory_core.py); a changed file matching NEITHER a mapping arm NOR
#      the ignore list fails loudly, named - a file nobody has mapped must be seen.
#
# A changed lib module whose mapped test file is absent exits non-zero. Override the base
# branch with GIT_BASE=<ref> (used by tests).
#
# Wiring (per-VM ~/.fleet/check.conf, alongside the full-gate CHECK_CMD):
#   CHECK_FAST_CMD="bash tools/fast-gate.sh"
#   CHECK_FAST_TIMEOUT=180
set -euo pipefail

# Fail-visible abort diagnostics (agents-adhc).
# UNCOVERABLE BY CONSTRUCTION: SIGKILL (kill -9), kernel OOM-killer invocations,
# host power loss, or kernel panics terminate the process immediately at the OS level
# without executing userspace signal handlers or shell traps.
FAST_GATE_STAGE="initializing"
FAST_GATE_TERMINATED=0

_fast_gate_cleanup() {
  local rc=$?
  if [ "$FAST_GATE_TERMINATED" -eq 1 ]; then
    return 0
  fi
  if [ "$rc" -ne 0 ]; then
    echo "fast-gate: aborted: exit $rc (stage: $FAST_GATE_STAGE)" >&2
  fi
}
_fast_gate_term() {
  FAST_GATE_TERMINATED=1
  echo "fast-gate: aborted: caught SIGTERM (stage: $FAST_GATE_STAGE)" >&2
  exit 143
}
_fast_gate_int() {
  FAST_GATE_TERMINATED=1
  echo "fast-gate: aborted: caught SIGINT (stage: $FAST_GATE_STAGE)" >&2
  exit 130
}
trap _fast_gate_cleanup EXIT
trap _fast_gate_term TERM
trap _fast_gate_int INT

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

FAST_GATE_STAGE="resolving changed files"
BASE="${GIT_BASE:-origin/main}"

# The branch delta. Empty when the base is absent/unknown -> smoke fallback.
# Override changed files directly with GIT_CHANGED (used by tests).
changed="${GIT_CHANGED:-$(git diff --name-only "$BASE"...HEAD 2>/dev/null || true)}"

run=""
mapped=""
unmatched=""

FAST_GATE_STAGE="mapping changed files"
while IFS= read -r f; do
  [ -z "$f" ] && continue
  case "$f" in
    tests/test_*.py)
      run="$run $f"
      ;;
    factory)
      # The dispatcher script; covered by the core runner, truth harnesses, auth failures, line andon, prompt exposure, and transient dir cleanup.
      mapped="$mapped tests/test_factory_core.py tests/test_factory_truth.py tests/test_factory_truth_2.py tests/test_adapter_auth_failure.py tests/test_line_andon.py tests/test_prompt_exposure.py tests/test_transient_dirs.py"
      # agents-dm8n round 2: the deleter that escaped round 1 lived in FACTORY (the failed
      # --apply proposal_run_dir rmtree at :2102), not in lib/retention.py - so a factory
      # change must run the two suites that pin deletion under the runs root.
      # SEARCH PERFORMED: `grep -n "shutil\.rmtree(\|\.unlink(\|os\.remove(\|os\.unlink("
      # factory` enumerates every deletion site in the dispatcher; tests/test_retention.py's
      # TestRunRootDeletionInventory holds that enumeration and fails on any drift, and
      # tests/test_hillclimb.py is the only suite that drives the run_hillclimb --apply
      # failure path end-to-end (its test_worktree_creation_failure_after_add_is_cleaned_up
      # now asserts the tombstone lands). Neither was reachable from this arm before.
      mapped="$mapped tests/test_retention.py tests/test_hillclimb.py"
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
      # The lock is only observable from OUTSIDE a single process, so this suite is the only one
      # that can see a regression to the unbounded wait (agents-4sij).
      mapped="$mapped tests/test_store_lock_timeout.py"
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
    lib/tool_pins.py)
      # Trusted-tool pinning (agents-7bj). Since agents-28nn this module also authenticates
      # bwrap itself, and the property that an unauthenticated bwrap is refused BEFORE it
      # executes lives in tests/test_sandbox.py (TestBwrapPinBoundary) — the pins contract
      # alone cannot see a sandbox-side regression.
      mapped="$mapped tests/test_tool_pins.py tests/test_sandbox.py"
      ;;
    tools/generate-tool-pins.sh)
      # Operator-run pin generator (never invoked by the factory — its own header). SEARCH
      # PERFORMED (agents-28nn): `grep -rn "generate-tool-pins" tests/` named no suite before
      # this bead; agents-28nn adds the assertion that its TOOLS list covers every
      # TRUSTED_TOOLS entry to tests/test_tool_pins.py, which owns the pins contract.
      mapped="$mapped tests/test_tool_pins.py"
      ;;
    THREAT_MODEL.md)
      # Root markdown the docs-drift scanner WALKS (check_docs.py os.walk()s every committed
      # .md outside IGNORE_DIRS). SEARCH PERFORMED (agents-28nn): `grep -rn 'ROOT /
      # "THREAT_MODEL' tests/` finds no direct reader; the test_threat_model_prepass.py hits
      # are fixture strings for the findings-store recognizer, not the committed file.
      mapped="$mapped tests/test_docs_drift.py"
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
      # Pi adapter keyless broker wireup, auth failure handling, containment policies, and factory core.
      mapped="$mapped tests/test_pi_keyless_broker.py tests/test_adapter_auth_failure.py tests/test_factory_core.py tests/test_containment.py"
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
      mapped="$mapped tests/test_docs_drift.py tests/test_prepass_exclusions.py tests/test_candidate_id_emission.py tests/test_prepass_pin_boundary.py"
      ;;
    agents/vuln-triage/scripts/triage.py)
      mapped="$mapped tests/test_vuln_triage_prepass.py"
      ;;
    agents/issue-triage/scripts/fetch_issues.py)
      mapped="$mapped tests/test_issue_triage_prepass.py tests/test_prepass_pin_boundary.py tests/test_redaction.py tests/test_docs_drift.py"
      ;;
    agents/release-notes/scripts/gather_commits.py)
      # agents-28nn round 4: gather_commits resolves git through the pin, pinned by
      # tests/test_prepass_pin_boundary.py. tests/test_redaction.py parses every agents/*/scripts/*.py,
      # and tests/test_docs_drift.py owns the prose.
      mapped="$mapped tests/test_prepass_pin_boundary.py tests/test_redaction.py tests/test_docs_drift.py"
      ;;
      ;;
    tests/sandbox_fixtures.py)
      # Shared fixture builder for tests (agents-8ztd); its own suite pins the property that a new
      # lib import reaches a sandbox without a fixture change.
      mapped="$mapped tests/test_sandbox_fixtures.py"
      ;;
    agents/vuln-verify/scripts/prepare_verification.py)
      # The verifier's pre-pass: unknown-location handling (agents-fy26) and path confinement
      # (agents-075) are both pinned in this suite.
      mapped="$mapped tests/test_vuln_verify_prepass.py"
      ;;
    agents/pr-fixer/scripts/collect_failures.py)
      # The proposer's pre-pass: unknown lines must not reach int() (agents-fy26); pin resolution (agents-01qd).
      mapped="$mapped tests/test_pr_fixer_prepass.py tests/test_station_trusted_tool_pins.py"
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
      # agents-28nn round 4: gitleaks is resolved through the pin (present-but-unauthenticatable
      # is loud; genuinely absent keeps the builtin fallback) - pinned by the boundary suite.
      mapped="$mapped tests/test_secret_scanner.py tests/test_candidate_id_emission.py tests/test_prepass_pin_boundary.py"
      ;;
    agents/modern-web/scripts/scan_modern_web.py)
      # agents-q0mt: the station now emits a candidate id; its own suite plus the pre-pass
      # exclusion suite, which exercises this script directly.
      mapped="$mapped tests/test_modern_web.py tests/test_prepass_exclusions.py tests/test_candidate_id_emission.py"
      ;;
    agents/deps-supply-chain/scripts/audit_deps.py)
      # agents-q0mt: emits candidate ids; the pre-pass exclusion suite exercises it too; pin resolution (agents-01qd).
      mapped="$mapped tests/test_audit_deps.py tests/test_prepass_exclusions.py tests/test_candidate_id_emission.py tests/test_station_trusted_tool_pins.py"
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
      # agents-q0mt: emits candidate ids; its own review suite plus the emission pin; pin resolution (agents-01qd).
      mapped="$mapped tests/test_perf_review.py tests/test_candidate_id_emission.py tests/test_station_trusted_tool_pins.py"
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
    agents/vuln-verify/report.schema.json)
      # The verifier's output CONTRACT. Nothing else maps a JSON schema, and the case above has no
      # default arm - so without this a change to the contract maps to nothing and the gate goes
      # green having run nothing at all. Its own suite pins the schema subset the agents use; the
      # prepass suite feeds the pathless records the widened property exists for (agents-nhpb).
      mapped="$mapped tests/test_report_schema.py tests/test_vuln_verify_prepass.py"
      ;;
    agents/threat-model/report.schema.json)
      # Output contract for threat-model bootstrap slot (agents-uhru).
      mapped="$mapped tests/test_report_schema.py tests/test_factory_truth_2.py"
      ;;
    tools/gen_site.py)
      mapped="$mapped tests/test_gen_site.py"
      ;;
    tools/fast-gate.sh)
      # Fast gate mapping verification test (agents-vt7w).
      mapped="$mapped tests/test_fast_gate_mapping.py"
      ;;
    docs/*)
      # Documentation pages snapshot and publishing scope (agents-vt7w). tests/test_docs_drift.py
      # pins docs/INTEGRATION.md by content (its Section 5 script table at :191 and its section
      # anchors at :485-492), so it belongs in this union (agents-9nir review).
      mapped="$mapped tests/test_docs_design.py tests/test_pages_publish_scope.py tests/test_docs_drift.py"
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
    README.md|AGENTS.md|THREAT_MODEL.md|CLAUDE.md)
      # Root governance, architecture, and threat model documentation.
      # tests/test_docs_drift.py reads committed docs and checks drift, anchors, and references.
      mapped="$mapped tests/test_docs_drift.py"
      ;;
    .github/*)
      # CI definitions. tests/test_ci_action.py pins the committed .github/actions/**
      # (action.yml parse plus the untrusted-context guard over every run: body);
      # tests/test_pages_publish_scope.py reads the committed workflows/pages.yml. No
      # suite can EXECUTE a workflow, so this union is the bounded approximation.
      mapped="$mapped tests/test_ci_action.py tests/test_pages_publish_scope.py"
      ;;
    findings/suppressions.yaml)
      # The committed suppressions register; tests/test_suppressions.py reads it directly
      # (ROOT / "findings" / SUPPRESSIONS_FILENAME), so a change here is a contract change.
      mapped="$mapped tests/test_suppressions.py"
      ;;
    agents/*/SKILL.md)
      # The docs-drift scanner os.walk()s every committed .md outside IGNORE_DIRS
      # (agents/docs-drift/scripts/check_docs.py:466-478) and its real-tree suite pins the
      # agents/*/SKILL.md candidate set by count (tests/test_docs_drift.py:384-394). A path
      # grep cannot see this consumer - a walker consumes a CLASS of paths (agents-9nir review).
      mapped="$mapped tests/test_docs_drift.py"
      ;;
    agents/*/agent.yaml)
      # Station manifests are read off the real tree: tests/test_docs_design.py:77 globs
      # agents/*/agent.yaml to check stations.html, and tests/test_containment.py:300 globs
      # them for the credential-grant drift guard (agents-9nir review).
      mapped="$mapped tests/test_docs_design.py tests/test_containment.py"
      ;;
    lines/*.yaml)
      # Line manifests are read off the real tree: tests/test_docs_design.py:78 globs
      # lines/*.yaml to check lines.html (agents-9nir review).
      mapped="$mapped tests/test_docs_design.py"
      ;;
    tools.yaml)
      # Runtime tool pins. lib/tool_pins.py reads the committed file at CONFIG_PATH when
      # FACTORY_TOOL_PINS is unset, and tests/test_child_env.py's resolve probes run against
      # the real repo WITHOUT the override, so the committed contents are asserted (a bd pin
      # would flip the fail-closed expectation); tests/test_tool_pins.py is the pins contract.
      mapped="$mapped tests/test_tool_pins.py tests/test_child_env.py"
      ;;
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
    reports/*.md)
      # Generated audit reports. reports/ is NOT in DEFAULT_IGNORE_DIRS (lib/exclusions.py:23-43
      # excludes findings/ and runs/ via FACTORY_ARTIFACT_DIRS at :11-15, not reports/), so the
      # docs-drift scanner DOES walk these files, and the real-tree fleet-resolution assertions
      # (tests/test_docs_drift.py:101-113) bind any walked .md that names a bare agent directory.
      mapped="$mapped tests/test_docs_drift.py"
      ;;
    # --- Ignore list (agents-9nir) -----------------------------------------------------
    # RULE: an ignore must be a DELIBERATE CASE ARM WITH A REASON, never a default.
    # "No arm" used to mean two different things - a considered exclusion and an
    # oversight - and they were indistinguishable, so every unmatched file was silently
    # masked by the smoke fallback below and the verdict read PASS for an unrelated
    # suite. The *) arm at the bottom fails loudly and NAMES any file no arm claims;
    # the smoke fallback after the loop is for ignored docs/config-only changes ONLY.
    # To exempt a path, add an arm here with the reason it needs no suite.
    # WARNING, learned the hard way (agents-9nir review, three instances in one bead): a
    # path grep cannot prove a path class is consumer-free, because a file can be consumed
    # WITHOUT BEING NAMED - by a WALKER (agents/*/SKILL.md via check_docs.py's os.walk),
    # by a GLOB (targets/*.yaml via lib/scheduler.py:140-144), and by a SUBPROCESS WITH A
    # DEFAULT PATH (tools.yaml via lib/tool_pins.py:46 read in test_child_env.py's probes).
    # So the reason in an ignore arm must record the SEARCH PERFORMED AND ITS RESULT,
    # never a judgement about who reads the path - a judgement is unfalsifiable, and that
    # is what made the original canvas `*.md` ignore arm's reason false.
    .beads/*)
      # The scanner never sees these: it skips dot dirs and .beads is in DEFAULT_IGNORE_DIRS
      # (lib/exclusions.py:23-43). Search performed: every .beads reference in tests mkdirs
      # its own tmp fixture (test_bd_json_contract.py:64, test_factory_core.py:537,
      # test_sinks.py:88, test_store_lock_timeout.py:273) - none reads the committed files.
      ;;
    findings/*.md)
      # findings/ is in FACTORY_ARTIFACT_DIRS (lib/exclusions.py:11-15), so the docs-drift
      # scanner never walks it; and findings/* is gitignored (only .gitkeep and
      # suppressions.yaml are force-tracked), so this arm only fires on a force-added file.
      ;;
    *.gitkeep)
      # Empty placeholders keeping otherwise-gitignored dirs (findings/, lines/,
      # schedules/) tracked. lib/retention.py:78 protects findings/.gitkeep by name, but
      # no suite reads the committed files (test_retention.py uses tmp fixtures).
      ;;
    .gitignore)
      # VCS metadata, consumed only by git itself. Tests mention .gitignore only as
      # fixtures they write into tmp targets (test_containment.py, test_hillclimb.py).
      ;;
    *)
      unmatched="$unmatched $f"
      ;;
  esac
done <<< "$changed"

FAST_GATE_STAGE="checking unmapped files"
# Loud failure (agents-9nir): a changed file that matches neither a mapping arm nor the
# ignore list is exactly the case that must be seen - name every such file and fail,
# rather than quietly running tests/test_factory_core.py and reporting PASS for an
# unrelated suite. This must run before the dry-run print so tests exercise it too.
if [ -n "$unmatched" ]; then
  echo "fast-gate: FAIL: changed file(s) match no mapping arm and no ignore-list arm:" >&2
  for u in $unmatched; do
    echo "fast-gate:   $u" >&2
  done
  echo "fast-gate: add a case arm mapping each file to its suite, or a deliberate ignore arm with a reason (agents-9nir)" >&2
  exit 1
fi

# Union, dedupe, deterministic order.
files="$(printf '%s\n' $run $mapped | awk 'NF && !seen[$0]++' | sort || true)"

# Dry-run support for testing mapping resolution without invoking unittest.
if [ -n "${FAST_GATE_DRY_RUN:-}" ]; then
  FAST_GATE_TERMINATED=1
  printf '%s\n' $files
  exit 0
fi

# Fall back to a bounded smoke subset when nothing maps (an all-ignored docs/config-only
# change, or no delta at all). Unmatched files never reach here - they fail loudly above.
if [ -z "$files" ]; then
  files="tests/test_factory_core.py"
fi

FAST_GATE_STAGE="preparing runner"
modules="$(printf '%s\n' $files | sed 's#/#.#g; s#\.py$##' | tr '\n' ' ' | sed 's/ *$//')"

FAST_GATE_STAGE="running tests ($modules)"
echo "fast-gate: base=$BASE; running: python3 -u -m unittest $modules"

rc=0
python3 -u -m unittest $modules || rc=$?

FAST_GATE_TERMINATED=1
if [ "$rc" -eq 0 ]; then
  passed_files="$(echo $files | tr '\n' ' ' | sed 's/ *$//')"
  echo "fast-gate: passed: $passed_files"
  exit 0
else
  echo "fast-gate: failed: exit $rc (modules: $modules)" >&2
  exit "$rc"
fi
