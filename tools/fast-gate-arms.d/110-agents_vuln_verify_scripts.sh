# tools/fast-gate-arms.d/110-agents_vuln_verify_scripts.sh — 15 arm(s), moved VERBATIM from the single
# case table that used to live in tools/fast-gate.sh. The rationale comments travel with
# the arm they explain (ADR 0001's assertion-consumer rule). Read README.md in this directory
# before adding an arm: PRECEDENCE IS THE NUMERIC PREFIX, and the first matching arm wins.
fast_gate_arms_110_agents_vuln_verify_scripts() {
  case "$1" in
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
      # agents-tdwv: ALSO its OWN suite - tests/test_audit_a11y.py tests THIS script's
      # CLI (no --output must drop candidate ids and matched line hashes from stdout),
      # so a change here could regress the suite written to test it. Same one-token
      # shape as agents-nhf0, agents-yx7z, agents-8jx1 and agents-4ic0; found by the
      # wildcard-set scoping pass rather than by the gate, which cannot see it.
      mapped="$mapped tests/test_candidate_id_emission.py tests/test_audit_a11y.py"
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
    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn
  esac
  return 0             # an arm matched; the loader stops here (first match wins)
}
FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES fast_gate_arms_110_agents_vuln_verify_scripts"
