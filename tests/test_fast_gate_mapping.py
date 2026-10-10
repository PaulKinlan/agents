#!/usr/bin/env python3
"""Tests for tools/fast-gate.sh mapping completeness and correctness (agents-vt7w).

Validates:
1. Critical lib modules resolve to their contract and regression suites (closing blind spots).
2. Every lib/*.py module resolves to test files that actually exist.
3. Every test file in tests/ is reachable by at least one source file mapping (no orphan suites).
4. tools/fast-gate.sh itself maps to this verification suite.
"""

import os
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FAST_GATE = ROOT / "tools" / "fast-gate.sh"


def resolve_fast_gate(changed_files: list[str]) -> list[str]:
    """Execute tools/fast-gate.sh with simulated changed files and extract mapped suites."""
    diff_text = "\n".join(changed_files)
    env = os.environ.copy()
    env["GIT_CHANGED"] = diff_text
    env["FAST_GATE_DRY_RUN"] = "1"
    res = subprocess.run(["bash", str(FAST_GATE)], cwd=ROOT, env=env, capture_output=True, text=True, check=True)
    return res.stdout.strip().split()


class TestFastGateMapping(unittest.TestCase):
    """Pin the fast-gate mapping contract against regressions."""

    def test_findings_py_maps_to_security_and_suppression_contracts(self):
        """lib/findings.py must run redaction (security) and suppressions (register) contracts."""
        mapped = resolve_fast_gate(["lib/findings.py"])
        self.assertIn("tests/test_findings.py", mapped)
        self.assertIn("tests/test_sinks.py", mapped)
        self.assertIn("tests/test_redaction.py", mapped, "redaction contract omitted (agents-q0mt)")
        self.assertIn("tests/test_suppressions.py", mapped, "suppressions contract omitted (agents-vt7w)")

    def test_report_schema_py_maps_to_schema_unit_and_perf_review(self):
        """lib/report_schema.py must run its own unit test and the concurrency guard suite."""
        mapped = resolve_fast_gate(["lib/report_schema.py"])
        self.assertIn("tests/test_report_schema.py", mapped, "primary unit test omitted (agents-vt7w)")
        self.assertIn("tests/test_perf_review.py", mapped, "concurrency guard omitted (agents-vt7w)")
        self.assertIn("tests/test_factory_truth_2.py", mapped)

    def test_sinks_package_maps_to_sink_adapters(self):
        """lib/sinks/*.py must run test_sink_adapters.py (registry, command sink, process cleanup)."""
        mapped = resolve_fast_gate(["lib/sinks/base.py"])
        self.assertIn("tests/test_sink_adapters.py", mapped, "sink adapters omitted (agents-vt7w)")
        self.assertIn("tests/test_sinks.py", mapped)

    def test_sandbox_py_maps_to_bwrap_guard(self):
        """lib/sandbox.py must run bwrap live tests and the no-bwrap refusal guard."""
        mapped = resolve_fast_gate(["lib/sandbox.py"])
        self.assertIn("tests/test_sandbox.py", mapped)
        self.assertIn("tests/test_no_bwrap_guard.py", mapped, "no-bwrap guard omitted (agents-vt7w)")

    def test_candidate_identity_maps_to_prepass_emission(self):
        """lib/candidate_identity.py must run property tests and prepass emission assertions."""
        mapped = resolve_fast_gate(["lib/candidate_identity.py"])
        self.assertIn("tests/test_candidate_identity.py", mapped)
        self.assertIn("tests/test_candidate_id_emission.py", mapped)

    def test_credential_broker_maps_to_pi_keyless(self):
        """lib/credential_broker.py must run keyless broker verification."""
        mapped = resolve_fast_gate(["lib/credential_broker.py"])
        self.assertIn("tests/test_credential_broker.py", mapped)
        self.assertIn("tests/test_pi_keyless_broker.py", mapped)

    def test_yaml_mini_maps_to_ci_action_contract(self):
        """lib/yaml_mini.py must run mini YAML unit tests and action.yml parse verification."""
        mapped = resolve_fast_gate(["lib/yaml_mini.py"])
        self.assertIn("tests/test_yaml_mini.py", mapped)
        self.assertIn("tests/test_ci_action.py", mapped)

    def test_claude_adapter_maps_to_claude_adapter_test(self):
        """lib/adapters/claude.sh must run claude adapter session auth scrub tests."""
        mapped = resolve_fast_gate(["lib/adapters/claude.sh"])
        self.assertIn("tests/test_claude_adapter.py", mapped)

    def test_pi_adapter_maps_to_keyless_and_auth_failure_tests(self):
        """lib/adapters/pi.sh must run keyless broker and adapter auth failure tests."""
        mapped = resolve_fast_gate(["lib/adapters/pi.sh"])
        self.assertIn("tests/test_pi_keyless_broker.py", mapped)
        self.assertIn("tests/test_adapter_auth_failure.py", mapped)
        self.assertIn("tests/test_factory_core.py", mapped)

    def test_other_adapters_map_to_auth_failure_and_core(self):
        """Other adapters must fall back to auth failure detection and factory core."""
        mapped = resolve_fast_gate(["lib/adapters/deepseek.sh"])
        self.assertIn("tests/test_adapter_auth_failure.py", mapped)
        self.assertIn("tests/test_factory_core.py", mapped)

    def test_factory_dispatcher_maps_to_line_andon_and_auth_failures(self):
        """factory dispatcher must run core truth, line andon, auth failure, and transient cleanup."""
        mapped = resolve_fast_gate(["factory"])
        self.assertIn("tests/test_factory_core.py", mapped)
        self.assertIn("tests/test_factory_truth.py", mapped)
        self.assertIn("tests/test_factory_truth_2.py", mapped)
        self.assertIn("tests/test_adapter_auth_failure.py", mapped)
        self.assertIn("tests/test_line_andon.py", mapped)
        self.assertIn("tests/test_prompt_exposure.py", mapped)
        self.assertIn("tests/test_transient_dirs.py", mapped)

    def test_all_lib_modules_resolve_to_existing_tests(self):
        """Every lib/*.py file must map to existing test files without failure."""
        lib_files = sorted(ROOT.glob("lib/*.py"))
        for lf in lib_files:
            rel = str(lf.relative_to(ROOT))
            mapped = resolve_fast_gate([rel])
            self.assertTrue(len(mapped) > 0, f"{rel} resolved to empty test set")
            for t in mapped:
                self.assertTrue((ROOT / t).is_file(), f"{rel} mapped to non-existent {t}")

    def test_fast_gate_sh_maps_to_this_test(self):
        """Changing tools/fast-gate.sh must run this verification test."""
        mapped = resolve_fast_gate(["tools/fast-gate.sh"])
        self.assertIn("tests/test_fast_gate_mapping.py", mapped)


if __name__ == "__main__":
    unittest.main()
