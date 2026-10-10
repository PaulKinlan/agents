#!/usr/bin/env python3
"""Tests for tools/fast-gate.sh mapping completeness and correctness (agents-vt7w).

Validates:
1. Critical lib modules resolve to their contract and regression suites (closing blind spots).
2. Every lib/*.py module resolves to test files that actually exist.
3. Every test file in tests/ is reachable by at least one source file mapping (no orphan suites).
4. tools/fast-gate.sh itself maps to this verification suite.
5. agents-9nir: the ignore list is deliberate - ignored docs/config-only paths still fall
   back quietly, and any changed file matching NEITHER a mapping arm NOR the ignore list
   FAILS LOUDLY, naming the file, even when other changed files do map. Markdown is NOT a
   prose-only class: the docs-drift scanner os.walk()s every committed .md outside
   IGNORE_DIRS (agents/docs-drift/scripts/check_docs.py:466-478), so walked-but-unpinned
   markdown fails loudly rather than being silently absorbed by a canvas ignore arm.
"""

import os
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FAST_GATE = ROOT / "tools" / "fast-gate.sh"


def run_fast_gate(changed_files: list[str]) -> subprocess.CompletedProcess:
    """Execute tools/fast-gate.sh with simulated changed files and return the raw result."""
    diff_text = "\n".join(changed_files)
    env = os.environ.copy()
    env["GIT_CHANGED"] = diff_text
    env["FAST_GATE_DRY_RUN"] = "1"
    return subprocess.run(["bash", str(FAST_GATE)], cwd=ROOT, env=env, capture_output=True, text=True)


def resolve_fast_gate(changed_files: list[str]) -> list[str]:
    """Execute tools/fast-gate.sh with simulated changed files and extract mapped suites."""
    res = run_fast_gate(changed_files)
    res.check_returncode()
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

    # --- agents-9nir: the ignore list is deliberate, and "no arm" fails loudly ----------

    def test_readme_maps_to_docs_drift(self):
        """README.md is the one markdown file a suite pins by content (its tree diagram)."""
        mapped = resolve_fast_gate(["README.md"])
        self.assertIn("tests/test_docs_drift.py", mapped, "README.md consumer suite omitted (agents-9nir)")

    def test_github_paths_map_to_ci_suites(self):
        """.github/** is consumed by the CI-action contract and the pages publish scope suites."""
        for path in (".github/workflows/ci.yml", ".github/actions/factory/action.yml"):
            with self.subTest(path=path):
                mapped = resolve_fast_gate([path])
                self.assertIn("tests/test_ci_action.py", mapped, f"{path}: CI action contract omitted (agents-9nir)")
                self.assertIn("tests/test_pages_publish_scope.py", mapped, f"{path}: publish scope omitted (agents-9nir)")

    def test_committed_suppressions_register_maps_to_suppressions_suite(self):
        """findings/suppressions.yaml is read directly by tests/test_suppressions.py."""
        mapped = resolve_fast_gate(["findings/suppressions.yaml"])
        self.assertIn("tests/test_suppressions.py", mapped, "suppressions register contract omitted (agents-9nir)")

    def test_skill_md_maps_to_docs_drift(self):
        """agents/*/SKILL.md is walked by the docs-drift scanner and pinned by count (agents-9nir P0)."""
        mapped = resolve_fast_gate(["agents/docs-drift/SKILL.md"])
        self.assertIn("tests/test_docs_drift.py", mapped, "SKILL.md walker suite omitted (agents-9nir)")

    def test_agent_yaml_maps_to_docs_design_and_containment(self):
        """agents/*/agent.yaml is globbed off the real tree by two suites (agents-9nir review)."""
        mapped = resolve_fast_gate(["agents/vuln-verify/agent.yaml"])
        self.assertIn("tests/test_docs_design.py", mapped, "stations.html glob omitted (test_docs_design.py:77)")
        self.assertIn("tests/test_containment.py", mapped, "credential-grant drift guard omitted (test_containment.py:300)")

    def test_lines_yaml_maps_to_docs_design(self):
        """lines/*.yaml is globbed off the real tree by the lines.html check (agents-9nir review)."""
        mapped = resolve_fast_gate(["lines/web-excellence.yaml"])
        self.assertIn("tests/test_docs_design.py", mapped, "lines.html glob omitted (test_docs_design.py:78)")

    def test_tools_yaml_maps_to_pins_and_child_env(self):
        """tools.yaml is read at CONFIG_PATH when FACTORY_TOOL_PINS is unset; the child-env probes assert on it."""
        mapped = resolve_fast_gate(["tools.yaml"])
        self.assertIn("tests/test_tool_pins.py", mapped)
        self.assertIn("tests/test_child_env.py", mapped, "fail-closed probe reads the committed tools.yaml (agents-9nir)")

    def test_docs_change_maps_to_docs_drift(self):
        """docs/* must include the suite that pins docs/INTEGRATION.md by content (agents-9nir review)."""
        mapped = resolve_fast_gate(["docs/INTEGRATION.md"])
        self.assertIn("tests/test_docs_design.py", mapped)
        self.assertIn("tests/test_pages_publish_scope.py", mapped)
        self.assertIn("tests/test_docs_drift.py", mapped, "INTEGRATION.md anchor/table pin omitted (agents-9nir)")

    def test_ignored_docs_and_vcs_metadata_fall_back_quietly(self):
        """Ignore-list paths resolve to nothing and exit 0, so the real run takes the smoke fallback quietly."""
        for path in (".gitignore", ".beads/metadata.json", "targets/voicebox.yaml",
                     "findings/.gitkeep", "schedules/.gitkeep"):
            with self.subTest(path=path):
                res = run_fast_gate([path])
                self.assertEqual(res.returncode, 0, f"{path}: ignored path must not fail (agents-9nir): {res.stderr}")
                self.assertEqual(res.stdout.strip(), "", f"{path}: ignored path must map to no suite (agents-9nir)")

    def test_walked_but_unpinned_markdown_fails_loudly(self):
        """Markdown the scanner walks but no assertion pins must NOT be silently ignored (agents-9nir P0).

        The docs-drift scanner walks every committed .md outside IGNORE_DIRS, so "prose, no
        consumer" is an unverifiable reason for walked markdown: neither ignore (a canvas
        with a false reason) nor map (a suite whose assertions cannot fail on the file) is
        honest, so the deliberate behaviour is the loud failure.
        """
        for path in ("agents/vuln-verify/README.md", "AGENTS.md", "targets/README.md",
                     "reports/factory-security-audit.md"):
            with self.subTest(path=path):
                res = run_fast_gate([path])
                self.assertNotEqual(res.returncode, 0, f"{path}: walked markdown must not be silently ignored (agents-9nir)")
                self.assertIn(path, res.stderr, f"{path}: the failure must name the file (agents-9nir)")

    def test_unmatched_file_fails_loudly_naming_the_file(self):
        """A changed file matching neither a mapping arm nor the ignore list must fail and name itself."""
        for path in ("package.json", "install.sh", ".agents/skills/beads/SKILL.md"):
            with self.subTest(path=path):
                res = run_fast_gate([path])
                self.assertNotEqual(res.returncode, 0, f"{path}: unmatched file must fail loudly (agents-9nir)")
                self.assertIn(path, res.stderr, f"{path}: the failure must name the unmatched file (agents-9nir)")
                self.assertIn("no mapping arm", res.stderr)

    def test_unmatched_file_fails_even_when_other_files_map(self):
        """A mapped sibling must not mask the unmatched file (the no-fallback hole, agents-9nir)."""
        res = run_fast_gate(["lib/sandbox.py", "install.sh"])
        self.assertNotEqual(res.returncode, 0, "unmatched file masked by a mapped sibling (agents-9nir)")
        self.assertIn("install.sh", res.stderr, "the failure must name the unmatched file")
        self.assertNotIn("lib/sandbox.py", res.stderr, "the mapped file must not be named as unmatched")


if __name__ == "__main__":
    unittest.main()
