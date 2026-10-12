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
   prose-only class: the docs-drift scanner os.walk()s every committed .md outside IGNORE_DIRS
   (its walks are in agents/docs-drift/scripts/check_docs.py at :256 and :491; the :466-478 range
   cited here before is that file's markdown tree-block PREFIX parsing - agents-xgha), so
   walked-but-unpinned markdown fails loudly rather than being silently absorbed by a canvas ignore arm.
"""

import ast
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FAST_GATE = ROOT / "tools" / "fast-gate.sh"
# The FLEET COVERAGE ORACLE. It lives in the fleet bundle, not in this repo (the repo's own contract
# suite reaches it the same way - tests/test_coverage_contract.py, agents-1kzf), so the pin below asks
# THE ORACLE what a changed file's consumers are rather than defining a second notion that could
# disagree with it (agents-oj5s).
ORACLE_SCRIPT = Path("/home/exedev/fleet/remote/check-coverage.py")


def oracle_coverage_for(changed_files: list[str], executed_suites: list[str]):
    """The coverage the ORACLE would report for a gate run that executed `executed_suites`.

    In-process reuse, mirroring tests/test_coverage_contract.py's oracle test: the log line is the
    gate's own suite marker, and git is stubbed so the oracle sees exactly `changed_files` as the
    delta. Returns None when the oracle is not installed on this machine - the caller must then say so
    rather than treating silence as coverage.
    """
    if not ORACLE_SCRIPT.is_file():
        return None
    import importlib.util
    import tempfile
    from unittest.mock import patch

    spec = importlib.util.spec_from_file_location("check_coverage_oracle", str(ORACLE_SCRIPT))
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    with tempfile.NamedTemporaryFile("w") as log:
        log.write("fast-gate: passed: " + " ".join(executed_suites) + "\n")
        log.flush()
        original = oracle.subprocess.check_output

        def stubbed(cmd, *args, **kwargs):
            if isinstance(cmd, list):
                if "rev-parse" in cmd:
                    return ("deadbeef" * 5) + "\n"
                if any("diff" in str(part) for part in cmd):
                    return "\n".join(changed_files) + "\n"
            return original(cmd, *args, **kwargs)

        with patch.object(oracle.subprocess, "check_output", side_effect=stubbed):
            return oracle.extract_coverage(log.name, str(ROOT), "HEAD", "bash tools/fast-gate.sh")


def run_fast_gate(changed_files: list[str]) -> subprocess.CompletedProcess:
    """Execute tools/fast-gate.sh with simulated changed files and return the raw result."""
    diff_text = "\n".join(changed_files)
    env = os.environ.copy()
    env["GIT_CHANGED"] = diff_text
    env["FAST_GATE_DRY_RUN"] = "1"
    return subprocess.run(["bash", str(FAST_GATE)], cwd=ROOT, env=env, capture_output=True, text=True)


def run_fast_gate_with_base(base: str) -> subprocess.CompletedProcess:
    """Execute tools/fast-gate.sh resolving the DELTA ITSELF against `base` (no GIT_CHANGED).

    The GIT_CHANGED override short-circuits the delta resolution, so it cannot exercise
    the base/ref handling at all - which is why the hole this covers survived a suite that
    used GIT_CHANGED everywhere.
    """
    env = os.environ.copy()
    env.pop("GIT_CHANGED", None)
    env["GIT_BASE"] = base
    env["FAST_GATE_DRY_RUN"] = "1"
    return subprocess.run(["bash", str(FAST_GATE)], cwd=ROOT, env=env, capture_output=True, text=True)


def resolve_fast_gate(changed_files: list[str]) -> list[str]:
    """Execute tools/fast-gate.sh with simulated changed files and extract mapped suites."""
    res = run_fast_gate(changed_files)
    res.check_returncode()
    return res.stdout.strip().split()


def suites_importing(dotted: str) -> set[str]:
    """The test suites that import `dotted` - the FALLBACK consumer notion, used only when the oracle
    cannot be reached (agents-oj5s).

    This is deliberately the second-best instrument and it is named as such: the oracle's notion of a
    consumer (import-based candidate discovery plus tests/coverage-contract.json) is the one the gate
    of record uses, so a pin built on this scan could one day disagree with the oracle. It exists
    because a pin that skips when the oracle is absent cannot fail, and a guard that cannot fail is not
    a guard. Both import SHAPES are scanned - the parenthesised multi-name `from lib.containment import
    (...)` the split modules use, and a plain `import lib.containment` - because the shape that exists
    today is not necessarily the shape a future consumer arrives with. (Measured when this was
    written: all seven importers use the from-import shape and none uses the plain one.) Dynamic
    imports (importlib, __import__) are NOT seen; that limit is real, and it is one more reason the
    oracle path is the one that matters.
    """
    found = set()
    for path in sorted((ROOT / "tests").glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == dotted:
                found.add(f"tests/{path.name}")
            elif isinstance(node, ast.Import) and any(alias.name == dotted for alias in node.names):
                found.add(f"tests/{path.name}")
    return found


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

    def test_tool_pins_py_maps_to_pins_contract_and_sandbox_boundary(self):
        """lib/tool_pins.py authenticates bwrap itself (agents-28nn): the refusal property
        lives in tests/test_sandbox.py, so the pins contract alone is not enough."""
        mapped = resolve_fast_gate(["lib/tool_pins.py"])
        self.assertIn("tests/test_tool_pins.py", mapped)
        self.assertIn("tests/test_sandbox.py", mapped,
                      "bwrap-pin boundary suite omitted (agents-28nn)")

    def test_budget_py_maps_to_the_line_runner_suite(self):
        """agents-8z4z: the line runner is a run_station_command caller (factory:1831), and
        tests/test_line_andon.py imports StationTimeout from lib.budget to drive the andon
        timeout path - so a budget.py edit must run it. Evidence is the gate's own coverage
        oracle, which reported `unmatched: ['lib/budget.py']` / `omitted:
        ['tests/test_line_andon.py']` on the change that wrapped the on_spawn call."""
        mapped = resolve_fast_gate(["lib/budget.py"])
        self.assertIn("tests/test_budget.py", mapped)
        self.assertIn("tests/test_line_andon.py", mapped,
                      "line-runner suite omitted for the station-command runner (agents-8z4z)")

    def test_generate_tool_pins_maps_to_pins_contract(self):
        """tools/generate-tool-pins.sh must run the suite asserting its TOOLS list covers
        every trusted tool (agents-28nn)."""
        mapped = resolve_fast_gate(["tools/generate-tool-pins.sh"])
        self.assertIn("tests/test_tool_pins.py", mapped,
                      "generator-coverage suite omitted (agents-28nn)")

    def test_threat_model_md_maps_to_the_walker_suite(self):
        """THREAT_MODEL.md is root markdown the docs-drift scanner walks (agents-28nn)."""
        mapped = resolve_fast_gate(["THREAT_MODEL.md"])
        self.assertIn("tests/test_docs_drift.py", mapped,
                      "walker suite omitted for walked root markdown (agents-28nn)")

    def test_patches_markdown_maps_to_the_walker_suite(self):
        """patches/*.md is walked by the docs-drift scanner (agents-g1je)."""
        mapped = resolve_fast_gate(["patches/README.md"])
        self.assertIn("tests/test_docs_drift.py", mapped,
                      "walker suite omitted for walked patches markdown (agents-g1je)")

    def test_patches_patch_artifacts_are_ignored(self):
        """patches/*.patch diff artifacts are consumed hub-side and ignored in fast gate (agents-g1je)."""
        mapped = resolve_fast_gate(["patches/fleet-land-message-tree-identity.patch"])
        self.assertEqual(mapped, [], "patch diff artifact should be claimed by ignore arm")

    def test_tests_fixtures_map_to_the_containment_suite(self):
        """tests/fixtures/ holds the checked-in attack payloads (agents-28nn round 5):
        fake_engine.sh is asserted on by TestEngineCredentialPinning, which agents-3iog
        moved into tests/test_containment_engine_credentials.py, so a payload change must
        run the module that contains the attack - and must NOT drag the whole containment
        suite, which is what the split was for."""
        mapped = resolve_fast_gate(["tests/fixtures/fake_engine.sh"])
        self.assertIn("tests/test_containment_engine_credentials.py", mapped,
                      "containing module omitted for the checked-in attack payload "
                      "(agents-28nn round 5; agents-3iog split)")
        self.assertNotIn("tests/test_containment.py", mapped,
                         "the attack-payload arm must not run the whole containment suite "
                         "(agents-3iog: no other containment module reads tests/fixtures/)")

    def test_containment_harness_maps_to_every_containment_module(self):
        """tests/containment_harness.py holds the setUp plus the 11 helpers the containment suites
        inherit (agents-3iog split), and it is deliberately NOT test_*.py so discovery never
        collects it. That is exactly why it needs its own arm rather than being absorbed: with no
        arm the gate FAILED CLOSED on it as unmapped ("changed file(s) match no mapping arm and no
        ignore-list arm") - correct behaviour for a file whose changes run nothing, but it left the
        split unlandable. A harness change reaches every inherited execution, so the arm names all
        six modules, plus the shape test that catches a test method creeping into the harness."""
        mapped = resolve_fast_gate(["tests/containment_harness.py"])
        for module in (
            "tests/test_containment.py",
            "tests/test_containment_declarations.py",
            "tests/test_containment_adapters.py",
            "tests/test_containment_engine_credentials.py",
            "tests/test_containment_prepass_pins.py",
            "tests/test_containment_egress.py",
            "tests/test_containment_shape.py",
        ):
            self.assertIn(module, mapped, f"harness arm must run {module} (agents-3iog)")

    def _assert_arm_covers(self, missing: list[str], source: str) -> None:
        """The FALLBACK path's failure message: it names the module, the suites the arm omits and the
        one-line fix, because a bare assertEqual teaches the next person nothing (agents-oj5s)."""
        self.assertFalse(missing, (
            "the lib/containment.py arm in tools/fast-gate.sh does not run every suite that consumes "
            f"lib.containment. Missing (per {source}): {missing}. "
            "FIX: add those names to the arm's mapped= list in tools/fast-gate.sh, beside "
            "tests/test_containment.py. This pin exists because the coverage contract REPORTS rather "
            "than FAILS, so a dropped suite is silent by construction - both the 2-suite and the "
            "8-suite selections exit 0 (agents-mo75 measured that; agents-oj5s pins it)."))

    def test_containment_py_arm_covers_every_consumer_the_oracle_names(self):
        """agents-oj5s, the regression pin the agents-mo75 review asked for. agents-mo75 added the
        lib/containment.py) arm after the basename rule was measured selecting only the thin
        tests/test_containment.py (55 tests) while the module's consumers run 151 - but nothing pinned
        the arm's LIST, so the next editor could drop a suite, or a new consumer could appear, with the
        gate staying green: the coverage contract REPORTS rather than FAILS.

        The instrument is the ORACLE'S notion of a consumer, not a private one: the arm's emitted
        selection is handed to the fleet coverage oracle, which reports any consumer it considers
        required and unexecuted as `omitted` (and the changed file itself as `unmapped` when nothing
        maps it). Only when the oracle is not installed does this fall back to the ast import scan in
        suites_importing(), which is a second-best notion and is labelled as such in the failure text.
        """
        selected = resolve_fast_gate(["lib/containment.py"])
        coverage = oracle_coverage_for(["lib/containment.py"], selected)
        if coverage is not None:
            unmapped = sorted(coverage.get("unmapped", []))
            omitted = sorted(coverage.get("omitted", []))
            self.assertEqual((unmapped, omitted), ([], []), (
                "the lib/containment.py arm in tools/fast-gate.sh does not cover the module's consumers. "
                f"Per the coverage oracle: unmapped changed file(s)={unmapped} (the arm is missing, so "
                f"nothing maps the module) and omitted suite(s)={omitted} (the arm exists but does not "
                "name them). FIX: the arm's mapped= list in tools/fast-gate.sh, beside "
                "tests/test_containment.py, must name every omitted suite. This pin exists because the "
                "coverage contract REPORTS rather than FAILS, so a dropped suite is silent by "
                "construction - both the 2-suite and the 8-suite selections exit 0 (agents-mo75 "
                "measured that; agents-oj5s pins it)."))
            return
        importers = suites_importing("lib.containment")
        # Vacuity guards, pinning the SCANNER's reach rather than a count that decays when suites are
        # split or merged: tests/test_containment.py uses the parenthesised many-name form, and
        # tests/test_child_env.py is a single-name importer outside the containment family - it is the
        # consumer the basename rule missed.
        self.assertIn("tests/test_containment.py", importers,
                      "the import scan must see the parenthesised from-import (agents-oj5s)")
        self.assertIn("tests/test_child_env.py", importers,
                      "the import scan must see a single-name from-import outside the suite family "
                      "(agents-oj5s)")
        self._assert_arm_covers(sorted(importers - set(selected)),
                               "the ast import scan (the fleet coverage oracle is not installed here)")

    def test_hermetic_env_and_package_init_map_to_hermetic_suite(self):
        """tests/__init__.py and tests/hermetic_env.py must map to test_hermetic_env.py and pin suites."""
        for path in ("tests/__init__.py", "tests/hermetic_env.py"):
            with self.subTest(path=path):
                mapped = resolve_fast_gate([path])
                self.assertIn("tests/test_hermetic_env.py", mapped, f"{path} must map to test_hermetic_env.py")
                self.assertIn("tests/test_sandbox.py", mapped, f"{path} must map to test_sandbox.py")
                self.assertIn("tests/test_tool_pins.py", mapped, f"{path} must map to test_tool_pins.py")

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
        """lib/adapters/claude.sh must run claude adapter session auth scrub and prompt exposure tests."""
        mapped = resolve_fast_gate(["lib/adapters/claude.sh"])
        self.assertIn("tests/test_claude_adapter.py", mapped)
        self.assertIn("tests/test_prompt_exposure.py", mapped, "claude.sh prompt exposure suite omitted (agents-9bp7)")

    def test_pi_adapter_maps_to_keyless_and_auth_failure_tests(self):
        """lib/adapters/pi.sh must run keyless broker and adapter auth failure tests."""
        mapped = resolve_fast_gate(["lib/adapters/pi.sh"])
        self.assertIn("tests/test_pi_keyless_broker.py", mapped)
        self.assertIn("tests/test_adapter_auth_failure.py", mapped)
        self.assertIn("tests/test_factory_core.py", mapped)
        self.assertIn("tests/test_containment.py", mapped, "pi.sh containment suite omitted (agents-71zn)")
        self.assertIn("tests/test_containment_adapters.py", mapped,
                      "pi.sh adapter suite omitted (agents-3iog split: the argv/env shape assertions "
                      "live in the adapters module, which the pre-split arm ran as part of the whole file)")
        self.assertIn("tests/test_prompt_exposure.py", mapped, "pi.sh prompt exposure suite omitted (agents-zak0)")

    def test_other_adapters_map_to_auth_failure_and_core(self):
        """Other adapters must fall back to auth failure detection and factory core."""
        mapped = resolve_fast_gate(["lib/adapters/deepseek.sh"])
        self.assertIn("tests/test_adapter_auth_failure.py", mapped)
        self.assertIn("tests/test_factory_core.py", mapped)
        self.assertIn("tests/test_prompt_exposure.py", mapped, "adapter prompt exposure suite omitted (agents-zak0)")

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

    def test_station_trusted_tool_pins_mapped_for_prepass_scripts(self):
        """Pre-pass scripts launching trusted tools must map tests/test_station_trusted_tool_pins.py (agents-01qd)."""
        for path in (
            "agents/perf-review/scripts/scan_perf_changes.py",
            "agents/pr-fixer/scripts/collect_failures.py",
            "agents/deps-supply-chain/scripts/audit_deps.py",
        ):
            with self.subTest(path=path):
                mapped = resolve_fast_gate([path])
                self.assertIn("tests/test_station_trusted_tool_pins.py", mapped,
                              f"{path} missing pin resolution suite (agents-01qd)")

    def test_fetch_issues_mapped_to_issue_triage_prepass(self):
        """fetch_issues.py must map tests/test_issue_triage_prepass.py (agents-ujtv)."""
        mapped = resolve_fast_gate(["agents/issue-triage/scripts/fetch_issues.py"])
        self.assertIn("tests/test_issue_triage_prepass.py", mapped,
                      "fetch_issues.py missing pre-pass test suite (agents-ujtv)")

    def test_station_script_class_arm_pins_parse_logs_consumer(self):
        """The agents/*/scripts/*.py class arm must resolve a station script that has no
        per-file arm, and must keep tests/test_prepass_exclusions.py (agents-1nb3).

        Pinned because the arm's first version was a SILENT GREEN: it omitted the only
        suite that exercises parse_logs.py while its own comment recorded the import
        (rev-9iyf). Resolving at all is covered here too - resolve_fast_gate() re-raises
        the gate's abort, so deleting the class arm outright fails this test rather than
        passing it.
        """
        mapped = resolve_fast_gate(["agents/log-check/scripts/parse_logs.py"])
        self.assertIn("tests/test_prepass_exclusions.py", mapped,
                      "parse_logs.py's only exercising suite omitted: the class arm's "
                      "silent green is back (agents-1nb3)")

    # --- agents-9nir: the ignore list is deliberate, and "no arm" fails loudly ----------

    def test_root_markdown_maps_to_docs_drift(self):
        """Root governance and architecture markdown files map to tests/test_docs_drift.py (agents-6hqi)."""
        for path in ("README.md", "AGENTS.md", "THREAT_MODEL.md", "CLAUDE.md"):
            with self.subTest(path=path):
                mapped = resolve_fast_gate([path])
                self.assertIn("tests/test_docs_drift.py", mapped, f"{path} consumer suite omitted (agents-6hqi)")

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
        self.assertIn("tests/test_containment_declarations.py", mapped,
                      "credential-grant drift guard omitted (agents-3iog moved it out of the "
                      "mid-file suite; the declaration tests are the only consumers of agents/*/agent.yaml)")
        self.assertNotIn("tests/test_containment.py", mapped,
                         "the station-manifest arm must not run the whole containment suite "
                         "(agents-3iog: no other containment module reads the real agents/ tree)")

    def test_lines_yaml_maps_to_docs_design(self):
        """lines/*.yaml is globbed off the real tree by the lines.html check (agents-9nir review)."""
        mapped = resolve_fast_gate(["lines/web-excellence.yaml"])
        self.assertIn("tests/test_docs_design.py", mapped, "lines.html glob omitted (test_docs_design.py:78)")

    def test_tools_yaml_maps_to_pins_and_child_env(self):
        """tools.yaml is read at CONFIG_PATH when FACTORY_TOOL_PINS is unset; the child-env probes assert on it."""
        mapped = resolve_fast_gate(["tools.yaml"])
        self.assertIn("tests/test_tool_pins.py", mapped)
        self.assertIn("tests/test_child_env.py", mapped, "fail-closed probe reads the committed tools.yaml (agents-9nir)")

    def test_test_file_change_selects_coverage_contract_audit(self):
        """agents-vim1: newly added or modified test files must audit the cross-module mock contract."""
        mapped = resolve_fast_gate(["tests/test_new_feature.py"])
        self.assertIn("tests/test_coverage_contract.py", mapped)
        self.assertIn("tests/test_new_feature.py", mapped)

    def test_coverage_contract_mapping(self):
        """tests/coverage-contract.json maps to test_coverage_contract and test_fast_gate_mapping (agents-1kzf)."""
        mapped = resolve_fast_gate(["tests/coverage-contract.json"])
        self.assertIn("tests/test_coverage_contract.py", mapped)
        self.assertIn("tests/test_fast_gate_mapping.py", mapped)

    def test_docs_change_maps_to_docs_drift(self):
        """docs/* must include the suite that pins docs/INTEGRATION.md by content (agents-9nir review)."""
        mapped = resolve_fast_gate(["docs/INTEGRATION.md"])
        self.assertIn("tests/test_docs_design.py", mapped)
        self.assertIn("tests/test_pages_publish_scope.py", mapped)
        self.assertIn("tests/test_docs_drift.py", mapped, "INTEGRATION.md anchor/table pin omitted (agents-9nir)")

    def test_targets_yaml_maps_to_schedules(self):
        """targets/*.yaml is globbed by lib/scheduler.py:140-144 and asserted via real-factory subprocesses."""
        mapped = resolve_fast_gate(["targets/voicebox.yaml"])
        self.assertIn("tests/test_schedules.py", mapped,
                      "scheduler glob consumer omitted (lib/scheduler.py:140-144, test_schedules.py:200-213) (agents-9nir)")

    def test_reports_markdown_maps_to_docs_drift(self):
        """reports/ is NOT in DEFAULT_IGNORE_DIRS, so the scanner walks it and the fleet assertions bind it."""
        mapped = resolve_fast_gate(["reports/factory-security-audit.md"])
        self.assertIn("tests/test_docs_drift.py", mapped,
                      "reports/*.md is walked (lib/exclusions.py:23-43 excludes findings/,runs/ - not reports/) (agents-9nir)")

    def test_ignored_docs_and_vcs_metadata_fall_back_quietly(self):
        """Ignore-list paths resolve to nothing and exit 0, so the real run takes the smoke fallback quietly.

        .gitignore USED TO BE IN THIS LIST AND WAS REMOVED BY agents-ah03: the ignore arm claimed it was
        "consumed only by git itself", citing two suites that write their own .gitignore into a tmp target
        - true, but it missed tests/test_docs_drift.py::TestPlanFindingsStoreAgreement, which drives
        `git check-ignore` against the committed file. An ignored path is not merely unmapped: it
        suppresses the smoke fallback, so the file ran one unrelated suite while a suite that can fail on
        it was never selected. The replacement assertion is test_gitignore_maps_to_the_suite_that_pins_it.
        """
        for path in (".beads/metadata.json", "findings/scan-notes.md",
                     "findings/.gitkeep", "schedules/.gitkeep"):
            with self.subTest(path=path):
                res = run_fast_gate([path])
                self.assertEqual(res.returncode, 0, f"{path}: ignored path must not fail (agents-9nir): {res.stderr}")
                self.assertEqual(res.stdout.strip(), "", f"{path}: ignored path must map to no suite (agents-9nir)")

    def test_gitignore_maps_to_the_suite_that_pins_it(self):
        """agents-ah03: .gitignore has a consumer, so it must MAP, not be ignored.

        The consumer is tests/test_docs_drift.py::TestPlanFindingsStoreAgreement: it runs
        `git check-ignore -q --no-index findings/<name>` against the repository for two names and asserts
        opposite outcomes (findings/*.md ignored, findings/suppressions.yaml not ignored and tracked). The
        committed .gitignore is what decides both, so a .gitignore edit can break that suite - and while
        this file was ignored, the fast gate would not have run it.
        """
        mapped = resolve_fast_gate([".gitignore"])
        self.assertIn("tests/test_docs_drift.py", mapped,
                      "a .gitignore change must select the suite that drives git check-ignore against it "
                      "(agents-ah03); ignoring it also suppressed the smoke fallback")

    def test_walked_but_unpinned_markdown_fails_loudly(self):
        """Markdown the scanner walks but no assertion pins must NOT be silently ignored (agents-9nir P0).

        The docs-drift scanner walks every committed .md outside IGNORE_DIRS, so "prose, no
        consumer" is an unverifiable reason for walked markdown: neither ignore (a canvas
        with a false reason) nor map (a suite whose assertions cannot fail on the file) is
        honest, so the deliberate behaviour is the loud failure.
        """
        for path in ("agents/vuln-verify/README.md", "targets/README.md"):
            with self.subTest(path=path):
                res = run_fast_gate([path])
                self.assertNotEqual(res.returncode, 0, f"{path}: walked markdown must not be silently ignored (agents-9nir)")
                self.assertIn(path, res.stderr, f"{path}: the failure must name the file (agents-9nir)")

    def test_install_sh_maps_to_the_gate_entrypoint_suite(self):
        """agents-3xqa: install.sh is the provisioning entrypoint and the CALLER of the gate's
        install step (agents-l2xb). It must select a suite that EXECUTES it - not fail loudly as
        an unmapped file, which is what made an install.sh edit unable to pass its own fast gate."""
        mapped = resolve_fast_gate(["install.sh"])
        self.assertIn("tests/test_gate_entrypoint_config.py", mapped,
                      "install.sh must map to the suite that drives it in a temp HOME (agents-3xqa)")

    def test_check_conf_and_cmd_map_to_consistency_and_entrypoint_suites(self):
        """agents-ows4: tools/check.conf and tools/check-cmd.sh configure and install the gate
        command; edits to either must map to tests/test_check_conf_consistency.py and
        tests/test_gate_entrypoint_config.py rather than failing loudly as unmapped."""
        for path in ("tools/check.conf", "tools/check-cmd.sh"):
            with self.subTest(path=path):
                mapped = resolve_fast_gate([path])
                self.assertIn("tests/test_check_conf_consistency.py", mapped,
                              f"{path} must map to the consistency test (agents-ows4)")
                self.assertIn("tests/test_gate_entrypoint_config.py", mapped,
                              f"{path} must map to the gate entrypoint suite (agents-ows4)")

    def test_unmatched_file_fails_loudly_naming_the_file(self):
        """A changed file matching neither a mapping arm nor the ignore list must fail and name itself."""
        for path in ("package.json", ".agents/skills/beads/SKILL.md"):
            with self.subTest(path=path):
                res = run_fast_gate([path])
                self.assertNotEqual(res.returncode, 0, f"{path}: unmatched file must fail loudly (agents-9nir)")
                self.assertIn(path, res.stderr, f"{path}: the failure must name the unmatched file (agents-9nir)")
                self.assertIn("no mapping arm", res.stderr)

    def test_unmatched_gate_config_path_refuses_loudly_with_actionable_guidance(self):
        """agents-ows4, agents-dtj6, agents-iwm5: a new/unmatched gate or provisioning config path must fail loudly,
        identifying the path, explaining that it is gate/provisioning config, pointing directly
        to tools/fast-gate.sh, and recommending relevant test suites so the fix is an immediate edit.
        The cited ignore-list section marker must actually exist as a heading in tools/fast-gate.sh (agents-iwm5)."""
        fast_gate_content = FAST_GATE.read_text(encoding="utf-8")
        for path in ("tools/new_gate.conf", "tools/custom-gate.sh"):
            with self.subTest(path=path):
                res = run_fast_gate([path])
                self.assertNotEqual(res.returncode, 0, f"{path} must fail loudly")
                self.assertIn(path, res.stderr, f"{path} must be named in the error")
                self.assertIn("gate/provisioning config", res.stderr)
                self.assertIn("tools/fast-gate.sh", res.stderr)
                self.assertIn("tests/test_check_conf_consistency.py", res.stderr)
                self.assertIn("--- Ignore list (agents-9nir) ---", res.stderr)
                self.assertNotIn("deliberate ignore list", res.stderr)
                self.assertNotIn("around line 135", res.stderr)

                # agents-iwm5: dynamically extract the cited header and assert it exists as an anchored heading line in tools/fast-gate.sh
                import re
                m = re.search(r"or an ignore arm under '([^']+)'", res.stderr)
                self.assertIsNotNone(m, f"expected refusal guidance to cite an ignore-list section, got:\n{res.stderr}")
                cited_header = m.group(1).strip()
                core_header = cited_header.strip("-").strip()
                # End-anchor required so comments like '# --- Ignore list (agents-9nir) --- is the old name' cannot match (agents-iwm5)
                heading_pattern = re.compile(rf"^\s*#\s*-+\s*{re.escape(core_header)}\s*-+\s*$", re.MULTILINE)
                self.assertTrue(heading_pattern.search(fast_gate_content),
                                f"the cited section {cited_header!r} must actually exist as an anchored heading line in tools/fast-gate.sh")

    def test_unmatched_file_fails_even_when_other_files_map(self):
        """A mapped sibling must not mask the unmatched file (the no-fallback hole, agents-9nir)."""
        res = run_fast_gate(["lib/sandbox.py", ".agents/skills/beads/SKILL.md"])
        self.assertNotEqual(res.returncode, 0, "unmatched file masked by a mapped sibling (agents-9nir)")
        self.assertIn(".agents/skills/beads/SKILL.md", res.stderr, "the failure must name the unmatched file")
        self.assertNotIn("lib/sandbox.py", res.stderr, "the mapped file must not be named as unmatched")

    def test_tree_guard_tier_runs_on_every_mapped_delta(self):
        """agents-dv23 (ADR agents-c07o): tests/test_tree_guards.py is an always-on tier that must
        be included in every mapped fast-gate run to enforce repo-wide invariants.

        agents-undf: the fast-gate consumer-coverage pin is a SECOND always-on tier with the same
        reach, moved out of the tree-guard file because agents-dv23 pins that file's classes. Both are
        asserted together, because a pin that exists and is not selected is the same as no pin - which
        is exactly how the consumer-coverage pin was born red on its own branch (agents-pdth)."""
        for path in ("lib/budget.py", "lib/child_env.py", "tools.yaml", "README.md"):
            with self.subTest(delta=path):
                mapped = resolve_fast_gate([path])
                for tier in ("tests/test_tree_guards.py", "tests/test_fast_gate_consumer_coverage.py"):
                    self.assertIn(tier, mapped,
                                  f"mapped delta for {path} must contain the always-on tier {tier}")

    def test_tree_guard_tier_module_holds_only_tree_property_tests(self):
        """agents-dv23, agents-5br9: tests/test_tree_guards.py must hold only repo-wide tree property tests,
        pinned by class names and count to prevent accidental unit-test creep into the always-on tier.
        TestWorktreeBeadsDecoyGuard (agents-5br9) enforces a repo-wide tree property: a linked worktree
        must hold no local decoy .beads database."""
        tree_guards_path = ROOT / "tests" / "test_tree_guards.py"
        self.assertTrue(tree_guards_path.is_file(), "tests/test_tree_guards.py must exist")
        import ast
        tree = ast.parse(tree_guards_path.read_text(encoding="utf-8"))
        classes = [node.name for node in tree.body if isinstance(node, ast.ClassDef)]
        self.assertEqual(classes, ["TestNoUnboundedSubprocess", "TestWorktreeBeadsDecoyGuard"],
                         "tests/test_tree_guards.py must contain exactly the pinned tree-guard classes")

    def test_a_tier_file_delta_selects_the_suite_that_guards_its_contents(self):
        """agents-azi1, found by the merger landing a union rather than by anyone anticipating it: the
        always-on tier file's CONTENTS are guarded by the pin in THIS module
        (test_tree_guard_tier_module_holds_only_tree_property_tests asserts it holds exactly
        ['TestNoUnboundedSubprocess']), so a change to tests/test_tree_guards.py must select this module.
        Without it, adding a class to the tier file PASSED the fast gate and FAILED the full gate: a real
        verdict about the file under review that was blind to the rule governing it - worse than an
        omission, because it says PASS. The generic tests/test_*.py arm cannot cover this: it adds
        direct_run_completeness and coverage_contract, neither of which reads the tier file (measured:
        exactly one suite names it). Both halves are asserted, because an explicit arm REPLACES the
        generic one (agents-bwbe) and a narrow fix would otherwise silently drop what it already gave."""
        mapped = resolve_fast_gate(["tests/test_tree_guards.py"])
        self.assertIn("tests/test_fast_gate_mapping.py", mapped,
                      "a change to the always-on tier file must run the suite that pins its contents "
                      "(agents-azi1: without it the fast gate passes a class-creep change that the full "
                      "gate rejects)")
        self.assertIn("tests/test_direct_run_completeness.py", mapped,
                      "the explicit tier-file arm must keep what the generic tests/test_*.py arm gave: "
                      "the __main__-last invariant (agents-9lh8, agents-h17y)")
        self.assertIn("tests/test_coverage_contract.py", mapped,
                      "the explicit tier-file arm must keep what the generic tests/test_*.py arm gave: "
                      "the cross-module mock coverage contract (agents-vim1)")

    def test_an_ordinary_test_file_delta_does_not_select_the_guard_suite(self):
        """The NEGATIVE half of agents-azi1's property, and the half that keeps its cost CONDITIONAL.

        azi1 asserts three times that a TIER file delta selects tests/test_fast_gate_mapping.py. Nothing
        asserted the converse, so nothing stopped the guard being pulled for EVERY tests/ delta - which would
        turn its cost from conditional-on-a-tier-file into constant-on-every-gate-run.

        MEASURED BEFORE THIS TEST WAS WRITTEN, with the same dry-run instrument the positive test uses: the
        gate selects test_fast_gate_mapping.py for tests/test_tree_guards.py, and does NOT select it for
        tests/test_summary_identity.py, tests/test_budget.py or tests/test_pip_audit.py - each of those gets
        the two generic companions plus the two always-on tiers. So the property is expressible, which is
        why it is asserted rather than noted as a limit.

        IF THIS EVER FAILS it means an explicit arm widened to cover ordinary test files, or the generic
        tests/test_*.py arm started adding the mapping suite: the guard's cost has stopped being conditional
        and the fleet pays ~13s on every gate run (agents-ud2k).
        """
        for path in ("tests/test_summary_identity.py", "tests/test_budget.py"):
            with self.subTest(path=path):
                mapped = resolve_fast_gate([path])
                self.assertNotIn(
                    "tests/test_fast_gate_mapping.py",
                    mapped,
                    f"an ordinary test-file delta ({path}) must not pull the tree-guard suite: that is what "
                    f"keeps the guard's cost conditional on a tier-file change rather than constant on every "
                    f"gate run (agents-ud2k, the pair to agents-azi1)",
                )

    def test_an_unresolvable_base_is_an_error_not_an_empty_delta(self):
        """A base that is not a commit must FAIL LOUDLY, never fall back to the smoke subset (agents-c1z0 P1).

        The delta used to be resolved with `git diff --name-only "$BASE"...HEAD 2>/dev/null || true`.
        `git diff` with an unresolvable base or no merge base exits non-zero and prints nothing
        on stdout, so "I could not determine the delta" reached the empty-change-set path, took
        the bounded smoke fallback and reported PASS for a suite unrelated to the change. On the
        same tree a VALID base produced a named refusal. A fallback that swallows an error must
        produce a DISTINCT value, so this is an error and it fails is the only honest outcome.
        """
        for base in ("origin/main-does-not-exist", "refs/heads/also-missing"):
            with self.subTest(base=base):
                res = run_fast_gate_with_base(base)
                self.assertNotEqual(res.returncode, 0, f"unresolvable base '{base}' must fail loudly (agents-c1z0)")
                self.assertIn(base, res.stderr, "the failure must name the base it could not resolve")
                self.assertIn("ERROR", res.stderr, "the message must say this is an error, not an empty delta")

    def test_a_real_base_with_no_delta_still_falls_back_quietly(self):
        """A base that IS a commit and a delta that is genuinely empty must still resolve (agents-c1z0).

        The guard must not over-correct: the smoke fallback is legitimate for a real base with
        no delta, and the docs/config-only ignore path depends on it. HEAD is a commit and
        HEAD...HEAD is empty by construction, so this pins the distinction - ERRORS are refused,
        ABSENCE OF A DELTA is not.
        """
        res = run_fast_gate_with_base("HEAD")
        self.assertEqual(res.returncode, 0, f"an empty delta against a real base must not fail: {res.stderr}")
        self.assertEqual(res.stdout.strip(), "", "an empty delta must resolve to no suites (the smoke fallback applies to the real run)")

    def test_a_real_base_with_a_real_delta_resolves_that_delta(self):
        """The same code path, with an actual delta against a real base, must map the real files (agents-c1z0).

        This is the third arm of the construction: the guard must not have replaced the
        resolution with a constant. `HEAD~1` is a real commit on any checkout with history.
        """
        res = run_fast_gate_with_base("HEAD~1")
        self.assertEqual(res.returncode, 0, f"a real base with a real delta must resolve: {res.stderr}")
        self.assertNotIn("is not a commit", res.stderr, "HEAD~1 must resolve as a commit")

    def test_a_failing_dedupe_pipeline_is_an_error_not_an_empty_suite_list(self):
        """A pipeline that cannot compute the suite list must FAIL LOUDLY (agents-c1z0 review).

        The dedupe pipeline used to end in `|| true`, which is the same error-masking shape
        as the base resolution fixed by this change, one line later: a failing `sort` or
        `awk` (OOM, a broken executable on PATH, SIGPIPE) suppressed its status, `files`
        became the empty string, and the smoke fallback reported PASS - discarding suites
        that HAD been mapped correctly. Constructed by the reviewer with GIT_CHANGED set to
        a mapped file and a `sort` earlier on PATH that exits 1: tests/test_sandbox.py was
        thrown away and the verdict was green. A UNKNOWN suite list is not an empty one.
        """
        with tempfile.TemporaryDirectory() as tmp:
            fake_sort = Path(tmp) / "sort"
            fake_sort.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            fake_sort.chmod(0o755)
            env = os.environ.copy()
            env["GIT_CHANGED"] = "lib/sandbox.py"
            env["PATH"] = f"{tmp}{os.pathsep}{env.get('PATH', '')}"
            res = subprocess.run(["bash", str(FAST_GATE)], cwd=ROOT, env=env, capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0, "a failing dedupe pipeline must not fall back to the smoke subset (agents-c1z0 review)")
        self.assertIn("dedupe pipeline failed", res.stderr, "the failure must name the broken pipeline")
        self.assertNotIn("test_factory_core.py", res.stdout + res.stderr, "the mapped suite must not be silently replaced by the smoke subset")

    def test_fast_gate_execution_reports_passed_terminal_signal_on_success(self):
        """tools/fast-gate.sh must leave an explicit 'fast-gate: passed:' terminal signal on success (agents-7zts)."""
        probe = ROOT / "tests" / "test_pass_probe_tmp.py"
        try:
            probe.write_text("import unittest\nclass _T(unittest.TestCase):\n    def test_ok(self): pass\n", encoding="utf-8")
            env = os.environ.copy()
            env["GIT_CHANGED"] = "tests/test_pass_probe_tmp.py"
            res = subprocess.run(["bash", str(FAST_GATE)], cwd=ROOT, env=env, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, f"expected rc 0, got {res.returncode}: {res.stderr}")
            # agents-h17y: the tests/test_*.py arm also maps tests/test_direct_run_completeness.py,
            # so any test-file run names it alongside the changed file - the class-wide __main__-block
            # invariant (agents-9lh8) is re-checked whenever a test file changes.
            self.assertIn("fast-gate: passed: tests/test_coverage_contract.py tests/test_direct_run_completeness.py tests/test_fast_gate_consumer_coverage.py tests/test_pass_probe_tmp.py tests/test_tree_guards.py", res.stdout)
        finally:
            probe.unlink(missing_ok=True)

    def test_fast_gate_execution_emits_single_line_marker_naming_all_suites(self):
        """agents-gttt: when multiple suites run, tools/fast-gate.sh must emit exactly ONE
        'fast-gate: passed:' line naming every executed suite, so the line-by-line coverage
        parser (/home/exedev/fleet/remote/check-coverage.py) does not silently drop suites."""
        probe_a = ROOT / "tests" / "test_multi_a_probe_tmp.py"
        probe_b = ROOT / "tests" / "test_multi_b_probe_tmp.py"
        try:
            probe_a.write_text("import unittest\nclass _A(unittest.TestCase):\n    def test_a(self): pass\n", encoding="utf-8")
            probe_b.write_text("import unittest\nclass _B(unittest.TestCase):\n    def test_b(self): pass\n", encoding="utf-8")
            env = os.environ.copy()
            env["GIT_CHANGED"] = f"{probe_a.relative_to(ROOT)}\n{probe_b.relative_to(ROOT)}"
            res = subprocess.run(["bash", str(FAST_GATE)], cwd=ROOT, env=env, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, f"expected rc 0, got {res.returncode}: {res.stderr}")
            passed_lines = [l for l in res.stdout.splitlines() if l.startswith("fast-gate: passed:")]
            self.assertEqual(len(passed_lines), 1, f"expected exactly one 'fast-gate: passed:' line, got: {passed_lines}")
            suites_on_marker = passed_lines[0].replace("fast-gate: passed:", "").split()
            expected = sorted(["tests/test_coverage_contract.py", "tests/test_direct_run_completeness.py",
                                 "tests/test_fast_gate_consumer_coverage.py",
                                 "tests/test_tree_guards.py",
                               str(probe_a.relative_to(ROOT)), str(probe_b.relative_to(ROOT))])
            self.assertEqual(sorted(suites_on_marker), expected,
                             f"completion marker must name all suites on the single marker line: {passed_lines[0]}")
        finally:
            probe_a.unlink(missing_ok=True)
            probe_b.unlink(missing_ok=True)

    def test_fast_gate_execution_reports_failed_terminal_signal_even_with_no_test_output(self):
        """P2 fix (agents-ltgl): tools/fast-gate.sh must leave a terminal signal naming the failure and exit code
        even when tests exit with no output at all (e.g. os._exit)."""
        probe = ROOT / "tests" / "test_abort_probe_tmp.py"
        try:
            probe.write_text("import os\nos._exit(1)\n", encoding="utf-8")
            env = os.environ.copy()
            env["GIT_CHANGED"] = "tests/test_abort_probe_tmp.py"
            res = subprocess.run(["bash", str(FAST_GATE)], cwd=ROOT, env=env, capture_output=True, text=True)
            self.assertEqual(res.returncode, 1, f"expected rc 1, got {res.returncode}")
            self.assertIn("fast-gate: failed: exit 1 (modules: tests.test_abort_probe_tmp tests.test_coverage_contract tests.test_direct_run_completeness tests.test_fast_gate_consumer_coverage tests.test_tree_guards)", res.stderr)
        finally:
            probe.unlink(missing_ok=True)

    def test_fast_gate_pre_runner_failure_emits_aborted_marker_with_stage(self):
        """agents-adhc: a failure occurring before the test runner starts (e.g. unmatched changed path)
        must emit a fail-visible 'fast-gate: aborted:' line naming the exit code and stage."""
        env = os.environ.copy()
        env["GIT_CHANGED"] = "nonexistent_unmatched_file.xyz"
        env.pop("FAST_GATE_DRY_RUN", None)
        res = subprocess.run(["bash", str(FAST_GATE)], cwd=ROOT, env=env, capture_output=True, text=True)
        self.assertEqual(res.returncode, 1)
        self.assertIn("fast-gate: aborted: exit 1 (stage: checking unmapped files)", res.stderr)

    def test_fast_gate_sigterm_emits_aborted_marker_with_stage(self):
        """agents-adhc: an external SIGTERM signal must emit a fail-visible 'fast-gate: aborted:' line
        naming the signal and stage."""
        import signal, time
        probe = ROOT / "tests" / "test_sleep_probe_tmp.py"
        try:
            probe.write_text("import unittest, time\nclass _S(unittest.TestCase):\n    def test_sleep(self): time.sleep(10)\n", encoding="utf-8")
            env = os.environ.copy()
            env["GIT_CHANGED"] = "tests/test_sleep_probe_tmp.py"
            env.pop("FAST_GATE_DRY_RUN", None)
            p = subprocess.Popen(["bash", str(FAST_GATE)], cwd=ROOT, env=env,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                 start_new_session=True)
            time.sleep(0.3)
            os.killpg(p.pid, signal.SIGTERM)
            _, stderr = p.communicate()
            self.assertIn("fast-gate: aborted: caught SIGTERM (stage: running tests (tests.test_coverage_contract tests.test_direct_run_completeness tests.test_fast_gate_consumer_coverage tests.test_sleep_probe_tmp tests.test_tree_guards))", stderr)
        finally:
            probe.unlink(missing_ok=True)


class TestReplacedGenericArmsKeepTheirNamesake(unittest.TestCase):
    """agents-iqyz: an arm that REPLACES the generic lib/*.py arm can pass while DROPPING the module's
    own suite - that is the silent failure direction of this change, because the replacement still maps
    consumers and so nothing looks wrong.

    The expected sets below are the MEASURED selection for each path (dry run, GIT_CHANGED=<path>), not
    a hand count: the namesake first, then the other families' suites that import the module. Asserted as
    a SUPERSET so that adding a consumer is allowed and dropping one is not.
    """

    CASES = {
        "lib/embargo.py": {
            "namesake": "tests/test_embargo.py",
            "expected": ['tests/test_embargo.py', 'tests/test_factory_truth.py', 'tests/test_model_rule_id.py', 'tests/test_report_schema.py', 'tests/test_threat_model_prepass.py', 'tests/test_tree_guards.py'],
        },
        "lib/redaction.py": {
            "namesake": "tests/test_redaction.py",
            "expected": ['tests/test_findings.py', 'tests/test_model_rule_id.py', 'tests/test_redaction.py', 'tests/test_secret_scanner.py', 'tests/test_tree_guards.py', 'tests/test_vuln_verify_prepass.py'],
        },
        "lib/retention.py": {
            "namesake": "tests/test_retention.py",
            "expected": ['tests/test_hillclimb.py', 'tests/test_retention.py', 'tests/test_tree_guards.py'],
        },
    }

    def test_each_replaced_arm_still_selects_its_namesake_and_its_consumers(self):
        for path, info in self.CASES.items():
            with self.subTest(path=path):
                proc = subprocess.run(
                    ["bash", "tools/fast-gate.sh"], cwd=ROOT, capture_output=True, text=True,
                    env={**os.environ, "GIT_CHANGED": path, "FAST_GATE_DRY_RUN": "1"}, timeout=120,
                )
                out = proc.stdout + proc.stderr
                selected = {ln.strip() for ln in out.splitlines()
                            if ln.strip().startswith("tests/") and ln.strip().endswith(".py")}
                self.assertIn(
                    info["namesake"], selected,
                    f"{path}: the replaced arm DROPS the module's own suite {info['namesake']} - the arm "
                    "must name the namesake as well as its consumers (agents-iqyz)",
                )
                missing = sorted(set(info["expected"]) - selected)
                self.assertEqual(
                    missing, [],
                    f"{path}: the arm no longer selects {missing} - a replaced arm must keep the "
                    "namesake and every consumer it was added for (agents-iqyz)",
                )

if __name__ == "__main__":
    unittest.main()
