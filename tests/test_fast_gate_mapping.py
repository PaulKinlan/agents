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
import fnmatch
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests import has_git_index, tracked_paths

ROOT = Path(__file__).resolve().parent.parent
FAST_GATE = ROOT / "tools" / "fast-gate.sh"
# The arm registry is a DIRECTORY of fragments since agents-hr6q (ADR 0002): the mapping used to be one
# `case` table inside tools/fast-gate.sh, and it was the file every delivery that needed a mapping had to
# edit. Anything that wants to read the arms - including the pins below that ask whether a module has an
# arm of its own - must read the registry, not the script.
ARMS_DIR = ROOT / "tools" / "fast-gate-arms.d"
# THE ONE DEAD ARM, NAMED RATHER THAN TOLERATED (agents-v8xv's obligation is that a dead arm is REPORTED).
# `findings/*.md` matches no tracked file today: it covers a class that must be ignored the moment one is
# committed, so it is kept deliberately and listed here with its reason. Anything else that stops matching
# a tracked path is a real defect and fails the pin below.
DEAD_ARM_EXCEPTIONS = {"findings/*.md"}


def arm_registry_figures(tracked_paths: list[str] | None = None) -> dict:
    """THE PROOF'S DENOMINATORS, DERIVED FROM THE ARTEFACT (agents-exmy).

    The evidence for fragmenting the arm table was reported as "a representative path of EVERY pattern
    (81 paths)". Counted against the object, the base table has 79 pattern arms and 81 was the POST-CHANGE
    count - a number that described one artefact while claiming to describe another. The lesson is that a
    count describing an artefact must be derived from it, and `arm_patterns()` is the artefact's own parser;
    so the denominators are computed here, and anyone can print them with one command:

        python3 -c "from tests.test_fast_gate_mapping import arm_registry_figures as f; print(f())"

    WHAT EACH FIGURE MEANS: patterns (the registry's arms), live (arms with a representative TRACKED path),
    dead (arms with none - each must be named in DEAD_ARM_EXCEPTIONS with its reason), and representative
    (the self-derived path set an equivalence proof can use, one tracked path per live arm, instead of a
    list written by hand). A representative must REACH its arm under the loader's first-match precedence
    (agents-1j3z): an arm whose matching paths are all claimed by an earlier arm is reported as shadowed.. The "N identical" figure belongs to the before/after procedure and is not
    derivable here; what is derivable - and what was wrong before - is the denominator it divides by.
    """
    if tracked_paths is None:
        tracked_paths = subprocess.run(["git", "-C", str(ROOT), "ls-files"],
                                       capture_output=True, text=True, check=True).stdout.split()
    patterns = arm_patterns()

    def first_match_arm(path: str) -> str | None:
        """The arm that ANSWERS this path, which is the first one that matches it (the loader's rule)."""
        for pattern in patterns:
            # A pattern line can carry alternatives (`README.md|AGENTS.md|...`), which `case` reads as
            # alternation, so a line matches if ANY alternative does.
            if any(fnmatch.fnmatchcase(path, alt) for alt in pattern.split("|")):
                return pattern
        return None

    def matches_any_PATH(pattern: str) -> bool:
        return any(any(fnmatch.fnmatchcase(path, alt) for alt in pattern.split("|"))
                   for path in tracked_paths)

    representative, dead, shadowed = {}, [], []
    for pattern in patterns:
        # agents-1j3z: "a path that matches this pattern" is NOT "a path that reaches this arm". The gate
        # resolves a path through the FIRST arm that matches it, so a representative is only a
        # representative if that arm answers it - otherwise the proof exercises the earlier arm and the
        # count of distinct paths falls short of the count of arms (measured: 79 distinct for 81 live arms,
        # with lib/*.py answered by lib/bench/*.py). An arm whose every matching path is claimed earlier is
        # SHADOWED: reported as its own class rather than counted as proven or written off as dead.
        hit = next((path for path in tracked_paths if first_match_arm(path) == pattern), None)
        if hit:
            representative[pattern] = hit
        elif matches_any_PATH(pattern):
            shadowed.append(pattern)
        else:
            dead.append(pattern)
    return {
        "patterns": len(patterns),
        "live": len(representative),
        "dead": sorted(dead),
        "shadowed": sorted(shadowed),
        "declared_dead": sorted(DEAD_ARM_EXCEPTIONS),
        "representative": representative,
        "tracked_paths": len(tracked_paths),
    }


def tracked_arm_fragments(root=None):
    """The TRACKED *.sh fragments of the fast-gate arm registry, in filename order.

    agents-ncue: the registry directory is not a frozen set during a run. The readers here globbed it, so
    an untracked fragment widened what they describe - measured, the arm count went 33 -> 34 - and that is
    worse than a cosmetic difference, because tools/fast-gate.sh SOURCES every *.sh it finds (agents-es0y),
    so an untracked fragment is code the gate executes. Enumerating git's index is the same set the gate
    witnesses, so a reader and the loader can no longer disagree about what the registry contains.
    """
    root = root or ROOT
    if has_git_index(root):
        arms_dir = root / "tools" / "fast-gate-arms.d"
        # tracked_paths takes a GIT PATHSPEC, in which `*` crosses `/`, so ask for the directory and keep
        # direct children: a nested path must not be mistaken for a fragment (measured in agents-37rj).
        return sorted(p for p in tracked_paths("tools/fast-gate-arms.d", root=root)
                      if p.suffix == ".sh" and len(p.relative_to(arms_dir).parts) == 1)
    # A SYNTHETIC root built by a fixture is not inside a work tree, so there is no index to ask and the
    # filesystem is then the WHOLE tree rather than a second, wider notion of it (see has_git_index).
    return sorted((root / "tools" / "fast-gate-arms.d").glob("*.sh"))


def arm_registry_text() -> str:
    """Every arm fragment, concatenated - the table the script used to hold."""
    fragments = tracked_arm_fragments()
    assert fragments, f"no arm fragments in {ARMS_DIR}: the registry cannot be empty"
    return "\n".join(path.read_text(encoding="utf-8") for path in fragments)


def arm_patterns() -> list[str]:
    """The patterns the registry declares, scanned the way tools/fast-gate.sh scans them: at exactly four
    spaces of indent, both the `<pattern>)` and the `<pattern>) body ;;` shapes, and never the loader's
    no-match fallback (which carries its own marker comment, because `*)` is also a real arm here)."""
    patterns = []
    for line in arm_registry_text().split("\n"):
        if "no arm in this fragment matched" in line:
            continue
        match = re.match(r"^    ([^ #)][^)]*)\)(\s.*)?$", line)
        if match:
            patterns.append(match.group(1))
    return patterns
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

    PROBE_GLOB = "test_*_probe_tmp.py"

    @staticmethod
    def clear_probe_leftovers():
        """Remove scratch suites a KILLED run left behind, and report what was removed (agents-xawg).

        The probe tests below write a scratch suite into tests/ because the gate has to RUN it, and they
        remove it in a `finally`. A `finally` does not run when the process is KILLED, and the fast gate's
        runner does kill suites on its bound - tests/test_fast_gate_mapping.py has a test for exactly that
        SIGTERM path. The leftover is a VALID unittest module in tests/, it is untracked (so the gate does
        not witness it), and lanes commit with `git add -A` - this was found when one nearly landed. So the
        leak is self-healing on the next run of this class, and .gitignore carries the load-bearing half:
        the pattern cannot be committed even between runs.
        """
        removed = []
        for leftover in sorted((ROOT / "tests").glob(TestFastGateMapping.PROBE_GLOB)):
            leftover.unlink()
            removed.append(leftover.name)
        return removed

    @classmethod
    def setUpClass(cls):
        cls.probe_leftovers_cleared = cls.clear_probe_leftovers()

    def test_a_killed_run_cannot_leave_a_committable_probe(self):
        """agents-xawg, both halves, each measured rather than asserted.

        (1) THE HAZARD IS CLOSED: a leaked probe is an ignored path, so `git add -A` cannot land it. Driven
        through git itself rather than by reading .gitignore, because the rule is only as good as git's
        opinion of it.
        (2) THE LEAK IS SELF-HEALING: a file a killed run left is removed by the next run of this class,
        which is the cleanup setUpClass calls.
        """
        probe = "tests/test_pass_probe_tmp.py"
        res = subprocess.run(["git", "check-ignore", "-q", "--no-index", probe], cwd=ROOT,
                             capture_output=True, text=True)
        self.assertEqual(res.returncode, 0,
                         f"{probe} must be IGNORED: a probe left by a killed run is a valid test file in "
                         f"tests/, it is untracked (so the gate never witnesses it), and lanes commit with "
                         f"`git add -A` (agents-xawg)")
        leftover = ROOT / "tests" / "test_leaked_probe_tmp.py"
        leftover.write_text("import unittest\nclass _L(unittest.TestCase):\n    def test_ok(self): pass\n",
                            encoding="utf-8")
        try:
            self.assertIn("test_leaked_probe_tmp.py", self.clear_probe_leftovers(),
                          "a leftover from a killed run must be reported as removed")
            self.assertFalse(leftover.exists(), "the leftover must be gone after the cleanup runs")
        finally:
            leftover.unlink(missing_ok=True)

    def test_findings_py_maps_to_security_and_suppression_contracts(self):
        """lib/findings.py must run redaction (security), suppressions (register) and the store's own
        consumer expectations (the candidate-identity index/rekey counts)."""
        mapped = resolve_fast_gate(["lib/findings.py"])
        self.assertIn("tests/test_findings.py", mapped)
        self.assertIn("tests/test_sinks.py", mapped)
        self.assertIn("tests/test_redaction.py", mapped, "redaction contract omitted (agents-q0mt)")
        self.assertIn("tests/test_suppressions.py", mapped, "suppressions contract omitted (agents-vt7w)")
        self.assertIn("tests/test_candidate_identity.py", mapped,
                      "findings-store index expectations omitted (agents-l606, agents-ozmt)")

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

    def test_github_sink_maps_promote_store_lock_without_taxing_other_sinks(self):
        """agents-5jjf: github's promote lock is tested outside the generic sink suite."""
        github = resolve_fast_gate(["lib/sinks/github.py"])
        generic = resolve_fast_gate(["lib/sinks/base.py"])
        self.assertTrue(set(generic).issubset(github), "github must retain the generic sink contracts")
        self.assertIn("tests/test_store_lock_timeout.py", github,
                      "github's promote/store-lock consumer is missing from the fast gate")
        for name in ("base.py", "beads.py", "command.py", "file.py", "github_issues.py"):
            with self.subTest(sink=name):
                mapped = resolve_fast_gate([f"lib/sinks/{name}"])
                self.assertNotIn("tests/test_store_lock_timeout.py", mapped,
                                 "the 19s store-lock suite must not tax other sink edits")

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
        split unlandable. A harness change reaches every inherited execution, so the arm names every
        module that inherits it, plus the shape test that catches a test method creeping into the
        harness. agents-ryw9 carried TestDispatcher's 49 non-admission tests into six more such
        modules, so this list is longer by those six - the pin is what makes the next split name
        them, which is the failure it was written for."""
        mapped = resolve_fast_gate(["tests/containment_harness.py"])
        for module in (
            "tests/test_containment.py",
            "tests/test_containment_declarations.py",
            "tests/test_containment_adapters.py",
            "tests/test_containment_engine_credentials.py",
            "tests/test_containment_prepass_pins.py",
            "tests/test_containment_egress.py",
            "tests/test_containment_shape.py",
            "tests/test_containment_broker.py",
            "tests/test_containment_confinement.py",
            "tests/test_containment_hardening.py",
            "tests/test_containment_run_isolation.py",
            "tests/test_containment_session_patch.py",
            "tests/test_containment_write_grants.py",
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
        # agents-fnko (P2, found by rev-ryw9's second verdict): a SPLIT that leaves this arm stale loses
        # tests, and the full gate cannot see it - the full gate discovers the whole tree, so only a pin
        # like this one can catch a per-arm selection regression. These tests used to ride along inside
        # tests/test_containment.py, which this arm names. Which modules go red under a broken pi.sh
        # engine-binary exec is MEASURED, not inferred: all six new dispatcher modules, plus 3 of the 4
        # in tests/test_containment_egress.py (the three egress tests that moved there).
        for module in (
            "tests/test_containment_confinement.py",
            "tests/test_containment_run_isolation.py",
            "tests/test_containment_write_grants.py",
            "tests/test_containment_session_patch.py",
            "tests/test_containment_hardening.py",
            "tests/test_containment_broker.py",
            "tests/test_containment_egress.py",
        ):
            self.assertIn(module, mapped,
                          f"pi.sh arm must run {module} (agents-fnko: tests that depend on pi.sh moved out "
                          "of tests/test_containment.py into it, and the full gate cannot see the loss)")

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
        """A changed file matching neither a mapping arm nor the ignore list must fail and name itself.

        agents-l80j: the fixture paths are `targets/README.md` (walked markdown, deliberately loud -
        see test_walked_but_unpinned_markdown_fails_loudly) and `package.json`. The second used to be
        `.agents/skills/beads/SKILL.md`, which is now covered by a documented ignore arm, so what is
        pinned here is the BEHAVIOUR (loud failure that names the file) rather than that one path.
        """
        for path in ("package.json", "targets/README.md"):
            with self.subTest(path=path):
                res = run_fast_gate([path])
                self.assertNotEqual(res.returncode, 0, f"{path}: unmatched file must fail loudly (agents-9nir)")
                self.assertIn(path, res.stderr, f"{path}: the failure must name the unmatched file (agents-9nir)")
                self.assertIn("no mapping arm", res.stderr)

    def test_unmatched_gate_config_path_refuses_loudly_with_actionable_guidance(self):
        """agents-ows4, agents-dtj6, agents-iwm5: a new/unmatched gate or provisioning config path must fail loudly,
        identifying the path, explaining that it is gate/provisioning config, pointing directly
        to tools/fast-gate.sh, and recommending relevant test suites so the fix is an immediate edit.
        The cited ignore-list section marker must actually exist as a heading in the arm registry (agents-iwm5,
        agents-hr6q: the heading moved with the arms into tools/fast-gate-arms.d/)."""
        # agents-hr6q: the cited ignore-list heading moved into the registry with the arms, so that is
        # where it has to be found - asserting against tools/fast-gate.sh alone would now fail on a
        # correct tree, and (worse) a heading asserted only in the script could not be cited from a
        # fragment that actually holds the arm.
        fast_gate_content = arm_registry_text()
        for path in ("tools/new_gate.conf", "tools/custom-gate.sh"):
            with self.subTest(path=path):
                res = run_fast_gate([path])
                self.assertNotEqual(res.returncode, 0, f"{path} must fail loudly")
                self.assertIn(path, res.stderr, f"{path} must be named in the error")
                self.assertIn("gate/provisioning config", res.stderr)
                self.assertIn("tools/fast-gate-arms.d/", res.stderr,
                              "the fix must name the registry the arm belongs in, not only the script")
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
                                f"the cited section {cited_header!r} must actually exist as an anchored "
                                "heading line in the arm registry")

    def test_unmatched_file_fails_even_when_other_files_map(self):
        """A mapped sibling must not mask the unmatched file (the no-fallback hole, agents-9nir)."""
        res = run_fast_gate(["lib/sandbox.py", "targets/README.md"])
        self.assertNotEqual(res.returncode, 0, "unmatched file masked by a mapped sibling (agents-9nir)")
        self.assertIn("targets/README.md", res.stderr, "the failure must name the unmatched file")
        self.assertNotIn("lib/sandbox.py", res.stderr, "the mapped file must not be named as unmatched")

    def test_agent_config_and_data_paths_are_claimed_or_deliberately_loud(self):
        """agents-l80j: of the nine tracked paths that no arm claimed, seven are now claimed - six by a
        documented ignore arm and one (the modern-web guidance catalogue) by a real suite mapping -
        while the two whose loud failure is DELIBERATE keep failing.

        DISCRIMINATOR: on the revision before this change all seven aborted with "match no mapping
        arm and no ignore-list arm", so this test is red against the revision it replaces rather
        than being a pin born green.
        """
        claimed_without_a_suite = (
            ".agents/skills/beads/SKILL.md",
            ".agents/skills/beads/agents/openai.yaml",
            ".claude/settings.json",
            ".codex/config.toml",
            ".codex/hooks.json",
            "skills",
        )
        for path in claimed_without_a_suite:
            with self.subTest(path=path):
                res = run_fast_gate([path])
                self.assertEqual(res.returncode, 0,
                                 f"{path}: must not abort the gate (agents-l80j)\n{res.stderr}")
                self.assertNotIn("no mapping arm", res.stderr, f"{path}: still reads as unmapped")

        # The catalogue is this station's DEFAULT input, so the station's own suite must run for it.
        catalogue = "agents/modern-web/scripts/guides_index.json"
        mapped = resolve_fast_gate([catalogue])
        self.assertIn("tests/test_modern_web.py", mapped,
                      f"{catalogue} is loaded by default at scan_modern_web.py:60, so the suite that "
                      "loads the catalogue (tests/test_modern_web.py:515-519) must be selected")
        self.assertIn("tests/test_factory_core.py", mapped,
                      f"{catalogue} is asserted against all 146 guides at "
                      "tests/test_factory_core.py:1029, so a lost guide must be able to fail the gate")

        # Deliberate loud failures stay loud: walked markdown (agents-9nir P0) and the npm manifest,
        # which no suite reads (searched repo-wide; the gate's own suites use their own fixtures).
        for path in ("package.json", "targets/README.md"):
            with self.subTest(path=path):
                res = run_fast_gate([path])
                self.assertNotEqual(res.returncode, 0,
                                    f"{path}: deliberate loud failure must not be silenced (agents-9nir)")
                self.assertIn(path, res.stderr, f"{path}: the refusal must name the file")

        # agents-dxtx (rev-l80j, P2): the exemption above is per-FILE, so a path that appears in an
        # exempted directory LATER must still be loud. DISCRIMINATOR for that finding: with the earlier
        # `.codex/*` pattern these paths resolved silently (rc 0, empty suite list) rather than being
        # refused, so this test is red against the revision the finding describes.
        for path in (".codex/unreviewed.sh", ".codex/new_helper.py"):
            with self.subTest(path=path):
                res = run_fast_gate([path])
                self.assertNotEqual(res.returncode, 0,
                                    f"{path}: a new file in an exempt directory must NOT be exempt "
                                    "(agents-dxtx - the exemption is per file, not per directory)")
                self.assertIn(path, res.stderr, f"{path}: the refusal must name the file")

    def test_beads_exemption_is_per_file_not_per_directory(self):
        """agents-3jb4: the `.beads/` ignore arm is a DIRECTORY that holds executable git hooks, so an
        exemption written as `.beads/*` silences every future file there instead of naming the ten tracked
        paths the search measured. Both halves are asserted: each tracked path stays exempt, and a path that
        is not tracked is refused by name. Red against the broad pattern (rc 0, empty suite list)."""
        tracked = subprocess.check_output(["git", "ls-files", ".beads/"], text=True).split()
        self.assertTrue(tracked, "the tracked .beads/ paths are the object this exemption is written for")
        for path in tracked:
            with self.subTest(tracked=path):
                self.assertEqual(run_fast_gate([path]).returncode, 0,
                                 f"{path}: a TRACKED .beads/ path is the measured exemption and stays exempt")
        for path in (".beads/unexpected.sh", ".beads/scripts/evil.py"):
            with self.subTest(new=path):
                res = run_fast_gate([path])
                self.assertNotEqual(res.returncode, 0,
                                    f"{path}: a new file under .beads/ must NOT be exempt "
                                    "(agents-3jb4 - the exemption is per file, not per directory)")
                self.assertIn(path, res.stderr, f"{path}: the refusal must name the file")

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
        must hold no local decoy .beads database.
        TestStagedRuntimeCarriesItsImports (agents-o7e2) enforces a repo-wide tree property too: every
        test staging list in tests/ must copy the modules the runtime it builds imports at module scope,
        read from the source rather than enumerated. It belongs in this tier and not in a unit suite
        because the property is about the tree as a whole - a new import in lib/findings.py makes OTHER
        files wrong, and the change that broke five of them touched none of them."""
        tree_guards_path = ROOT / "tests" / "test_tree_guards.py"
        self.assertTrue(tree_guards_path.is_file(), "tests/test_tree_guards.py must exist")
        import ast
        tree = ast.parse(tree_guards_path.read_text(encoding="utf-8"))
        classes = [node.name for node in tree.body if isinstance(node, ast.ClassDef)]
        self.assertEqual(classes, ["TestNoUnboundedSubprocess", "TestWorktreeBeadsDecoyGuard",
                                   "TestStagedRuntimeCarriesItsImports"],
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

    @staticmethod
    def _dispatched_modules(gate_output: str) -> list[str]:
        """The modules THIS run dispatched, read from the summary header tools/fast-gate.sh writes.

        The header is written before the runner starts (`cwd=<dir> modules=<space-separated>`), so it is the
        run's own record of what it meant to execute rather than a second copy of the marker under test.
        """
        m = re.search(r"fast-gate: runner output -> (\S+)", gate_output)
        if not m:
            return []
        header = Path(m.group(1)).read_text(encoding="utf-8", errors="replace").splitlines()
        for line in header:
            if line.startswith("cwd=") and " modules=" in line:
                return line.split(" modules=", 1)[1].split()
        return []

    def test_fast_gate_execution_reports_failed_terminal_signal_even_with_no_test_output(self):
        """P2 fix (agents-ltgl): tools/fast-gate.sh must leave a terminal signal naming the failure and exit code
        even when tests exit with no output at all (e.g. os._exit).

        agents-lgdv: AND THE SIGNAL'S PAYLOAD MUST BE THE SUITES IT NAMES. The coverage reader takes every
        whitespace token after `fast-gate: failed:` as a suite name - that is the vocabulary in fleet's
        remote/check-coverage.py, pinned on its own side by tests/check-coverage.test.sh:161
        (`fast-gate: failed: tests/thing_test.ts`). The old payload `exit $rc (modules: ...)` therefore
        published `exit`, `1` and `modules:` as three phantom suites ahead of the real module names: a fast
        gate record held 13 entries for a 10-module run. The assertion below is against the run's OWN
        dispatch set, so it pins the contract rather than the current string.
        """
        probe = ROOT / "tests" / "test_abort_probe_tmp.py"
        try:
            probe.write_text("import os\nos._exit(1)\n", encoding="utf-8")
            env = os.environ.copy()
            env["GIT_CHANGED"] = "tests/test_abort_probe_tmp.py"
            res = subprocess.run(["bash", str(FAST_GATE)], cwd=ROOT, env=env, capture_output=True, text=True)
            self.assertEqual(res.returncode, 1, f"expected rc 1, got {res.returncode}")
            failed_lines = [l for l in res.stderr.splitlines() if l.startswith("fast-gate: failed:")]
            self.assertEqual(len(failed_lines), 1, f"expected exactly one failed marker, got: {failed_lines}")
            payload = failed_lines[0].replace("fast-gate: failed:", "").split()
            dispatched = self._dispatched_modules(res.stderr)
            self.assertTrue(dispatched,
                            "could not read the dispatch set from this run's own summary header "
                            "(`cwd=... modules=...`), so the payload assertion below cannot be made")
            self.assertEqual(sorted(payload), sorted(dispatched),
                             f"the failed marker must name exactly the modules that ran: {failed_lines[0]}")
            # The three phantoms the bead measured, named so the regression is legible.
            for phantom in ("exit", "modules:", "1"):
                self.assertNotIn(phantom, payload,
                                 f"a marker payload is the suite list; {phantom!r} is prose that the "
                                 f"coverage reader counts as a suite")
            # The exit code is a real fact and is published - just not inside the list position (agents-lgdv).
            self.assertIn("fast-gate: exit 1", res.stderr)
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

    def test_a_space_separated_changed_list_is_named_as_a_format_error_not_as_an_arm_gap(self):
        """agents-dtml: `GIT_CHANGED="$a $b"` is the obvious way to build the variable by hand or from a
        shell list, and GIT_CHANGED is read ONE PATH PER LINE (the shape `git diff --name-only`
        prints), so the whole line arrives as a single path and matches no arm.

        The failure that used to come out was the generic 'match no mapping arm' abort - which sends the
        reader to tools/fast-gate.sh's arm table, measured by agents-hr6q as edited by 20.2% of all
        landings, to add arms for paths that ALREADY HAVE THEM (each of the three resolves to its own
        suite on its own line). The abort must still fail closed; it must also name the input shape,
        and name it BEFORE the arm-table instruction so a reader stops at the right sentence.
        """
        joined = " ".join(["lib/tool_pins.py", "lib/findings.py", "docs/INTEGRATION.md"])
        res = run_fast_gate([joined])
        self.assertEqual(res.returncode, 1, "fail-closed is not negotiable: a space-separated list must never be accepted")
        self.assertIn("NOTE (agents-dtml)", res.stderr, "the abort must name the space-separated shape")
        self.assertIn("ONE PATH PER LINE", res.stderr, "and must state the format GIT_CHANGED is read in")
        self.assertIn("printf", res.stderr, "and show the accepted form, not just describe it")
        self.assertIn("never split", res.stderr, "a path MAY contain spaces, so the gate reports and does not split")
        self.assertLess(
            res.stderr.index("NOTE (agents-dtml)"),
            res.stderr.index("To fix, add an arm fragment"),
            "the note must come BEFORE the arm-table instruction, or it does not stop the misdirection it exists for",
        )

    def test_the_space_separated_note_does_not_fire_on_a_single_path_with_spaces(self):
        """agents-dtml, the half that makes the note safe to read: it is a DISCRIMINATOR, not a parser.

        Two shapes must stay silent, and both are ordinary: (a) one path that exists and contains
        spaces - the whole line IS a path, so there is no list to report; (b) a nonexistent path whose
        tokens are not paths either - guessing a list from the presence of whitespace alone would fire
        on any typo and teach readers to ignore the note.
        """
        # (agents-ug3a) This probe cannot move to a scratch repo in /tmp like its siblings: the path has to
        # EXIST from the gate's point of view and stay repo-RELATIVE, because that is the shape a changed-file
        # list really has, and moving it would test a different input. It lives under a path .gitignore
        # already covers instead - at the checkout root a killed run left a committable temp directory, and
        # there is no `tmp*/` root ignore rule. The check-ignore assertion below is the property that makes
        # the relocation a fix rather than a relocation.
        scratch = ROOT / ".agent-state"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as tmp:
            spaced = Path(tmp) / "a path with spaces.xyz"
            spaced.write_text("", encoding="utf-8")
            rel = str(spaced.relative_to(ROOT))
            self.assertEqual(
                subprocess.run(["git", "-C", str(ROOT), "check-ignore", "-q", rel]).returncode, 0,
                "an interrupted probe must not leave COMMITTABLE debris under the checkout")
            exists = run_fast_gate([rel])
            self.assertEqual(exists.returncode, 1, "an unmatched path is still fail-closed")
            self.assertNotIn("NOTE (agents-dtml)", exists.stderr, "a single path that exists is not a list")
        absent = run_fast_gate(["no such file.xyz"])
        self.assertEqual(absent.returncode, 1)
        self.assertNotIn("NOTE (agents-dtml)", absent.stderr,
                         "whitespace alone is not evidence of a list: the tokens must look like paths")

    def test_fast_gate_sigterm_emits_aborted_marker_with_stage(self):
        """agents-adhc: an external SIGTERM signal must emit a fail-visible 'fast-gate: aborted:' line
naming the signal and stage.

agents-ob1x: THE STAGE IS WAITED FOR, NOT RACED. This used to start the gate, wait a FIXED 0.3s and
then signal it, while the assertIn below demands the emitter already be in the "running tests" stage.
Measured on this VM the gate prints its "running:" stage line at 0.208-0.265s across four runs and at
0.51s on a fifth, so the 0.3s window is not merely tight - it is sometimes already exceeded before the
signal is sent, which is the flake that failed the full gate for union e71d73f at 2.5x contention. So
the gate's OWN stage announcement is the handshake: read its stdout until the "running: python3 -u -m
unittest ..." line appears, bounded, and signal only then. The assertion is unchanged; this removes the
race rather than weakening what is checked, and if the stage line never arrives the test fails loudly.
"""
        import selectors, signal, time
        probe = ROOT / "tests" / "test_sleep_probe_tmp.py"
        try:
            probe.write_text("import unittest, time\nclass _S(unittest.TestCase):\n    def test_sleep(self): time.sleep(10)\n", encoding="utf-8")
            env = os.environ.copy()
            env["GIT_CHANGED"] = "tests/test_sleep_probe_tmp.py"
            env.pop("FAST_GATE_DRY_RUN", None)
            p = subprocess.Popen(["bash", str(FAST_GATE)], cwd=ROOT, env=env,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                 start_new_session=True)
            sel = selectors.DefaultSelector()
            sel.register(p.stdout, selectors.EVENT_READ)
            entered = False
            deadline = time.monotonic() + 60
            while not entered and time.monotonic() < deadline and p.poll() is None:
                for key, _ in sel.select(timeout=1.0):
                    if "running:" in key.fileobj.readline():
                        entered = True
                        break
            self.assertTrue(
                entered,
                "the gate never reached its 'running:' stage within 60s, so the SIGTERM stage assertion "
                "cannot be made (agents-ob1x). Not a silent timeout: the gate either failed to start or "
                "never announced the runner; on the old fixed-sleep form this condition surfaced as a "
                "mid-flight stage name instead.",
            )
            os.killpg(p.pid, signal.SIGTERM)
            _, stderr = p.communicate()
            self.assertIn("fast-gate: aborted: caught SIGTERM (stage: running tests (tests.test_coverage_contract tests.test_direct_run_completeness tests.test_fast_gate_consumer_coverage tests.test_sleep_probe_tmp tests.test_tree_guards))", stderr)
        finally:
            probe.unlink(missing_ok=True)


class TestRepoWideInvariantsAreKeyedOnTheChangedPathClass(unittest.TestCase):
    """agents-wsiv: the retention inventory is a REPO-WIDE invariant, and a per-path arm cannot add a suite to a
    path another arm already claims, because arms are first-match-wins - the measured case is agents-ssyq's tool,
    which HAD its own exact-path arm at 300 and never ran the inventory (an unenumerated rm -rf in it passed the
    fast gate on two tips and was caught only by the full gate at merge). Claiming tools/*.sh in the registry
    instead is worse, because it silences the loud unmatched failure for that directory - which is why the
    dispatch keys this on the changed path's CLASS. Every selection below is MEASURED from a dry run.
    """

    SELECTED = (
        "tools/red-first.sh",             # the class the measured failure came from
        "install.sh",                     # a shell script outside tests/, which no arm's path can reach
    )
    NOT_SELECTED = (
        "docs/css/factory.css",           # mapped and outside every scanned class
        "tests/some_runner.sh",           # a shell script INSIDE tests/, which the inventory does not scan
        "lib/egress_proxy.py",            # a lib/ change the inventory's own suite does NOT import (agents-6vev)
        "README.md",
    )

    def _selected(self, path: str) -> set:
        proc = run_fast_gate([path])
        out = proc.stdout + proc.stderr
        return {ln.strip() for ln in out.splitlines()
                if ln.strip().startswith("tests/") and ln.strip().endswith(".py")}

    def test_a_changed_path_in_a_scanned_class_selects_the_inventory(self):
        for path in self.SELECTED:
            with self.subTest(path=path):
                self.assertIn(
                    "tests/test_retention.py", self._selected(path),
                    f"{path} is in a class the inventory scans, so the inventory must run for it (agents-wsiv)",
                )

    def test_a_changed_path_outside_those_classes_does_not_pay_for_the_check(self):
        for path in self.NOT_SELECTED:
            with self.subTest(path=path):
                self.assertNotIn(
                    "tests/test_retention.py", self._selected(path),
                    f"{path} cannot violate the inventory, so its ~0.50s must not be paid on every change: "
                    "an always-on version of this check is a permanent tax on the fast gate for a rare class "
                    "of change",
                )

    def test_an_unclaimed_tools_script_still_fails_loudly(self):
        """The class key ADDS a suite; it does not CLAIM a path. A tools script the registry has no arm for must
        still fail closed with the actionable prompt, because that prompt is what tells the next author to write
        an arm - the property a blanket `tools/*.sh` registry arm would have destroyed, and the reason this fix
        keys on the class in the dispatch instead."""
        proc = run_fast_gate(["tools/any-new-script.sh"])
        self.assertNotEqual(
            proc.returncode, 0,
            "an unclaimed tools script must fail closed, not go green against the inventory alone",
        )
        self.assertIn(
            "tools/any-new-script.sh", proc.stderr + proc.stdout,
            "the loud failure must name the unmatched path",
        )

    def _declared(self, name: str) -> set:
        """Read a declared fact OUT OF tools/fast-gate.sh, so the two-fact split is declared in exactly ONE place
        and this suite cannot drift from it by restating it here."""
        script = (ROOT / "tools" / "fast-gate.sh").read_text(encoding="utf-8")
        m = re.search(rf'^{name}="([^"]+)"', script, re.M)
        self.assertIsNotNone(m, f"{name} is not declared in tools/fast-gate.sh - the facts must live there")
        return set(m.group(1).split())

    def test_the_coverage_fact_is_complete_against_the_inventorys_own_scanner(self):
        """(a) THE PINNED COVERAGE PROPERTY, RESTORED IN FULL. The coverage set says which paths COULD violate
        the invariant, so it must cover everything lib/retention.py actually scans. A first version of this
        change pointed the guard at the narrow selection set instead, which bought the gate by weakening this
        property - the trade coord's option (c) refuses, and the reason coverage and selection are now separate
        constants rather than one."""
        from tests.test_retention import _scanned_sources
        covered = self._declared("inventory_scanned_classes")
        undeclared = []
        for rel, _path in _scanned_sources(ROOT):
            top = rel.split("/", 1)[0] if "/" in rel else rel
            if top in covered:
                continue
            if rel.endswith(".sh") and not rel.startswith("tests/"):
                continue      # the script rule the dispatch applies to both sets
            undeclared.append(rel)
        self.assertEqual(
            undeclared, [],
            f"the inventory scans these paths and the COVERAGE set does not declare them: {undeclared}",
        )

    def test_the_selection_fact_is_a_subset_of_the_coverage_fact(self):
        """(b) The relationship between the two facts, asserted so it cannot be inverted again: SELECTION may
        narrow COVERAGE, never widen it. Widening would mean claiming a suite for paths the inventory does not
        even scan; collapsing them is the defect this split exists to remove."""
        selection = self._declared("inventory_selected_classes")
        coverage = self._declared("inventory_scanned_classes")
        self.assertTrue(
            selection <= coverage,
            f"selection {sorted(selection)} is not a subset of coverage {sorted(coverage)}",
        )

    def test_a_lib_change_is_covered_but_not_selected(self):
        """(c) The distinction as BEHAVIOUR, which is the whole point of the split: lib/egress_proxy.py is
        COVERED (the inventory scans lib/, so a change there could violate it) and NOT SELECTED (nothing imports
        it, so adding the suite would spend full-gate time on the fast path), while the shell scripts outside
        tests/ are BOTH."""
        coverage = self._declared("inventory_scanned_classes")
        selection = self._declared("inventory_selected_classes")
        self.assertIn("lib", coverage, "the inventory scans lib/, so lib/ must appear in the coverage set")
        self.assertNotIn("lib", selection, "lib/ is covered but must NOT be selected (agents-6vev)")
        self.assertIn("tools", selection, "tools/ is the measured case and must stay selected")
        self.assertNotIn("tests/test_retention.py", self._selected("lib/egress_proxy.py"))
        self.assertIn("tests/test_retention.py", self._selected("tools/red-first.sh"))


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
            "expected": ['tests/test_embargo.py', 'tests/test_factory_truth.py', 'tests/test_model_rule_id.py', 'tests/test_report_schema.py', 'tests/test_threat_model_prepass.py', 'tests/test_station_candidate_accounting.py',
                                'tests/test_tree_guards.py'],
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

class TestArmRegistryIsAFragmentDirectory(unittest.TestCase):
    """agents-hr6q (ADR 0002 sections 2 and 4): the arm table is tools/fast-gate-arms.d/, one fragment per
    contiguous run of arms, and these are the properties the shape has to keep.

    WHY THE SHAPE WAS CHANGED AT ALL: the table was the most-collided artefact in the repository (144
    landings touched tools/fast-gate.sh, 40 both-sided, 84 of those changes appending one arm), so a
    delivery that only added a mapping still had to edit the gate every lane depends on. The acceptance
    recorded on agents-hr6q is an EQUIVALENCE PROOF (FAST_GATE_DRY_RUN=1 gives an identical suite set
    before and after for a representative path of every arm); what is pinned HERE is the part of the shape
    a future delivery can break silently - a second home for one pattern, a fragment that is sourced and
    never called, a dead arm, and a new arm that would need a second file edited.
    """

    def _run_gate_in_copy(self, changed: str, fragment: str | None = None) -> subprocess.CompletedProcess:
        """Run the REAL script from a COPY of itself plus its registry, so a probe fragment can be added
        without writing into the registry this repository ships. Returns the completed process."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "tools").mkdir()
            shutil.copy2(FAST_GATE, tmp / "tools" / "fast-gate.sh")
            shutil.copytree(ARMS_DIR, tmp / "tools" / "fast-gate-arms.d")
            if fragment is not None:
                (tmp / "tools" / "fast-gate-arms.d" / "999-zz-probe.sh").write_text(fragment, encoding="utf-8")
            env = os.environ.copy()
            env["GIT_CHANGED"] = changed
            env["FAST_GATE_DRY_RUN"] = "1"
            return subprocess.run(
                ["bash", str(tmp / "tools" / "fast-gate.sh")], cwd=str(tmp), env=env,
                capture_output=True, text=True,
            )

    @staticmethod
    def _probe(pattern: str, suite: str) -> str:
        """A fragment with one arm, in the shape the registry documents, so a probe differs from a real
        fragment only in what it computes."""
        return (
            "probe_arms() {\n"
            '  case "$1" in\n'
            f"    {pattern})\n"
            f'      mapped="$mapped {suite}"\n'
            "      ;;\n"
            "    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn\n"
            "  esac\n"
            "  return 0\n"
            "}\n"
            'FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES probe_arms"\n'
        )

    def test_the_arms_are_not_in_the_script_any_more(self):
        """The move is complete: the script no longer carries the table, it loads the registry. A
        half-move (arms in both places) is the state where a delivery cannot tell which file to edit."""
        script = FAST_GATE.read_text(encoding="utf-8")
        self.assertNotIn('case "$f" in', script,
                         "the arm table must not come back into tools/fast-gate.sh - it belongs in "
                         "tools/fast-gate-arms.d/ (ADR 0002)")
        self.assertIn("fast_gate_arms_load", script, "the script must load the registry")
        self.assertIn("fast-gate-arms.d", script)
        self.assertGreaterEqual(len(tracked_arm_fragments()), 20,
                                "the registry split the table into per-run fragments; a handful of files "
                                "would mean arms were merged back into a shared file")

    def test_a_new_arm_is_one_new_file_and_needs_nothing_else(self):
        """THE PROPERTY THE SPLIT EXISTS FOR (agents-hr6q acceptance, clause 3): a delivery that only adds
        a mapping adds ONE file. The probe declares its own stage and the loader picks it up with no edit
        to tools/fast-gate.sh and no edit to any fragment that already exists."""
        res = self._run_gate_in_copy("the-new-module.py", self._probe("the-new-module.py", "tests/test_the_new_module.py"))
        self.assertEqual(res.returncode, 0, f"a new fragment must be loaded: {res.stderr}")
        self.assertIn("tests/test_the_new_module.py", res.stdout.split())

    def test_a_changed_fragment_is_mapped_by_the_registrys_own_arm(self):
        """THE FAILURE MEASURED ON THIS CHANGE'S FIRST GATE RUN, pinned so it cannot come back: the
        registry's own files had no arm, so the gate refused all 29 fragments as unmapped - the loud
        failure doing its job, and a shape that would have been UNUSABLE, because every delivery that adds
        a mapping adds one of these files. A registry cannot cover the files that hold its arms unless the
        arm is there, so this drives the gate rather than reading for a string."""
        suites = resolve_fast_gate(["tools/fast-gate-arms.d/999-anything.sh"])
        self.assertIn("tests/test_fast_gate_mapping.py", suites,
                      "a changed arm fragment must select the suite that owns the mapping contract and the "
                      "fragment guards")
        for consumer in ("tests/test_fast_gate_consumer_coverage.py",
                         "tests/test_fast_gate_importer_boundaries.py",
                         "tests/test_coverage_contract.py"):
            self.assertIn(consumer, suites,
                          f"{consumer} reads the registry, so a changed fragment is a change to its subject")
        self.assertIn("tests/test_docs_drift.py", resolve_fast_gate(["tools/fast-gate-arms.d/README.md"]),
                      "the registry's README is committed markdown: docs_drift walks it, so it is mapped "
                      "rather than left to fail loudly")

    def test_an_unmatched_file_is_named_once_not_once_per_pass(self):
        """agents-ywb5: THE O(N^2) SHAPE HAS AN OBSERVABLE SIGNATURE, and this drives it rather than reading
        for it. The change that moved the arms into a fragment directory left the old loop header above the
        new loop, so the loader was redefined and re-run per changed path, the mapping loop re-read all N
        paths N times, and every unmatched file was named N times. MEASURED on the nested version: three
        unmatched paths printed each path THREE times, and a 40-path delta took 6.76s against 0.16s for one
        pass. A duplicate in the output is the cheap detector for the whole class, so it is pinned here -
        the reading-for-a-string half is the structural test below."""
        dupes = ["unmatched_alpha.xyz", "unmatched_beta.xyz", "unmatched_gamma.xyz"]
        res = run_fast_gate(dupes)
        self.assertNotEqual(res.returncode, 0, "three unmapped files must still fail the gate loudly")
        for path in dupes:
            self.assertEqual(res.stderr.count(path), 1,
                             f"{path} must be named exactly once: a count of N means the mapping loop ran N "
                             f"times over the same changed-file list (agents-ywb5)\n{res.stderr}")

    def test_the_registry_is_loaded_once_and_mapped_in_one_pass(self):
        """The structural half of agents-ywb5, because the duplicate-output signature above only fires for
        an UNMATCHED path. The shape itself is what matters: one loop over the delta, one loader call. Two
        `done <<< "$changed"` terminators is how the nested version announced itself."""
        script = FAST_GATE.read_text(encoding="utf-8")
        self.assertEqual(script.count('done <<< "$changed"'), 1,
                         "exactly one loop may consume the changed-file list (agents-ywb5)")
        self.assertEqual(script.count("while IFS= read -r f; do"), 1,
                         "the mapping loop must not be nested inside another read loop")
        self.assertEqual(script.count("fast_gate_arms_load || exit 1"), 1,
                         "the fragments must be loaded once per run, not once per changed path")

    def test_every_suite_named_in_the_registry_exists(self):
        """Fragment consistency (agents-t12i): a fragment naming a suite that does not exist would select
        nothing when its path changes, and the failure would appear only on that path's next change. The
        registry is read as text so a typo is caught by the mapping suite instead."""
        # COMMENTS ARE EXCLUDED, for the same reason the pattern scan excludes them: an arm's rationale
        # quotes example paths (one cites a deliberately nonexistent suite from a contract test), and a
        # prose quotation is not a reference the gate will try to run.
        code_lines = [line for line in arm_registry_text().split("\n") if not line.lstrip().startswith("#")]
        named = sorted(set(re.findall(r"(tests/[A-Za-z0-9_]+\.py)", "\n".join(code_lines))))
        self.assertGreaterEqual(len(named), 30, "the registry names far fewer suites than it should - scan broken?")
        missing = [suite for suite in named if not (ROOT / suite).is_file()]
        self.assertEqual(missing, [], f"the registry names suites that do not exist: {missing}")

    def test_a_duplicate_pattern_fails_rather_than_being_resolved_by_position(self):
        """agents-v8xv's obligation. Precedence is now carried by filenames, so an arm declared twice
        would be resolved silently by position - which is the accident this shape must not have. BOTH arm
        shapes are probed, because the guard scans the fragments' text: the loader's own no-match fallback
        is excluded by its marker comment (otherwise `*)`, a real arm in the ignore list, would collide
        with it and the guard would fail on a correct registry)."""
        shapes = {
            "pattern on its own line": (
                "    lib/sandbox.py)\n"
                '      mapped="$mapped tests/test_x.py"\n'
                "      ;;\n"
            ),
            "single-line arm": '    lib/sandbox.py) mapped="$mapped tests/test_x.py" ;;\n',
        }
        for label, arm_text in shapes.items():
            with self.subTest(arm_shape=label):
                fragment = (
                    "probe_arms() {\n"
                    '  case "$1" in\n'
                    f"{arm_text}"
                    "    *) return 1 ;;   # no arm in this fragment matched: the NEXT fragment gets its turn\n"
                    "  esac\n"
                    "  return 0\n"
                    "}\n"
                    'FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES probe_arms"\n'
                )
                res = self._run_gate_in_copy("lib/sandbox.py", fragment)
                self.assertNotEqual(res.returncode, 0, "a duplicate pattern must fail, not be resolved by position")
                self.assertIn("duplicate arm pattern 'lib/sandbox.py'", res.stderr)
                self.assertIn("one pattern, one home", res.stderr)

    def test_a_fragment_that_registers_no_stage_or_a_bogus_one_fails(self):
        """A fragment that is sourced and never called is the failure mode the arm guard exists for: it
        looks present in the tree and is absent from the gate. Both halves are probed - no registration,
        and a registration naming a function the fragment does not define."""
        cases = {
            "no registration": (
                "probe_arms() {\n"
                '  case "$1" in\n'
                "    *) return 1 ;;   # no arm in this fragment matched\n"
                "  esac\n"
                "  return 0\n"
                "}\n",
                "registers no stage",
            ),
            "registration with no function": (
                'FAST_GATE_ARM_STAGES="$FAST_GATE_ARM_STAGES probe_arms_missing"\n',
                "probe_arms_missing",
            ),
        }
        for label, (fragment, expected) in cases.items():
            with self.subTest(case=label):
                res = self._run_gate_in_copy("lib/sandbox.py", fragment)
                self.assertNotEqual(res.returncode, 0, f"{label}: the registry must refuse to load")
                self.assertIn("999-zz-probe.sh", res.stderr, f"{label}: the failure must name the fragment")
                self.assertIn(expected, res.stderr, f"{label}: the failure must name what is wrong")

    def test_a_missing_registry_is_an_error_not_an_empty_suite_list(self):
        """The asymmetry that matters: an empty suite list reads as 'nothing to run' and would be green,
        while an absent registry means the mapping is UNKNOWN. It must fail."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            (tmp / "tools").mkdir()
            shutil.copy2(FAST_GATE, tmp / "tools" / "fast-gate.sh")
            env = os.environ.copy()
            env["GIT_CHANGED"] = "lib/sandbox.py"
            env["FAST_GATE_DRY_RUN"] = "1"
            res = subprocess.run(["bash", str(tmp / "tools" / "fast-gate.sh")], cwd=str(tmp),
                                 env=env, capture_output=True, text=True)
        self.assertNotEqual(res.returncode, 0, "a gate with no arm registry must not report success")
        self.assertIn("no arm stages were registered", res.stderr)

    def test_every_pattern_has_exactly_one_home(self):
        """The static counterpart of the loader's duplicate guard, so a duplicate is caught by reading the
        registry rather than only by running a gate with a probe fragment in it."""
        patterns = arm_patterns()
        self.assertTrue(patterns, "the registry declares no patterns - the scan or the registry is broken")
        duplicates = sorted({p for p in patterns if patterns.count(p) > 1})
        self.assertEqual(duplicates, [], f"these patterns are declared in more than one fragment: {duplicates}")

    def test_the_registry_derives_its_own_denominators(self):
        """agents-exmy: the equivalence proof's denominator must be COUNTED FROM THE REGISTRY, not written by
        hand - the published claim said "a representative path of EVERY pattern (81 paths)" while the table
        it describes had 79 arms, and no reader could check that without redoing the work. This pin derives
        the figures through arm_registry_figures(), so the numbers below are printed by the code that owns
        the registry and the arithmetic cannot drift from it."""
        figures = arm_registry_figures()
        self.assertGreater(figures["patterns"], 50, f"the registry scan found almost no arms: {figures}")
        self.assertEqual(figures["patterns"],
                         figures["live"] + len(figures["dead"]) + len(figures["shadowed"]),
                         f"every arm is live, dead or shadowed: {figures['patterns']} patterns, "
                         f"{figures['live']} live, {len(figures['dead'])} dead, "
                         f"{len(figures['shadowed'])} shadowed")
        # agents-1j3z: a representative that an EARLIER arm answers is not a representative at all - the
        # proof would exercise the earlier arm and report the arm it meant to cover as covered. This is the
        # invariant the naive selection broke for two arms.
        patterns = arm_patterns()

        def first_match_arm(path: str):
            for pattern in patterns:
                if any(fnmatch.fnmatchcase(path, alt) for alt in pattern.split("|")):
                    return pattern
            return None

        misrouted = {arm: path for arm, path in figures["representative"].items()
                     if first_match_arm(path) != arm}
        self.assertEqual({}, misrouted,
                         "a representative must be answered by the arm it stands for, because the loader "
                         f"takes the FIRST match: {misrouted}")
        self.assertEqual(len(figures["representative"]), len(set(figures["representative"].values())),
                         "two arms sharing one path means one of them is not represented: "
                         f"{sorted(figures['representative'].values())}")
        self.assertEqual(figures["dead"], figures["declared_dead"],
                         "the arms matching no tracked path must be exactly the ones NAMED in "
                         f"DEAD_ARM_EXCEPTIONS with their reason (not a superset, not a subset): {figures}")
        # The representative path set is what an equivalence proof divides by: one TRACKED path per live arm.
        self.assertEqual(len(figures["representative"]), figures["live"],
                         "every live arm must have a representative tracked path for the proof to count")

    def test_no_arm_pattern_is_dead(self):
        """agents-v8xv's third obligation: an arm matching no tracked path is REPORTED. Measured when the
        table moved: every pattern matched at least one tracked file except the ignore arm for
        findings/*.md - a class that must be ignored the moment such a file is committed, so it is kept and
        NAMED here with its reason rather than left silently dead."""
        tracked = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files"], capture_output=True, text=True, check=True,
        ).stdout.split()
        self.assertTrue(tracked, "git ls-files returned nothing - the pin would pass vacuously")
        # A pattern line can carry alternatives (`README.md|AGENTS.md|...`), which `case` reads as
        # alternation - so a line is alive if ANY alternative matches a tracked path.
        dead = [
            p for p in arm_patterns()
            if not any(fnmatch.fnmatchcase(path, alt) for alt in p.split("|") for path in tracked)
        ]
        self.assertEqual(sorted(set(dead) - DEAD_ARM_EXCEPTIONS), [],
                         "these arm patterns match no tracked path, so they map nothing: either fix the "
                         "pattern or name it in DEAD_ARM_EXCEPTIONS with its reason")


class TestTheArmRegistryReaderIgnoresUntrackedFragments(unittest.TestCase):
    """agents-ncue: the arm registry reader must enumerate what the gate TRACKS, not what is on disk.

    The untracked-debris shape already has a sibling for the test tree
    (test_untracked_debris_is_not_absorbed_by_consumer_coverage, agents-jn73); this is the arms half, and it
    matters more than a count, because tools/fast-gate.sh SOURCES every *.sh it finds in this directory
    (agents-es0y) - a fragment the reader is willing to describe is code the gate is willing to run.

    The probe is built in a SYNTHETIC root that is git-initialised, so nothing is ever written into the
    live registry: a test that left a stray *.sh there would itself be the hazard it is testing for.
    """

    def test_untracked_debris_is_not_absorbed_by_the_arm_registry_reader(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            arms_dir = root / "tools" / "fast-gate-arms.d"
            arms_dir.mkdir(parents=True)
            (arms_dir / "010-tracked.sh").write_text("# a TRACKED fragment\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "add", "tools/fast-gate-arms.d/010-tracked.sh"],
                           check=True)
            # The pairing that makes this a check rather than a tautology: a fragment the index sees IS read,
            # so a green here cannot be satisfied by a reader that enumerates nothing at all.
            self.assertEqual([p.name for p in tracked_arm_fragments(root)], ["010-tracked.sh"])
            (arms_dir / "999-untracked.sh").write_text("# debris from an interrupted run\n", encoding="utf-8")
            self.assertEqual(
                [p.name for p in tracked_arm_fragments(root)], ["010-tracked.sh"],
                "an untracked fragment must not be enumerated: tools/fast-gate.sh SOURCES every *.sh it "
                "finds (agents-es0y), so a reader that names one names code the gate would execute",
            )


if __name__ == "__main__":
    unittest.main()
