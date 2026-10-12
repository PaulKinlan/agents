#!/usr/bin/env python3
"""The general fast-gate consumer-coverage property (agents-pdth).

MOVED HERE FROM tests/test_tree_guards.py BY agents-undf, AND THE REASON IS A RESULT WORTH KEEPING:
agents-dv23 pins that file to hold EXACTLY ["TestNoUnboundedSubprocess"], and
TestFastGateMapping.test_tree_guard_tier_module_holds_only_tree_property_tests asserts it by AST. This
pin is a CONSUMER-COVERAGE pin, not a tree property, so placing it there made the union RED - and the
delta that created it could not see that, because GIT_CHANGED=tests/test_tree_guards.py does not select
tests/test_fast_gate_mapping.py, which is where the guard on that file's CONTENTS lives. The pin was
BORN RED and every gate run on its own branch was honest and blind: a real record of the wrong thing.

THE LESSON, STATED SO THE NEXT LANE DOES NOT REPEAT IT: a pin placed inside an artefact that is itself
pinned cannot be seen by the delta that creates it. Prefer a module that owns its own subject.

IT IS AN ALWAYS-ON TIER NOW, LIKE THE FILE IT CAME FROM: tools/fast-gate.sh adds it to every mapped and
smoke run, so it has exactly the reach the tree-guard tier has - a pin that exists and is not selected
is the same as no pin.
"""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------------------------------
# agents-pdth: THE GENERAL FAST-GATE COVERAGE PROPERTY
#
# WHY THIS EXISTS: an arm for a lib/*.py module maps by basename, so a suite that imports the module
# but is not named test_<module>.py is silently omitted - and the arm still looks green. Measured on
# this repo's own history: 94 of 520 cached fast-gate records carry a non-empty `omitted` list, so the
# decay is live, not theoretical. A list that decays is worse than no list, because it reads like
# coverage.
#
# THE ORACLE'S RULE, MIRRORED RATHER THAN IMPORTED, AND WHY: the independent oracle is
# ~/fleet/remote/check-coverage.py (has_import_reference), which lives in the fleet tree and is not
# available to this repo's CI - so it cannot be imported here. What is mirrored is its consumer rule:
# a suite CONSUMES a module when an import statement or a `from` import names the module's stem. It is
# deliberately Python-only, because every suite in this repo is Python; the fleet oracle also covers
# JS/TS and class-inheritance chains, which this repo has no use for.
#
# KNOWN LIMIT, STATED SO A GREEN IS NOT OVERREAD: this mirrors the RULE, not the implementation. If
# the fleet oracle's notion of a consumer changes, this pin keeps enforcing the old one, and the two
# would disagree silently - the probe below is what catches the version of that failure that happens
# HERE (an oracle that stops seeing anything), not the version that happens there.
#
# COST: measured at 0.04s per module dry run, 21 modules, ~0.8s on EVERY mapped gate run. That is
# within the ADR agents-g9e2 budget of ~1s and is why this is a pin rather than 21 fixed arms.
#
# THE ALLOWLIST IS DEBT, AND IT IS GUARDED IN BOTH DIRECTIONS: an omission NOT in it fails (the arm
# must be fixed or the entry justified), and an entry that is NO LONGER an omission fails as stale -
# otherwise the list only ever grows, which is how an allowlist becomes a dumping ground.
# ---------------------------------------------------------------------------------------------------

# Each entry names WHY it is exempt. Format: module -> {suite: reason}.
# MODULES: {"<lib module stem>": {"<tests/ suite>": "<why this omission is known and accepted>"}}
# GENERATED FROM MEASUREMENT (agents-pdth), not typed: re-derive with the oracle in this file.
CONSUMER_COVERAGE_ALLOWLIST = {
    "candidate_identity": {
        "tests/test_findings.py": "basename arm: this suite imports lib/candidate_identity.py, but the arm selects only the module's namesake suite(s), so a change to lib/candidate_identity.py does not run it",
        "tests/test_scan_surface.py": "basename arm: this suite imports lib/candidate_identity.py, but the arm selects only the module's namesake suite(s), so a change to lib/candidate_identity.py does not run it",
    },
    "child_env": {
        "tests/containment_harness.py": "basename arm: this suite imports lib/child_env.py, but the arm selects only the module's namesake suite(s), so a change to lib/child_env.py does not run it",
        "tests/test_containment.py": "basename arm: this suite imports lib/child_env.py, but the arm selects only the module's namesake suite(s), so a change to lib/child_env.py does not run it",
        "tests/test_containment_adapters.py": "basename arm: this suite imports lib/child_env.py, but the arm selects only the module's namesake suite(s), so a change to lib/child_env.py does not run it",
        "tests/test_containment_declarations.py": "basename arm: this suite imports lib/child_env.py, but the arm selects only the module's namesake suite(s), so a change to lib/child_env.py does not run it",
        "tests/test_containment_egress.py": "basename arm: this suite imports lib/child_env.py, but the arm selects only the module's namesake suite(s), so a change to lib/child_env.py does not run it",
        "tests/test_containment_engine_credentials.py": "basename arm: this suite imports lib/child_env.py, but the arm selects only the module's namesake suite(s), so a change to lib/child_env.py does not run it",
        "tests/test_containment_prepass_pins.py": "basename arm: this suite imports lib/child_env.py, but the arm selects only the module's namesake suite(s), so a change to lib/child_env.py does not run it",
        "tests/test_factory_core.py": "basename arm: this suite imports lib/child_env.py, but the arm selects only the module's namesake suite(s), so a change to lib/child_env.py does not run it",
    },
    "containment": {
        "tests/containment_harness.py": "basename arm: this suite imports lib/containment.py, but the arm selects only the module's namesake suite(s), so a change to lib/containment.py does not run it",
    },
    "credential_broker": {
        "tests/containment_harness.py": "basename arm: this suite imports lib/credential_broker.py, but the arm selects only the module's namesake suite(s), so a change to lib/credential_broker.py does not run it",
        "tests/test_child_env.py": "basename arm: this suite imports lib/credential_broker.py, but the arm selects only the module's namesake suite(s), so a change to lib/credential_broker.py does not run it",
        "tests/test_containment.py": "basename arm: this suite imports lib/credential_broker.py, but the arm selects only the module's namesake suite(s), so a change to lib/credential_broker.py does not run it",
        "tests/test_containment_adapters.py": "basename arm: this suite imports lib/credential_broker.py, but the arm selects only the module's namesake suite(s), so a change to lib/credential_broker.py does not run it",
        "tests/test_containment_declarations.py": "basename arm: this suite imports lib/credential_broker.py, but the arm selects only the module's namesake suite(s), so a change to lib/credential_broker.py does not run it",
        "tests/test_containment_egress.py": "basename arm: this suite imports lib/credential_broker.py, but the arm selects only the module's namesake suite(s), so a change to lib/credential_broker.py does not run it",
        "tests/test_containment_engine_credentials.py": "basename arm: this suite imports lib/credential_broker.py, but the arm selects only the module's namesake suite(s), so a change to lib/credential_broker.py does not run it",
        "tests/test_containment_prepass_pins.py": "basename arm: this suite imports lib/credential_broker.py, but the arm selects only the module's namesake suite(s), so a change to lib/credential_broker.py does not run it",
        "tests/test_factory_core.py": "basename arm: this suite imports lib/credential_broker.py, but the arm selects only the module's namesake suite(s), so a change to lib/credential_broker.py does not run it",
        "tests/test_line_andon.py": "basename arm: this suite imports lib/credential_broker.py, but the arm selects only the module's namesake suite(s), so a change to lib/credential_broker.py does not run it",
    },
    "egress_proxy": {
        "tests/containment_harness.py": "not a suite: is_test_filename excludes it and it has its own arm, so no arm can ever select it AS A SUITE. The arm for lib/egress_proxy.py now selects the module's namesake suite AND the six containment suites, so this entry is not stale - none of those can cover a non-suite harness - and it is kept, with this reason corrected, because the omission is real (agents-bwbe; agents-m4pf)",
        "tests/test_containment.py": "basename arm: this suite imports lib/egress_proxy.py, but the arm selects only the module's namesake suite(s), so a change to lib/egress_proxy.py does not run it",
        "tests/test_containment_adapters.py": "basename arm: this suite imports lib/egress_proxy.py, but the arm selects only the module's namesake suite(s), so a change to lib/egress_proxy.py does not run it",
        "tests/test_containment_declarations.py": "basename arm: this suite imports lib/egress_proxy.py, but the arm selects only the module's namesake suite(s), so a change to lib/egress_proxy.py does not run it",
        "tests/test_containment_egress.py": "basename arm: this suite imports lib/egress_proxy.py, but the arm selects only the module's namesake suite(s), so a change to lib/egress_proxy.py does not run it",
        "tests/test_containment_engine_credentials.py": "basename arm: this suite imports lib/egress_proxy.py, but the arm selects only the module's namesake suite(s), so a change to lib/egress_proxy.py does not run it",
        "tests/test_containment_prepass_pins.py": "basename arm: this suite imports lib/egress_proxy.py, but the arm selects only the module's namesake suite(s), so a change to lib/egress_proxy.py does not run it",
    },
    "findings": {
        "tests/test_candidate_identity.py": "basename arm: this suite imports lib/findings.py, but the arm selects only the module's namesake suite(s), so a change to lib/findings.py does not run it",
        "tests/test_factory_core.py": "basename arm: this suite imports lib/findings.py, but the arm selects only the module's namesake suite(s), so a change to lib/findings.py does not run it",
        "tests/test_factory_truth.py": "basename arm: this suite imports lib/findings.py, but the arm selects only the module's namesake suite(s), so a change to lib/findings.py does not run it",
        "tests/test_perf_review.py": "basename arm: this suite imports lib/findings.py, but the arm selects only the module's namesake suite(s), so a change to lib/findings.py does not run it",
    },
    "sandbox": {
        "tests/containment_harness.py": "basename arm: this suite imports lib/sandbox.py, but the arm selects only the module's namesake suite(s), so a change to lib/sandbox.py does not run it",
        "tests/test_adapter_auth_failure.py": "basename arm: this suite imports lib/sandbox.py, but the arm selects only the module's namesake suite(s), so a change to lib/sandbox.py does not run it",
        "tests/test_containment.py": "basename arm: this suite imports lib/sandbox.py, but the arm selects only the module's namesake suite(s), so a change to lib/sandbox.py does not run it",
        "tests/test_containment_adapters.py": "basename arm: this suite imports lib/sandbox.py, but the arm selects only the module's namesake suite(s), so a change to lib/sandbox.py does not run it",
        "tests/test_containment_declarations.py": "basename arm: this suite imports lib/sandbox.py, but the arm selects only the module's namesake suite(s), so a change to lib/sandbox.py does not run it",
        "tests/test_containment_egress.py": "basename arm: this suite imports lib/sandbox.py, but the arm selects only the module's namesake suite(s), so a change to lib/sandbox.py does not run it",
        "tests/test_containment_engine_credentials.py": "basename arm: this suite imports lib/sandbox.py, but the arm selects only the module's namesake suite(s), so a change to lib/sandbox.py does not run it",
        "tests/test_containment_prepass_pins.py": "basename arm: this suite imports lib/sandbox.py, but the arm selects only the module's namesake suite(s), so a change to lib/sandbox.py does not run it",
        "tests/test_factory_core.py": "basename arm: this suite imports lib/sandbox.py, but the arm selects only the module's namesake suite(s), so a change to lib/sandbox.py does not run it",
        "tests/test_factory_truth.py": "basename arm: this suite imports lib/sandbox.py, but the arm selects only the module's namesake suite(s), so a change to lib/sandbox.py does not run it",
        "tests/test_factory_truth_2.py": "basename arm: this suite imports lib/sandbox.py, but the arm selects only the module's namesake suite(s), so a change to lib/sandbox.py does not run it",
        "tests/test_line_andon.py": "basename arm: this suite imports lib/sandbox.py, but the arm selects only the module's namesake suite(s), so a change to lib/sandbox.py does not run it",
        "tests/test_pi_keyless_broker.py": "basename arm: this suite imports lib/sandbox.py, but the arm selects only the module's namesake suite(s), so a change to lib/sandbox.py does not run it",
        "tests/test_prompt_exposure.py": "basename arm: this suite imports lib/sandbox.py, but the arm selects only the module's namesake suite(s), so a change to lib/sandbox.py does not run it",
        "tests/test_report_schema.py": "basename arm: this suite imports lib/sandbox.py, but the arm selects only the module's namesake suite(s), so a change to lib/sandbox.py does not run it",
    },
    "tool_pins": {
        "tests/test_bench_runner.py": "basename arm: this suite imports lib/tool_pins.py, but the arm selects only the module's namesake suite(s), so a change to lib/tool_pins.py does not run it",
        "tests/test_containment_prepass_pins.py": "basename arm: this suite imports lib/tool_pins.py, but the arm selects only the module's namesake suite(s), so a change to lib/tool_pins.py does not run it",
        "tests/test_factory_core.py": "basename arm: this suite imports lib/tool_pins.py, but the arm selects only the module's namesake suite(s), so a change to lib/tool_pins.py does not run it",
        "tests/test_hermetic_env.py": "basename arm: this suite imports lib/tool_pins.py, but the arm selects only the module's namesake suite(s), so a change to lib/tool_pins.py does not run it",
        "tests/test_sink_adapters.py": "basename arm: this suite imports lib/tool_pins.py, but the arm selects only the module's namesake suite(s), so a change to lib/tool_pins.py does not run it",
        "tests/test_store_lock_timeout.py": "basename arm: this suite imports lib/tool_pins.py, but the arm selects only the module's namesake suite(s), so a change to lib/tool_pins.py does not run it",
    },
}

# Import reference to a module stem, the same shape the fleet oracle matches (agents-pdth).
_IMPORT_RE = r"^\s*(?:import\s+[^;\n]*?\b{stem}\b|from\s+[^;\n]*?\b{stem}\b)"

# THE STRIPPING IS PART OF THE RULE, AND I LEARNED THAT BY MEASURING RATHER THAN ASSUMING: without it
# this oracle counted an import written inside a docstring or a comment as a consumer, and reported 16
# omissions for lib/sandbox.py where the fleet oracle reports 15 - the extra one being a suite that only
# MENTIONS the module. Mirroring the stripping (check-coverage.py:has_import_reference) brought the count
# to 15, matching the ADR agents-g9e2. A rule copied without its preprocessing is a different rule.
_STRIP = (
    (re.compile(r"/\*.*?\*/", re.DOTALL), " "),
    (re.compile(r'""".*?"""', re.DOTALL), " "),
    (re.compile(r"'''.*?'''", re.DOTALL), " "),
    (re.compile(r"`(?:\\.|[^`\\])*`", re.DOTALL), " "),
    (re.compile(r"//.*"), ""),
    (re.compile(r"#.*"), ""),
)


def _strip_code(source):
    """Remove comments and string literals before looking for imports (see above)."""
    for pattern, repl in _STRIP:
        source = pattern.sub(repl, source)
    return source


def _importing_suites(stem, root=None):
    """Suites under tests/ whose CODE imports `stem` - the oracle's consumer set."""
    root = root or ROOT
    pattern = re.compile(_IMPORT_RE.format(stem=re.escape(stem)), re.MULTILINE)
    found = set()
    for path in sorted((root / "tests").rglob("*.py")):
        try:
            src = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if pattern.search(_strip_code(src)):
            found.add(path.relative_to(root).as_posix())
    return found


def _selected_suites(module_path, root=None):
    """What the fast gate would actually run for a change to `module_path`.

    Asked of the gate itself with FAST_GATE_DRY_RUN, so this pins the mapping as it IS rather than a
    second copy of it. The dry run exits before the runner, so this cannot recurse into the suite that
    called it (agents-qtnv's re-entrancy concern, and agents-k6kr's wrapped-shape incident).
    """
    root = root or ROOT
    proc = subprocess.run(
        ["bash", "tools/fast-gate.sh"],
        cwd=root,
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_CHANGED": module_path, "FAST_GATE_DRY_RUN": "1"},
        timeout=60,
    )
    out = proc.stdout + proc.stderr
    return {ln.strip() for ln in out.splitlines() if ln.strip().startswith("tests/") and ln.strip().endswith(".py")}


def _lib_modules(root=None):
    root = root or ROOT
    return sorted(p.stem for p in (root / "lib").glob("*.py") if p.stem != "__init__")


class TestFastGateConsumerCoverage(unittest.TestCase):
    """Every suite that imports a lib module must be selected when that module changes."""

    def test_the_oracle_can_see_a_known_bad_case_and_stays_quiet_on_a_known_good_one(self):
        """THE PROBE (ADR agents-g9e2 item 3). An oracle that silently returns nothing must FAIL.

        A known-bad tree (a module with an importing suite the gate does not select) must be FLAGGED,
        and a known-good tree (a module with no importing suite) must produce NO omission. Without the
        second half, an oracle that flags everything would also pass a one-sided probe.
        """
        with tempfile.TemporaryDirectory() as td:
            fake = Path(td)
            (fake / "lib").mkdir()
            (fake / "tests").mkdir()
            (fake / "lib" / "widget.py").write_text("def widget():\n    return 1\n", encoding="utf-8")
            (fake / "tests" / "test_widget.py").write_text(
                "import unittest\nfrom lib import widget\n\n\nclass T(unittest.TestCase):\n"
                "    def test_it(self):\n        self.assertTrue(widget.widget())\n",
                encoding="utf-8",
            )
            (fake / "lib" / "orphan.py").write_text("def orphan():\n    return 2\n", encoding="utf-8")
            # KNOWN BAD: widget.py has a consumer, so the consumer set is non-empty. The probe does not
            # ask the gate (there is no gate in a temp tree); it asserts the ORACLE SEES the reference.
            self.assertEqual(
                _importing_suites("widget", root=fake),
                {"tests/test_widget.py"},
                "the oracle did not see an importing suite in a known-bad tree - it cannot be trusted "
                "when it reports no omissions (agents-pdth)",
            )
            # KNOWN GOOD: no importer, so no consumer, so nothing to omit.
            self.assertEqual(
                _importing_suites("orphan", root=fake),
                set(),
                "the oracle invented a consumer for a module nothing imports (agents-pdth)",
            )

    def test_a_consumer_the_gate_does_not_select_must_be_allowlisted(self):
        failures = []
        for module in _lib_modules():
            path = f"lib/{module}.py"
            omitted = _importing_suites(module) - _selected_suites(path)
            allowed = set(CONSUMER_COVERAGE_ALLOWLIST.get(module, {}))
            unlisted = sorted(omitted - allowed)
            if unlisted:
                failures.append(
                    f"{path} omits {len(unlisted)} consumer(s) and they are not in the allowlist: "
                    f"{', '.join(unlisted)}. Fix the arm in tools/fast-gate.sh, or add each entry to "
                    f"CONSUMER_COVERAGE_ALLOWLIST with the reason it is exempt (agents-pdth)."
                )
        self.assertEqual(failures, [], "\n".join(failures))

    def test_the_allowlist_has_no_stale_entries(self):
        """An entry that is no longer an omission must FAIL, or the list only ever grows."""
        stale = []
        for module, entries in CONSUMER_COVERAGE_ALLOWLIST.items():
            omitted = _importing_suites(module) - _selected_suites(f"lib/{module}.py")
            for suite in entries:
                if suite not in omitted:
                    stale.append(
                        f"CONSUMER_COVERAGE_ALLOWLIST['{module}']['{suite}'] is STALE: the gate now "
                        f"selects it, or the suite no longer imports the module. Delete the entry so "
                        f"the list shrinks (agents-pdth)."
                    )
        self.assertEqual(stale, [], "\n".join(stale))


if __name__ == "__main__":
    unittest.main()
