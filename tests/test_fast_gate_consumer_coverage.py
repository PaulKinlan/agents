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

import functools
import importlib.util
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The independent oracle the mirror mirrors (agents-5z4e). It lives in the fleet tree, so it is NOT
# available to this repo's CI - which is exactly why the mirror is the always-on assertion and this
# cross-check is optional rather than the other way round.
_FLEET_ORACLE = Path("/home/exedev/fleet/remote/check-coverage.py")


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
# COST, RE-MEASURED AT agents-y2b2 RATHER THAN RESTATED: the shape this file COMMITS TO made 32 gate dry
# runs - 21 modules in one test, the allowlist's 11 in another - which the recorded figure had undercounted
# as 21. Sharing the answer takes it to 21, MEASURED BY COUNTING SUBPROCESS CALLS with the lru_cache
# decorators in and out rather than estimated. So the honest figure is SMALLER than the wrong one was, which
# is why the remedy was 'compute it once' rather than 'correct the number': a corrected figure for an
# unchanged shape would rot the moment the shape moved. Whole class on this VM: 4 tests in 5.526s against 3
# tests in 5.663s before - the cross-check added in agents-5z4e cost less than the dry runs it stopped
# repeating.
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
        "tests/containment_harness.py": "basename arm: this suite imports lib/egress_proxy.py, but the arm selects only the module's namesake suite(s), so a change to lib/egress_proxy.py does not run it",
        "tests/test_containment.py": "basename arm: this suite imports lib/egress_proxy.py, but the arm selects only the module's namesake suite(s), so a change to lib/egress_proxy.py does not run it",
        "tests/test_containment_adapters.py": "basename arm: this suite imports lib/egress_proxy.py, but the arm selects only the module's namesake suite(s), so a change to lib/egress_proxy.py does not run it",
        "tests/test_containment_declarations.py": "basename arm: this suite imports lib/egress_proxy.py, but the arm selects only the module's namesake suite(s), so a change to lib/egress_proxy.py does not run it",
        "tests/test_containment_egress.py": "basename arm: this suite imports lib/egress_proxy.py, but the arm selects only the module's namesake suite(s), so a change to lib/egress_proxy.py does not run it",
        "tests/test_containment_engine_credentials.py": "basename arm: this suite imports lib/egress_proxy.py, but the arm selects only the module's namesake suite(s), so a change to lib/egress_proxy.py does not run it",
        "tests/test_containment_prepass_pins.py": "basename arm: this suite imports lib/egress_proxy.py, but the arm selects only the module's namesake suite(s), so a change to lib/egress_proxy.py does not run it",
    },
    "embargo": {
        "tests/test_factory_truth.py": "basename arm: this suite imports lib/embargo.py, but the arm selects only the module's namesake suite(s), so a change to lib/embargo.py does not run it",
        "tests/test_model_rule_id.py": "basename arm: this suite imports lib/embargo.py, but the arm selects only the module's namesake suite(s), so a change to lib/embargo.py does not run it",
        "tests/test_report_schema.py": "basename arm: this suite imports lib/embargo.py, but the arm selects only the module's namesake suite(s), so a change to lib/embargo.py does not run it",
        "tests/test_threat_model_prepass.py": "basename arm: this suite imports lib/embargo.py, but the arm selects only the module's namesake suite(s), so a change to lib/embargo.py does not run it",
    },
    "findings": {
        "tests/test_candidate_identity.py": "basename arm: this suite imports lib/findings.py, but the arm selects only the module's namesake suite(s), so a change to lib/findings.py does not run it",
        "tests/test_factory_core.py": "basename arm: this suite imports lib/findings.py, but the arm selects only the module's namesake suite(s), so a change to lib/findings.py does not run it",
        "tests/test_factory_truth.py": "basename arm: this suite imports lib/findings.py, but the arm selects only the module's namesake suite(s), so a change to lib/findings.py does not run it",
        "tests/test_perf_review.py": "basename arm: this suite imports lib/findings.py, but the arm selects only the module's namesake suite(s), so a change to lib/findings.py does not run it",
    },
    "redaction": {
        "tests/test_findings.py": "basename arm: this suite imports lib/redaction.py, but the arm selects only the module's namesake suite(s), so a change to lib/redaction.py does not run it",
        "tests/test_model_rule_id.py": "basename arm: this suite imports lib/redaction.py, but the arm selects only the module's namesake suite(s), so a change to lib/redaction.py does not run it",
        "tests/test_secret_scanner.py": "basename arm: this suite imports lib/redaction.py, but the arm selects only the module's namesake suite(s), so a change to lib/redaction.py does not run it",
        "tests/test_vuln_verify_prepass.py": "basename arm: this suite imports lib/redaction.py, but the arm selects only the module's namesake suite(s), so a change to lib/redaction.py does not run it",
    },
    "retention": {
        "tests/test_hillclimb.py": "basename arm: this suite imports lib/retention.py, but the arm selects only the module's namesake suite(s), so a change to lib/retention.py does not run it",
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


@functools.lru_cache(maxsize=None)
def _importing_suites(stem, root=None):
    """Suites under tests/ whose CODE imports `stem` - the oracle's consumer set.

    MEMOISED (agents-y2b2): two tests ask the same question of the same modules, and without sharing the
    answer the committed shape paid for every dry run twice.
    """
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


@functools.lru_cache(maxsize=None)
def _selected_suites(module_path, root=None):
    """What the fast gate would actually run for a change to `module_path`.

    Asked of the gate itself with FAST_GATE_DRY_RUN, so this pins the mapping as it IS rather than a
    second copy of it. The dry run exits before the runner, so this cannot recurse into the suite that
    called it (agents-qtnv's re-entrancy concern, and agents-k6kr's wrapped-shape incident).

    MEMOISED (agents-y2b2): the cost claim recorded 21 dry runs where the COMMITTED shape made 32, because
    two tests each asked the gate for the same mapping. Sharing the answer is the remedy that cannot rot -
    a corrected figure for an unchanged shape would.
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


# The non-suite consumers, ASSERTED rather than described (agents-tuz8). The mirror is deliberately
# broader than the oracle: a helper that imports a lib module is still a consumer, because the gate cannot
# run it but a change to that module still breaks it. This is that difference, pinned - a sixth module
# gaining a helper consumer, or a new helper appearing, fails here rather than quietly widening the claim.
NON_SUITE_CONSUMERS = {
    "child_env": ["tests/containment_harness.py"],
    "containment": ["tests/containment_harness.py"],
    "credential_broker": ["tests/containment_harness.py"],
    "egress_proxy": ["tests/containment_harness.py"],
    "sandbox": ["tests/containment_harness.py"],
}


def _load_oracle():
    spec = importlib.util.spec_from_file_location("_fleet_check_coverage", _FLEET_ORACLE)
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    return oracle


def _oracle_importers(oracle, module, suites_only):
    """What the ORACLE's rule says, optionally restricted to the files it calls suites."""
    found = set()
    for path in sorted((ROOT / "tests").rglob("*.py")):
        if suites_only and not oracle.is_test_filename(str(path)):
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        # RAW content: the oracle strips comments and docstrings itself, and IT owns that preprocessing -
        # a mirror that pre-stripped would compare its own rule to the oracle's filtered view of it
        # (agents-pdth measured 16 against 15 that way).
        if oracle.has_import_reference(content, module):
            found.add(path.relative_to(ROOT).as_posix())
    return found


class TestMirrorAgreesWithFleetOracle(unittest.TestCase):
    """agents-5z4e: the mirror is what runs everywhere; the oracle is what the mirror mirrors.

    MIRROR PLUS OPTIONAL AGREEMENT CROSS-CHECK, the shape coord endorsed: the mirror stays the always-on
    assertion nothing can skip, and when the oracle IS present this asserts the two agree - so a drift in
    either becomes a red test rather than two green ones that quietly disagree.

    THE TWO SUITE DEFINITIONS DIFFER IN PRINCIPLE AND THE DIFFERENCE IS DELIBERATE - CORRECTED AT
    agents-tuz8, WHICH FALSIFIED THE PARAGRAPH THAT USED TO STAND HERE. That earlier warrant said the four
    files the oracle would not call suites import none of the 21 lib modules. It is FALSE: experiments showed
    tests/containment_harness.py imports FIVE of them (child_env, containment, credential_broker,
    egress_proxy, sandbox), which is why the allowlist legitimately carries it for those five modules. The
    old paragraph was produced by a measurement that fed every file to the oracle, so both sides used the
    mirror's definition and the equality could not fail on the cases that actually differ - the warrant was
    computed with the definition it was meant to test.

    WHAT THE TWO RULES ARE FOR, so the difference reads as intended rather than as drift. The MIRROR globs
    tests/**/*.py because a non-suite file that imports a module is still a consumer: the gate cannot run it,
    but a change to that module still breaks it. The ORACLE's is_test_filename excludes __init__.py and
    helper modules because the oracle deals in suites it can execute. So the cross-check is two halves:
      1. ON FILES THE ORACLE CALLS SUITES the mirror and the oracle must agree exactly - that half compares
         two implementations and can fail on rule drift;
      2. THE NON-SUITE DELTA is asserted as the NAMED SET below, so a sixth module gaining a helper consumer,
         or a new helper appearing, fails loudly instead of silently widening the mirror's claim.
    """

    def test_the_mirror_and_the_fleet_oracle_agree_on_suites(self):
        """Like-for-like: for files the oracle calls SUITES, the two implementations must agree exactly."""
        if not _FLEET_ORACLE.is_file():
            self.skipTest(
                f"the fleet oracle is not present at {_FLEET_ORACLE}, so the mirror alone runs - this is "
                "the normal case in this repo's CI, and the reason the mirror is not a call to the oracle"
            )
        oracle = _load_oracle()
        mismatches = []
        for module in _lib_modules():
            mirror = {f for f in _importing_suites(module) if oracle.is_test_filename(f)}
            theirs = _oracle_importers(oracle, module, suites_only=True)
            if mirror != theirs:
                mismatches.append(
                    f"{module}: mirror-only={sorted(mirror - theirs)} oracle-only={sorted(theirs - mirror)}"
                )
        self.assertEqual(
            mismatches,
            [],
            "the mirror and the fleet oracle disagree on which SUITES import a module - one of the two "
            "rules has changed and the pin is enforcing the old one (agents-5z4e, narrowed at "
            "agents-tuz8):\n" + "\n".join(mismatches),
        )

    def test_the_non_suite_consumer_delta_is_the_named_set(self):
        """Half two: the files the oracle excludes, asserted as a NAMED SET rather than described.

        The mirror is deliberately broader, so this delta is real and intended - which is exactly why it
        must be pinned. Before agents-tuz8 the test compared membership for EVERY file, which made both
        sides use the mirror's definition and could not fail here at all.
        """
        if not _FLEET_ORACLE.is_file():
            self.skipTest(f"the fleet oracle is not present at {_FLEET_ORACLE}")
        oracle = _load_oracle()
        actual = {}
        for module in _lib_modules():
            delta = sorted(f for f in _importing_suites(module) if not oracle.is_test_filename(f))
            if delta:
                actual[module] = delta
        self.assertEqual(
            actual,
            {m: sorted(v) for m, v in NON_SUITE_CONSUMERS.items()},
            "the set of NON-SUITE files importing lib modules changed. If a new helper appeared, or a "
            "module gained one, that is not automatically wrong - but it widens the mirror's claim, so "
            "record it here deliberately (agents-tuz8).",
        )


if __name__ == "__main__":
    unittest.main()
