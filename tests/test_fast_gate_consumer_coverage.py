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

import ast
import contextlib
import functools
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# The tracked-file instrument (tests/__init__.py): the allowlist loader reads the fragment set from git's
# index, because a fragment is CONFIGURATION and an uncommitted file must not be able to change it
# (agents-2it3; the same instrument agents-nder/zf2p use for their walkers).
from tests import has_git_index, tracked_paths

# The ONE definition of "the tracked arm fragments" (agents-ncue), shared with the loader in
# tools/fast-gate.sh so a reader and the gate cannot disagree about what the registry contains. Imported
# as a submodule rather than as `from tests import ...`: this module already owns its package-initialiser
# import above, and re-importing the package buys nothing (agents-ncue measured the same on its reader).
from tests.test_fast_gate_mapping import tracked_arm_fragments

ROOT = Path(__file__).resolve().parent.parent

# The independent oracle the mirror mirrors (agents-5z4e). It lives in the fleet tree, so it is NOT
# available to this repo's CI - which is exactly why the mirror is the always-on assertion and this
# cross-check is optional rather than the other way round.
_FLEET_ORACLE = Path(os.environ.get("FACTORY_COVERAGE_ORACLE") or "check-coverage.py")

# Bound for the gate's own dry-run/resolve subprocess calls (agents-4jqna). The batch resolve (23
# lib modules answered in ONE invocation) measured 42.70s, 50.60s, 42.70s on this VM at load 6.37;
# the old per-call bound of 60s left 18% headroom over the quiet measurement, and at load 20.8 the
# same call EXCEEDED it and reddened a full gate for a delta that does not touch the gate at all.
# The cost is gate STARTUP - a fixed per-invocation cost multiplied by load on a 2-vCPU box shared
# by ten lanes - so a wall-clock bound 1.18x the quiet measurement cannot hold. 210s is 4x the
# worst measured run, the same measurement-sized shape as _CLI_GUARD_S in tests/test_sinks.py
# (agents-0qyjo/g4cq9): a hang guard, not a sleep. The durable fix is gate-startup cost coming down
# (agents-kw7wl); when it does, lower it HERE, in one place.
_GATE_CLI_GUARD_S = 210

# The worst standalone measurement behind _GATE_CLI_GUARD_S (see above), kept as its own number so
# the guard below fails with the measurement in the message rather than with an opinion.
_WORST_MEASURED_GATE_CLI_S = 50.6

# Bound for this file's LOCAL GIT plumbing (agents-5bpe4): fixture init/add on temp trees and the
# `git ls-files` reads at the repo root - all sub-0.1s here (worst measured: git ls-files tests,
# 0.095s cold on this VM). 60s is a hang guard at >600x that measurement, deliberately FAR below
# _GATE_CLI_GUARD_S: a wedged fixture git must not spend the gate CLI's budget, and a legitimate
# bound on a local call must never be forced onto the gate constant - the guard's old false-red
# (agents-5bpe4): its rule said "every bound must use _GATE_CLI_GUARD_S", so bounding a local git
# call at its own class meant tripping the guard, and the only escape was deleting it.
_LOCAL_GIT_GUARD_S = 60

# The worst standalone measurement behind _LOCAL_GIT_GUARD_S (see above), kept as its own number so
# the headroom pin below fails with the measurement in the message rather than with an opinion.
_WORST_MEASURED_LOCAL_GIT_S = 0.095


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
# the fleet's coverage oracle (has_import_reference), which lives in the fleet tree and is not
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
# ---------------------------------------------------------------------------------------------------
# THE ALLOWLIST, AND WHY IT CARRIES NO REASONS (agents-02s9). Each entry is just the suite now; the reason
# is DERIVED when a test fails, from the gate's own answer to "what do you select for this module" - a
# measurement rather than a sentence.
#
# The reasons used to be prose, one string per module, and all of them said the arm "selects only the
# module's namesake suite(s)". That was true for the modules that fall to the generic lib/*.py) arm and
# FALSE for those with a dedicated arm - and it never mentioned the two always-on tiers every arm adds. A
# false reason attached to a true fact is worse than no reason, because the next reader trusts the wrong
# mechanism; the fix is not better prose but a reason that cannot be written down wrong.
#
# The arm's PATTERN is named rather than its LINE - the line moves, the pattern is greppable, and the
# selection beside it is measured rather than read.
# ---------------------------------------------------------------------------------------------------
# ---------------------------------------------------------------------------------------------------
# agents-nerv: THIS IS A DIRECTORY OF FRAGMENTS, NOT A LITERAL. Appending to one dict in one file made
# every lane that omitted a consumer resolve a conflict against every other lane (N deliveries, N-1
# rebases and re-gates). A delivery now drops its OWN fragment - tests/fast_gate_allowlists.d/<id>.json -
# and this test merges whatever is there, so no two deliveries touch one file.
#
# The base fragments are the migration of what used to be the literals here, generated from those
# literals with ast.literal_eval and asserted EQUAL to them - not transcribed, because a hand copy would
# make the test agree with itself (agents-nerv).
#
# A MALFORMED FRAGMENT IS AN ERROR RATHER THAN SOMETHING TO SKIP: silently ignoring one is how an
# omission stops being guarded, which is the failure this whole file exists to prevent.
_ALLOWLIST_DIR = ROOT / "tests" / "fast_gate_allowlists.d"
# agents-1mz0: the WHY for an entry, and for the four assertion-consumer exclusions, is in
# docs/adr/0001-fast-gate-coverage-tiers.md, section "The Assertion-Consumer Class". This directory
# carries no reasons by design (agents-02s9); the pointer keeps the ADR findable from here.


def _allowlist_fragments(root=ROOT):
    """The allowlist fragment FILES to merge, from GIT'S INDEX where there is one (agents-2it3).

    THIS IS UNTRUSTED INPUT REACHING A PARSER, WHICH IS WHY IT IS NOT JUST A COVERAGE COUNT (agents-2it3's
    distinction from the other filesystem-walker findings): the loader below parses what it finds and merges
    it into the gate's exemptions, so a file that was never COMMITTED could add an exemption - silencing the
    omission check this directory exists to explain - or, if it does not parse, raise at IMPORT and fail this
    whole module. Both were measured on the glob this replaces, with an untracked file in the directory:
      * a VALID untracked fragment took the loaded set from 3 to 4 (it was configuration);
      * a MALFORMED untracked fragment raised from the module's import:
        "AssertionError: zz_bad_tmp.json: not valid JSON (Expecting property name ...)".
    git's index is the set the gate witnesses, so an uncommitted file cannot reach the parser at all.

    A NON-GIT ROOT still falls back to the filesystem, because there is then no index to ask and no
    tracked/untracked distinction to be had; that case cannot arise in a gate run, which is a work tree. Same
    fallback, same argument, as tests/test_ci_action.py's action_files.
    """
    allowlist_dir = root / "tests" / "fast_gate_allowlists.d"
    if has_git_index(root):
        # tracked_paths takes a git PATHSPEC: ask for the directory (a pathspec's `*` crosses `/`, so asking
        # for `*.json` would reach into subdirectories) and filter the direct-child .json files here.
        return sorted(p for p in tracked_paths("tests/fast_gate_allowlists.d", root=root)
                      if p.parent == allowlist_dir and p.suffix == ".json")
    return sorted(allowlist_dir.glob("*.json"))


def _untracked_allowlist_fragments(root=ROOT, *, tracked=None):
    """Find guard-weakening JSON skipped by the index reader; a non-Git root has no strays."""
    if not has_git_index(root):
        return []
    if tracked is None:
        tracked = _allowlist_fragments(root)
    allowlist_dir = root / "tests" / "fast_gate_allowlists.d"
    indexed = set(tracked)
    return sorted(p for p in allowlist_dir.glob("*.json") if p not in indexed)


def _report_untracked_allowlist_fragments(paths, root=ROOT):
    """Keep notices off stdout: it is the fleet oracle's suite-marker channel."""
    for path in paths:
        print(f"fast-gate: WARNING: ignoring UNTRACKED allowlist fragment (not loaded): "
              f"{str(path.relative_to(root))!r}", file=sys.stderr)


def _load_allowlist_fragments(*, fragments=None):
    """Merge every fragment; return (consumer_coverage, non_suite, provenance).

    provenance maps (kind, module, suite) -> the fragment file that declared it, so a stale entry names
    the file a reader must edit rather than a directory they must search (agents-nerv).
    """
    coverage, non_suite, provenance = {}, {}, {}
    # THE FRAGMENT SET IS READ FROM THE TREE, NOT THE MACHINE (agents-2it3): see _allowlist_fragments.
    if fragments is None:
        fragments = _allowlist_fragments()
    if not fragments:
        raise AssertionError(f"no allowlist fragments in {_ALLOWLIST_DIR}: the merged allowlist would be empty")
    for path in fragments:
        try:
            blob = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise AssertionError(f"{path.name}: not valid JSON ({exc}) - a fragment that does not parse must fail")
        # agents-tdcf (found by rev-nerv): A FRAGMENT THAT IS VALID JSON BUT NOT AN OBJECT. The
        # loader used to reach .get() straight after parsing, so a fragment holding a JSON array died
        # with "AttributeError: 'list' object has no attribute 'get'" - loud, but with no filename in
        # it, and a directory of fragments is only usable if the error says WHICH fragment is wrong.
        # A reader who has to bisect the directory to find a typo has been given a worse tool than the
        # single dict this replaced. The check is ahead of the first .get, and it names the file.
        if not isinstance(blob, dict):
            raise AssertionError(
                f"{path.name}: a fragment must be a JSON object, not {type(blob).__name__} "
                f"(got {str(blob)[:60]!r}) - a directory of fragments is only usable if the error "
                f"names the file"
            )
        kind = blob.get("kind")
        if kind not in ("consumer_coverage", "non_suite_consumers"):
            raise AssertionError(f"{path.name}: kind must be consumer_coverage or non_suite_consumers, got {kind!r}")
        target = coverage if kind == "consumer_coverage" else non_suite
        modules = blob.get("modules")
        if not isinstance(modules, dict):
            raise AssertionError(f"{path.name}: modules must be an object mapping module -> list of suites")
        for module, suites in modules.items():
            if not isinstance(suites, list) or not all(isinstance(s, str) for s in suites):
                raise AssertionError(f"{path.name}: {module} must map to a list of suite paths")
            for suite in suites:
                target.setdefault(module, set()).add(suite)
                provenance[(kind, module, suite)] = path.name
    return coverage, non_suite, provenance


# A skipped fragment cannot weaken the guard, but a silent skip hides a configuration mistake.
# Snapshot once at import and report ONCE at module teardown, where the runner receipt's tail shows it.
# Test-created probes appear only AFTER import: they cannot create routine gate noise, and a test
# that deliberately calls _load_allowlist_fragments() later cannot overwrite the snapshot.
_FRAGMENTS_AT_IMPORT = _allowlist_fragments()
_UNTRACKED_ALLOWLIST_FRAGMENTS_AT_IMPORT = _untracked_allowlist_fragments(tracked=_FRAGMENTS_AT_IMPORT)
CONSUMER_COVERAGE_ALLOWLIST, NON_SUITE_CONSUMERS, _ALLOWLIST_PROVENANCE = _load_allowlist_fragments(
    fragments=_FRAGMENTS_AT_IMPORT)


def _fragment_declaring(kind, module, suite):
    """The fragment that declared this entry - named so a stale entry tells a reader what to edit."""
    return _ALLOWLIST_PROVENANCE.get((kind, module, suite), "<no fragment names this entry>")

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


@functools.lru_cache(maxsize=None)
def _strip_code(source):
    """Remove comments and string literals before looking for imports (see above).

    MEMOISED BY CONTENT (agents-jn73): it is pure, and the consumer scan asks the same 97 files the same
    question once per lib module - measured at 2,037 strip passes over 97 distinct sources in one run of
    this module. Keyed on the source string, so two files with identical text share the answer and any
    change to the text is a different key.
    """
    for pattern, repl in _STRIP:
        source = pattern.sub(repl, source)
    return source


def _arm_pattern(module):
    """The case pattern in tools/fast-gate.sh that owns lib/<module>.py, or the generic catch-all.

    THE PATTERN RATHER THAN ITS LINE: the line moves on every unrelated edit, while the pattern is greppable
    and the selection printed beside it is measured. A reason naming a stale line is the same defect as a
    reason naming the wrong arm, one commit later. Read once per FAILING run, never on a green one.
    """
    text = _arm_registry_text()
    if re.search(rf"^\s+lib/{re.escape(module)}\.py\)", text, re.MULTILINE):
        return f"lib/{module}.py)"
    return "lib/*.py)"

def _arm_registry_text(root=None) -> str:
    """The fast-gate arm registry, reassembled from its fragments (agents-hr6q, ADR 0002).

    The arms used to be one `case` table inside tools/fast-gate.sh; they are now one file per contiguous
    run of arms under tools/fast-gate-arms.d/, and this helper is the reader that reconstitutes them for
    the one question this module asks of the source ("does this module have an arm of its own?"). Reading
    the script alone would answer "no" for every module and quietly change what the reasons below say.

    ENUMERATED FROM GIT'S INDEX, not the filesystem (agents-jwn9). This was the FOURTH and last glob of
    this directory in the tree - agents-ncue fixed the other three - so it was the last place where an
    untracked fragment could enter the registry text, and a stray whose body merely CONTAINS a matching
    pattern answers "does this module have an arm of its own?" with a green. The enumeration is delegated
    to tracked_arm_fragments so there is one definition of the registry rather than a fourth copy of it.
    """
    fragments = tracked_arm_fragments(root)
    assert fragments, (
        f"no arm fragments in {(root or ROOT) / 'tools' / 'fast-gate-arms.d'}: the registry cannot be read"
    )
    return "\n".join(path.read_text(encoding="utf-8") for path in fragments)


def _why_omitted(module, suite):
    """Why `suite` imports lib/<module>.py and the gate still does not run it for a change to that file.

    DERIVED, NOT WRITTEN DOWN (agents-02s9). The sentence is built from the gate's own answer, so it cannot
    describe the wrong mechanism - which is what all 62 hand-written reasons did for the seven modules that
    have a dedicated arm, every one of them claiming the arm selects "only the namesake suite(s)".

    Cost on a green run: nothing. It is called only for an unlisted omission or a stale entry, and the
    selection it quotes is the _selected_suites the test already asked for.
    """
    selected = sorted(_selected_suites(f"lib/{module}.py"))
    return (
        f"{suite} imports lib/{module}.py, but the {_arm_pattern(module)} arm in tools/fast-gate.sh does not "
        f"select it - it selects {', '.join(s.split('/')[-1] for s in selected)}"
    )


def _tracked_test_files(root=None):
    """The tracked .py files under tests/ (agents-nder: from git's index, never a filesystem walk).

    NOT MEMOISED (agents-9891; agents-jn73's landed record states the asymmetry): this runs `git ls-files`, so
    it reads the world's INDEX and memoising it was a BEHAVIOURAL change rather than only a cost change. It was
    measured at ~0.04s of the 2.4s agents-jn73 bought (strip-only 8.72s vs both 8.68s, same tree, same machine,
    back to back), which does not buy a cache whose safety rests on an argument instead of on purity.
    _strip_code above stays memoised: it is pure, and it carried the whole win.

    WHAT THIS DOES AND DOES NOT FIX, measured rather than assumed (and the distinction matters, because the
    easy claim here is false): the ORACLE path (_oracle_importers, whose only cache was this one) is
    index-live again - a mid-process `git add` is SEEN with no cache_clear, where on the jn73 bytes it was
    MISSED. The MIRROR path is not: _importing_suites below is memoised in its own right (agents-y2b2, before
    this bead) and caches the composed answer, which is why test_untracked_debris_is_not_absorbed_by_consumer_
    coverage still clears it. So this removes a 0.04s cache whose correctness was conditional; it does not make
    the module index-live.
    """
    root = root or ROOT
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "tests"],
        capture_output=True, text=True, check=True, timeout=_LOCAL_GIT_GUARD_S
    ).stdout.splitlines()
    paths = sorted(root / p for p in out if p.endswith(".py"))
    if not paths:
        raise RuntimeError(f"no tracked test files found under {root / 'tests'}")
    return paths


@functools.lru_cache(maxsize=None)
def _importing_suites(stem, root=None):
    """Suites under tests/ whose CODE imports `stem` - the oracle's consumer set.

    MEMOISED (agents-y2b2): two tests ask the same question of the same modules, and without sharing the
    answer the committed shape paid for every dry run twice.
    """
    root = root or ROOT
    pattern = re.compile(_IMPORT_RE.format(stem=re.escape(stem)), re.MULTILINE)
    found = set()
    for path in _tracked_test_files(root):
        try:
            src = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if pattern.search(_strip_code(src)):
            found.add(path.relative_to(root).as_posix())
    return found


def _parse_resolutions(stdout, rc):
    """The resolve-mode contract as {path: suites}, or {} when the gate did NOT answer it.

    {} MEANS "ASK PER PATH", NOT "NOTHING IS SELECTED": a batch that refused (an unmatched path fails
    loudly, exactly as it does for the union run) has printed some per-path lines but no ':always' line,
    and answering from it would hand back sets MISSING the tier pins - a wrong answer that looks like a
    right one. So an absent ':always' line is treated as no answer at all, and the caller pays the slow
    path instead.
    """
    if rc != 0:
        return {}
    always = None
    mapping = {}
    for line in stdout.splitlines():
        if line.startswith(":always\t"):
            always = {s for s in line.split("\t", 1)[1].split() if s}
        elif line.startswith("!"):
            mapping[line[1:].strip()] = set()
        elif "\t" in line:
            path, suites = line.split("\t", 1)
            mapping[path.strip()] = {s for s in suites.split() if s}
    if always is None:
        return {}
    return {path: suites | always for path, suites in mapping.items()}


@functools.lru_cache(maxsize=None)
def _batch_resolutions(root=None):
    """THE MAPPING OF EVERY lib/ MODULE, FROM ONE GATE INVOCATION (agents-wzmj, F1).

    The same question _selected_suites asks per path, asked once for the whole module set. The gate's
    per-path resolve mode answers it from the single pass that already resolves every path, so the 21
    startups the module walk used to pay (0.194s each, 4.07s) become one.

    DELIBERATELY NOT SILENT WHEN THE GATE DOES NOT ANSWER: the caller falls back to the per-path dry
    run, which is correct but slow, so an inert mode would cost the saving without anybody noticing -
    test_the_resolve_mode_answers_every_module_from_one_invocation pins the ANSWER, not just the call.

    FAST_GATE_DRY_RUN IS SET AS WELL, and that is a safety property and not redundant: the resolve mode
    is checked before the dry run, so a gate that HAS the mode answers per path, while a gate that does
    not falls through to the dry-run exit instead of the RUNNER. Measured: without it, the batch call on
    an unpatched gate ran the suites and hit the 60s timeout - the recursion the dry run exists to
    prevent, since this module is one of the suites it would have selected.
    """
    root = root or ROOT
    paths = [f"lib/{module}.py" for module in _lib_modules(root)]
    return _resolve_batch(paths, root)


def _resolve_batch(paths, root=None):
    """One gate startup resolving an ARBITRARY path collection (the worker behind _batch_resolutions).

    Uncached on purpose: each caller owns its own entry point and path set (the lib-module walk via
    _batch_resolutions, the agents-1v6ap cross-class sample via its test), so one startup per set is
    paid exactly once per module run and no cache key can silently mix the two contracts.
    """
    root = root or ROOT
    if not paths:
        return {}
    proc = subprocess.run(
        ["bash", "tools/fast-gate.sh"],
        cwd=root,
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_CHANGED": "\n".join(paths), "FAST_GATE_RESOLVE_PATHS": "1",
             "FAST_GATE_DRY_RUN": "1"},
        timeout=_GATE_CLI_GUARD_S,
    )
    return _parse_resolutions(proc.stdout, proc.returncode)


def _raw_dry_run_union(path, root=None):
    """What the UNION dry run selects when `path` alone is the change set - the raw side of THE
    EQUIVALENCE. Deliberately NOT routed through _selected_suites or _batch_resolutions: the
    equivalence is only a measurement while its two sides are independent mechanisms - a raw side
    answered from the batch record would make the test batch-versus-batch, which cannot fail on a
    record defect (agents-1v6ap)."""
    root = root or ROOT
    proc = subprocess.run(
        ["bash", "tools/fast-gate.sh"], cwd=root, capture_output=True, text=True,
        env={**os.environ, "GIT_CHANGED": path, "FAST_GATE_DRY_RUN": "1"}, timeout=_GATE_CLI_GUARD_S,
    )
    return {ln.strip() for ln in (proc.stdout + proc.stderr).splitlines()
            if ln.strip().startswith("tests/") and ln.strip().endswith(".py")}


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
    batch = _batch_resolutions(root)
    if module_path in batch:
        return batch[module_path]
    proc = subprocess.run(
        ["bash", "tools/fast-gate.sh"],
        cwd=root,
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_CHANGED": module_path, "FAST_GATE_DRY_RUN": "1"},
        timeout=_GATE_CLI_GUARD_S,
    )
    out = proc.stdout + proc.stderr
    return {ln.strip() for ln in out.splitlines() if ln.strip().startswith("tests/") and ln.strip().endswith(".py")}


def _lib_modules(root=None):
    """The TRACKED direct-child modules of lib/ - the module set this mirror asks the gate about.

    agents-37rj: this was a filesystem glob, the last walker of the agents-4ieg class in this module, and
    its answer feeds BOTH the gate dry run in test_a_consumer_the_gate_does_not_select_must_be_allowlisted
    AND the mirror-versus-oracle comparison (three call sites) - so an untracked file under lib/ widened
    BOTH SIDES of a comparison whose whole value is that they are two independent views of one tree.
    Measured: an untracked lib/zz37rj_probe.py took this from 21 modules to 22, while the two sides were
    supposed to disagree only about what they can see of the SAME tree. Read git's index instead, which is
    the set the gate witnesses.
    """
    root = root or ROOT
    if has_git_index(root):
        # tracked_paths takes a GIT PATHSPEC, in which `*` crosses `/` - `lib/*.py` also matches
        # lib/bench/runner.py (measured) - so ask for the directory and keep direct children here.
        lib = root / "lib"
        stems = {p.stem for p in tracked_paths("lib", root=root)
                 if p.suffix == ".py" and len(p.relative_to(lib).parts) == 1}
        return sorted(stem for stem in stems if stem != "__init__")
    # A SYNTHETIC root built by a fixture is not inside a work tree, so there is no index to ask, and the
    # filesystem is then the WHOLE tree rather than a second, wider notion of it (see has_git_index).
    return sorted(p.stem for p in (root / "lib").glob("*.py") if p.stem != "__init__")


class TestAllowlistFragmentsAreConfigurationFromTheTree(unittest.TestCase):
    """agents-2it3: the fragment set is CONFIGURATION, so it is read from git's index, not the filesystem.

    THE PAIR IS THE POINT, and coord asked for it explicitly: 'the untracked fragment was not loaded' is also
    what a loader that loaded NOTHING would report, so the negative direction here is asserted TOGETHER with
    the direction that proves the reader still loads what it should. Both directions are measured against a
    direct 'git ls-files' read of the same directory, which is an independent instrument rather than the one
    under test.

    THE OTHER HALF OF THE DEFECT, which the count alone does not capture: this loader deliberately fails
    LOUDLY on a fragment that does not parse (agents-nerv - silently skipping one is how an omission stops
    being guarded). With a filesystem walker that made an uncommitted, malformed file able to fail the whole
    module AT IMPORT; measured, it raised 'AssertionError: zz_bad_tmp.json: not valid JSON (...)'.
    """

    VALID = '{"kind": "consumer_coverage", "modules": {"zz_probe": ["tests/test_probe.py"]}}'

    def _scratch_fragments(self, root):
        """Stage one known fragment in an isolated Git index; never plant guard input in ROOT."""
        fragments = root / "tests" / "fast_gate_allowlists.d"
        fragments.mkdir(parents=True)
        tracked = fragments / "consumer_coverage.json"
        tracked.write_text(self.VALID + "\n", encoding="utf-8")
        subprocess.run(["git", "-c", "init.defaultBranch=main", "init", "-q", str(root)],
                       check=True, capture_output=True, timeout=_LOCAL_GIT_GUARD_S)
        subprocess.run(["git", "-C", str(root), "add", "--",
                        "tests/fast_gate_allowlists.d/consumer_coverage.json"],
                       check=True, capture_output=True, timeout=_LOCAL_GIT_GUARD_S)
        return fragments, tracked

    def _tracked_fragment_names(self, root=ROOT):
        """The tracked .json fragments, read independently of the loader (a direct git call)."""
        listed = subprocess.run(
            ["git", "-C", str(root), "ls-files", "tests/fast_gate_allowlists.d"],
            capture_output=True, text=True, check=True, timeout=_LOCAL_GIT_GUARD_S,
        ).stdout.splitlines()
        return sorted(Path(name).name for name in listed if name.endswith(".json"))

    def test_an_untracked_fragment_is_not_configuration_and_the_tracked_ones_still_are(self):
        with tempfile.TemporaryDirectory(prefix="allowlist-fragments-") as tmp:
            root = Path(tmp)
            fragments, tracked = self._scratch_fragments(root)
            probe = fragments / "zz_untracked_probe_tmp.json"
            probe.write_text(self.VALID + "\n", encoding="utf-8")
            loaded = _allowlist_fragments(root)
            self.assertNotIn(
                probe, loaded,
                "an UNCOMMITTED file in the allowlist directory was read as configuration, so a file nobody "
                "reviewed can add an exemption (agents-2it3)",
            )
            self.assertEqual(loaded, [tracked], "the reader must still load tracked configuration")
            self.assertEqual([p.name for p in loaded], self._tracked_fragment_names(root))
            ignored = _untracked_allowlist_fragments(root, tracked=loaded)
            self.assertEqual(ignored, [probe])
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                _report_untracked_allowlist_fragments(ignored, root)
            self.assertEqual(out.getvalue(), "", "stdout is the fleet oracle's marker channel")
            self.assertEqual(err.getvalue().count("zz_untracked_probe_tmp.json"), 1)
            self.assertIn("not loaded", err.getvalue())

    def test_an_untracked_malformed_fragment_cannot_fail_the_loader_at_import(self):
        with tempfile.TemporaryDirectory(prefix="allowlist-fragments-") as tmp:
            root = Path(tmp)
            fragments, tracked = self._scratch_fragments(root)
            probe = fragments / "zz_untracked_bad_tmp.json"
            probe.write_text("{ this is not json\n", encoding="utf-8")
            with self.assertRaises(json.JSONDecodeError):
                json.loads(probe.read_text(encoding="utf-8"))
            self.assertEqual(_allowlist_fragments(root), [tracked],
                             "an uncommitted malformed fragment must not be parsed")
            ignored = _untracked_allowlist_fragments(root, tracked=[tracked])
            self.assertEqual(ignored, [probe])
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                _report_untracked_allowlist_fragments(ignored, root)
            self.assertEqual(err.getvalue().count("zz_untracked_bad_tmp.json"), 1)

    def test_a_normal_tracked_run_reports_no_untracked_fragment(self):
        with tempfile.TemporaryDirectory(prefix="allowlist-fragments-") as tmp:
            root = Path(tmp)
            _, tracked = self._scratch_fragments(root)
            self.assertEqual(_allowlist_fragments(root), [tracked])
            ignored = _untracked_allowlist_fragments(root, tracked=[tracked])
            self.assertEqual(ignored, [])
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                _report_untracked_allowlist_fragments(ignored, root)
            self.assertEqual(err.getvalue(), "", "a normal tracked run must be silent")

    def test_a_non_git_root_has_no_untracked_fragment_distinction(self):
        with tempfile.TemporaryDirectory(prefix="allowlist-no-git-") as tmp:
            root = Path(tmp)
            fragments = root / "tests" / "fast_gate_allowlists.d"
            fragments.mkdir(parents=True)
            only = fragments / "consumer_coverage.json"
            only.write_text(self.VALID + "\n", encoding="utf-8")
            self.assertEqual(_allowlist_fragments(root), [only])
            self.assertEqual(_untracked_allowlist_fragments(root), [])

    def test_teardown_reports_import_time_stray_once(self):
        with tempfile.TemporaryDirectory(prefix="allowlist-fragments-") as tmp:
            root = Path(tmp)
            fragments, _ = self._scratch_fragments(root)
            stray = fragments / "zz_untracked_probe_tmp.json"
            stray.write_text(self.VALID + "\n", encoding="utf-8")
            out, err = io.StringIO(), io.StringIO()
            module = sys.modules[__name__]
            with mock.patch.object(module, "_UNTRACKED_ALLOWLIST_FRAGMENTS_AT_IMPORT", [stray]), \
                    mock.patch.object(module, "ROOT", root), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                tearDownModule()
            self.assertEqual(out.getvalue(), "", "never write into the stdout marker channel")
            self.assertEqual(err.getvalue().count("zz_untracked_probe_tmp.json"), 1)

    def test_imports_the_tracked_file_instrument_only_once(self):
        """agents-bz4m: keep the documented import, not the bare rebase duplicate."""
        source = Path(__file__).read_text(encoding="utf-8")
        imports = [node for node in ast.walk(ast.parse(source))
                   if isinstance(node, ast.ImportFrom) and node.module == "tests"]
        self.assertEqual(len(imports), 1, "the same names must be imported from tests only once")
        self.assertEqual({alias.name for alias in imports[0].names}, {"has_git_index", "tracked_paths"})
        self.assertIn("a fragment is CONFIGURATION",
                      "\n".join(source.splitlines()[imports[0].lineno - 4:imports[0].lineno - 1]),
                      "keep the commented import, not the bare duplicate")

    def test_a_malformed_TRACKED_fragment_still_fails_loudly(self):
        """The teeth agents-nerv added must survive: a fragment that IS configuration and does not parse
        must name itself and stop the merge, rather than being skipped into a quietly smaller allowlist.

        The malformed file lives in a temp dir and is handed to the merge through the same seam the loader
        uses, so this asserts the BEHAVIOUR without staging a file in the repository's index.
        """
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "zz_bad_fragment.json"
            bad.write_text("{ this is not json\n", encoding="utf-8")
            with mock.patch.object(sys.modules[__name__], "_allowlist_fragments", return_value=[bad]):
                with self.assertRaises(AssertionError) as ctx:
                    _load_allowlist_fragments()
        self.assertIn(bad.name, str(ctx.exception),
                      "the failure must name the fragment a reader has to fix")

    def test_the_allowlist_still_merges_real_content(self):
        """The cheapest positive control of all: the merged allowlist this module gates on is not empty, so
        the fragment reader is demonstrably parsing configuration that carries entries."""
        self.assertTrue(CONSUMER_COVERAGE_ALLOWLIST or NON_SUITE_CONSUMERS,
                        "the merged allowlist is empty: the fragment reader is not reading configuration")
        self.assertTrue(set(_ALLOWLIST_PROVENANCE.values()) <= set(self._tracked_fragment_names()),
                        "every provenance entry must name a TRACKED fragment")


class TestTheAllowlistPointsAtItsDocumentedReasons(unittest.TestCase):
    """agents-1mz0: the ADR records WHY the assertion-consumer class and its exclusions exist, but a
    reader who lands on the allowlists had no pointer to it. This guards DISCOVERABILITY only - the
    allowlist itself still carries no reasons, which is deliberate (agents-02s9): a reason that cannot be
    written down wrong is the gate's own measured answer, and the prose reasons live in the ADR."""

    ADR = "docs/adr/0001-fast-gate-coverage-tiers.md"
    SECTION = "### The Assertion-Consumer Class: When an Importer Is Not a Consumer"

    def test_the_allowlist_directory_names_the_adr(self):
        """A reader inspecting tests/fast_gate_allowlists.d/ must be able to find the reasons."""
        pointer = _ALLOWLIST_DIR / "README.md"
        self.assertTrue(pointer.is_file(), f"{pointer} must exist and point at the ADR")
        self.assertIn(self.ADR, pointer.read_text(encoding="utf-8"))

    def test_this_test_file_names_the_adr(self):
        """The criterion lives here as well as in the arm, so the pointer must too."""
        src = Path(__file__).read_text(encoding="utf-8")
        self.assertIn(self.ADR, src)

    def test_the_pointer_names_a_section_that_exists(self):
        """A pointer to a heading that has been renamed is worse than none: it reads as authoritative."""
        adr = ROOT / self.ADR
        self.assertTrue(adr.is_file(), f"{self.ADR} must exist")
        text = adr.read_text(encoding="utf-8")
        self.assertIn(self.SECTION, text, "the ADR heading the pointer names must still exist")
        for excluded in ("tests/test_sinks.py", "tests/test_gen_site.py"):
            self.assertIn(excluded, text, f"the exclusion {excluded} must stay documented in the ADR")


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
            subprocess.run(["git", "init", "-q"], cwd=fake, check=True, timeout=_LOCAL_GIT_GUARD_S)
            subprocess.run(["git", "add", "."], cwd=fake, check=True, timeout=_LOCAL_GIT_GUARD_S)
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

    def test_untracked_debris_is_not_absorbed_by_consumer_coverage(self):
        """A check must read git's objects rather than the filesystem (agents-jcd2).

        Untracked debris left under tests/ by an interrupted run must not be absorbed
        into the consumer set or the oracle's importers.
        """
        probe = ROOT / "tests" / "test_zz_debris_probe_tmp.py"
        probe.write_text("import unittest\nfrom lib import child_env\n", encoding="utf-8")
        try:
            _importing_suites.cache_clear()
            importers = _importing_suites("child_env")
            self.assertNotIn("tests/test_zz_debris_probe_tmp.py", importers)
            self.assertIn("tests/test_containment.py", importers)
            if _FLEET_ORACLE.exists():
                oracle = _load_oracle()
                oracle_importers = _oracle_importers(oracle, "child_env", suites_only=False)
                self.assertNotIn("tests/test_zz_debris_probe_tmp.py", oracle_importers)
                self.assertIn("tests/test_containment.py", oracle_importers)
        finally:
            probe.unlink(missing_ok=True)
            _importing_suites.cache_clear()

    def test_untracked_debris_is_not_absorbed_by_the_arm_registry_reader(self):
        """The arms half of the check above (agents-jwn9, found while fixing agents-ncue).

        _arm_registry_text answers "does this module have an arm of its own?" for the allowlist reasons,
        and it answered by globbing the registry directory. An untracked fragment whose body contains a
        matching pattern therefore answers that question with a green - and tools/fast-gate.sh SOURCES
        every *.sh it finds (agents-es0y), so a stray is code the gate would execute.

        The probe is built in a SYNTHETIC, git-initialised root. A fixture that wrote a stray *.sh into
        the live registry would itself be the hazard it is testing for.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            arms = root / "tools" / "fast-gate-arms.d"
            arms.mkdir(parents=True)
            (arms / "010-tracked.sh").write_text("case TRACKED_FRAGMENT in\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q", str(root)], check=True, timeout=_LOCAL_GIT_GUARD_S)
            subprocess.run(
                ["git", "-C", str(root), "add", "tools/fast-gate-arms.d/010-tracked.sh"],
                check=True, timeout=_LOCAL_GIT_GUARD_S,
            )
            self.assertIn(
                "TRACKED_FRAGMENT", _arm_registry_text(root),
                "a fragment git's index sees must be read: without this, the assertion below could pass "
                "for a reader that enumerates nothing at all",
            )
            (arms / "999-stray.sh").write_text("case STRAY_FRAGMENT in\n", encoding="utf-8")
            self.assertNotIn(
                "STRAY_FRAGMENT", _arm_registry_text(root),
                "an UNTRACKED fragment must not enter the registry text: it answers this reader's question "
                "with a green while the gate treats every *.sh it finds as code (agents-jwn9, agents-es0y)",
            )

    def test_a_consumer_the_gate_does_not_select_must_be_allowlisted(self):
        failures = []
        for module in _lib_modules():
            path = f"lib/{module}.py"
            omitted = _importing_suites(module) - _selected_suites(path)
            allowed = set(CONSUMER_COVERAGE_ALLOWLIST.get(module, {}))
            unlisted = sorted(omitted - allowed)
            if unlisted:
                detail = "\n  ".join(_why_omitted(module, s) for s in unlisted)
                failures.append(
                    f"{path} omits {len(unlisted)} consumer(s) and they are not in the allowlist:\n  "
                    f"{detail}\nFix the arm in tools/fast-gate.sh, or add each suite to "
                    f"a fragment in tests/fast_gate_allowlists.d/ - its exemption is then explained by the same "
                    f"measurement (agents-pdth)."
                )
        self.assertEqual(failures, [], "\n".join(failures))

    def test_the_allowlist_has_no_stale_entries(self):
        """An entry that is no longer an omission must FAIL, or the list only ever grows."""
        stale = []
        for module, entries in CONSUMER_COVERAGE_ALLOWLIST.items():
            omitted = _importing_suites(module) - _selected_suites(f"lib/{module}.py")
            for suite in entries:
                if suite not in omitted:
                    still_runs = [s.split("/")[-1] for s in sorted(_selected_suites(f"lib/{module}.py"))]
                    stale.append(
                        f"{_fragment_declaring('consumer_coverage', module, suite)} declares "
                        f"{module} -> {suite}, and that entry is STALE: the gate now "
                        f"selects it, or the suite no longer imports the module. For that file the gate "
                        f"selects {still_runs}. Delete the entry so the list shrinks (agents-pdth)."
                    )
        self.assertEqual(stale, [], "\n".join(stale))


# The non-suite consumers, ASSERTED rather than described (agents-tuz8). The mirror is deliberately
# broader than the oracle: a helper that imports a lib module is still a consumer, because the gate cannot
# run it but a change to that module still breaks it. This is that difference, pinned - a sixth module
# gaining a helper consumer, or a new helper appearing, fails here rather than quietly widening the claim.
# NON_SUITE_CONSUMERS is loaded from tests/fast_gate_allowlists.d/ together with the allowlist
# above, so a lane widening the mirror drops its own fragment instead of editing this file.


class TestTheResolveModeAnswersManyPathsInOneInvocation(unittest.TestCase):
    """agents-wzmj (F1): one startup answers the mapping for every path, instead of one per path.

    The saving is real only if the ANSWER is real, so what is pinned here is not that the mode was asked
    for but that it replied - a mode that is silently inert costs the saving without anybody noticing,
    because the per-path fallback keeps every other test green.
    """

    def test_the_batch_answer_equals_the_per_path_dry_run(self):
        """THE EQUIVALENCE, on the real module set: the batch says exactly what the union dry run says for
        each path alone. Without this the mode could return a plausible set and be wrong."""
        batch = _batch_resolutions()
        modules = sorted(_lib_modules())
        self.assertTrue(modules, "no lib/ modules: the equivalence below would pass vacuously")
        self.assertEqual(sorted(batch), [f"lib/{module}.py" for module in modules],
                         "every module must be ANSWERED by the one invocation; an unanswered module means "
                         "the mode is inert and the caller is silently on the slow path again")
        for module in modules[:5]:
            path = f"lib/{module}.py"
            self.assertEqual(_raw_dry_run_union(path), batch[path],
                             f"the batch answer for {path} must be what the union dry run selects")

    # agents-1v6ap: the cross-class equivalence sample. The lib/ modules sampled by the pin above carry
    # NEITHER a retention add-on NOR a self-run in their records - the very components agents-kw7wl
    # changed (a record became the path's OWN suites + retention add-on + self-run, and the ':always'
    # line dropped $run to tiers only). A record-vs-raw divergence on tools/ or tests/ paths was
    # invisible to this module, because its content pins read THROUGH the cache. Each sample carries a
    # record component the lib class lacks:
    #   tools/fast-gate.sh      - retention add-on (tools class) on the gate's own multi-suite arm
    #   tools/red-first.sh      - retention add-on on a .sh path outside tests/
    #   tests/test_red_first.py - self-run: the record must carry the changed file itself (run=$f)
    # Measured cost of the pin: one batch startup (3.8s) + three raw dry runs (~3s each) on a quiet
    # box; agents/*.py was left out of the sample deliberately - it would add ~3s to this always-on
    # suite to carry the SAME retention add-on tools/red-first.sh already pins, through an arm whose
    # mapped-set semantics are the lib class's own.
    _CROSS_CLASS_SAMPLE = ("tools/fast-gate.sh", "tools/red-first.sh", "tests/test_red_first.py")

    def test_the_batch_answer_equals_the_per_path_dry_run_across_record_classes(self):
        """THE EQUIVALENCE beyond lib/ (agents-1v6ap): for the classes whose record content agents-kw7wl
        changed, the batch record plus ':always' must equal what the union dry run selects for the path
        alone. The marker assertions below are what make this a measurement of THOSE classes: without
        the retention add-on and the self-run actually riding in the records, the equalities would
        degrade to the lib-class semantics the pin above already covers - two sets agreeing because
        neither carries the components that changed."""
        batch = _resolve_batch(self._CROSS_CLASS_SAMPLE)
        self.assertEqual(sorted(batch), sorted(self._CROSS_CLASS_SAMPLE),
                         "every sampled path must be ANSWERED by the one invocation; an unanswered "
                         "path means the mode is inert for that class and this pin is vacuous")
        for path in self._CROSS_CLASS_SAMPLE:
            self.assertEqual(_raw_dry_run_union(path), batch[path],
                             f"the batch record for {path} must be what the union dry run selects for "
                             "it alone - retention add-on and self-run included")
        self.assertIn("tests/test_retention.py", batch["tools/red-first.sh"],
                      "the retention add-on must ride in a tools/ record, else this sample is lib-class "
                      "and the pin above already covered it")
        self.assertIn("tests/test_red_first.py", batch["tests/test_red_first.py"],
                      "the self-run must ride in a changed test file's own record (':always' is tiers "
                      "only since agents-kw7wl), else this sample is lib-class too")

    def test_a_batch_that_did_not_answer_is_not_trusted(self):
        """The pairing that makes the test above a measurement: a refused run and a run that printed
        per-path lines but no ':always' line must BOTH mean 'ask per path', because answering from either
        would return sets missing the tier pins - a wrong answer shaped exactly like a right one."""
        self.assertEqual(_parse_resolutions("lib/a.py\ttests/test_b.py\n", 1), {},
                         "a refused batch must not be answered from")
        self.assertEqual(_parse_resolutions("lib/a.py\ttests/test_b.py\n", 0), {},
                         "per-path lines without the ':always' line are not an answer")
        parsed = _parse_resolutions("lib/a.py\ttests/test_b.py\n:always\ttests/test_tree_guards.py \n", 0)
        self.assertEqual(parsed, {"lib/a.py": {"tests/test_b.py", "tests/test_tree_guards.py"}},
                         "and a complete answer IS parsed, so the two refusals above are not a parser "
                         "that returns nothing for everything")


def _load_oracle():
    spec = importlib.util.spec_from_file_location("_fleet_check_coverage", _FLEET_ORACLE)
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    return oracle


def _oracle_importers(oracle, module, suites_only):
    """What the ORACLE's rule says, optionally restricted to the files it calls suites."""
    found = set()
    for path in _tracked_test_files(ROOT):
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


def _literal_timeout_bounds(source):
    """Every timeout bound in `source` that is a VALUE rather than a reference to a named constant.

    AST, NOT A REGEX (agents-cygm4). The regex this replaces governed only the spellings it
    enumerated, so a reviewer-measured `timeout=(60)` - the exact shape Black produces when it
    splits a long call - passed the guard in silence, as did a wrapped `timeout=\n    (60)`. A
    spelling list can always be walked around; the tree cannot. Parentheses, line breaks,
    arithmetic (`timeout=30 * 2`), f-strings and `**{...}` spreads all collapse to the same node,
    so the contract below is one rule instead of a growing list of patterns. Every spelling is
    pinned as a mutant in TestTheTimeoutGuardItself.

    Prose is not counted (the agents-kevst lesson, done exactly): the regex era could only
    approximate that by dropping full-line comments, so a literal quoted in a docstring still
    tripped it. A string is not a bound - what this pins is executable code, and the AST is
    precisely that.

    `timeout` must be a bare `ast.Name` (the module-level constant). A `Name` holding a computed
    local would pass too, which is the line drawn here: the point is that the bound is NAMED and
    sited, not that its arithmetic is re-checked by the test.
    """
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call):
            for keyword in node.keywords:
                if keyword.arg == "timeout" and not isinstance(keyword.value, ast.Name):
                    found.append(ast.unparse(keyword.value))
        elif isinstance(node, ast.Dict):
            # The dict-spread spelling: `**{"check": True, "timeout": 60}`. Walking every dict
            # also catches a bounds dict built on one line and spread on the next, which the
            # regex (like the spread it targeted) could not follow.
            for key, value in zip(node.keys, node.values):
                if (
                    isinstance(key, ast.Constant)
                    and key.value == "timeout"
                    and not isinstance(value, ast.Name)
                ):
                    found.append(ast.unparse(value))
    return sorted(found)


class TestGateCliTimeoutPolicy(unittest.TestCase):
    """Bounds on this file's subprocess calls are sized from measurement, once PER CALL CLASS
    (agents-4jqna, agents-5bpe4): _GATE_CLI_GUARD_S for tools/fast-gate.sh invocations,
    _LOCAL_GIT_GUARD_S for local git plumbing.

    The third instance of the same drift in one week, after the beads-sink bound (agents-0qyjo) and
    CHECK_FAST_TIMEOUT: a literal per-call bound sized on a quiet box reddens a healthy gate under
    load. This module is part of the gate's own coverage contract, so when it flakes the gate
    reddens on itself."""

    def test_no_literal_timeout_remains_in_this_file(self):
        """A reintroduced literal is how a file ends up with several bounds for the same CLI.

        The contract (agents-5bpe4): NO numeric timeout VALUE may appear in this file's code;
        every subprocess bound references a module-level named constant, one per call class -
        _GATE_CLI_GUARD_S for tools/fast-gate.sh invocations, _LOCAL_GIT_GUARD_S for local git
        plumbing.

        THE SCAN IS AST-BASED, NOT A REGEX (agents-cygm4). The regex era enumerated spellings:
        'timeout = NN' (agents-aau00) and the quoted dict KEY (agents-5bpe4) were each added after
        a reviewer-measured mutant, and the next mutant - `timeout=(60)`, the exact shape Black
        produces when it splits a long call - still passed in silence while this docstring claimed
        "NO bare numeric timeout literal". A spelling list invites the next counter-example; the
        AST does not have one, because every parenthesised, wrapped, computed or spread spelling is
        the same node it already rejects. The mutants are pinned as data in
        TestTheTimeoutGuardItself, so this green is only green while a reintroduced literal reddens it.
        """
        source = (ROOT / "tests" / "test_fast_gate_consumer_coverage.py").read_text(encoding="utf-8")
        literals = _literal_timeout_bounds(source)
        self.assertEqual(
            literals, [],
            "every subprocess bound in this file must reference a named constant - "
            "_GATE_CLI_GUARD_S for tools/fast-gate.sh invocations, _LOCAL_GIT_GUARD_S for local "
            f"git plumbing; found bare literal timeout(s) {literals}. Re-inlining one is how three "
            "call sites for the SAME gate invocation ended up sharing one quiet-box opinion "
            "(agents-4jqna), and a literal on a local git call would be sized by the wrong class "
            "entirely (agents-5bpe4)")

    def test_the_guard_still_covers_the_worst_measured_run(self):
        """Not a number chosen for looks: it is a multiple of a measurement, and the message says which.

        And it has a CEILING (agents-5bpe4): the lower pin alone let the bound creep - a future
        edit could declare 1200 (half the tracked fast-gate budget) and still pass 'at least 3x'.
        One gate invocation may not eat more than a quarter of the whole gate's budget:
        CHECK_FAST_TIMEOUT is 2400s (docs/speed.md), so the ceiling is 600s.
        """
        self.assertGreaterEqual(
            _GATE_CLI_GUARD_S, 3 * _WORST_MEASURED_GATE_CLI_S,
            f"_GATE_CLI_GUARD_S={_GATE_CLI_GUARD_S} has less than 3x headroom over the worst measured "
            f"batch-resolve run ({_WORST_MEASURED_GATE_CLI_S}s at load 6.37); the gate reddens on a "
            "busy box long before a real hang, which is what agents-4jqna was")
        self.assertLessEqual(
            _GATE_CLI_GUARD_S, 600,
            f"_GATE_CLI_GUARD_S={_GATE_CLI_GUARD_S} exceeds a quarter of the tracked fast-gate budget "
            "(CHECK_FAST_TIMEOUT=2400s, docs/speed.md): one wedged gate CLI could then eat the whole "
            "gate's budget (agents-5bpe4). If a measurement genuinely demands more, the fix is the "
            "gate's startup cost (agents-kw7wl), not this bound.")

    def test_the_local_git_bound_is_its_own_class(self):
        """agents-5bpe4: the local-git guard is sized from its OWN measurement and stays far below
        the gate CLI's bound - the two classes must not converge, or bounding a local call would
        again mean borrowing the gate's number (the old false-red), and a wedged fixture git would
        be indistinguishable in cost from a wedged gate CLI."""
        self.assertGreaterEqual(
            _LOCAL_GIT_GUARD_S, 3 * _WORST_MEASURED_LOCAL_GIT_S,
            f"_LOCAL_GIT_GUARD_S={_LOCAL_GIT_GUARD_S} has less than 3x headroom over the worst "
            f"measured local git call ({_WORST_MEASURED_LOCAL_GIT_S}s: git ls-files tests, cold, "
            "this VM)")
        self.assertLess(
            _LOCAL_GIT_GUARD_S, _GATE_CLI_GUARD_S,
            f"_LOCAL_GIT_GUARD_S={_LOCAL_GIT_GUARD_S} must stay below "
            f"_GATE_CLI_GUARD_S={_GATE_CLI_GUARD_S}: local git plumbing is sub-0.1s work and must "
            "never be sized by the gate CLI's O(startup) measurement (agents-5bpe4)")


class TestTheTimeoutGuardItself(unittest.TestCase):
    """The no-literal guard is only worth its green if a reintroduced literal reddens it.

    agents-cygm4: the regex guard was widened twice (agents-aau00, agents-5bpe4) and each widening
    was found by a REVIEWER-MEASURED mutant rather than by the test itself, which is the tell that
    the guard had no mutants of its own. Each spelling below is a specific counter-example that
    either slipped past the regex era or that the AST earns for free; they are data, so widening
    or narrowing the guard means editing a case here instead of reasoning about a pattern.
    """

    CAUGHT = {
        "bare literal": "run(cmd, timeout=60)",
        "spaced assignment": "run(cmd, timeout = 60)",
        "float literal": "run(cmd, timeout=0.5)",
        # The mutant that opened agents-cygm4: parenthesised, and the Black-split shape of it.
        "parenthesised": "run(cmd, timeout=(60))",
        "black-split": "run(\n    cmd,\n    check=True,\n    timeout=(\n        60\n    ),\n)",
        "expression": "run(cmd, timeout=30 * 2)",
        "dict-spread": 'run(cmd, **{"check": True, "timeout": 60})',
        "dict-built-then-spread": 'bounds = {"timeout": 60}\nrun(cmd, **bounds)',
    }

    ALLOWED = {
        "named constant": "run(cmd, timeout=_LOCAL_GIT_GUARD_S)",
        "named constant in a dict": (
            'run(cmd, **{"check": True, "timeout": _GATE_CLI_GUARD_S})'
        ),
        # Prose is not a bound: the regex era could only approximate that by dropping comment
        # lines, so a docstring quoting a literal tripped it.
        "prose": 'MESSAGE = "call it with timeout=60 next time"',
    }

    def test_every_measured_mutant_is_caught(self):
        """A guard that misses its mutant is no guard at all - so the mutants live here as tests."""
        for spelling, snippet in self.CAUGHT.items():
            with self.subTest(spelling=spelling):
                self.assertTrue(
                    _literal_timeout_bounds(snippet),
                    f"the timeout guard is silent on the '{spelling}' spelling: {snippet!r}. This "
                    "is exactly the agents-cygm4 gap (a parenthesised literal passed a regex that "
                    "claimed to forbid every bare literal) - fix the guard, not this assertion",
                )

    def test_named_constants_and_prose_stay_clean(self):
        """The guard must be precise as well as complete, or it reddens on correct code."""
        for case, snippet in self.ALLOWED.items():
            with self.subTest(case=case):
                self.assertEqual(
                    _literal_timeout_bounds(snippet),
                    [],
                    f"{case} must not be flagged: {snippet!r}",
                )


def tearDownModule():
    """Publish the import-time discovery once near the receipt tail, never on stdout.

    The gate's arm reporter also puts warnings at the end: warnings only at import
    would disappear from the tail a lane reads. Normal tracked runs emit nothing.
    """
    _report_untracked_allowlist_fragments(_UNTRACKED_ALLOWLIST_FRAGMENTS_AT_IMPORT, root=ROOT)


if __name__ == "__main__":
    unittest.main()
