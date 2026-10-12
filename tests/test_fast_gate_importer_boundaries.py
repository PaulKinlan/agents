"""Two importer-shaped boundaries that a future "name every importer" rule must NOT 'fix'.

agents-6vev, filed from agents-bwbe's review. The durable home for a finding that could not go in
that commit's body: amending it would void a cached gate verdict and two cross-family reviews.

THE QUESTION THIS PINS. When a reader asks "does the lib/egress_proxy.py) arm in tools/fast-gate.sh
name every file that mentions this module?", the answer is NOT "add the rest". Across tests/*.py,
SIXTEEN files mention 'egress_proxy' and EIGHT of them are import-shaped (seven matching the dotted
lib.egress_proxy form plus tests/test_egress_proxy.py, which uses `from lib import egress_proxy`).
The arm that landed with agents-bwbe names SEVEN. Exactly TWO files are deliberately outside it, and
each for a different reason:

  1. tests/containment_harness.py IMPORTS lib.egress_proxy and is NOT a test suite - it is a
     fixture, so the coverage oracle's is_test_filename() excludes it. Adding it to a suite-running
     arm would RUN A FIXTURE AS IF IT WERE A SUITE. It does not need the arm anyway: it has its OWN
     arm in tools/fast-gate.sh for changes TO it, which is the right place for a shared helper.
  2. tests/test_retention.py does NOT import lib.egress_proxy. It holds a TEXTUAL deletion-inventory
     entry for a socket unlink inside that module, so no import-graph rule can ever name it - by
     construction, not by omission. The instrument that covers the inventory is the FULL gate
     (`python3 -m unittest discover -s tests`), which runs it on every landing.

WHY THIS IS A TEST RATHER THAN A COMMENT. A comment saying "do not add these" is a claim with no
failure mode; these assertions fail if either boundary is closed up, and each failure names which
one and why it was deliberate. If a future editor strengthens the arm - or adds the general rule
agents-pdth is building - these tests say which two files to exclude and on what evidence.

DELIBERATELY INDEPENDENT OF THE ARM: every assertion here holds on a tree where the dedicated
lib/egress_proxy.py) arm does not exist yet, so this file neither depends on agents-bwbe landing nor
turns red while it is in review. What it pins is the SHAPE of the exclusion, not the arm's contents.
"""

import ast
import unittest
from pathlib import Path

from tests.test_fast_gate_consumer_coverage import _load_oracle
from tests.test_fast_gate_mapping import resolve_fast_gate

ROOT = Path(__file__).resolve().parent.parent
MODULE = "lib/egress_proxy.py"
HARNESS = "tests/containment_harness.py"
INVENTORY = "tests/test_retention.py"


def _imports_module(path, module):
    """True if path imports module - the oracle's own notion of a consumer."""
    stem = module.split("/")[-1].removesuffix(".py")
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(a.name in (module.removesuffix(".py"), f"lib.{stem}") for a in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.replace("/", ".").endswith(stem):
                return True
    return False


class TestImporterShapedBoundaries(unittest.TestCase):
    def test_the_fixture_is_not_a_suite_so_it_must_never_join_a_suite_running_arm(self):
        oracle = _load_oracle()
        self.assertFalse(
            oracle.is_test_filename(HARNESS),
            f"{HARNESS} is a fixture, not a suite. If this ever becomes True it will be collected "
            f"by discovery AND run as a suite by any arm that names it - the reason agents-6vev "
            f"keeps it out of the lib/egress_proxy.py) arm.",
        )
        self.assertTrue(
            _imports_module(HARNESS, MODULE),
            f"{HARNESS} is one of the import-shaped consumers of {MODULE} - which is exactly why it "
            f"is tempting to add to that arm, and why the exclusion needs saying out loud",
        )
        gate = (ROOT / "tools" / "fast-gate.sh").read_text(encoding="utf-8")
        self.assertIn(
            f"{HARNESS})",
            gate,
            f"{HARNESS} must keep its OWN arm in tools/fast-gate.sh: a shared fixture is covered by "
            f"changes TO it, not by every module whose arm might be tempted to include it "
            f"(agents-6vev)",
        )

    def test_the_inventory_reference_is_text_so_no_import_rule_can_name_it(self):
        self.assertFalse(
            _imports_module(INVENTORY, MODULE),
            f"{INVENTORY} must not import {MODULE}: its reference is a TEXTUAL deletion-inventory "
            f"entry for a socket unlink. If it ever gains a real import, this boundary has moved "
            f"and the fast arm may legitimately need it (agents-6vev).",
        )
        source = (ROOT / INVENTORY).read_text(encoding="utf-8")
        self.assertIn(
            MODULE,
            source,
            f"{INVENTORY} is expected to MENTION {MODULE} in its inventory - it is the textual "
            f"reference this test exists to describe, not a missing import",
        )

    def test_the_selection_for_the_module_names_neither_boundary(self):
        """The rule stated as behaviour: neither excluded file may come out of the selection."""
        selected = resolve_fast_gate([MODULE])
        self.assertNotIn(
            HARNESS,
            selected,
            f"a change to {MODULE} must never select {HARNESS}: it is a fixture, and any arm that "
            f"runs it is running a suite that does not exist (agents-6vev)",
        )
        self.assertNotIn(
            INVENTORY,
            selected,
            f"a change to {MODULE} must never select {INVENTORY}: it does not import the module, "
            f"and selecting it for every egress change would spend full-gate time on the fast path "
            f"(agents-6vev)",
        )
        self.assertIn(
            "tests/test_egress_proxy.py",
            selected,
            f"the boundary must not be mistaken for removing the module's own suite: the explicit "
            f"arm REPLACES the generic basename arm, so its own suite has to be named there "
            f"(agents-mo75, agents-bwbe)",
        )
