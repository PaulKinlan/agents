#!/usr/bin/env python3
"""agents-8ibx: the fast gate runs its selection as per-module shards, and these are the properties that
shape has to keep.

WHY THE SHAPE CHANGED AT ALL, as a measurement rather than a preference. tools/fast-gate.sh ran its whole
selection as ONE `python3 -u -m unittest`. On an 8-path delta (24 modules, 597 tests) that cost 162.5s of
wall against 67.2s of child CPU - the wall was almost entirely waiting, and against the fleet's 180s fast
bound it left roughly 10% headroom. A run that close to its bound is bound-killed the moment a priority job
arrives, and two such kills held the single heavy slot for their full 210s each while producing no verdict
(agents-s5ug). The unit of parallelism is the TEST MODULE (ADR 0002 / agents-5fy0), which is the shape
tools/full-gate.sh already runs for the full gate; the same selection measured 51.4s of wall at 4 workers
with the same 597 tests at rc=0.

WHAT IS PINNED HERE. Each case is a way the change could be WRONG rather than merely slow:

  * the DRY RUN's stdout is byte-identical at any shard width. That stream is the marker channel
    the external coverage oracle parses, and two assertions in test_fast_gate_mapping.py pin it to exactly the
    suite list - so a runner that leaks one line onto stdout breaks the coverage reader, not just a test.
  * every selected module actually RUNS, and the total is reported. The evidence rule is that an id count
    of 0 fails the run whatever the child's exit code: measured on this toolchain an empty module is caught
    earlier by `unittest`'s own exit 5, so what is pinned here is the observable requirement (the run fails
    and the module is named) rather than which of the two checks fires.
  * a failing module is NAMED, but not in the `fast-gate: failed:` marker: that payload is read token by
    token as SUITE NAMES (agents-lgdv), so the culprit goes on a `fast-gate: FAIL:` diagnostic instead.
  * the worker count cannot be configured into a wrong value: 0 or unset means the default, the default is
    bounded by both this VM's cores and the size of the selection, and a run invoked FROM a shard stays
    serial instead of fanning out again - the outer run already holds the heavy slot.

The fixtures are tiny synthetic unittest packages in their own git repository - the technique
tests/test_full_gate_sharding.py uses for the full gate - so a case costs milliseconds and nothing here
touches the real suite or the real checks directory.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GATE = ROOT / "tools" / "fast-gate.sh"

# A path the registry maps (tools/fast-gate-arms.d/170-findings_suppressions_yaml.sh), so the selection
# under test is the REAL one. The suite list itself is read from the dry run, so an arm change moves this
# test's fixtures along with the registry instead of breaking it.
CHANGED = "findings/suppressions.yaml"

PASSING = "import unittest\n\n\nclass Case(unittest.TestCase):\n    def test_ok(self):\n        self.assertTrue(True)\n"
EMPTY = "import unittest\n\n\nclass Case(unittest.TestCase):\n    \"\"\"This module defines no test methods.\"\"\"\n"
FAILING = "import unittest\n\n\nclass Case(unittest.TestCase):\n    def test_no(self):\n        self.fail('injected red')\n"


class TestFastGateShardsItsSelection(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "tools").mkdir()
        (self.root / "tests").mkdir()
        (self.root / "checks").mkdir()
        shutil.copy2(GATE, self.root / "tools" / "fast-gate.sh")
        shutil.copytree(ROOT / "tools" / "fast-gate-arms.d", self.root / "tools" / "fast-gate-arms.d")
        (self.root / "tests" / "__init__.py").write_text("", encoding="utf-8")
        for cmd in (["git", "init", "-q"], ["git", "config", "user.email", "t@example.com"],
                    ["git", "config", "user.name", "Test"], ["git", "add", "."]):
            subprocess.run(cmd, cwd=self.root, check=True, capture_output=True)

    def _run(self, dry_run=True, **settings):
        env = dict(os.environ, FLEET_CHECKS_DIR=str(self.root / "checks"), GIT_CHANGED=CHANGED)
        env.pop("FAST_GATE_DRY_RUN", None)
        # The runner marks its shard children so a nested gate does not fan out again. This test runs
        # INSIDE a shard when the real gate selects it, so without popping the marker every case below
        # would assert the serial shape instead of the default one. Same reason, same shape, as
        # tests/test_full_gate_sharding.py popping FULL_GATE_SHARD_CHILD.
        env.pop("FAST_GATE_SHARD_CHILD", None)
        if dry_run:
            env["FAST_GATE_DRY_RUN"] = "1"
        env.update({k: str(v) for k, v in settings.items()})
        return subprocess.run(["bash", str(self.root / "tools" / "fast-gate.sh")], cwd=self.root,
                              env=env, capture_output=True, text=True, timeout=120, check=False)

    def _selection(self):
        """The suites the registry selects for CHANGED, asked of the gate rather than hard-coded."""
        proc = self._run()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
        self.assertTrue(lines, "the fixture path must select suites, or every assertion below is vacuous")
        return lines

    def _stub(self, relpath, body=PASSING):
        path = self.root / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        subprocess.run(["git", "add", str(path)], cwd=self.root, check=True, capture_output=True)

    def _with_stubs(self, override=None):
        """Build every selected suite as a tiny module, replacing one of them when asked."""
        selection = self._selection()
        for rel in selection:
            self._stub(rel, (override or {}).get(rel, PASSING))
        return selection

    def test_the_dry_run_stdout_is_byte_identical_whatever_the_shard_width(self):
        selection = self._selection()
        for line in selection:
            self.assertTrue(
                line.startswith("tests/") and line.endswith(".py"),
                f"the dry run's stdout carries suite paths and nothing else: {line!r}",
            )
        default = self._run().stdout
        one = self._run(FAST_GATE_SHARDS=1).stdout
        four = self._run(FAST_GATE_SHARDS=4).stdout
        self.assertEqual(
            one, default,
            "the dry run's stdout is what the external coverage oracle parses and what "
            "test_fast_gate_mapping.py pins to exactly the suite list: sharding must not reach it",
        )
        self.assertEqual(one, four, "the shard width must not change the dry run's stdout either")

    def test_every_selected_module_runs_by_name_and_the_gate_passes(self):
        selection = self._with_stubs()
        proc = self._run(dry_run=False, FAST_GATE_SHARDS=2)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("fast-gate: passed:", proc.stdout, "a passing run still publishes its suites on stdout")
        for rel in selection:
            module = rel[:-3].replace("/", ".")
            self.assertIn(
                f"----- {module} rc=0 ", proc.stderr,
                f"{rel} was selected and must be reported by name: a shard that never reported is a shard "
                "that never ran, and the union check is what makes that visible",
            )
        self.assertNotIn("ids=0 ", proc.stderr, "a module that executed no tests fails even at rc=0")

    def test_a_failing_module_is_named_outside_the_suite_marker(self):
        selection = self._selection()
        failing = selection[0]
        proc = self._run_custom(selection, {failing: FAILING}, FAST_GATE_SHARDS=2)
        self.assertNotEqual(proc.returncode, 0, "a failing module must fail the run")
        markers = [ln for ln in proc.stderr.splitlines() if ln.startswith("fast-gate: failed:")]
        self.assertEqual(len(markers), 1, f"exactly one failure marker: {markers}")
        # The marker's payload is read token by token as suite names (agents-lgdv), so prose there would be
        # published as phantom suites - the defect that comment block exists to prevent. The payload is the
        # dispatched set in MODULE form (`tests.test_x`, which is what the runner receives); the `passed:`
        # marker uses the path form. Either way every token has to be a selected suite.
        dispatched = {rel[:-3].replace("/", ".") for rel in selection}
        for token in markers[0].split(":", 2)[2].split():
            self.assertIn(
                token, dispatched,
                f"the `failed:` marker may name the dispatched suites and nothing else: {token!r}",
            )
        module = failing[:-3].replace("/", ".")
        self.assertIn(
            f"fast-gate: FAIL: shard module failed: {module} (rc=1)", proc.stderr,
            "the culprit is named on a diagnostic line, which is where it can be said without entering the "
            "suite-name vocabulary",
        )

    def test_a_module_that_executes_nothing_fails_and_is_named(self):
        """A module with no test methods must fail the run, and must be named.

        MEASURED, because the first version of this test asserted the wrong mechanism: `python3 -m
        unittest` exits 5 (`NO TESTS RAN`) rather than 0, so on this toolchain the module is caught by its
        exit code and reported by the `shard module failed` line. The runner ALSO tests the evidence -
        an id count of 0 is a failure whatever the exit code was - and that branch does not fire here. It
        stays because the invariant is about the EVIDENCE for a PASS, not about the current semantics of
        an exit code that is not ours to guarantee; what this case pins is the observable requirement.
        """
        selection = self._selection()
        empty = selection[0]
        proc = self._run_custom(selection, {empty: EMPTY}, FAST_GATE_SHARDS=2)
        module = empty[:-3].replace("/", ".")
        self.assertNotEqual(
            proc.returncode, 0,
            "a module that executed no tests must not be reported as a passing run",
        )
        self.assertIn(
            module, proc.stderr,
            "the module that ran nothing is named on a diagnostic line rather than only inside the marker",
        )
        self.assertNotIn("fast-gate: passed:", proc.stdout, "nothing may be published as passed")

    def test_a_nested_run_stays_serial_unless_a_width_is_asked_for(self):
        """A gate invoked from inside a shard defaults to 1 worker, and an explicit width still wins.

        MEASURED MOTIVATION: one own-delta run wrote EIGHT nested summaries into the checks directory,
        because the mapping and consumer-coverage suites invoke the real gate. Before sharding each of
        those nested runs was one process; without this bound a sharded outer run could reach four lanes
        times four nested workers, on a VM whose heavy budget is a single slot.
        """
        selection = self._with_stubs()
        nested = self._run(dry_run=False, FAST_GATE_SHARD_CHILD=1)
        self.assertEqual(nested.returncode, 0, nested.stderr)
        self.assertIn(
            f"{len(selection)} module(s), 1 worker(s)", nested.stderr,
            "a nested gate run is serial: the outer run has already spent the slot's budget",
        )
        explicit = self._run(dry_run=False, FAST_GATE_SHARD_CHILD=1, FAST_GATE_SHARDS=2)
        expected = min(2, len(selection))
        self.assertIn(
            f"{len(selection)} module(s), {expected} worker(s)", explicit.stderr,
            "an explicit FAST_GATE_SHARDS is the operator's decision and still applies",
        )

    def test_the_default_worker_count_is_bounded_by_this_vm_and_by_the_selection(self):
        selection = self._with_stubs()
        proc = self._run(dry_run=False, FAST_GATE_SHARDS=0)
        expected = max(1, min(4, os.cpu_count() or 1, len(selection)))
        self.assertIn(
            f"{len(selection)} module(s), {expected} worker(s)", proc.stderr,
            "0 or unset means the default, and the default is min(4, nproc) bounded by the selection - a "
            "shared VM runs seven lanes and the gate itself has one heavy slot",
        )

    def test_costs_reads_module_timings_from_nested_seconds_map(self):
        """agents-pdl1m: costs() reads module timings from nested 'seconds' map in cost cache."""
        import ast, json
        src = (self.root / "tools" / "fast-gate.sh").read_text(encoding="utf-8")
        py_lines = []
        in_py = False
        for line in src.splitlines():
            if not in_py and "<<'PY'" in line:
                in_py = True
                continue
            if in_py and line == "PY":
                break
            if in_py:
                py_lines.append(line)
        tree = ast.parse("\n".join(py_lines))
        nodes = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
        nodes.extend([n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "costs"])
        mod = ast.Module(body=nodes, type_ignores=[])
        ast.fix_missing_locations(mod)

        with tempfile.TemporaryDirectory() as td:
            table = Path(td) / "full-gate-module-costs.json"
            # 1. Standard full gate cache format with nested 'seconds' and 'identity'
            table.write_text(json.dumps({
                "seconds": {"tests.test_alpha": 42.0, "tests.test_beta": 1.5},
                "identity": {"commit": "abc", "tree": "def", "modules": 2}
            }), encoding="utf-8")
            ns = {
                "cache": str(table),
                "modules": ["tests.test_alpha", "tests.test_beta", "tests.test_unmeasured"],
            }
            exec(compile(mod, "fast-gate.sh", "exec"), ns)
            costs_map = ns["costs"]()
            self.assertEqual(costs_map["tests.test_alpha"], 42.0)
            self.assertEqual(costs_map["tests.test_beta"], 1.5)
            self.assertEqual(costs_map["tests.test_unmeasured"], 1.0)

            # 2. Legacy flat dictionary format compatibility
            table.write_text(json.dumps({"tests.test_alpha": 33.0}), encoding="utf-8")
            costs_map_flat = ns["costs"]()
            self.assertEqual(costs_map_flat["tests.test_alpha"], 33.0)
            self.assertEqual(costs_map_flat["tests.test_unmeasured"], 1.0)

    def _run_custom(self, selection, overrides, **settings):
        """Run with a chosen module failing or empty, every other selected suite passing."""
        for rel in selection:
            self._stub(rel, overrides.get(rel, PASSING))
        return self._run(dry_run=False, **settings)


if __name__ == "__main__":
    unittest.main()
