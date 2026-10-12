"""agents-5vun: the pins audit DETECTS, and states what it cannot check.

Every test drives REAL files through the CLI (or through audit()) - a test that mocked the
parser or the generator would assert the audit's own opinion rather than its behaviour.

The last test is the important one to keep: it PINS THE MEASURED LIMIT. A self-consistent
forged entry whose path the lookup also chooses is accepted by this audit (and by
verify_pin), because nothing in-process can authenticate a pins file. If someone later
"fixes" the audit so that test passes differently, they either added a trust anchor (good,
and the test should say so) or they broke the honest limit into a false claim of security.
"""

import hashlib
import io
import contextlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lib.pins_audit import DEFAULT_LOOKUP, audit, main, render  # noqa: E402

CLI = ROOT / "tools" / "audit-tool-pins.sh"
# The coverage oracle reads the LITERAL in run_cli()'s subprocess call, so it must name the tool
# this suite actually spawns - pinned in a test below rather than left to drift.
CLI_LITERAL = "tools/audit-tool-pins.sh"
GENERATOR = ROOT / "tools" / "generate-tool-pins.sh"
PIN_NAMES = ("FACTORY_TOOL_PINS", "FACTORY_VERIFIED_TOOL_PINS")


def write_fake_binary(path: Path, marker: str = "FORGED") -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!/bin/sh\necho {marker}\n")
    path.chmod(0o755)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_pins(path: Path, entries: dict) -> Path:
    lines = []
    for name, entry in entries.items():
        lines.append(f"{name}:")
        if entry.get("path"):
            lines.append(f"  path: {entry['path']}")
        if entry.get("sha256"):
            lines.append(f"  sha256: {entry['sha256']}")
    path.write_text("\n".join(lines) + "\n")
    return path


def run_cli(args, env_extra=None, clear_pins_env=True):
    env = os.environ.copy()
    if clear_pins_env:
        for name in PIN_NAMES:
            env.pop(name, None)
    env.update(env_extra or {})
    # THE LITERAL PATH IS DELIBERATE, NOT A STYLE CHOICE (agents-5vun). The fleet's coverage
    # oracle (remote/check-coverage.py) relates a changed file to a suite by looking for the
    # file's path, basename or stem INSIDE a subprocess/exec call in the test source; a
    # `str(CLI)` indirection hides it, and a .sh source can never be matched by test-name
    # stem either, because its are_extensions_compatible() is `ext1 == ext2` - so before this
    # literal, a change to tools/audit-tool-pins.sh was reported UNMAPPED by the fleet
    # extractor even though it ran this suite. Same reason tests/test_fast_gate_mapping.py
    # names tools/fast-gate.sh at its call site.
    return subprocess.run(["bash", str(ROOT / "tools" / "audit-tool-pins.sh"), *args],
                          cwd=str(ROOT), env=env, capture_output=True, text=True)


def generate(dest: Path, lookup: str) -> Path:
    subprocess.run(["bash", str(GENERATOR), str(dest), "--lookup-path", lookup],
                   cwd=str(ROOT), check=True, capture_output=True, text=True)
    return dest


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="pins-audit-test-")
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        for name in PIN_NAMES:
            self.addCleanup(os.environ.pop, name, None)

    # --- the detector fires ---------------------------------------------------------------

    def test_a_forged_path_is_reported_and_the_audit_exits_non_zero(self):
        """agents-5vun's own artefact: a pin at a path the lookup would never choose."""
        forged = self.dir / "attacker" / "git"
        digest = write_fake_binary(forged, "FORGED-EXECUTED")
        pins = write_pins(self.dir / "pins.yaml", {"git": {"path": str(forged), "sha256": digest}})
        result = run_cli(["--pins", str(pins)])
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(str(forged), result.stdout)
        self.assertIn("DIFFERS", result.stdout)
        self.assertIn("DISAGREES", result.stdout)

    def test_a_digest_that_does_not_match_the_binary_is_reported(self):
        """The re-hash check, which does not depend on the lookup dirs at all."""
        real_git = "/usr/bin/git"
        if not Path(real_git).is_file():  # pragma: no cover - environment guard
            self.skipTest("no /usr/bin/git on this machine")
        pins = write_pins(self.dir / "pins.yaml",
                          {"git": {"path": real_git, "sha256": "0" * 64}})
        report = audit(pins_arg=str(pins), lookup=str(self.dir))
        self.assertTrue(report.disagrees)
        self.assertTrue(any("hashes to" in m for m in report.hash_mismatches),
                        report.hash_mismatches)

    def test_an_extra_entry_the_lookup_would_not_produce_is_reported(self):
        forged = self.dir / "attacker" / "sneaky"
        digest = write_fake_binary(forged, "SNEAKY")
        pins = write_pins(self.dir / "pins.yaml", {"sneaky": {"path": str(forged), "sha256": digest}})
        report = audit(pins_arg=str(pins), lookup=str(self.dir / "empty-lookup"))
        kinds = {(d.name, d.in_use is not None, d.rederived is not None) for d in report.differences}
        self.assertIn(("sneaky", True, False), kinds)
        self.assertTrue(report.disagrees)

    def test_a_malformed_pins_file_cannot_be_audited_and_exits_two(self):
        pins = self.dir / "pins.yaml"
        pins.write_text("git:\n  path: /usr/bin/git\n  sha256: not-64-hex\n")
        result = run_cli(["--pins", str(pins)])
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("CANNOT AUDIT", result.stdout)

    def test_a_rederivation_that_exceeds_its_timeout_cannot_run_rather_than_traceback(self):
        """agents-u4k7: the bound is BOTH present AND reported when it is reached.

        tests/test_budget.py owns the repo-wide rule that this call carries a timeout= - it is
        what caught this call unbounded, and that rule is not duplicated here. What it cannot
        see is what happens AT the bound: a generator that hangs must leave the audit saying
        "cannot run" (exit 2), never a traceback and never a silently skipped re-derivation,
        which would read as agreement. The generator is driven to expiry through the module's
        own constant, so this costs milliseconds rather than the generator's measured 6 s.
        """
        forged = self.dir / "lookup" / "git"
        digest = write_fake_binary(forged, "ANY")
        pins = write_pins(self.dir / "pins.yaml", {"git": {"path": str(forged), "sha256": digest}})
        with mock.patch("lib.pins_audit.GENERATOR_TIMEOUT_SECONDS", 0.001):
            report = audit(pins_arg=str(pins), lookup=str(self.dir / "lookup"))
            with contextlib.redirect_stdout(io.StringIO()) as out:
                rc = main(["--pins", str(pins), "--lookup-path", str(self.dir / "lookup")])
        self.assertIsNotNone(report.rederivation_error, "the timeout must be reported, not raised")
        self.assertIn("did not finish within", report.rederivation_error)
        self.assertIn("UNKNOWN", report.rederivation_error)
        self.assertEqual(rc, 2, "a re-derivation that could not run is exit 2, never a green")
        self.assertIn("FAILED", out.getvalue())

    # --- the audit does not fire on a coherent file ---------------------------------------

    def test_a_file_that_agrees_with_a_fresh_derivation_exits_zero(self):
        lookup = self.dir / "lookup"
        write_fake_binary(lookup / "git", "REAL")
        pins = generate(self.dir / "pins.yaml", str(lookup))
        result = run_cli(["--pins", str(pins), "--lookup-path", str(lookup)])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("AGREES", result.stdout)

    def test_the_coverage_oracles_literal_names_the_tool_this_suite_spawns(self):
        """The fleet's oracle reads a LITERAL path inside the subprocess call, so it is a contract.

        If the tool is renamed and this literal is not, the fleet extractor reports every change
        to the tool as unmapped even though this suite ran - silently, and in the note a reader
        sees. So the literal and the tool are asserted to agree (agents-5vun).
        """
        self.assertTrue(CLI.is_file(), f"the tool moved: {CLI}")
        self.assertTrue(CLI_LITERAL.endswith(CLI.name), f"literal {CLI_LITERAL} != tool {CLI.name}")
        self.assertIn(CLI_LITERAL, Path(__file__).read_text(),
                      "run_cli() must name the tool by its literal path for the fleet oracle")

    def test_no_pins_file_in_use_is_reported_and_exits_zero(self):
        result = run_cli([])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("nothing to audit", result.stdout)
        self.assertIn("file in use : NONE", result.stdout)

    # --- the constraints coord put on the detector ----------------------------------------

    def test_the_report_states_what_it_inspected_rederived_and_could_not_check(self):
        """A detector must not imply it verified more than it did."""
        result = run_cli(["--pins", str(self.dir / "pins.yaml")])
        for section in ("INSPECTED", "RE-DERIVED", "NOT CHECKED"):
            self.assertIn(section, result.stdout)
        self.assertIn("lookup-path", result.stdout)
        self.assertIn("root of trust", result.stdout)
        self.assertIn("No local change closes that", result.stdout)

    def test_the_route_that_selected_the_file_is_named(self):
        pins = write_pins(self.dir / "pins.yaml",
                          {"git": {"path": str(write_fake_binary(self.dir / "git")),
                                    "sha256": hashlib.sha256((self.dir / "git").read_bytes()).hexdigest()}})
        legacy = run_cli([], env_extra={"FACTORY_TOOL_PINS": str(pins)})
        self.assertIn("FACTORY_TOOL_PINS", legacy.stdout)
        self.assertIn("legacy", legacy.stdout)
        self.assertNotIn("CANNOT AUDIT", legacy.stdout)
        explicit = run_cli(["--pins", str(pins)])
        self.assertIn("explicit --pins", explicit.stdout)

    def test_a_child_only_name_is_not_silently_audited_as_the_dispatcher(self):
        """configure_host_pins() drops FACTORY_VERIFIED_TOOL_PINS, so the report must say so."""
        pins = self.dir / "pins.yaml"
        pins.write_text("git:\n  path: /usr/bin/git\n  sha256: " + "0" * 64 + "\n")
        result = run_cli([], env_extra={"FACTORY_VERIFIED_TOOL_PINS": str(pins)})
        self.assertIn("FACTORY_VERIFIED_TOOL_PINS", result.stdout)
        self.assertIn("NOT the file audited here", result.stdout)

    def test_the_measured_limit_is_pinned_a_self_consistent_forgery_inside_the_lookup_passes(self):
        """THE HONEST LIMIT, in a test: if this ever changes, a trust anchor was added.

        The forged binary's directory is PREPENDED to the lookup - the mechanism agents-5vun
        measured as the reason this attack does not need a compromised system hasher - so the
        generator itself pins the forged binary: the pins file is a FAITHFUL record of a
        compromised lookup, self-consistent, and the audit cannot tell it from an honest one.
        Neither can verify_pin. Documented here rather than hidden, because the whole point of
        this bead is that a detector must not be read as a fix.
        """
        lookup = self.dir / "lookup"
        digest = write_fake_binary(lookup / "git", "FORGED-BUT-SELF-CONSISTENT")
        effective_lookup = f"{lookup}{os.pathsep}{DEFAULT_LOOKUP}"
        pins = generate(self.dir / "pins.yaml", effective_lookup)
        self.assertIn(f"path: {lookup / 'git'}", pins.read_text(),
                      "the pinned git must be the forged one, or this test proves nothing")
        report = audit(pins_arg=str(pins), lookup=effective_lookup)
        self.assertFalse(report.disagrees,
                         "the audit now catches this - if a trust anchor was added, update "
                         "this test AND the NOT CHECKED text in lib/pins_audit.py")
        self.assertIn("NOT CHECKED", render(report))
        self.assertEqual(digest, hashlib.sha256((lookup / "git").read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
