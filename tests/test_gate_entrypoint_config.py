"""agents-ia3p (C): the DEPLOYED entrypoint must read the TRACKED gate command.

WHY THIS FILE EXISTS AND WHY IT IS SEPARATE FROM test_check_conf_consistency.py: that file
tests MY resolver in isolation, and an isolated exercise of the resolver is exactly what
let the original P1 through. The reviewer's finding was that the tracked config is read
only by the resolver and its test - THE THING BUILT TO END "A FIX IN A PLACE THE DEPLOYED
INVOCATION DOES NOT READ" WAS ITSELF IN A PLACE THE DEPLOYED INVOCATION DOES NOT READ. So
the evidence here comes from the real entrypoint, ~/fleet/bin/fleet-check, with a TEMP HOME
that has no .fleet/check.conf - which is what a fresh VM looks like.

THE DEFECT, AT THE SOURCE (read, not assumed): fleet-check:149 is
    [ -f "$HOME/.fleet/check.conf" ] && source "$HOME/.fleet/check.conf"
:155-160 auto-detect deno.json or package.json AND NOTHING ELSE, and :161 exits 2 with
"no CHECK_CMD in ~/.fleet/check.conf and nothing to auto-detect; ask coord to set it".
THIS IS A PYTHON PROJECT WITH NEITHER MANIFEST, so on a fresh VM the gate does not fall
back to a wrong command - IT CANNOT RUN AT ALL, and that is true for every Python project
in the fleet.

THE FIX SHAPE (C): tools/check-cmd.sh --install writes THIS PROJECT'S resolved command into
$HOME/.fleet/check.conf from the tracked tools/check.conf. The deployed entrypoint then
reads the tracked command through the mechanism it already uses, with no fleet-bundle
change, and the tracked file stays the source of truth a PR can review.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESOLVER = ROOT / "tools" / "check-cmd.sh"
TRACKED = ROOT / "tools" / "check.conf"
FLEET_CHECK = Path.home() / "fleet" / "bin" / "fleet-check"


def _tracked_fields() -> dict:
    fields = {}
    for line in TRACKED.read_text(encoding="utf-8").splitlines():
        m = re.match(r'^([A-Z_]+)="(.*)"\s*$', line.strip())
        if m:
            fields[m.group(1)] = m.group(2)
    return fields


class TestTheEntrypointReadsTheTrackedCommand(unittest.TestCase):
    """The acceptance: a fresh VM with no per-VM config uses the TRACKED hermetic command."""

    def setUp(self):
        if not FLEET_CHECK.is_file():
            self.skipTest(f"no deployed entrypoint at {FLEET_CHECK} on this VM")
        res = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"],
                             capture_output=True, text=True, cwd=str(ROOT))
        if res.stdout.strip():
            self.skipTest("fleet-check requires a clean worktree; uncommitted changes present")

    def _fresh_home(self) -> str:
        """A HOME with no .fleet/check.conf - what a reprovisioned VM has."""
        tmp = tempfile.mkdtemp(prefix="ia3p-fresh-home-")
        return tmp

    def test_a_fresh_home_has_no_per_vm_config(self):
        """The precondition, asserted rather than assumed: the test is only meaningful if
        the temp HOME really is missing the file the bug depends on."""
        home = self._fresh_home()
        self.assertFalse((Path(home) / ".fleet" / "check.conf").exists())

    # NOTE ON THE ENTRYPOINT'S PRECONDITION, WHICH COST TWO RED RUNS THAT LOOKED LIKE TEST
    # BUGS: fleet-check REFUSES TO RUN ON A DIRTY WORKTREE ("worktree has uncommitted
    # changes; commit first"), so BOTH arms below must run against a COMMITTED tree. That is
    # why an uncommitted edit makes these tests fail with a message about git rather than
    # about the config - the failure is real and about the precondition, not the harness.

    def test_the_entrypoint_refuses_on_a_fresh_home(self):
        """RED-FIRST EVIDENCE, AND THE P1 STATED AS A TEST.

        THE INTERFACE, ESTABLISHED BY READING RATHER THAN ASSUMING (this cost me one wrong
        harness, so it is written down): fleet-check accepts ONLY no-args, --status or
        --stop. --status resolves the sha and reads the CACHE, then RETURNS BEFORE THE
        CONFIG IS EVER SOURCED - which is why my first version of this test, asserting that
        --status refuses, was asserting an interface that does not exist. ONLY NO-ARGS and
        --fast reach the config: the source is at :149, the auto-detect at :155-159, and
        :170/:191 compare the cached record's .cmd against $CHECK_CMD.

        NO-ARGS NORMALLY STARTS A REAL GATE, which is why this test asserts the REFUSAL
        path only: on a fresh HOME this project has no per-VM config, and it has neither a
        deno.json nor a package.json, so the entrypoint exits 2 BEFORE running anything.
        The test therefore exercises the defect and starts no suite.

        THE POSITIVE ARM IS A NAMED FOLLOW-UP RATHER THAN A GUESS: to observe the config
        being READ successfully without running a suite, place a PASS record whose .cmd
        equals the tracked command for the tree, so the entrypoint takes the cache-hit path
        at :170 and prints the verdict without starting a gate. That needs the record's
        shape, which I have not read yet.
        """
        home = self._fresh_home()
        env = dict(os.environ)
        env["HOME"] = home
        env.pop("FLEET_CHECK_CONF", None)
        res = subprocess.run(
            ["bash", str(FLEET_CHECK)],
            capture_output=True, text=True, timeout=120, env=env, cwd=str(ROOT),
        )
        blob = res.stdout + res.stderr
        self.assertEqual(res.returncode, 2,
                         "on a fresh HOME with no per-VM config and no deno/package "
                         f"manifest, the entrypoint must REFUSE rather than run anything: "
                         f"rc={res.returncode}, {blob[:300]}")
        self.assertRegex(blob, r"auto-detect|CHECK_CMD",
                         "the refusal must name the missing command, which is the P1: the "
                         f"gate has no path for this project at all: {blob[:300]}")
        self.assertNotIn("started the", blob,
                         "the refusal path must not have started a gate")

    def test_no_args_is_the_mode_that_reaches_the_config(self):
        """The interface fact, pinned so the next reader does not repeat my wrong harness:
        a bare sha or an unknown flag prints usage and exits 2 without sourcing anything,
        while no-args and --fast are the only modes that reach :149."""
        home = self._fresh_home()
        env = dict(os.environ)
        env["HOME"] = home
        env.pop("FLEET_CHECK_CONF", None)
        res = subprocess.run(
            ["bash", str(FLEET_CHECK), "--definitely-not-a-flag"],
            capture_output=True, text=True, timeout=60, env=env, cwd=str(ROOT),
        )
        blob = res.stdout + res.stderr
        self.assertEqual(res.returncode, 2, blob[:300])
        self.assertNotIn("started the", blob, "an unknown flag must not start a gate")


class TestTheEntrypointResolvesTheInstalledCommand(unittest.TestCase):
    """THE POSITIVE ARM, WHICH IS REQUIRED AND NOT A FOLLOW-UP.

    agents-ia3p, reviewer finding: the refusal arm ALONE pins the defect as the contract -
    a test that asserts "no config, so refuse" documents the bug as intended behaviour, and
    the next reader treats it as settled. The PAIR is the property: absent config ->
    refuse, installed config -> RESOLVE. So this class asserts the second half.

    HOW IT AVOIDS STARTING A REAL GATE: fleet-check takes the CACHE-HIT path at :170 when a
    PASS record for the tree has `.cmd` EQUAL TO $CHECK_CMD. So the test installs the config
    into a temp HOME, writes that record itself, and asks the entrypoint to resolve it -
    it reads the config and prints a verdict WITHOUT running anything. If the entrypoint
    could not read the installed command, the .cmd comparison would fail and it would start
    a gate instead, which is why "did it start one" is asserted rather than assumed.
    """

    def setUp(self):
        if not FLEET_CHECK.is_file():
            self.skipTest(f"no deployed entrypoint at {FLEET_CHECK} on this VM")
        res = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"],
                             capture_output=True, text=True, cwd=str(ROOT))
        if res.stdout.strip():
            self.skipTest("fleet-check requires a clean worktree; uncommitted changes present")

    def test_the_entrypoint_resolves_the_installed_tracked_command(self):
        import json
        home = tempfile.mkdtemp(prefix="ia3p-positive-")
        env = dict(os.environ)
        env["HOME"] = home
        env.pop("FLEET_CHECK_CONF", None)

        # 1. the install step, which install.sh now invokes on provisioning
        install = subprocess.run(["bash", str(RESOLVER), "--install"],
                                 capture_output=True, text=True, timeout=60, env=env, cwd=str(ROOT))
        self.assertEqual(install.returncode, 0, install.stderr[:300])

        # agents-gxnb: stub setsid and fleet-heavy on PATH so that even if the test
        # condition regresses (mismatched command, missing record, etc.), fleet-check
        # cannot launch a detached real full gate in the background.
        bin_dir = Path(home) / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        marker = Path(home) / "spawn_attempted.txt"
        stub_script = (
            "#!/bin/sh\n"
            f'echo "interceptor called: $*" >> "{marker}"\n'
            "exit 99\n"
        )
        for tool in ("setsid", "fleet-heavy"):
            stub_path = bin_dir / tool
            stub_path.write_text(stub_script, encoding="utf-8")
            stub_path.chmod(0o755)

        env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"

        tracked = _tracked_fields()["CHECK_CMD"]
        tree = subprocess.run(["git", "rev-parse", "HEAD^{tree}"], capture_output=True,
                              text=True, timeout=30, cwd=str(ROOT)).stdout.strip()
        self.assertTrue(tree, "need the committed tree the gate caches against")

        # 2. the PASS record the entrypoint compares against, with the TRACKED command
        checks = Path(home) / ".fleet" / "checks"
        checks.mkdir(parents=True, exist_ok=True)
        record = checks / f"{tree}.json"
        record.write_text(json.dumps({
            "state": "PASS", "cmd": tracked, "kind": "full", "tree": tree,
            "sha": tree, "rc": 0, "lane": "test", "at": "1970-01-01T00:00:00Z",
            "run_s": 1, "secs": 1, "wait_s": 0, "done": True,
            "log": str(checks / "log.txt"),
        }), encoding="utf-8")

        # 3. ASK THE REAL ENTRYPOINT
        # NO ARGS, not --status and not a positional tree: no-args is the ONLY mode that
        # both SOURCES the config (:149) and can take the cache-hit path (:170). --status
        # resolves the sha and returns BEFORE the config is read, so it could not show the
        # installed command being used even if it succeeded.
        res = subprocess.run(["bash", str(FLEET_CHECK)],
                             capture_output=True, text=True, timeout=120, env=env, cwd=str(ROOT))
        blob = res.stdout + res.stderr
        self.assertFalse(marker.exists(),
                         "fleet-check attempted to spawn a detached gate (cache miss or command mismatch)!")
        self.assertNotIn("started the", blob,
                         f"with a matching PASS record the entrypoint must NOT start a gate: {blob[:300]}")
        # The entrypoint prints a HUMAN line here, not the record's JSON: measured output
        # is "fleet-check: PASS (cached) for tree of <tree>: ...". The assertion is on THAT
        # shape, because the point is that it resolved the installed command and reached
        # the cached verdict - which is exactly what a wrong or missing config would make
        # impossible (the .cmd comparison at :170 would fail and it would start a gate).
        self.assertIn("PASS (cached)", blob,
                      f"the entrypoint must resolve the installed command and report the "
                      f"cached verdict: {blob[:300]}")

    def test_command_mismatch_fails_cleanly_without_spawning_real_gate(self):
        """agents-gxnb: when the cached command does not match $CHECK_CMD, fleet-check's
        attempt to re-run the gate is intercepted, proving no real full gate can run."""
        import json
        home = tempfile.mkdtemp(prefix="ia3p-regress-")
        env = dict(os.environ)
        env["HOME"] = home
        env.pop("FLEET_CHECK_CONF", None)

        install = subprocess.run(["bash", str(RESOLVER), "--install"],
                                 capture_output=True, text=True, timeout=60, env=env, cwd=str(ROOT))
        self.assertEqual(install.returncode, 0)

        bin_dir = Path(home) / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        marker = Path(home) / "spawn_attempted.txt"
        stub_script = (
            "#!/bin/sh\n"
            f'echo "interceptor called: $*" >> "{marker}"\n'
            "exit 99\n"
        )
        for tool in ("setsid", "fleet-heavy"):
            stub_path = bin_dir / tool
            stub_path.write_text(stub_script, encoding="utf-8")
            stub_path.chmod(0o755)

        env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"

        tree = subprocess.run(["git", "rev-parse", "HEAD^{tree}"], capture_output=True,
                              text=True, timeout=30, cwd=str(ROOT)).stdout.strip()
        checks = Path(home) / ".fleet" / "checks"
        checks.mkdir(parents=True, exist_ok=True)
        record = checks / f"{tree}.json"
        # Deliberately mismatched command
        record.write_text(json.dumps({
            "state": "PASS", "cmd": "mismatched-non-hermetic-command", "kind": "full", "tree": tree,
            "sha": tree, "rc": 0, "lane": "test", "at": "1970-01-01T00:00:00Z",
            "run_s": 1, "secs": 1, "wait_s": 0, "done": True,
            "log": str(checks / "log.txt"),
        }), encoding="utf-8")

        res = subprocess.run(["bash", str(FLEET_CHECK)],
                             capture_output=True, text=True, timeout=60, env=env, cwd=str(ROOT))
        # The entrypoint reports the mismatch
        self.assertIn("cached PASS was for a different command", res.stdout)
        # The spawn attempt was intercepted and neutralized before any real tests ran
        self.assertTrue(marker.exists(), "stub interceptor must capture the spawn attempt")


class TestInstalledConfigDoesNotDrift(unittest.TestCase):
    """The named weakness of (C): the tracked file is the source, the per-VM file is a copy.

    HONEST LIMIT, AND IT MAKES THE STRICTER CHOICE CORRECT: from the files alone, a
    HAND-TUNED override and a STALE INSTALL are the same bytes. There is no marker that
    distinguishes "I meant this locally" from "the tracked file moved on". So this test
    FAILS ON ANY DIVERGENCE from the tracked command, and the documented way to tune
    locally is the FLEET_CHECK_CONF / override path rather than editing the installed file.
    """

    def test_install_is_idempotent_and_matches_the_tracked_command(self):
        home = tempfile.mkdtemp(prefix="ia3p-drift-")
        env = dict(os.environ)
        env["HOME"] = home
        env.pop("FLEET_CHECK_CONF", None)
        for _ in range(2):  # idempotent: installing twice must not compound anything
            r = subprocess.run(["bash", str(RESOLVER), "--install"],
                               capture_output=True, text=True, timeout=60, env=env, cwd=str(ROOT))
            self.assertEqual(r.returncode, 0, r.stderr[:300])

        installed = (Path(home) / ".fleet" / "check.conf").read_text(encoding="utf-8")
        tracked_cmd = _tracked_fields()["CHECK_CMD"]
        m = re.search(r'^CHECK_CMD="(.*)"\s*$', installed, re.M)
        self.assertIsNotNone(m, f"the installed file must define CHECK_CMD: {installed!r}")
        self.assertEqual(m.group(1), tracked_cmd,
                         "the installed command MUST equal the tracked one; a divergence "
                         "means either a hand-edit or a stale install, and this test "
                         "cannot tell them apart, so it refuses both")

    def test_install_overwrites_stale_per_vm_config_with_tracked_values(self):
        """When an existing per-VM check.conf carries a stale command (e.g. without -t .),
        running --install must overwrite it with the tracked hermetic command."""
        home = tempfile.mkdtemp(prefix="ia3p-stale-")
        conf = Path(home) / ".fleet" / "check.conf"
        conf.parent.mkdir(parents=True)
        conf.write_text('CHECK_CMD="python3 -m unittest discover -s tests -v"\n', encoding="utf-8")

        env = dict(os.environ)
        env["HOME"] = home
        env.pop("FLEET_CHECK_CONF", None)

        r = subprocess.run(["bash", str(RESOLVER), "--install"],
                           capture_output=True, text=True, timeout=60, env=env, cwd=str(ROOT))
        self.assertEqual(r.returncode, 0, r.stderr[:300])

        installed = conf.read_text(encoding="utf-8")
        tracked_cmd = _tracked_fields()["CHECK_CMD"]
        self.assertIn(tracked_cmd, installed)
        self.assertIn("-t .", installed)

    def test_install_overwrites_malformed_per_vm_config_with_tracked_values(self):
        """agents-r1o7: when an existing per-VM check.conf contains invalid syntax or corruption,
        running --install must repair it from tracked defaults without failing during sourcing."""
        home = tempfile.mkdtemp(prefix="ia3p-malformed-")
        conf = Path(home) / ".fleet" / "check.conf"
        conf.parent.mkdir(parents=True)
        conf.write_text('SYNTAX ERROR = %%% not valid bash\n', encoding="utf-8")

        env = dict(os.environ)
        env["HOME"] = home
        env.pop("FLEET_CHECK_CONF", None)

        r = subprocess.run(["bash", str(RESOLVER), "--install"],
                           capture_output=True, text=True, timeout=60, env=env, cwd=str(ROOT))
        self.assertEqual(r.returncode, 0, f"install must repair malformed config: {r.stderr}")

        installed = conf.read_text(encoding="utf-8")
        tracked_cmd = _tracked_fields()["CHECK_CMD"]
        self.assertIn(tracked_cmd, installed)
        self.assertIn("-t .", installed)

    def test_install_warns_when_overwriting_foreign_project_config(self):
        """agents-f6no: when ~/.fleet/check.conf already exists without agents-factory stamp
        (e.g. written by another project on a shared-HOME host), --install must warn to stderr
        and stamp the project name and machine-global scope in the header."""
        home = tempfile.mkdtemp(prefix="f6no-foreign-")
        conf = Path(home) / ".fleet" / "check.conf"
        conf.parent.mkdir(parents=True)
        conf.write_text('CHECK_CMD="echo OTHER_PROJECT_GATE"\n', encoding="utf-8")

        env = dict(os.environ)
        env["HOME"] = home
        env.pop("FLEET_CHECK_CONF", None)

        r = subprocess.run(["bash", str(RESOLVER), "--install"],
                           capture_output=True, text=True, timeout=60, env=env, cwd=str(ROOT))
        self.assertEqual(r.returncode, 0)
        self.assertIn("WARNING", r.stderr)
        self.assertIn("not stamped by agents-factory", r.stderr)

        installed = conf.read_text(encoding="utf-8")
        self.assertIn("# Project: agents-factory", installed)
        self.assertIn("# WARNING: This file is MACHINE-GLOBAL", installed)

        # Idempotent second install should NOT warn
        r2 = subprocess.run(["bash", str(RESOLVER), "--install"],
                            capture_output=True, text=True, timeout=60, env=env, cwd=str(ROOT))
        self.assertEqual(r2.returncode, 0)
        self.assertNotIn("WARNING", r2.stderr)


if __name__ == "__main__":
    unittest.main()
