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
:156-159 auto-detect a command it can actually run - deno.json WITH .tasks.check, or
package.json WITH .scripts.test - and :160 exits 2 with "no CHECK_CMD in
~/.fleet/check.conf and nothing to auto-detect; ask coord to set it".
THIS REPO MATCHES NEITHER PREDICATE (agents-3q1e, MEASURED 2026-10-12): deno.json does not
exist, and package.json EXISTS but declares no scripts.test, so `jq -e '.scripts.test'
package.json` exits 1 and the auto-detect falls through. On a fresh VM the gate therefore does
not fall back to a wrong command - for THIS repo it cannot resolve a command at all.
(The paragraph above used to say "this is a Python project with NEITHER MANIFEST" and then to
generalise that to every Python project in the fleet. Both were unmeasured claims about the
environment rather than statements about the condition the entrypoint tests, and the second was
simply false: a Python project carrying deno.json with .tasks.check, or package.json with
.scripts.test, auto-detects perfectly well. This file was written to end exactly that defect
class, so the condition is now the one fleet-check actually evaluates - and the citations are
the ones I read: the predicates span :156-159 and the exit 2 is at :160, not :161.) 

THE FIX SHAPE (C): tools/check-cmd.sh --install writes THIS PROJECT'S resolved command into
$HOME/.fleet/check.conf from the tracked tools/check.conf. The deployed entrypoint then
reads the tracked command through the mechanism it already uses, with no fleet-bundle
change, and the tracked file stays the source of truth a PR can review.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RESOLVER = ROOT / "tools" / "check-cmd.sh"
TRACKED = ROOT / "tools" / "check.conf"
FLEET_CHECK = Path.home() / "fleet" / "bin" / "fleet-check"

# THE FLEET-BUNDLE INTERFACE THIS SUITE DRIVES, ASSERTED RATHER THAN ASSUMED (agents-o8jd).
#
# This file's subject is ~/fleet/bin/fleet-check - a file in ANOTHER repo, with no version pin
# here and no signal when it changes. On 2026-10-11 the bundle grew a lane guard
# (`if [ -z "$FAST" ] && [ -z "$FORCE_FULL" ] && [ "${FLEET_LANE:-}" != merger ]`, so a full-gate
# attempt from a non-merger lane exits 2) and this suite went RED for every implementer lane
# while passing for a merger lane - and the failure read as `'PASS (cached)' not found`, which
# names a string rather than the fleet-side change that caused it. agents-3xqa pinned the suite's
# own environment; this map closes the remaining half: the anchors below are what this suite
# actually depends on, so losing one fails HERE, in one message that names the bundle, the
# anchor, and the assertion that needs it.
#
# WHAT THIS DOES AND DOES NOT DO. It detects an anchor being REMOVED or reworded. It does NOT
# detect a rename that keeps the anchor as a prefix (`fleet-heavy` -> `fleet-heavy-v2`), because
# these are substring checks and a lookahead regex to close that would be a check nobody can
# read; for the two spawn stubs that case is covered anyway, because every test that can reach
# the spawn path asserts its stub DID intercept the attempt, so a bypass fails loudly rather
# than starting a real gate quietly. It also cannot detect a behavioural change that keeps the
# text - that is what the tests below are for. And it is a CONTRACT check, not a version pin:
# a bundle edit that keeps these anchors is fine, which is the property we want (sensitivity to
# the interface, not to the file's text).
FLEET_BUNDLE_ANCHORS = {
    "FLEET_LANE": "the lane variable the bundle requires (lane=${FLEET_LANE:?...}) and the one "
                  "_entrypoint_env pins to merger; without it the bundle exits before the "
                  "config/verdict paths these tests assert on (agents-3xqa)",
    "FORCE_FULL": "the guard's sibling bypass, beside FAST; the shape _entrypoint_env's pin is "
                  "written against, so a rewrite of that guard must be met by a suite update",
    "setsid": "one of the two commands _prevent_real_gate stubs FIRST on PATH; if the bundle "
              "starts a gate some other way, an entrypoint test can spawn a REAL full gate in "
              "the background and pay for the VM's one heavy slot (agents-gxnb)",
    "fleet-heavy": "the other stubbed command, for the same reason as setsid",
    ".fleet/check.conf": "the per-VM config this suite installs into a temp HOME and asserts "
                          "on; the path is part of the interface, not an implementation detail",
    "PASS (cached)": "the cached-verdict line "
                     "test_the_entrypoint_resolves_the_installed_tracked_command asserts on",
    "cached PASS was for a different command": "the mismatch line "
                                               "test_command_mismatch_fails_cleanly_without_spawning_real_gate "
                                               "asserts on",
}


def missing_bundle_anchors(source: str) -> dict:
    """The anchors absent from `source`, each mapped to what depends on it."""
    return {anchor: why for anchor, why in FLEET_BUNDLE_ANCHORS.items() if anchor not in source}


def _entrypoint_env(home: str) -> dict:
    """The env the deployed entrypoint is driven with, PINNED - so the verdict is about the
    entrypoint and not about WHO RAN THE SUITE.

    MEASURED 2026-10-12 on a PRISTINE origin/main worktree (60ab891, no lane delta):
    fleet-check:173 refuses a FULL-gate attempt from any lane that is not `merger` ("the FULL
    gate is the merger's job"), and that refusal fires AFTER the config is sourced (:149) but
    BEFORE the cached-verdict path (:170/:191) these tests assert on. So inheriting the
    caller's FLEET_LANE made both arms of TestTheEntrypointResolvesTheInstalledCommand FAIL
    for every implementer lane while a merger lane passed them; the fresh-HOME refusal arm
    was never lane-dependent because with no per-VM config it exits 2 at the auto-detect
    refusal (:161) before the lane guard for any lane, so the pin is inert there. A result
    that depends on the calling lane is a machine-state assertion; it turns an unrelated
    change red for everyone, and install.sh maps to this suite (agents-3xqa), so the Resolves
    pair had to become lane-independent. `merger` is the only
    lane value the entrypoint lets through to the config path, and EVERY test here also calls
    _prevent_real_gate, so passing that gate cannot start a real full gate.
    """
    env = dict(os.environ)
    env["HOME"] = home
    env["FLEET_LANE"] = "merger"
    env.pop("FLEET_CHECK_CONF", None)
    return env


def _prevent_real_gate(env: dict, home: str) -> Path:
    """Put stubs for `setsid` and `fleet-heavy` FIRST on PATH so that no test in this file can
    start a detached real full gate in the background (agents-gxnb, extended from the positive
    arm to every entrypoint arm - four tests, all of which now reach the spawn path by virtue
    of the pinned lane above). The stubs exit 99 and record the attempt, so a regression is
    ASSERTED ON rather than paid for by the VM's one heavy slot. Returns the marker path the
    caller asserts is absent.
    """
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
    return marker


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
        path only: on a fresh HOME this project has no per-VM config, and the auto-detect at
        fleet-check:156-159 matches neither predicate - deno.json does not exist, and
        package.json exists but declares no scripts.test (measured 2026-10-12:
        `jq -e '.scripts.test' package.json` -> rc=1) - so the entrypoint exits 2 BEFORE
        running anything. The test therefore exercises the defect and starts no suite.

        THE POSITIVE ARM IS A NAMED FOLLOW-UP RATHER THAN A GUESS: to observe the config
        being READ successfully without running a suite, place a PASS record whose .cmd
        equals the tracked command for the tree, so the entrypoint takes the cache-hit path
        at :170 and prints the verdict without starting a gate. That needs the record's
        shape, which I have not read yet.
        """
        home = self._fresh_home()
        env = _entrypoint_env(home)
        marker = _prevent_real_gate(env, home)
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
        self.assertFalse(marker.exists(),
                         "a refusal must not have reached the spawn path at all")

    def test_no_args_is_the_mode_that_reaches_the_config(self):
        """The interface fact, pinned so the next reader does not repeat my wrong harness:
        a bare sha or an unknown flag prints usage and exits 2 without sourcing anything,
        while no-args and --fast are the only modes that reach :149."""
        home = self._fresh_home()
        env = _entrypoint_env(home)
        marker = _prevent_real_gate(env, home)
        res = subprocess.run(
            ["bash", str(FLEET_CHECK), "--definitely-not-a-flag"],
            capture_output=True, text=True, timeout=60, env=env, cwd=str(ROOT),
        )
        blob = res.stdout + res.stderr
        self.assertEqual(res.returncode, 2, blob[:300])
        self.assertNotIn("started the", blob, "an unknown flag must not start a gate")
        self.assertFalse(marker.exists(), "an unknown flag must not reach the spawn path")


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
        env = _entrypoint_env(home)

        # 1. THE INSTALL STEP, DRIVEN THROUGH THE PROVISIONING ENTRYPOINT INSTEAD OF ASSERTED
        # IN PROSE. This used to read "the install step, which install.sh now invokes on
        # provisioning" while install.sh had NO check-cmd.sh reference at all - a sentence
        # about intent standing in for behaviour, which is exactly how the original P1
        # survived a suite written to end it (agents-l2xb; coord asked for behaviour here).
        # The claim is now EXECUTED and then ASSERTED: install.sh is run, and the file the
        # entrypoint below reads must exist BECAUSE of it.
        install = subprocess.run(["bash", str(ROOT / "install.sh")],
                                 capture_output=True, text=True, timeout=120, env=env, cwd=str(ROOT))
        self.assertEqual(install.returncode, 0, install.stderr[:300])
        self.assertTrue((Path(home) / ".fleet" / "check.conf").is_file(),
                        "install.sh must be the CALLER that provisions the per-VM config; the "
                        "assertion, not a comment, is what pins its call site")

        # agents-gxnb: stub setsid and fleet-heavy on PATH so that even if the test
        # condition regresses (mismatched command, missing record, etc.), fleet-check
        # cannot launch a detached real full gate in the background.
        marker = _prevent_real_gate(env, home)

        # The tracked command as evaluated when sourced by fleet-check:
        res_cmd = subprocess.run(["bash", str(RESOLVER), "CHECK_CMD"],
                                 env={"FLEET_CHECK_CONF": "/dev/null", "PATH": os.environ.get("PATH", "")},
                                 capture_output=True, text=True, cwd=str(ROOT))
        tracked = res_cmd.stdout.strip()
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
                      f"the entrypoint ({FLEET_CHECK}) must resolve the installed command and "
                      f"report the cached verdict (agents-o8jd: this line is part of the "
                      f"fleet-bundle interface this suite drives): {blob[:300]}")

    def test_command_mismatch_fails_cleanly_without_spawning_real_gate(self):
        """agents-gxnb: when the cached command does not match $CHECK_CMD, fleet-check's
        attempt to re-run the gate is intercepted, proving no real full gate can run."""
        import json
        home = tempfile.mkdtemp(prefix="ia3p-regress-")
        env = _entrypoint_env(home)

        install = subprocess.run(["bash", str(RESOLVER), "--install"],
                                 capture_output=True, text=True, timeout=60, env=env, cwd=str(ROOT))
        self.assertEqual(install.returncode, 0)

        marker = _prevent_real_gate(env, home)

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
        self.assertIn("cached PASS was for a different command", res.stdout,
                      f"the entrypoint ({FLEET_CHECK}) must report the command mismatch "
                      f"(agents-o8jd: this line is part of the fleet-bundle interface this "
                      f"suite drives): {(res.stdout + res.stderr)[:300]}")
        # The spawn attempt was intercepted and neutralized before any real tests ran
        self.assertTrue(marker.exists(), "stub interceptor must capture the spawn attempt")


class TestAFailedUpdateIsNotSwallowed(unittest.TestCase):
    """agents-yow5: install.sh's `git pull --ff-only --quiet || true` swallowed a failed
    update, so a VM continued with STALE stations, printed its success lines and EXITED 0.

    That is worse than a visible failure: the caller (remote/provision.sh:970) runs this
    installer with ALL OUTPUT SUPPRESSED, so the exit code is the only signal that survives,
    and the thing that certifies the VM looks correctly provisioned could not tell a fresh
    install from a silent one.
    """

    def _checkout_whose_remote_is_gone(self, root: Path) -> Path:
        """A real git checkout whose pull fails for the reason a VM's pull fails: the remote
        it tracks is not there. Built from a real clone of a real repository so the failure is
        git's own, not a fixture's imitation of one.
        """
        origin = root / "origin.git"
        seed = root / "seed"
        seed.mkdir()
        commit = ["-c", "user.email=installer@test.invalid", "-c", "user.name=installer"]
        subprocess.run(["git", "init", "-q", "--bare", str(origin)], check=True)
        subprocess.run(["git", "init", "-q", "-b", "main", str(seed)], check=True)
        (seed / "factory").write_text("#!/bin/sh\n", encoding="utf-8")
        (seed / "agents").mkdir()
        subprocess.run(["git", "-C", str(seed), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(seed), *commit, "commit", "-q", "-m", "seed"],
                       check=True)
        subprocess.run(["git", "-C", str(seed), "push", "-q", str(origin),
                        "HEAD:refs/heads/main"], check=True)
        subprocess.run(["git", "-C", str(origin), "symbolic-ref", "HEAD",
                        "refs/heads/main"], check=True)

        dst = root / "agents"
        subprocess.run(["git", "clone", "-q", str(origin), str(dst)], check=True)
        # The remote disappears: an unreachable remote, deterministic and instant (a bogus
        # https URL would depend on DNS timing on a starved VM).
        shutil.rmtree(origin)
        return dst

    def test_a_failed_pull_is_not_silent_and_does_not_exit_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            home.mkdir()
            dst = self._checkout_whose_remote_is_gone(root)

            # The installer must run from OUTSIDE a checkout: run from this repo it finds
            # factory+agents beside itself and takes the "use this checkout" branch, never
            # reaching the update path that is under test here.
            installer_dir = root / "installer"
            installer_dir.mkdir()
            installer = installer_dir / "install.sh"
            shutil.copy(ROOT / "install.sh", installer)

            env = _entrypoint_env(str(home))
            _prevent_real_gate(env, str(home))
            res = subprocess.run(["bash", str(installer), "-d", str(dst)],
                                 capture_output=True, text=True, env=env, cwd=str(root))

            self.assertNotEqual(
                res.returncode, 0,
                "a failed update must not exit 0: provision.sh calls this installer with its "
                "output suppressed, so a zero here is how a stale VM is reported as "
                "correctly provisioned",
            )
            output = res.stdout + res.stderr
            self.assertIn("could not update the Software Factory checkout", output,
                          "the failure must name what failed in the installer's own words")
            self.assertIn("pull", output.lower())
            self.assertNotIn("Installing Software Factory skills", res.stdout,
                             "the installer must not continue to install (stale) skills")
            self.assertFalse((home / ".pi" / "agent" / "skills").exists(),
                             "a failed update still linked skills into the agent hub")


class TestInstalledConfigDoesNotDrift(unittest.TestCase):
    """The named weakness of (C): the tracked file is the source, the per-VM file is a copy.

    HONEST LIMIT, AND IT MAKES THE STRICTER CHOICE CORRECT: from the files alone, a
    HAND-TUNED override and a STALE INSTALL are the same bytes. There is no marker that
    distinguishes "I meant this locally" from "the tracked file moved on". So this test
    FAILS ON ANY DIVERGENCE from the tracked command; the documented way to update or tune
    is editing tools/check.conf and re-running `bash tools/check-cmd.sh --install`.
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


class TestProvisioningInstallsTheGateCommand(unittest.TestCase):
    """agents-l2xb / agents-3xqa: install.sh - the provisioning entrypoint - IS THE CALLER.

    WHY THIS CLASS EXISTS: tools/check-cmd.sh --install resolves the tracked config and writes
    the per-VM copy the deployed entrypoint reads, and the suites above prove the entrypoint
    reads that copy. What was MISSING was the call site: nothing in the provisioning/setup
    lifecycle ran --install, so a fresh VM - and a VM whose per-VM copy had gone stale - kept
    the entrypoint's rc-2 refusal while every tracked file said the gate was configured. That
    is the original P1 shape (a fix in a place the DEPLOYED INVOCATION does not read) one
    level up, which is why it is pinned by EXECUTION rather than by grepping install.sh for a
    string: a grep cannot fail when the call site is present but unreachable, and the arm that
    maps install.sh to this file (agents-3xqa) needs a consumer that actually fails.

    NO git-dirty precondition and no dependency on the fleet bundle, unlike the classes above:
    install.sh is executed with a TEMP HOME and no network (the checkout branch is taken
    because `factory` and `agents/` are present in ROOT), so this runs wherever the repo does.
    """

    def _run_installer(self, home: str) -> subprocess.CompletedProcess:
        env = dict(os.environ)
        env["HOME"] = home
        # Keep the installer off any ambient per-VM redirect or alternate checkout: this test
        # is about what PROVISIONING writes for a plain, default host.
        for var in ("FLEET_CHECK_CONF", "SF_INSTALL_DIR", "SF_REPO_URL", "SKILL_FILTER"):
            env.pop(var, None)
        return subprocess.run(
            ["bash", str(ROOT / "install.sh")],
            capture_output=True, text=True, timeout=120, env=env, cwd=str(ROOT),
        )

    def test_install_sh_installs_the_tracked_gate_command(self):
        """A fresh host: provisioning writes the file the deployed gate reads, carrying the
        TRACKED command (including the load-bearing `-t .` hermeticity flag)."""
        home = tempfile.mkdtemp(prefix="l2xb-provision-")
        res = self._run_installer(home)
        self.assertEqual(res.returncode, 0, (res.stdout + res.stderr)[-600:])

        conf = Path(home) / ".fleet" / "check.conf"
        self.assertTrue(conf.is_file(),
                        "install.sh must write ~/.fleet/check.conf: it is the only config the "
                        "deployed gate reads, and nothing else in the provisioning lifecycle does")
        installed = conf.read_text(encoding="utf-8")
        m = re.search(r'^CHECK_CMD="(.*)"\s*$', installed, re.M)
        self.assertIsNotNone(m, f"the installed file must define CHECK_CMD: {installed!r}")
        self.assertEqual(m.group(1), _tracked_fields()["CHECK_CMD"],
                         "provisioning must install the TRACKED command; a divergence means a "
                         "hand-edit or a stale install, and this test cannot tell them apart")
        self.assertIn("-t .", installed)

    def test_install_sh_repairs_a_stale_per_vm_config(self):
        """The 'repaired host' half of the acceptance, which is the half a fresh-host check
        cannot see: a per-VM copy predating the `-t .` hermeticity fix must be REPLACED by
        the tracked command when provisioning runs, not left in place."""
        home = tempfile.mkdtemp(prefix="l2xb-repair-")
        conf = Path(home) / ".fleet" / "check.conf"
        conf.parent.mkdir(parents=True)
        conf.write_text('CHECK_CMD="python3 -m unittest discover -s tests -v"\n', encoding="utf-8")

        res = self._run_installer(home)
        self.assertEqual(res.returncode, 0, (res.stdout + res.stderr)[-600:])

        installed = conf.read_text(encoding="utf-8")
        self.assertIn(_tracked_fields()["CHECK_CMD"], installed)
        self.assertIn("-t .", installed)


class TestTheFleetBundleInterfaceThisSuiteDrives(unittest.TestCase):
    """agents-o8jd: fail LOUDLY and IN ONE MESSAGE when the fleet bundle drops an anchor.

    The rest of this file asserts the entrypoint's behaviour, which is the right way to test it -
    but a fleet-side change that removes or renames something the suite drives used to surface as
    a confusing assertion about a string (measured 2026-10-12: `'PASS (cached)' not found`, red
    for every implementer lane and green for a merger lane, i.e. a verdict that was a function of
    WHO RAN THE SUITE - see _entrypoint_env). This test turns that into one named failure.

    Non-vacuity is proven in the second test below, against synthetic sources: the real bundle is
    never mutated, because it is the shared entrypoint for every lane on this VM.
    """

    def setUp(self):
        if not FLEET_CHECK.is_file():
            self.skipTest(f"no deployed entrypoint at {FLEET_CHECK} on this VM")
        self.source = FLEET_CHECK.read_text(encoding="utf-8", errors="replace")

    def test_every_anchor_this_suite_depends_on_is_still_present(self):
        missing = missing_bundle_anchors(self.source)
        if not missing:
            return
        lines = [
            f"THE FLEET BUNDLE NO LONGER PRESENTS {len(missing)} ANCHOR(S) THIS SUITE DRIVES: "
            f"{FLEET_CHECK}",
            "",
            "This project suite's subject is a file in the fleet bundle, so a fleet-side change "
            "like this is expected to need a matching update HERE rather than to fail as a "
            "string assertion somewhere below (agents-o8jd).",
            "",
        ]
        for anchor, why in sorted(missing.items()):
            lines.append(f"  MISSING {anchor!r} - needed by: {why}")
        lines += [
            "",
            "What to do: if the bundle still offers this capability under a new name or wording, "
            "update FLEET_BUNDLE_ANCHORS and the dependent assertion in the same change; if the "
            "capability is GONE, this suite must stop depending on it (or be deleted with the "
            "interface it tests).",
        ]
        self.fail("\n".join(lines))

    def test_the_anchor_check_fires_when_an_anchor_is_missing(self):
        """A green run above must mean the check looked, not that it is dead code."""
        complete = "\n".join(FLEET_BUNDLE_ANCHORS)
        self.assertEqual({}, missing_bundle_anchors(complete))
        for anchor, why in FLEET_BUNDLE_ANCHORS.items():
            broken = complete.replace(anchor, "")
            self.assertEqual({anchor: why}, missing_bundle_anchors(broken),
                             f"dropping {anchor!r} must be reported, and only it")


if __name__ == "__main__":
    unittest.main()
