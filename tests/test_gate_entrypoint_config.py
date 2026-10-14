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

import hashlib
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
    env["FLEET_CHECK_CONF"] = str(Path(home) / ".fleet" / "check.conf")  # agents-0utp: name the host-wide file explicitly; it is no longer the default
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
        # agents-1i7v: this grammar used to be `NAME="value"` only, so on the real
        # tools/check.conf it returned CHECK_CMD and CHECK_FAST_CMD and SILENTLY omitted
        # CHECK_TIMEOUT and CHECK_FAST_TIMEOUT, which are unquoted shell integers. A field that
        # exists in the file and not in the parse is a pin that cannot fail for what it names,
        # and it made "which fields exist" depend on which test module you asked. The grammar
        # below is the same one tests/test_check_conf_consistency.py uses: a quoted value (for a
        # command string, which may contain inner quotes and spaces) or a single bare token (for
        # a numeric bound). Anchoring, the [A-Z_]+ name and the end-of-line anchor are unchanged,
        # so comments, fragments and trailing junk are still rejected - the narrowness this
        # regex had was incidental to its purpose, not the protection it provided.
        m = re.match(r'^([A-Z_]+)=(?:"(.*)"|(\S+))\s*$', line.strip())
        if m:
            fields[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
    return fields


# agents-825v: every temp HOME this suite creates is REGISTERED, so a test that leaks a detached
# worker fails HERE rather than after the suite exits. The leak is measured rather than imagined: a
# fixture that fabricates FLEET_CHECKS_DIR and drives the real entrypoint can leave a fleet-heavy
# worker orphaned to ppid 1 holding the VM's single heavy slot - seen as the fleet-heavy "descendants
# still held slot1" warning in the landing-gate logs, and as a husk still alive 1h50m later, orphaned,
# with its temp HOME already deleted.
#
# MODULE-LEVEL ON PURPOSE: the suite's 13 temp-HOME sites span SIX test classes (1+2+4+1+2+3), so a
# helper defined on one class is an AttributeError in the other five - measured, not foreseen: the
# first attempt failed with exactly that, 9 errors. They take the case explicitly for the same reason.
#
# AND THE CHECK IS SCOPED TO THIS TEST'S OWN HOME, deliberately: a global process diff would fire on
# another lane's perfectly legitimate in-flight gate, and a machine-state assertion that turns an
# unrelated change red is the defect class this suite already had to fix once (agents-3xqa).
def _registered_tmp_home(case: unittest.TestCase, prefix: str) -> str:
    """A temp HOME whose teardown asserts no live process still references it."""
    home = tempfile.mkdtemp(prefix=prefix)
    case.addCleanup(_assert_no_live_process_referencing, case, home)
    return home


def _assert_no_live_process_referencing(case: unittest.TestCase, path: str) -> None:
    """Fail if any live process still references the temp HOME this test was given (agents-825v).

    Reads /proc directly rather than shelling out, so the check does not depend on pgrep or ps being
    available, and skips this process, whose own argv can legitimately name the path while the
    assertion is being made. THREE CHANNELS, because argv alone missed a real leak (agents-qlqc): a
    detached worker can reference the home only through cwd or through an inherited environment.
    """
    survivors = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        # agents-qlqc (found by rev-825v): cmdline ALONE IS NOT ENOUGH. A leaked worker can reference
        # the temp HOME only through its working directory or its environment - the reviewer demonstrated
        # a detached process with cwd set to the home and an argv that never names it, which escaped this
        # tripwire while still holding the heavy slot. Measured here: that exact leak read NO on the
        # landed code and YES with all three channels checked. The survivor record NAMES the channel
        # that matched, because which one it was is what tells a reader what the fix has to cover.
        for channel, probe in (("argv", "cmdline"), ("cwd", None), ("env", "environ")):
            try:
                raw = os.readlink(f"/proc/{entry.name}/cwd").encode() if probe is None else (entry / probe).read_bytes()
            except OSError:
                continue
            printable = raw.replace(b"\x00", b" ")
            if path.encode() in printable:
                survivors.append((entry.name, channel, printable.decode("utf-8", "replace")[:200]))
                break
    case.assertEqual(
        survivors, [],
        f"a live process still references this test's temp HOME {path} after the test finished: "
        f"{survivors}. That is the agents-825v leak - a worker that outlived its parent and holds "
        f"the VM's single heavy slot. Kill it in this test's own cleanup, or stop the fixture "
        f"inheriting the environment.",
    )


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
        tmp = _registered_tmp_home(self, "ia3p-fresh-home-")
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
        home = _registered_tmp_home(self, "ia3p-positive-")
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
        home = _registered_tmp_home(self, "ia3p-regress-")
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

    WHAT THIS CLASS ENFORCES (agents-024z). The tests below install into a temp HOME and assert two
    properties: `--install` is idempotent and writes CHECK_CMD EQUAL to the tracked value, and a
    PRE-EXISTING stale, malformed or other-project file is REPAIRED by it (overwritten with the
    tracked values, with a warning for the foreign case).

    WHAT IT DELIBERATELY DOES NOT. It never reads the live ~/.fleet/check.conf, so it does NOT fail
    on a hand-tuned divergence in an operator's HOME - a claim the earlier wording here made ("this
    test FAILS ON ANY DIVERGENCE from the tracked command") and that this class cannot provide: a
    reader who trusted it would not write the test that is actually missing. The omission is chosen,
    not overlooked - that file is machine-global state, so asserting its contents would make this
    suite non-hermetic and turn it red on every host that has not run --install, which is the
    machine-state pathology the fleet's speed guidance names. What a divergent live file does in
    practice: the deployed entrypoint SOURCES it, so the live command is what runs until someone
    repairs it, and the repair is the install command that WRITES THAT FILE, which since agents-0utp is
    `bash tools/check-cmd.sh --install --global` (the bare form now writes a repo-local file the deployed
    gate does not read by default) - or editing tools/check.conf and re-running it). A stale PASS record cannot quietly hide that: the cache-hit
    path requires a record whose `.cmd` equals the command actually resolved, which
    TestTheEntrypointResolvesTheInstalledCommand pins. Drift between the TRACKED file and CI is
    guarded by tests/test_check_conf_consistency.py, not here.

    HONEST LIMIT, AND IT MAKES THE STRICTER CHOICE CORRECT: from the files alone, a HAND-TUNED
    override and a STALE INSTALL are the same bytes. There is no marker that distinguishes "I
    meant this locally" from "the tracked file moved on". So --install refuses to guess and
    overwrites both, which is what the repair tests below measure; the documented way to update or
    tune is editing tools/check.conf and re-running the install command that writes the file you mean
    (`--install --global` for the host-wide config the deployed gate reads).
    """

    def test_install_is_idempotent_and_matches_the_tracked_command(self):
        home = _registered_tmp_home(self, "ia3p-drift-")
        env = dict(os.environ)
        env["HOME"] = home
        env["FLEET_CHECK_CONF"] = str(Path(home) / ".fleet" / "check.conf")  # agents-0utp: name the host-wide file explicitly; it is no longer the default
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

        # agents-024z: the header --install writes into EVERY VM's live config is the only prose
        # most operators ever read about this guard, and it used to promise one this suite cannot
        # keep (it said the suite "fails on any divergence", which it cannot detect because it
        # never reads the live file). The two facts the header may state are pinned here: the file
        # is machine-global, and it names the repair. The negative assertion is what makes the
        # false promise unable to come back - it is the falsifiable half of this bead.
        #
        # agents-0utp: AND IT MUST NAME WHICH LIFE THIS COPY LEADS, not assert the global one
        # whatever the destination was. At the default path the global claim is true; the
        # discriminating case is the next test, where FLEET_CHECK_CONF points at a per-repo
        # override and the same header would have told its reader that --install maintains it -
        # while --install without the variable replaces the host's shared file instead.
        self.assertIn("THIS COPY IS MACHINE-GLOBAL", installed)
        self.assertIn("BY DEFAULT for any repo invoked", installed)
        # agents-0utp FOLLOW-UP: the GLOBAL life's repair command must be the one that WRITES THIS FILE, and
        # after the default moved that is --global. The assertion that used to stand here pinned the bare form
        # and justified it with "it rewrites this very file" - which stopped being true the moment --install
        # defaulted to a repo-local destination. So the test was pinning a repair that writes somewhere else
        # and leaves this file stale: agents-d081's failure mode, a fix that cannot reach the copy that runs.
        self.assertIn("--install --global", installed)
        self.assertNotIn("re-run: bash tools/check-cmd.sh --install", installed,
                         "the machine-global copy must not be told to run the bare form: that writes the "
                         "repo-local default instead and leaves this file, which fleet-check reads, stale")
        self.assertIn("--install", installed)
        self.assertNotIn("fails on any divergence", installed,
                         "the emitted header must not promise a guard no test performs "
                         "(agents-024z): nothing in this suite reads the live per-VM file")

    def test_header_names_a_per_repo_override_as_repo_local_rather_than_machine_global(self):
        """agents-0utp, the discriminating half of the pair above: with FLEET_CHECK_CONF pointing at a
        per-repo path, the SAME generator must not write a header that calls the file machine-global.

        The defect this pins: the header asserted MACHINE-GLOBAL whatever $dest was, so a repo-local override
        described itself as the host's shared config and named a repair that does not write it. agents-0utp
        FOLLOW-UP (this revision): the previous wording of this test also pinned a sentence that had gone stale
        in the OPPOSITE direction - "running --install WITHOUT it set replaces the machine-global
        ~/.fleet/check.conf" - which was true before the default moved and false after, so the header kept
        warning about a trap the tool no longer sets. The trap now is that a bare --install writes a DIFFERENT
        file than the one in front of the reader, and that is what is asserted below.
        """
        home = _registered_tmp_home(self, "0utp-lives-")
        dest = Path(home) / "repo-override" / "agents-factory-check.conf"
        env = dict(os.environ)
        env["HOME"] = home
        env["FLEET_CHECK_CONF"] = str(dest)
        r = subprocess.run(["bash", str(RESOLVER), "--install"],
                           capture_output=True, text=True, timeout=60, env=env, cwd=str(ROOT))
        self.assertEqual(r.returncode, 0, r.stderr[:300])

        installed = dest.read_text(encoding="utf-8")
        self.assertIn("THIS COPY IS AN EXPLICIT OVERRIDE", installed)
        self.assertIn(str(dest), installed,
                      "an override must name the path it is read from, or the reader cannot tell "
                      "which file FLEET_CHECK_CONF has to name")
        self.assertNotIn("THIS COPY IS MACHINE-GLOBAL", installed,
                         "with FLEET_CHECK_CONF set this file is NOT the host's shared config; a header "
                         "that says it is tells the reader that --install maintains it (agents-0utp)")
        self.assertIn("NOT machine-global", installed,
                      "the header must state the negative too: an override is neither the host-wide file nor "
                      "the repo-local default, and a reader who assumes either runs the wrong repair")
        repo_default = Path(home) / ".fleet" / f"{ROOT.name}-check.conf"
        self.assertIn(str(repo_default), installed,
                      "an explicit override must name the file a bare --install WOULD write (agents-0utp "
                      "follow-up): the old header said a bare install replaces the host's shared config, which "
                      "stopped being true when the default moved, and a reader who believes it cannot see that "
                      "the obvious repair targets a different file")
        self.assertNotIn("replaces the machine-global", installed,
                         "the override header must not describe the pre-default-move behaviour of a bare "
                         "--install (agents-0utp follow-up)")
        # agents-mnvd, the review finding on the first attempt: the header warned that a bare --install replaces
        # the host's shared config and then, four lines later, instructed the reader to run exactly that. The
        # tune instruction must select THIS file. Both assertions below fail on tip 31582544.
        tail = installed[installed.index("To tune"):]
        self.assertIn("FLEET_CHECK_CONF=", tail,
                      "an override's tune instruction must name the variable, or it hands the reader the bare "
                      "command the header just warned about (agents-mnvd)")
        self.assertNotIn("re-run: bash tools/check-cmd.sh --install", tail,
                         "the override header must not carry the unqualified install command at all")
        self.assertFalse((Path(home) / ".fleet" / "check.conf").exists(),
                         "installing to an override must NOT also write the machine-global path")

    def test_install_overwrites_stale_per_vm_config_with_tracked_values(self):
        """When an existing per-VM check.conf carries a stale command (e.g. without -t .),
        running --install must overwrite it with the tracked hermetic command."""
        home = _registered_tmp_home(self, "ia3p-stale-")
        conf = Path(home) / ".fleet" / "check.conf"
        conf.parent.mkdir(parents=True)
        conf.write_text('CHECK_CMD="python3 -m unittest discover -s tests -v"\n', encoding="utf-8")

        env = dict(os.environ)
        env["HOME"] = home
        env["FLEET_CHECK_CONF"] = str(Path(home) / ".fleet" / "check.conf")  # agents-0utp: name the host-wide file explicitly; it is no longer the default

        r = subprocess.run(["bash", str(RESOLVER), "--install"],
                           capture_output=True, text=True, timeout=60, env=env, cwd=str(ROOT))
        self.assertEqual(r.returncode, 0, r.stderr[:300])

        installed = conf.read_text(encoding="utf-8")
        tracked_cmd = _tracked_fields()["CHECK_CMD"]
        self.assertIn(tracked_cmd, installed)
        self.assertIn('CHECK_CMD="bash tools/full-gate.sh"', installed)

    def test_install_overwrites_malformed_per_vm_config_with_tracked_values(self):
        """agents-r1o7: when an existing per-VM check.conf contains invalid syntax or corruption,
        running --install must repair it from tracked defaults without failing during sourcing."""
        home = _registered_tmp_home(self, "ia3p-malformed-")
        conf = Path(home) / ".fleet" / "check.conf"
        conf.parent.mkdir(parents=True)
        conf.write_text('SYNTAX ERROR = %%% not valid bash\n', encoding="utf-8")

        env = dict(os.environ)
        env["HOME"] = home
        env["FLEET_CHECK_CONF"] = str(Path(home) / ".fleet" / "check.conf")  # agents-0utp: name the host-wide file explicitly; it is no longer the default

        r = subprocess.run(["bash", str(RESOLVER), "--install"],
                           capture_output=True, text=True, timeout=60, env=env, cwd=str(ROOT))
        self.assertEqual(r.returncode, 0, f"install must repair malformed config: {r.stderr}")

        installed = conf.read_text(encoding="utf-8")
        tracked_cmd = _tracked_fields()["CHECK_CMD"]
        self.assertIn(tracked_cmd, installed)
        self.assertIn('CHECK_CMD="bash tools/full-gate.sh"', installed)

    def test_install_warns_when_overwriting_foreign_project_config(self):
        """agents-f6no: when ~/.fleet/check.conf already exists without agents-factory stamp
        (e.g. written by another project on a shared-HOME host), --install must warn to stderr
        and stamp the project name and machine-global scope in the header."""
        home = _registered_tmp_home(self, "f6no-foreign-")
        conf = Path(home) / ".fleet" / "check.conf"
        conf.parent.mkdir(parents=True)
        conf.write_text('CHECK_CMD="echo OTHER_PROJECT_GATE"\n', encoding="utf-8")

        env = dict(os.environ)
        env["HOME"] = home
        env["FLEET_CHECK_CONF"] = str(Path(home) / ".fleet" / "check.conf")  # agents-0utp: name the host-wide file explicitly; it is no longer the default

        r = subprocess.run(["bash", str(RESOLVER), "--install"],
                           capture_output=True, text=True, timeout=60, env=env, cwd=str(ROOT))
        self.assertEqual(r.returncode, 0)
        self.assertIn("WARNING", r.stderr)
        self.assertIn("not stamped by agents-factory", r.stderr)

        installed = conf.read_text(encoding="utf-8")
        self.assertIn("# Project: agents-factory", installed)
        self.assertIn("# THIS COPY IS MACHINE-GLOBAL", installed)

        # Idempotent second install should NOT warn
        r2 = subprocess.run(["bash", str(RESOLVER), "--install"],
                            capture_output=True, text=True, timeout=60, env=env, cwd=str(ROOT))
        self.assertEqual(r2.returncode, 0)
        self.assertNotIn("WARNING", r2.stderr)


# agents-0utp: --install DEFAULTS TO A REPO-LOCAL DESTINATION (tools/check-cmd.sh). Every case below is ABOUT the
# host-wide file - its subject is the per-VM config the whole machine reads - so each one now asks for it
# EXPLICITLY with --global. That is the intent-preserving change: the default moved, the subject did not.
class TestThePerVmConfigCanBeCheckedForDrift(unittest.TestCase):
    """agents-d081: --check is the detector this suite cannot be, and the reason is the same one
    agents-024z recorded for the docstring above - the drift lives in a MACHINE-GLOBAL file, so a test
    asserting the LIVE copy would be red on any host that has not run --install, which is the
    machine-state pathology that turns one lane's change red for everyone.

    So the capability is tested HERMETICALLY instead: every case below drives --check against a temp
    HOME, which proves the detector works without this suite reading the operator's file. Any caller
    that wants to inspect the live VM - provisioning, a fleet-side check, a lane that suspects its own
    gate - can run the mode directly. Measured motivation: on this VM the deployed copy predated the
    tracked file (no summary/tee wrapper in CHECK_CMD, CHECK_FAST_TIMEOUT 360 against the tracked 180)
    and nothing reported it.
    """

    def _run(self, *args, home):
        env = dict(os.environ)
        env["HOME"] = home
        env["FLEET_CHECK_CONF"] = str(Path(home) / ".fleet" / "check.conf")  # agents-0utp: name the host-wide file explicitly; it is no longer the default
        return subprocess.run(["bash", str(RESOLVER), *args], capture_output=True, text=True,
                              timeout=60, env=env, cwd=str(ROOT))

    def test_not_installed_in_sync_drift_and_malformed_are_each_distinguished(self):
        home = _registered_tmp_home(self, "d081-check-")
        conf = Path(home) / ".fleet" / "check.conf"

        # 1. NOTHING INSTALLED is not drift, but it is not silence either: a distinct code so a caller
        #    can tell "this VM was never installed" from "this VM has drifted".
        r = self._run("--check", home=home)
        self.assertEqual(r.returncode, 3, r.stderr[:300])
        self.assertIn("no per-VM config", r.stderr)

        # 2. Just installed: in sync, and it says so.
        self.assertEqual(self._run("--install", home=home).returncode, 0)
        r = self._run("--check", home=home)
        self.assertEqual(r.returncode, 0, r.stderr[:300])
        self.assertIn("in sync", r.stdout)

        # 3. ONE KEY DIVERGES, which is exactly the drift measured on this VM: the key is named, both
        #    values are shown, and the repair is stated - a failure message that teaches.
        text = conf.read_text(encoding="utf-8")
        self.assertIn("CHECK_FAST_TIMEOUT=180", text, "the tracked value this case mutates away")
        conf.write_text(text.replace("CHECK_FAST_TIMEOUT=180", "CHECK_FAST_TIMEOUT=360"),
                        encoding="utf-8")
        r = self._run("--check", home=home)
        self.assertEqual(r.returncode, 1, r.stderr[:300])
        self.assertIn("CHECK_FAST_TIMEOUT", r.stderr)
        self.assertIn("180", r.stderr)
        self.assertIn("360", r.stderr)
        self.assertIn("--install", r.stderr, "the drift message must name the repair")

        # 4. A MALFORMED COPY IS DRIFT, NOT A CRASH: --check must not source the file it is judging.
        conf.write_text('CHECK_CMD="unterminated\nnot shell at all (\n', encoding="utf-8")
        r = self._run("--check", home=home)
        self.assertEqual(r.returncode, 1,
                         f"--check must survive a malformed copy and report drift: {r.stderr[:300]}")

        # 5. A HAND-ADDED KEY IS DRIFT: --install writes exactly the tracked keys, so anything else in
        #    the per-VM file silently changes the gate's environment.
        self.assertEqual(self._run("--install", home=home).returncode, 0)
        conf.write_text(conf.read_text(encoding="utf-8") + 'CHECK_SNEAKY="true"\n', encoding="utf-8")
        r = self._run("--check", home=home)
        self.assertEqual(r.returncode, 1, r.stderr[:300])
        self.assertIn("CHECK_SNEAKY", r.stderr)

        # 6. THE RIGHT KEYS WITH NO PROJECT STAMP ARE STILL DRIFT, and this is the shape the real
        #    agents-factory VM was in when this detector was written (measured 2026-10-12): a copy
        #    produced by an --install from before the stamp existed (agents-f6no). The keys agree, so a
        #    key-only comparison would call it in sync; the provenance does not.
        self.assertEqual(self._run("--install", home=home).returncode, 0)
        stamped = conf.read_text(encoding="utf-8")
        conf.write_text(stamped.replace("# Project: agents-factory",
                                        "# Project: some-other-project", 1), encoding="utf-8")
        r = self._run("--check", home=home)
        self.assertEqual(r.returncode, 1, r.stderr[:300])
        self.assertIn("stamp", r.stderr)

        # 7. --quiet IS THE POINT-OF-USE FORM (tools/fast-gate.sh warns from it on every lane's gate
        #    run): one line naming the keys, the same exit code, and none of the verbose report - a
        #    warning that is eight lines long on every gate is one people learn to scroll past.
        self.assertEqual(self._run("--install", home=home).returncode, 0)
        conf.write_text(conf.read_text(encoding="utf-8").replace("CHECK_TIMEOUT=2400",
                                                                 "CHECK_TIMEOUT=99"),
                        encoding="utf-8")
        r = self._run("--check", "--quiet", home=home)
        self.assertEqual(r.returncode, 1, r.stderr[:300])
        self.assertIn("DRIFT keys:", r.stderr)
        self.assertIn("CHECK_TIMEOUT", r.stderr)
        self.assertNotIn("differs", r.stderr, "quiet means one line, not the full per-key report")

        # 8. AND THE FULL REPORT NAMES EVERY DIFFERING KEY at the end, so a reader (or a log) has the
        #    list in one place rather than having to reassemble it from the lines above.
        r = self._run("--check", home=home)
        self.assertEqual(r.returncode, 1, r.stderr[:300])
        self.assertIn("DRIFT keys: CHECK_TIMEOUT", r.stderr)
        # agents-p8lh: this assertion used to pin the BARE install command, and that is exactly what was wrong -
        # this class drifts the HOST-WIDE file (FLEET_CHECK_CONF is pointed at ~/.fleet/check.conf), and since
        # agents-0utp the bare form writes the repo-local default instead. The next class runs the printed
        # command and proves it repairs the file it names; here the shape is pinned for this destination.
        self.assertIn("repair with: bash tools/check-cmd.sh --install --global", r.stderr)


class TestTheFastGateWarnsAboutPerVmDriftAtThePointOfUse(unittest.TestCase):
    """agents-d081: A CHECK NOBODY RUNS IS NOT LOUD.

    A detector is worth what calls it, and the one surface in this repo that ALREADY runs on every lane
    is tools/fast-gate.sh - the deployed entrypoint invokes it via CHECK_FAST_CMD, and the suites in
    tests/test_fast_gate_mapping.py drive it directly. So the warning lives there: NAMED, on stderr, and
    NON-BLOCKING, because the per-VM config is machine-global and failing a gate on it would turn every
    lane red for a branch that is entirely innocent.

    BOTH DIRECTIONS ARE PINNED, and the silent one is the one that protects the fleet's speed: a drifted
    host is loud, an in-sync host is silent, a host with nothing installed is silent (a fresh VM
    legitimately has no per-VM file), and in no case does the verdict or the stdout contract change -
    the dry run's resolved suite list must not gain a line because of a machine's configuration.
    """

    def _run_gate(self, home, changed=".beads/metadata.json"):
        env = dict(os.environ)
        env["HOME"] = home
        env["FLEET_CHECK_CONF"] = str(Path(home) / ".fleet" / "check.conf")  # agents-0utp: name the host-wide file explicitly; it is no longer the default
        env["GIT_CHANGED"] = changed
        env["FAST_GATE_DRY_RUN"] = "1"
        return subprocess.run(["bash", str(ROOT / "tools" / "fast-gate.sh")], capture_output=True,
                              text=True, timeout=120, env=env, cwd=str(ROOT))

    def _install_into(self, home):
        env = dict(os.environ)
        env["HOME"] = home
        env["FLEET_CHECK_CONF"] = str(Path(home) / ".fleet" / "check.conf")  # agents-0utp: name the host-wide file explicitly; it is no longer the default
        return subprocess.run(["bash", str(RESOLVER), "--install"], capture_output=True, text=True,
                              timeout=60, env=env, cwd=str(ROOT))

    def test_drifted_is_loud_installed_and_absent_are_silent(self):
        # (a) THE SHAPE THIS VM WAS ACTUALLY IN: no stamp, CHECK_CMD without the capture wrapper, and a
        #     fast timeout of 360 against the tracked 180.
        home = _registered_tmp_home(self, "d081-point-of-use-")
        conf = Path(home) / ".fleet" / "check.conf"
        conf.parent.mkdir(parents=True)
        conf.write_text('CHECK_CMD="python3 -m unittest discover -s tests -t . -v"\n'
                        "CHECK_FAST_TIMEOUT=360\n", encoding="utf-8")
        drifted = self._run_gate(home)
        self.assertEqual(drifted.returncode, 0,
                         "the drift warning must NOT change the gate's verdict: the config is host-wide "
                         "and a failing gate would turn every lane red for an innocent branch")
        self.assertIn("WARNING (agents-d081)", drifted.stderr)
        self.assertIn("CHECK_FAST_TIMEOUT", drifted.stderr,
                      "the warning must NAME the keys that differ, not just that something did")
        self.assertIn("check-cmd.sh --install", drifted.stderr, "and name the repair")
        self.assertEqual(drifted.stdout.strip(), "",
                         "the dry-run stdout contract must be untouched by a machine's config")

        # (b) IN SYNC: the same run must be silent - a warning that fires on correct work is wallpaper.
        self.assertEqual(self._install_into(home).returncode, 0)
        in_sync = self._run_gate(home)
        self.assertEqual(in_sync.returncode, 0)
        self.assertNotIn("WARNING", in_sync.stderr)

        # (c) NOTHING INSTALLED: also silent. A fresh VM has no per-VM file, and that is not drift -
        #     exit code 3 exists precisely so the two states are not confused.
        empty = _registered_tmp_home(self, "d081-fresh-")
        fresh = self._run_gate(empty)
        self.assertEqual(fresh.returncode, 0)
        self.assertNotIn("WARNING", fresh.stderr)


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
        home = _registered_tmp_home(self, "l2xb-provision-")
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
        self.assertIn('CHECK_CMD="bash tools/full-gate.sh"', installed)

    def test_install_sh_repairs_a_stale_per_vm_config(self):
        """The 'repaired host' half of the acceptance, which is the half a fresh-host check
        cannot see: a per-VM copy predating the `-t .` hermeticity fix must be REPLACED by
        the tracked command when provisioning runs, not left in place."""
        home = _registered_tmp_home(self, "l2xb-repair-")
        conf = Path(home) / ".fleet" / "check.conf"
        conf.parent.mkdir(parents=True)
        conf.write_text('CHECK_CMD="python3 -m unittest discover -s tests -v"\n', encoding="utf-8")

        res = self._run_installer(home)
        self.assertEqual(res.returncode, 0, (res.stdout + res.stderr)[-600:])

        installed = conf.read_text(encoding="utf-8")
        self.assertIn(_tracked_fields()["CHECK_CMD"], installed)
        self.assertIn('CHECK_CMD="bash tools/full-gate.sh"', installed)

    def test_install_sh_says_what_it_repaired_and_checks_the_repair_landed(self):
        """agents-d081: THE REPAIR ABOVE USED TO BE SILENT, so a host that had been running a
        different gate command for days learned nothing when provisioning finally replaced it - and
        an install that could not write the config (read-only or wrong HOME) was still reported as a
        success. Both halves are pinned here: the drift is NAMED before it is replaced, and the
        config is verified against the tracked one afterwards."""
        home = _registered_tmp_home(self, "d081-loud-")
        conf = Path(home) / ".fleet" / "check.conf"
        conf.parent.mkdir(parents=True)
        # The measured shape of a drifted host: the pre-authored-via-an-older-installer command, with
        # a value that differs from the tracked one in a way a reader can see.
        conf.write_text('CHECK_CMD="python3 -m unittest discover -s tests -t . -v"\n'
                        'CHECK_FAST_TIMEOUT=360\n', encoding="utf-8")

        res = self._run_installer(home)
        self.assertEqual(res.returncode, 0, (res.stdout + res.stderr)[-600:])
        output = res.stdout + res.stderr
        self.assertIn("did not match the tracked one", output,
                      "a drift that provisioning repairs must be REPORTED, not repaired silently")
        self.assertIn("CHECK_FAST_TIMEOUT", output,
                      "the report must name the key that differed, not just that something did")
        self.assertNotIn("STILL differs", output,
                         "a successful install must leave the per-VM config equal to the tracked one")
        self.assertEqual(
            [(line.split("=", 1)[0], line) for line in conf.read_text(encoding="utf-8").splitlines()
             if line.startswith("CHECK_")],
            [(line.split("=", 1)[0], line)
             for line in TRACKED.read_text(encoding="utf-8").splitlines()
             if line.startswith("CHECK_")],
            "after provisioning the per-VM copy must be the tracked keys, line for line",
        )


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


class TestAFailedUpdateNamesItsFailureClass(unittest.TestCase):
    """agents-a1ko: the installer must CLASSIFY a failed update, not merely fail.

    WHY A CLASS AND NOT ONLY A FAILURE (agents-yow5 made the failure loud). The caller
    (remote/provision.sh:970) runs this installer with all output suppressed, so what an operator
    actually sees is a non-zero exit and nothing else - and a transient NETWORK outage and a
    DIVERGED checkout are the same exit code with OPPOSITE responses: retry later, versus
    investigate the checkout on the host. Naming the class in the installer's own output is the only
    thing that survives the suppression.

    EVERY SHAPE BELOW IS DRIVEN AGAINST REAL GIT, one fixture mutated three ways, so the
    classification is pinned to git's behaviour rather than to a string someone remembered. Two
    properties are asserted per case: the class the installer NAMES is the right one, and the two
    responses to the other classes do not appear - an operator who cannot distinguish them is where
    this started.

    THE THIRD CLASS IS THE HONEST ONE, and it is asserted rather than assumed to be unreachable: an
    unrecognised failure is reported as `checkout-local-state` instead of being guessed into one of
    the other two. For it the test asserts the CLASS and the git evidence, never git's wording,
    because that wording is not stable: MEASURED in two runs of the same shape on this VM, git said
    "error: cannot pull with rebase: You have unstaged changes." under the host's global
    pull.rebase=true, and "error: Your local changes to the following files would be overwritten by
    merge" with that setting pinned false. The fixture pins `pull.rebase=false` locally, and the
    run's environment blinds the host's git config, because a verdict that depends on the machine
    is a defect in the test rather than evidence about the installer.
    """

    IDENTITY = ["-c", "user.email=installer@test.invalid", "-c", "user.name=installer"]

    def _git(self, cwd: Path, *args: str) -> str:
        return subprocess.run(["git", "-C", str(cwd), *args], check=True,
                              capture_output=True, text=True).stdout

    def _seed_commit(self, seed: Path, origin: Path, message: str) -> None:
        self._git(seed, "add", "-A")
        subprocess.run(["git", "-C", str(seed), *self.IDENTITY, "commit", "-q", "-m", message],
                       check=True, capture_output=True, text=True)
        self._git(seed, "push", "-q", str(origin), "HEAD:refs/heads/main")

    def _working_checkout(self, root: Path) -> tuple[Path, Path, Path]:
        """A real checkout that CAN be pulled, so each shape is one mutation of it and the
        difference between two cases is the mutation rather than two different fixtures."""
        origin = root / "origin.git"
        seed = root / "seed"
        seed.mkdir()
        subprocess.run(["git", "init", "-q", "--bare", str(origin)], check=True)
        self._git(origin, "symbolic-ref", "HEAD", "refs/heads/main")
        subprocess.run(["git", "init", "-q", "-b", "main", str(seed)], check=True)
        (seed / "tracked.txt").write_text("one\n", encoding="utf-8")
        self._seed_commit(seed, origin, "one")

        checkout = root / "agents"
        subprocess.run(["git", "clone", "-q", str(origin), str(checkout)], check=True)
        self._git(checkout, "config", "pull.rebase", "false")
        return origin, seed, checkout

    def _run_installer(self, root: Path, checkout: Path, home: Path):
        """install.sh, run from OUTSIDE a checkout so the update branch is the one under test."""
        installer_dir = root / "installer"
        installer_dir.mkdir(exist_ok=True)
        installer = installer_dir / "install.sh"
        shutil.copy(ROOT / "install.sh", installer)
        env = _entrypoint_env(str(home))
        env["GIT_CONFIG_GLOBAL"] = os.devnull
        env["GIT_CONFIG_SYSTEM"] = os.devnull
        return subprocess.run(["bash", str(installer), "-d", str(checkout)],
                              capture_output=True, text=True, env=env, cwd=str(root),
                              timeout=120)

    def _assert_installs_nothing_and_names(self, res, home: Path, checkout: Path,
                                           expected: str, *not_expected: str) -> str:
        output = res.stdout + res.stderr
        self.assertNotEqual(res.returncode, 0, output)
        self.assertIn(f"FAILURE CLASS: {expected}", output,
                      "the installer must NAME the class of failure in its own output, because "
                      "provisioning suppresses everything else it prints")
        for other in not_expected:
            self.assertNotIn(f"FAILURE CLASS: {other}", output)
        short = self._git(checkout, "rev-parse", "--short", "HEAD").strip()
        self.assertIn(f"still at {short}", output,
                      "the message must say which revision the checkout is stuck at")
        self.assertIn("nothing was installed from it", output)
        self.assertFalse((home / ".pi").exists(),
                         "a failed update still linked skills into the agent hub")
        return output

    def test_an_unreachable_remote_is_named_as_unreachable(self):
        """The transient case: the remote is not there. Retrying later is the right response."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            home.mkdir()
            origin, _seed, checkout = self._working_checkout(root)
            shutil.rmtree(origin)

            output = self._assert_installs_nothing_and_names(
                self._run_installer(root, checkout, home), home, checkout,
                "remote-unreachable", "checkout-diverged", "checkout-local-state")
            self.assertIn("transient", output,
                          "the unreachable case must say it is usually transient, which is the "
                          "response it wants from an operator")

    def test_a_diverged_checkout_is_named_as_diverged(self):
        """The other operator-relevant case: the histories diverged, so retrying cannot help."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            home.mkdir()
            origin, seed, checkout = self._working_checkout(root)
            (checkout / "local.txt").write_text("local\n", encoding="utf-8")
            self._git(checkout, "add", "-A")
            subprocess.run(["git", "-C", str(checkout), *self.IDENTITY, "commit", "-q", "-m",
                            "local work"], check=True, capture_output=True, text=True)
            (seed / "tracked.txt").write_text("two\n", encoding="utf-8")
            self._seed_commit(seed, origin, "the remote moves on")

            output = self._assert_installs_nothing_and_names(
                self._run_installer(root, checkout, home), home, checkout,
                "checkout-diverged", "remote-unreachable", "checkout-local-state")
            self.assertIn("Investigate", output,
                          "the diverged case must ask for an investigation on the host rather "
                          "than a retry")

    def test_a_locally_modified_checkout_is_not_guessed_into_the_other_two_classes(self):
        """The honest third class: not the network, and not the word we would be guessing.

        A dirty checkout that the incoming commit would overwrite is neither transient nor
        diverged, and git's wording for it moves with the host's git config, which is exactly why
        it must be reported as unrecognised rather than mapped onto one of the named two.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            home.mkdir()
            origin, seed, checkout = self._working_checkout(root)
            (checkout / "tracked.txt").write_text("uncommitted edit\n", encoding="utf-8")
            (seed / "tracked.txt").write_text("remote change\n", encoding="utf-8")
            self._seed_commit(seed, origin, "the remote changes the same file")

            output = self._assert_installs_nothing_and_names(
                self._run_installer(root, checkout, home), home, checkout,
                "checkout-local-state", "remote-unreachable", "checkout-diverged")
            self.assertIn("  git: ", output,
                          "an unrecognised failure must carry git's own text as the evidence, "
                          "since the class is the installer's inference and the text is not")



    def test_a_denied_authentication_is_not_reported_as_a_transient_outage(self):
        """agents-uvzh (found reviewing this change): git's text for a REFUSED credential and for an
        UNREACHABLE remote OVERLAP - a denied key prints "Permission denied (publickey)." and then
        "fatal: Could not read from remote repository." (MEASURED here with a real pull against an ssh://
        remote whose GIT_SSH_COMMAND refuses). Until this class existed, the unreachable arm matched that
        text first, so an operator was told to retry a failure that retrying cannot fix - which is worse
        than no class at all, because the wording is an instruction."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            home.mkdir()
            _origin, _seed, checkout = self._working_checkout(root)
            stub = root / "ssh-refuses"
            stub.write_text("#!/bin/sh\necho 'Permission denied (publickey).' >&2\nexit 255\n",
                            encoding="utf-8")
            stub.chmod(0o755)
            self._git(checkout, "remote", "set-url", "origin", "ssh://git@example.invalid/repo.git")
            self._git(checkout, "config", "core.sshCommand", str(stub))

            res = self._run_installer(root, checkout, home)
            output = self._assert_installs_nothing_and_names(
                res, home, checkout, "remote-auth-denied", "remote-unreachable", "checkout-diverged")
            self.assertIn("Permission denied", output, "git's own text must be quoted as evidence")
            self.assertIn("NOT transient", output)
            self.assertNotIn("usually transient", output,
                             "the auth class must not borrow the unreachable wording: that wording is an "
                             "instruction to retry")

    def test_a_refused_connection_is_not_stolen_into_the_permanent_class(self):
        """agents-9fjb, THE MIRROR DIRECTION. The uvzh fix IS the arm order, so the property that needs a
        test is the one the fix creates: an eager auth arm must not capture a failure that is not
        authentication, or a network problem starts telling operators to stop retrying.

        REAL SSH, NO NETWORK, AND NO STUB: the remote is a closed port on loopback. Port 1 cannot be
        listened on without root, so the kernel refuses immediately - MEASURED output is ssh's
        "ssh: connect to host 127.0.0.1 port 1: Connection refused" followed by git's
        "fatal: Could not read from remote repository.", which is the SAME last line a refused key
        produces (test_a_denied_authentication_is_not_reported_as_a_transient_outage). That overlap is why
        the auth arm has to be both narrow and first, and why widening it to git's generic line would look
        harmless and swap the two classes.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            home.mkdir()
            _origin, _seed, checkout = self._working_checkout(root)
            self._git(checkout, "remote", "set-url", "origin", "ssh://git@127.0.0.1:1/repo.git")

            output = self._assert_installs_nothing_and_names(
                self._run_installer(root, checkout, home), home, checkout,
                "remote-unreachable", "remote-auth-denied", "checkout-diverged", "checkout-local-state")
            self.assertIn("transient", output,
                          "a refused connection is a network failure, so the transient instruction is the "
                          "right response and the mirror of the auth case")
            self.assertNotIn("FAILURE CLASS: remote-auth-denied", output,
                             "a closed port is not a credential problem: if the auth arm captures this, an "
                             "operator is told to fix a key when the network is what failed")

    def test_an_unresolvable_host_is_not_stolen_into_the_permanent_class(self):
        """The second mirror case, chosen because it fails on DNS POLICY rather than on this VM's
        connectivity: .invalid is reserved by RFC 6761 and never resolves, so the case needs no network and
        cannot pass or fail because a cable is unplugged. Same property as above - the failure is the
        network's, not the credential's.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            home.mkdir()
            _origin, _seed, checkout = self._working_checkout(root)
            self._git(checkout, "remote", "set-url", "origin",
                      "ssh://git@no-such-host.invalid/repo.git")

            output = self._assert_installs_nothing_and_names(
                self._run_installer(root, checkout, home), home, checkout,
                "remote-unreachable", "remote-auth-denied", "checkout-diverged", "checkout-local-state")
            self.assertIn("  git: ", output,
                          "the class is the installer's inference and git's text is the evidence, so the "
                          "unreachable case must carry it here too")
            self.assertNotIn("FAILURE CLASS: remote-auth-denied", output,
                             "a name that does not resolve is not a credential problem")

class TestTheDefaultInstallDestinationIsRepoLocal(unittest.TestCase):
    """agents-0utp ACCEPTANCE, which coord named and which nobody had run: INSTALL IN REPO A, GATE IN REPO B,
    GLOBAL UNTOUCHED - with the host-wide file's HASH UNCHANGED before and after, because 'untouched' is a claim
    about bytes and not about a command's exit code.

    Why the hash and not just existence: the hazard this bead was filed for is a repo's install OVERWRITING the
    shared config that other repos read, so an assertion that the file does not exist would pass on a machine
    where it never existed and say nothing about the overwrite. Here a foreign global config is created first,
    and the test asks the filesystem what it holds afterwards.
    """

    def test_default_install_writes_repo_local_and_leaves_the_host_wide_hash_unchanged(self):
        home = _registered_tmp_home(self, "0utp-abi-")
        global_conf = Path(home) / ".fleet" / "check.conf"
        global_conf.parent.mkdir(parents=True, exist_ok=True)
        pre = ('# Project: agents-factory (/some/other/repo)\n'
               'CHECK_CMD="bash tools/full-gate.sh"\n'
               'CHECK_FAST_CMD="bash tools/fast-gate.sh"\n')
        global_conf.write_text(pre, encoding="utf-8")
        before = hashlib.sha256(global_conf.read_bytes()).hexdigest()

        env = dict(os.environ)
        env["HOME"] = home
        env.pop("FLEET_CHECK_CONF", None)
        r = subprocess.run(["bash", str(RESOLVER), "--install"],
                           capture_output=True, text=True, timeout=60, env=env, cwd=str(ROOT))
        self.assertEqual(r.returncode, 0, r.stderr[:400])

        self.assertEqual(hashlib.sha256(global_conf.read_bytes()).hexdigest(), before,
                         "a DEFAULT --install must not write the host-wide config that every repo on this "
                         "machine reads (agents-0utp); the hash is the claim, the exit code is not")
        self.assertEqual(global_conf.read_text(encoding="utf-8"), pre,
                         "the host-wide file must be byte-identical afterwards")

        repo_conf = Path(home) / ".fleet" / f"{ROOT.name}-check.conf"
        self.assertTrue(repo_conf.exists(),
                        f"the default destination is the repo-local file, expected {repo_conf}")
        repo_text = repo_conf.read_text(encoding="utf-8")
        self.assertIn("THIS COPY IS THE REPO-LOCAL DEFAULT", repo_text,
                      "the file a bare --install writes must SAY it is the repo-local default: the header used "
                      "to call every destination machine-global, and after the default moved the more damaging "
                      "half of that was the repair it named (agents-0utp)")
        self.assertNotIn("THIS COPY IS MACHINE-GLOBAL", repo_text)
        self.assertIn("bash tools/check-cmd.sh --install", repo_text,
                      "in THIS life the bare form does write this file, so it is the correct repair to name")

    def test_global_flag_is_the_explicit_opt_in_for_the_host_wide_file(self):
        """The escape hatch has to work, or the default is a cage: provisioning (install.sh) claims the machine's
        config on purpose, and it does so by asking."""
        home = _registered_tmp_home(self, "0utp-global-")
        env = dict(os.environ)
        env["HOME"] = home
        env.pop("FLEET_CHECK_CONF", None)
        r = subprocess.run(["bash", str(RESOLVER), "--install", "--global"],
                           capture_output=True, text=True, timeout=60, env=env, cwd=str(ROOT))
        self.assertEqual(r.returncode, 0, r.stderr[:400])
        global_conf = Path(home) / ".fleet" / "check.conf"
        self.assertTrue(global_conf.exists(), "--global must still reach the host-wide path")
        self.assertIn("THIS COPY IS MACHINE-GLOBAL", global_conf.read_text(encoding="utf-8"))


class TestThePrintedRepairRepairsTheFileItNames(unittest.TestCase):
    """agents-p8lh (review finding on agents-0utp @ 4bcb1b48): --check's repair line named a command that
    writes a DIFFERENT file than the one it had just reported drift in, so a reader who followed the
    instruction kept the stale gate command running while believing it had repaired it. That is agents-d081's
    failure mode - a repair that cannot reach the copy that runs - and it is the fleet's most repeated defect
    shape: THE INSTRUCTION IS THE DEFECT.

    These tests assert the PROPERTY, not the wording: read the command the tool printed, RUN IT, ASK AGAIN,
    and the drift must be gone. That is what makes them the control coord asked for - a grep would have passed
    on the broken tip, because the broken tip printed a perfectly well-formed command that simply wrote a
    different file. Every destination --check can report on is covered, because the three cases answer with
    three different commands (--install --global / the bare form / FLEET_CHECK_CONF=<dest>).
    """

    def _write_drifting(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('# Project: agents-factory (/somewhere/else)\n'
                        'CHECK_CMD="bash tools/full-gate.sh"\n'
                        'CHECK_FAST_CMD="bash tools/fast-gate.sh"\n'
                        'CHECK_TIMEOUT=1\nCHECK_FAST_TIMEOUT=2\n', encoding="utf-8")

    def _env(self, home, extra=None):
        env = dict(os.environ)
        env["HOME"] = home
        env.pop("FLEET_CHECK_CONF", None)
        if extra:
            env.update(extra)
        return env

    def _check(self, env):
        return subprocess.run(["bash", str(RESOLVER), "--check"], capture_output=True, text=True,
                              timeout=60, env=env, cwd=str(ROOT))

    @staticmethod
    def _printed_repair(stderr):
        for line in stderr.splitlines():
            if "repair with:" in line:
                return line.split("repair with:", 1)[1].split("   (rewrites", 1)[0].strip()
        return ""

    def _assert_repair_reaches(self, home, extra, dest, expect_in_command):
        env = self._env(home, extra)
        first = self._check(env)
        self.assertEqual(first.returncode, 1, f"expected drift to be reported: {first.stderr[:300]}")
        self.assertIn(str(dest), first.stderr,
                      "the report must name the file it is about, or a reader cannot tell what is stale")
        repair = self._printed_repair(first.stderr)
        self.assertTrue(repair, f"--check must print the repair: {first.stderr[:300]}")
        self.assertIn(expect_in_command, repair,
                      f"the repair for {dest} must be the command that writes IT; got: {repair}")

        # THE PROPERTY: run exactly what it printed, then ask again. Through a shell, because that is what a
        # reader does with a printed command line - and because the FLEET_CHECK_CONF form is a shell assignment
        # prefix, not a program name.
        ran = subprocess.run(["bash", "-c", repair], capture_output=True, text=True, timeout=60,
                             env=env, cwd=str(ROOT))
        self.assertEqual(ran.returncode, 0, f"the printed repair must succeed: {ran.stderr[:300]}")
        second = self._check(env)
        self.assertEqual(second.returncode, 0,
                         "following the printed repair must REMOVE the drift it reported - on the tip before "
                         f"agents-p8lh this fails, because the command wrote a different file: {second.stderr[:300]}")

    def test_the_repair_for_the_host_wide_file_writes_the_host_wide_file(self):
        home = _registered_tmp_home(self, "p8lh-global-")
        self._write_drifting(Path(home) / ".fleet" / "check.conf")
        self._assert_repair_reaches(home, None, Path(home) / ".fleet" / "check.conf", "--install --global")

    def test_the_repair_for_an_explicit_override_writes_that_override(self):
        home = _registered_tmp_home(self, "p8lh-explicit-")
        dest = Path(home) / "elsewhere" / "team.conf"
        self._write_drifting(dest)
        self._assert_repair_reaches(home, {"FLEET_CHECK_CONF": str(dest)}, dest,
                                    f"FLEET_CHECK_CONF={dest}")

    def test_the_repair_for_the_repo_local_default_is_the_bare_form(self):
        home = _registered_tmp_home(self, "p8lh-repo-default-")
        dest = Path(home) / ".fleet" / f"{ROOT.name}-check.conf"
        self._write_drifting(dest)
        # A lane reaches the repo-local default exactly this way - the install NOTE tells it to set the variable
        # to the path it just wrote - and for THIS destination the bare form is the correct repair.
        self._assert_repair_reaches(home, {"FLEET_CHECK_CONF": str(dest)}, dest,
                                    "bash tools/check-cmd.sh --install")
        self.assertNotIn("--global", self._printed_repair(self._check(self._env(home, {"FLEET_CHECK_CONF": str(dest)})).stderr),
                         "the bare form writes this file; naming --global would write the host-wide one instead")

    def test_the_point_of_use_warning_names_the_same_repair(self):
        """tools/fast-gate.sh warns about drift on every gate, and it used to carry its own copy of the repair
        command - which is how it went on naming the pre-move one. It now asks the tool that owns the rule, so
        the warning and --check cannot disagree."""
        home = _registered_tmp_home(self, "p8lh-point-of-use-")
        self._write_drifting(Path(home) / ".fleet" / "check.conf")
        env = self._env(home)
        env["GIT_CHANGED"] = ".beads/metadata.json"
        env["FAST_GATE_DRY_RUN"] = "1"
        r = subprocess.run(["bash", str(ROOT / "tools" / "fast-gate.sh")], capture_output=True, text=True,
                           timeout=120, env=env, cwd=str(ROOT))
        self.assertIn("WARNING (agents-d081)", r.stderr)
        self.assertIn("repair: bash tools/check-cmd.sh --install --global", r.stderr,
                      "the point-of-use warning must name the command that writes the drifting file")
        self.assertNotIn("repair: bash tools/check-cmd.sh --install - ", r.stderr,
                         "and must not offer the form that writes a different file")


class TestTheReaderRefusesACommandThatCannotRunHere(unittest.TestCase):
    """agents-0r1c: the reader half of the machine-global check.conf hazard.

    agents-0utp fixed the WRITER and agents-p8lh made the printed repairs truthful, but a config ALREADY
    installed by another repo keeps being read: the live ~/.fleet/check.conf carries `bash tools/fast-gate.sh`
    and a suite command needing tools/ and tests/, which exist only in agents-factory. A gate in any other repo
    died with EXIT 127 - a message about a MISSING TOOL when the truth is a FOREIGN CONFIG - and nothing in the
    reader refused it. These tests are the acceptance coord named: a foreign stamped config carrying a
    repo-relative command, the reader run from a DIFFERENT repo, refusing and naming the repo - plus the
    controls that keep the guard from becoming its own defect.

    THE TWO CONTROLS ARE THE POINT. (1) A config whose paths all resolve here is NOT refused, even when its
    Project: stamp names another directory - a lane worktree of this same project is exactly that, and refusing
    on identity alone would turn every worktree gate red for an innocent branch. (2) The refusal is scoped to
    the OFFENDING FIELD: a caller asking for the one command that does resolve here still gets it. A guard that
    failed either control would be worse than the defect it prevents, which is why they are asserted rather than
    described. Removing the guard makes every refusal assertion below fail.
    """

    def _repo(self, tag, commands, stamp='# Project: agents-factory (/some/other/checkout)\n'):
        """A second repo that carries the reader (a copy of tools/check-cmd.sh + the tracked conf) and a HOME-level
        config describing commands that may or may not resolve in it - the shape of a lane worktree on a shared
        host, which is where this defect is measured."""
        home = Path(_registered_tmp_home(self, tag))
        repo = home / "repoB"
        (repo / "tools").mkdir(parents=True)
        for name in ("check-cmd.sh", "check.conf"):
            shutil.copy(ROOT / "tools" / name, repo / "tools" / name)
        conf = home / ".fleet" / "check.conf"
        conf.parent.mkdir(parents=True, exist_ok=True)
        conf.write_text(stamp + "".join(f'{k}="{v}"\n' for k, v in commands.items()), encoding="utf-8")
        env = dict(os.environ)
        env["HOME"] = str(home)
        env["FLEET_CHECK_CONF"] = str(conf)
        return repo, env

    def _read(self, repo, env, *args):
        return subprocess.run(["bash", "tools/check-cmd.sh", *args], capture_output=True, text=True,
                              timeout=60, env=env, cwd=str(repo))

    def test_a_foreign_command_that_cannot_run_here_is_refused_and_the_repo_is_named(self):
        repo, env = self._repo("0r1c-foreign-",
                               {"CHECK_CMD": "python3 -m unittest discover -s tests -t . -v",
                                "CHECK_FAST_CMD": "bash tools/fast-gate.sh"})
        r = self._read(repo, env, "CHECK_FAST_CMD")
        self.assertEqual(r.returncode, 2, f"the reader must REFUSE, not hand out a command that cannot run: {r.stdout}")
        self.assertEqual(r.stdout, "", "a refusal must not print a command for anyone to run")
        self.assertIn("REFUSING", r.stderr)
        self.assertIn("agents-factory", r.stderr,
                      "the refusal must name the repo the config came from, taken from the Project: stamp")
        self.assertIn("tools/fast-gate.sh", r.stderr, "and the path that does not exist here")
        self.assertIn("EXIT 127", r.stderr, "and why that matters: the failure reads as a missing tool")
        self.assertRegex(r.stderr, r"repair: .*check-cmd\.sh --install",
                         "every refusal must print the one-line repair (agents-0r1c)")

    def test_the_unittest_discovery_flag_is_checked_as_a_path(self):
        repo, env = self._repo("0r1c-suites-",
                               {"CHECK_CMD": "python3 -m unittest discover -s tests -t . -v",
                                "CHECK_FAST_CMD": "bash tools/fast-gate.sh"})
        r = self._read(repo, env)
        self.assertEqual(r.returncode, 2)
        self.assertIn("tests", r.stderr,
                      "-s tests names a directory, and a repo without it cannot run that command either")

    def test_the_refusal_is_scoped_to_the_offending_field(self):
        repo, env = self._repo("0r1c-scoped-",
                               {"CHECK_CMD": "bash tools/check-cmd.sh --check",
                                "CHECK_FAST_CMD": "bash tools/fast-gate.sh"})
        # CHECK_CMD names tools/check-cmd.sh, which IS here: it must still be reported.
        good = self._read(repo, env, "CHECK_CMD")
        self.assertEqual(good.returncode, 0, f"a resolvable command must not be refused: {good.stderr}")
        self.assertEqual(good.stdout.strip(), "bash tools/check-cmd.sh --check")
        bad = self._read(repo, env, "CHECK_FAST_CMD")
        self.assertEqual(bad.returncode, 2, "...and the sibling that cannot run is still refused")

    def test_a_config_whose_paths_resolve_here_is_not_refused(self):
        """THE FALSE-POSITIVE CONTROL. The stamp names another checkout, and every named path exists here: this
        is a lane worktree of the same project, and refusing it would make the guard a fleet-wide outage."""
        repo, env = self._repo("0r1c-legit-",
                               {"CHECK_CMD": "bash tools/check-cmd.sh --check",
                                "CHECK_FAST_CMD": "bash tools/check.conf"})
        r = self._read(repo, env, "CHECK_FAST_CMD")
        self.assertEqual(r.returncode, 0, f"a resolvable config must be read normally: {r.stderr}")
        self.assertEqual(r.stdout.strip(), "bash tools/check.conf")

    def test_an_unstamped_config_is_refused_without_inventing_a_culprit(self):
        repo, env = self._repo("0r1c-unstamped-", {"CHECK_FAST_CMD": "bash tools/fast-gate.sh"}, stamp="")
        r = self._read(repo, env, "CHECK_FAST_CMD")
        self.assertEqual(r.returncode, 2, "an unstamped config can still name a command that cannot run here")
        self.assertIn("no 'Project:' stamp", r.stderr)
        self.assertNotIn("was installed by", r.stderr,
                         "the reader must not attribute a file nobody stamped to a repo")

    def test_install_still_repairs_an_unrunnable_config(self):
        """THE WAY OUT HAS TO SURVIVE THE GUARD: if --install were refused too, the refusal would be a trap -
        the only command that can fix the config is the one the config's state disables."""
        repo, env = self._repo("0r1c-repair-", {"CHECK_CMD": "bash tools/full-gate.sh",
                                                "CHECK_FAST_CMD": "bash tools/fast-gate.sh"})
        r = self._read(repo, env, "--install")
        self.assertEqual(r.returncode, 0, f"--install must still work on a broken config: {r.stderr[:300]}")
        self.assertIn("installed the project's gate command", r.stdout)


if __name__ == "__main__":
    unittest.main()


