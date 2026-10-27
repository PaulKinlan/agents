#!/usr/bin/env python3
"""Live bd JSON contract, isolated to a disposable local Dolt DB (no GitHub or remote)."""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lib.sinks.beads import _bd_json

# A HANG GUARD, NOT A MEASUREMENT (agents-e3r9p). Nothing in this module asserts how fast `bd` is - the
# contract under test is the real CLI's JSON SHAPES - so this bound only exists to stop a wedged binary from
# wedging the gate. It was 60 s, which is below what a cold `bd init` costs on the fleet VM: the test
# builds an EMPTY HOME/XDG config+data home on purpose, so bd bootstraps its dolt data directory and runs
# its migrations from nothing every time. Measured on the agents-factory VM with bd 1.3.1: 71.70 s with the
# ambient HOME, 99.20 s with this test's isolated env. `lib/findings.py` maps to this module, so a 60 s
# guard here failed the fast gate for every lib/findings change - and the merger's full gate with it - for a
# reason no author could fix. Do not make this a skip: that would drop the contract on exactly the hosts
# where it matters.
#
# RAISED AGAIN FOR A DIFFERENT REASON (agents-fzcs6): the 240 s above is above this test's OWN cost
# (99.20 s), but it is not above the cost of WAITING FOR `bd` AT ALL on this VM. tests run with the
# fleet's `bd` shim, which serialises every bd call VM-wide on one flock (fleet/bin/bd, fleet-tm5/e10 -
# the embedded Dolt DB allows one process at a time), so a cold `bd init` here queues behind whatever the
# lanes, the inbox and the dashboard are doing. Measured during the failing full gate: `bd init` was
# still waiting at 240 s while a concurrent lane held the lock. A bound has to cover the queue, not only
# the work, or it fails for contention rather than for anything the test did. 600 s is ~6x the isolated
# measurement and covers a busy fleet; the structural fix (running bd-touching modules in a serial phase
# instead of among four parallel shards) is a gate-scheduling decision and is NOT made here.
_BD_GUARD_S = 600


def _real_binary(name):
    """The first PATH hit for `name` that is a real executable IMAGE, never a wrapper SCRIPT.

    WHY NOT `shutil.which`, AND WHY NOT A STRING MATCH ON THE WRAPPER'S PATH EITHER (agents-gd5kp).
    On the fleet VM the first PATH hit for `bd` is `~/fleet/bin/bd`: a bash wrapper whose entire job is
    `flock -w 300 ~/.fleet/bd.lock <real bd>`, so a test that spawns it puts a HOST-GLOBAL lock between
    itself and its own subject - the wall becomes a fact about how many other lanes are calling bd, and
    the wait tops out at the wrapper's own 300 s lock timeout rather than at anything the tree controls.
    That wrapper also CANNOT RUN under this module's isolated HOME, which is not optional here: the
    wrapper's lock file is `$HOME/.fleet/bd.lock`, and the temp HOME has no `.fleet` directory, so
    `flock` exits 66 without exec'ing bd at all (measured: `env -i PATH=/usr/bin:/bin HOME=$tmp
    flock -w 5 $tmp/.fleet/bd.lock true` -> "cannot open lock file", rc 66).

    The rule this module used to carry - "if the PATH hit's last three components are fleet/bin/bd, use
    $HOME/.local/bin/bd instead" - stated that property about ONE host: install the same wrapper
    anywhere else and this module silently targets the wrapper, i.e. the verdict becomes an observation
    about the machine, which is the defect class agents-21ap and agents-v1a2 fixed for tool pins. It
    also resolved a tool from `$HOME` while deliberately replacing `$HOME` for the child, which is the
    same contradiction in a smaller place.

    So the wanted property is stated as a property of the FILE: a wrapper is a script (`#!`), a real
    tool is a mapped executable image. When only a wrapper is on PATH this returns None and the module
    SKIPS - the honest answer, because a wrapper cannot be trusted to be the subject under test.
    """
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry:
            continue
        candidate = Path(entry) / name
        try:
            if not candidate.is_file() or not os.access(candidate, os.X_OK):
                continue
            with open(candidate, "rb") as handle:
                header = handle.read(2)
        except OSError:
            continue
        if header == b"#!":
            continue
        return str(candidate)
    return None


def _real_bd():
    return _real_binary("bd")


@unittest.skipUnless(_real_bd(), "real bd binary is not installed on PATH")
class TestRealBdJsonContract(unittest.TestCase):
    def test_promote_issue_create_update_and_exhaustive_list_json_shapes(self):
        # Verified with bd 1.3.1 (c1c4b642a, 2026-10-07). The real CLI returns
        # create -> object, update -> ARRAY of one object, list -> array of objects.
        # Unlike the recorder, bd does not enforce external_ref uniqueness itself;
        # promotion's exhaustive list + duplicate refusal must not be removed.
        with tempfile.TemporaryDirectory(prefix="factory-bd-contract-") as tmp:
            root = Path(tmp)
            repo = root / "scratch-repo"
            repo.mkdir()
            for directory in ("home", "config", "data"):
                (root / directory).mkdir()
            env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": str(root / "home"),
                "XDG_CONFIG_HOME": str(root / "config"),
                "XDG_DATA_HOME": str(root / "data"),
                "GIT_CONFIG_GLOBAL": str(root / "gitconfig"),
                "BD_NON_INTERACTIVE": "1",
                "BD_NO_REMOTE_ADOPT": "1",
                "BEADS_ACTOR": "factory-json-contract-test",
            }
            bd_bin = _real_bd()
            with mock.patch.dict(os.environ, env, clear=True):
                subprocess.run(["git", "init", "-q", str(repo)], cwd=root,
                               check=True, capture_output=True, timeout=20)
                self.assertEqual(subprocess.run(["git", "remote"], cwd=repo,
                                check=True, capture_output=True, text=True,
                                timeout=10).stdout.strip(), "")
                init = subprocess.run(
                    [bd_bin, "init", "--skip-hooks", "--skip-agents",
                     "--non-interactive", "--prefix", "scratch", "--quiet"],
                    cwd=repo, capture_output=True, text=True, timeout=_BD_GUARD_S)
                self.assertEqual(init.returncode, 0, init.stderr)
                self.assertTrue((repo / ".beads").is_dir())
                self.assertEqual(_bd_json(bd_bin, repo,
                                          ["list", "--all", "--json", "-n", "0"]), [])

                ref = "factory:github.com/example/repo:" + "a" * 64
                issue = "https://github.com/example/repo/issues/1"
                created = _bd_json(bd_bin, repo, [
                    "create", "--title", "[lint] Contract probe",
                    "--description", "Issue: " + issue,
                    "--type", "task", "--external-ref", ref, "--json",
                ])
                self.assertIsInstance(created, dict)
                bead_id = created.get("id")
                self.assertIsInstance(bead_id, str)
                self.assertRegex(bead_id, re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$"))
                self.assertEqual(created["external_ref"], ref)

                rows = _bd_json(bd_bin, repo, ["list", "--all", "--json", "-n", "0"])
                self.assertIsInstance(rows, list)
                self.assertTrue(all(isinstance(row, dict) for row in rows))
                matching = [row for row in rows if row.get("external_ref") == ref]
                self.assertEqual(len(matching), 1)
                self.assertTrue({"id", "external_ref", "description", "status"}
                                <= matching[0].keys())
                self.assertEqual(matching[0]["id"], bead_id)

                description = "Issue: " + issue + "\nFingerprint: " + "a" * 64
                updated = _bd_json(bd_bin, repo, [
                    "update", bead_id, "--description", description, "--json",
                ])
                self.assertIsInstance(updated, list)  # real bd 1.3.1, NOT the stub's object
                self.assertEqual(len(updated), 1)
                self.assertEqual(updated[0]["id"], bead_id)
                self.assertEqual(updated[0]["description"], description)
                rows = _bd_json(bd_bin, repo, ["list", "--all", "--json", "-n", "0"])
                self.assertEqual(next(row for row in rows if row["id"] == bead_id)[
                    "description"], description)
                # No bd dolt push/remote, no gh invocation, no project tracker touched.


class TestRealBinaryResolution(unittest.TestCase):
    """agents-gd5kp: resolution must never SELECT the wrapper that serialises on a host lock.

    These run against a synthetic PATH, so they say nothing about the host they run on and cost
    microseconds. They are what makes the rule above a rule: with the old `shutil.which`-plus-path
    -string-match resolver, `test_a_wrapper_elsewhere_on_path_is_skipped` fails on any host whose
    wrapper is installed anywhere other than `.../fleet/bin/bd`.
    """

    def _plant(self, root, name, body, executable=True):
        directory = root / name
        directory.mkdir()
        tool = directory / "bd"
        tool.write_bytes(body)
        if executable:
            tool.chmod(0o755)
        return directory, tool

    def test_a_wrapper_elsewhere_on_path_is_skipped_for_the_real_binary(self):
        # The wrapper is FIRST on PATH - exactly the fleet's order - and is not at the one path the
        # old rule knew about, so only a structural rule can find the binary behind it.
        with tempfile.TemporaryDirectory(prefix="factory-bd-resolve-") as tmp:
            root = Path(tmp)
            wrapper_dir, wrapper = self._plant(root, "wrapper", b"#!/bin/sh\nexit 66\n")
            real_dir, real = self._plant(root, "real", b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8)
            with mock.patch.dict(os.environ, {"PATH": f"{wrapper_dir}{os.pathsep}{real_dir}"}):
                self.assertEqual(_real_binary("bd"), str(real))
                self.assertNotEqual(_real_binary("bd"), str(wrapper))

    def test_only_a_wrapper_on_path_resolves_to_none_so_the_module_skips(self):
        # A wrapper cannot be run under the isolated HOME, so running it would fail for a reason that
        # is not the contract. None makes skipUnless say "real bd binary is not installed on PATH".
        with tempfile.TemporaryDirectory(prefix="factory-bd-resolve-") as tmp:
            wrapper_dir, _ = self._plant(Path(tmp), "wrapper", b"#!/bin/sh\nexit 66\n")
            with mock.patch.dict(os.environ, {"PATH": str(wrapper_dir)}):
                self.assertIsNone(_real_binary("bd"))

    def test_a_non_executable_file_named_bd_is_not_selected(self):
        with tempfile.TemporaryDirectory(prefix="factory-bd-resolve-") as tmp:
            root = Path(tmp)
            dead_dir, _ = self._plant(root, "not-exec", b"\x7fELF", executable=False)
            with mock.patch.dict(os.environ, {"PATH": str(dead_dir)}):
                self.assertIsNone(_real_binary("bd"))


if __name__ == "__main__":
    unittest.main()
