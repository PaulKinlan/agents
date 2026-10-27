#!/usr/bin/env python3
"""Live bd JSON contract, isolated to a disposable local Dolt DB (no GitHub or remote)."""

import os
import re
import shutil
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


def _real_bd():
    selected = shutil.which("bd")
    if not selected:
        return None
    # On exe.dev the first PATH entry is a flock shim whose real binary is relative
    # to $HOME. The test deliberately changes HOME to an isolated temp directory, so
    # use the binary behind this known shim; ordinary bd installations need no shim.
    if Path(selected).parts[-3:] == ("fleet", "bin", "bd"):
        actual = Path.home() / ".local" / "bin" / "bd"
        return str(actual) if actual.is_file() and os.access(actual, os.X_OK) else None
    return selected


@unittest.skipUnless(_real_bd(), "real bd is not installed on PATH")
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


if __name__ == "__main__":
    unittest.main()
