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

from lib.findings import _bd_json


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
                    cwd=repo, capture_output=True, text=True, timeout=60)
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
