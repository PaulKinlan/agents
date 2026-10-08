"""Integrity-pinned resolution of host-side trusted tools (agents-7bj).

The factory resolves gh/bd/git/semgrep/gitleaks/node/npm/npx by name; a trojaned binary
earlier on PATH would run with the factory's privileges. lib/tool_pins resolves each by
absolute path + SHA-256 and fails closed on a missing pin or a mismatch. These tests use a
temp directory of fake executables and a temp pins config, so they exercise the
resolution/verification logic without touching the real tools.
"""

import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lib.tool_pins import (ToolPinError, allowlisted_path, load_tool_pins, resolve_tool,
                           sha256_file, tool_dir, verify_pin)


def _make_tool(directory: Path, name: str, content: str = "#!/bin/sh\nexit 0\n") -> Path:
    path = directory / name
    path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


class ResolveToolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="toolpins-"))
        self.bindir = self.tmp / "bin"
        self.bindir.mkdir()
        self.gh = _make_tool(self.bindir, "gh")
        self.gh_sha = sha256_file(self.gh)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_resolve_verifies_matching_sha_pin(self):
        path = resolve_tool("gh", path_env=str(self.bindir),
                            pins={"gh": {"sha256": self.gh_sha}})
        self.assertEqual(Path(path).resolve(), self.gh.resolve())

    def test_resolve_fails_closed_on_sha_mismatch(self):
        self.gh.write_text("#!/bin/sh\necho TROJAN\n", encoding="utf-8")
        with self.assertRaises(ToolPinError):
            resolve_tool("gh", path_env=str(self.bindir),
                         pins={"gh": {"sha256": self.gh_sha}})

    def test_resolve_fails_closed_when_unpinned(self):
        # A trusted tool with no sha256 pin must be refused, not silently resolved by PATH.
        # Other test modules opt out globally; force the opt-out OFF for this one test.
        with mock.patch.dict(os.environ, {"FACTORY_ALLOW_UNPINNED_TOOLS": "0"}):
            with self.assertRaises(ToolPinError):
                resolve_tool("gh", path_env=str(self.bindir), pins={})

    def test_resolve_unpinned_allowed_by_explicit_opt_in(self):
        with mock.patch.dict(os.environ, {"FACTORY_ALLOW_UNPINNED_TOOLS": "1"}):
            path = resolve_tool("gh", path_env=str(self.bindir), pins={})
        self.assertEqual(Path(path).resolve(), self.gh.resolve())

    def test_resolve_fails_closed_on_path_mismatch(self):
        pins = {"gh": {"path": "/nowhere/gh", "sha256": self.gh_sha}}
        with self.assertRaises(ToolPinError):
            resolve_tool("gh", path_env=str(self.bindir), pins=pins)

    def test_resolve_fails_closed_when_unresolvable(self):
        with self.assertRaises(ToolPinError):
            resolve_tool("no-such-tool", path_env=str(self.bindir), pins={})

    def test_resolve_uses_configured_path_over_path_order(self):
        other = self.tmp / "other"
        other.mkdir()
        planted = _make_tool(other, "gh", "#!/bin/sh\necho PLANTED\n")
        pins = {"gh": {"path": str(self.gh), "sha256": self.gh_sha}}
        path = resolve_tool("gh", path_env=str(other) + os.pathsep + str(self.bindir), pins=pins)
        self.assertEqual(Path(path).resolve(), self.gh.resolve())
        self.assertNotEqual(Path(path).resolve(), planted.resolve())

    def test_path_pin_without_sha_is_a_config_error(self):
        cfg = self.tmp / "tools.yaml"
        cfg.write_text("gh:\n  path: /usr/bin/gh\n", encoding="utf-8")
        with self.assertRaises(ToolPinError):
            load_tool_pins(cfg)

    def test_non_hex_sha_is_rejected_on_load(self):
        cfg = self.tmp / "tools.yaml"
        cfg.write_text("gh:\n  sha256: not-hex\n", encoding="utf-8")
        with self.assertRaises(ToolPinError):
            load_tool_pins(cfg)

    def test_verify_pin_checks_configured_path(self):
        # P1-3: verify_pin must reject a resolved path that is not the pinned path.
        other = self.tmp / "other"; other.mkdir()
        rogue = _make_tool(other, "gh")
        pins = {"gh": {"path": str(self.gh), "sha256": self.gh_sha}}
        with self.assertRaises(ToolPinError):
            verify_pin("gh", str(rogue), pins)


class AllowlistedPathTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="toolpins-path-"))
        self.bin_a = self.tmp / "a"; self.bin_a.mkdir()
        self.bin_b = self.tmp / "b"; self.bin_b.mkdir()
        self.bin_c = self.tmp / "c"; self.bin_c.mkdir()
        _make_tool(self.bin_a, "gh")
        _make_tool(self.bin_b, "bd")
        _make_tool(self.bin_c, "planted")
        self.path_env = os.pathsep.join(str(p) for p in (self.bin_a, self.bin_b, self.bin_c))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_allowlisted_path_contains_resolved_tool_dirs_and_system_dirs(self):
        with mock.patch.dict(os.environ, {"FACTORY_ALLOW_UNPINNED_TOOLS": "1"}):
            result = allowlisted_path(("gh", "bd"), path_env=self.path_env, pins={})
        entries = result.split(os.pathsep)
        self.assertIn(str(self.bin_a.resolve()), entries)
        self.assertIn(str(self.bin_b.resolve()), entries)
        # System bin dirs are kept so a wrapped/shimmed tool's shebang (env, bash) resolves.
        for d in ("/usr/bin", "/bin"):
            self.assertIn(d, entries)
        # An unrelated dir earlier on PATH is excluded, so a planted tool cannot be picked up.
        self.assertNotIn(str(self.bin_c.resolve()), entries)

    def test_tool_dir_is_the_resolved_binarys_parent(self):
        with mock.patch.dict(os.environ, {"FACTORY_ALLOW_UNPINNED_TOOLS": "1"}):
            self.assertEqual(tool_dir("gh", path_env=self.path_env, pins={}),
                             str(self.bin_a.resolve()))

    def test_allowlisted_path_fails_closed_on_unresolvable_tool(self):
        with self.assertRaises(ToolPinError):
            allowlisted_path(("gh", "missing"), path_env=self.path_env, pins={})

    def test_allowlisted_path_supports_a_wrapped_bash_tool(self):
        # P0-1: a `bd` that is `#!/usr/bin/env bash` needs env/bash on PATH. The allowlisted
        # PATH must keep the standard system bin dirs, or the wrapper exits 127 and no bead is
        # filed. Here the wrapped tool's own dir + /usr/bin (where bash/env live) are present,
        # while an unrelated planted dir is not.
        wrapped = _make_tool(self.bin_b, "bd", "#!/usr/bin/env bash\nexit 0\n")
        with mock.patch.dict(os.environ, {"FACTORY_ALLOW_UNPINNED_TOOLS": "1"}):
            result = allowlisted_path(("bd",), path_env=self.path_env, pins={})
        entries = result.split(os.pathsep)
        self.assertIn(str(self.bin_b.resolve()), entries)  # the wrapped tool's own dir
        self.assertIn("/usr/bin", entries)  # bash + env live here
        self.assertIn("/bin", entries)
        self.assertNotIn(str(self.bin_c.resolve()), entries)


if __name__ == "__main__":
    unittest.main()
