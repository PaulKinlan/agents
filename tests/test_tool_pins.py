"""Integrity-pinned resolution of host-side trusted tools (agents-7bj).

The factory resolves gh/bd/git/semgrep/gitleaks/node/npm/npx by name; a trojaned binary
earlier on PATH would run with the factory's privileges. lib/tool_pins resolves each by
absolute path + SHA-256 and fails closed on a missing pin or a mismatch. These tests use a
temp directory of fake executables and a temp pins config, so they exercise the
resolution/verification logic without touching the real tools.
"""

import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lib.tool_pins import (TRUSTED_TOOLS, ToolPinError, allowlisted_path, host_pins_path,
                           load_tool_pins, resolve_tool, sha256_file, tool_dir, verify_pin)


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

    def test_bwrap_is_a_trusted_tool_and_fails_closed_when_unpinned(self):
        """agents-28nn: bwrap delivers the OS sandbox itself, and the wrap-verification
        proof cannot catch a fake bwrap that execs its child natively (the run directory
        is bound at the same host path inside and outside the wrap), so bwrap must be in
        the pinned set and refused when unpinned like every other trusted tool. The
        sandbox-side boundary property is pinned in tests/test_sandbox.py
        (TestBwrapPinBoundary)."""
        self.assertIn("bwrap", TRUSTED_TOOLS)
        _make_tool(self.bindir, "bwrap")
        with mock.patch.dict(os.environ, {"FACTORY_ALLOW_UNPINNED_TOOLS": "0"}):
            with self.assertRaises(ToolPinError):
                resolve_tool("bwrap", path_env=str(self.bindir), pins={})

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


class HostPinsTests(unittest.TestCase):
    """agents-3g6: FACTORY_TOOL_PINS host file is merged OVER tools.yaml (the out-of-band
    pin source that makes fail-closed deployable without editing the repo)."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="hostpins-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.gh = _make_tool(self.tmp, "gh")

    def test_host_pins_merge_over_repo_per_tool(self):
        repo = self.tmp / "tools.yaml"
        repo.write_text(
            f"gh:\n  path: /repo/gh\n  sha256: {sha256_file(self.gh)}\n"
            "bd:\n  sha256: " + "a" * 64 + "\n", encoding="utf-8")
        host = self.tmp / "host.pins.yaml"
        host_sha = "b" * 64
        host.write_text(f"gh:\n  path: {self.gh}\n  sha256: {host_sha}\n", encoding="utf-8")
        with mock.patch.dict(os.environ, {"FACTORY_TOOL_PINS": str(host)}):
            pins = load_tool_pins(path=repo)
        # gh is overridden by the host file; bd (not in the host file) keeps the repo entry.
        self.assertEqual(pins["gh"], {"path": str(self.gh), "sha256": host_sha})
        self.assertEqual(pins["bd"], {"sha256": "a" * 64})

    def test_host_pins_missing_file_is_no_change(self):
        repo = self.tmp / "tools.yaml"
        repo.write_text(f"gh:\n  sha256: {sha256_file(self.gh)}\n", encoding="utf-8")
        missing = self.tmp / "does-not-exist.pins.yaml"
        with mock.patch.dict(os.environ, {"FACTORY_TOOL_PINS": str(missing)}):
            pins = load_tool_pins(path=repo)
        self.assertEqual(pins["gh"], {"sha256": sha256_file(self.gh)})

    def test_host_pins_malformed_file_raises(self):
        host = self.tmp / "host.pins.yaml"
        host.write_text("gh:\n  sha256: not-hex\n", encoding="utf-8")
        with mock.patch.dict(os.environ, {"FACTORY_TOOL_PINS": str(host)}):
            with self.assertRaises(ToolPinError):
                load_tool_pins()

    def test_host_pins_path_is_none_when_unset(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(host_pins_path())

    def test_host_pins_still_fails_closed_when_host_is_absent(self):
        # A missing host file must NOT relax the fail-closed default: an unpinned trusted
        # tool still refuses to resolve.
        with mock.patch.dict(os.environ, {"FACTORY_TOOL_PINS": str(self.tmp / "nope.yaml"),
                                          "FACTORY_ALLOW_UNPINNED_TOOLS": "0"}):
            with self.assertRaises(ToolPinError):
                resolve_tool("gh", path_env=str(self.tmp), pins=load_tool_pins())


class GenerateToolPinsScriptTests(unittest.TestCase):
    """tools/generate-tool-pins.sh writes the host pins file every real run depends on.
    Fail-closed is the default, so a trusted tool MISSING from the generator's list is
    silently un-pinnable on a freshly generated host file — the run then refuses that
    tool (or, for bwrap, reads the host as unable to sandbox, agents-28nn). The
    generator's TOOLS list must cover exactly the trusted set."""

    SCRIPT = Path(__file__).resolve().parent.parent / "tools" / "generate-tool-pins.sh"

    def test_the_generator_covers_every_trusted_tool(self):
        script = self.SCRIPT.read_text(encoding="utf-8")
        match = re.search(r'^TOOLS="([^"]*)"', script, re.MULTILINE)
        self.assertIsNotNone(match, "generate-tool-pins.sh has no TOOLS list to audit")
        self.assertEqual(set(match.group(1).split()), set(TRUSTED_TOOLS),
                         "the generator must pin exactly the trusted tools — a missing one "
                         "is un-pinnable on the generated host file, an extra one is dead")


@unittest.skipUnless(shutil.which("bash"), "the generator is a bash script")
class GenerateToolPinsSourceTests(unittest.TestCase):
    """agents-28nn round 2, review P1: the generator is the pin's SOURCE OF TRUTH, so its
    lookup must never trust the inherited PATH — an earlier CI step that manipulates PATH
    (one $GITHUB_PATH line) would otherwise have the generator hash AND pin a planted
    fake, supplying both the binary and the hash that vouches for it.

    These tests run the REAL script with a PATH whose first entry holds a fake `git` AND
    a fake `sha256sum` (the attacker controls the tool AND the hasher). The pin file must
    contain no trace of the planted directory and must hash the real system git. The
    behaviour-mutation proof: removing the script's `PATH="$PIN_LOOKUP_PATH"` line makes
    the planted git the one that gets pinned, and the first assertion fails.
    """

    LOOKUP_DIRS = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin",
                   "/sbin", "/bin")
    BOGUS_HASH = "f" * 64  # the fake hasher's output: proof the real hasher ran (or not)

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="toolpins-gen-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.fakebin = self.tmp / "fakebin"
        self.fakebin.mkdir()
        fake_git = _make_tool(self.fakebin, "git", "#!/bin/sh\necho PLANTED-GIT\n")
        self.fake_git_sha = sha256_file(fake_git)
        # A fake hasher too: the lookup confinement must cover every command the
        # generator runs, or the pin's hash itself comes from a planted binary.
        _make_tool(self.fakebin, "sha256sum",
                   f"#!/bin/sh\necho '{self.BOGUS_HASH}  fake'\n")
        self.out = self.tmp / "tools.pins.yaml"

    def _run_generator(self, *extra_args):
        env = {"PATH": os.pathsep.join([str(self.fakebin), *self.LOOKUP_DIRS]),
               "HOME": str(self.tmp)}
        res = subprocess.run(
            ["bash", str(GenerateToolPinsScriptTests.SCRIPT), str(self.out), *extra_args],
            env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(res.returncode, 0, res.stderr)
        return self.out.read_text(encoding="utf-8")

    def _system_tool(self, name):
        for d in self.LOOKUP_DIRS:
            candidate = Path(d) / name
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate
        return None

    def test_a_path_planted_tool_and_hasher_are_never_pinned(self):
        body = self._run_generator()
        self.assertNotIn(str(self.fakebin), body,
                         "the lookup must be confined to the system dirs — a PATH-planted "
                         "binary must never be the pin's source")
        self.assertNotIn(self.BOGUS_HASH, body,
                         "the planted hasher must never feed the pin")
        self.assertNotIn(self.fake_git_sha, body,
                         "the planted git's own hash must never be vouched for")
        system_git = self._system_tool("git")
        if system_git is not None:
            match = re.search(r'^git:\n  path: (\S+)\n  sha256: ([0-9a-f]{64})$', body,
                              re.MULTILINE)
            self.assertIsNotNone(match, "a git present in the system dirs must be pinned")
            self.assertEqual(os.path.realpath(match.group(1)),
                             os.path.realpath(str(system_git)))
            self.assertEqual(match.group(2), sha256_file(system_git))

    def test_a_tool_found_only_outside_the_lookup_dirs_is_reported_unpinned(self):
        """The honest failure direction: a real install outside the system dirs (nvm,
        homebrew, ~/.local) is NOT silently trusted from the inherited PATH — it is
        reported not found, so the host fails closed until the operator passes
        --lookup-path explicitly."""
        only_fake = _make_tool(self.fakebin, "gitleaks")
        if self._system_tool("gitleaks") is not None:
            self.skipTest("gitleaks lives in the system dirs on this host")
        body = self._run_generator()
        self.assertNotIn(str(only_fake), body)
        self.assertIn("# gitleaks: not found", body,
                      "a tool outside the lookup dirs must be skipped with a comment, "
                      "never pinned from the inherited PATH")

    def test_lookup_path_flag_explicitly_admits_an_operator_dir(self):
        """The explicit override works: --lookup-path (a flag on the invocation, which in
        CI lives in the pinned action.yml — never an inherited env var, which
        $GITHUB_ENV could set) lets an operator pin a home-installed tool. The dir is
        PREPENDED to the system dirs, so the script's own hasher still resolves from the
        system dirs."""
        opbin = self.tmp / "opbin"
        opbin.mkdir()
        op_git = _make_tool(opbin, "git", "#!/bin/sh\necho OPERATOR-GIT\n")
        body = self._run_generator("--lookup-path", str(opbin))
        match = re.search(r'^git:\n  path: (\S+)\n  sha256: ([0-9a-f]{64})$', body,
                          re.MULTILINE)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), str(opbin / "git"))
        self.assertEqual(match.group(2), sha256_file(op_git))


class PinsFileFailureModeTests(unittest.TestCase):
    """agents-28nn round 2, review P2: every pins-file failure must surface as
    ToolPinError — the fail-closed path callers handle (the sandbox probe degrades, the
    sinks report an honest note) — never as a raw OSError that crashes the factory."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="toolpins-io-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    @unittest.skipIf(os.geteuid() == 0, "root ignores file permission bits")
    def test_an_unreadable_pins_file_raises_tool_pin_error_not_permission_error(self):
        cfg = self.tmp / "tools.yaml"
        cfg.write_text("gh:\n  sha256: " + "a" * 64 + "\n", encoding="utf-8")
        cfg.chmod(0o000)
        self.addCleanup(cfg.chmod, 0o644)
        with self.assertRaises(ToolPinError):
            load_tool_pins(cfg)

    def test_a_directory_where_the_pins_file_is_expected_raises_tool_pin_error(self):
        with self.assertRaises(ToolPinError):
            load_tool_pins(self.tmp)  # a directory, not a file

    def test_a_non_utf8_pins_file_raises_tool_pin_error(self):
        cfg = self.tmp / "tools.yaml"
        cfg.write_bytes(b"gh:\xff\xfe\x00binary")
        with self.assertRaises(ToolPinError):
            load_tool_pins(cfg)

    def test_an_empty_pins_file_is_zero_pins_and_still_fails_closed(self):
        cfg = self.tmp / "tools.yaml"
        cfg.write_text("", encoding="utf-8")
        with mock.patch.dict(os.environ, {"FACTORY_TOOL_PINS": "",
                                          "FACTORY_ALLOW_UNPINNED_TOOLS": "0"}):
            self.assertEqual(load_tool_pins(cfg), {})
            with self.assertRaises(ToolPinError):
                resolve_tool("gh", path_env=str(self.tmp), pins=load_tool_pins(cfg))


if __name__ == "__main__":
    unittest.main()
