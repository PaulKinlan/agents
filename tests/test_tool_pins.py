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
import threading
import unittest
from pathlib import Path
from unittest import mock

from lib.tool_pins import (MAX_PINS_FILE_BYTES, TRUSTED_TOOLS, ToolPinError,
                           allowlisted_path, host_pins_path, load_tool_pins,
                           pin_trusted_argv, resolve_tool, sha256_file, tool_dir,
                           verify_pin)


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

    def test_engine_binaries_are_trusted_tools_and_fail_closed_when_unpinned(self):
        """agents-28nn round 5, review P0: the adapter is the LAST GRANTER BEFORE THE KEY,
        so the engine binaries it executes (pi, claude, agentapi) are trusted
        tools — an unpinned engine is a credential exfiltration path, not merely an
        unverified binary (proven by construction: a fake pi handed the run's
        ANTHROPIC_API_KEY and dumped its environment). deepseek has no CLI binary (agents-mhv7)
        and is purely payload-only Python HTTP station code. The end-to-end containment property
        is pinned in tests/test_containment.py (TestEngineCredentialPinning)."""
        for binary in ("pi", "claude", "agentapi"):
            with self.subTest(binary=binary):
                self.assertIn(binary, TRUSTED_TOOLS)
                _make_tool(self.bindir, binary)
                with mock.patch.dict(os.environ, {"FACTORY_ALLOW_UNPINNED_TOOLS": "0"}):
                    with self.assertRaises(ToolPinError):
                        resolve_tool(binary, path_env=str(self.bindir), pins={})
        self.assertNotIn("deepseek", TRUSTED_TOOLS,
                         "deepseek executes no CLI binary and has no pin (agents-mhv7)")

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

    def test_exported_functions_and_a_cwd_planted_binary_cannot_influence_the_pin(self):
        """agents-28nn round 3, review P1 — the reviewer's own construction: `export -f`
        the tool AND the hasher (a BASH_FUNC_* line via $GITHUB_ENV reaches a later CI
        step's bash), drop a CWD-relative namesake, run the generator from that CWD.
        `command -v` would resolve the FUNCTION and answer with a bare name, the script
        would hash ./git, and the emitted RELATIVE path would later be expanded by
        resolve_tool from the factory's CWD. The explicit per-directory filesystem lookup
        is the only lookup shell state cannot answer for us — and the emit-side
        absolute-path reject is the hard backstop.

        The behaviour-mutation proof: replacing resolve_in_lookup's body with
        `command -v "$1"` (the round-2 shape) makes this test fail two ways — with the
        reject kept, the generator exits 2 on the bare function name; with the reject
        also removed, the emitted `path: git` fails the absolute-path assertion.
        """
        _make_tool(self.fakebin, "bwrap")  # the CWD-planted namesake
        wrapper = (
            "git() { echo FUNCTION-GIT; }\n"
            "bwrap() { echo FUNCTION-BWRAP; }\n"
            f"sha256sum() {{ echo '{self.BOGUS_HASH}  fake'; }}\n"
            "export -f git bwrap sha256sum\n"
            f"cd '{self.fakebin}'\n"
            f"exec bash '{GenerateToolPinsScriptTests.SCRIPT}' '{self.out}'\n"
        )
        env = {"PATH": os.pathsep.join([str(self.fakebin), *self.LOOKUP_DIRS]),
               "HOME": str(self.tmp)}
        res = subprocess.run(["bash", "-c", wrapper], env=env, capture_output=True,
                             text=True, timeout=30)
        self.assertEqual(res.returncode, 0, res.stderr)
        body = self.out.read_text(encoding="utf-8")
        for match in re.finditer(r'^  path: (\S+)$', body, re.MULTILINE):
            self.assertTrue(match.group(1).startswith("/"),
                            f"a RELATIVE pin path was emitted: {match.group(1)!r} — "
                            "resolve_tool would expand it from the factory's CWD")
        self.assertNotIn(str(self.fakebin), body,
                         "neither the exported function nor the CWD namesake may be pinned")
        self.assertNotIn(self.BOGUS_HASH, body,
                         "the exported hasher function must never feed the pin")
        system_git = self._system_tool("git")
        if system_git is not None:
            match = re.search(r'^git:\n  path: (\S+)\n  sha256: ([0-9a-f]{64})$', body,
                              re.MULTILINE)
            self.assertIsNotNone(match, "the real system git must still be pinned")
            self.assertEqual(match.group(1), str(system_git))
            self.assertEqual(match.group(2), sha256_file(system_git))

    def test_a_relative_lookup_path_dir_is_never_emitted(self):
        """The reject's other boundary: --lookup-path with a RELATIVE dir can never yield
        an absolute pin path, so the tool is reported not found rather than emitted as a
        CWD-relative pin."""
        oprel = self.tmp / "oprel"
        oprel.mkdir()
        _make_tool(oprel, "git", "#!/bin/sh\necho RELATIVE-GIT\n")
        env = {"PATH": os.pathsep.join(self.LOOKUP_DIRS), "HOME": str(self.tmp)}
        res = subprocess.run(
            ["bash", str(GenerateToolPinsScriptTests.SCRIPT), str(self.out),
             "--lookup-path", "oprel"],
            env=env, cwd=self.tmp, capture_output=True, text=True, timeout=30)
        self.assertEqual(res.returncode, 0, res.stderr)
        body = self.out.read_text(encoding="utf-8")
        # The header comment legitimately records the flag's value; the boundary is that
        # no EMITTED pin path may come from it.
        paths = re.findall(r'^  path: (\S+)$', body, re.MULTILINE)
        self.assertFalse(any("oprel" in p for p in paths),
                         "a relative lookup dir must never produce a pin path")
        for p in paths:
            self.assertTrue(p.startswith("/"),
                            f"a RELATIVE pin path was emitted: {p!r}")

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

    # agents-28nn round 3, review P2: the resource-failure SET. The reader is BOUNDED — a
    # non-regular file is refused by kind before any read, an over-bound size is refused
    # unread, and the read is hard-capped so a file that grows past the bound is refused
    # — because an unbounded read of a FIFO or device file allocates until the machine's
    # OOM killer, a crash no except clause can catch (verified by execution: /dev/urandom
    # grew to ~12 GB before the host reaper). Every mode must raise ToolPinError, the
    # failure shape the sandbox probe degrades on — never hang, never crash.

    def test_a_fifo_where_the_pins_file_is_expected_raises_tool_pin_error(self):
        fifo = self.tmp / "tools.fifo"
        os.mkfifo(fifo)

        def writer():
            # Keeps the MUTATION direction bounded: with the regular-file refusal removed,
            # the read blocks on the FIFO until this writer feeds it valid pins content —
            # which then parses cleanly, so the missing ToolPinError fails the test. The
            # open is O_NONBLOCK with retries: with the fix no reader ever comes (every
            # attempt fails ENXIO and the thread exits), and under the mutation the reader
            # is blocked in open() waiting for exactly this writer, so one of the attempts
            # lands. A single non-blocking open would race the reader's scheduling.
            import time as _time
            fd = None
            for _ in range(30):
                try:
                    fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
                    break
                except OSError:
                    _time.sleep(0.1)
            if fd is None:
                return  # the fixed reader never opens the FIFO: ENXIO is expected
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write("gh:\n  sha256: " + "a" * 64 + "\n")
            except OSError:
                pass

        feeder = threading.Thread(target=writer, daemon=True)
        feeder.start()
        try:
            with mock.patch.dict(os.environ, {"FACTORY_TOOL_PINS": ""}):
                with self.assertRaises(ToolPinError) as raised:
                    load_tool_pins(fifo)
        finally:
            feeder.join(timeout=5)
        self.assertFalse(feeder.is_alive(),
                         "the reader must REFUSE the FIFO, never block on it")
        self.assertIn("FIFO", str(raised.exception))

    def test_a_device_file_where_the_pins_file_is_expected_raises_tool_pin_error(self):
        # /dev/null: st_size 0 and no end — the naive read sees an empty file, the exact
        # shape that made the round-2 fix look sufficient. /dev/urandom is deliberately
        # NOT used: reading it to exhaustion is the crash being fixed.
        with mock.patch.dict(os.environ, {"FACTORY_TOOL_PINS": ""}):
            with self.assertRaises(ToolPinError) as raised:
                load_tool_pins(Path("/dev/null"))
        self.assertIn("character device", str(raised.exception))

    def test_an_over_bound_pins_file_is_refused_before_it_is_read(self):
        cfg = self.tmp / "tools.yaml"
        cfg.write_text("gh:\n  sha256: " + "a" * 64 + "\n" + "# pad\n" * 200_000,
                       encoding="utf-8")
        self.assertGreater(cfg.stat().st_size, MAX_PINS_FILE_BYTES)
        with mock.patch.dict(os.environ, {"FACTORY_TOOL_PINS": ""}):
            with self.assertRaises(ToolPinError) as raised:
                load_tool_pins(cfg)
        self.assertIn("over the", str(raised.exception))
        self.assertIn("bound", str(raised.exception))

    def test_a_pins_file_that_grows_past_the_bound_while_being_read_is_refused(self):
        """The TOCTOU sibling: fstat says small, the file is big by the time the read
        finishes. The read's hard cap — not the fstat check — is what catches it.
        The lie is told at os.fstat (what the reader actually consults), identified by
        /proc/self/fd so only the pins file's descriptor is misreported."""
        cfg = self.tmp / "tools.yaml"
        cfg.write_text("gh:\n  sha256: " + "a" * 64 + "\n" + "# pad\n" * 200_000,
                       encoding="utf-8")
        self.assertGreater(cfg.stat().st_size, MAX_PINS_FILE_BYTES)
        real_fstat = os.fstat

        def lying_fstat(fd, *args, **kwargs):
            result = real_fstat(fd, *args, **kwargs)
            try:
                if os.readlink(f"/proc/self/fd/{fd}") == str(cfg):
                    return os.stat_result((result.st_mode, result.st_ino, result.st_dev,
                                           result.st_nlink, result.st_uid, result.st_gid, 10,
                                           int(result.st_atime), int(result.st_mtime),
                                           int(result.st_ctime)))
            except OSError:
                pass
            return result

        with mock.patch.dict(os.environ, {"FACTORY_TOOL_PINS": ""}), \
             mock.patch("os.fstat", lying_fstat):
            with self.assertRaises(ToolPinError) as raised:
                load_tool_pins(cfg)
        self.assertIn("grew past", str(raised.exception))

    def test_a_regular_to_fifo_swap_before_open_cannot_block_the_reader(self):
        """agents-28nn round 4, review P2 — the reviewer's constructed case, kept as the
        permanent regression test: the pins path is a REGULAR file when the run starts and
        a FIFO by the time the reader opens it. A stat-then-open BY NAME has a swap window
        between the two syscalls: the stat sees the regular file, the open then blocks on
        the FIFO waiting for a writer (the reviewer reproduced the block at a 2s timeout).
        The byte cap bounds a READ, not a blocking OPEN — so the reader opens
        O_RDONLY|O_NONBLOCK and validates the OPENED DESCRIPTOR with fstat: the object
        validated is the object read, the FIFO is refused by kind, and nothing ever
        blocks. The swap is injected by an os.open wrapper — the first path-touching call
        in BOTH the fixed and the reverted reader — so the construction bites whichever
        implementation is under test; the feeder thread keeps the MUTATION direction
        bounded (a reverted reader blocks in open() until the feeder's write lands, then
        parses the fed pins and raises NOTHING, failing the test)."""
        cfg = self.tmp / "tools.yaml"
        cfg.write_text("gh:\n  sha256: " + "a" * 64 + "\n", encoding="utf-8")
        swapped = []
        real_open = os.open

        def swapping_open(path, flags, *args, **kwargs):
            if not swapped and str(path) == str(cfg):
                # The swap: the regular pins file becomes a FIFO between the reader's
                # validation and its open. os.mkfifo cannot replace an existing file,
                # so rename it aside first — the reader's open then meets the FIFO.
                os.rename(cfg, self.tmp / "original.yaml")
                os.mkfifo(cfg)
                swapped.append(True)
            return real_open(path, flags, *args, **kwargs)

        def writer():
            import time as _time
            fd = None
            for _ in range(30):
                try:
                    fd = real_open(cfg, os.O_WRONLY | os.O_NONBLOCK)
                    break
                except OSError:
                    _time.sleep(0.1)
            if fd is None:
                return  # the fixed reader never completes a blocking open: ENXIO expected
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write("gh:\n  sha256: " + "a" * 64 + "\n")
            except OSError:
                pass

        feeder = threading.Thread(target=writer, daemon=True)
        feeder.start()
        try:
            with mock.patch.dict(os.environ, {"FACTORY_TOOL_PINS": ""}), \
                 mock.patch("os.open", swapping_open):
                with self.assertRaises(ToolPinError) as raised:
                    load_tool_pins(cfg)
        finally:
            feeder.join(timeout=5)
        self.assertFalse(feeder.is_alive(),
                         "the reader must REFUSE the swapped-in FIFO, never block on it")
        self.assertTrue(swapped, "the construction must actually perform the swap")
        self.assertIn("FIFO", str(raised.exception))


class TrustedArgvLauncherPolicyTests(unittest.TestCase):
    """agents-28nn round 4, review P1 — the PINNED THING IS THE EXECUTED ARGV, not its
    first element: ['env', 'git', '--version'] is not git, it is the environment running
    git. The round-3 check inspected argv[0] only, so a config-supplied command hid a
    trusted tool BEHIND a launcher and the real tool rode past the pin (constructed by
    the reviewer: a PATH-planted fake git executed via env with unpinned tools
    disallowed). The policy: a trusted tool may appear ONLY in command position (where
    the pin resolves it); anywhere else in the argv is refused with the element named —
    complete over the argv by construction, with no launcher list to keep current."""

    def test_env_cannot_smuggle_a_trusted_tool_past_the_pin(self):
        """THE HOLE, CLOSED: pre-fix this returned ['env', 'git', '--version'] UNCHANGED."""
        with self.assertRaises(ToolPinError) as raised:
            pin_trusted_argv(["env", "git", "--version"])
        self.assertIn("argv[1]", str(raised.exception))
        self.assertIn("'git'", str(raised.exception))
        self.assertIn("'env'", str(raised.exception))

    def test_env_with_assignments_cannot_smuggle_a_trusted_tool(self):
        with self.assertRaises(ToolPinError) as raised:
            pin_trusted_argv(["env", "FOO=bar", "git", "status"])
        self.assertIn("argv[2]", str(raised.exception))

    def test_nice_and_sudo_cannot_smuggle_a_trusted_tool(self):
        for launcher in ("nice", "sudo"):
            with self.subTest(launcher=launcher):
                with self.assertRaises(ToolPinError):
                    pin_trusted_argv([launcher, "git", "--version"])

    def test_a_trusted_name_as_data_is_refused_with_the_element_named(self):
        """Fail closed, named, with the sh -c escape hatch documented in the message."""
        with self.assertRaises(ToolPinError) as raised:
            pin_trusted_argv(["mysink", "--compare", "git"])
        self.assertIn("argv[2]", str(raised.exception))
        self.assertIn("sh -c", str(raised.exception))

    def test_a_non_trusted_command_passes_through_untouched(self):
        argv = ["env", "FOO=bar", "mysink", "--flag", "value"]
        self.assertEqual(pin_trusted_argv(argv), argv)

    def test_the_shell_escape_hatch_is_unchanged(self):
        """sh -c is the operator's documented explicit trust decision: the shell STRING is
        opaque to the pin BY DESIGN — the boundary is stated, not claimed covered."""
        argv = ["sh", "-c", "git status && mysink"]
        self.assertEqual(pin_trusted_argv(argv), argv)

    def test_a_trusted_tool_in_command_position_is_still_routed(self):
        """The round-3 behaviour is preserved: argv[0] naming a trusted tool resolves
        through the pin — here unpinned, so the routing itself fails closed."""
        with mock.patch.dict(os.environ, {"FACTORY_ALLOW_UNPINNED_TOOLS": "",
                                          "FACTORY_TOOL_PINS": ""}):
            with self.assertRaises(ToolPinError):
                pin_trusted_argv(["git", "--version"])


if __name__ == "__main__":
    unittest.main()
