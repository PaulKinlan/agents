#!/usr/bin/env python3
"""Regression tests for station scripts resolving trusted tools via pin machinery (agents-01qd).

Verifies that:
1. agents/perf-review/scripts/scan_perf_changes.py authenticates `git` and refuses unauthenticated/mismatched binaries.
2. agents/pr-fixer/scripts/collect_failures.py authenticates `git` and refuses unauthenticated/mismatched binaries.
3. agents/deps-supply-chain/scripts/audit_deps.py authenticates `npm` and refuses unauthenticated/mismatched binaries, while gracefully handling genuinely absent `npm`.
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class TestStationTrustedToolPins(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="station-tool-pins-"))
        self.fakebin = self.tmp / "fakebin"
        self.fakebin.mkdir()
        self.target = self.tmp / "target"
        self.target.mkdir()

    def tearDown(self):
        subprocess.run(["rm", "-rf", str(self.tmp)], check=False)

    def _plant(self, name: str) -> Path:
        fake = self.fakebin / name
        log = self.tmp / f"fake_{name}.log"
        fake.write_text(f"#!/bin/sh\necho EXECUTED >> {log}\nexit 0\n", encoding="utf-8")
        fake.chmod(0o755)
        return fake

    def _pins_file(self, content: str) -> Path:
        pins = self.tmp / "tools.pins.yaml"
        pins.write_text(content, encoding="utf-8")
        return pins

    def test_perf_review_refuses_unauthenticated_git(self):
        """perf-review pre-pass must refuse unauthenticated git and fail closed (exit 2)."""
        fake_git = self._plant("git")
        pins = self._pins_file(f"git:\n  path: {fake_git}\n  sha256: {'0' * 64}\n")

        env = os.environ.copy()
        env["PATH"] = f"{self.fakebin}:{env.get('PATH', '')}"
        env["FACTORY_TOOL_PINS"] = str(pins)
        env.pop("FACTORY_ALLOW_UNPINNED_TOOLS", None)

        script = ROOT / "agents/perf-review/scripts/scan_perf_changes.py"
        res = subprocess.run([sys.executable, str(script), "--target", str(self.target)],
                             env=env, capture_output=True, text=True)

        self.assertEqual(res.returncode, 2, f"expected exit 2 on pin failure, got {res.returncode}")
        self.assertIn("Error: trusted tool 'git' cannot be authenticated", res.stderr)
        self.assertFalse((self.tmp / "fake_git.log").exists(), "unauthenticated git was executed")

    def test_pr_fixer_refuses_unauthenticated_git(self):
        """pr-fixer pre-pass must refuse unauthenticated git and fail closed (exit 2)."""
        fake_git = self._plant("git")
        pins = self._pins_file(f"git:\n  path: {fake_git}\n  sha256: {'0' * 64}\n")

        env = os.environ.copy()
        env["PATH"] = f"{self.fakebin}:{env.get('PATH', '')}"
        env["FACTORY_TOOL_PINS"] = str(pins)
        env.pop("FACTORY_ALLOW_UNPINNED_TOOLS", None)

        script = ROOT / "agents/pr-fixer/scripts/collect_failures.py"
        res = subprocess.run([sys.executable, str(script), "--target", str(self.target)],
                             env=env, capture_output=True, text=True)

        self.assertEqual(res.returncode, 2, f"expected exit 2 on pin failure, got {res.returncode}")
        self.assertIn("Error: trusted tool 'git' cannot be authenticated", res.stderr)
        self.assertFalse((self.tmp / "fake_git.log").exists(), "unauthenticated git was executed")

    def test_deps_supply_chain_refuses_unauthenticated_npm(self):
        """deps-supply-chain must refuse unauthenticated npm when npm is present on PATH (exit 2)."""
        fake_npm = self._plant("npm")
        pins = self._pins_file(f"npm:\n  path: {fake_npm}\n  sha256: {'0' * 64}\n")

        env = os.environ.copy()
        env["PATH"] = f"{self.fakebin}:{env.get('PATH', '')}"
        env["FACTORY_TOOL_PINS"] = str(pins)
        env.pop("FACTORY_ALLOW_UNPINNED_TOOLS", None)

        pkg = self.target / "package.json"
        pkg.write_text('{"name": "test", "dependencies": {"foo": "1.0.0"}}\n')

        script = ROOT / "agents/deps-supply-chain/scripts/audit_deps.py"
        res = subprocess.run([sys.executable, str(script), "--target", str(self.target)],
                             env=env, capture_output=True, text=True)

        self.assertEqual(res.returncode, 2, f"expected exit 2 on pin failure, got {res.returncode}")
        self.assertIn("Error: npm cannot be authenticated", res.stderr)
        self.assertFalse((self.tmp / "fake_npm.log").exists(), "unauthenticated npm was executed")

    def test_deps_supply_chain_handles_genuinely_absent_npm(self):
        """deps-supply-chain gracefully skips npm audit when npm is genuinely absent."""
        empty_bin = self.tmp / "empty_bin"
        empty_bin.mkdir()

        # Pin npm with sha256 but NO path so resolve_tool checks PATH (empty_bin),
        # genuinely raising 'could not be resolved on PATH' rather than finding a host-pinned path.
        pins = self._pins_file(f"npm:\n  sha256: {'0' * 64}\n")

        env = os.environ.copy()
        env["PATH"] = str(empty_bin)
        env["FACTORY_TOOL_PINS"] = str(pins)
        env.pop("FACTORY_ALLOW_UNPINNED_TOOLS", None)

        pkg = self.target / "package.json"
        pkg.write_text('{"name": "test", "dependencies": {"foo": "1.0.0"}}\n')

        script = ROOT / "agents/deps-supply-chain/scripts/audit_deps.py"
        res = subprocess.run([sys.executable, str(script), "--target", str(self.target)],
                             env=env, capture_output=True, text=True)

        self.assertEqual(res.returncode, 0, f"expected exit 0 when npm is absent, got {res.returncode}")
        self.assertNotIn("Error: npm cannot be authenticated", res.stderr)
        # Verify that npm audit was not attempted: no 'npm-audit-unavailable' coverage gap candidate
        self.assertNotIn("npm-audit-unavailable", res.stdout)

    def test_prepass_child_environment_forwards_tool_pins(self):
        """prepass_environment must forward FACTORY_TOOL_PINS and FACTORY_ALLOW_UNPINNED_TOOLS (agents-qbl8)."""
        from lib.child_env import prepass_environment
        parent = {
            "PATH": "/bin:/usr/bin",
            "FACTORY_TOOL_PINS": "/some/path/tools.pins.yaml",
            "FACTORY_ALLOW_UNPINNED_TOOLS": "1"
        }
        child_env = prepass_environment({"capabilities": {"requires": ["git"]}}, parent=parent)
        self.assertEqual(child_env.get("FACTORY_TOOL_PINS"), "/some/path/tools.pins.yaml")
        self.assertEqual(child_env.get("FACTORY_ALLOW_UNPINNED_TOOLS"), "1")

    def test_perf_review_runs_dispatched_under_prepass_env_with_valid_pins(self):
        """perf-review runs to exit 0 when dispatched under prepass_environment with valid pins (agents-qbl8)."""
        import hashlib
        from lib.child_env import prepass_environment

        fake_git = self._plant("git")
        git_sha = hashlib.sha256(fake_git.read_bytes()).hexdigest()
        pins = self._pins_file(f"git:\n  path: {fake_git}\n  sha256: {git_sha}\n")

        parent = os.environ.copy()
        parent["PATH"] = f"{self.fakebin}:{parent.get('PATH', '')}"
        parent["FACTORY_TOOL_PINS"] = str(pins)
        parent.pop("FACTORY_ALLOW_UNPINNED_TOOLS", None)

        child_env = prepass_environment({"capabilities": {"requires": ["git"]}}, parent=parent)
        script = ROOT / "agents/perf-review/scripts/scan_perf_changes.py"
        res = subprocess.run([sys.executable, str(script), "--target", str(self.target)],
                             env=child_env, capture_output=True, text=True)

        self.assertEqual(res.returncode, 0, f"expected exit 0, got {res.returncode}: {res.stderr}")
        self.assertTrue((self.tmp / "fake_git.log").exists(), "authenticated git should have run")

    def test_pr_fixer_runs_dispatched_under_prepass_env_with_valid_pins(self):
        """pr-fixer runs to exit 0 when dispatched under prepass_environment with valid pins (agents-qbl8)."""
        import hashlib
        from lib.child_env import prepass_environment

        fake_git = self._plant("git")
        git_sha = hashlib.sha256(fake_git.read_bytes()).hexdigest()
        pins = self._pins_file(f"git:\n  path: {fake_git}\n  sha256: {git_sha}\n")

        parent = os.environ.copy()
        parent["PATH"] = f"{self.fakebin}:{parent.get('PATH', '')}"
        parent["FACTORY_TOOL_PINS"] = str(pins)
        parent.pop("FACTORY_ALLOW_UNPINNED_TOOLS", None)

        child_env = prepass_environment({"capabilities": {"requires": ["git"]}}, parent=parent)
        script = ROOT / "agents/pr-fixer/scripts/collect_failures.py"
        res = subprocess.run([sys.executable, str(script), "--target", str(self.target)],
                             env=child_env, capture_output=True, text=True)

        self.assertEqual(res.returncode, 0, f"expected exit 0, got {res.returncode}: {res.stderr}")
        self.assertTrue((self.tmp / "fake_git.log").exists(), "authenticated git should have run")

    def test_deps_supply_chain_runs_dispatched_under_prepass_env_with_valid_pins(self):
        """deps-supply-chain runs to exit 0 when dispatched under prepass_environment with valid pins (agents-qbl8)."""
        import hashlib
        from lib.child_env import prepass_environment

        fake_npm = self._plant("npm")
        npm_sha = hashlib.sha256(fake_npm.read_bytes()).hexdigest()
        pins = self._pins_file(f"npm:\n  path: {fake_npm}\n  sha256: {npm_sha}\n")

        parent = os.environ.copy()
        parent["PATH"] = f"{self.fakebin}:{parent.get('PATH', '')}"
        parent["FACTORY_TOOL_PINS"] = str(pins)
        parent.pop("FACTORY_ALLOW_UNPINNED_TOOLS", None)

        pkg = self.target / "package.json"
        pkg.write_text('{"name": "test", "dependencies": {"foo": "1.0.0"}}\n')

        child_env = prepass_environment({"capabilities": {"requires": ["npm"]}}, parent=parent)
        script = ROOT / "agents/deps-supply-chain/scripts/audit_deps.py"
        res = subprocess.run([sys.executable, str(script), "--target", str(self.target)],
                             env=child_env, capture_output=True, text=True)

        self.assertEqual(res.returncode, 0, f"expected exit 0, got {res.returncode}: {res.stderr}")
        self.assertTrue((self.tmp / "fake_npm.log").exists(), "authenticated npm should have run")

    def test_deps_supply_chain_refuses_malformed_pins_file(self):
        """deps-supply-chain must exit 2 loudly on malformed pins file rather than treating npm as absent (agents-syhp)."""
        pins = self._pins_file("npm:\n  path: /nonexistent/npm\n")

        env = os.environ.copy()
        env["PATH"] = str(self.fakebin)
        env["FACTORY_TOOL_PINS"] = str(pins)
        env.pop("FACTORY_ALLOW_UNPINNED_TOOLS", None)

        pkg = self.target / "package.json"
        pkg.write_text('{"name": "test", "dependencies": {"foo": "1.0.0"}}\n')

        script = ROOT / "agents/deps-supply-chain/scripts/audit_deps.py"
        res = subprocess.run([sys.executable, str(script), "--target", str(self.target)],
                             env=env, capture_output=True, text=True)

        self.assertEqual(res.returncode, 2, f"expected exit 2 on malformed pins file, got {res.returncode}")
        self.assertIn("Error: npm cannot be authenticated", res.stderr)

    def test_perf_review_runs_sandboxed_under_sandbox_command_with_home_pins(self):
        """sandboxed pre-pass wrap must bind host pins file so child can authenticate tools (agents-ebm7)."""
        import hashlib
        import shutil
        from lib.sandbox import sandbox_command, sandbox_available
        from lib.child_env import prepass_environment

        if not sandbox_available():
            self.skipTest("bubblewrap sandbox not available on this host")

        real_git = shutil.which("git")
        if not real_git:
            self.skipTest("git is not installed on this host")
        real_bwrap = shutil.which("bwrap")
        if not real_bwrap:
            self.skipTest("bwrap is not installed on this host")

        # Test controls its own fixture under $HOME (which bubblewrap tmpfs hides by default).
        # We write a valid pins file for git and bwrap into $HOME, proving sandbox_command explicitly
        # mounts the host pins file read-only over the sandbox's /home tmpfs while authenticating bwrap.
        git_sha = hashlib.sha256(Path(real_git).read_bytes()).hexdigest()
        bwrap_sha = hashlib.sha256(Path(real_bwrap).read_bytes()).hexdigest()
        home_pins = Path.home() / f".test-pins-{os.getpid()}.yaml"
        try:
            home_pins.write_text(
                f"git:\n  path: {real_git}\n  sha256: {git_sha}\n"
                f"bwrap:\n  path: {real_bwrap}\n  sha256: {bwrap_sha}\n",
                encoding="utf-8"
            )
        except OSError as e:
            self.skipTest(f"cannot create test pins fixture under $HOME: {e}")

        subprocess.run(["git", "init", "-q", str(self.target)], check=True)
        run_dir = self.tmp / "run"
        run_dir.mkdir()

        orig_pins = os.environ.get("FACTORY_TOOL_PINS")
        orig_unpinned = os.environ.get("FACTORY_ALLOW_UNPINNED_TOOLS")
        try:
            os.environ["FACTORY_TOOL_PINS"] = str(home_pins)
            os.environ.pop("FACTORY_ALLOW_UNPINNED_TOOLS", None)
            child_env = prepass_environment({"capabilities": {"requires": ["git"]}})
            script = ROOT / "agents/perf-review/scripts/scan_perf_changes.py"
            inner = [sys.executable, str(script), "--target", str(self.target)]
            cmd = sandbox_command(
                inner, target_dir=str(self.target), factory_root=str(ROOT),
                run_dir=str(run_dir), env=child_env, executables=["git"]
            )

            res = subprocess.run(cmd, env=child_env, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, f"sandboxed run failed: {res.returncode}: {res.stderr}")
        finally:
            if orig_pins is not None:
                os.environ["FACTORY_TOOL_PINS"] = orig_pins
            else:
                os.environ.pop("FACTORY_TOOL_PINS", None)
            if orig_unpinned is not None:
                os.environ["FACTORY_ALLOW_UNPINNED_TOOLS"] = orig_unpinned
            else:
                os.environ.pop("FACTORY_ALLOW_UNPINNED_TOOLS", None)
            home_pins.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
