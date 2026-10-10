#!/usr/bin/env python3
"""Pre-pass scripts re-authenticate their own trusted tools through the pin (agents-28nn
round 4): a station script's own trusted-tool launch is a census kind of its own.

The reviewer's constructed case, kept as a regression test: a PATH-planted fake `gh` ran
with GH_TOKEN in its environment on the trusted-private UNSANDBOXED path (no sandbox bind
boundary verifies anything there), and fetch_github_issues RETURNED AN EMPTY RESULT rather
than failing — the station proceeded believing it had queried the real tool. A wrong answer
that looks like a normal one is the finding family's defect, so both halves are pinned here:

* the binary is authenticated BEFORE it executes (an unauthenticatable trusted tool exits
  nonzero and the fake's invocation log must not exist), and
* the failure is LOUD — an unauthenticated gh and a FAILED gh both exit 2, never a quiet
  empty candidate list that reads like "no open issues".

A genuinely empty result from the pinned tool stays an ordinary empty result.
"""

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

from tests.sandbox_fixtures import copy_station_script  # noqa: E402

FETCH_ISSUES = "agents/issue-triage/scripts/fetch_issues.py"
GATHER_COMMITS = "agents/release-notes/scripts/gather_commits.py"
CHECK_DOCS = "agents/docs-drift/scripts/check_docs.py"
SCAN = "agents/secret-scan/scripts/scan.py"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class PrepassPinBoundaryBase(unittest.TestCase):
    """Sandbox a station script (lib import closure included) and run it with a fake
    trusted tool first on PATH and a pins file that does not match the fake."""

    def _sandbox(self, script_rel: str):
        tmp = Path(tempfile.mkdtemp(prefix="prepass-pin-"))
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", str(tmp)], check=False))
        sandbox = tmp / "sandbox"
        copy_station_script(sandbox, ROOT / script_rel, script_rel)
        fakebin = tmp / "fakebin"
        fakebin.mkdir()
        target = tmp / "target"
        target.mkdir()
        subprocess.run(["git", "init", "-q", str(target)], check=True)
        return tmp, sandbox, fakebin, target

    def _plant(self, fakebin: Path, name: str, body: str) -> Path:
        fake = fakebin / name
        fake.write_text(body, encoding="utf-8")
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return fake

    def _pins(self, tmp: Path, name: str, *, path=None, sha256=None) -> Path:
        pins = tmp / f"pins-{name}.yaml"
        lines = [f"{name}:"]
        if path:
            lines.append(f"  path: {path}")
        if sha256:
            lines.append(f"  sha256: {sha256}")
        pins.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return pins

    def _env(self, pins: Path, fakebin: Path) -> dict:
        env = {
            "PATH": f"{fakebin}:/usr/bin:/bin:/usr/local/bin",
            "HOME": os.environ.get("HOME", "/root"),
            "FACTORY_TOOL_PINS": str(pins),
            "FACTORY_ALLOW_UNPINNED_TOOLS": "0",
            "GH_TOKEN": "fake-token-for-the-constructed-case",
        }
        return env

    def _run(self, sandbox: Path, script_rel: str, target: Path, env: dict):
        cmd = [sys.executable, str(sandbox / script_rel), "--target", str(target)]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=env)


class TestFetchIssuesPinBoundary(PrepassPinBoundaryBase):
    """The credentialed case: GH_TOKEN present, fake gh first on PATH."""

    def test_an_unauthenticatable_gh_is_refused_before_it_executes_and_loudly(self):
        tmp, sandbox, fakebin, target = self._sandbox(FETCH_ISSUES)
        log = tmp / "fake.log"
        self._plant(fakebin, "gh", f'#!/bin/sh\necho ran >> {log}\necho "[]"\nexit 0\n')
        real_gh = subprocess.run(["command", "-v", "gh"], shell=True, capture_output=True,
                                 text=True, env={"PATH": "/usr/bin:/bin:/usr/local/bin"})
        # Pin the sha of the REAL gh (or any content the fake does not have), so the
        # PATH-order winner mismatches.
        anchor = real_gh.stdout.strip() or "/usr/bin/git"
        pins = self._pins(tmp, "gh", sha256=_sha256(Path(anchor)))
        res = self._run(sandbox, FETCH_ISSUES, target, self._env(pins, fakebin))
        self.assertEqual(res.returncode, 2, res.stderr)
        self.assertIn("cannot be authenticated", res.stderr)
        self.assertFalse(log.exists(), "the fake gh executed: the pin was bypassed")

    def test_a_pinned_gh_that_FAILS_is_loud_not_an_empty_result(self):
        tmp, sandbox, fakebin, target = self._sandbox(FETCH_ISSUES)
        fake = self._plant(fakebin, "gh",
                           "#!/bin/sh\necho simulated failure >&2\nexit 1\n")
        pins = self._pins(tmp, "gh", path=str(fake), sha256=_sha256(fake))
        res = self._run(sandbox, FETCH_ISSUES, target, self._env(pins, fakebin))
        self.assertEqual(res.returncode, 2, res.stderr)
        self.assertIn("gh issue list failed", res.stderr)

    def test_the_dispatcher_resolved_path_survives_a_rewritten_pins_file(self):
        """agents-28nn round 6, review P1: on the UNSANDBOXED path the pins file is
        operator-writable and the child runs as the operator, so the credential handoff
        must not depend on it. The dispatcher hands the host-verified path in
        FACTORY_RESOLVED_TOOL_GH; even with the pins file REWRITTEN to grant the fake
        (path+sha of the fake — a pin IS a grant, the falsified round-5 claim), the
        script must execute the dispatcher-verified binary and the fake must never run."""
        tmp, sandbox, fakebin, target = self._sandbox(FETCH_ISSUES)
        fake_log = tmp / "fake.log"
        real_log = tmp / "real.log"
        fake = self._plant(fakebin, "gh", f'#!/bin/sh\necho ran >> {fake_log}\necho "[]"\n')
        # A second plant standing in for the dispatcher-verified binary (the host-verified
        # path is an operator decision; what matters is WHICH one executes).
        verified = self._plant(fakebin, "gh-verified",
                               f'#!/bin/sh\necho ran >> {real_log}\necho "[]"\n')
        pins = self._pins(tmp, "gh", path=str(fake), sha256=_sha256(fake))
        env = self._env(pins, fakebin)
        env["FACTORY_RESOLVED_TOOL_GH"] = str(verified)
        out = tmp / "out.json"
        cmd = [sys.executable, str(sandbox / FETCH_ISSUES), "--target", str(target),
               "--output", str(out)]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=env)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertFalse(fake_log.exists(),
                         "the rewritten pins file redirected the credential handoff to "
                         "the fake: a file the child can write decided who gets GH_TOKEN")
        self.assertTrue(real_log.exists(),
                        "the dispatcher-verified binary must be the one that executes")

    def test_a_genuine_empty_result_from_the_pinned_gh_stays_an_empty_result(self):
        tmp, sandbox, fakebin, target = self._sandbox(FETCH_ISSUES)
        fake = self._plant(fakebin, "gh", '#!/bin/sh\necho "[]"\nexit 0\n')
        pins = self._pins(tmp, "gh", path=str(fake), sha256=_sha256(fake))
        out = tmp / "out.json"
        env = self._env(pins, fakebin)
        cmd = [sys.executable, str(sandbox / FETCH_ISSUES), "--target", str(target),
               "--output", str(out)]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=env)
        self.assertEqual(res.returncode, 0, res.stderr)
        record = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(record["candidate_count"], 0)
        self.assertEqual(record["source"], "github")


class TestSecretScanPinBoundary(PrepassPinBoundaryBase):
    def test_a_present_but_unauthenticatable_gitleaks_is_loud_never_a_builtin_fallback(self):
        tmp, sandbox, fakebin, target = self._sandbox(SCAN)
        log = tmp / "fake.log"
        self._plant(fakebin, "gitleaks", f'#!/bin/sh\necho ran >> {log}\nexit 0\n')
        # A sha the fake cannot match (git's content), so the PATH plant is refused.
        pins = self._pins(tmp, "gitleaks", sha256=_sha256(Path("/usr/bin/git")))
        res = self._run(sandbox, SCAN, target, self._env(pins, fakebin))
        self.assertEqual(res.returncode, 2, res.stderr)
        self.assertIn("cannot be authenticated", res.stderr)
        self.assertFalse(log.exists(), "the fake gitleaks executed: the pin was bypassed")

    def test_a_genuinely_absent_gitleaks_keeps_the_documented_builtin_fallback(self):
        tmp, sandbox, fakebin, target = self._sandbox(SCAN)
        # No gitleaks on PATH at all and none pinned: resolve_tool fails closed AND
        # shutil.which finds nothing, so the documented builtin-regex fallback runs.
        pins = self._pins(tmp, "gitleaks", sha256="0" * 64)
        env = self._env(pins, fakebin)
        out = tmp / "out.json"
        cmd = [sys.executable, str(sandbox / SCAN), "--target", str(target),
               "--output", str(out)]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=env)
        self.assertEqual(res.returncode, 0, res.stderr)
        record = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(record["scanner"], "builtin-regex")


class TestGatherCommitsPinBoundary(PrepassPinBoundaryBase):
    def test_a_path_planted_git_is_refused_before_it_executes(self):
        tmp, sandbox, fakebin, target = self._sandbox(GATHER_COMMITS)
        log = tmp / "fake.log"
        self._plant(fakebin, "git", f'#!/bin/sh\necho ran >> {log}\nexit 0\n')
        pins = self._pins(tmp, "git", sha256=_sha256(Path("/usr/bin/gh")
                                                     if Path("/usr/bin/gh").exists()
                                                     else Path("/bin/sh")))
        res = self._run(sandbox, GATHER_COMMITS, target, self._env(pins, fakebin))
        self.assertEqual(res.returncode, 2, res.stderr)
        self.assertIn("cannot be authenticated", res.stderr)
        self.assertFalse(log.exists(), "the fake git executed: the pin was bypassed")


class TestCheckDocsPinBoundary(PrepassPinBoundaryBase):
    def test_a_path_planted_git_is_refused_before_it_executes(self):
        # _git_paths is consulted only when the scan produces candidates, so drive the
        # boundary directly: import the SANDBOXED script and call _git_paths with a fake
        # git first on PATH and a pin it cannot match. sys.exit(2) must raise SystemExit
        # out of the subprocess try/except (which catches Exception, not BaseException).
        import importlib.util
        from unittest import mock

        tmp, sandbox, fakebin, target = self._sandbox(CHECK_DOCS)
        log = tmp / "fake.log"
        self._plant(fakebin, "git", f'#!/bin/sh\necho ran >> {log}\nexit 0\n')
        pins = self._pins(tmp, "git", sha256=_sha256(Path("/bin/sh")))
        spec = importlib.util.spec_from_file_location(
            "check_docs_sandboxed", sandbox / CHECK_DOCS)
        mod = importlib.util.module_from_spec(spec)
        env = self._env(pins, fakebin)
        with mock.patch.dict(os.environ, env, clear=False):
            spec.loader.exec_module(mod)
            with self.assertRaises(SystemExit) as ctx:
                mod._git_paths(target, "tracked")
        self.assertEqual(ctx.exception.code, 2)
        self.assertFalse(log.exists(), "the fake git executed: the pin was bypassed")


if __name__ == "__main__":
    unittest.main()
