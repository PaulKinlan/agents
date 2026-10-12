"""Shared harness for the containment suites.

The stub-engine/dispatcher harness (setUp plus its helpers) lived inside
`TestDispatcher`, so the two subclasses that add their own assertions inherited
and RE-RAN all 54 of its tests under an identical setUp - 108 duplicate
executions, about 100 s of the old file's 163 s (agents-3iog). The harness now
lives here: `TestDispatcher` subclasses it and owns the tests, while
`TestEngineCredentialPinning` and `TestPrepassEffectivePinsEveryPath` inherit
the HARNESS only and run just their own tests.

This module is deliberately NOT named test_*.py: it holds no tests of its own,
and unittest discovery must not collect it per importing module.
"""

import hashlib
import http.server
import importlib.machinery
import importlib.util
import json
import os
os.environ.setdefault("FACTORY_ALLOW_UNPINNED_TOOLS", "1")  # agents-7bj: tests use unpinned stub tools
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib.containment import (  # noqa: E402
    ENGINE_READ_SCOPE, ENGINE_TOOL_POLICIES, GRANTABLE_POLICIES, READ_ONLY, WORKTREE_WRITE,
    WORKTREE_WRITE_UNVERIFIED_ENGINES, ContainmentError, banner_lines,
    budget_note, check_engine, downgrade_network_to_withheld, egress_allowlist, load_policy,
    policy_record,
)
from lib.sandbox import SANDBOXED_ENGINES, sandbox_available, sandbox_command  # noqa: E402
from lib.credential_broker import PLACEHOLDER_PREFIX  # noqa: E402
from lib.child_env import child_environment  # noqa: E402
from lib import egress_proxy  # noqa: E402
from lib import containment as containment_module  # noqa: E402
from lib import sandbox as sandbox_module  # noqa: E402
from lib.egress_proxy import EgressProxy  # noqa: E402

# Whether THIS host can run bubblewrap. The confinement acceptance test needs it; the
# fail-closed and opt-in tests simulate its absence with a broken bwrap on PATH, so they run
# anywhere (review P0, agents-9n7).
_BWRAP = sandbox_available()

_loader = importlib.machinery.SourceFileLoader("factory_cli_pnu", str(ROOT / "factory"))
_spec = importlib.util.spec_from_loader("factory_cli_pnu", _loader)
factory_cli = importlib.util.module_from_spec(_spec)
_loader.exec_module(factory_cli)

STUB_REPORT = "echo '{\"summary\":\"stub\",\"scanned_files\":0,\"findings\":[]}'\n"


def manifest(**overrides):
    cfg = {
        "name": "probe",
        "containment": "t0-readonly",
        "capabilities": {"write": False, "network": False, "browser": False, "requires": []},
        "budget": {"max_minutes": 5},
    }
    cfg.update(overrides)
    return cfg


class ContainmentHarness(unittest.TestCase):
    """The real `factory run` CLI, from a sandbox copy, against a stub `pi`.

    The stub reports through its stdout, which the adapter captures into the run
    directory's model_output.txt — the only place an engine can write, because the OS
    sandbox (agents-9n7) makes the factory root read-only and the run directory writable.
    extract_json_from_output tolerates the marker lines around the JSON report."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="factory-pnu-dispatch-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        # agents-r2ne census: copies the factory BINARY plus a WHOLE-tree copy of lib/ (a
        # non-station artefact and no hand-maintained enumeration), so the station-script
        # builder in tests/sandbox_fixtures.py does not apply. Different case.
        shutil.copyfile(ROOT / "factory", self.root / "factory")
        shutil.copytree(ROOT / "lib", self.root / "lib",
                        ignore=shutil.ignore_patterns("__pycache__"))
        self.target = self.root / "target"
        self.target.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "echo \"ARGV:$*\"\n"
            "echo \"POLICY:${FACTORY_TOOL_POLICY:-unset}\"\n"
            "echo \"BUDGET:${FACTORY_MAX_BUDGET_USD:-unset}\"\n"
            # The canary's *path* arrives through a file inside the target (the adapter
            # cds there); env would not reach the engine — child_environment is an
            # allowlist, which is exactly the point.
            "CANARY_PATH=$(cat canary-path.txt 2>/dev/null || echo /nonexistent)\n"
            "echo \"CANARY:$(cat \"$CANARY_PATH\" 2>&1 | head -1)\"\n"
            # agents-854: expose pi's agent-dir redirect and the provider override the
            # dispatcher wrote into it, so the test can assert the keyless wiring end to end.
            "echo \"AGENTDIR:${PI_CODING_AGENT_DIR:-unset}\"\n"
            "echo \"MODELSJSON:$(cat \"${PI_CODING_AGENT_DIR:-/nonexistent}/models.json\" 2>/dev/null || echo none)\"\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)

    def stub_lines(self):
        runs = self.run_dirs()
        self.assertEqual(len(runs), 1, "expected exactly one run directory")
        output = (runs[0] / "model_output.txt").read_text(encoding="utf-8")
        return output.splitlines()

    def stub_line(self, prefix):
        for line in self.stub_lines():
            if line.startswith(prefix):
                return line[len(prefix):]
        self.fail(f"no {prefix} line in the stub's output")

    def agent(self, yaml_text):
        directory = self.root / "agents" / "probe"
        directory.mkdir(parents=True)
        (directory / "agent.yaml").write_text(yaml_text, encoding="utf-8")
        (directory / "SKILL.md").write_text("# Probe\n", encoding="utf-8")

    def trusted_target(self, name="trusted", visibility="private", extra=""):
        """agents-bp0: write a named-target manifest carrying the trusted attestation
        (`trusted: true` + `visibility: private`) pointing at the harness target.
        visibility=None omits the field (it then normalizes to public, failing closed)."""
        (self.root / "targets").mkdir(exist_ok=True)
        vis = f"visibility: {visibility}\n" if visibility is not None else ""
        (self.root / "targets" / f"{name}.yaml").write_text(
            f"name: {name}\npath: {self.target}\n{vis}trusted: true\n{extra}",
            encoding="utf-8")
        return name

    def factory(self, engine, extra_env=None, target_arg=None):
        env = {"PATH": f"{self.bin}{os.pathsep}/usr/bin:/bin", "HOME": str(self.root),
               "FACTORY_ALLOW_UNPINNED_TOOLS": "1"}
        env.update(extra_env or {})
        return subprocess.run(
            [sys.executable, str(self.root / "factory"), "run", "probe", "--target",
             target_arg or str(self.target), "--engine", engine, "--sink", "file"],
            cwd=str(self.root), env=env, capture_output=True, text=True, timeout=120,
        )

    def run_dirs(self):
        runs = self.root / "runs"
        return sorted(runs.glob("probe-*")) if runs.exists() else []

    def _git_init_target(self):
        """Make self.target a git repo with one committed file, so a write grant can create a
        disposable worktree of its HEAD."""
        subprocess.run(["git", "init", "-q", str(self.target)], check=True, capture_output=True)
        (self.target / "fixme.txt").write_text("original line\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.target), "add", "-A"], check=True,
                       capture_output=True)
        subprocess.run(["git", "-C", str(self.target), "-c", "user.email=factory@test",
                        "-c", "user.name=factory", "commit", "-qm", "initial"], check=True,
                       capture_output=True)

    def _editing_stub(self):
        """Overwrite the stub pi with one that records its policy/cwd and makes an edit
        (modify a tracked file + add a new one) so the session diff is non-empty."""
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "echo \"POLICY:${FACTORY_TOOL_POLICY:-unset}\"\n"
            "echo \"CWD:$(pwd)\"\n"
            "printf '// proposed fix\\n' >> fixme.txt\n"
            "printf 'brand new file\\n' > proposed.txt\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)

    def _target_fingerprint(self):
        """A byte-level fingerprint of the target checkout: its HEAD commit plus a sha256 of
        every working-tree file's relative path and content (.git internals excluded). Equal
        fingerprints before and after a run prove the checkout is byte-identical — the explicit
        hard requirement, stronger than `git status` alone."""
        head = subprocess.run(["git", "-C", str(self.target), "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True).stdout.strip()
        digest = hashlib.sha256(head.encode("utf-8"))
        for path in sorted(p for p in self.target.rglob("*")
                           if p.is_file() and ".git" not in p.relative_to(self.target).parts):
            digest.update(str(path.relative_to(self.target)).encode("utf-8"))
            digest.update(path.read_bytes())
        return digest.hexdigest()

    def _assert_no_leaked_worktree(self):
        """No disposable session worktree may survive a run (coord hard requirement): neither
        the directory under the run dir nor a registration in the target's .git/worktrees."""
        for run_dir in self.run_dirs():
            self.assertFalse((run_dir / "worktree").exists(),
                             f"leaked worktree directory in {run_dir}")
        listing = subprocess.run(
            ["git", "-C", str(self.target), "worktree", "list", "--porcelain"],
            capture_output=True, text=True, check=True).stdout
        self.assertNotIn("/worktree", listing, "leaked worktree registration: " + listing)
