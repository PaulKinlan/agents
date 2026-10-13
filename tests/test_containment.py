"""Containment: the dispatcher's policy record.

agents-ryw9 split this file: it keeps the admission/budget/banner subset.
The 49 tests that used to live here are in the sibling subject modules, and the
header below is theirs too (agents-3iog).
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

from tests import containment_harness as harness

# TestDispatcher's tests read TestAdapters.ENGINE_BINARY. Import the MODULE, not the name:
# a class imported into this namespace would be collected by discovery here as well, which is
# the duplicate-run shape this split exists to remove (agents-3iog).
from tests import test_containment_adapters as adapters

class TestDispatcher(harness.ContainmentHarness):
    """The real `factory run` CLI, from a sandbox copy, against a stub `pi`.

    The stub reports through its stdout, which the adapter captures into the run
    directory's model_output.txt — the only place an engine can write, because the OS
    sandbox (agents-9n7) makes the factory root read-only and the run directory writable.
    extract_json_from_output tolerates the marker lines around the JSON report.
    """


    def test_an_engine_that_cannot_enforce_is_refused_before_any_work(self):
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        res = self.factory("antigravity")
        self.assertEqual(res.returncode, 3, res.stdout + res.stderr)
        self.assertIn("cannot enforce", res.stderr)
        self.assertEqual(self.run_dirs(), [], "a refused run must leave no run directory")


    def test_a_declaration_above_its_ceiling_is_refused_before_any_work(self):
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi")
        self.assertEqual(res.returncode, 3, res.stdout + res.stderr)
        self.assertIn("exceeds the t0-readonly ceiling", res.stderr)
        self.assertEqual(self.run_dirs(), [], "the engine must not start")


    def test_the_policy_is_set_explicitly_enforced_and_recorded(self):
        """A FACTORY_TOOL_POLICY in the caller's environment never reaches the adapter."""
        self.agent("name: probe\nclass: proposer\ncontainment: t2-local\n"
                   "capabilities:\n  write: true\nbudget: {max_minutes: 1}\n")
        self.trusted_target("trusted")
        res = self.factory("pi", {"FACTORY_TOOL_POLICY": "unrestricted",
                                  "FACTORY_ALLOW_UNSANDBOXED": "1"}, target_arg="trusted")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.stub_line("POLICY:"), READ_ONLY)
        argv = self.stub_line("ARGV:").split()
        self.assertEqual(argv[argv.index("--tools") + 1], "read,grep,find,ls")
        self.assertIn("Withheld:    write", res.stdout)
        self.assertIn("[pi adapter] Tool policy: read-only", res.stdout)
        runs = self.run_dirs()
        self.assertEqual(len(runs), 1)
        record = json.loads((runs[0] / "policy.json").read_text(encoding="utf-8"))
        self.assertEqual(record["granted"]["tool_policy"], READ_ONLY)
        self.assertEqual(record["declared"]["containment"], "t2-local")
        self.assertEqual(set(record["withheld"]), {"write"})


    def test_a_declared_usd_cap_reaches_the_adapter_only_from_the_dispatcher(self):
        """agents-js7: the declared cap is set explicitly on the adapter environment; an
        ambient FACTORY_MAX_BUDGET_USD in the operator's shell never reaches the adapter."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1, max_usd: 0.5}\n")
        self.trusted_target("trusted")
        res = self.factory("pi", {"FACTORY_MAX_BUDGET_USD": "999",
                                  "FACTORY_ALLOW_UNSANDBOXED": "1"}, target_arg="trusted")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.stub_line("BUDGET:"), "0.5", "the declared cap, not the ambient one")
        self.assertIn("NOT enforced (the pi adapter has no per-run budget flag)", res.stdout)
        record = json.loads((self.run_dirs()[0] / "policy.json").read_text(encoding="utf-8"))
        self.assertIn("budget.max_usd", record["not_enforced"])


    def test_an_unpinned_run_is_auditable_in_policy_json_and_banner(self):
        """agents-onf6: an unpinned-tools run must record the waiver in the run banner
        and in policy.json (in not_enforced and unpinned_tools_opt_in) so it is auditable."""
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\nbudget: {max_minutes: 1}\n")
        self.trusted_target("trusted")
        res = self.factory("pi", {"FACTORY_ALLOW_UNPINNED_TOOLS": "1",
                                  "FACTORY_ALLOW_UNSANDBOXED": "1"}, target_arg="trusted")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("Tool pins:   NOT enforced — explicit FACTORY_ALLOW_UNPINNED_TOOLS=1", res.stdout)
        record = json.loads((self.run_dirs()[0] / "policy.json").read_text(encoding="utf-8"))
        self.assertIn("trusted-tool-pins", record["not_enforced"])
        self.assertIn("unpinned_tools_opt_in", record)
        self.assertIn("FACTORY_ALLOW_UNPINNED_TOOLS=1", record["unpinned_tools_opt_in"])

if __name__ == "__main__":
    unittest.main()
