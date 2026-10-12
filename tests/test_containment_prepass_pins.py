"""Containment: the pre-pass's effective pins on every path.

Split from tests/test_containment.py (agents-3iog); the harness's tests are no
longer re-run under this subclass (they ran identically to TestDispatcher's).
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

class TestPrepassEffectivePinsEveryPath(harness.ContainmentHarness):
    """agents-28nn round 5, review P1 — THE CONTROL MUST BE A PROPERTY OF THE OPERATION,
    NOT OF THE PATH TAKEN TO IT.

    This is the THIRD appearance of the inverted-polarity shape in this bead (the
    agents-dpt pins forwarding to children; the round-4 verdict's bind verification only
    when sandbox_ok; and this one), so it is fixed as a design rule, not patched as a
    slip: the merged effective pins were written ONLY inside the `if sandbox_ok:` block,
    so the LESS-confined unsandboxed pre-pass had LESS control — it re-derived its pins
    from the forwarded host path instead of verifying against EXACTLY what the host
    verified (a snapshot a host-pins swap between host resolution and child exec cannot
    widen).

    The constructed case forces the unsandboxed path on a sandboxed host — a host pins
    file with NO bwrap entry fails the probe closed, and FACTORY_ALLOW_UNSANDBOXED=1 plus
    a trusted private target permits the run — and the pre-pass records the
    FACTORY_VERIFIED_TOOL_PINS it was handed (the dispatcher's snapshot; agents-oq3j). The control
    must hold on this path too: the env
    names the dispatcher's effective pins file (a factory-pins-*/ dir, NOT the run dir,
    NOT the forwarded host file) and its content is the merged view.

    MUTATION PROOF (performed, not asserted): reverting the hoist — the effective-pins
    write back inside `if sandbox_ok:` — turns this red: the pre-pass then records the
    FORWARDED host pins path, which fails the effective-file assertions below.
    """

    RECORDER = (
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "out = sys.argv[sys.argv.index('--output') + 1]\n"
        "pins = os.environ.get('FACTORY_VERIFIED_TOOL_PINS', '')\n"
        "Path(out).write_text(json.dumps({\n"
        "    'candidates': [],\n"
        "    'pins_env': pins,\n"
        "    'pins_exists': bool(pins) and Path(pins).exists(),\n"
        "    'pins_content': Path(pins).read_text() if pins and Path(pins).exists() else '',\n"
        "}))\n")

    def _present_trusted_prepass_pin_lines(self):
        """Path+sha256 pins for every TRUSTED tool in PREPASS_EXECUTABLES that is PRESENT
        on the harness PATH (agents-28nn round 6): the dispatcher verifies the pre-pass's
        whole trusted-tool set host-side on EVERY path — exactly what the sandboxed path's
        bind boundary does at wrap time (lib/sandbox.py _executable_binds verify_pins every
        pinned tool) — so a present-but-unauthenticatable tool refuses the run and these
        pins must exist. Genuinely ABSENT tools are skipped (the script fails closed or
        takes its documented fallback, as on the sandboxed path).
        MUST be called BEFORE planting any fake on the harness PATH: a pin IS a grant, so
        the pinned path must be the real system binary, never the plant."""
        import hashlib
        from lib.sandbox import PREPASS_EXECUTABLES
        from lib.tool_pins import TRUSTED_TOOLS
        lines = []
        for name in sorted(set(PREPASS_EXECUTABLES) & set(TRUSTED_TOOLS)):
            tool = shutil.which(name, path=f"{self.bin}{os.pathsep}/usr/bin:/bin")
            if tool is None:
                continue
            digest = hashlib.sha256(Path(tool).read_bytes()).hexdigest()
            lines.append(f"{name}:\n  path: {tool}\n  sha256: {digest}\n")
        return "".join(lines)

    def test_a_child_rewriting_the_pins_cannot_redirect_the_credential_handoff(self):
        """agents-28nn round 6, review P1 — the effective-pins TOCTOU on the UNSANDBOXED
        path, COMPOSED with the falsified polarity argument (a pin IS a grant):
        A CONTROL THAT DEPENDS ON A MOUNT NAMESPACE IS ABSENT ON THE PATH THAT HAS NONE.

        The constructed case, kept as a regression test: an unsandboxed pre-pass child
        REWRITES the child-only pins file it was handed, injecting a pin that names a
        planted fake git by path+hash — the round-6 reviewer's exact construction — and
        then asks lib.tool_pins which git it may execute. On the round-5 tree the
        resolver validated the injected pin and the fake would have run with the
        pre-pass's credentials. The fix: the credential handoff must not depend on a
        file the child can write — the dispatcher resolves the pre-pass's trusted tools
        HOST-SIDE, before the handoff, and the verified absolute paths ride the
        fork-time env (FACTORY_RESOLVED_TOOL_*), so prepass_tool returns the REAL git
        and the injected pin is never consulted.

        MUTATION PROOF (performed, not asserted): reverting prepass_tool's dispatcher
        preference (unsandboxed arm falls through to resolve_tool against the pins file)
        turns this red — the recorded resolution names the FAKE.
        """
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        scripts = self.root / "agents" / "probe" / "scripts"
        scripts.mkdir(parents=True)
        self.trusted_target("trusted")
        import hashlib
        stub = self.bin / "pi"
        digest = hashlib.sha256(stub.read_bytes()).hexdigest()
        host_pins = self.root / "tools.pins.yaml"
        host_pins.write_text(
            f"pi:\n  path: {stub}\n  sha256: {digest}\n" + self._present_trusted_prepass_pin_lines(),
            encoding="utf-8")
        fake = self.bin / "git"
        fake.write_text("#!/bin/sh\necho PWNED\n", encoding="utf-8")
        fake.chmod(0o755)
        # The fake's path is embedded in the script (the pre-pass env is an allowlist, so
        # a test-only variable would never reach the child).
        rewriter = (
            "import hashlib, json, os, sys\n"
            "from pathlib import Path\n"
            "sys.path.insert(0, str(Path(__file__).resolve().parents[3]))\n"
            "from lib.tool_pins import prepass_tool\n"
            "out = sys.argv[sys.argv.index('--output') + 1]\n"
            "pins = Path(os.environ['FACTORY_VERIFIED_TOOL_PINS'])\n"
            f"fake = {str(fake)!r}\n"
            "digest = hashlib.sha256(Path(fake).read_bytes()).hexdigest()\n"
            # THE ATTACK: rewrite the pins file in place, granting the fake the git role.
            "pins.write_text('git:\\n  path: %s\\n  sha256: %s\\n' % (fake, digest))\n"
            "Path(out).write_text(json.dumps({\n"
            "    'candidates': [],\n"
            "    'resolved_git': prepass_tool('git'),\n"
            "    'dispatcher_env': os.environ.get('FACTORY_RESOLVED_TOOL_GIT', ''),\n"
            "}))\n")
        (scripts / "rewrite_pins.py").write_text(rewriter, encoding="utf-8")
        res = self.factory("pi", {"FACTORY_ALLOW_UNSANDBOXED": "1",
                                  "FACTORY_ALLOW_UNPINNED_TOOLS": "0",
                                  "FACTORY_TOOL_PINS": str(host_pins)},
                           target_arg="trusted")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("Sandbox:     NOT enforced", res.stdout,
                      "the test must EXERCISE the unsandboxed path: " + res.stdout)
        runs = self.run_dirs()
        self.assertEqual(len(runs), 1)
        record = json.loads((runs[0] / "candidates.json").read_text(encoding="utf-8"))
        self.assertTrue(record["dispatcher_env"],
                        "the dispatcher must hand the child a host-verified git path")
        self.assertNotEqual(record["resolved_git"], str(fake),
                            "the injected pin redirected the handoff: the rewritten pins "
                            "file decided which binary receives the credentials")
        self.assertEqual(record["resolved_git"], record["dispatcher_env"],
                         "the child must execute the dispatcher-verified path, never "
                         "what the rewritten pins file names")

    def test_the_unsandboxed_prepass_verifies_against_the_same_effective_pins(self):
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "budget: {max_minutes: 1}\n")
        scripts = self.root / "agents" / "probe" / "scripts"
        scripts.mkdir(parents=True)
        (scripts / "record_pins.py").write_text(self.RECORDER, encoding="utf-8")
        self.trusted_target("trusted")
        # Pin the stub engine by path + content; OMIT bwrap so the probe fails closed and
        # the trusted-target opt-in takes the UNSANDBOXED path on this sandboxed host.
        # Every PRESENT trusted pre-pass tool must ALSO be pinned (agents-28nn round 6):
        # the dispatcher now verifies the pre-pass's whole trusted-tool set host-side on
        # EVERY path, and a present-but-unauthenticatable tool refuses the run — exactly
        # what the sandboxed path's bind boundary does at wrap time.
        import hashlib
        stub = self.bin / "pi"
        digest = hashlib.sha256(stub.read_bytes()).hexdigest()
        host_pins = self.root / "tools.pins.yaml"
        host_pins.write_text(
            f"pi:\n  path: {stub}\n  sha256: {digest}\n"
            + self._present_trusted_prepass_pin_lines(),
            encoding="utf-8")
        res = self.factory("pi", {"FACTORY_ALLOW_UNSANDBOXED": "1",
                                  "FACTORY_ALLOW_UNPINNED_TOOLS": "0",
                                  "FACTORY_TOOL_PINS": str(host_pins)},
                           target_arg="trusted")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("Sandbox:     NOT enforced", res.stdout,
                      "the test must EXERCISE the unsandboxed path, or it proves nothing "
                      "about it: " + res.stdout)
        runs = self.run_dirs()
        self.assertEqual(len(runs), 1)
        record = json.loads((runs[0] / "candidates.json").read_text(encoding="utf-8"))
        pins_env = record["pins_env"]
        self.assertTrue(record["pins_exists"],
                        "the unsandboxed pre-pass must receive a pins file that EXISTS")
        self.assertEqual(Path(pins_env).name, "tool-pins.effective.yaml",
                         "every path's child must verify against the EFFECTIVE pins the "
                         "host wrote, not a re-derived merge of the forwarded host file: "
                         + pins_env)
        self.assertTrue(Path(pins_env).parent.name.startswith("factory-pins-"),
                        "the effective pins live in their own per-run dir: " + pins_env)
        self.assertNotIn(str(runs[0]), pins_env,
                         "the pins file must not live in the rw run dir (the round-5 P0)")
        self.assertNotEqual(pins_env, str(host_pins),
                            "the child gets the host's merged snapshot, not the host file "
                            "itself (a swap between host resolution and child exec must "
                            "not widen what the child trusts)")
        self.assertIn(digest, record["pins_content"],
                      "the effective pins must carry the host's merge (the pi pin)")

if __name__ == "__main__":
    unittest.main()
