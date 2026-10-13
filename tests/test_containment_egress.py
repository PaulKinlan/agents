"""Containment: network egress end to end (agents-2x6).

Split from tests/test_containment.py (agents-3iog), with the http-upstream mock
and the in-sandbox probe script it drives.
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

def _mock_http_upstream(port_holder, ready, stop):
    """A plain-HTTP mock upstream for the agents-2x6 end-to-end test: answers every
    request with `200 mock-upstream-ok` on an ephemeral loopback port (host side; the
    sandboxed client never dials it directly — only the egress proxy does)."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    srv.settimeout(0.2)
    port_holder.append(srv.getsockname()[1])
    ready.set()
    try:
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            with conn:
                conn.settimeout(3)
                data = b""
                try:
                    while b"\r\n\r\n" not in data:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    body = b"mock-upstream-ok"
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: "
                                 + str(len(body)).encode()
                                 + b"\r\nConnection: close\r\n\r\n" + body)
                except OSError:
                    pass
    finally:
        srv.close()


_E2E_PROBE_SCRIPT = r"""
import http.client, json, socket, sys, urllib.error, urllib.request

port = int(sys.argv[1])
results = {}

def fetch(url):
    try:
        with urllib.request.urlopen(url, timeout=6) as r:
            return "ok-{}-{}".format(r.status, r.read().decode())
    except urllib.error.HTTPError as e:
        return "http-{}".format(e.code)
    except OSError as e:
        return "os-{}:{}".format(type(e).__name__, getattr(e, "reason", e))

# (a) allowlisted host: relay -> proxy -> mock upstream.
results["allowlisted"] = fetch("http://allowlisted.test:{}/fetch".format(port))
# (b) non-allowlisted host: the proxy must refuse it, never dial it.
results["forbidden"] = fetch("http://forbidden.test:{}/fetch".format(port))

# (c) coercion 1: absolute-URI target forbidden, forged Host header allowlisted. The
# proxy's decision must come from the request line, never the header.
conn = http.client.HTTPConnection("127.0.0.1", 8385, timeout=6)
try:
    conn.request("GET", "http://forbidden.test:{}/smuggle".format(port),
                 headers={"Host": "allowlisted.test:{}".format(port)})
    results["coerce_host_header"] = "http-{}".format(conn.getresponse().status)
except OSError as e:
    results["coerce_host_header"] = "os-{}".format(type(e).__name__)
finally:
    conn.close()

# (c) coercion 2: a direct CONNECT to a non-allowlisted host.
line = "no-response"
s = socket.create_connection(("127.0.0.1", 8385), timeout=6)
try:
    s.sendall(("CONNECT forbidden.test:{0} HTTP/1.1\r\nHost: forbidden.test:{0}\r\n\r\n"
               .format(port)).encode())
    data = s.recv(4096)
    if data:
        line = data.split(b"\r\n", 1)[0].decode("latin-1")
finally:
    s.close()
results["coerce_connect"] = line

# The kernel property, in the same sandboxed run: no route off the netns at all.
try:
    socket.create_connection(("93.184.216.34", 443), timeout=3).close()
    results["direct"] = "REACHED"
except OSError:
    results["direct"] = "UNREACHABLE"

print("EGRESS:" + json.dumps(results, sort_keys=True))
"""


class TestEgressEndToEnd(unittest.TestCase):
    """agents-2x6 named end-to-end acceptance (coord guardrails), all in ONE sandboxed
    run: from INSIDE a real --unshare-net bubblewrap engine, through the net_forward relay
    and the egress proxy, (a) an allowlisted host succeeds against a mock upstream,
    (b) a non-allowlisted host genuinely fails (403 from the proxy, ENETUNREACH from the
    kernel for anything off the netns), and (c) the proxy cannot be coerced into reaching
    a non-allowlisted host via the request — the dial target is taken from the request
    line and checked against the run's own allowlist, never trusted from a header. The
    mock upstream is loopback, so the SSRF guard is patched to treat it as public (the
    established pattern from tests/test_egress_proxy.py); bwrap, --unshare-net, the relay
    and the proxy's allowlist decision are all the real mechanism."""

    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_allowlisted_egress_works_and_everything_else_genuinely_fails(self):
        with tempfile.TemporaryDirectory(prefix="factory-2x6-e2e-") as tmpdir:
            root = Path(tmpdir)
            target = root / "target"
            target.mkdir()
            run_dir = root / "runs" / "probe-e2e"
            run_dir.mkdir(parents=True)

            port_holder, upstream_ready, upstream_stop = [], threading.Event(), threading.Event()
            threading.Thread(target=_mock_http_upstream,
                             args=(port_holder, upstream_ready, upstream_stop),
                             daemon=True).start()
            self.assertTrue(upstream_ready.wait(5))
            upstream_port = port_holder[0]

            probe = run_dir / "probe.py"
            probe.write_text(_E2E_PROBE_SCRIPT, encoding="utf-8")

            # The mock upstream listens on a random (non-standard) port, so pin it in the
            # allowlist entry (agents-cn3: a bare host permits only the standard web ports).
            proxy = EgressProxy([f"allowlisted.test:{upstream_port}"],
                                str(run_dir / "egress-proxy.sock"))
            proxy.start()
            child_env = {"PATH": "/usr/bin:/bin",
                         "HTTP_PROXY": "http://127.0.0.1:8385",
                         "HTTPS_PROXY": "http://127.0.0.1:8385",
                         "NO_PROXY": "localhost,127.0.0.1",
                         "FACTORY_ALLOW_UNPINNED_TOOLS": "1"}
            try:
                with mock.patch.object(egress_proxy, "_public_addresses",
                                       return_value=["127.0.0.1"]):
                    wrapped = sandbox_command(
                        [sys.executable, str(probe), str(upstream_port)],
                        target_dir=target, factory_root=ROOT, run_dir=run_dir,
                        env=child_env,
                        executables=(sys.executable,),
                        egress_forwards=[(8385, str(run_dir / "egress-proxy.sock"))])
                    res = subprocess.run(wrapped, capture_output=True, text=True,
                                         timeout=120, env=child_env)
            finally:
                proxy.stop()
                upstream_stop.set()

            line = next((l for l in res.stdout.splitlines() if l.startswith("EGRESS:")), None)
            self.assertIsNotNone(
                line, "the sandboxed probe produced no verdict:\n" + res.stdout + res.stderr)
            results = json.loads(line[len("EGRESS:"):])

            # (a) the allowlisted host is reachable through relay + proxy + mock upstream.
            self.assertEqual(results["allowlisted"], "ok-200-mock-upstream-ok", results)
            # (b) a non-allowlisted host genuinely fails: refused by the proxy (403) ...
            self.assertEqual(results["forbidden"], "http-403", results)
            # ... and a dial off the netns fails at the kernel, not by convention.
            self.assertEqual(results["direct"], "UNREACHABLE", results)
            # (c) coercion: the Host header cannot smuggle a non-allowlisted target ...
            self.assertEqual(results["coerce_host_header"], "http-403", results)
            # ... and a direct CONNECT to a non-allowlisted host is refused too.
            self.assertIn("403", results["coerce_connect"], results)



class TestEngineNetworkBoundary(harness.ContainmentHarness):
    """The engine's network boundary (netns, allowlist, downgrade)."""


    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_a_sandboxed_engine_has_no_route_off_its_netns(self):
        """agents-2x6 acceptance: with egress control active the engine runs under
        --unshare-net, so a dial off the sandbox must genuinely fail at the kernel, not by
        convention. The allowlisted path — the credential broker through the net_forward
        relay — is proven end to end by the 8h4 acceptance test above, which now runs through
        that relay (the engine dials 127.0.0.1:8384 and the broker answers). This is the
        complement: everything ELSE is unreachable, and no resolver is available either."""
        stub = self.bin / "pi"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "python3 - <<'PYEOF'\n"
            "import socket\n"
            "try:\n"
            "    socket.create_connection(('93.184.216.34', 443), timeout=3).close()\n"
            "    print('DIRECT:REACHED')\n"
            "except OSError:\n"
            "    print('DIRECT:UNREACHABLE')\n"
            "try:\n"
            "    socket.gethostbyname('api.github.com')\n"
            "    print('DNS:RESOLVED')\n"
            "except OSError:\n"
            "    print('DNS:BLOCKED')\n"
            "PYEOF\n"
            "cat >/dev/null\n" + STUB_REPORT,
            encoding="utf-8",
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        self.agent("name: probe\nclass: observer\ncontainment: t0-readonly\n"
                   "capabilities: {}\nbudget: {max_minutes: 1}\n")
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(self.stub_line("DIRECT:"), "UNREACHABLE",
                         "under --unshare-net a dial off the netns must fail at the kernel")
        self.assertEqual(self.stub_line("DNS:"), "BLOCKED",
                         "no resolver may be reachable from the isolated netns")


    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_the_prepass_egress_is_held_to_its_own_allowlist(self):
        """agents-2x6 acceptance: the pre-pass runs under --unshare-net with the egress
        proxy as its only route off the netns (HTTP_PROXY points at the in-sandbox relay),
        and the allowlist is derived from the agent's OWN requires — here [gh] →
        api.github.com — so a fetch of any other host is refused by the proxy itself (403).
        The refusal is decided before any upstream dial, so this needs no live network."""
        self.agent("name: probe\nclass: observer\ncontainment: t1-fetch\n"
                   "capabilities:\n  network: true\n  requires: [gh]\n"
                   "budget: {max_minutes: 1}\n")
        scripts = self.root / "agents" / "probe" / "scripts"
        scripts.mkdir(parents=True)
        (scripts / "prepass.py").write_text(
            "import json, os, sys, urllib.error, urllib.request\n"
            "out = sys.argv[sys.argv.index('--output') + 1]\n"
            "try:\n"
            "    urllib.request.urlopen('http://registry.npmjs.org/-/ping', timeout=5)\n"
            "    verdict = 'reached'\n"
            "except urllib.error.HTTPError as e:\n"
            "    verdict = f'http-{e.code}'\n"
            "except OSError as e:\n"
            "    verdict = f'os-{type(e).__name__}'\n"
            "with open(out, 'w', encoding='utf-8') as fh:\n"
            "    json.dump({'egress': verdict, 'proxy': os.environ.get('HTTP_PROXY')}, fh)\n",
            encoding="utf-8",
        )
        res = self.factory("pi")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        payload = json.loads((self.run_dirs()[0] / "candidates.json").read_text(encoding="utf-8"))
        self.assertEqual(payload["proxy"], "http://127.0.0.1:8385",
                         "the pre-pass must be pointed at the in-sandbox egress proxy")
        self.assertEqual(payload["egress"], "http-403",
                         "a host outside the agent's own requires allowlist must be refused")


    @unittest.skipUnless(_BWRAP, "needs a host where bubblewrap actually runs")
    def test_unbrokerable_model_downgrades_network_and_reports_egress_unfiltered(self):
        """agents-8xei: when a run requests an unbrokerable model (e.g. mistral/mistral-large),
        the key survey recognizes the model provider cannot be brokered under --unshare-net,
        downgrades network to withheld, and honestly reports network-egress as not enforced."""
        self.agent("name: probe\nclass: observer\ncontainment: t1-fetch\n"
                   "capabilities:\n  network: true\n"
                   "budget: {max_minutes: 1}\n")
        res = self.factory("pi", {"FACTORY_MODEL": "mistral/mistral-large"})
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        record = json.loads((self.run_dirs()[0] / "policy.json").read_text(encoding="utf-8"))
        self.assertIn("network-egress", record["not_enforced"])
        self.assertFalse(record["granted"]["os_sandbox"]["network_egress_filtered"])
        self.assertIn("network egress NOT filtered", res.stdout)
        self.assertIn("Withheld:    network", res.stdout)

if __name__ == "__main__":
    unittest.main()
