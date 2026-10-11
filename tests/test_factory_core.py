#!/usr/bin/env python3
"""Unit tests for the Software Factory core library (findings store, YAML parser, containment)."""

import importlib.machinery
import importlib.util
import json
import os
os.environ.setdefault("FACTORY_ALLOW_UNPINNED_TOOLS", "1")  # agents-7bj: tests use unpinned stub tools
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
import typing
from unittest import mock

from lib.findings import FindingsStore, compute_fingerprint, normalize_text
from lib.child_env import child_environment
from lib.credential_broker import PLACEHOLDER_PREFIX
from lib.sandbox import sandbox_available
from lib.tool_pins import ToolPinError

# --- hermetic test environment (agents-21ap) -------------------------------------------------
# The pin machinery under test resolves tools through FACTORY_TOOL_PINS when the OPERATOR'S
# shell exports it (~/.fleet/local.conf does on this VM), so without this scrub these tests
# observed the host rather than the tree: on 2026-10-11 a re-provision generated the host pins
# file and 42 tests across three modules went red on EVERY tree, including landed main, each
# with `trusted tool 'pi' resolved to /tmp/.../bin/pi, not the configured path
# /usr/local/bin/pi`. The tests were right - they plant a fake `pi` and assert the pin refuses
# it - and the environment was not hermetic. See tests/hermetic_env.py for why this removes the
# ambient input rather than installing pins of its own.
from tests import hermetic_env  # noqa: E402


def setUpModule():
    hermetic_env.isolate_operator_config()


def tearDownModule():
    hermetic_env.restore_operator_config()


FACTORY_ROOT = Path(__file__).resolve().parent.parent
loader = importlib.machinery.SourceFileLoader("factory_cli", str(FACTORY_ROOT / "factory"))
spec = importlib.util.spec_from_loader("factory_cli", loader)
factory_cli = importlib.util.module_from_spec(spec)
loader.exec_module(factory_cli)

# The dispatcher must REFUSE pi on hosts without a runnable OS sandbox. Engine-run
# tests cannot assert successful execution there; refusal tests remain ungated.
_RUNNABLE_BWRAP = sandbox_available()
_NEEDS_BWRAP = "needs a host where bubblewrap actually runs"


def _write_draining_report_stub(stub: Path, report_src: Path, marker: str = "") -> None:
    """Canned engine output must consume the real adapter's entire piped prompt first.

    pi.sh/claude.sh use pipefail: exiting with unread stdin can SIGPIPE their printf,
    turning a valid canned report into a spurious adapter failure (agents-ub9/61t).
    """
    stub.write_text(
        "#!/usr/bin/env bash\n"
        "cat >/dev/null\n"
        + (f"echo {marker}\n" if marker else "")
        + f"cat '{report_src}'\n",
        encoding="utf-8",
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)


def _unpinned_stub_child_environment(**kwargs) -> typing.Dict[str, str]:
    """`child_environment` plus the dev/test opt-in an unpinned stub `bd`/`gh` needs.

    The findings child re-resolves its trusted tools by name under its own fail-closed pin
    check (agents-7bj); the stub tools these tests install carry no pin, so the child needs the
    same explicit opt-in tests/test_sinks.py gives its recorder.
    """
    env = child_environment(**kwargs)
    env["FACTORY_ALLOW_UNPINNED_TOOLS"] = "1"
    return env


class TestDrainingReportStub(unittest.TestCase):
    def test_large_prompt_cannot_sigpipe_a_canned_report(self):
        """Runs without bwrap; reverting the drain fails deterministically under pipefail."""
        with tempfile.TemporaryDirectory() as tmpdir:
            report_src = Path(tmpdir) / "report.json"
            report_src.write_text('{"summary":"stub","findings":[]}')
            for engine in ("pi", "claude"):
                with self.subTest(engine=engine):
                    stub = Path(tmpdir) / engine
                    _write_draining_report_stub(stub, report_src, marker=f"{engine.upper()}-RAN")
                    res = subprocess.run(
                        ["bash", "-o", "pipefail", "-c",
                         '"$1" -c \'import sys; sys.stdout.write("x"*200000)\' | "$2"',
                         "bash", sys.executable, str(stub)],
                        capture_output=True, text=True, timeout=10, check=False)
                    self.assertEqual(res.returncode, 0, res.stderr)
                    self.assertIn(f"{engine.upper()}-RAN", res.stdout)
                    self.assertEqual(json.loads(res.stdout.splitlines()[-1])["summary"], "stub")


class TestSoftwareFactoryCore(unittest.TestCase):
    def test_fingerprint_line_number_independence(self):
        """Fingerprints must be identical across line shifts and whitespace reformatting."""
        fp1 = compute_fingerprint("secret-scan", "generic-key", "./src/config.js", "const key = 'abc';")
        fp2 = compute_fingerprint("secret-scan", "generic-key", "src/config.js", "  const   key = 'abc'; \n")
        self.assertEqual(fp1, fp2)

    def test_findings_lifecycle_transitions(self):
        """Verify new -> unchanged -> fixed -> regressed state machine transitions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            store = FindingsStore("test-target", findings_dir=Path(tmpdir))
            sample = [{
                "rule_id": "xss-sink",
                "path": "app.js",
                "line_number": 10,
                "snippet": "el.innerHTML = user;",
                "severity": "high",
                "title": "DOM XSS"
            }]

            # Run 1: new
            _, stats1, _ = store.process_run("vuln-discovery", sample)
            self.assertEqual(stats1["new"], 1)

            # Run 2: unchanged (even if line_number changes)
            sample[0]["line_number"] = 42
            _, stats2, _ = store.process_run("vuln-discovery", sample)
            self.assertEqual(stats2["unchanged"], 1)
            self.assertEqual(stats2["new"], 0)

            # Run 3: empty findings -> fixed
            _, stats3, fixed = store.process_run("vuln-discovery", [])
            self.assertEqual(stats3["fixed"], 1)
            self.assertEqual(len(fixed), 1)

            # Run 4: reappears -> regressed
            _, stats4, _ = store.process_run("vuln-discovery", sample)
            self.assertEqual(stats4["regressed"], 1)

    def test_indentation_aware_yaml_parser(self):
        """Verify nested maps (schedule:, budget:) and lists parse properly."""
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as tf:
            tf.write(
                "name: fauxmium\n"
                "visibility: public\n"
                "agents:\n"
                "  - secret-scan\n"
                "  - test-gap\n"
                "schedule:\n"
                "  secret-scan:\n"
                "    interval: 86400\n"
                "    hour: 7\n"
            )
            tf_path = Path(tf.name)

        try:
            parsed = factory_cli.load_yaml_simple(tf_path)
            self.assertEqual(parsed["name"], "fauxmium")
            self.assertEqual(parsed["agents"], ["secret-scan", "test-gap"])
            self.assertIsInstance(parsed["schedule"], dict)
            self.assertEqual(parsed["schedule"]["secret-scan"]["interval"], 86400)
            self.assertEqual(parsed["schedule"]["secret-scan"]["hour"], 7)
        finally:
            tf_path.unlink(missing_ok=True)


class TestGitPinBoundary(unittest.TestCase):
    """agents-28nn round 2, review P1: git IS in TRUSTED_TOOLS, but the factory's own git
    plumbing (_run_git — worktree creation, the session diff, cleanup) executed
    ["git", ...] by NAME across the operator's PATH, so the pin machinery was never
    consulted for a nominally trusted tool and a PATH-planted fake git ran unverified
    with the factory's privileges. A trust list that some call sites ignore is a comment.

    The boundary is at the deliverer: _run_git resolves git through
    lib.tool_pins.resolve_tool BEFORE every invocation. These tests remove
    FACTORY_ALLOW_UNPINNED_TOOLS (the module-level dev/test opt-in the other suites use)
    because the properties they pin are exactly what the opt-in waives.

    The behaviour-mutation proof: reverting _run_git to prepend the literal "git"
    (PATH-order resolution) makes the first test fail both ways at once — no ToolPinError
    is raised AND the planted fake's invocation log appears.
    """

    FAKE = ('#!/bin/sh\n'
            # Log every invocation: refusal must PRECEDE any execution of the untrusted
            # binary, so the log existing at all fails the refusal tests. Exits 0 so the
            # mutation (by-name resolution) looks like a SUCCESSFUL git call — the test
            # notices via the log and the missing ToolPinError, not via an error code.
            'echo ran >> "$FAKE_GIT_LOG"\n'
            'exit 0\n')

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="factory-28nn-git-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        # Resolve the REAL git before any PATH tampering, and pin it by content.
        self.real_git = os.path.realpath(shutil.which("git"))
        from lib.tool_pins import sha256_file
        self.real_sha = sha256_file(Path(self.real_git))
        self.pins = self.root / "tools.pins.yaml"
        # The proof-satisfying fake, planted in its own directory.
        self.fake_dir = self.root / "fakebin"
        self.fake_dir.mkdir()
        self.fake_log = self.root / "fake-git-ran"
        stub = self.fake_dir / "git"
        stub.write_text(self.FAKE, encoding="utf-8")
        stub.chmod(0o755)
        # Environment: deterministic pins file, NO dev/test opt-in, PATH under control.
        self._saved = {k: os.environ.get(k)
                       for k in ("PATH", "FACTORY_TOOL_PINS", "FACTORY_ALLOW_UNPINNED_TOOLS",
                                 "FAKE_GIT_LOG")}
        self.addCleanup(self._restore_env)
        os.environ["FACTORY_TOOL_PINS"] = str(self.pins)
        os.environ.pop("FACTORY_ALLOW_UNPINNED_TOOLS", None)
        os.environ["FAKE_GIT_LOG"] = str(self.fake_log)

    def _restore_env(self):
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _plant_fake_first_on_path(self):
        os.environ["PATH"] = f"{self.fake_dir}{os.pathsep}{self._saved['PATH']}"

    def _write_pins(self, body):
        self.pins.write_text(body, encoding="utf-8")

    def test_a_path_planted_fake_git_is_refused_before_it_executes(self):
        """THE FILED HOLE, CLOSED: with only the real git's content pinned (no `path` pin,
        so resolution still follows PATH order), the planted fake is resolved, fails the
        hash check, and is refused — never executed."""
        self._write_pins(f"git:\n  sha256: {self.real_sha}\n")
        self._plant_fake_first_on_path()
        with self.assertRaises(ToolPinError) as raised:
            factory_cli._run_git(["status", "--porcelain"], self.root)
        self.assertIn("git", str(raised.exception))
        self.assertFalse(self.fake_log.exists(),
                         "the unauthenticated git must be refused BEFORE it executes")

    def test_a_full_pin_bypasses_the_planted_fake_and_runs_the_real_git(self):
        """The positive direction: with `path` + `sha256` pinned, the configured path wins
        over PATH order, so the planted fake is not even resolved and the REAL git runs."""
        self._write_pins(f"git:\n  path: {self.real_git}\n  sha256: {self.real_sha}\n")
        self._plant_fake_first_on_path()
        res = factory_cli._run_git(["--version"], self.root)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("git version", res.stdout)
        self.assertFalse(self.fake_log.exists(),
                         "the PATH-planted fake must not execute even on the success path")

    def test_an_unpinned_git_fails_closed(self):
        """The fail-closed composition for git itself: no pin anywhere and no dev opt-in,
        so even the REAL git is refused rather than resolved by PATH order."""
        self._write_pins("")  # no git entry anywhere
        with self.assertRaises(ToolPinError):
            factory_cli._run_git(["--version"], self.root)


@unittest.skipUnless(_RUNNABLE_BWRAP, _NEEDS_BWRAP)
class TestDispatcherBudget(unittest.TestCase):
    """budget.max_minutes is enforced by the dispatcher, not decorative (SF-06)."""

    def test_hung_engine_is_killed_at_the_station_budget(self):
        """A hung engine dies at the declared budget and the station fails.

        Without enforcement this test would sit for the stub's full 60 s and then report a
        clean zero-finding run — the failure mode the audit observed with a stale auth key.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = Path(tmpdir)
            (sandbox / "agents" / "hung").mkdir(parents=True)
            (sandbox / "agents" / "hung" / "agent.yaml").write_text(
                "name: hung\n"
                "class: observer\n"
                "containment: t0-readonly\n"
                "short_circuit_empty: false\n"
                "budget: {max_minutes: 0.25}\n",  # 15 s: headroom so pre-pass + sandbox bind setup finishes before the engine step
                encoding="utf-8",
            )
            # agents-r2ne census: a FACTORY-runtime tree, not a station-script fixture - the
            # copies are the dispatcher's shell adapter plus the egress-wrap runtime, not a
            # station script's dependencies, so tests/sandbox_fixtures.py:copy_station_script
            # (which derives ONE station script's Python import closure) does not apply here.
            (sandbox / "lib" / "adapters").mkdir(parents=True)
            adapter = sandbox / "lib" / "adapters" / "pi.sh"
            shutil.copyfile(FACTORY_ROOT / "lib" / "adapters" / "pi.sh", adapter)
            adapter.chmod(adapter.stat().st_mode | stat.S_IEXEC)
            # agents-2x6: a sandboxed engine wraps behind lib/net_forward.py from
            # FACTORY_ROOT, so the temp factory needs it or the adapter dies instantly.
            shutil.copyfile(FACTORY_ROOT / "lib" / "net_forward.py",
                            sandbox / "lib" / "net_forward.py")
            target = sandbox / "target"
            target.mkdir()
            bindir = sandbox / "bin"
            bindir.mkdir()
            stub = bindir / "pi"
            stub.write_text("#!/usr/bin/env bash\nsleep 60\n", encoding="utf-8")
            stub.chmod(stub.stat().st_mode | stat.S_IEXEC)

            env = dict(os.environ)
            env["PATH"] = f"{bindir}{os.pathsep}{env['PATH']}"
            started = time.monotonic()
            with mock.patch.object(factory_cli, "FACTORY_ROOT", sandbox), \
                 mock.patch.dict(os.environ, env, clear=True):
                with self.assertRaises(factory_cli.StationTimeout) as ctx:
                    factory_cli.run_agent("hung", str(target), engine_arg="pi")
            elapsed = time.monotonic() - started
            self.assertIn("engine 'pi'", str(ctx.exception))
            self.assertIn("station budget", str(ctx.exception))
            self.assertLess(elapsed, 30, "the hung engine was not stopped at its budget")


class TestDispatcherChildEnvironment(unittest.TestCase):
    """The engine and pre-pass children get an explicit, credential-free environment (SF-04)."""

    def _run_probe(self, extra_agent_yaml: str = "", containment: str = "t0-readonly", env_overrides: "typing.Optional[typing.Dict[str, str]]" = None, target_arg: "typing.Optional[str]" = None):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = Path(tmpdir)
            (sandbox / "agents" / "probe" / "scripts").mkdir(parents=True)
            (sandbox / "agents" / "probe" / "agent.yaml").write_text(
                "name: probe\n"
                "class: observer\n"
                f"containment: {containment}\n"
                "short_circuit_empty: false\n"
                + extra_agent_yaml +
                "budget: {max_minutes: 1}\n",
                encoding="utf-8",
            )
            prepass_log_name = "prepass-env.json"
            (sandbox / "agents" / "probe" / "scripts" / "prepass.py").write_text(
                "import json, os, sys\n"
                "args = sys.argv[1:]\n"
                "out = args[args.index('--output') + 1]\n"
                # The env log goes next to --output (the run directory): the OS sandbox
                # (agents-9n7) makes the factory root read-only for children.
                f"json.dump(dict(os.environ), open(os.path.join(os.path.dirname(out), '{prepass_log_name}'), 'w'))\n"
                "json.dump({'candidates': []}, open(out, 'w'))\n",
                encoding="utf-8",
            )

            # agents-r2ne census: a FACTORY-runtime tree, not a station-script fixture - the copy
            # set is the factory dispatcher's own runtime (shell adapters, the lib/sinks package
            # directory, budget.py and friends), which tests/sandbox_fixtures.py:copy_station_script
            # deliberately does not derive (it follows ONE station script's Python import closure).
            (sandbox / "lib" / "adapters").mkdir(parents=True)
            adapter = sandbox / "lib" / "adapters" / "pi.sh"
            shutil.copyfile(FACTORY_ROOT / "lib" / "adapters" / "pi.sh", adapter)
            adapter.chmod(adapter.stat().st_mode | stat.S_IEXEC)
            for module in ("findings.py", "redaction.py", "embargo.py", "tool_pins.py", "net_forward.py", "egress_proxy.py", "line_numbers.py"):
                shutil.copyfile(FACTORY_ROOT / "lib" / module, sandbox / "lib" / module)
            # Sink adapters (fleet-km8): findings.py delegates delivery to lib/sinks.
            shutil.copytree(FACTORY_ROOT / "lib" / "sinks", sandbox / "lib" / "sinks", dirs_exist_ok=True)
            shutil.copyfile(FACTORY_ROOT / "lib" / "budget.py", sandbox / "lib" / "budget.py")

            bindir = sandbox / "bin"
            bindir.mkdir()
            stub = bindir / "pi"
            stub.write_text(
                "#!/usr/bin/env bash\n"
                "cat >/dev/null\n"  # real pi.sh pipes its prompt under pipefail
                # The env dump goes to stdout (captured into the run directory's
                # model_output.txt): the sandbox leaves the engine nothing else writable.
                "echo ENGINE-ENV-BEGIN\n"
                "env\n"
                "echo ENGINE-ENV-END\n"
                "echo '{\"summary\":\"stub\",\"scanned_files\":0,\"findings\":[]}'\n",
                encoding="utf-8",
            )
            stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
            target = sandbox / "target"
            target.mkdir()

            overrides = {
                "PATH": f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}",
                "GITHUB_TOKEN": "ghs_ci_token",
                "GH_TOKEN": "ghs_ci_token",
                "AWS_SECRET_ACCESS_KEY": "aws-secret",
                "SSH_AUTH_SOCK": "/tmp/does-not-matter.sock",
                "ANTHROPIC_API_KEY": "sk-ant-ci",
                "GEMINI_API_KEY": "gem-ci",
                "PROJECT_UNRELATED_TOKEN": "unrelated",
            }
            if env_overrides:
                overrides.update(env_overrides)
            target_arg = target_arg or str(target)
            if target_arg != str(target):
                # agents-bp0: a named target manifest (e.g. one carrying the trusted
                # attestation) — resolve_target reads it from the mocked FACTORY_ROOT.
                (sandbox / "targets").mkdir(exist_ok=True)
                (sandbox / "targets" / f"{target_arg}.yaml").write_text(
                    f"name: {target_arg}\npath: {target}\nvisibility: private\n"
                    f"trusted: true\n", encoding="utf-8")
            with mock.patch.object(factory_cli, "FACTORY_ROOT", sandbox), \
                 mock.patch.dict(os.environ, overrides):
                factory_cli.run_agent("probe", target_arg, engine_arg="pi")

            runs = sorted((sandbox / "runs").glob("probe-*"))
            self.assertEqual(len(runs), 1, "expected exactly one run directory")
            prepass = json.loads((runs[0] / prepass_log_name).read_text(encoding="utf-8"))
            # The engine stub dumps `env` between markers in model_output.txt (KEY=value
            # lines, not JSON).
            model_output = (runs[0] / "model_output.txt").read_text(encoding="utf-8")
            env_block = model_output.split("ENGINE-ENV-BEGIN\n", 1)[1]
            env_block = env_block.split("ENGINE-ENV-END", 1)[0]
            engine = {}
            for line in env_block.splitlines():
                if "=" in line:
                    name, value = line.split("=", 1)
                    engine[name] = value
            return prepass, engine

    @mock.patch("lib.sandbox._probe_result", False)
    def test_agent_children_never_inherit_operator_credentials_unbrokered(self):
        # By setting FACTORY_ALLOW_UNSANDBOXED for a target that carries the trusted
        # attestation (agents-bp0), we force the pi run even without bubblewrap. This
        # allows us to prove SF-04 (no unrelated credentials leak) on any host, keeping
        # the non-brokered assertions meaningful everywhere.
        prepass, engine = self._run_probe(
            env_overrides={"FACTORY_ALLOW_UNSANDBOXED": "1"}, target_arg="trusted")
        for child, env in (("pre-pass", prepass), ("engine", engine)):
            for name in ("GITHUB_TOKEN", "GH_TOKEN", "AWS_SECRET_ACCESS_KEY",
                         "SSH_AUTH_SOCK", "PROJECT_UNRELATED_TOKEN"):
                with self.subTest(child=child, name=name):
                    self.assertNotIn(name, env)
        self.assertNotIn("ANTHROPIC_API_KEY", prepass)

        # agents-28nn round 6: the broker starts on EVERY path when the run holds a real
        # key, so an UNSANDBOXED engine is now brokered too — it carries a non-secret
        # placeholder + the broker's loopback base URL for the run's provider, and the
        # operator's raw keys never reach its environ (the leak the round closed; the
        # old assertion here — "unsandboxed gets the real key directly, no broker" —
        # encoded exactly that leak).
        self.assertTrue(engine["DEEPSEEK_API_KEY"].startswith(PLACEHOLDER_PREFIX),
                        engine.get("DEEPSEEK_API_KEY"))
        self.assertTrue(engine["DEEPSEEK_BASE_URL"].startswith("http://127.0.0.1:"),
                        engine.get("DEEPSEEK_BASE_URL"))
        # The harm the finding named: the raw keys must not appear anywhere in the
        # child's environment — neither under their own names nor any other.
        self.assertNotIn("ANTHROPIC_API_KEY", engine)
        self.assertNotIn("GEMINI_API_KEY", engine)
        self.assertNotIn("sk-ant-ci", engine.values())
        self.assertNotIn("gem-ci", engine.values())

    @unittest.skipUnless(sandbox_available(),
                         "the pi run is refused without bubblewrap, and brokering (agents-8h4) "
                         "applies only to a sandboxed engine")
    def test_agent_children_never_inherit_operator_credentials_brokered(self):
        prepass, engine = self._run_probe(env_overrides={"FACTORY_MODEL": "anthropic/claude-3-5-sonnet"})
        # agents-8h4 / agents-3z8: a SANDBOXED engine never carries the operator's real model key. The
        # dispatcher brokers it — the engine's environ (and so its /proc/self/environ, the leak
        # vector THREAT_MODEL §6.1 names) holds a non-secret placeholder + the localhost broker
        # base URL, and the real key is injected host-side only. Non-allowed credentials are stripped.
        self.assertTrue(engine["ANTHROPIC_API_KEY"].startswith(PLACEHOLDER_PREFIX),
                        engine.get("ANTHROPIC_API_KEY"))
        self.assertNotIn("GEMINI_API_KEY", engine)
        self.assertNotIn("sk-ant-ci", engine.values())
        self.assertNotIn("gem-ci", engine.values())
        self.assertTrue(engine["ANTHROPIC_BASE_URL"].startswith("http://127.0.0.1:"),
                        engine.get("ANTHROPIC_BASE_URL"))
        self.assertIn("PATH", engine)

    @unittest.skipUnless(_RUNNABLE_BWRAP, _NEEDS_BWRAP)
    def test_prepass_gets_github_only_when_the_agent_declares_gh(self):
        """issue-triage's pre-pass calls gh: it declares requires: [gh] at t1-fetch with network
        (a manifest listing gh without network is refused, agents-05h); nothing else gets it."""
        prepass, engine = self._run_probe("capabilities:\n  network: true\n  requires: [gh]\n",
                                          containment="t1-fetch")
        self.assertEqual(prepass["GH_TOKEN"], "ghs_ci_token")
        self.assertNotIn("GH_TOKEN", engine)

    @mock.patch("lib.sandbox._probe_result", False)
    def test_every_prepass_child_receives_the_egress_allowlist_proxy_unsandboxed(self):
        """agents-28nn round 7 (verdict P1): the allowlist proxy control belongs to the
        pre-pass OPERATION, not to the sandbox path. An UNSANDBOXED pre-pass must egress
        through the run's allowlist proxy on host loopback exactly like the sandboxed one
        does through the netns relay — and the operator's own proxy vars must NOT ride
        along (they are the uncontrolled egress this round removed). Mutation proof,
        both directions: deleting the dispatcher's unsandboxed proxy assignment turns
        this red (no HTTP_PROXY in the child's env); restoring the old proxied=True
        inheritance turns it red too (operator-proxy.invalid would survive)."""
        prepass, _engine = self._run_probe(
            env_overrides={"FACTORY_ALLOW_UNSANDBOXED": "1",
                           "HTTP_PROXY": "http://operator-proxy.invalid:3128",
                           "HTTPS_PROXY": "http://operator-proxy.invalid:3128"},
            target_arg="trusted")
        proxy = prepass.get("HTTP_PROXY", "")
        self.assertTrue(proxy.startswith("http://127.0.0.1:"),
                        f"the unsandboxed pre-pass must egress via the loopback allowlist "
                        f"proxy, got HTTP_PROXY={proxy!r}")
        self.assertNotIn("operator-proxy", proxy)
        self.assertEqual(prepass.get("HTTPS_PROXY"), proxy)
        self.assertEqual(prepass.get("NO_PROXY"), "localhost,127.0.0.1")
        self.assertNotIn("operator-proxy", json.dumps(prepass),
                         "the operator's own proxy config must not reach ANY pre-pass "
                         "child on either path")

    @unittest.skipUnless(_RUNNABLE_BWRAP, _NEEDS_BWRAP)
    def test_every_prepass_child_receives_the_egress_allowlist_proxy_sandboxed(self):
        """The confined direction of the same property: the sandboxed pre-pass dials the
        relay's fixed port, and the operator's proxy vars do not survive there either."""
        prepass, _engine = self._run_probe(
            env_overrides={"HTTP_PROXY": "http://operator-proxy.invalid:3128"})
        self.assertEqual(prepass.get("HTTP_PROXY"),
                         f"http://127.0.0.1:{factory_cli.EGRESS_PROXY_PORT}")
        self.assertEqual(prepass.get("HTTPS_PROXY"),
                         f"http://127.0.0.1:{factory_cli.EGRESS_PROXY_PORT}")
        self.assertEqual(prepass.get("NO_PROXY"), "localhost,127.0.0.1")
        self.assertNotIn("operator-proxy", json.dumps(prepass))

    @mock.patch("lib.sandbox._probe_result", False)
    def test_engine_children_never_inherit_the_operator_proxy_on_the_unsandboxed_path(self):
        """agents-28nn round 8 (verdict P1, the fourth inverted-polarity instance): the
        adapter env used to pass proxied=not engine_sandboxed(engine), forwarding the
        operator's HTTP_PROXY/HTTPS_PROXY/NO_PROXY to the UNSANDBOXED engine only — the
        less-confined path given more network configuration freedom than the confined
        one, the exact shape the rule on lib/sandbox.py's engine_sandboxed condemns.
        The engine's model traffic goes through the host-side credential broker or its
        own ~/.pi session, never an inherited operator proxy. Mutation proof, both
        directions: restoring proxied=not engine_sandboxed(engine) at the adapter env
        build turns this red (operator-proxy.invalid survives into the engine's env);
        the sandboxed sibling test above pins that the confined path never had them."""
        _prepass, engine = self._run_probe(
            env_overrides={"FACTORY_ALLOW_UNSANDBOXED": "1",
                           "HTTP_PROXY": "http://operator-proxy.invalid:3128",
                           "HTTPS_PROXY": "http://operator-proxy.invalid:3128"},
            target_arg="trusted")
        self.assertNotIn("operator-proxy", json.dumps(engine),
                         "the operator's own proxy config must not reach the engine child "
                         "on the less-confined path")


@unittest.skipUnless(_RUNNABLE_BWRAP, _NEEDS_BWRAP)
class TestDispatcherCandidateBinding(unittest.TestCase):
    """The dispatcher hands the scanner's candidates to the store, which binds model strings to
    them (agents-nha): an invented rule_id/path is stored as unclassified/unknown."""

    def test_model_strings_are_bound_to_the_scanner_candidates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = Path(tmpdir)
            (sandbox / "agents" / "probe" / "scripts").mkdir(parents=True)
            (sandbox / "agents" / "probe" / "agent.yaml").write_text(
                "name: probe\n"
                "class: observer\n"
                "containment: t0-readonly\n"
                "short_circuit_empty: false\n"
                "budget: {max_minutes: 1}\n",
                encoding="utf-8",
            )

            candidates_src = sandbox / "candidates-src.json"
            candidates_src.write_text(json.dumps({"candidates": [{
                "rule_id": "scanner-rule", "path": "src/a.js", "line_number": 1, "snippet": "x",
            }]}), encoding="utf-8")
            (sandbox / "agents" / "probe" / "scripts" / "prepass.py").write_text(
                "import json, sys\n"
                "args = sys.argv[1:]\n"
                f"payload = json.load(open(r'{candidates_src}'))\n"
                "json.dump(payload, open(args[args.index('--output') + 1], 'w'))\n",
                encoding="utf-8",
            )

            report_src = sandbox / "report-src.json"
            report_src.write_text(json.dumps({
                "summary": "stub", "scanned_files": 1,
                "findings": [{
                    "rule_id": "model-invented", "path": "elsewhere.js", "line_number": 1,
                    "snippet": "x", "severity": "low", "title": "Invented location",
                    "description": "d", "remediation": "r",
                }],
            }), encoding="utf-8")

            # agents-r2ne census: a FACTORY-runtime tree, not a station-script fixture - same
            # classification as the dispatcher-runtime copy blocks above: the set is the
            # factory's own runtime, which the shared builder deliberately does not derive.
            (sandbox / "lib" / "adapters").mkdir(parents=True)
            adapter = sandbox / "lib" / "adapters" / "pi.sh"
            shutil.copyfile(FACTORY_ROOT / "lib" / "adapters" / "pi.sh", adapter)
            adapter.chmod(adapter.stat().st_mode | stat.S_IEXEC)
            for module in ("findings.py", "redaction.py", "embargo.py", "tool_pins.py", "net_forward.py", "egress_proxy.py", "line_numbers.py"):
                shutil.copyfile(FACTORY_ROOT / "lib" / module, sandbox / "lib" / module)
            # Sink adapters (fleet-km8): findings.py delegates delivery to lib/sinks.
            shutil.copytree(FACTORY_ROOT / "lib" / "sinks", sandbox / "lib" / "sinks", dirs_exist_ok=True)
            shutil.copyfile(FACTORY_ROOT / "lib" / "budget.py", sandbox / "lib" / "budget.py")

            bindir = sandbox / "bin"
            bindir.mkdir()
            stub = bindir / "pi"
            _write_draining_report_stub(stub, report_src)
            target = sandbox / "target"
            target.mkdir()

            with mock.patch.object(factory_cli, "FACTORY_ROOT", sandbox), \
                 mock.patch.dict(os.environ,
                                 {"PATH": f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}"}):
                factory_cli.run_agent("probe", str(target), engine_arg="pi")

            store = json.loads((sandbox / "findings" / "target.json").read_text(encoding="utf-8"))
            record, = store["findings"].values()
            self.assertEqual(record["rule_id"], "unclassified")
            self.assertEqual(record["path"], "unknown")
            report_text = (sandbox / "findings" / "target-latest.md").read_text(encoding="utf-8")
            self.assertIn("unclassified", report_text)
            self.assertIn("unknown", report_text)


class TestTargetVisibility(unittest.TestCase):
    """A declared public issue target wins over general AGENTS.md beads instructions."""

    def test_explicit_public_issue_config_precedes_generic_beads_guidance(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "target"
            target.mkdir()
            (target / "AGENTS.md").write_text("use `bd` for all task tracking\n")
            (root / "targets").mkdir()
            (root / "targets" / "sandbox.yaml").write_text(
                f"name: sandbox\npath: {target}\nsink: github-issues\n"
                "repo: PaulKinlan/example\nvisibility: public\n")
            with mock.patch.object(factory_cli, "FACTORY_ROOT", root):
                _, path, cfg = factory_cli.resolve_target("sandbox")
                self.assertEqual(path, target)
                self.assertEqual(cfg["visibility"], "public")
                self.assertEqual(cfg["repo"], "PaulKinlan/example")
                self.assertEqual(factory_cli.detect_sink(path, cfg, None), "github-issues")

    def test_raw_target_has_no_publication_attestation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _, path, cfg = factory_cli.resolve_target(tmpdir)
            self.assertEqual(path, Path(tmpdir))
            self.assertNotIn("visibility", cfg)
            self.assertNotIn("repo", cfg)
            self.assertEqual(factory_cli.detect_sink(path, cfg, None), "file")

    def test_explicit_visibility_fills_a_raw_target_and_never_overrides_a_manifest(self):
        """agents-dpt: `--visibility` is the only declaration a raw --target path can carry.

        It fills a missing value, never overrides a manifest's own (so `targets/agents.yaml`
        behaviour is intact and a declared private target cannot be widened), and omitting it
        still leaves visibility undeclared — the fail-closed default.
        """
        raw = {"name": "raw", "path": "/tmp/raw", "sink": "beads"}
        self.assertNotIn("visibility", factory_cli.apply_explicit_visibility(raw, None))
        self.assertNotIn("visibility", factory_cli.apply_explicit_visibility(raw, "bogus"))
        self.assertEqual(factory_cli.apply_explicit_visibility(raw, "public")["visibility"],
                         "public")
        self.assertEqual(factory_cli.apply_explicit_visibility(raw, "private")["visibility"],
                         "private")
        self.assertNotIn("visibility", raw)  # the caller's own manifest cfg is not mutated
        declared = {"name": "agents", "path": "/tmp/agents", "sink": "beads",
                    "visibility": "private"}
        self.assertEqual(factory_cli.apply_explicit_visibility(declared, "public")["visibility"],
                         "private")


@unittest.skipUnless(_RUNNABLE_BWRAP, _NEEDS_BWRAP)
class TestRawTargetVisibilityDispatch(unittest.TestCase):
    """agents-dpt: `--visibility` is what carries an explicit declaration through a RAW
    `--target` path into the findings dispatch, so the audit can file what it finds.

    Without it there is no manifest to read, lib/embargo.py fail-closes and every
    high/critical finding stays local — the self-audit's `embargoed 17, published 0`.
    """

    def _run_probe(self, visibility_arg):
        """Run one probe station against a raw target path with the beads sink in a fresh
        sandbox; return the (store records, recorded bd calls) it produced."""
        temporary = tempfile.TemporaryDirectory(prefix="factory-auditvis-")
        self.addCleanup(temporary.cleanup)
        sandbox = Path(temporary.name)

        (sandbox / "agents" / "probe" / "scripts").mkdir(parents=True)
        (sandbox / "agents" / "probe" / "agent.yaml").write_text(
            "name: probe\n"
            "class: observer\n"
            "containment: t0-readonly\n"
            "short_circuit_empty: false\n"
            "budget: {max_minutes: 1}\n",
            encoding="utf-8",
        )

        report_src = sandbox / "report-src.json"
        report_src.write_text(json.dumps({
            "summary": "stub", "scanned_files": 1,
            "findings": [{
                "rule_id": "raw-visibility-probe", "path": "src/a.py", "line_number": 1,
                "snippet": "x", "severity": "high", "title": "High finding",
                "description": "d", "remediation": "r",
            }],
        }), encoding="utf-8")

        # agents-r2ne census: a FACTORY-runtime tree, not a station-script fixture - same
        # classification as the dispatcher-runtime copy blocks above: the set is the
        # factory's own runtime, which the shared builder deliberately does not derive.
        (sandbox / "lib" / "adapters").mkdir(parents=True)
        adapter = sandbox / "lib" / "adapters" / "pi.sh"
        shutil.copyfile(FACTORY_ROOT / "lib" / "adapters" / "pi.sh", adapter)
        adapter.chmod(adapter.stat().st_mode | stat.S_IEXEC)
        for module in ("findings.py", "redaction.py", "embargo.py", "tool_pins.py",
                       "net_forward.py", "egress_proxy.py", "line_numbers.py"):
            shutil.copyfile(FACTORY_ROOT / "lib" / module, sandbox / "lib" / module)
        # Sink adapters (fleet-km8): findings.py delegates delivery to lib/sinks.
        shutil.copytree(FACTORY_ROOT / "lib" / "sinks", sandbox / "lib" / "sinks",
                        dirs_exist_ok=True)
        shutil.copyfile(FACTORY_ROOT / "lib" / "budget.py", sandbox / "lib" / "budget.py")

        bindir = sandbox / "bin"
        bindir.mkdir()
        _write_draining_report_stub(bindir / "pi", report_src)

        # A stub `bd` records every call beside itself (no env plumbing needed) and answers
        # `list` (dedupe) and `create` (filing).
        calls = bindir / "bd-calls.jsonl"
        bd_stub = bindir / "bd"
        bd_stub.write_text(
            f"#!{sys.executable}\n"
            "import json, sys\n"
            "from pathlib import Path\n"
            "args = sys.argv[1:]\n"
            "log = Path(sys.argv[0]).parent / 'bd-calls.jsonl'\n"
            "with log.open('a', encoding='utf-8') as fh:\n"
            "    fh.write(json.dumps(args) + '\\n')\n"
            "if args[0] == 'list':\n"
            "    print('[]')\n"
            "elif args[0] == 'create':\n"
            "    print(json.dumps({'id': 'probe-1', 'status': 'open'}))\n"
            "else:\n"
            "    sys.exit(9)\n",
            encoding="utf-8",
        )
        bd_stub.chmod(0o755)

        target = sandbox / "target"
        (target / ".beads").mkdir(parents=True)

        # The stub bd is unpinned by construction, so this test declares a stub-tool
        # environment: no host pin file (FACTORY_TOOL_PINS), plus the same dev/test opt-in
        # tests/test_sinks.py gives its recorder (agents-7bj). Both the parent's PATH rebuild
        # and the findings child resolve bd from PATH under those rules.
        with mock.patch.object(factory_cli, "FACTORY_ROOT", sandbox), \
             mock.patch.dict(os.environ,
                             {"PATH": f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}",
                              "FACTORY_TOOL_PINS": str(sandbox / "no-such-pins.yaml")}), \
             mock.patch.object(factory_cli, "child_environment",
                               _unpinned_stub_child_environment):
            factory_cli.run_agent("probe", str(target), engine_arg="pi",
                                  explicit_sink="beads", visibility_arg=visibility_arg)

        store = json.loads((sandbox / "findings" / "target.json").read_text(encoding="utf-8"))
        recorded = [json.loads(line) for line in calls.read_text(encoding="utf-8").splitlines()] \
            if calls.exists() else []
        return list(store["findings"].values()), recorded

    def test_raw_target_files_with_explicit_visibility_and_embargoes_without_it(self):
        _, filed = self._run_probe("public")
        self.assertTrue([call for call in filed if call[0] == "create"],
                        f"explicit --visibility public must reach the beads sink: {filed}")

        records, held = self._run_probe(None)
        self.assertEqual([record["rule_id"] for record in records], ["raw-visibility-probe"])
        self.assertEqual([call for call in held if call[0] == "create"], [],
                         "missing visibility must still embargo high findings from beads")


@unittest.skipUnless(_RUNNABLE_BWRAP, _NEEDS_BWRAP)
class TestPerStationEngine(unittest.TestCase):
    """A line can pin a station's engine, so verification need not share discovery's family."""

    def test_station_engines_override_the_line_engine(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sandbox = Path(tmpdir)
            (sandbox / "agents" / "probe").mkdir(parents=True)
            (sandbox / "agents" / "probe" / "agent.yaml").write_text(
                "name: probe\n"
                "class: observer\n"
                "containment: t0-readonly\n"
                "short_circuit_empty: false\n"
                "budget: {max_minutes: 1}\n",
                encoding="utf-8",
            )
            report_src = sandbox / "report-src.json"
            report_src.write_text(json.dumps({"summary": "stub", "scanned_files": 1,
                                              "findings": []}), encoding="utf-8")
            (sandbox / "lines").mkdir()
            (sandbox / "lines" / "testline.yaml").write_text(
                "name: testline\n"
                "stations:\n"
                "  - probe\n"
                "station_engines:\n"
                "  probe: pi\n",
                encoding="utf-8",
            )
            # agents-r2ne census: a FACTORY-runtime tree, not a station-script fixture - same
            # classification as the dispatcher-runtime copy blocks above: the set is the
            # factory's own runtime, which the shared builder deliberately does not derive.
            (sandbox / "lib" / "adapters").mkdir(parents=True)
            for engine in ("pi", "claude"):
                adapter = sandbox / "lib" / "adapters" / f"{engine}.sh"
                shutil.copyfile(FACTORY_ROOT / "lib" / "adapters" / f"{engine}.sh", adapter)
                adapter.chmod(adapter.stat().st_mode | stat.S_IEXEC)
            for module in ("findings.py", "redaction.py", "embargo.py", "tool_pins.py", "net_forward.py", "egress_proxy.py", "line_numbers.py"):
                shutil.copyfile(FACTORY_ROOT / "lib" / module, sandbox / "lib" / module)
            # Sink adapters (fleet-km8): findings.py delegates delivery to lib/sinks.
            shutil.copytree(FACTORY_ROOT / "lib" / "sinks", sandbox / "lib" / "sinks", dirs_exist_ok=True)
            shutil.copyfile(FACTORY_ROOT / "lib" / "budget.py", sandbox / "lib" / "budget.py")

            bindir = sandbox / "bin"
            bindir.mkdir()
            for engine in ("pi", "claude"):
                stub = bindir / engine
                # Marker reaches model_output.txt; sandboxed engine cannot write
                # elsewhere in the factory root. Shared helper also drains stdin.
                _write_draining_report_stub(stub, report_src, marker=f"{engine.upper()}-RAN")
            target = sandbox / "target"
            target.mkdir()

            with mock.patch.object(factory_cli, "FACTORY_ROOT", sandbox), \
                 mock.patch.dict(os.environ, {
                     "PATH": f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}",
                     "ANTHROPIC_API_KEY": "stub-key",
                 }):
                factory_cli.run_line("testline", str(target), engine_arg="claude")

            outputs = "\n".join(
                (run / "model_output.txt").read_text(encoding="utf-8")
                for run in sorted((sandbox / "runs").glob("probe-*")))
            self.assertIn("PI-RAN", outputs, "the station's pinned engine must run")
            self.assertNotIn("CLAUDE-RAN", outputs,
                             "the line engine must not run for a station that pins another")


class TestEngineAdapterAuth(unittest.TestCase):
    """Engine adapters must dispatch on the caller's existing session auth, and must never
    report a run that did not happen. Adapters are exercised against a stub engine binary,
    so these are deterministic — no model call, no API key."""

    def _stub_engine(self, tmp: Path) -> Path:
        """A fake `claude` that records the environment it was launched with."""
        bindir = tmp / "bin"
        bindir.mkdir(exist_ok=True)
        stub = bindir / "claude"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "cat >/dev/null\n"  # claude.sh uses pipefail around its prompt pipe
            "printf '%s\\n' \"$*\" > \"$FAKE_PROMPT_LOG\"\n"
            "env > \"$FAKE_ENV_LOG\"\n"
            "echo '{\"summary\":\"stub\",\"scanned_files\":0,\"findings\":[]}'\n"
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        return bindir

    def _run_claude_adapter(self, tmp: Path, env_overrides: dict,
                            prompt: str = "prompt"):
        adapter = FACTORY_ROOT / "lib" / "adapters" / "claude.sh"
        run_dir = tmp / "run"
        target = tmp / "target"
        target.mkdir(exist_ok=True)
        env = dict(os.environ)
        env["HOME"] = str(tmp / "home")
        env["FAKE_PROMPT_LOG"] = str(tmp / "prompt.log")
        env["FAKE_ENV_LOG"] = str(tmp / "child-env.log")
        env.update(env_overrides)
        return subprocess.run(
            ["bash", str(adapter), "probe", str(target), str(tmp), str(run_dir)],
            input=prompt, capture_output=True, text=True, env=env, timeout=60,
        ), run_dir

    def test_canned_claude_report_drains_a_large_adapter_prompt(self):
        """Fail-on-revert: an unread pipe would make real claude.sh exit 1."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            bindir = self._stub_engine(tmp)
            res, run_dir = self._run_claude_adapter(tmp, {
                "PATH": f"{bindir}:{os.environ['PATH']}",
                "ANTHROPIC_API_KEY": "synthetic-test-key",
                # agents-28nn round 5: the adapter execs only this dispatcher-verified path.
                "FACTORY_ENGINE_BIN": str(bindir / "claude"),
            }, prompt="x" * 200000)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn('"summary":"stub"', (run_dir / "model_output.txt").read_text())

    def test_claude_prefers_session_and_scrubs_ambient_api_key(self):
        """A login on disk must win over a stale API key in the caller's environment."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            creds = tmp / "home" / ".claude" / ".credentials.json"
            creds.parent.mkdir(parents=True)
            creds.write_text("{\"stub\":true}")
            bindir = self._stub_engine(tmp)

            res, run_dir = self._run_claude_adapter(tmp, {
                "PATH": f"{bindir}:{os.environ['PATH']}",
                "ANTHROPIC_API_KEY": "sk-ant-stale-key",
                "FACTORY_ENGINE_BIN": str(bindir / "claude"),
            })

            self.assertEqual(res.returncode, 0, res.stderr)
            child_env = (tmp / "child-env.log").read_text()
            self.assertNotIn("ANTHROPIC_API_KEY=", child_env)
            self.assertTrue((run_dir / "model_output.txt").exists())

    def test_claude_keeps_api_key_without_a_session(self):
        """The CI plane authenticates by injected API key and has no login on disk."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            bindir = self._stub_engine(tmp)

            res, _ = self._run_claude_adapter(tmp, {
                "PATH": f"{bindir}:{os.environ['PATH']}",
                "ANTHROPIC_API_KEY": "sk-ant-ci-key",
                "FACTORY_ENGINE_BIN": str(bindir / "claude"),
            })

            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("ANTHROPIC_API_KEY=sk-ant-ci-key", (tmp / "child-env.log").read_text())

    def test_claude_fails_fast_with_no_credentials_at_all(self):
        """No login and no key is an error before any engine invocation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            bindir = self._stub_engine(tmp)

            res, run_dir = self._run_claude_adapter(tmp, {
                "PATH": f"{bindir}:{os.environ['PATH']}",
                "ANTHROPIC_API_KEY": "",
                "ANTHROPIC_AUTH_TOKEN": "",
            })

            self.assertEqual(res.returncode, 1)
            self.assertIn("no Claude credentials", res.stderr)
            self.assertFalse((tmp / "child-env.log").exists(), "engine must not be invoked")
            self.assertFalse((run_dir / "model_output.txt").exists())

    @unittest.skipIf(shutil.which("agentapi"), "agentapi installed; missing-binary path not reachable")
    def test_antigravity_fails_loudly_when_agentapi_is_missing(self):
        """A missing engine must abort the run, never write a placeholder the dispatcher
        would then store as a clean, zero-finding report. agents-28nn round 5: "missing"
        now surfaces as FACTORY_ENGINE_BIN unset — the dispatcher could not resolve and
        pin-verify agentapi — and the adapter REFUSES (exit 3) rather than falling back
        to a by-name PATH lookup, which is the exfiltration path this round closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            run_dir = tmp / "run"
            adapter = FACTORY_ROOT / "lib" / "adapters" / "antigravity.sh"
            env = dict(os.environ)
            env["PATH"] = "/usr/bin:/bin"
            env.pop("FACTORY_ENGINE_BIN", None)

            res = subprocess.run(
                ["bash", str(adapter), "probe", str(tmp), str(tmp), str(run_dir)],
                input="prompt", capture_output=True, text=True, env=env, timeout=60,
            )

            self.assertEqual(res.returncode, 3)
            self.assertIn("FACTORY_ENGINE_BIN", res.stderr)
            self.assertFalse((run_dir / "model_output.txt").exists())


class TestModernWebGuidanceCoverage(unittest.TestCase):
    """Ensure scan_modern_web.py covers 100% of the 146 official modern-web-guidance guides."""

    def test_all_146_guides_are_mapped_to_rules(self):
        scanner_path = FACTORY_ROOT / "agents" / "modern-web" / "scripts" / "scan_modern_web.py"
        s_loader = importlib.machinery.SourceFileLoader("scan_modern_web", str(scanner_path))
        s_spec = importlib.util.spec_from_loader("scan_modern_web", s_loader)
        scanner = importlib.util.module_from_spec(s_spec)
        s_loader.exec_module(scanner)

        catalog = scanner.load_guides_catalog()
        self.assertGreaterEqual(len(catalog), 146)

        covered = set()
        for rule in scanner.RULES:
            covered.update(rule.get("guide_ids", []))

        missing = set(catalog.keys()) - covered
        self.assertEqual(missing, set(), f"Unmapped modern-web-guidance guides: {missing}")


class TestAgentIntegrationInstructions(unittest.TestCase):
    """Ensure --agent flag and integrate command produce actionable agent instructions."""

    def test_factory_agent_flag(self):
        res = subprocess.run(
            [sys.executable, str(FACTORY_ROOT / "factory"), "--agent"],
            capture_output=True, text=True, timeout=10
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("# The Software Factory — Integration & Automation Guide", res.stdout)
        self.assertIn("## 1. CI/CD Plane: GitHub Actions", res.stdout)
        self.assertIn("paulkinlan/agents/.github/actions/factory", res.stdout)

    def test_factory_integrate_subcommand(self):
        res = subprocess.run(
            [sys.executable, str(FACTORY_ROOT / "factory"), "integrate", "--section", "github-actions"],
            capture_output=True, text=True, timeout=10
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("## 1. CI/CD Plane: GitHub Actions", res.stdout)
        self.assertIn("permissions:", res.stdout)
        self.assertNotIn("## 3. Target Enrolment Plane", res.stdout)


if __name__ == "__main__":
    unittest.main()


