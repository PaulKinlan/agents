#!/usr/bin/env python3
"""A sandboxed pi run on a host with NO provider key still reaches the model (agents-3y2/854).

Why this test exists
--------------------
The fleet's project VMs hold no model credential at all: the keys live in exe.dev's managed
BYOK endpoints and the sandboxed engine must reach them through the dispatcher's credential
broker (`lib/credential_broker.py`) plus a generated `models.json` in pi's agent directory
(`factory:_write_pi_models_json`). This is the ONLY way a sandboxed pi can authenticate --
the OS sandbox deliberately hides `~/.pi`.

Every existing unit test proved a PIECE of that path (the broker forwards keylessly, the
child env carries the placeholder, models.json is well-formed) but none drove the real
dispatcher end to end with an EMPTY host environment -- the fleet's actual condition. So a
revision that sandboxed pi but never registered the keyless provider (or never wrote
models.json) passed the whole suite and failed on every VM at 03:00 with pi's opaque
"No API key found for the selected model."

This test drives `factory.run_agent` with a stub `pi` that FAILS unless it sees the full
keyless wire-up, with every model key removed from the environment. It pins the invariant:
**a sandboxed pi run authenticates with zero host credentials, via the broker + models.json.**
"""

import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
os.environ.setdefault("FACTORY_ALLOW_UNPINNED_TOOLS", "1")  # stub tools are unpinned on purpose
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from lib.sandbox import sandbox_available  # noqa: E402

_RUNNABLE_BWRAP = sandbox_available()
_NEEDS_BWRAP = "needs a host where bubblewrap actually runs"

_loader = importlib.machinery.SourceFileLoader("factory_cli_keyless", str(ROOT / "factory"))
_spec = importlib.util.spec_from_loader("factory_cli_keyless", _loader)
factory_cli = importlib.util.module_from_spec(_spec)
_loader.exec_module(factory_cli)

LIB_MODULES = ("findings.py", "redaction.py", "embargo.py", "budget.py", "child_env.py",
               "credential_broker.py", "net_forward.py", "egress_proxy.py",
               "report_schema.py", "containment.py", "sandbox.py", "retention.py",
               "tool_pins.py", "yaml_mini.py")

# Every variable that could carry a real model credential on the host (lib/child_env.py
# plus the broker's secret vars). The fleet has none of them set.
MODEL_KEY_VARS = (
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
    "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "DEEPSEEK_API_KEY",
    "OPENROUTER_API_KEY", "KIMI_API_KEY", "ZAI_API_KEY", "QWEN_API_KEY",
    "DEEPSEEK_BASE_URL", "KIMI_BASE_URL", "ZAI_BASE_URL", "QWEN_BASE_URL",
    "OPENAI_BASE_URL", "ANTHROPIC_BASE_URL",
)

REPORT = json.dumps({"summary": "stub", "scanned_files": 1, "findings": []})


class KeylessSandbox:
    """A factory root whose stub `pi` fails loudly unless the keyless wire-up is present."""

    def __init__(self, root: Path):
        self.root = root
        self.target = root / "target"
        self.target.mkdir()
        (root / "lib" / "adapters").mkdir(parents=True)
        adapter = root / "lib" / "adapters" / "pi.sh"
        shutil.copyfile(ROOT / "lib" / "adapters" / "pi.sh", adapter)
        adapter.chmod(adapter.stat().st_mode | stat.S_IEXEC)
        for module in LIB_MODULES:
            src = ROOT / "lib" / module
            if src.exists():
                shutil.copyfile(src, root / "lib" / module)
        sinks = ROOT / "lib" / "sinks"
        if sinks.is_dir():
            shutil.copytree(sinks, root / "lib" / "sinks", dirs_exist_ok=True)
        (root / "outputs").mkdir()
        (root / "lines").mkdir()
        self.bin = root / "bin"
        self.bin.mkdir()
        self.output = root / "outputs" / "probe.txt"
        self.output.write_text(REPORT, encoding="utf-8")
        stub = self.bin / "pi"
        # The stub is a precondition assertion, not a canned printer: if the sandboxed engine
        # did not receive the keyless broker channel + models.json, it exits 7 so the adapter
        # reports "engine 'pi' exited 1" and the run fails -- exactly the production symptom.
        stub.write_text(
            "#!/usr/bin/env bash\n"
            "cat >/dev/null\n"
            "fail() { echo \"[keyless-stub] $*\" >&2; exit 7; }\n"
            "[ -n \"${DEEPSEEK_BASE_URL:-}\" ] || fail 'DEEPSEEK_BASE_URL not set by the broker'\n"
            "case \"$DEEPSEEK_BASE_URL\" in *'/proxy/deepseek'*) ;; *) fail \"base URL is not the broker: $DEEPSEEK_BASE_URL\";; esac\n"
            "[ \"${DEEPSEEK_API_KEY:-}\" = 'factory-broker-placeholder' ] || fail 'DEEPSEEK_API_KEY is not the broker placeholder'\n"
            "[ -n \"${PI_CODING_AGENT_DIR:-}\" ] || fail 'PI_CODING_AGENT_DIR not set'\n"
            "[ -s \"$PI_CODING_AGENT_DIR/models.json\" ] || fail 'models.json was not written for pi'\n"
            "grep -q '\"deepseek\"' \"$PI_CODING_AGENT_DIR/models.json\" || fail 'models.json has no deepseek provider'\n"
            "case \"${ANTHROPIC_API_KEY:-}\" in *sk-*) fail 'a real Anthropic key reached the sandbox';; esac\n"
            f"cat '{self.output}'\n",
            encoding="utf-8")
        stub.chmod(0o755)
        agent = root / "agents" / "probe"
        agent.mkdir(parents=True)
        (agent / "agent.yaml").write_text(
            "name: probe\nclass: observer\ncontainment: t0-readonly\n"
            "budget: {max_minutes: 1}\n", encoding="utf-8")

    @contextlib.contextmanager
    def patched(self):
        env = {"PATH": f"{self.bin}{os.pathsep}/usr/bin:/bin", "HOME": str(self.root / "home")}
        Path(env["HOME"]).mkdir(exist_ok=True)
        with mock.patch.object(factory_cli, "FACTORY_ROOT", self.root), \
             mock.patch.dict(os.environ, env):
            # The fleet holds no credential: remove every model key and base URL for the run.
            for var in MODEL_KEY_VARS:
                os.environ.pop(var, None)
            yield

    def run(self):
        out = io.StringIO()
        with self.patched(), contextlib.redirect_stdout(out):
            result = factory_cli.run_agent("probe", str(self.target), engine_arg="pi",
                                           explicit_sink="file")
        return result, out.getvalue()

    def newest_run_dir(self) -> Path:
        runs = sorted((self.root / "runs").glob("probe-*"), key=lambda p: p.stat().st_mtime)
        return runs[-1]


@unittest.skipUnless(_RUNNABLE_BWRAP, _NEEDS_BWRAP)
class TestSandboxedPiKeyless(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="factory-keyless-")
        self.addCleanup(tmp.cleanup)
        self.box = KeylessSandbox(Path(tmp.name).resolve())

    def test_sandboxed_pi_authenticates_with_no_host_credentials(self):
        result, output = self.box.run()
        self.assertIn("keyless broker", output,
                      "the adapter must report the keyless broker channel")
        # The stub asserts the full wire-up (broker base URL + placeholder + models.json);
        # a missing piece exits 7, which surfaces here as a station failure.
        self.assertIsNotNone(result)

    def test_broker_enforcement_is_recorded_not_left_as_env_credentials(self):
        _, _ = self.box.run()
        policy = json.loads((self.box.newest_run_dir() / "policy.json").read_text())
        self.assertNotIn("env-credentials", policy.get("not_enforced", []),
                         "once the broker swapped the engine env, env-credentials is enforced")
        broker = policy.get("granted", {}).get("credential_broker", {})
        self.assertIn("deepseek", broker.get("providers", []),
                      "policy.json must record the brokered provider")
        self.assertEqual(broker.get("enforced"),
                         "engine env contains placeholders only")


if __name__ == "__main__":
    unittest.main()
