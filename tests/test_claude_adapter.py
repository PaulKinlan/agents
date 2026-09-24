#!/usr/bin/env python3
"""claude.sh: the child process must not inherit variables that override the session.

Claude Code resolves auth and endpoint from a precedence list. The adapter used to remove
two of those variables, which left four more reaching the engine, so a shell export could
still divert a run away from the developer's signed-in session (agents-e3u).

The expected set is asserted explicitly *and* re-parsed out of the adapter, so removing a
variable from the adapter's list fails here too — this is the guard rail that stops the
documented invariant from drifting away from the code again.

The engine is a stub: these tests are deterministic and need no credentials, no login and
no model call.
"""

import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

FACTORY_ROOT = Path(__file__).resolve().parent.parent
ADAPTER = FACTORY_ROOT / "lib" / "adapters" / "claude.sh"

# Read out of the installed CLI (2.1.265) rather than from documentation. The two key
# variables were already scrubbed by the original fix; the rest are what agents-e3u caught
# surviving into the child.
EXPECTED_OVERRIDES = {
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_BEDROCK_BASE_URL",
    "ANTHROPIC_CUSTOM_HEADERS",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_GATEWAY",
    "AWS_BEARER_TOKEN_BEDROCK",
}

# Syntactically valid, never valid anywhere: these must not reach the engine.
JUNK = "sentinel-value-do-not-use"
NON_OVERRIDE = {"HTTP_PROXY": "http://proxy.invalid:3128", "LANG": "en_GB.UTF-8"}


def adapter_override_vars() -> set:
    """Parse SESSION_OVERRIDE_VARS out of the adapter so the list cannot drift silently."""
    source = ADAPTER.read_text(encoding="utf-8")
    block = re.search(r"SESSION_OVERRIDE_VARS=\((.*?)\)", source, re.S)
    if not block:
        raise AssertionError("SESSION_OVERRIDE_VARS not found in claude.sh")
    return set(re.findall(r"\b([A-Z][A-Z0-9_]{3,})\b", block.group(1)))


class ClaudeAdapterTestCase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="factory-claude-adapter-")
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.run_dir = self.tmp / "run"
        self.target = self.tmp / "target"
        self.target.mkdir()

        bindir = self.tmp / "bin"
        bindir.mkdir()
        self.env_dump = self.tmp / "child-env.txt"
        stub = bindir / "claude"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            'env > "$FAKE_ENV_DUMP"\n'
            "echo '{\"summary\":\"stub\",\"scanned_files\":0,\"findings\":[]}'\n"
        )
        stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
        self.bindir = bindir

    def sign_in(self):
        credentials = self.home / ".claude" / ".credentials.json"
        credentials.parent.mkdir(parents=True, exist_ok=True)
        credentials.write_text('{"stub": true}', encoding="utf-8")

    def run_adapter(self, extra_env):
        env = dict(os.environ)
        env.update({
            "HOME": str(self.home),
            "PATH": f"{self.bindir}:{os.environ['PATH']}",
            "FAKE_ENV_DUMP": str(self.env_dump),
        })
        # Drop anything the developer's own shell is carrying, so the only overrides present
        # are the ones this test sets on purpose.
        for name in EXPECTED_OVERRIDES:
            env.pop(name, None)
        env.update(extra_env)
        return subprocess.run(
            ["bash", str(ADAPTER), "probe", str(self.target), str(self.tmp), "prompt", str(self.run_dir)],
            capture_output=True, text=True, env=env, timeout=60,
        )

    def child_env(self) -> str:
        return self.env_dump.read_text(encoding="utf-8")

    def test_expected_set_matches_the_adapter(self):
        self.assertEqual(adapter_override_vars(), EXPECTED_OVERRIDES)

    def test_every_override_is_scrubbed_when_a_session_exists(self):
        self.sign_in()
        result = self.run_adapter({name: JUNK for name in EXPECTED_OVERRIDES})

        self.assertEqual(result.returncode, 0, result.stderr)
        child = self.child_env()
        for name in sorted(EXPECTED_OVERRIDES):
            with self.subTest(variable=name):
                self.assertNotIn(f"{name}=", child, f"{name} reached the engine")

    def test_scrubbing_is_reported_so_a_proxy_user_can_see_why(self):
        self.sign_in()
        result = self.run_adapter({name: JUNK for name in EXPECTED_OVERRIDES})

        self.assertIn("Scrubbed ambient auth overrides:", result.stdout)
        for name in ("ANTHROPIC_BASE_URL", "CLAUDE_CODE_USE_BEDROCK"):
            self.assertIn(name, result.stdout)

    def test_quiet_when_there_is_nothing_to_scrub(self):
        self.sign_in()
        result = self.run_adapter({})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("Scrubbed ambient auth overrides", result.stdout)

    def test_overrides_survive_without_a_session(self):
        """The CI plane authenticates through these; there is no login on the runner."""
        result = self.run_adapter({name: JUNK for name in EXPECTED_OVERRIDES})

        self.assertEqual(result.returncode, 0, result.stderr)
        child = self.child_env()
        for name in sorted(EXPECTED_OVERRIDES):
            with self.subTest(variable=name):
                self.assertIn(f"{name}={JUNK}", child)

    def test_unrelated_environment_is_untouched(self):
        """Subtraction, not a hermetic env: a proxy or locale the caller set still applies."""
        self.sign_in()
        result = self.run_adapter(dict(NON_OVERRIDE))

        self.assertEqual(result.returncode, 0, result.stderr)
        child = self.child_env()
        for name, value in NON_OVERRIDE.items():
            with self.subTest(variable=name):
                self.assertIn(f"{name}={value}", child)
        self.assertIn(f"HOME={self.home}", child)

    def test_no_session_and_no_key_fails_before_the_engine_runs(self):
        result = self.run_adapter({})

        self.assertEqual(result.returncode, 1)
        self.assertIn("no Claude credentials", result.stderr)
        self.assertFalse(self.env_dump.exists(), "engine must not be invoked")


if __name__ == "__main__":
    unittest.main()
