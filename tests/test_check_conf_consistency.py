"""agents-ia3p: assert the gate's command lives in a TRACKED file, and CI agrees with it.

WHY THIS FILE EXISTS: the -t . hermeticity fix lived ONLY in an untracked per-VM
check.conf while deployed CI ran package-blind discovery without -t ., bypassing
tests/__init__.py and failing to run the hermetic test environment declaration (P1).

This test proves:
1. tools/check.conf exists and defines the package-aware discovery command.
2. .github/workflows/ci.yml runs the exact same flags (the drift guard).
3. tools/check-cmd.sh resolves the tracked command as default and refuses on missing/empty config.
"""

from __future__ import annotations

import os
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CI_YML = ROOT / ".github" / "workflows" / "ci.yml"
TRACKED = ROOT / "tools" / "check.conf"


def _tracked_fields() -> dict:
    fields = {}
    for line in TRACKED.read_text(encoding="utf-8").splitlines():
        m = re.match(r'^([A-Z_]+)=(?:"(.*)"|(\S+))\s*$', line.strip())
        if m:
            fields[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
    return fields


def _discovery_commands() -> list[str]:
    """Every `unittest discover` invocation in the deployed CI workflow, regardless of interpreter variant."""
    commands = []
    for line in CI_YML.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if "unittest discover" in stripped:
            if stripped.startswith("run:"):
                stripped = stripped[4:].strip()
            commands.append(stripped)
    return commands


class TestTrackedCheckConfig(unittest.TestCase):
    """The acceptance: tools/check.conf is tracked and specifies package-aware discovery."""

    def test_tracked_config_file_exists(self):
        self.assertTrue(TRACKED.is_file(),
                        f"tracked gate config missing: {TRACKED} - a fresh VM gets no "
                        f"default without it, which was the original P1")

    def test_tracked_config_defines_the_hermetic_full_gate(self):
        fields = _tracked_fields()
        for required in ("CHECK_CMD", "CHECK_FAST_CMD", "CHECK_TIMEOUT", "CHECK_FAST_TIMEOUT"):
            self.assertIn(required, fields, f"missing required field: {required}")

        cmd = fields["CHECK_CMD"]
        self.assertIn("discover", cmd, f"CHECK_CMD is not a discovery command: {cmd!r}")
        self.assertRegex(cmd, r"(^|\s)-t\s+\.",
                         f"CHECK_CMD must carry `-t .` or the hermetic declaration never "
                         f"runs: {cmd!r}")

    def test_tracked_fields_parser_accepts_inner_quotes_and_unquoted_values(self):
        """The parser must accept escaped inner quotes (e.g. bash -c commands) and unquoted values."""
        sample = (
            'CHECK_CMD="bash -c \'echo \\"inner quotes\\" && python3 -m unittest discover -s tests -t . -v\'"\n'
            'CHECK_FAST_CMD="bash tools/fast-gate.sh"\n'
            'CHECK_TIMEOUT=2400\n'
            'CHECK_FAST_TIMEOUT=180\n'
        )
        fields = {}
        for line in sample.splitlines():
            m = re.match(r'^([A-Z_]+)=(?:"(.*)"|(\S+))\s*$', line.strip())
            if m:
                fields[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
        self.assertIn("CHECK_CMD", fields)
        self.assertIn('echo \\"inner quotes\\"', fields["CHECK_CMD"])
        self.assertEqual(fields["CHECK_TIMEOUT"], "2400")
        self.assertEqual(fields["CHECK_FAST_TIMEOUT"], "180")

    def test_every_discovery_in_ci_carries_the_same_top_level_flag(self):
        """EVERY invocation, not just the first - the second line initially lacked it."""
        commands = _discovery_commands()
        self.assertTrue(commands, "expected at least one discovery invocation in ci.yml")
        for cmd in commands:
            with self.subTest(command=cmd):
                self.assertRegex(cmd, r"(^|\s)-t\s+\.",
                                 f"ci.yml runs package-blind discovery, so the hermetic "
                                 f"declaration does not run there and CI's result is not "
                                 f"the result we measured: {cmd!r}")

    def test_ci_and_the_tracked_config_agree_on_the_hermeticity_flags(self):
        """The drift guard. A future edit to one without the other fails HERE.

        Both sides must be package-aware, and neither may acquire a discovery flag the
        other lacks. This is the assertion that makes the fix a property rather than an
        edit: it compares the two, so it fails whichever side changes alone.
        """
        tracked = _tracked_fields()["CHECK_CMD"]
        for cmd in _discovery_commands():
            for flag in ("-t .",):
                with self.subTest(command=cmd, flag=flag):
                    self.assertIn(flag, tracked,
                                  f"the tracked CHECK_CMD lost {flag!r}: {tracked!r}")
                    self.assertIn(flag, cmd,
                                  f"the CI invocation lost {flag!r}: {cmd!r}")


class TestConfigIsResolvedLoudly(unittest.TestCase):
    """The resolver must REFUSE rather than silently substitute a default (agents-5o5q, agents-g2n4)."""

    def test_missing_tracked_config_fails_loudly_naming_file(self):
        """Shape (a): a missing TRACKED config (tools/check.conf) must exit 2 loudly naming the file."""
        import subprocess, tempfile, os
        resolver = ROOT / "tools" / "check-cmd.sh"
        self.assertTrue(resolver.is_file(), "tools/check-cmd.sh must exist")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_tools = Path(tmp) / "tools"
            tmp_tools.mkdir(parents=True)
            symlink_resolver = tmp_tools / "check-cmd.sh"
            os.symlink(resolver, symlink_resolver)

            res = subprocess.run(["bash", str(symlink_resolver), "CHECK_CMD"],
                                 capture_output=True, text=True, timeout=30)
            self.assertEqual(res.returncode, 2, f"missing tracked config must exit 2: {res.stderr}")
            self.assertIn("the TRACKED gate config is missing", res.stderr,
                          "refusal must report missing tracked configuration")
            self.assertIn(str(tmp_tools / "check.conf"), res.stderr,
                          "refusal must name the exact missing file path (agents-g2n4)")

    def test_empty_or_unset_check_cmd_is_refused_loudly(self):
        """Shape (b): an override that unsets or empties CHECK_CMD must be refused loudly naming the file."""
        import subprocess, tempfile, os
        resolver = ROOT / "tools" / "check-cmd.sh"
        self.assertTrue(resolver.is_file(), "tools/check-cmd.sh must exist")
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "empty.conf"
            conf.write_text('CHECK_CMD=""\n', encoding="utf-8")
            env = dict(os.environ)
            env["FLEET_CHECK_CONF"] = str(conf)
            res = subprocess.run(["bash", str(resolver), "CHECK_CMD"],
                                 capture_output=True, text=True, timeout=30, env=env)
            self.assertNotEqual(res.returncode, 0, "empty CHECK_CMD must fail non-zero")
            self.assertIn("CHECK_CMD is unset or empty", res.stderr,
                          "refusal must report empty/unset CHECK_CMD")
            self.assertIn(str(conf), res.stderr,
                          "refusal must name the offending configuration file (agents-g2n4)")

    def test_syntax_error_in_config_fails_loudly_under_set_e(self):
        """Shape (c): syntax errors in sourced config must be fatal under set -e naming the file."""
        import subprocess, tempfile, os
        resolver = ROOT / "tools" / "check-cmd.sh"
        self.assertTrue(resolver.is_file(), "tools/check-cmd.sh must exist")
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "broken.conf"
            conf.write_text('CHECK_CMD="unterminated\n', encoding="utf-8")
            env = dict(os.environ)
            env["FLEET_CHECK_CONF"] = str(conf)
            res = subprocess.run(["bash", str(resolver), "CHECK_CMD"],
                                 capture_output=True, text=True, timeout=30, env=env)
            self.assertNotEqual(res.returncode, 0, "syntax error must fail non-zero")
            self.assertRegex(res.stderr, r"unexpected EOF|syntax error")
            self.assertIn(str(conf), res.stderr,
                          "refusal must name the syntax-error configuration file (agents-g2n4)")

    def test_missing_override_is_tolerated_and_uses_tracked_defaults(self):
        """A missing override file is tolerated and falls back to tracked defaults."""
        import subprocess, tempfile, os
        resolver = ROOT / "tools" / "check-cmd.sh"
        self.assertTrue(resolver.is_file(), "tools/check-cmd.sh must exist")
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env["FLEET_CHECK_CONF"] = os.path.join(tmp, "does-not-exist.conf")
            res = subprocess.run(["bash", str(resolver), "CHECK_CMD"],
                                 capture_output=True, text=True, timeout=30, env=env)
            self.assertEqual(res.returncode, 0, f"a missing OVERRIDE is fine: {res.stderr}")
            self.assertIn("-t .", res.stdout,
                          "the resolved command must come from the tracked config")


if __name__ == "__main__":
    unittest.main()
