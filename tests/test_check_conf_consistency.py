"""agents-ia3p: the tracked gate command and the deployed CI invocation must not drift.

THE DEFECT THIS GUARDS AGAINST, IN FULL: the `-t .` that makes `unittest discover` import
`tests/__init__.py` - and therefore run the hermetic declaration - lived ONLY in an
untracked per-VM `~/.fleet/check.conf`. `.github/workflows/ci.yml` is version-controlled
and IS the deployed invocation, and it ran package-blind discovery. So the file that
survived a rebuild had the defect and the file that did not had the fix. The knowledge was
already tracked (docs/proposals/hermetic-test-environment-declaration.md:60 describes this
exact defect, :64 gives the corrected command) and the behaviour was not.

A DOCUMENT IS NOT A TEST, which is the reason these assertions exist: the proposal told us
the right answer while the system ran a different one for as long as it took a cross-VM
report to notice. Changing a file fixes today; asserting the relationship is what stops the
next edit from separating them.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECK_CONF = ROOT / "tools" / "check.conf"
CI = ROOT / ".github" / "workflows" / "ci.yml"


def _tracked_fields() -> dict:
    """Read tools/check.conf the way the shell reads it, without executing it.

    Deliberately a simple parse of KEY="value" lines rather than `source`: this test runs
    in the same suite the config describes, and a config that a test has to EXECUTE to
    read is a config whose failure mode is a test that never runs.
    """
    fields = {}
    for line in CHECK_CONF.read_text(encoding="utf-8").splitlines():
        m = re.match(r'^([A-Z_]+)="(.*)"\s*$', line.strip())
        if m:
            fields[m.group(1)] = m.group(2)
    return fields


def _discovery_commands() -> list:
    """Every `unittest discover` invocation in the deployed CI workflow."""
    out = []
    for line in CI.read_text(encoding="utf-8").splitlines():
        if "unittest discover" in line:
            out.append(line.strip())
    return out


class TestTrackedCheckConfig(unittest.TestCase):
    def test_the_tracked_config_exists_and_names_a_command(self):
        self.assertTrue(CHECK_CONF.is_file(),
                        "tools/check.conf must be TRACKED - it is the default a fresh VM "
                        "gets, and the config that survives a rebuild")
        fields = _tracked_fields()
        self.assertIn("CHECK_CMD", fields, "the tracked config must name the full gate")
        self.assertTrue(fields["CHECK_CMD"].strip(), "CHECK_CMD must not be empty")
        self.assertIn("CHECK_FAST_CMD", fields, "the tracked config must name the fast gate")

    def test_the_tracked_full_gate_is_package_aware(self):
        """The load-bearing flag. Without it tests/__init__.py never runs."""
        cmd = _tracked_fields()["CHECK_CMD"]
        self.assertIn("discover", cmd, f"CHECK_CMD is not a discovery command: {cmd!r}")
        self.assertRegex(cmd, r"(^|\s)-t\s+\.",
                         f"CHECK_CMD must carry `-t .` or the hermetic declaration never "
                         f"runs: {cmd!r}")

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
    """The resolver must REFUSE rather than silently substitute a default."""

    def test_a_missing_tracked_config_is_an_error_not_a_fallback(self):
        """agents-04ag: when the TRACKED config (tools/check.conf) is absent, check-cmd.sh
        must exit 2 loudly and refuse to invent a fallback command."""
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
            self.assertEqual(res.returncode, 2,
                             f"missing TRACKED config must exit 2: {res.stderr}")
            self.assertIn("the TRACKED gate config is missing", res.stderr,
                          "the refusal must name the missing tracked file")

    def test_a_missing_override_is_tolerated_and_uses_tracked_defaults(self):
        """A missing per-VM override is optional; check-cmd.sh must tolerate its absence
        and resolve values from the tracked configuration."""
        import subprocess, tempfile, os
        resolver = ROOT / "tools" / "check-cmd.sh"
        self.assertTrue(resolver.is_file(), "tools/check-cmd.sh must exist")
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env["FLEET_CHECK_CONF"] = os.path.join(tmp, "does-not-exist.conf")
            res = subprocess.run(["bash", str(resolver), "CHECK_CMD"],
                                 capture_output=True, text=True, timeout=30, env=env)
            self.assertEqual(res.returncode, 0,
                             f"a missing OVERRIDE is fine (it is optional): {res.stderr}")
            self.assertIn("-t .", res.stdout,
                          "the resolved command must come from the tracked config")


if __name__ == "__main__":
    unittest.main()
