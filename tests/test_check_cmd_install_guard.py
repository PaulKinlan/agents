"""Install-time protection for an existing gate command (agents-i3kq)."""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class TestInstallExistingCommand(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name) / "home"
        self.home.mkdir()
        self.repo = Path(self.tmp.name) / "old-repo"
        (self.repo / "tools").mkdir(parents=True)
        self.conf = self.home / ".fleet" / "check.conf"
        self.conf.parent.mkdir()
        self.env = dict(os.environ, HOME=str(self.home))
        self.env.pop("FLEET_CHECK_CONF", None)
        self.resolver = ROOT / "tools" / "check-cmd.sh"

    def install(self, *args):
        return subprocess.run(["bash", str(self.resolver), "--install", "--global", *args],
                              cwd=ROOT, env=self.env, text=True, capture_output=True, timeout=30)

    def old(self, cmd):
        self.conf.write_text(f'# Written by tools/check-cmd.sh --install from tools/check.conf\n'
                             f'# Project: old-repo ({self.repo})\nCHECK_CMD="{cmd}"\n', encoding="utf-8")
        return self.conf.read_text(encoding="utf-8")

    def backups(self):
        return list(self.conf.parent.glob("check.conf.backup.*"))

    def test_missing_script_refused_without_replacement(self):
        old = self.old("bash tools/missing-gate.sh")
        res = self.install()
        self.assertNotEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("bash tools/missing-gate.sh", res.stderr)
        self.assertIn(str(self.repo / "tools" / "missing-gate.sh"), res.stderr)
        self.assertIn("--force", res.stderr)
        self.assertEqual(self.conf.read_text(), old)
        self.assertEqual(self.backups(), [])

    def test_force_proceeds_with_timestamped_backup(self):
        old = self.old("bash tools/missing-gate.sh")
        res = self.install("--force")
        self.assertEqual(res.returncode, 0, res.stderr)
        backups = self.backups()
        self.assertEqual(len(backups), 1)
        self.assertRegex(backups[0].name, r"check\.conf\.backup\.\d{8}T\d{15}\.\d+$")
        self.assertEqual(backups[0].read_text(), old)
        self.assertIn(str(backups[0]), res.stdout)
        self.assertNotEqual(self.conf.read_text(), old)

    def test_resolving_script_still_backed_up(self):
        (self.repo / "tools" / "gate.sh").write_text("echo gate\n")
        old = self.old("bash tools/gate.sh")
        res = self.install()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(len(self.backups()), 1)
        self.assertEqual(self.backups()[0].read_text(), old)

    def test_current_value_and_origin_printed(self):
        self.old("bash tools/gate.sh")
        (self.repo / "tools" / "gate.sh").write_text("echo gate\n")
        res = self.install()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("bash tools/gate.sh", res.stdout + res.stderr)
        self.assertIn(f"Project: old-repo ({self.repo})", res.stdout + res.stderr)
        self.assertIn("Written by tools/check-cmd.sh", res.stdout + res.stderr)

    def test_compound_command_warns_but_never_refuses(self):
        old = self.old("bash tools/missing-gate.sh | cat")
        res = self.install()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("cannot resolve", res.stderr)
        self.assertEqual(self.backups()[0].read_text(), old)

    def test_global_unknown_base_warns_instead_of_guessing_cwd(self):
        self.conf.write_text('# Project: old-repo\nCHECK_CMD="bash tools/missing-gate.sh"\n')
        res = self.install()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("no trustworthy repo base", res.stderr)
        self.assertEqual(len(self.backups()), 1)

    def test_missing_stamped_repo_does_not_use_installers_cwd(self):
        self.conf.write_text(f'# Project: gone ({self.repo / "deleted"})\n'
                             'CHECK_CMD="bash tools/missing-gate.sh"\n')
        res = self.install()
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("no trustworthy repo base", res.stderr)
        self.assertEqual(len(self.backups()), 1)

    def test_repo_local_destination_is_guarded_too(self):
        local = self.home / ".fleet" / f"{ROOT.name}-check.conf"
        local.write_text(f'# Project: old-repo ({self.repo})\nCHECK_CMD="bash tools/missing-gate.sh"\n')
        res = subprocess.run(["bash", str(self.resolver), "--install"], cwd=ROOT, env=self.env,
                             text=True, capture_output=True, timeout=30)
        self.assertNotEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("--force", res.stderr)

    def test_explicit_fleet_check_conf_wins_over_global(self):
        old_global = self.old("bash tools/gate.sh")
        custom = Path(self.tmp.name) / "custom.conf"
        env = dict(self.env, FLEET_CHECK_CONF=str(custom))
        res = subprocess.run(["bash", str(self.resolver), "--install", "--global"],
                             cwd=ROOT, env=env, text=True, capture_output=True, timeout=30)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn(f"--global ignored: FLEET_CHECK_CONF={custom} is explicit and wins", res.stderr)
        self.assertTrue(custom.is_file())
        self.assertEqual(self.conf.read_text(), old_global)
        self.assertEqual(self.backups(), [])

    def test_red_first_mutant_without_guard_fails_refusal_property(self):
        # Remove only the install guard in a private copy; the same behavioural assertion MUST go red.
        shadow = Path(self.tmp.name) / "shadow"
        (shadow / "tools").mkdir(parents=True)
        shutil.copyfile(ROOT / "tools" / "check.conf", shadow / "tools" / "check.conf")
        source = self.resolver.read_text()
        mutant = re.sub(r"  # BEGIN INSTALL_EXISTING_GUARD:.*?  # END INSTALL_EXISTING_GUARD\n",
                        "", source, count=1, flags=re.S)
        self.assertNotEqual(mutant, source, "test must actually remove the guard")
        (shadow / "tools" / "check-cmd.sh").write_text(mutant)
        self.resolver = shadow / "tools" / "check-cmd.sh"
        with self.assertRaises(AssertionError) as failed:
            self.test_missing_script_refused_without_replacement()
        self.assertIn("0 == 0", str(failed.exception))  # its non-zero refusal assertion fails
