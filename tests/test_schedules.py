#!/usr/bin/env python3
"""Unit and integration tests for Software Factory launchd and systemd schedule generation."""

import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

FACTORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(FACTORY_ROOT))

from lib.scheduler import (
    generate_plist,
    generate_systemd_units,
    get_label,
    get_scheduled_candidates,
    install_schedule,
    normalize_platform,
    uninstall_schedule,
    validate_plist,
    validate_systemd_units,
)


class TestScheduleGeneration(unittest.TestCase):
    def test_normalize_platform(self):
        self.assertEqual(normalize_platform("macos"), "darwin")
        self.assertEqual(normalize_platform("darwin"), "darwin")
        self.assertEqual(normalize_platform("launchd"), "darwin")
        self.assertEqual(normalize_platform("linux"), "linux")
        self.assertEqual(normalize_platform("systemd"), "linux")
        self.assertEqual(normalize_platform("all"), "all")
        self.assertIn(normalize_platform("auto"), ("darwin", "linux"))
        with self.assertRaises(ValueError):
            normalize_platform("windows")

    def test_get_label(self):
        label = get_label("voicebox", "secret-scan")
        self.assertEqual(label, "com.softwarefactory.voicebox.secret-scan")

    def test_generate_plist_calendar(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            cadence = {"hour": 7, "minute": 30}
            plist_path = generate_plist("voicebox", "secret-scan", cadence=cadence, output_dir=out_dir)

            self.assertTrue(plist_path.exists())
            self.assertEqual(plist_path.name, "com.softwarefactory.voicebox.secret-scan.plist")

            with open(plist_path, "rb") as fp:
                data = plistlib.load(fp)

            self.assertEqual(data["Label"], "com.softwarefactory.voicebox.secret-scan")
            self.assertEqual(
                data["ProgramArguments"],
                [str(FACTORY_ROOT / "factory"), "run", "secret-scan", "--target", "voicebox"]
            )
            self.assertEqual(data["WorkingDirectory"], str(FACTORY_ROOT))
            self.assertIn("PATH", data["EnvironmentVariables"])
            self.assertIn("HOME", data["EnvironmentVariables"])
            self.assertTrue(data["StandardOutPath"].endswith("schedule-voicebox-secret-scan.stdout.log"))
            self.assertTrue(data["StandardErrorPath"].endswith("schedule-voicebox-secret-scan.stderr.log"))
            self.assertEqual(data["StartCalendarInterval"], {"Hour": 7, "Minute": 30})

    def test_generate_plist_interval(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            cadence = {"interval": 3600}
            plist_path = generate_plist("chrome-agent-platform", "issue-triage", cadence=cadence, output_dir=out_dir)

            self.assertTrue(plist_path.exists())
            with open(plist_path, "rb") as fp:
                data = plistlib.load(fp)

            self.assertEqual(data["StartInterval"], 3600)
            self.assertNotIn("StartCalendarInterval", data)

    def test_validate_plist_invalid(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bad_plist = Path(tmpdir) / "bad.plist"
            # Missing label
            with open(bad_plist, "wb") as fp:
                plistlib.dump({"ProgramArguments": ["factory"]}, fp)
            with self.assertRaises(ValueError):
                validate_plist(bad_plist)

            # Missing interval or calendar
            with open(bad_plist, "wb") as fp:
                plistlib.dump({
                    "Label": "com.test",
                    "ProgramArguments": ["factory", "run"],
                    "WorkingDirectory": "/tmp",
                    "EnvironmentVariables": {"PATH": "/bin", "HOME": "/tmp"},
                    "StandardOutPath": "/tmp/out.log",
                    "StandardErrorPath": "/tmp/err.log"
                }, fp)
            with self.assertRaises(ValueError):
                validate_plist(bad_plist)

    def test_generate_systemd_units_calendar(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            cadence = {"hour": 7, "minute": 35}
            service_path, timer_path = generate_systemd_units("voicebox", "deps-supply-chain", cadence=cadence, output_dir=out_dir)

            self.assertTrue(service_path.exists())
            self.assertTrue(timer_path.exists())
            self.assertEqual(service_path.name, "com.softwarefactory.voicebox.deps-supply-chain.service")
            self.assertEqual(timer_path.name, "com.softwarefactory.voicebox.deps-supply-chain.timer")

            service_txt = service_path.read_text(encoding="utf-8")
            timer_txt = timer_path.read_text(encoding="utf-8")

            # Validate service content
            self.assertIn("[Unit]", service_txt)
            self.assertIn("Description=Software Factory Agent: deps-supply-chain on target voicebox", service_txt)
            self.assertIn("[Service]", service_txt)
            self.assertIn("Type=oneshot", service_txt)
            self.assertIn(f"WorkingDirectory={FACTORY_ROOT}", service_txt)
            self.assertIn('Environment="PATH=', service_txt)
            self.assertIn('Environment="HOME=', service_txt)
            self.assertIn(f"ExecStart={FACTORY_ROOT / 'factory'} run deps-supply-chain --target voicebox", service_txt)
            self.assertIn("StandardOutput=append:", service_txt)
            self.assertIn("StandardError=append:", service_txt)

            # Validate timer content
            self.assertIn("[Unit]", timer_txt)
            self.assertIn("[Timer]", timer_txt)
            self.assertIn("Unit=com.softwarefactory.voicebox.deps-supply-chain.service", timer_txt)
            self.assertIn("OnCalendar=*-*-* 07:35:00", timer_txt)
            self.assertIn("Persistent=true", timer_txt)
            self.assertIn("[Install]", timer_txt)
            self.assertIn("WantedBy=timers.target", timer_txt)

    def test_generate_systemd_units_interval(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            cadence = {"interval": 7200}
            service_path, timer_path = generate_systemd_units("agents", "docs-write", cadence=cadence, output_dir=out_dir)

            timer_txt = timer_path.read_text(encoding="utf-8")
            self.assertIn("OnBootSec=5min", timer_txt)
            self.assertIn("OnUnitActiveSec=7200s", timer_txt)
            self.assertIn("Persistent=true", timer_txt)

    def test_validate_systemd_units_invalid(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            s_file = Path(tmpdir) / "invalid.service"
            t_file = Path(tmpdir) / "invalid.timer"

            s_file.write_text("[Unit]\nDescription=Test\n", encoding="utf-8")
            t_file.write_text("[Unit]\nDescription=Test\n", encoding="utf-8")

            with self.assertRaises(ValueError):
                validate_systemd_units(s_file, t_file)

    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd-analyze not installed")
    def test_systemd_analyze_verify_real(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            s_path, t_path = generate_systemd_units("voicebox", "secret-scan", cadence={"hour": 7, "minute": 30}, output_dir=out_dir)
            res = subprocess.run(
                ["systemd-analyze", "verify", str(s_path), str(t_path)],
                capture_output=True,
                text=True,
                check=False
            )
            self.assertEqual(res.returncode, 0, f"systemd-analyze verify failed: {res.stderr}")

    def test_install_and_uninstall_launchd_isolated(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_launch_dir = Path(tmpdir) / "LaunchAgents"
            install_schedule("voicebox", "secret-scan", platform="darwin", dest_dir=fake_launch_dir)

            dest_plist = fake_launch_dir / "com.softwarefactory.voicebox.secret-scan.plist"
            self.assertTrue(dest_plist.exists())

            uninstall_schedule("voicebox", "secret-scan", platform="darwin", dest_dir=fake_launch_dir)
            self.assertFalse(dest_plist.exists())

    def test_install_and_uninstall_systemd_isolated(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_systemd_dir = Path(tmpdir) / "systemd" / "user"
            install_schedule("voicebox", "secret-scan", platform="systemd", dest_dir=fake_systemd_dir)

            dest_service = fake_systemd_dir / "com.softwarefactory.voicebox.secret-scan.service"
            dest_timer = fake_systemd_dir / "com.softwarefactory.voicebox.secret-scan.timer"
            self.assertTrue(dest_service.exists())
            self.assertTrue(dest_timer.exists())

            uninstall_schedule("voicebox", "secret-scan", platform="systemd", dest_dir=fake_systemd_dir)
            self.assertFalse(dest_service.exists())
            self.assertFalse(dest_timer.exists())

    def test_cli_schedule_generate_and_list(self):
        factory_bin = FACTORY_ROOT / "factory"

        # Test CLI generate with --platform all
        res = subprocess.run(
            [str(factory_bin), "schedule", "generate", "--target", "voicebox", "--agent", "secret-scan", "--platform", "all"],
            capture_output=True,
            text=True,
            check=False
        )
        self.assertEqual(res.returncode, 0, f"CLI generate failed: {res.stderr}")
        self.assertIn("Generated (launchd):", res.stdout)
        self.assertIn("Generated (systemd):", res.stdout)

        # Test CLI list
        res_list = subprocess.run(
            [str(factory_bin), "schedule", "list"],
            capture_output=True,
            text=True,
            check=False
        )
        self.assertEqual(res_list.returncode, 0)
        self.assertIn("Software Factory Schedules", res_list.stdout)

    def test_cli_schedule_option_flags_syntax(self):
        factory_bin = FACTORY_ROOT / "factory"

        # Test CLI with --generate flag syntax
        res_gen = subprocess.run(
            [str(factory_bin), "schedule", "--generate", "--target", "voicebox", "--agent", "secret-scan", "--platform", "systemd"],
            capture_output=True,
            text=True,
            check=False
        )
        self.assertEqual(res_gen.returncode, 0, f"CLI --generate failed: {res_gen.stderr}")
        self.assertIn("Generated (systemd):", res_gen.stdout)

        # Test CLI with --list flag syntax
        res_list = subprocess.run(
            [str(factory_bin), "schedule", "--list", "--platform", "systemd"],
            capture_output=True,
            text=True,
            check=False
        )
        self.assertEqual(res_list.returncode, 0)
        self.assertIn("Software Factory Schedules (Linux systemd user):", res_list.stdout)


if __name__ == "__main__":
    unittest.main()
