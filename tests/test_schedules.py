#!/usr/bin/env python3
"""Unit and integration tests for Software Factory launchd and systemd schedule generation."""

import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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
            self.assertIn(f'ExecStart="{FACTORY_ROOT / "factory"}" run deps-supply-chain --target voicebox', service_txt)
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

    def test_systemd_units_with_spaced_factory_root_and_percent(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            spaced_root = Path(tmpdir) / "repo with spaces % and signs"
            spaced_root.mkdir()
            dummy_factory = spaced_root / "factory"
            dummy_factory.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            dummy_factory.chmod(0o755)

            service_path, timer_path = generate_systemd_units(
                "voicebox",
                "secret-scan",
                cadence={"hour": 7, "minute": 30},
                output_dir=spaced_root,
                factory_root=spaced_root
            )

            service_txt = service_path.read_text(encoding="utf-8")
            escaped_root = str(spaced_root).replace("%", "%%")
            self.assertIn(f'ExecStart="{escaped_root}/factory" run secret-scan --target voicebox', service_txt)
            self.assertIn(f'WorkingDirectory={escaped_root}', service_txt)
            self.assertIn(f'StandardOutput=append:{escaped_root}/runs/', service_txt)

            if shutil.which("systemd-analyze"):
                res = subprocess.run(
                    ["systemd-analyze", "verify", str(service_path), str(timer_path)],
                    capture_output=True,
                    text=True,
                    check=False
                )
                self.assertEqual(res.returncode, 0, f"systemd-analyze verify failed on spaced path: {res.stderr}")

    def test_manager_commands_handle_failure_nonzero_and_preserve_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_home = Path(tmpdir) / "home"
            fake_home.mkdir()
            fake_xdg = fake_home / ".config"
            fake_xdg.mkdir()

            fake_bin = Path(tmpdir) / "bin"
            fake_bin.mkdir()

            fake_systemctl = fake_bin / "systemctl"
            fake_systemctl.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = \"--version\" ]; then echo 'systemd 261'; exit 0; fi\n"
                "echo 'synthetic scheduler failure' >&2\n"
                "exit 7\n",
                encoding="utf-8"
            )
            fake_systemctl.chmod(0o755)

            fake_launchctl = fake_bin / "launchctl"
            fake_launchctl.write_text(
                "#!/bin/sh\n"
                "echo 'synthetic scheduler failure' >&2\n"
                "exit 7\n",
                encoding="utf-8"
            )
            fake_launchctl.chmod(0o755)

            env = dict(os.environ)
            env["HOME"] = str(fake_home)
            env["XDG_CONFIG_HOME"] = str(fake_xdg)
            env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
            factory_bin = FACTORY_ROOT / "factory"

            # 1. Install failure exits non-zero
            res_inst = subprocess.run(
                [str(factory_bin), "schedule", "--install", "--target", "voicebox", "--agent", "secret-scan", "--platform", "systemd"],
                capture_output=True,
                text=True,
                env=env,
                check=False
            )
            self.assertNotEqual(res_inst.returncode, 0, "Install should exit non-zero when systemctl fails")
            self.assertIn("synthetic scheduler failure", res_inst.stdout + res_inst.stderr)

            # 2. Trigger failure exits non-zero
            res_trig = subprocess.run(
                [str(factory_bin), "schedule", "--trigger", "--target", "voicebox", "--agent", "secret-scan", "--platform", "systemd"],
                capture_output=True,
                text=True,
                env=env,
                check=False
            )
            self.assertNotEqual(res_trig.returncode, 0, "Trigger should exit non-zero when systemctl fails")

            # 3. Systemd Uninstall failure exits non-zero AND PRESERVES unit files
            user_systemd = fake_xdg / "systemd" / "user"
            user_systemd.mkdir(parents=True, exist_ok=True)
            test_svc = user_systemd / "com.softwarefactory.voicebox.secret-scan.service"
            test_tmr = user_systemd / "com.softwarefactory.voicebox.secret-scan.timer"
            test_svc.write_text("[Unit]\nDescription=Test\n", encoding="utf-8")
            test_tmr.write_text("[Unit]\nDescription=Test\n", encoding="utf-8")

            res_uninst = subprocess.run(
                [str(factory_bin), "schedule", "--uninstall", "--target", "voicebox", "--agent", "secret-scan", "--platform", "systemd"],
                capture_output=True,
                text=True,
                env=env,
                check=False
            )
            self.assertNotEqual(res_uninst.returncode, 0, "Uninstall should exit non-zero when disable fails")
            # Assert files were NOT destructively deleted
            self.assertTrue(test_svc.exists(), "Service file must be preserved on disable failure")
            self.assertTrue(test_tmr.exists(), "Timer file must be preserved on disable failure")

            # 4. Launchd Uninstall failure exits non-zero AND PRESERVES plist
            user_launch = fake_home / "Library" / "LaunchAgents"
            user_launch.mkdir(parents=True, exist_ok=True)
            test_plist = user_launch / "com.softwarefactory.voicebox.secret-scan.plist"
            test_plist.write_text("<plist></plist>", encoding="utf-8")

            res_launch_uninst = subprocess.run(
                [str(factory_bin), "schedule", "--uninstall", "--target", "voicebox", "--agent", "secret-scan", "--platform", "darwin"],
                capture_output=True,
                text=True,
                env=env,
                check=False
            )
            self.assertNotEqual(res_launch_uninst.returncode, 0, "Uninstall should exit non-zero when launchctl fails")
            self.assertTrue(test_plist.exists(), "Plist must be preserved on unload failure")

    def test_get_active_systemd_timers_inactive_rows(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_home = Path(tmpdir) / "home"
            fake_home.mkdir()
            fake_xdg = fake_home / ".config"
            fake_xdg.mkdir()

            fake_bin = Path(tmpdir) / "bin"
            fake_bin.mkdir()

            # Mock systemctl where list-timers returns an inactive row with - - - -
            fake_systemctl = fake_bin / "systemctl"
            fake_systemctl.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = \"--user\" ] && [ \"$2\" = \"list-timers\" ]; then\n"
                "  echo '- - - - com.softwarefactory.voicebox.secret-scan.timer com.softwarefactory.voicebox.secret-scan.service'\n"
                "  exit 0\n"
                "fi\n"
                "if [ \"$1\" = \"--user\" ] && [ \"$2\" = \"show\" ]; then\n"
                "  echo 'ActiveState=inactive'\n"
                "  echo 'SubState=dead'\n"
                "  exit 0\n"
                "fi\n"
                "exit 0\n",
                encoding="utf-8"
            )
            fake_systemctl.chmod(0o755)

            env = dict(os.environ)
            env["HOME"] = str(fake_home)
            env["XDG_CONFIG_HOME"] = str(fake_xdg)
            env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
            factory_bin = FACTORY_ROOT / "factory"

            res_list = subprocess.run(
                [str(factory_bin), "schedule", "--list", "--platform", "systemd"],
                capture_output=True,
                text=True,
                env=env,
                check=False
            )
            self.assertEqual(res_list.returncode, 0)
            for line in res_list.stdout.splitlines():
                if "voicebox" in line and "secret-scan" in line:
                    parts = line.split()
                    # Line format: TARGET AGENT CADENCE_PART1 CADENCE_PART2 INSTALLED ACTIVE STATUS
                    # e.g. ['voicebox', 'secret-scan', 'at', '07:30', 'no', 'no', '-']
                    self.assertEqual(parts[-2], "no", f"Inactive timer row must not be marked active: {line}")
                    self.assertEqual(parts[-1], "-", f"Inactive timer status should be '-': {line}")

    def test_manager_commands_selective_daemon_reload_failure(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_home = Path(tmpdir) / "home"
            fake_home.mkdir()
            fake_xdg = fake_home / ".config"
            fake_xdg.mkdir()

            fake_bin = Path(tmpdir) / "bin"
            fake_bin.mkdir()

            # Mock systemctl where ONLY daemon-reload fails (exit 7), others succeed
            fake_systemctl = fake_bin / "systemctl"
            fake_systemctl.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = \"--version\" ]; then echo 'systemd 261'; exit 0; fi\n"
                "if [ \"$1\" = \"--user\" ] && [ \"$2\" = \"daemon-reload\" ]; then\n"
                "  echo 'selective reload failure' >&2\n"
                "  exit 7\n"
                "fi\n"
                "exit 0\n",
                encoding="utf-8"
            )
            fake_systemctl.chmod(0o755)

            env = dict(os.environ)
            env["HOME"] = str(fake_home)
            env["XDG_CONFIG_HOME"] = str(fake_xdg)
            env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
            factory_bin = FACTORY_ROOT / "factory"

            # 1. Install must exit non-zero when daemon-reload fails
            res_inst = subprocess.run(
                [str(factory_bin), "schedule", "--install", "--target", "voicebox", "--agent", "secret-scan", "--platform", "systemd"],
                capture_output=True,
                text=True,
                env=env,
                check=False
            )
            self.assertNotEqual(res_inst.returncode, 0, "Install must exit non-zero when daemon-reload fails")
            self.assertIn("Failed to reload systemd daemon via systemctl", res_inst.stdout + res_inst.stderr)

            # Destination files must be cleaned up on failed install
            user_systemd = fake_xdg / "systemd" / "user"
            dest_svc = user_systemd / "com.softwarefactory.voicebox.secret-scan.service"
            dest_tmr = user_systemd / "com.softwarefactory.voicebox.secret-scan.timer"
            self.assertFalse(dest_svc.exists(), "Service file should be removed on failed install reload")
            self.assertFalse(dest_tmr.exists(), "Timer file should be removed on failed install reload")

            # 2. Uninstall must exit non-zero when daemon-reload fails
            user_systemd.mkdir(parents=True, exist_ok=True)
            dest_svc.write_text("[Unit]\nDescription=Test\n", encoding="utf-8")
            dest_tmr.write_text("[Unit]\nDescription=Test\n", encoding="utf-8")

            res_uninst = subprocess.run(
                [str(factory_bin), "schedule", "--uninstall", "--target", "voicebox", "--agent", "secret-scan", "--platform", "systemd"],
                capture_output=True,
                text=True,
                env=env,
                check=False
            )
            self.assertNotEqual(res_uninst.returncode, 0, "Uninstall must exit non-zero when daemon-reload fails")
            self.assertIn("Failed to reload systemd daemon via systemctl", res_uninst.stdout + res_uninst.stderr)

    def test_install_rollback_preserves_existing_and_mixed_definitions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_home = Path(tmpdir) / "home"
            fake_home.mkdir()
            fake_xdg = fake_home / ".config"
            fake_xdg.mkdir()
            fake_bin = Path(tmpdir) / "bin"
            fake_bin.mkdir()

            # Mock systemctl where command can fail conditionally based on env FAIL_CMD
            fake_systemctl = fake_bin / "systemctl"
            fake_systemctl.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = \"--version\" ]; then echo 'systemd 261'; exit 0; fi\n"
                "if [ -n \"$FAIL_CMD\" ]; then\n"
                "  for arg in \"$@\"; do\n"
                "    if [ \"$arg\" = \"$FAIL_CMD\" ]; then\n"
                "      echo \"synthetic $FAIL_CMD failure\" >&2\n"
                "      exit 7\n"
                "    fi\n"
                "  done\n"
                "fi\n"
                "exit 0\n",
                encoding="utf-8"
            )
            fake_systemctl.chmod(0o755)

            fake_launchctl = fake_bin / "launchctl"
            fake_launchctl.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = \"load\" ]; then echo 'synthetic load failure' >&2; exit 7; fi\n"
                "exit 0\n",
                encoding="utf-8"
            )
            fake_launchctl.chmod(0o755)

            env = dict(os.environ)
            env["HOME"] = str(fake_home)
            env["XDG_CONFIG_HOME"] = str(fake_xdg)
            env["PATH"] = f"{fake_bin}:{env.get('PATH', '')}"
            factory_bin = FACTORY_ROOT / "factory"

            user_systemd = fake_xdg / "systemd" / "user"
            user_systemd.mkdir(parents=True, exist_ok=True)
            dest_svc = user_systemd / "com.softwarefactory.voicebox.secret-scan.service"
            dest_tmr = user_systemd / "com.softwarefactory.voicebox.secret-scan.timer"

            # Case 1: Both service and timer pre-exist; daemon-reload fails
            dest_svc.write_text("PRE_EXISTING_SERVICE_CONTENT", encoding="utf-8")
            dest_tmr.write_text("PRE_EXISTING_TIMER_CONTENT", encoding="utf-8")
            env["FAIL_CMD"] = "daemon-reload"

            res1 = subprocess.run(
                [str(factory_bin), "schedule", "--install", "--target", "voicebox", "--agent", "secret-scan", "--platform", "systemd"],
                capture_output=True,
                text=True,
                env=env,
                check=False
            )
            self.assertNotEqual(res1.returncode, 0)
            self.assertEqual(dest_svc.read_text(encoding="utf-8"), "PRE_EXISTING_SERVICE_CONTENT")
            self.assertEqual(dest_tmr.read_text(encoding="utf-8"), "PRE_EXISTING_TIMER_CONTENT")

            # Case 2: Both service and timer pre-exist; enable fails
            env["FAIL_CMD"] = "enable"
            res2 = subprocess.run(
                [str(factory_bin), "schedule", "--install", "--target", "voicebox", "--agent", "secret-scan", "--platform", "systemd"],
                capture_output=True,
                text=True,
                env=env,
                check=False
            )
            self.assertNotEqual(res2.returncode, 0)
            self.assertEqual(dest_svc.read_text(encoding="utf-8"), "PRE_EXISTING_SERVICE_CONTENT")
            self.assertEqual(dest_tmr.read_text(encoding="utf-8"), "PRE_EXISTING_TIMER_CONTENT")

            # Case 3: Mixed presence - only service pre-exists; enable fails
            dest_tmr.unlink()
            res3 = subprocess.run(
                [str(factory_bin), "schedule", "--install", "--target", "voicebox", "--agent", "secret-scan", "--platform", "systemd"],
                capture_output=True,
                text=True,
                env=env,
                check=False
            )
            self.assertNotEqual(res3.returncode, 0)
            self.assertEqual(dest_svc.read_text(encoding="utf-8"), "PRE_EXISTING_SERVICE_CONTENT")
            self.assertFalse(dest_tmr.exists(), "Newly created timer must be unlinked on failure")

            # Case 4: Mixed presence - only timer pre-exists; daemon-reload fails
            dest_svc.unlink()
            dest_tmr.write_text("PRE_EXISTING_TIMER_ONLY", encoding="utf-8")
            env["FAIL_CMD"] = "daemon-reload"
            res4 = subprocess.run(
                [str(factory_bin), "schedule", "--install", "--target", "voicebox", "--agent", "secret-scan", "--platform", "systemd"],
                capture_output=True,
                text=True,
                env=env,
                check=False
            )
            self.assertNotEqual(res4.returncode, 0)
            self.assertEqual(dest_tmr.read_text(encoding="utf-8"), "PRE_EXISTING_TIMER_ONLY")
            self.assertFalse(dest_svc.exists(), "Newly created service must be unlinked on failure")

            # Case 5: Launchd pre-existing plist preserved on load failure
            user_launch = fake_home / "Library" / "LaunchAgents"
            user_launch.mkdir(parents=True, exist_ok=True)
            dest_plist = user_launch / "com.softwarefactory.voicebox.secret-scan.plist"
            dest_plist.write_text("PRE_EXISTING_PLIST_CONTENT", encoding="utf-8")

            res_launch = subprocess.run(
                [str(factory_bin), "schedule", "--install", "--target", "voicebox", "--agent", "secret-scan", "--platform", "darwin"],
                capture_output=True,
                text=True,
                env=env,
                check=False
            )
            self.assertNotEqual(res_launch.returncode, 0)
            self.assertEqual(dest_plist.read_text(encoding="utf-8"), "PRE_EXISTING_PLIST_CONTENT")


class TestControlPlaneTimeouts(unittest.TestCase):
    """SF-06: control-plane commands are bounded, so a wedged service manager cannot hang
    the factory CLI (these calls have no agent budget to derive a timeout from)."""

    def test_control_plane_command_times_out(self):
        from lib import scheduler

        original = scheduler.CONTROL_TIMEOUT_SECONDS
        scheduler.CONTROL_TIMEOUT_SECONDS = 0.5
        try:
            with self.assertRaises(subprocess.TimeoutExpired):
                scheduler._run_control(
                    [sys.executable, "-c", "import time; time.sleep(10)"]
                )
        finally:
            scheduler.CONTROL_TIMEOUT_SECONDS = original

    def test_every_scheduler_call_goes_through_the_bounded_helper(self):
        source = (FACTORY_ROOT / "lib" / "scheduler.py").read_text(encoding="utf-8")
        # Only the helper itself may call subprocess.run; every call site uses the helper.
        self.assertEqual(source.count("subprocess.run("), 1)
        self.assertGreaterEqual(source.count("_run_control("), 2)


class TestTriggerScheduleDoesNotBlock(unittest.TestCase):
    """Type=oneshot services are synchronous: the trigger must enqueue, not wait for the run."""

    def test_systemd_trigger_passes_no_block(self):
        from lib import scheduler

        with tempfile.TemporaryDirectory() as tmpdir:
            bin_dir = Path(tmpdir) / "bin"
            bin_dir.mkdir()
            calls = Path(tmpdir) / "calls"
            stub = bin_dir / "systemctl"
            stub.write_text(
                "#!/bin/sh\n"
                f"printf '%s\\n' \"$*\" >> \"{calls}\"\n"
                "exit 0\n",
                encoding="utf-8",
            )
            stub.chmod(0o755)

            env = dict(os.environ)
            env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
            with mock.patch.dict(os.environ, env):
                self.assertTrue(
                    scheduler.trigger_schedule("voicebox", "secret-scan", platform="systemd")
                )

            recorded = calls.read_text(encoding="utf-8")
            self.assertIn("--no-block", recorded)
            self.assertIn("com.softwarefactory.voicebox.secret-scan.service", recorded)


if __name__ == "__main__":
    unittest.main()
