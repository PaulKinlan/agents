#!/usr/bin/env python3
"""Scheduler for Software Factory supporting macOS launchd and Linux systemd.

Generates, installs, uninstalls, validates, and monitors user-level scheduled
SDLC agent runs under the user's active session auth and environment.
"""

import argparse
import os
import plistlib
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

FACTORY_ROOT = Path(__file__).resolve().parent.parent
SCHEDULES_DIR = FACTORY_ROOT / "schedules"

# Control-plane commands (launchctl, systemctl, plutil, systemd-analyze) answer in well under a
# second when the service manager is healthy. A fixed cap stops a wedged manager from hanging the
# factory CLI; these calls are not agent stations, so there is no budget.max_minutes to derive
# from (SF-06).
CONTROL_TIMEOUT_SECONDS = 30


def _run_control(cmd, **kwargs) -> subprocess.CompletedProcess:
    """subprocess.run for control-plane commands, always with a hard timeout."""
    kwargs.setdefault("capture_output", True)
    kwargs.setdefault("text", True)
    return subprocess.run(cmd, timeout=CONTROL_TIMEOUT_SECONDS, **kwargs)


def get_launch_agents_dir() -> Path:
    """Return standard user launchd agents directory (~/Library/LaunchAgents)."""
    return Path.home() / "Library" / "LaunchAgents"


LAUNCH_AGENTS_DIR = get_launch_agents_dir()


def get_systemd_user_dir() -> Path:
    """Return standard user systemd units directory (~/.config/systemd/user)."""
    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg_config) if xdg_config else Path.home() / ".config"
    return base / "systemd" / "user"


def normalize_platform(platform: Optional[str] = None) -> str:
    """Normalize platform identifier to 'darwin', 'linux', or 'all'."""
    if not platform or platform == "auto":
        return "darwin" if sys.platform == "darwin" else "linux"
    p = platform.lower()
    if p in ("darwin", "macos", "launchd"):
        return "darwin"
    if p in ("linux", "systemd"):
        return "linux"
    if p == "all":
        return "all"
    raise ValueError(f"Unknown platform: {platform}")


def get_label(target: str, agent: str) -> str:
    """Standardized service label across launchd and systemd."""
    return f"com.softwarefactory.{target}.{agent}"


def _escape_systemd_specifiers(val: Any) -> str:
    """Escape percent specifiers for systemd unit file values."""
    return str(val).replace("%", "%%")


def _parse_scalar(val: str) -> Any:
    if val.lower() == "true":
        return True
    if val.lower() == "false":
        return False
    if val.isdigit():
        return int(val)
    return val.strip("'\"")


def load_yaml_simple(path: Path) -> Dict[str, Any]:
    """Indentation-aware YAML parser for simple key-value, list, and nested map manifests."""
    result: Dict[str, Any] = {}
    stack: list = [(-1, result)]

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0]
        line_clean = line.strip()
        if not line_clean:
            continue

        indent = len(line) - len(line.lstrip(" "))
        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()

        parent = stack[-1][1]

        if line_clean.startswith("- "):
            val = line_clean[2:].strip()
            if isinstance(parent, dict) and len(parent) == 0 and len(stack) >= 2:
                outer_dict = stack[-2][1]
                if isinstance(outer_dict, dict):
                    for k in reversed(list(outer_dict.keys())):
                        if outer_dict[k] is parent:
                            new_list = [_parse_scalar(val)]
                            outer_dict[k] = new_list
                            stack[-1] = (stack[-1][0], new_list)
                            break
            elif isinstance(parent, list):
                parent.append(_parse_scalar(val))
            continue

        if ":" in line_clean:
            key, val = [p.strip() for p in line_clean.split(":", 1)]
            if not isinstance(parent, dict):
                continue

            if not val:
                new_map: Dict[str, Any] = {}
                parent[key] = new_map
                stack.append((indent, new_map))
            elif val.startswith("[") and val.endswith("]"):
                items = [_parse_scalar(x.strip()) for x in val[1:-1].split(",") if x.strip()]
                parent[key] = items
            else:
                parent[key] = _parse_scalar(val)
    return result


def get_scheduled_candidates(target_filter: Optional[str] = None, agent_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    """Discover all target-agent pairs configured for scheduling."""
    targets_dir = FACTORY_ROOT / "targets"
    agents_dir = FACTORY_ROOT / "agents"
    candidates = []

    for t_file in sorted(targets_dir.glob("*.yaml")):
        t_cfg = load_yaml_simple(t_file)
        t_name = t_cfg.get("name", t_file.stem)
        if target_filter and t_name != target_filter:
            continue

        target_agents = t_cfg.get("agents", [])
        schedule_section = t_cfg.get("schedule", {})

        for ag in target_agents:
            if agent_filter and ag != agent_filter:
                continue

            ag_yaml = agents_dir / ag / "agent.yaml"
            if not ag_yaml.exists():
                continue
            ag_cfg = load_yaml_simple(ag_yaml)
            triggers = ag_cfg.get("triggers", [])

            is_schedulable = "schedule" in triggers or ag in schedule_section
            if not is_schedulable:
                continue

            cadence_info = {"interval": 86400}
            if isinstance(schedule_section, dict) and ag in schedule_section:
                sec = schedule_section[ag]
                if isinstance(sec, dict):
                    cadence_info = sec
                elif isinstance(sec, int):
                    cadence_info = {"interval": sec}

            candidates.append({
                "target": t_name,
                "agent": ag,
                "cadence": cadence_info,
                "class": ag_cfg.get("class", "observer"),
                "label": get_label(t_name, ag)
            })

    return candidates


def _format_cadence(cadence: Dict[str, Any]) -> str:
    if "interval" in cadence:
        return f"interval={cadence['interval']}s"
    if "hour" in cadence:
        return f"at {int(cadence['hour']):02d}:{int(cadence.get('minute', 0)):02d}"
    if "calendar" in cadence:
        return f"cal={cadence['calendar']}"
    return str(cadence)


def validate_plist(plist_path: Path) -> Dict[str, Any]:
    """Validate structure, required keys, and syntax of a launchd plist."""
    if not plist_path.exists():
        raise FileNotFoundError(f"Plist file does not exist: {plist_path}")

    with open(plist_path, "rb") as fp:
        data = plistlib.load(fp)

    if not isinstance(data, dict):
        raise ValueError(f"Plist root must be a dictionary: {plist_path}")

    label = data.get("Label")
    if not label or not isinstance(label, str):
        raise ValueError(f"Plist missing valid 'Label': {plist_path}")

    args = data.get("ProgramArguments")
    if not args or not isinstance(args, list) or not all(isinstance(x, str) for x in args):
        raise ValueError(f"Plist missing valid 'ProgramArguments' string list: {plist_path}")

    wd = data.get("WorkingDirectory")
    if not wd or not isinstance(wd, str):
        raise ValueError(f"Plist missing valid 'WorkingDirectory': {plist_path}")

    env = data.get("EnvironmentVariables")
    if not isinstance(env, dict) or "PATH" not in env or "HOME" not in env:
        raise ValueError(f"Plist missing valid 'EnvironmentVariables' containing PATH and HOME: {plist_path}")

    if not data.get("StandardOutPath") or not data.get("StandardErrorPath"):
        raise ValueError(f"Plist missing logging paths StandardOutPath/StandardErrorPath: {plist_path}")

    if "StartInterval" not in data and "StartCalendarInterval" not in data:
        raise ValueError(f"Plist missing StartInterval or StartCalendarInterval: {plist_path}")

    if shutil.which("plutil"):
        res = _run_control(["plutil", "-lint", str(plist_path)], capture_output=True, text=True, check=False)
        if res.returncode != 0:
            raise ValueError(f"plutil lint failed for {plist_path}: {res.stderr.strip() or res.stdout.strip()}")

    return data


def generate_plist(
    target: str,
    agent: str,
    cadence: Optional[Dict[str, Any]] = None,
    output_dir: Optional[Path] = None,
    factory_root: Optional[Path] = None
) -> Path:
    """Generate launchd plist dictionary, write to schedules/ (or output_dir), and validate."""
    root = factory_root or FACTORY_ROOT
    out_dir = output_dir or SCHEDULES_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    runs_dir = root / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)

    label = get_label(target, agent)
    plist_path = out_dir / f"{label}.plist"

    cadence = cadence or {"interval": 86400}

    user_path = os.environ.get("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
    user_home = os.environ.get("HOME", str(Path.home()))

    plist_data: Dict[str, Any] = {
        "Label": label,
        "ProgramArguments": [
            str(root / "factory"),
            "run",
            agent,
            "--target",
            target
        ],
        "WorkingDirectory": str(root),
        "EnvironmentVariables": {
            "PATH": user_path,
            "HOME": user_home
        },
        "RunAtLoad": False,
        "StandardOutPath": str(runs_dir / f"schedule-{target}-{agent}.stdout.log"),
        "StandardErrorPath": str(runs_dir / f"schedule-{target}-{agent}.stderr.log")
    }

    if "interval" in cadence:
        plist_data["StartInterval"] = int(cadence["interval"])
    elif "hour" in cadence:
        cal: Dict[str, int] = {"Hour": int(cadence["hour"])}
        cal["Minute"] = int(cadence.get("minute", 0))
        plist_data["StartCalendarInterval"] = cal

    with open(plist_path, "wb") as fp:
        plistlib.dump(plist_data, fp)

    validate_plist(plist_path)
    return plist_path


def validate_systemd_units(service_path: Path, timer_path: Path) -> Tuple[str, str]:
    """Validate structure, required sections, and directives of systemd service and timer units."""
    if not service_path.exists():
        raise FileNotFoundError(f"Service unit file does not exist: {service_path}")
    if not timer_path.exists():
        raise FileNotFoundError(f"Timer unit file does not exist: {timer_path}")

    service_content = service_path.read_text(encoding="utf-8")
    timer_content = timer_path.read_text(encoding="utf-8")

    # Service unit validation
    if "[Unit]" not in service_content or "Description=" not in service_content:
        raise ValueError(f"Service unit missing [Unit] section or Description: {service_path}")
    if "[Service]" not in service_content:
        raise ValueError(f"Service unit missing [Service] section: {service_path}")
    if "Type=oneshot" not in service_content:
        raise ValueError(f"Service unit missing Type=oneshot: {service_path}")
    if "ExecStart=" not in service_content:
        raise ValueError(f"Service unit missing ExecStart directive: {service_path}")
    if "WorkingDirectory=" not in service_content:
        raise ValueError(f"Service unit missing WorkingDirectory directive: {service_path}")
    if "Environment=" not in service_content or "PATH=" not in service_content:
        raise ValueError(f"Service unit missing Environment directive with PATH: {service_path}")
    if "StandardOutput=" not in service_content or "StandardError=" not in service_content:
        raise ValueError(f"Service unit missing StandardOutput/StandardError logging: {service_path}")

    # Timer unit validation
    if "[Unit]" not in timer_content or "Description=" not in timer_content:
        raise ValueError(f"Timer unit missing [Unit] section or Description: {timer_path}")
    if "[Timer]" not in timer_content or "Unit=" not in timer_content:
        raise ValueError(f"Timer unit missing [Timer] section or Unit directive: {timer_path}")
    if not any(k in timer_content for k in ("OnCalendar=", "OnUnitActiveSec=", "OnBootSec=")):
        raise ValueError(f"Timer unit missing scheduling directive (OnCalendar/OnUnitActiveSec/OnBootSec): {timer_path}")
    if "[Install]" not in timer_content or "WantedBy=" not in timer_content:
        raise ValueError(f"Timer unit missing [Install] section or WantedBy directive: {timer_path}")

    # If systemd-analyze is present, perform system-level verification
    if shutil.which("systemd-analyze"):
        res = _run_control(
            ["systemd-analyze", "verify", str(service_path), str(timer_path)],
            capture_output=True,
            text=True,
            check=False
        )
        if res.returncode != 0:
            raise ValueError(f"systemd-analyze verify failed: {res.stderr.strip() or res.stdout.strip()}")

    return (service_content, timer_content)


def generate_systemd_units(
    target: str,
    agent: str,
    cadence: Optional[Dict[str, Any]] = None,
    output_dir: Optional[Path] = None,
    factory_root: Optional[Path] = None
) -> Tuple[Path, Path]:
    """Generate systemd user service (.service) and timer (.timer) unit files, write to schedules/, and validate."""
    root = factory_root or FACTORY_ROOT
    out_dir = output_dir or SCHEDULES_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    runs_dir = root / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)

    label = get_label(target, agent)
    service_path = out_dir / f"{label}.service"
    timer_path = out_dir / f"{label}.timer"

    cadence = cadence or {"interval": 86400}
    user_path = os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
    user_home = os.environ.get("HOME", str(Path.home()))

    stdout_log = runs_dir / f"schedule-{target}-{agent}.stdout.log"
    stderr_log = runs_dir / f"schedule-{target}-{agent}.stderr.log"

    factory_bin = root / "factory"
    # Quote executable path in ExecStart and escape '%' specifiers
    escaped_bin = _escape_systemd_specifiers(factory_bin)
    exec_start = f'"{escaped_bin}" run {agent} --target {target}'
    escaped_wd = _escape_systemd_specifiers(root)
    escaped_stdout = _escape_systemd_specifiers(stdout_log)
    escaped_stderr = _escape_systemd_specifiers(stderr_log)
    escaped_path = _escape_systemd_specifiers(user_path)
    escaped_home = _escape_systemd_specifiers(user_home)

    service_content = f"""[Unit]
Description=Software Factory Agent: {agent} on target {target}
After=network-online.target

[Service]
Type=oneshot
WorkingDirectory={escaped_wd}
Environment="PATH={escaped_path}"
Environment="HOME={escaped_home}"
ExecStart={exec_start}
StandardOutput=append:{escaped_stdout}
StandardError=append:{escaped_stderr}
"""

    if "calendar" in cadence:
        timing_directives = f"OnCalendar={cadence['calendar']}\nPersistent=true"
    elif "hour" in cadence:
        hour = int(cadence["hour"])
        minute = int(cadence.get("minute", 0))
        second = int(cadence.get("second", 0))
        timing_directives = f"OnCalendar=*-*-* {hour:02d}:{minute:02d}:{second:02d}\nPersistent=true"
    elif "interval" in cadence:
        interval = int(cadence["interval"])
        timing_directives = f"OnBootSec=5min\nOnUnitActiveSec={interval}s\nPersistent=true"
    else:
        timing_directives = "OnBootSec=5min\nOnUnitActiveSec=86400s\nPersistent=true"

    timer_content = f"""[Unit]
Description=Software Factory Timer for {agent} on target {target}

[Timer]
Unit={label}.service
{timing_directives}

[Install]
WantedBy=timers.target
"""

    service_path.write_text(service_content, encoding="utf-8")
    timer_path.write_text(timer_content, encoding="utf-8")

    validate_systemd_units(service_path, timer_path)
    return (service_path, timer_path)


def get_loaded_launchd_services() -> Dict[str, Dict[str, str]]:
    """Query launchctl for active com.softwarefactory services."""
    if not shutil.which("launchctl"):
        return {}
    try:
        res = _run_control(["launchctl", "list"], capture_output=True, text=True, check=True)
    except Exception:
        return {}

    services = {}
    for line in res.stdout.splitlines():
        parts = line.strip().split("\t")
        if len(parts) == 3:
            pid, exit_status, label = parts
            if label.startswith("com.softwarefactory."):
                services[label] = {
                    "pid": pid,
                    "exit_status": exit_status
                }
    return services


def get_active_systemd_timers() -> Dict[str, Dict[str, Any]]:
    """Query systemctl for active user timers, correctly differentiating active from inactive rows."""
    if not shutil.which("systemctl"):
        return {}
    try:
        res = _run_control(
            ["systemctl", "--user", "list-timers", "--all", "--no-legend"],
            capture_output=True,
            text=True,
            check=True
        )
    except Exception:
        return {}

    timers: Dict[str, Dict[str, Any]] = {}
    for line in res.stdout.splitlines():
        parts = line.strip().split()
        if len(parts) >= 6:
            unit = parts[-2]
            activates = parts[-1]
            if unit.endswith(".timer"):
                # If first column is '-' or 'n/a', there is no next scheduled trigger
                has_next = parts[0] != "-" and parts[0].lower() != "n/a"
                timers[unit] = {
                    "unit": unit,
                    "activates": activates,
                    "active": has_next,
                    "next": " ".join(parts[:3]) if has_next else "-"
                }
    return timers


def list_schedules(platform: Optional[str] = None):
    """List all configured schedules and their current status on the host scheduler."""
    plat = normalize_platform(platform)
    candidates = get_scheduled_candidates()

    if plat == "darwin":
        loaded = get_loaded_launchd_services()
        print("\nSoftware Factory Schedules (macOS launchd):")
        print("=" * 85)
        print(f"{'TARGET':<22} {'AGENT':<18} {'CADENCE':<16} {'INSTALLED':<11} {'LOADED':<10} {'PID/STATUS'}")
        print("-" * 85)

        launch_dir = get_launch_agents_dir()
        for item in candidates:
            label = item["label"]
            dest_plist = launch_dir / f"{label}.plist"
            installed = "yes" if dest_plist.exists() else "no"
            is_loaded = "yes" if label in loaded else "no"
            status = "-"
            if label in loaded:
                info = loaded[label]
                status = f"pid={info['pid']}" if info['pid'] != "-" else f"last_exit={info['exit_status']}"

            cadence_str = _format_cadence(item["cadence"])
            print(f"{item['target']:<22} {item['agent']:<18} {cadence_str:<16} {installed:<11} {is_loaded:<10} {status}")

        print("=" * 85)
    else:
        systemd_user_dir = get_systemd_user_dir()
        active_timers = get_active_systemd_timers()

        print("\nSoftware Factory Schedules (Linux systemd user):")
        print("=" * 95)
        print(f"{'TARGET':<22} {'AGENT':<18} {'CADENCE':<16} {'INSTALLED':<11} {'ACTIVE':<10} {'STATUS / NEXT RUN'}")
        print("-" * 95)

        for item in candidates:
            label = item["label"]
            dest_service = systemd_user_dir / f"{label}.service"
            dest_timer = systemd_user_dir / f"{label}.timer"
            installed = "yes" if (dest_service.exists() and dest_timer.exists()) else ("partial" if (dest_service.exists() or dest_timer.exists()) else "no")

            timer_unit = f"{label}.timer"
            active_info = active_timers.get(timer_unit)

            actual_active = False
            status_str = "-"

            if shutil.which("systemctl"):
                try:
                    res = _run_control(
                        ["systemctl", "--user", "show", timer_unit, "--property=ActiveState,SubState"],
                        capture_output=True,
                        text=True,
                        check=False
                    )
                    props = {}
                    for p_line in res.stdout.splitlines():
                        if "=" in p_line:
                            k, v = p_line.split("=", 1)
                            props[k.strip()] = v.strip()
                    active_state = props.get("ActiveState", "inactive")
                    sub_state = props.get("SubState", "dead")
                    if active_state == "active" and sub_state in ("waiting", "running"):
                        actual_active = True
                        if active_info and active_info.get("active") and active_info.get("next") != "-":
                            status_str = active_info.get("next")
                        else:
                            status_str = f"active ({sub_state})"
                    else:
                        actual_active = False
                        status_str = "-" if installed == "no" else sub_state
                except Exception:
                    actual_active = False
                    status_str = "-"
            elif active_info and active_info.get("active"):
                actual_active = True
                status_str = active_info.get("next", "active")

            active_str = "active" if actual_active else "no"
            cadence_str = _format_cadence(item["cadence"])
            print(f"{item['target']:<22} {item['agent']:<18} {cadence_str:<16} {installed:<11} {active_str:<10} {status_str}")

        print("=" * 95)


def install_schedule(
    target: str,
    agent: str,
    platform: Optional[str] = None,
    dest_dir: Optional[Path] = None
) -> bool:
    """Generate, install, and enable schedule for a target-agent pair."""
    plat = normalize_platform(platform)
    candidates = get_scheduled_candidates(target_filter=target, agent_filter=agent)
    if not candidates:
        print(f"Error: Target '{target}' and agent '{agent}' do not form a valid schedulable pair.")
        return False

    candidate = candidates[0]
    label = candidate["label"]

    if plat == "darwin":
        plist_path = generate_plist(target, agent, candidate["cadence"])
        target_dir = dest_dir or get_launch_agents_dir()
        target_dir.mkdir(parents=True, exist_ok=True)
        dest_path = target_dir / f"{label}.plist"

        plist_orig = dest_path.read_bytes() if dest_path.exists() else None
        shutil.copyfile(plist_path, dest_path)

        if dest_dir is None and shutil.which("launchctl"):
            _run_control(["launchctl", "unload", "-w", str(dest_path)], capture_output=True, check=False)
            res = _run_control(["launchctl", "load", "-w", str(dest_path)], capture_output=True, text=True, check=False)
            if res.returncode == 0:
                print(f"✓ Installed and loaded launchd schedule: {label}")
                print(f"  Plist: {dest_path}")
                print(f"  Cadence: {candidate['cadence']}")
                return True
            else:
                err_msg = res.stderr.strip() or res.stdout.strip()
                print(f"✗ Failed to load into launchctl: {err_msg}")
                if plist_orig is not None:
                    dest_path.write_bytes(plist_orig)
                    _run_control(["launchctl", "load", "-w", str(dest_path)], capture_output=True, check=False)
                else:
                    dest_path.unlink(missing_ok=True)
                return False
        else:
            print(f"✓ Installed launchd plist: {dest_path}")
            print(f"  Cadence: {candidate['cadence']}")
            return True
    else:
        service_path, timer_path = generate_systemd_units(target, agent, candidate["cadence"])
        target_dir = dest_dir or get_systemd_user_dir()
        target_dir.mkdir(parents=True, exist_ok=True)

        dest_service = target_dir / f"{label}.service"
        dest_timer = target_dir / f"{label}.timer"

        service_orig = dest_service.read_bytes() if dest_service.exists() else None
        timer_orig = dest_timer.read_bytes() if dest_timer.exists() else None

        def _rollback():
            if service_orig is not None:
                dest_service.write_bytes(service_orig)
            else:
                dest_service.unlink(missing_ok=True)

            if timer_orig is not None:
                dest_timer.write_bytes(timer_orig)
            else:
                dest_timer.unlink(missing_ok=True)

            if dest_dir is None and shutil.which("systemctl") and (service_orig is not None or timer_orig is not None):
                _run_control(["systemctl", "--user", "daemon-reload"], capture_output=True, text=True, check=False)

        shutil.copyfile(service_path, dest_service)
        shutil.copyfile(timer_path, dest_timer)

        if dest_dir is None and shutil.which("systemctl"):
            res_reload = _run_control(["systemctl", "--user", "daemon-reload"], capture_output=True, text=True, check=False)
            if res_reload.returncode != 0:
                err_msg = res_reload.stderr.strip() or res_reload.stdout.strip()
                print(f"✗ Failed to reload systemd daemon via systemctl: {err_msg}")
                _rollback()
                return False

            res = _run_control(["systemctl", "--user", "enable", "--now", f"{label}.timer"], capture_output=True, text=True, check=False)
            if res.returncode == 0:
                print(f"✓ Installed and enabled systemd schedule: {label}.timer")
                print(f"  Service: {dest_service}")
                print(f"  Timer: {dest_timer}")
                print(f"  Cadence: {candidate['cadence']}")
                return True
            else:
                err_msg = res.stderr.strip() or res.stdout.strip()
                print(f"✗ Failed to enable {label}.timer via systemctl: {err_msg}")
                _rollback()
                return False
        else:
            print(f"✓ Installed systemd units: {dest_service} and {dest_timer}")
            print(f"  Cadence: {candidate['cadence']}")
            return True


def uninstall_schedule(
    target: str,
    agent: str,
    platform: Optional[str] = None,
    dest_dir: Optional[Path] = None
) -> bool:
    """Disable, unload, and remove scheduled service definitions."""
    plat = normalize_platform(platform)
    label = get_label(target, agent)

    if plat == "darwin":
        target_dir = dest_dir or get_launch_agents_dir()
        dest_path = target_dir / f"{label}.plist"
        if not dest_path.exists():
            print(f"Schedule not found in LaunchAgents: {label}")
            return True

        if dest_dir is None and shutil.which("launchctl"):
            res = _run_control(["launchctl", "unload", "-w", str(dest_path)], capture_output=True, text=True, check=False)
            if res.returncode != 0:
                err_msg = res.stderr.strip() or res.stdout.strip()
                print(f"✗ Failed to unload {label} via launchctl: {err_msg}")
                return False

        dest_path.unlink()
        print(f"✓ Uninstalled launchd schedule: {label}")
        return True
    else:
        target_dir = dest_dir or get_systemd_user_dir()
        dest_service = target_dir / f"{label}.service"
        dest_timer = target_dir / f"{label}.timer"

        if not dest_timer.exists() and not dest_service.exists():
            print(f"Schedule not found in systemd user directory: {label}")
            return True

        if dest_dir is None and shutil.which("systemctl"):
            res_dis = _run_control(["systemctl", "--user", "disable", "--now", f"{label}.timer"], capture_output=True, text=True, check=False)
            if res_dis.returncode != 0:
                err_msg = res_dis.stderr.strip() or res_dis.stdout.strip()
                print(f"✗ Failed to disable {label}.timer via systemctl: {err_msg}")
                return False

            res_stop = _run_control(["systemctl", "--user", "stop", f"{label}.service"], capture_output=True, text=True, check=False)
            if res_stop.returncode != 0:
                err_msg = res_stop.stderr.strip() or res_stop.stdout.strip()
                print(f"✗ Failed to stop {label}.service via systemctl: {err_msg}")
                return False

        if dest_timer.exists():
            dest_timer.unlink()
        if dest_service.exists():
            dest_service.unlink()

        if dest_dir is None and shutil.which("systemctl"):
            res_reload = _run_control(["systemctl", "--user", "daemon-reload"], capture_output=True, text=True, check=False)
            if res_reload.returncode != 0:
                err_msg = res_reload.stderr.strip() or res_reload.stdout.strip()
                print(f"✗ Failed to reload systemd daemon via systemctl: {err_msg}")
                return False

        print(f"✓ Uninstalled systemd schedule: {label}")
        return True


def trigger_schedule(target: str, agent: str, platform: Optional[str] = None) -> bool:
    """Trigger an immediate run of a scheduled service."""
    plat = normalize_platform(platform)
    label = get_label(target, agent)

    if plat == "darwin":
        res = _run_control(["launchctl", "start", label], capture_output=True, text=True, check=False)
        if res.returncode == 0:
            print(f"✓ Triggered immediate launchd execution for: {label}")
            return True
        else:
            err_msg = res.stderr.strip() or res.stdout.strip()
            print(f"✗ Failed to trigger {label}: {err_msg}")
            return False
    else:
        service_name = f"{label}.service"
        # Type=oneshot services are synchronous: a plain `systemctl start` blocks until the run
        # finishes and would trip the control-plane cap. Enqueue the start and return.
        res = _run_control(["systemctl", "--user", "start", "--no-block", service_name], capture_output=True, text=True, check=False)
        if res.returncode == 0:
            print(f"✓ Triggered immediate systemd execution for: {service_name}")
            return True
        else:
            err_msg = res.stderr.strip() or res.stdout.strip()
            print(f"✗ Failed to trigger {service_name}: {err_msg}")
            return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Software Factory Scheduler (launchd / systemd)")
    parser.add_argument("--platform", choices=["auto", "launchd", "systemd", "darwin", "linux", "all"], default="auto", help="Scheduler platform")
    parser.add_argument("--install", action="store_true", help="Install schedule")
    parser.add_argument("--uninstall", action="store_true", help="Uninstall schedule")
    parser.add_argument("--generate", action="store_true", help="Generate schedule unit files into schedules/")
    parser.add_argument("--list", action="store_true", help="List schedules")
    parser.add_argument("--trigger", action="store_true", help="Trigger immediate run")
    parser.add_argument("--target", help="Target name")
    parser.add_argument("--agent", help="Agent name")
    parser.add_argument("--all", action="store_true", help="Operate on all configured schedules")

    sub = parser.add_subparsers(dest="command")

    list_p = sub.add_parser("list", help="List schedulable agents and current status")
    list_p.add_argument("--platform", choices=["auto", "launchd", "systemd", "darwin", "linux"], default="auto")

    gen = sub.add_parser("generate", help="Generate schedule files into schedules/")
    gen.add_argument("--target", help="Target name")
    gen.add_argument("--agent", help="Agent name")
    gen.add_argument("--platform", choices=["auto", "launchd", "systemd", "darwin", "linux", "all"], default="auto")

    inst = sub.add_parser("install", help="Install and enable schedule")
    inst.add_argument("--target", help="Target name")
    inst.add_argument("--agent", help="Agent name")
    inst.add_argument("--all", action="store_true", help="Install all configured schedules")
    inst.add_argument("--platform", choices=["auto", "launchd", "systemd", "darwin", "linux"], default="auto")

    uninst = sub.add_parser("uninstall", help="Disable and remove schedule")
    uninst.add_argument("--target", help="Target name")
    uninst.add_argument("--agent", help="Agent name")
    uninst.add_argument("--all", action="store_true", help="Uninstall all configured schedules")
    uninst.add_argument("--platform", choices=["auto", "launchd", "systemd", "darwin", "linux"], default="auto")

    trig = sub.add_parser("trigger", help="Trigger an immediate run of a loaded service")
    trig.add_argument("--target", required=True, help="Target name")
    trig.add_argument("--agent", required=True, help="Agent name")
    trig.add_argument("--platform", choices=["auto", "launchd", "systemd", "darwin", "linux"], default="auto")

    args = parser.parse_args()

    action = args.command
    if not action:
        if args.install:
            action = "install"
        elif args.uninstall:
            action = "uninstall"
        elif args.generate:
            action = "generate"
        elif args.trigger:
            action = "trigger"
        elif args.list:
            action = "list"
        else:
            action = "list"

    plat = getattr(args, "platform", "auto")

    success = True
    if action == "list":
        list_schedules(platform=plat)
    elif action == "generate":
        target_plat = normalize_platform(plat)
        candidates = get_scheduled_candidates(args.target, args.agent)
        for c in candidates:
            if target_plat == "all":
                p1 = generate_plist(c["target"], c["agent"], c["cadence"])
                p2, p3 = generate_systemd_units(c["target"], c["agent"], c["cadence"])
                print(f"Generated (launchd): {p1}")
                print(f"Generated (systemd): {p2}, {p3}")
            elif target_plat == "darwin":
                p = generate_plist(c["target"], c["agent"], c["cadence"])
                print(f"Generated (launchd): {p}")
            else:
                s, t = generate_systemd_units(c["target"], c["agent"], c["cadence"])
                print(f"Generated (systemd): {s}, {t}")
    elif action == "install":
        if getattr(args, "all", False):
            for item in get_scheduled_candidates():
                if not install_schedule(item["target"], item["agent"], platform=plat):
                    success = False
        elif args.target and args.agent:
            if not install_schedule(args.target, args.agent, platform=plat):
                success = False
        else:
            print("Specify --target <name> --agent <name> or --all")
            success = False
    elif action == "uninstall":
        if getattr(args, "all", False):
            for item in get_scheduled_candidates():
                if not uninstall_schedule(item["target"], item["agent"], platform=plat):
                    success = False
        elif args.target and args.agent:
            if not uninstall_schedule(args.target, args.agent, platform=plat):
                success = False
        else:
            print("Specify --target <name> --agent <name> or --all")
            success = False
    elif action == "trigger":
        if not trigger_schedule(args.target, args.agent, platform=plat):
            success = False

    if not success:
        sys.exit(1)
