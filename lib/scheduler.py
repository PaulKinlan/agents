#!/usr/bin/env python3
"""Scheduler for Software Factory using macOS launchd User Agents.

Generates, installs, uninstalls, and monitors launchd plists for scheduled
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
LAUNCH_AGENTS_DIR = Path.home() / "Library" / "LaunchAgents"

def get_label(target: str, agent: str) -> str:
    """Standardized launchd service label."""
    return f"com.softwarefactory.{target}.{agent}"

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

            # Check if agent supports schedule trigger or target explicitly schedules it
            is_schedulable = "schedule" in triggers or ag in schedule_section
            if not is_schedulable:
                continue

            # Cadence: default to 86400 seconds (24h) if unspecified
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

def generate_plist(target: str, agent: str, cadence: Optional[Dict[str, Any]] = None) -> Path:
    """Generate launchd plist dictionary and write to schedules/."""
    SCHEDULES_DIR.mkdir(parents=True, exist_ok=True)
    runs_dir = FACTORY_ROOT / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)

    label = get_label(target, agent)
    plist_path = SCHEDULES_DIR / f"{label}.plist"

    cadence = cadence or {"interval": 86400}

    # Preserving path with all essential development tools
    user_path = os.environ.get("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
    user_home = os.environ.get("HOME", str(Path.home()))

    plist_data: Dict[str, Any] = {
        "Label": label,
        "ProgramArguments": [
            str(FACTORY_ROOT / "factory"),
            "run",
            agent,
            "--target",
            target
        ],
        "WorkingDirectory": str(FACTORY_ROOT),
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
        if "minute" in cadence:
            cal["Minute"] = int(cadence["minute"])
        plist_data["StartCalendarInterval"] = cal

    with open(plist_path, "wb") as fp:
        plistlib.dump(plist_data, fp)

    return plist_path

def get_loaded_services() -> Dict[str, Dict[str, str]]:
    """Query launchctl for active com.softwarefactory services."""
    try:
        res = subprocess.run(["launchctl", "list"], capture_output=True, text=True, check=True)
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

def list_schedules():
    candidates = get_scheduled_candidates()
    loaded = get_loaded_services()

    print("\nSoftware Factory Schedules:")
    print("=" * 80)
    print(f"{'TARGET':<20} {'AGENT':<15} {'CADENCE':<15} {'INSTALLED':<12} {'LOADED':<10} {'PID/STATUS'}")
    print("-" * 80)

    for item in candidates:
        label = item["label"]
        dest_plist = LAUNCH_AGENTS_DIR / f"{label}.plist"
        installed = "yes" if dest_plist.exists() else "no"
        is_loaded = "yes" if label in loaded else "no"
        status = "-"
        if label in loaded:
            info = loaded[label]
            status = f"pid={info['pid']}" if info['pid'] != "-" else f"last_exit={info['exit_status']}"

        cadence_str = f"interval={item['cadence'].get('interval')}s" if "interval" in item['cadence'] else f"at {item['cadence'].get('hour')}:{item['cadence'].get('minute', 0):02d}"
        print(f"{item['target']:<20} {item['agent']:<15} {cadence_str:<15} {installed:<12} {is_loaded:<10} {status}")

    print("=" * 80)

def install_schedule(target: str, agent: str):
    """Generate and register the agent with macOS launchd."""
    candidates = get_scheduled_candidates(target_filter=target, agent_filter=agent)
    if not candidates:
        print(f"Error: Target '{target}' and agent '{agent}' do not form a valid schedulable pair.")
        sys.exit(1)

    candidate = candidates[0]
    label = candidate["label"]
    plist_path = generate_plist(target, agent, candidate["cadence"])

    LAUNCH_AGENTS_DIR.mkdir(parents=True, exist_ok=True)
    dest_path = LAUNCH_AGENTS_DIR / f"{label}.plist"
    shutil.copyfile(plist_path, dest_path)

    # Unload first in case an older version was registered
    subprocess.run(["launchctl", "unload", "-w", str(dest_path)], capture_output=True, check=False)
    # Load and enable
    res = subprocess.run(["launchctl", "load", "-w", str(dest_path)], capture_output=True, text=True, check=False)
    if res.returncode == 0:
        print(f"✓ Installed and loaded schedule: {label}")
        print(f"  Plist: {dest_path}")
        print(f"  Cadence: {candidate['cadence']}")
    else:
        print(f"✗ Failed to load into launchctl: {res.stderr.strip()}")

def uninstall_schedule(target: str, agent: str):
    """Unload from launchctl and remove plist."""
    label = get_label(target, agent)
    dest_path = LAUNCH_AGENTS_DIR / f"{label}.plist"

    if dest_path.exists():
        subprocess.run(["launchctl", "unload", "-w", str(dest_path)], capture_output=True, check=False)
        dest_path.unlink()
        print(f"✓ Uninstalled schedule: {label}")
    else:
        print(f"Schedule not found in LaunchAgents: {label}")

def trigger_schedule(target: str, agent: str):
    """Trigger an immediate launchd run."""
    label = get_label(target, agent)
    res = subprocess.run(["launchctl", "start", label], capture_output=True, text=True, check=False)
    if res.returncode == 0:
        print(f"✓ Triggered immediate launchd execution for: {label}")
    else:
        print(f"✗ Failed to trigger {label}: {res.stderr.strip()}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Software Factory launchd Scheduler")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("list", help="List schedulable agents and current launchd status")

    gen = sub.add_parser("generate", help="Generate launchd plists into schedules/")
    gen.add_argument("--target", help="Target name")
    gen.add_argument("--agent", help="Agent name")

    inst = sub.add_parser("install", help="Install and load launchd plists into ~/Library/LaunchAgents")
    inst.add_argument("--target", required=True, help="Target name")
    inst.add_argument("--agent", required=True, help="Agent name")

    uninst = sub.add_parser("uninstall", help="Unload and remove launchd plist")
    uninst.add_argument("--target", required=True, help="Target name")
    uninst.add_argument("--agent", required=True, help="Agent name")

    trig = sub.add_parser("trigger", help="Trigger an immediate run of a loaded service")
    trig.add_argument("--target", required=True, help="Target name")
    trig.add_argument("--agent", required=True, help="Agent name")

    args = parser.parse_args()

    if args.command == "list" or not args.command:
        list_schedules()
    elif args.command == "generate":
        candidates = get_scheduled_candidates(args.target, args.agent)
        for c in candidates:
            p = generate_plist(c["target"], c["agent"], c["cadence"])
            print(f"Generated: {p}")
    elif args.command == "install":
        install_schedule(args.target, args.agent)
    elif args.command == "uninstall":
        uninstall_schedule(args.target, args.agent)
    elif args.command == "trigger":
        trigger_schedule(args.target, args.agent)
