#!/usr/bin/env python3
"""Static documentation site generator for The Software Factory.

Generates and updates the designated regions in docs/*.html from
repository declarations (agents/*/agent.yaml, lines/*.yaml, factory CLI tree,
and installation contracts).

Stdlib-only Python 3 (stdlib-only fail-closed YAML parser; no external dependencies).
Follows docs/DESIGN.md.
"""

import argparse
import html
import importlib.machinery
import importlib.util
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

# Valid enums per AGENTS.md / THREAT_MODEL.md
VALID_CLASSES = {"observer", "proposer", "optimizer"}
VALID_PLANES = {"local", "ci", "both"}
VALID_CONTAINMENTS = {"t0-readonly", "t1-fetch", "t2-local", "t3-sandbox"}

ACTION_PIN = "57d2a2951567973da7637b9016c0c5e67ad7a73d"
SLUG_RE = re.compile(r"^[a-z0-9-]+$")

PAGES = ("index.html", "install.html", "use.html", "stations.html", "lines.html", "help.html")
PAGE_MARKERS: Dict[str, Tuple[str, ...]] = {
    "index.html": ("quickstart",),
    "install.html": (
        "install-prerequisites",
        "install-local",
        "install-auth",
        "install-action",
        "install-extras",
    ),
    "use.html": ("cli-reference",),
    "stations.html": ("stations",),
    "lines.html": ("lines",),
    "help.html": (),
}


def _parse_scalar(val: str, path: Path, lineno: int) -> Any:
    v = val.strip()
    if not v:
        return ""
    if v.lower() == "true":
        return True
    if v.lower() == "false":
        return False
    if v.isdigit() or (v.startswith("-") and v[1:].isdigit()):
        return int(v)
    try:
        return float(v)
    except ValueError:
        pass
    if v.startswith('"'):
        if not v.endswith('"') or len(v) < 2:
            raise ValueError(f"YAML parse error in {path}:{lineno}: unclosed double quote: {val}")
        return v[1:-1]
    if v.startswith("'"):
        if not v.endswith("'") or len(v) < 2:
            raise ValueError(f"YAML parse error in {path}:{lineno}: unclosed single quote: {val}")
        return v[1:-1]
    if v.startswith(("&", "*", "|", ">", "!", "%", "@", "`")):
        raise ValueError(f"YAML parse error in {path}:{lineno}: unsupported YAML construct: {val}")
    return v


def load_yaml(path: Path) -> Dict[str, Any]:
    """Parse YAML manifest using stdlib-only parser that fails closed on unsupported or malformed constructs."""
    result: Dict[str, Any] = {}
    stack: list = [(-1, result, "root")]

    for lineno, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if "\t" in raw_line:
            raise ValueError(f"YAML parse error in {path}:{lineno}: tabs are forbidden")
        line = raw_line.split("#", 1)[0]
        line_clean = line.strip()
        if not line_clean:
            continue

        indent = len(line) - len(line.lstrip(" "))
        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()

        parent_indent, parent, parent_name = stack[-1]

        if line_clean.startswith("- "):
            val_str = line_clean[2:].strip()
            # If parent was an empty dict placeholder created for a block list under mapping key
            if isinstance(parent, dict) and len(parent) == 0 and len(stack) >= 2:
                outer_indent, outer_dict, _ = stack[-2]
                if isinstance(outer_dict, dict):
                    for k in reversed(list(outer_dict.keys())):
                        if outer_dict[k] is parent:
                            new_list = [_parse_scalar(val_str, path, lineno)]
                            outer_dict[k] = new_list
                            stack[-1] = (parent_indent, new_list, k)
                            break
                    else:
                        raise ValueError(f"YAML parse error in {path}:{lineno}: orphan list item: {raw_line}")
                else:
                    raise ValueError(f"YAML parse error in {path}:{lineno}: invalid list context: {raw_line}")
            elif isinstance(parent, list):
                parent.append(_parse_scalar(val_str, path, lineno))
            else:
                raise ValueError(
                    f"YAML parse error in {path}:{lineno}: list item in non-list context ({type(parent).__name__}): {raw_line}"
                )
            continue

        if ":" in line_clean:
            parts = line_clean.split(":", 1)
            key = parts[0].strip()
            val = parts[1].strip()

            if not key or not re.match(r"^[a-zA-Z0-9_-]+$", key):
                raise ValueError(f"YAML parse error in {path}:{lineno}: invalid key name: {key!r}")

            if not isinstance(parent, dict):
                raise ValueError(
                    f"YAML parse error in {path}:{lineno}: mapping key {key!r} inside {type(parent).__name__}: {raw_line}"
                )

            if not val:
                new_map: Dict[str, Any] = {}
                parent[key] = new_map
                stack.append((indent, new_map, key))
            elif val.startswith("[") and val.endswith("]"):
                inner = val[1:-1].strip()
                if not inner:
                    parent[key] = []
                else:
                    items = [_parse_scalar(x.strip(), path, lineno) for x in inner.split(",") if x.strip()]
                    parent[key] = items
            elif val.startswith("[") or val.endswith("]"):
                raise ValueError(f"YAML parse error in {path}:{lineno}: malformed flow sequence: {val}")
            elif val.startswith("{") or val.endswith("}"):
                raise ValueError(f"YAML parse error in {path}:{lineno}: flow mappings not supported: {val}")
            else:
                parent[key] = _parse_scalar(val, path, lineno)
            continue

        # Non-empty, non-comment line that does not start with '- ' and lacks ':' must fail closed
        raise ValueError(f"YAML parse error in {path}:{lineno}: unparseable construct: {raw_line}")

    return result


def get_agents(repo_root: Path) -> List[Dict[str, Any]]:
    """Discover, validate and sort all agent manifests in agents/*/agent.yaml."""
    agents_dir = repo_root / "agents"
    if not agents_dir.is_dir():
        raise RuntimeError(f"Agents directory not found: {agents_dir}")

    agents = []
    for manifest_path in sorted(agents_dir.glob("*/agent.yaml")):
        dirname = manifest_path.parent.name
        data = load_yaml(manifest_path)
        name = data.get("name")
        if not name or name != dirname:
            raise ValueError(f"Agent manifest name '{name}' does not match directory '{dirname}'")
        if not SLUG_RE.match(name):
            raise ValueError(f"Agent name '{name}' is not a valid slug ([a-z0-9-]+)")

        agent_class = data.get("class")
        if agent_class not in VALID_CLASSES:
            raise ValueError(f"Agent '{name}' has invalid class '{agent_class}' (expected {VALID_CLASSES})")

        plane = data.get("plane")
        if isinstance(plane, list):
            for p in plane:
                if p not in VALID_PLANES:
                    raise ValueError(f"Agent '{name}' has invalid plane entry '{p}'")
        elif isinstance(plane, str):
            if plane not in VALID_PLANES:
                raise ValueError(f"Agent '{name}' has invalid plane '{plane}'")
        else:
            raise ValueError(f"Agent '{name}' missing valid plane declaration")

        containment = data.get("containment")
        if containment not in VALID_CONTAINMENTS:
            raise ValueError(f"Agent '{name}' has invalid containment '{containment}'")

        summary = data.get("summary")
        if not summary or not isinstance(summary, str):
            raise ValueError(f"Agent '{name}' missing summary string")

        caps = data.get("capabilities", {})
        if not isinstance(caps, dict):
            raise ValueError(f"Agent '{name}' capabilities must be a mapping")

        agents.append({
            "name": name,
            "class": agent_class,
            "plane": plane,
            "containment": containment,
            "summary": summary,
            "capabilities": {
                "write": bool(caps.get("write", False)),
                "network": bool(caps.get("network", False)),
                "browser": bool(caps.get("browser", False)),
                "requires": list(caps.get("requires") or []),
            },
        })

    return sorted(agents, key=lambda a: a["name"])


def get_lines(repo_root: Path, known_agent_names: Set[str]) -> List[Dict[str, Any]]:
    """Discover, validate and sort all Factory Lines in lines/*.yaml."""
    lines_dir = repo_root / "lines"
    if not lines_dir.is_dir():
        raise RuntimeError(f"Lines directory not found: {lines_dir}")

    lines = []
    for line_path in sorted(lines_dir.glob("*.yaml")):
        stem = line_path.stem
        data = load_yaml(line_path)
        name = data.get("name")
        if not name or name != stem:
            raise ValueError(f"Line manifest name '{name}' does not match file stem '{stem}'")
        if not SLUG_RE.match(name):
            raise ValueError(f"Line name '{name}' is not a valid slug ([a-z0-9-]+)")

        summary = data.get("summary")
        if not summary or not isinstance(summary, str):
            raise ValueError(f"Line '{name}' missing summary string")

        stations = data.get("stations", [])
        if not isinstance(stations, list) or not stations:
            raise ValueError(f"Line '{name}' must declare a non-empty list of stations")

        for station_name in stations:
            if station_name not in known_agent_names:
                raise ValueError(f"Line '{name}' references unknown station '{station_name}'")

        lines.append({
            "name": name,
            "summary": summary,
            "stations": list(stations),  # Preserve declared order!
            "andon_halt_on_critical": bool(data.get("andon_halt_on_critical", False)),
            "andon_halt_on_failure": bool(data.get("andon_halt_on_failure", False)),
            "andon_stations": list(data.get("andon_stations") or []),
        })

    return sorted(lines, key=lambda l: l["name"])


def format_action_options(actions: List[Any]) -> List[str]:
    items = []
    for a in actions:
        if a.dest == "help":
            continue
        if a.option_strings:
            opts = ", ".join(a.option_strings)
            if a.choices:
                opts += f" {{{','.join(a.choices)}}}"
            elif a.nargs != 0 and a.dest:
                opts += f" {a.metavar or a.dest.upper()}"
        else:
            opts = a.metavar or a.dest
        items.append((opts, a.help or ""))

    if not items:
        return []

    lines = []
    max_len = min(24, max(len(opt) for opt, _ in items))
    for opt, h in items:
        if not h:
            lines.append(f"  {opt}")
        elif len(opt) <= max_len:
            lines.append(f"  {opt:<{max_len}}  {h}")
        else:
            lines.append(f"  {opt}")
            lines.append(f"  {' ':<{max_len}}  {h}")
    return lines


def format_parser_block(p: argparse.ArgumentParser) -> str:
    lines = []
    usage = p.format_usage().strip()
    lines.append(usage)

    pos_actions = [
        a for a in p._actions
        if not a.option_strings and a.dest != "help" and not isinstance(a, argparse._SubParsersAction)
    ]
    opt_actions = [
        a for a in p._actions
        if a.option_strings and a.dest != "help"
    ]
    subp_actions = [
        a for a in p._actions
        if isinstance(a, argparse._SubParsersAction)
    ]

    if pos_actions:
        lines.append("")
        lines.append("positional arguments:")
        lines.extend(format_action_options(pos_actions))

    if subp_actions:
        for sa in subp_actions:
            sub_items = []
            for name in sa.choices:
                h = ""
                for ca in getattr(sa, "_choices_actions", []):
                    if ca.dest == name:
                        h = ca.help or ""
                sub_items.append((name, h))
            if sub_items:
                lines.append("")
                lines.append("subcommands:")
                max_len = min(24, max(len(n) for n, _ in sub_items))
                for name, h in sub_items:
                    lines.append(f"  {name:<{max_len}}  {h}" if h else f"  {name}")

    if opt_actions:
        lines.append("")
        lines.append("options:")
        lines.extend(format_action_options(opt_actions))

    return "\n".join(lines)


def format_command_reference(cmd_parser: argparse.ArgumentParser) -> str:
    blocks = [format_parser_block(cmd_parser)]

    for a in cmd_parser._actions:
        if isinstance(a, argparse._SubParsersAction):
            for sub_name, sub_p in a.choices.items():
                blocks.append(format_parser_block(sub_p))

    return "\n\n".join(blocks)


def get_cli_commands(repo_root: Path) -> List[Dict[str, Any]]:
    """Extract CLI subcommands, usage, options and choices directly from factory argparse tree."""
    factory_path = repo_root / "factory"
    if not factory_path.is_file():
        raise RuntimeError(f"Factory CLI script not found at {factory_path}")

    loader = importlib.machinery.SourceFileLoader("factory_mod", str(factory_path))
    spec = importlib.util.spec_from_loader("factory_mod", loader)
    if not spec:
        raise RuntimeError("Failed to create module spec for factory")
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)

    if not hasattr(mod, "build_parser"):
        raise RuntimeError("factory script must provide build_parser() function")

    parser = mod.build_parser(prog="./factory")
    subp_actions = [a for a in parser._actions if isinstance(a, mod.argparse._SubParsersAction)]
    if not subp_actions:
        raise RuntimeError("No subparsers found in factory CLI parser")

    subp_action = subp_actions[0]
    expected_commands = [
        "integrate", "list", "promote", "run", "line",
        "hillclimb", "hook", "skills", "schedule"
    ]

    choices = subp_action.choices
    for cmd in expected_commands:
        if cmd not in choices:
            raise RuntimeError(f"Expected subcommand '{cmd}' missing from factory argparse tree")

    help_map = {}
    for ca in subp_action._choices_actions:
        help_map[ca.dest] = ca.help

    commands = []
    for name in expected_commands:
        subp = choices[name]
        desc = help_map.get(name, "")
        code = format_command_reference(subp)
        commands.append({
            "name": name,
            "description": desc,
            "code": code,
        })

    return commands


# ---------------------------------------------------------------------------
# Region Renderers
# ---------------------------------------------------------------------------

def render_quickstart(agents: List[Dict[str, Any]]) -> str:
    """Render GENERATED:quickstart."""
    runnable = [a for a in agents if a["containment"] == "t0-readonly" and a["class"] == "observer"]
    if not runnable:
        return '<p class="callout"><a href="install.html">Install the factory</a> to get started.</p>'
    sample_station = "secret-scan" if any(a["name"] == "secret-scan" for a in runnable) else runnable[0]["name"]
    return (
        "<pre><code>git clone https://github.com/PaulKinlan/agents.git\n"
        "cd agents\n"
        "./install.sh\n"
        "./factory list\n"
        f"./factory run {sample_station} --target . --sink file</code></pre>"
    )


def render_install_prerequisites() -> str:
    """Render GENERATED:install-prerequisites."""
    return (
        "<ul>"
        "<li>Python 3.9+ and Git.</li>"
        "<li>At least one installed, authenticated AI CLI: <code>pi</code>, <code>claude</code> or <code>antigravity</code>. "
        'Engine availability and containment rules vary; check <a href="help.html#boundaries">boundaries</a>.</li>'
        "<li><code>bd</code> is optional for a configured Beads sink; <code>gh</code> is optional for GitHub issue input and promotion.</li>"
        "</ul>"
    )


def render_install_local() -> str:
    """Render GENERATED:install-local."""
    return (
        "<pre><code>git clone https://github.com/PaulKinlan/agents.git\n"
        "cd agents\n"
        "./install.sh\n"
        "./factory list\n"
        "./factory --agent</code></pre>"
        "<p>No <code>--version</code> flag is provided. Use <code>./factory --help</code> to inspect installed commands.</p>"
    )


def render_install_auth() -> str:
    """Render GENERATED:install-auth."""
    return (
        "<p>Local runs reuse your authenticated CLI session. For headless action runs, supply the provider key as a GitHub Actions secret "
        "via <code>model_api_key</code> (Gemini or Anthropic); DeepSeek uses <code>deepseek_api_key</code>. "
        "Provider environment variables include <code>GEMINI_API_KEY</code>, <code>ANTHROPIC_API_KEY</code> and <code>DEEPSEEK_API_KEY</code>. "
        "Never store keys in a workflow file or the site.</p>"
        '<div class="callout callout--warning"><strong>Choose a boundary you can verify.</strong>'
        "<p>On Linux, <code>pi</code> requires a working bubblewrap sandbox unless an explicitly trusted private target opts into the exceptional unsandboxed path. "
        "Do not treat an agent prompt as confinement.</p></div>"
    )


def render_install_action(repo_root: Path) -> str:
    """Render GENERATED:install-action with pinned commit and input contract."""
    # Verify commit exists in git
    res = subprocess.run(
        ["git", "cat-file", "-e", f"{ACTION_PIN}^{{commit}}"],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        raise ValueError(f"Action pin commit {ACTION_PIN} not found in repository history")

    return (
        "<p>Pin both the action and fetched factory payload to reviewed 40-character commits. "
        "Give the job only the permissions it needs. The full workflow and its current pin belong in "
        '<a href="https://github.com/PaulKinlan/agents/blob/main/docs/INTEGRATION.md">INTEGRATION.md</a>.</p>'
        f"<pre><code># In your workflow, after actions/checkout:\n"
        f"- uses: paulkinlan/agents/.github/actions/factory@{ACTION_PIN}\n"
        f"  with:\n"
        f"    agent: secret-scan\n"
        f"    target: '.'\n"
        f"    sink: file\n"
        f"    factory_ref: {ACTION_PIN}\n"
        f"    model_api_key: ${{{{ secrets.GEMINI_API_KEY }}}}</code></pre>"
        "<p>Set <code>permissions: contents: read</code> by default. Use a write permission only for an approved workflow that requires it. "
        "The action uploads a full report as an authenticated artifact and uses a reduced step summary; "
        "do not copy raw report content into a public page.</p>"
    )


def render_install_extras(commands: List[Dict[str, Any]]) -> str:
    """Render GENERATED:install-extras."""
    cmd_names = {c["name"] for c in commands}
    cards = []
    if "hook" in cmd_names:
        cards.append(
            '<article class="card"><h3>Pre-commit</h3>'
            "<p>Install the fast deterministic hook. Blocking hooks do not invoke models.</p>"
            "<pre><code>./factory hook install --target .</code></pre></article>"
        )
    if "skills" in cmd_names:
        cards.append(
            '<article class="card"><h3>Interactive skills</h3>'
            "<p>Link the factory skills into supported local CLI skill directories.</p>"
            "<pre><code>./factory skills install</code></pre></article>"
        )
    if "schedule" in cmd_names:
        cards.append(
            '<article class="card"><h3>Recurring runs</h3>'
            "<p>Inspect registered schedules before installing any.</p>"
            "<pre><code>./factory schedule list</code></pre></article>"
        )

    if not cards:
        return '<p class="callout">No optional integrations available.</p>'

    return f'<div class="card-grid">{"".join(cards)}</div>'


def render_cli_reference(commands: List[Dict[str, Any]]) -> str:
    """Render GENERATED:cli-reference."""
    if not commands:
        return '<p class="callout">No CLI commands declared.</p>'

    articles = []
    for cmd in commands:
        name = html.escape(cmd["name"], quote=True)
        desc = html.escape(cmd["description"])
        code = html.escape(cmd["code"])
        articles.append(
            f'<article class="command">'
            f'<h3 id="cmd-{name}"><code>{name}</code></h3>'
            f'<p>{desc}</p>'
            f'<pre><code>{code}</code></pre>'
            f'</article>'
        )

    return "\n".join(articles)


def render_stations(agents: List[Dict[str, Any]]) -> str:
    """Render GENERATED:stations."""
    if not agents:
        return '<p class="callout">No stations declared.</p>'

    articles = []
    for agent in agents:
        name = html.escape(agent["name"], quote=True)
        agent_class = html.escape(agent["class"], quote=True)
        summary = html.escape(agent["summary"])
        containment = html.escape(agent["containment"])

        plane = agent["plane"]
        plane_str = ", ".join(plane) if isinstance(plane, list) else str(plane)
        plane_escaped = html.escape(plane_str)

        caps = agent["capabilities"]
        enabled_caps = []
        if caps.get("write"):
            enabled_caps.append("write")
        if caps.get("network"):
            enabled_caps.append("network")
        if caps.get("browser"):
            enabled_caps.append("browser")
        cap_text = ", ".join(enabled_caps) if enabled_caps else "read-only"
        cap_escaped = html.escape(cap_text)

        reqs = caps.get("requires") or []
        req_text = ", ".join(reqs) if reqs else "None declared"
        req_escaped = html.escape(req_text)

        articles.append(
            f'<article class="station" data-class="{agent_class}">'
            f'<h3 id="station-{name}">{name}</h3>'
            f'<p>{summary}</p>'
            f'<ul class="meta" aria-label="Class, plane and containment">'
            f'<li>{agent_class}</li>'
            f'<li>{plane_escaped}</li>'
            f'<li>{containment}</li>'
            f'</ul>'
            f'<dl>'
            f'<dt>Capability</dt><dd>{cap_escaped}</dd>'
            f'<dt>Requires</dt><dd>{req_escaped}</dd>'
            f'</dl>'
            f'</article>'
        )

    return f'<div class="station-grid">\n{"".join(articles)}\n</div>'


def render_lines(lines: List[Dict[str, Any]]) -> str:
    """Render GENERATED:lines."""
    if not lines:
        return '<p class="callout">No Factory Lines declared.</p>'

    cards = []
    for line in lines:
        name = html.escape(line["name"], quote=True)
        summary = html.escape(line["summary"])
        stations = line["stations"]
        count = len(stations)
        kicker_text = f"Factory Line · {count} {'stations' if count != 1 else 'station'}"

        items = []
        for s in stations:
            s_esc = html.escape(s, quote=True)
            items.append(f'<li><a href="stations.html#station-{s_esc}">{s_esc}</a></li>')
        ordered_list = f"<ol>{''.join(items)}</ol>"

        halt_crit = "halt" if line["andon_halt_on_critical"] else "continue"
        halt_fail = "halt" if line["andon_halt_on_failure"] else "continue as incomplete"
        andon_stations = line.get("andon_stations") or []
        guarded_part = ""
        if andon_stations:
            guarded_escaped = html.escape(", ".join(andon_stations))
            guarded_part = f" Guarded stations: {guarded_escaped}."

        policy_text = (
            f'<p class="policy"><strong>Andon policy:</strong> '
            f'Critical: {halt_crit}. Genuine failure: {halt_fail}.{guarded_part}</p>'
        )

        cards.append(
            f'<article class="line-card">'
            f'<p class="kicker">{kicker_text}</p>'
            f'<h3 id="line-{name}">{name}</h3>'
            f'<p>{summary}</p>'
            f'<h4>Ordered stations</h4>'
            f'{ordered_list}'
            f'{policy_text}'
            f'</article>'
        )

    return f'<div class="line-grid">\n{"".join(cards)}\n</div>'


# ---------------------------------------------------------------------------
# Core Generation & Fail-Closed Validation
# ---------------------------------------------------------------------------

def replace_region(content: str, marker_name: str, new_inner: str) -> str:
    """Replace content between markers, preserving markers and editorial text outside."""
    begin_marker = f"<!-- BEGIN GENERATED:{marker_name} -->"
    end_marker = f"<!-- END GENERATED:{marker_name} -->"

    b_count = content.count(begin_marker)
    e_count = content.count(end_marker)

    if b_count != 1 or e_count != 1:
        raise ValueError(
            f"Marker count error for '{marker_name}': begin count={b_count}, end count={e_count} (must be exactly 1 each)"
        )

    b_idx = content.index(begin_marker)
    e_idx = content.index(end_marker)

    if b_idx > e_idx:
        raise ValueError(f"Malformed markers: '{begin_marker}' appears after '{end_marker}'")

    prefix = content[: b_idx + len(begin_marker)]
    suffix = content[e_idx:]
    return f"{prefix}\n{new_inner}\n{suffix}"


def validate_safety(text: str, filename: str) -> None:
    """Safety checks: public site must not leak host paths, runs, findings, or secrets."""
    forbidden_patterns = [
        (r"/(?:home|Users|root)/[^\s<>\"'`]+", "Host user filesystem path (/home, /Users, /root)"),
        (r"/tmp/[^\s<>\"'`]+", "Host /tmp temporary path"),
        (r"targets/[\w.-]+\.yaml", "Internal target manifest path"),
        (r"findings/[\w.-]+\.json", "Internal findings store file path"),
        (r"runs/[\w.-]+/", "Internal run directory path"),
        (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token"),
        (r"sk-[A-Za-z0-9_-]{20,}", "API secret token"),
    ]
    for pattern, label in forbidden_patterns:
        m = re.search(pattern, text)
        if m:
            raise ValueError(f"Security constraint violation in {filename}: found {label} ({m.group(0)})")


def generate_all(repo_root: Path = ROOT, docs_dir: Path = DOCS) -> Dict[str, str]:
    """Execute site generation and return the new contents for all docs pages."""
    agents = get_agents(repo_root)
    agent_names = {a["name"] for a in agents}
    lines = get_lines(repo_root, agent_names)
    commands = get_cli_commands(repo_root)

    fill_map: Dict[str, str] = {
        "quickstart": render_quickstart(agents),
        "install-prerequisites": render_install_prerequisites(),
        "install-local": render_install_local(),
        "install-auth": render_install_auth(),
        "install-action": render_install_action(repo_root),
        "install-extras": render_install_extras(commands),
        "cli-reference": render_cli_reference(commands),
        "stations": render_stations(agents),
        "lines": render_lines(lines),
    }

    results: Dict[str, str] = {}

    for filename, markers in PAGE_MARKERS.items():
        page_path = docs_dir / filename
        if not page_path.is_file():
            raise FileNotFoundError(f"Documentation page not found: {page_path}")

        content = page_path.read_text(encoding="utf-8")
        updated = content

        for marker in markers:
            if marker not in fill_map:
                raise KeyError(f"No renderer defined for marker '{marker}'")
            updated = replace_region(updated, marker, fill_map[marker])

        validate_safety(updated, filename)
        results[filename] = updated

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Software Factory site generator")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check whether generated site is fresh without writing changes (exit 1 if dirty)",
    )
    args = parser.parse_args()

    try:
        new_pages = generate_all(ROOT, DOCS)
    except Exception as e:
        sys.stderr.write(f"Generation failed closed: {e}\n")
        return 1

    dirty = False
    for filename, new_content in new_pages.items():
        page_path = DOCS / filename
        current_content = page_path.read_text(encoding="utf-8")
        if current_content != new_content:
            dirty = True
            if not args.check:
                page_path.write_text(new_content, encoding="utf-8")

    if args.check and dirty:
        sys.stderr.write("Generated documentation is stale or uncommitted.\n")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
