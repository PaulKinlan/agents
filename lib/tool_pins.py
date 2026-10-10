#!/usr/bin/env python3
"""Integrity-pinned resolution of the factory's host-side trusted tools (agents-7bj).

The factory is the highest-privilege component in a run: it resolves its trusted tools
(``bwrap``, ``gh``, ``bd``, ``git``, ``semgrep``, ``gitleaks``, ``node``/``npm``/``npx``)
by *name* across ``PATH`` and executes them host-side for the pre-pass, the findings
dispatch, bead promotion — and, for ``bwrap``, the OS sandbox itself. A trojaned binary
earlier on ``PATH`` — or a hijacked install tree — would run with the factory's GitHub
token and write access, and because these tools are the audit's own ground truth a
compromised one can both fake evidence and act on it (threat-model
``tm-external-tool-integrity``). For ``bwrap`` the stakes are the boundary itself: a fake
``bwrap`` that execs its child natively satisfies every check the sandbox module can run
*through* it (agents-28nn), so the binary must be authenticated before it is executed.

So each trusted tool is resolved to an **absolute path** and pinned by **SHA-256** from
factory configuration (``tools.yaml`` under ``FACTORY_ROOT``):

1. the configured ``path`` (if set) is used, else the tool is found by name across PATH;
2. the real (symlink-resolved) file's SHA-256 is computed;
3. a configured ``path`` or ``sha256`` that does not match the resolved binary raises
   ``ToolPinError`` — the run fails closed rather than executing an unverified tool.

**Fail closed when unpinned.** A trusted tool that has no ``sha256`` pin is refused — a
silent fall back to PATH order is exactly the audit finding. The single exception is the
explicit, auditable dev/test opt-in ``FACTORY_ALLOW_UNPINNED_TOOLS=1``, which restores the
by-name fallback; it is never the default. A ``path`` pin without a matching ``sha256`` is a
configuration error (a symlink deref could otherwise redirect the pin outside the trusted
tree), so it is refused regardless of the opt-in.

**Every failure of the pin machinery is a ``ToolPinError``** (agents-28nn round 2): an
unreadable pins file, a directory where a file is expected, non-UTF-8 pins content, or a
binary that cannot be hashed all raise ``ToolPinError``, never a raw ``OSError`` — so a
caller that handles pin failures (lib/sandbox.py's probe degrading to "cannot sandbox",
the sinks' honest "tool unavailable" notes) cannot be crashed past by a filesystem error.

The sandbox binder (lib/sandbox.py ``_executable_binds``) calls ``verify_pin`` for each
pinned tool before binding it, so a pinned pre-pass tool is authenticated by the same rule.

**Out-of-band host pins (agents-3g6).** The repo ``tools.yaml`` is the default, but a repo
cannot carry host-specific hashes (every machine's binaries differ). A deployer points
``FACTORY_TOOL_PINS`` at a host-local file (e.g. ``/etc/factory/tools.pins.yaml`` or
``$HOME/.config/factory/tools.pins.yaml``) that is *merged over* ``tools.yaml`` — the host
file wins per tool. An unset env var or a missing host file leaves the repo pins as-is (so
the fail-closed default is unchanged); a *malformed* host file raises ``ToolPinError`` rather
than being silently ignored. Generate the file with ``tools/generate-tool-pins.sh``.
"""

import hashlib
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

FACTORY_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = FACTORY_ROOT / "tools.yaml"

# Env var naming a host-local pins file, merged OVER tools.yaml (agents-3g6). Host-specific
# hashes cannot live in the repo, so the fleet nightly runner, CI and downstream consumers
# generate one on the host and point this at it. Absent/unset = repo pins only (still
# fail-closed); a malformed file raises instead of being ignored.
HOST_PINS_ENV = "FACTORY_TOOL_PINS"

# The explicit dev/test opt-in that restores by-name resolution for an unpinned trusted tool.
# `_unpinned_allowed` reads it, and lib.child_env forwards it to the children that resolve a
# trusted tool themselves (findings dispatch, promotion) so a run that opted in parent-side does
# not fail its sink child closed (agents-7ua).
UNPINNED_ALLOW_ENV = "FACTORY_ALLOW_UNPINNED_TOOLS"

# Host-side tools the factory must resolve + pin before it trusts them.
# `bwrap` is the sandbox wrapper — the one binary whose integrity decides whether any
# sandbox exists at all (agents-28nn). `bd`/`git` are the findings store and the
# worktree/admin; `gh` fetches issues and drives promotion; `semgrep`/`gitleaks` and
# `node`/`npm`/`npx` are the pre-pass scanners.
TRUSTED_TOOLS: Tuple[str, ...] = ("bwrap", "gh", "bd", "git", "semgrep", "gitleaks",
                                  "node", "npm", "npx")

def _unpinned_allowed() -> bool:
    """The explicit, auditable dev/test opt-in: resolves unpinned trusted tools by name
    (PATH order). Real runs must pin every trusted tool in tools.yaml or fail closed."""
    return os.environ.get(UNPINNED_ALLOW_ENV, "").strip().lower() in (
        "1", "true", "yes", "on",
    )

# Standard system bin dirs a shimmed/wrapped tool's shebang needs (env, bash, sh). The
# findings-dispatch child PATH is rebuilt from the resolved tools' install trees PLUS these,
# so a `#!/usr/bin/env bash` wrapper still finds its interpreter without re-exposing arbitrary
# operator PATH directories (review P0-1, agents-7bj).
SYSTEM_BIN_DIRS: Tuple[str, ...] = (
    "/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin",
)


class ToolPinError(RuntimeError):
    """A trusted tool could not be resolved or did not match its configured pin. The station
    fails rather than executing an unverified binary."""


def sha256_file(path: Path) -> str:
    """SHA-256 of a file's contents, streamed (never loads a whole binary into memory)."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_pins_file(path: Path, label: str) -> Dict[str, Dict[str, str]]:
    """Parse one pins YAML file into ``{tool: {path?, sha256?}}``.

    A hand-rolled indent parser (so the findings child grows no PyYAML dependency) for a
    two-level map:

        gh:
          path: /usr/bin/gh      # optional: absolute path the tool must resolve to
          sha256: <64 hex>       # required for a trusted tool (the content/version pin)

    A missing file is an empty pin set — resolution then fails closed for any trusted tool, so
    a deleted config can never silently widen trust. A malformed entry — a non-string
    path/sha256, a sha256 that is not 64 hex chars, or a path pin without a sha256 — raises
    ``ToolPinError`` so a bad pin cannot silently not-match. A file that cannot be READ as
    pins — unreadable (chmod 000), a directory where a file is expected, non-UTF-8 bytes —
    raises the same ``ToolPinError`` rather than a raw ``OSError``/``PermissionError``
    escaping to a caller that only handles pin failures: lib/sandbox.py's probe must DEGRADE
    to "cannot sandbox" on any pin-machinery failure, never crash the factory (agents-28nn
    round 2, the unreadable-pins P2).
    """
    if not path.exists():
        return {}
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise ToolPinError(
            f"{label}: the pins file cannot be read as pins ({e}); failing closed rather "
            f"than guessing") from e
    pins: Dict[str, Dict[str, str]] = {}
    current: Optional[str] = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if indent == 0 and stripped.endswith(":"):
            current = stripped[:-1].strip()
            if current:
                pins.setdefault(current, {})
        elif indent > 0 and current is not None:
            if ":" in stripped:
                key, _, value = stripped.partition(":")
                key = key.strip()
                value = value.strip()
                if key in ("path", "sha256") and value:
                    pins[current][key] = value
    for tool, entry in pins.items():
        if not isinstance(entry, dict):
            raise ToolPinError(f"{label}: {tool!r} entry is malformed")
        for key in ("path", "sha256"):
            value = entry.get(key)
            if value is not None and not isinstance(value, str):
                raise ToolPinError(f"{label}: {tool}.{key} must be a string")
        sha = entry.get("sha256")
        if sha is not None and (len(sha) != 64 or any(c not in "0123456789abcdefABCDEF" for c in sha)):
            raise ToolPinError(f"{label}: {tool}.sha256 must be 64 hex chars")
        if entry.get("path") is not None and sha is None:
            raise ToolPinError(
                f"{label}: {tool}.path requires a matching {tool}.sha256 (a bare path pin "
                "can be redirected through a symlink)")
    return pins


def host_pins_path() -> Optional[Path]:
    """The host-local pins file named by ``FACTORY_TOOL_PINS`` (agents-3g6), or None."""
    raw = os.environ.get(HOST_PINS_ENV, "").strip()
    if not raw:
        return None
    return Path(os.path.expanduser(raw))


def load_tool_pins(path: Optional[Path] = None) -> Dict[str, Dict[str, str]]:
    """Load the effective pins: ``tools.yaml`` (or `path`) merged OVER by the host file.

    The repo ``tools.yaml`` (or `path`, for tests) is parsed first. If ``FACTORY_TOOL_PINS``
    names an existing host file, it is parsed and its per-tool entries REPLACE the repo's —
    the host file wins for every tool it defines, because only the host knows its own
    binaries' hashes. An unset env var or a missing host file leaves the repo pins unchanged
    (still fail-closed when unpinned); a malformed host file raises ``ToolPinError``.
    """
    repo = _parse_pins_file(Path(path) if path is not None else CONFIG_PATH, "tools.yaml")
    host = host_pins_path()
    if host is not None and host.exists():
        repo.update(_parse_pins_file(host, f"FACTORY_TOOL_PINS ({host})"))
    return repo


def _require_pin(name: str, entry: Dict[str, str]) -> None:
    """Fail closed when a trusted tool has no content pin, unless the dev opt-in is set.

    A trusted tool with no ``sha256`` would otherwise resolve by PATH order — the exact
    audit finding. The opt-in is explicit (``FACTORY_ALLOW_UNPINNED_TOOLS``), auditable, and
    never the default. A non-trusted name (bash/sh/env/python3) needs no pin.
    """
    if name not in TRUSTED_TOOLS:
        return
    if entry.get("sha256") is None and not _unpinned_allowed():
        raise ToolPinError(
            f"trusted tool {name!r} is not pinned (no {name}.sha256 in tools.yaml nor the "
            f"{HOST_PINS_ENV} host file); pin it, or set {UNPINNED_ALLOW_ENV}=1 to "
            "opt out explicitly for a dev/test run")


def _resolve_candidate(name: str, pins: Dict[str, Dict[str, str]],
                       path_env: Optional[str]) -> Optional[str]:
    """The path to verify for `name`: the configured pin path, else `which` across PATH."""
    pinned_path = pins.get(name, {}).get("path")
    if pinned_path:
        return os.path.expanduser(pinned_path)
    return shutil.which(name, path=path_env)


def verify_pin(name: str, real_path: str,
               pins: Optional[Dict[str, Dict[str, str]]] = None) -> None:
    """Enforce `name`'s configured pin against an already-resolved ``real_path``.

    Raises ``ToolPinError`` when the tool is unpinned (a trusted tool with no content pin and
    no dev opt-in), when a configured ``path`` does not match the resolved real path, or when
    a configured ``sha256`` does not match the file's contents. Used by ``resolve_tool`` and
    by the sandbox binder (lib/sandbox.py ``_executable_binds``), which resolves launch paths
    itself and must authenticate each one before binding it.
    """
    if pins is None:
        pins = load_tool_pins()
    entry = pins.get(name, {})
    _require_pin(name, entry)
    pinned_path = entry.get("path")
    if pinned_path is not None:
        if os.path.realpath(os.path.expanduser(pinned_path)) != os.path.realpath(real_path):
            raise ToolPinError(
                f"trusted tool {name!r} resolved to {real_path}, not the configured path "
                f"{pinned_path}")
    pinned_sha = entry.get("sha256")
    if pinned_sha is not None:
        try:
            actual = sha256_file(Path(real_path))
        except OSError as e:
            # A binary that cannot be read cannot be authenticated (agents-28nn round 2):
            # fail closed as a pin failure, never as a raw OSError escaping the machinery.
            raise ToolPinError(
                f"trusted tool {name!r} at {real_path} could not be hashed ({e}); refusing "
                "to run an unverified binary") from e
        if actual.lower() != pinned_sha.lower():
            raise ToolPinError(
                f"trusted tool {name!r} at {real_path} hashes to {actual[:16]}…, not the configured "
                f"pin {pinned_sha[:16]}… — refusing to run an unverified binary")


def resolve_tool(name: str, path_env: Optional[str] = None,
                 pins: Optional[Dict[str, Dict[str, str]]] = None) -> str:
    """Resolve `name` to a trusted absolute path, enforcing its pin.

    Returns the real (symlink-resolved) absolute path of the binary. Raises ``ToolPinError``
    when the tool is unpinned (a trusted tool with no content pin), cannot be resolved, or a
    configured ``path``/``sha256`` does not match. A non-trusted name resolves by name.
    """
    if pins is None:
        pins = load_tool_pins()
    entry = pins.get(name, {})
    _require_pin(name, entry)
    candidate = _resolve_candidate(name, pins, path_env)
    if candidate is None:
        raise ToolPinError(f"trusted tool {name!r} could not be resolved on PATH")
    real = os.path.realpath(candidate)
    if not os.path.isfile(real):
        raise ToolPinError(f"trusted tool {name!r} resolves to a non-file: {real}")
    verify_pin(name, real, pins)
    return real


def tool_dir(name: str, path_env: Optional[str] = None,
             pins: Optional[Dict[str, Dict[str, str]]] = None) -> str:
    """The directory holding the resolved `name` (the install-tree ``bin`` dir), for a PATH."""
    return str(Path(resolve_tool(name, path_env, pins)).parent)


def allowlisted_path(names: Sequence[str], path_env: Optional[str] = None,
                     pins: Optional[Dict[str, Dict[str, str]]] = None) -> str:
    """A PATH of the resolved tools' install trees plus the standard system bin dirs.

    The findings-dispatch child resolves ``gh``/``bd`` by name; giving it this PATH (instead
    of the inherited operator PATH) means it cannot pick up a trojaned tool from an unrelated
    directory earlier on PATH. Resolution itself is pinned by ``resolve_tool``, so a name that
    cannot be verified raises instead of being silently dropped. The system bin dirs are kept
    because a shimmed/wrapped tool (``#!/usr/bin/env bash``) needs its interpreter, and those
    are standard, trusted locations — never arbitrary operator PATH directories.
    """
    dirs: List[str] = []
    for name in names:
        d = tool_dir(name, path_env, pins)
        if d not in dirs:
            dirs.append(d)
    for d in SYSTEM_BIN_DIRS:
        if os.path.isdir(d) and d not in dirs:
            dirs.append(d)
    return os.pathsep.join(dirs)
