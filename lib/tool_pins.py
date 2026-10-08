#!/usr/bin/env python3
"""Integrity-pinned resolution of the factory's host-side trusted tools (agents-7bj).

The factory is the highest-privilege component in a run: it resolves its trusted tools
(``gh``, ``bd``, ``git``, ``semgrep``, ``gitleaks``, ``node``/``npm``/``npx``) by *name*
across ``PATH`` and executes them host-side for the pre-pass, the findings dispatch and bead
promotion. A trojaned binary earlier on ``PATH`` — or a hijacked install tree — would run
with the factory's GitHub token and write access, and because these tools are the audit's own
ground truth a compromised one can both fake evidence and act on it (threat-model
``tm-external-tool-integrity``).

So each trusted tool is resolved to an **absolute path** and pinned by **SHA-256** from
factory configuration (``tools.yaml`` under ``FACTORY_ROOT``). Resolution is:

1. pin ``path`` if configured, else ``shutil.which(name, path=PATH)``;
2. the real file's SHA-256 is computed;
3. a configured ``path`` or ``sha256`` that does not match the resolved binary raises
   ``ToolPinError`` — the run fails closed rather than executing an unverified tool.

A tool with no pin entry still resolves by name (backward compatible), but the *child* PATH
used for the findings dispatch is then rebuilt from the resolved tools' directories, so the
dispatch never relies on the inherited ``PATH`` order to find ``gh``/``bd``.
"""

import hashlib
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

FACTORY_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = FACTORY_ROOT / "tools.yaml"

# Host-side tools the factory must resolve + (optionally) pin before it trusts them.
# `bd`/`git` are the findings store and the worktree/admin; `gh` fetches issues and drives
# promotion; `semgrep`/`gitleaks` and `node`/`npm`/`npx` are the pre-pass scanners.
TRUSTED_TOOLS: Tuple[str, ...] = ("gh", "bd", "git", "semgrep", "gitleaks", "node", "npm", "npx")


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


def load_tool_pins(path: Optional[Path] = None) -> Dict[str, Dict[str, str]]:
    """Parse ``tools.yaml`` into ``{tool: {path?, sha256?}}``.

    The format is a two-level map (a hand-rolled indent parser, so the findings child does
    not grow a PyYAML dependency):

        gh:
          path: /usr/bin/gh      # optional: absolute path the tool must resolve to
          sha256: <64 hex>       # optional: SHA-256 the binary must hash to

    A missing file is an empty pin set (nothing to enforce), never an error. A malformed
    entry — a non-string path/sha256, or a sha256 that is not 64 hex chars — raises
    ``ToolPinError`` so a bad pin cannot silently widen trust.
    """
    path = Path(path) if path is not None else CONFIG_PATH
    if not path.exists():
        return {}
    pins: Dict[str, Dict[str, str]] = {}
    current: Optional[str] = None
    for raw in path.read_text(encoding="utf-8").splitlines():
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
    # Validate what was read: a malformed pin must fail closed, not silently not-match.
    for tool, entry in pins.items():
        if not isinstance(entry, dict):
            raise ToolPinError(f"tools.yaml: {tool!r} entry is malformed")
        for key in ("path", "sha256"):
            value = entry.get(key)
            if value is not None and not isinstance(value, str):
                raise ToolPinError(f"tools.yaml: {tool}.{key} must be a string")
        sha = entry.get("sha256")
        if sha is not None and (len(sha) != 64 or any(c not in "0123456789abcdefABCDEF" for c in sha)):
            raise ToolPinError(f"tools.yaml: {tool}.sha256 must be 64 hex chars")
    return pins


def _resolve_candidate(name: str, pins: Dict[str, Dict[str, str]],
                       path_env: Optional[str]) -> Optional[str]:
    """The path to verify for `name`: the configured pin path, else `which` across PATH."""
    pinned_path = pins.get(name, {}).get("path")
    if pinned_path:
        return os.path.expanduser(pinned_path)
    return shutil.which(name, path=path_env)


def verify_pin(name: str, real_path: str,
               pins: Optional[Dict[str, Dict[str, str]]] = None) -> None:
    """Enforce `name`'s configured SHA-256 pin against an already-resolved ``real_path``.

    Raises ``ToolPinError`` when a configured ``sha256`` does not match the file's contents.
    Used by ``resolve_tool`` and by the sandbox binder (lib/sandbox.py ``_executable_binds``),
    which resolves launch paths itself and must authenticate each one before binding it. A
    tool with no sha256 pin verifies trivially (nothing to enforce). The ``path`` pin is a
    resolution concern, not a content check: ``resolve_tool`` prefers the configured path, so
    a name with a path pin never resolves elsewhere.
    """
    if pins is None:
        pins = load_tool_pins()
    pinned_sha = pins.get(name, {}).get("sha256")
    if pinned_sha is None:
        return
    actual = sha256_file(Path(real_path))
    if actual.lower() != pinned_sha.lower():
        raise ToolPinError(
            f"trusted tool {name!r} at {real_path} hashes to {actual[:16]}…, not the configured "
            f"pin {pinned_sha[:16]}… — refusing to run an unverified binary")


def resolve_tool(name: str, path_env: Optional[str] = None,
                 pins: Optional[Dict[str, Dict[str, str]]] = None) -> str:
    """Resolve `name` to a trusted absolute path, enforcing any configured pin.

    Returns the real (symlink-resolved) absolute path of the binary. Raises ``ToolPinError``
    when the tool cannot be resolved, or when a configured ``path``/``sha256`` does not match
    the resolved binary. A tool with no pin entry resolves by name and is still returned by
    absolute path (so the caller never re-resolves it from PATH order later).
    """
    if pins is None:
        pins = load_tool_pins()
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
    """A PATH containing only the directories of the resolved tools in `names`.

    The findings-dispatch child resolves ``gh``/``bd`` by name; giving it this PATH (instead
    of the inherited operator PATH) means it cannot pick up a trojaned tool from an unrelated
    directory earlier on PATH. Resolution itself is pinned by ``resolve_tool``, so a name that
    cannot be verified raises instead of being silently dropped.
    """
    dirs: List[str] = []
    for name in names:
        d = tool_dir(name, path_env, pins)
        if d not in dirs:
            dirs.append(d)
    return os.pathsep.join(dirs)
