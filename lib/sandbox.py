#!/usr/bin/env python3
"""OS sandbox for the factory's children: bubblewrap on Linux (agents-9n7).

Before this module the factory had no OS sandbox: the engine process and the deterministic
pre-pass ran as the operator, with the operator's filesystem and network. Only the model's
*tools* were restricted, and pi's read tool is not path-confined, so a prompt-injected pi
session could read any file the operator can read (THREAT_MODEL.md section 6.1; verified
2026-09-26 with a canary at ``../outside/canary.txt``). Non-negotiable #2: a model is never
a containment boundary — so the boundary is now the kernel's, via bubblewrap(1).

What the sandbox does (allowlist, not denylist — everything unbound is invisible):

* **Target read-only.** The scanned checkout is ro-bound; the run directory is rw-bound so
  the adapter can write ``model_output.txt`` and the pre-pass can write ``candidates.json``.
  The factory root is ro-bound (adapter scripts, SKILL.md) with ``runs/`` masked, so one
  run's model session cannot read another run's raw scanner artifacts.
* **Credential stores hidden.** ``$HOME`` and the home roots (``/home``, ``/root``) are
  fresh tmpfs mounts: ``~/.pi/auth.json``, ``~/.aws``, ``~/.ssh``, ``~/.claude``,
  ``~/.config`` and everything else the operator's home holds do not exist inside. Engine
  auth reaches the sandbox the only way that does not give the read tool a file to open:
  environment variables, allowlisted per engine by lib/child_env.py.
* **No host /proc.** The sandbox runs in a private PID namespace with its own procfs:
  host processes, their cmdlines and their environments are invisible. The engine's own
  ``/proc/self/environ`` necessarily remains readable by its own read tool (bun/pi crashes
  without a real procfs — verified by strace), which is why credentials reach the engine
  only as the per-engine environment allowlist of lib/child_env.py, never as files, and
  why lib/redaction.py masks credential shapes in everything a run publishes. Removing
  even that channel needs a credential-broker proxy (follow-up bead).
* **Executables re-bound by resolution.** PATH directories outside the visible roots are
  ro-bound, and symlinks inside them are resolved to their package root (``bin/``-style
  directory names walked past), so launcher shims and versioned installs (nvm, ``~/.local``)
  work inside without binding whole home subtrees.

What it does NOT do, stated plainly because policy.json must never overclaim:

* **Egress is not filtered.** The engine must reach the model API and bwrap cannot
  allowlist hosts; ``network-egress`` stays in policy.json's not_enforced until an egress
  proxy exists. The model session has no network *tool* (read-only policy), so the open
  egress is the engine binary's own, not the model's.
* **Linux + bubblewrap only.** Elsewhere sandbox_available() is False and every banner and
  record keeps saying NOT confined (THREAT_MODEL.md section 7 accepts unsandboxed runs for
  trusted targets; the honesty is the point).

Engines are added to SANDBOXED_ENGINES only after their adapter is verified to run inside
the wrapper; an unlisted engine runs unsandboxed and its banner says so.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

BWRAP = "bwrap"
TOOL = "bubblewrap"

# Engines whose adapters are verified to run inside sandbox_command(). claude/antigravity
# need their session auth from $HOME, which the sandbox hides by design; deepseek is
# payload-only. pi authenticates from env keys (lib/child_env.py ENGINE_CREDENTIALS), so
# hiding $HOME costs it nothing (agents-9n7).
SANDBOXED_ENGINES = frozenset({"pi"})

# Directory names that are structural plumbing of an install tree, not the package itself:
# a resolved symlink's package root is the first ancestor that is not one of these.
_STRUCTURAL = frozenset({"bin", "sbin", "lib", "lib32", "lib64", "libx32", "libexec", "share"})

# Roots that hold user credentials and are therefore never bound, only tmpfs'd over.
_HIDDEN_ROOTS = ("/home", "/root")

# Hard cap on bind mounts: a pathological PATH must not produce an unbounded bwrap argv.
_MAX_BINDS = 96


class SandboxError(RuntimeError):
    """The sandbox was requested but cannot be built (too many binds, bwrap missing at
    wrap time). The station fails rather than running unsandboxed and overclaiming."""


_probe_result: Optional[bool] = None


def sandbox_available() -> bool:
    """Whether this host can actually run the bubblewrap sandbox. Cached; probed for real
    (an executable on PATH is not proof — unprivileged user namespaces may be disabled)."""
    global _probe_result
    if _probe_result is None:
        _probe_result = _probe()
    return _probe_result


def _probe() -> bool:
    if not sys.platform.startswith("linux"):
        return False
    bwrap = shutil.which(BWRAP)
    if not bwrap:
        return False
    plan = _BindPlan()
    _system_binds(plan)
    plan.dev("/dev")
    plan.tmpfs("/tmp")
    argv = [bwrap, *plan.argv, "--die-with-parent", "--new-session", "--", "/bin/true"]
    try:
        res = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return res.returncode == 0


def engine_sandboxed(engine: str) -> bool:
    """Whether runs of `engine` get the OS sandbox on this host."""
    return engine in SANDBOXED_ENGINES and sandbox_available()


def sandbox_record(engine: str) -> Optional[Dict[str, Any]]:
    """The machine-readable sandbox state for policy.json / the banner, or None when this
    host has no sandbox. `engine_sandboxed` says whether the engine session itself is
    inside it; the pre-pass is sandboxed whenever the host can sandbox at all."""
    if not sandbox_available():
        return None
    return {
        "tool": TOOL,
        "engine_sandboxed": engine in SANDBOXED_ENGINES,
        "prepass_sandboxed": True,
        "engine_read_scope": ("confined to the target directory by the OS sandbox "
                              "(bubblewrap bind mounts)"
                              if engine in SANDBOXED_ENGINES else None),
        "network_egress_filtered": False,
        "notes": ["host /proc invisible (private PID namespace); the engine's own "
                  "/proc/self/environ is readable by its own read tool, so engine API "
                  "keys reach it only via the lib/child_env.py allowlist and published "
                  "output is redacted (lib/redaction.py)"],
    }


def _system_binds(plan: "_BindPlan") -> None:
    """/usr and /etc read-only, with the merged-usr symlinks (or real binds) the host uses.
    /etc carries the CA certificates and resolver config TLS needs."""
    for directory in ("/usr", "/etc"):
        if os.path.isdir(directory):
            plan.ro_bind(directory)
    for name in ("bin", "sbin", "lib", "lib64"):
        link = f"/{name}"
        if os.path.islink(link):
            plan.symlink(os.readlink(link).lstrip("/"), link)
        elif os.path.isdir(link):
            plan.ro_bind(link)


class _BindPlan:
    """Ordered, deduplicated mounts. Order matters: tmpfs first, binds over it (bwrap
    allows nesting tmpfs and rw binds inside an earlier ro-bind — verified, agents-9n7).

    Visibility semantics: a path is `visible` only when it is inside a *bind* mount (the
    real content is there). A tmpfs ancestor hides content, so paths under it are NOT
    visible and must be bound explicitly; that is what makes `--tmpfs /home` plus targeted
    re-binds an allowlist.
    """

    def __init__(self) -> None:
        self.argv: List[str] = []
        self._mounts: List[Tuple[Path, str]] = []  # (path, kind): kind in tmpfs|ro|rw

    def _nearest(self, path: Path) -> Optional[str]:
        best: Optional[Path] = None
        kind: Optional[str] = None
        for mounted, mounted_kind in self._mounts:
            if (path == mounted or mounted in path.parents) and (
                    best is None or len(mounted.parts) > len(best.parts)):
                best, kind = mounted, mounted_kind
        return kind

    def tmpfs(self, path: str) -> None:
        target = Path(path)
        if any(m == target and k == "tmpfs" for m, k in self._mounts):
            return
        self.argv += ["--tmpfs", path]
        self._mounts.append((target, "tmpfs"))
        self._cap()

    def symlink(self, target: str, link: str) -> None:
        """A merged-usr style symlink; recorded as a read-only mount so paths under it are
        visible to the dedup logic."""
        self.argv += ["--symlink", target, link]
        self._mounts.append((Path(link), "ro"))
        self._cap()

    def dev(self, path: str) -> None:
        self.argv += ["--dev", path]
        self._mounts.append((Path(path), "ro"))
        self._cap()

    def ro_bind(self, source: str) -> None:
        self._bind(source, ro=True)

    def rw_bind(self, source: str) -> None:
        self._bind(source, ro=False)

    def _bind(self, source: str, ro: bool) -> None:
        path = Path(os.path.realpath(source))
        if not path.exists():
            return
        nearest = self._nearest(path)
        if ro and nearest in ("ro", "rw"):
            return  # already inside a bind with the real content
        self.argv += (["--ro-bind"] if ro else ["--bind"]) + [str(path), str(path)]
        self._mounts.append((path, "ro" if ro else "rw"))
        self._cap()

    def _cap(self) -> None:
        if len(self._mounts) > _MAX_BINDS:
            raise SandboxError(f"more than {_MAX_BINDS} mounts needed; refusing to run")

    def visible(self, path: str) -> bool:
        """Whether `path`'s real content is already inside the sandbox."""
        return self._nearest(Path(path)) in ("ro", "rw")


def _package_root(path: Path) -> Optional[Path]:
    """The install-tree root for a resolved executable: walk past bin/lib-style directory
    names (~/.local/pi/pi -> ~/.local/pi; .../node_modules/npm/bin/npm-cli.js -> .../npm).
    None when the walk escapes into a hidden root or the filesystem root — those are never
    bound whole."""
    current = path.parent if path.is_file() else path
    while current.name in _STRUCTURAL and current != current.parent:
        current = current.parent
    if current == current.parent:  # reached /
        return None
    for root in _HIDDEN_ROOTS:
        if str(current) == root:
            return None
    return current


def _path_binds(plan: _BindPlan, path_env: str) -> None:
    """Bind the PATH directories the child needs that are not otherwise visible, resolving
    symlinks inside them to their package roots so shim chains work (agents-9n7)."""
    for entry in path_env.split(os.pathsep):
        if not entry or not os.path.isdir(entry):
            continue
        if plan.visible(entry):
            continue
        plan.ro_bind(entry)
        try:
            entries = sorted(os.listdir(entry))
        except OSError:
            continue
        for name in entries:
            candidate = os.path.join(entry, name)
            if not os.path.islink(candidate):
                continue
            resolved = Path(os.path.realpath(candidate))
            if not resolved.exists() or plan.visible(str(resolved)):
                continue
            root = _package_root(resolved)
            if root is not None:
                plan.ro_bind(str(root))


def sandbox_command(
    inner: Sequence[str],
    *,
    target_dir: os.PathLike | str,
    factory_root: os.PathLike | str,
    run_dir: os.PathLike | str,
    env: Optional[Dict[str, str]] = None,
) -> List[str]:
    """Wrap `inner` (adapter or pre-pass argv) in a bubblewrap invocation.

    `env` is the child's environment (lib/child_env.py allowlist); its PATH decides which
    executable trees get re-bound. The child runs in a private PID namespace with a real
    procfs mounted inside it: bun/pi needs a genuine /proc/self (verified by strace), and
    the private namespace keeps every host process — and its environ — invisible.
    """
    bwrap = shutil.which(BWRAP)
    if not bwrap:
        raise SandboxError(f"{BWRAP} not found on PATH")
    if not inner:
        raise SandboxError("empty command")

    child_env = dict(os.environ if env is None else env)
    target = str(Path(target_dir).resolve())
    factory = str(Path(factory_root).resolve())
    runs = str(Path(run_dir).resolve())

    plan = _BindPlan()
    _system_binds(plan)
    plan.dev("/dev")
    plan.tmpfs("/tmp")

    # Hide the credential roots, then give $HOME back as an empty writable tmpfs so tools
    # that create dot-directories (pi, npm) work without any real home content.
    for root in _HIDDEN_ROOTS:
        if os.path.isdir(root):
            plan.tmpfs(root)
    # $HOME and TMPDIR always get their own tmpfs, even under a tmpfs'd home root: the
    # parent tmpfs is empty, so without this the path itself would not exist and tools
    # that write to $HOME or $TMPDIR would fail with ENOENT instead of working on a
    # private scratch space.
    home = child_env.get("HOME")
    if home and home.startswith("/") and home not in _HIDDEN_ROOTS:
        plan.tmpfs(home)
    tmpdir = child_env.get("TMPDIR")
    if tmpdir and tmpdir.startswith("/"):
        plan.tmpfs(tmpdir)

    # Factory root read-only (adapter scripts, SKILL.md), with other runs' artifacts masked
    # and this run's directory writable.
    plan.ro_bind(factory)
    factory_runs = Path(factory) / "runs"
    if factory_runs.is_dir():
        plan.tmpfs(str(factory_runs))
    plan.rw_bind(runs)

    # The target, read-only.
    plan.ro_bind(target)

    # Executables: the pre-pass interpreter and everything the child's PATH must find.
    interpreter = Path(sys.executable).resolve()
    if not plan.visible(str(interpreter)):
        root = _package_root(interpreter)
        if root is None:
            raise SandboxError(f"cannot expose the interpreter {interpreter} safely")
        plan.ro_bind(str(root))
    _path_binds(plan, child_env.get("PATH", ""))

    argv = [bwrap, *plan.argv]
    argv += ["--unshare-pid", "--proc", "/proc"]
    argv += ["--die-with-parent", "--new-session", "--"]
    argv += [str(item) for item in inner]
    return argv
