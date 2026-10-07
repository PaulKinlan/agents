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
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

BWRAP = "bwrap"
TOOL = "bubblewrap"

# Engines whose adapters are verified to run inside sandbox_command(). claude/antigravity
# need their session auth from $HOME, which the sandbox hides by design; deepseek is
# payload-only. pi authenticates from env keys (lib/child_env.py ENGINE_CREDENTIALS), so
# hiding $HOME costs it nothing (agents-9n7).
SANDBOXED_ENGINES = frozenset({"pi"})

# Narrow executable allowlists (review P1, agents-9n7). The sandbox binds ONLY these
# resolved programs (as install trees / launch paths), never whole PATH directories, so an
# unrelated directory the operator happened to leave on PATH cannot smuggle files into the
# engine's read scope. Names that resolve under /usr need no bind (already visible); the
# list matters for tools that live under a hidden home root. A tool that is not listed
# fails to resolve, which fails the scan loudly rather than widening the sandbox — extend
# the list when a real run gains a new dependency.
#
# The real pi is a `#!/usr/bin/env node` script (its launcher lives in ~/.local/pi), so the
# engine child MUST have `node` bound or it dies with "env: node: No such file or directory"
# (review P1, agents-9n7). bash runs the adapter and the pi shim; env resolves the shebangs;
# the engine name itself ("pi") is added by the dispatcher. pi's model session shells out to
# nothing else (its read/grep/find/ls tools are builtins or /usr utilities, already visible).
ENGINE_EXECUTABLES = ("bash", "sh", "env", "node")
# Audited against agents/*/scripts/*.py: the pre-passes shell out to git, gh, gitleaks and
# node/npm/npx (the dependency audit), plus python3 for sub-scans; bash/sh/env cover shell
# shebangs. Only the home-installed tools (node/npm/npx/gitleaks) actually incur a bind —
# git/gh/python3 resolve under /usr and are already visible.
PREPASS_EXECUTABLES = (
    "bash", "sh", "env", "git", "gh", "gitleaks", "node", "npm", "npx", "python3",
)

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
        "engine_read_scope": ("confined by the OS sandbox to the target (read-only) plus "
                              "the factory runtime, the engine's own install tree and "
                              "system dirs; the operator's home, credentials, other runs "
                              "and the rest of the host filesystem are invisible"
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
            # Longest prefix wins; on a tie (the same path mounted twice — e.g. a tmpfs
            # later covered by a ro/rw bind) the LAST recorded mount is the effective one,
            # because bwrap applies mounts in order and the later bind covers the tmpfs.
            if (path == mounted or mounted in path.parents) and (
                    best is None or len(mounted.parts) >= len(best.parts)):
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

    def ro_bind(self, source: str, dest: Optional[str] = None) -> None:
        self._bind(source, ro=True, dest=dest)

    def rw_bind(self, source: str, dest: Optional[str] = None) -> None:
        self._bind(source, ro=False, dest=dest)

    def _bind(self, source: str, ro: bool, dest: Optional[str] = None) -> None:
        path = Path(os.path.realpath(source))
        if not path.exists():
            return
        target = Path(dest) if dest else path
        nearest = self._nearest(target)
        if ro and nearest in ("ro", "rw"):
            return  # already inside a bind with the real content
        self.argv += (["--ro-bind"] if ro else ["--bind"]) + [str(path), str(target)]
        self._mounts.append((target, "ro" if ro else "rw"))
        self._cap()

    def _cap(self) -> None:
        if len(self._mounts) > _MAX_BINDS:
            raise SandboxError(f"more than {_MAX_BINDS} mounts needed; refusing to run")

    def visible(self, path: str) -> bool:
        """Whether `path`'s real content is already inside the sandbox."""
        return self._nearest(Path(path)) in ("ro", "rw")


def _package_root(path: Path) -> Optional[Path]:
    """The install-tree root for a resolved executable, inferred conservatively so a flat
    directory of unrelated files is never bound whole (review P1, agents-9n7). A package
    root is returned only when either:
      (a) the executable sits under a structural directory (bin/sbin/libexec/lib/...) that
          signals a real install tree with siblings — .../npm/bin/npm-cli.js -> .../npm,
          .../v24/bin/node -> .../v24; or
      (b) the executable's own directory is named after it, i.e. a dedicated package dir
          (~/.local/pi/pi -> ~/.local/pi, which holds pi's resources).
    A lone executable in an unrelated flat directory (/tmp/tools/mytool) has no inferable
    package, so None is returned and only the file is bound. None also when the walk escapes
    into a hidden root or the filesystem root."""
    if path.is_file():
        exe_name = path.name
        current = path.parent
    else:
        exe_name = None
        current = path
    walked = False
    while current.name in _STRUCTURAL and current != current.parent:
        current = current.parent
        walked = True
    if not walked and not (exe_name is not None and current.name == exe_name):
        return None  # lone executable in an unrelated flat directory: bind the file only
    if current == current.parent:  # reached /
        return None
    for root in _HIDDEN_ROOTS:
        if str(current) == root:
            return None
    return current


def _is_broad_root(pkg: Path, home: Optional[str]) -> bool:
    """A package root that is really a top-level user prefix (~/.local, ~/fleet): binding it
    whole would expose far more than the one tool. Detected by the root's parent being the
    user's home or a hidden root, so we fall back to binding just the executable file."""
    parent = pkg.parent
    if str(parent) in _HIDDEN_ROOTS:
        return True
    if home and str(parent) == str(Path(home)):
        return True
    return False


def _resolutions(name: str, path_env: str) -> List[str]:
    """Every executable path for `name` across PATH, like `which -a` — a launcher shim in
    one directory often execs the real binary in another, and both launch paths must exist
    inside the sandbox."""
    out: List[str] = []
    for entry in path_env.split(os.pathsep):
        if not entry:
            continue
        candidate = os.path.join(entry, name)
        try:
            if os.path.exists(candidate) and os.access(candidate, os.X_OK):
                out.append(candidate)
        except OSError:
            continue
    return out


def _executable_binds(plan: _BindPlan, names: Iterable[str], path_env: str,
                      home: Optional[str]) -> None:
    """Bind only the resolved executables the child needs — NEVER whole PATH directories.

    An arbitrary directory on the inherited operator PATH could hold a canary or credential
    file that has nothing to do with any tool; binding it would re-expose exactly what the
    sandbox hides (review P1, agents-9n7). So each name is resolved across PATH and bound
    as (a) its narrow install tree when that tree is tool-specific, and (b) its launch path
    when that path lives outside the tree (shim/symlink chains). A name that resolves under
    /usr needs nothing (already visible). A name that cannot be resolved safely is skipped —
    a missing tool fails the scan loudly rather than widening the sandbox.
    """
    for name in names:
        for launch in _resolutions(name, path_env):
            launch_p = Path(launch)
            real = Path(os.path.realpath(launch))
            if not real.exists():
                continue
            # Bind the tool's own install tree when it is tool-specific (node's versioned
            # tree, pi's ~/.local/pi), so the real binary and its siblings resolve at their
            # true paths. A tree that is really a top-level user prefix (~/.local) is too
            # broad to bind whole — the executable file alone is bound instead.
            pkg = _package_root(real)
            if pkg is not None and not _is_broad_root(pkg, home) and not plan.visible(str(pkg)):
                plan.ro_bind(str(pkg))
            if not plan.visible(str(real)):
                plan.ro_bind(str(real))
            # Make the launch path the child's PATH/shim resolves exist and point at the
            # real binary: a symlink is replicated as a symlink (so a self-locating binary
            # like pi still finds its resources), a real file is bound in place.
            if not plan.visible(str(launch_p)):
                if os.path.islink(launch):
                    plan.symlink(str(real), str(launch_p))
                else:
                    plan.ro_bind(str(real), dest=str(launch_p))


def sandbox_command(
    inner: Sequence[str],
    *,
    target_dir: os.PathLike | str,
    factory_root: os.PathLike | str,
    run_dir: os.PathLike | str,
    env: Optional[Dict[str, str]] = None,
    executables: Sequence[str] = (),
) -> List[str]:
    """Wrap `inner` (adapter or pre-pass argv) in a bubblewrap invocation.

    `env` is the child's environment (lib/child_env.py allowlist). `executables` is the
    narrow allowlist of program names the child may exec; each is resolved across env's
    PATH and bound as its install tree / launch path — PATH directories themselves are
    never bound (review P1, agents-9n7). The child runs in a private PID namespace with a
    real procfs mounted inside it: bun/pi needs a genuine /proc/self (verified by strace),
    and the private namespace keeps every host process — and its environ — invisible.
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
    home = child_env.get("HOME")

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
    if home and home.startswith("/") and home not in _HIDDEN_ROOTS:
        plan.tmpfs(home)
    tmpdir = child_env.get("TMPDIR")
    if tmpdir and tmpdir.startswith("/") and not plan.visible(tmpdir):
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

    # Executables: the pre-pass interpreter, then the narrow allowlist the caller named.
    # Resolved by name and bound as install trees / launch paths — never whole PATH dirs.
    interpreter = Path(sys.executable).resolve()
    if not plan.visible(str(interpreter)):
        root = _package_root(interpreter)
        if root is None or _is_broad_root(root, home):
            plan.ro_bind(str(interpreter))
        else:
            plan.ro_bind(str(root))
    _executable_binds(plan, executables, child_env.get("PATH", ""), home)

    argv = [bwrap, *plan.argv]
    argv += ["--unshare-pid", "--proc", "/proc"]
    argv += ["--die-with-parent", "--new-session", "--"]
    argv += [str(item) for item in inner]
    return argv
