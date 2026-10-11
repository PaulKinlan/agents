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
  work inside without binding whole home subtrees. A pinned trusted tool (bwrap/gh/bd/git/
  semgrep/gitleaks/node/npm/npx, agents-7bj) has its SHA-256 verified before it is bound; a
  mismatch fails the wrap closed.
* **bwrap itself is pinned (agents-28nn).** The wrap's own binary is resolved and
  authenticated by the same tool-pin rule BEFORE it executes: ``_verify_wrap``'s
  child's-write proof cannot catch a fake bwrap, because the run directory is bound at the
  SAME host path inside and outside the wrap, so a fake that execs the child natively
  satisfies the proof (verified by execution with a planted stub). No check run *through*
  an unauthenticated binary can catch that binary lying about namespaces it never created,
  so the assertion is on the deliverer: an unpinned or pin-mismatching bwrap makes the
  sandbox unavailable (the factory then refuses or honestly downgrades) and fails
  ``sandbox_command()`` closed.

What it does NOT do, stated plainly because policy.json must never overclaim:

* **Egress is filtered when the dispatcher turns it on (agents-2x6).** With
  ``--unshare-net`` the child has no route off its namespace, so a direct ``connect()`` to
  any external address fails ENETUNREACH and DNS does not resolve — the kernel enforces the
  boundary, not a proxy-env convention an injected engine could ignore. Its only egress is
  the in-sandbox ``lib/net_forward.py`` relay to the host-side credential broker (model API)
  and the egress allowlist proxy (pre-pass fetches), both reached over bind-mounted UNIX
  sockets. A run that cannot broker every provider the engine might use keeps the host
  network instead, and policy.json then keeps reporting ``network-egress`` as not enforced.
* **Linux + bubblewrap only.** Elsewhere sandbox_available() is False and every banner and
  record keeps saying NOT confined (THREAT_MODEL.md section 7 accepts unsandboxed runs for
  trusted targets; the honesty is the point).

Two things stay deliberately distinct, because a record must never conflate them: bubblewrap
being available on the host (sandbox_available(), a minimal probe) and the wrap built for a run
actually starting its child (sandbox_command() exercises the plan it just built before it
returns — agents-kwi). An unexercised wrap raises SandboxError, so the station fails before any
banner or policy.json claims the run was sandboxed.

Engines are added to SANDBOXED_ENGINES only after their adapter is verified to run inside
the wrapper; an unlisted engine runs unsandboxed and its banner says so.
"""

import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

# Integrity pins for host-side trusted tools (agents-7bj): a pinned tool's content is
# authenticated (SHA-256) before it is bound into the sandbox (see _executable_binds).
# agents-28nn: bwrap itself is resolved through the same pin rule (resolve_tool) — the
# binary that delivers the sandbox must be authenticated before it executes.
from lib.tool_pins import TRUSTED_TOOLS as PINNED_TOOLS
from lib.tool_pins import ToolPinError, resolve_tool, verify_pin

BWRAP = "bwrap"
TOOL = "bubblewrap"
# AF_UNIX sun_path is 108 bytes including the terminating NUL, so a usable path is at most
# 107 bytes. Longer paths fail bind() with ENAMETOOLONG; we refuse them loudly first (agents-x8l).
SUN_PATH_LIMIT = 107

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

# Exec-time verification (agents-kwi). sandbox_available() answers "can bubblewrap run on this
# host?" with a minimal probe; it does NOT answer "does the wrap built for THIS run start its
# child?". A wrap that fails at exec — bwrap present and the probe green, but the child never
# launched (a broken/hostile bwrap, an inner program that is not exec-able inside the plan) —
# used to be recorded as "Sandbox: enforced"/engine_sandboxed: true, because the record was
# built from the probe. sandbox_command() therefore EXERCISES the plan it just built, once,
# with a sentinel child, before it returns: the sentinel runs inside the wrap, proves it got in
# by writing a one-time token into the run directory (rw-bound by the plan), and exits 0. No
# proof, no wrap — SandboxError, so the station fails before any banner or policy.json exists,
# exactly like the bwrap-missing path. Cost: one short-lived bwrap per wrap.
_VERIFY_TIMEOUT = 60
_VERIFY_TOKEN_NOT_READABLE = 40       # the sentinel got in; the token never arrived on stdin
_VERIFY_INNER_NOT_EXECUTABLE = 41     # the sentinel got in; the real inner is not runnable there
_VERIFY_RUN_DIR_NOT_WRITABLE = 42     # the sentinel got in; the run-directory bind is not writable


class SandboxError(RuntimeError):
    """The sandbox was requested but cannot be built (too many binds, bwrap missing at
    wrap time, or a wrap that cannot start a child inside the sandbox). The station fails
    rather than running unsandboxed and overclaiming."""


_probe_result: Optional[bool] = None
_probe_reason: Optional[str] = None


def sandbox_available() -> bool:
    """Whether this host can actually run the bubblewrap sandbox. Cached; probed for real
    (an executable on PATH is not proof — unprivileged user namespaces may be disabled)."""
    global _probe_result
    if _probe_result is None:
        _probe_result = _probe()
    return _probe_result


def sandbox_unavailable_reason() -> Optional[str]:
    """WHY the probe said this host cannot sandbox, or None when it can (agents-28nn round 2).

    A refusal or an honest downgrade must NAME the cause — a quiet downgrade that reads
    like a normal no-bwrap host hides a pin refusal (e.g. a deployer who forgot to
    regenerate host pins, or an unreadable pins file) behind an innocent-looking message.
    Probes here record their failure reason; the factory's refusal and banner then say
    exactly why the boundary is absent."""
    if sandbox_available():
        return None
    return _probe_reason


def _verify_wrap(head: List[str], tail: "Callable[[Sequence[str]], List[str]]", *,
                 inner: Sequence[str], run_dir: Path, env: Dict[str, str]) -> None:
    """Start a sentinel child inside the wrap that was just built, and require proof that it
    got in (agents-kwi). Raises SandboxError when the wrap cannot launch its child.

    `head` and `tail` are the wrap's own argv split around its command, so the exercise runs
    the SAME plan, the same namespaces and the same net_forward relay argv (agents-2x6) — only
    the final command is replaced by the sentinel. The sentinel is /bin/sh (every Linux host
    has it, and the plan binds the system directories), given the inner program to resolve and
    the destination path for the proof. IT IS NOT GIVEN THE TOKEN IN ITS ARGV (agents-0p3l):
    the token arrives on stdin, because the sentinel's cmdline is world-readable. It exits 0
    only after resolving `inner[0]` inside the sandbox AND writing the token through the
    run-directory bind, so the
    proof is the child's own write and not bwrap's exit status: a bwrap that returns 0 without
    running the child fails too.

    What this does and does not establish: it establishes that a child starts inside the wrap
    built for this run, with the real inner resolved there. It does not run the real command
    (that would run the engine), so an inner that starts and then fails on its own is an engine
    failure, reported by the station, not a wrap failure.
    """
    token = os.urandom(16).hex()
    token_path = run_dir / f".sandbox-wrap-verify-{token[:8]}"
    # THE TOKEN ARRIVES ON STDIN AND NEVER IN ARGV (agents-0p3l).
    #
    # argv was the leak. The sentinel runs as a child of bwrap, and /proc/<pid>/cmdline is
    # world-readable (0444), so a token passed as an argument was readable by ANY process on
    # the host, any uid, for as long as the wrap was being verified - and the run-directory
    # bind then wrote it to a path. The proof itself is unchanged and deliberately so: it is
    # still the child's own write into the run directory and not bwrap's exit status, and the
    # run-directory-write check still needs only the DESTINATION path, which is not a secret
    # (a random-named file that is unlinked immediately) whereas the token is.
    #
    # RESIDUAL, STATED RATHER THAN LEFT TO BE DISCOVERED: a SAME-UID process can still read
    # the token from /proc/<pid>/fd/0 while this child holds the pipe, and can read the
    # destination from the cmdline. The token moved from WORLD-readable to SAME-UID-readable.
    # That is a real narrowing and it is NOT a containment boundary, and it is unavoidable at
    # this layer because the factory and every process it launches share one uid by design.
    # A different-uid boundary for the token is a different change.
    #
    # `read` needs the newline, hence input=token + '\n' below: without it dash's read
    # returns non-zero at EOF even though it filled the variable, which would be
    # indistinguishable from a token that never arrived.
    script = (f'IFS= read -r tok || exit {_VERIFY_TOKEN_NOT_READABLE}\n'
              'if { [ -f "$1" ] && [ -x "$1" ]; } || command -v "$1" >/dev/null 2>&1; '
              f'then :; else exit {_VERIFY_INNER_NOT_EXECUTABLE}; fi\n'
              'printf "%s" "$tok" > "$2" 2>/dev/null || '
              f'exit {_VERIFY_RUN_DIR_NOT_WRITABLE}\n')
    sentinel = ["/bin/sh", "-c", script, "factory-wrap-verify", str(inner[0]),
                str(token_path)]
    try:
        res = subprocess.run([*head, *tail(sentinel)], input=(token + "\n").encode(),
                             capture_output=True, timeout=_VERIFY_TIMEOUT, env=env)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise SandboxError(
            f"could not exercise the {BWRAP} wrap before returning it ({e}); refusing to run "
            f"(and to record the run as sandboxed) on a wrap that was never shown to start "
            f"its child") from e
    try:
        proof = token_path.read_text(encoding="utf-8") == token
    except OSError:
        proof = False
    finally:
        try:
            token_path.unlink()
        except OSError:
            pass
    if res.returncode == _VERIFY_TOKEN_NOT_READABLE:
        raise SandboxError(
            f"the sandbox wrap's verify child could not read the one-time token from its "
            f"stdin, so the wrap was never shown to start its child; refusing to run (and to "
            f"record the run as sandboxed)")
    if res.returncode == _VERIFY_INNER_NOT_EXECUTABLE:
        raise SandboxError(
            f"the sandbox wrap cannot execute {str(inner[0])!r} inside it, so the child it was "
            f"built for would never start; refusing to run (and to record the run as "
            f"sandboxed) on a wrap that was never shown to start its child")
    if res.returncode == _VERIFY_RUN_DIR_NOT_WRITABLE:
        raise SandboxError(
            f"the sandbox wrap cannot write to the run directory {run_dir}, so the child's "
            f"output could not be collected; refusing to run (and to record the run as "
            f"sandboxed) on a wrap that was never shown to start its child")
    if res.returncode != 0 or not proof:
        detail = (f"{BWRAP} exited 0 without launching the child" if res.returncode == 0
                  else f"{BWRAP} exited {res.returncode}")
        raise SandboxError(
            f"the wrap built for this run could not start a child inside the sandbox "
            f"({detail}); bwrap being available is not proof that this child starts, so "
            f"refusing to run (and to record the run as sandboxed) on a wrap that was never "
            f"shown to start its child")


def _resolve_bwrap() -> str:
    """The bwrap binary, authenticated by the trusted-tool pin rule (agents-28nn).

    bwrap is the binary the whole sandbox claim stands on, and it cannot be verified by
    any probe run THROUGH it: ``_verify_wrap``'s proof is the sentinel's write through the
    run-directory bind, but the plan binds that directory at the SAME host path inside and
    outside the wrap, so a PATH-planted fake that just execs the child natively satisfies
    the proof — the write, the exit status, everything (verified by execution with a
    planted stub). The only sound assertion is on the deliverer: resolve + SHA-256 pin via
    lib/tool_pins, failing closed when unpinned (the explicit
    FACTORY_ALLOW_UNPINNED_TOOLS=1 dev/test opt-in excepted, as for gh/git).
    Raises ToolPinError when the resolved bwrap is unpinned or does not match its pin.
    """
    return resolve_tool(BWRAP)


def _probe() -> bool:
    global _probe_reason
    _probe_reason = None
    if not sys.platform.startswith("linux"):
        _probe_reason = "not a Linux host (bubblewrap is Linux-only)"
        return False
    try:
        bwrap = _resolve_bwrap()
    except ToolPinError as e:
        # An unpinned or pin-mismatching bwrap cannot be trusted to deliver a sandbox, so
        # this host is reported as unable to sandbox: the factory then refuses the run
        # (pi) or runs honestly unsandboxed under the explicit attestation — it never
        # overclaims a sandbox an unauthenticated binary claimed to build (agents-28nn).
        # The reason is recorded for the loud refusal/downgrade: a pin failure must never
        # read like an ordinary bwrap-less host (round 2).
        _probe_reason = f"bwrap cannot be authenticated: {e}"
        return False
    plan = _BindPlan()
    _system_binds(plan)
    plan.dev("/dev")
    plan.tmpfs("/tmp")
    argv = [bwrap, *plan.argv, "--die-with-parent", "--new-session", "--", "/bin/true"]
    try:
        res = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as e:
        _probe_reason = f"the bwrap probe could not execute: {e}"
        return False
    if res.returncode != 0:
        detail = (res.stderr or "").strip().splitlines()
        _probe_reason = (f"the bwrap probe exited {res.returncode}"
                         + (f" ({detail[-1][:200]})" if detail else ""))
        return False
    return True


def engine_sandboxed(engine: str) -> bool:
    """Whether runs of `engine` get the OS sandbox on this host.

    THE RULE every conditional on this function (or on sandbox_available) must satisfy
    (agents-28nn — the NAMED, VERIFIABLE appearances are four: the round-5
    effective-pins hoist, the round-6 credential broker gate in factory, the round-7
    pre-pass HTTP_PROXY only-if-sandbox_ok, and the round-8 adapter env's
    proxied=not engine_sandboxed, which handed the operator's HTTP(S)_PROXY/NO_PROXY
    to the UNSANDBOXED engine only until round 8 dropped it. The bead's record uses
    higher ordinals — third at round 5, six at the round-8 verdict — because earlier
    verdicts counted shapes they never named into the record (the round-6 verdict
    reported three further shapes and named only the broker); an unnamed shape cannot
    be enumerated, so this comment enumerates what the record names and asserts no
    total it cannot verify (searched at the round-8 attestation: the bead's
    verdict/coord comments for "polarity", and every conditional on
    engine_sandboxed/sandbox_available/sandbox_ok in factory and lib/ — no live
    inverted instance remains). One alleged instance was resolved by FALSIFICATION:
    no adapter proxy is gated on egress_active — the adapter's proxy is a UNIX-socket
    forward for the broker): THE LESS-CONFINED PATH MUST NOT RECEIVE MORE THAN THE
    MORE-CONFINED PATH. A control that applies only on the confined path leaves the
    less-confined path with less control — the inverted polarity. Before gating anything
    on the result of this check, ask what the unsandboxed path gets instead: if the
    answer is MORE (raw credentials, a wider trust set, an unauthenticated handoff), the
    control belongs on the OPERATION, not on the path taken to it. Referenced from the
    credential broker and the hoisted pre-pass pins in factory.
    """
    return engine in SANDBOXED_ENGINES and sandbox_available()


def sandbox_record(engine: str, egress_filtered: bool = False) -> Optional[Dict[str, Any]]:
    """The machine-readable sandbox state for policy.json / the banner, or None when this
    host has no sandbox. `engine_sandboxed` says whether the engine session itself is
    inside it; the pre-pass is sandboxed whenever the host can sandbox at all.

    `egress_filtered` (agents-2x6) reports whether THIS run isolates the network namespace
    and confines egress to the broker + allowlist proxy. It is per-run and drives whether
    policy.json drops `network-egress` from not_enforced, so a fallback run that keeps the
    host network passes False and the record never overclaims."""
    if not sandbox_available():
        return None
    return {
        "tool": TOOL,
        "engine_sandboxed": engine in SANDBOXED_ENGINES,
        "prepass_sandboxed": True,
        "engine_read_scope": ("confined by the OS sandbox to the target (read-only) plus the factory repository "
                              "(with runs/ and findings/ masked), the engine's install tree and system dirs "
                              "(/usr, /etc); ambient $HOME (ssh, cloud credentials), other runs and the rest of "
                              "the host filesystem are invisible"
                              if engine in SANDBOXED_ENGINES else None),
        "network_egress_filtered": egress_filtered,
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


def _package_json_root(path: Path) -> Optional[Path]:
    """Nearest ancestor directory containing a ``package.json`` (a node package root), for a
    runtime file a wrapper launcher execs. The pi bundle is
    ``.../pi-coding-agent/dist/bundle/cli.js``; its package root is ``.../pi-coding-agent``
    (the whole package is needed: ``cli-runtime.js``, ``chunks/``, ``node_modules``)."""
    current = path.parent if path.is_file() else path
    while current != current.parent:
        if (current / "package.json").is_file():
            return current
        current = current.parent
    return None


def _wrapper_runtime_paths(real: Path) -> List[str]:
    """Existing absolute paths a ``#!`` wrapper script references directly.

    A launcher often execs a runtime in a different tree than its own (agents-wza: pi's
    ``~/.local/pi/pi`` execs ``node ~/.pi/agent/npm/.../dist/bundle/cli.js``). Binding
    only the launcher's own tree leaves that hardcoded runtime invisible inside the sandbox
    (``$HOME`` is tmpfs'd), so the module cannot resolve. Extract the absolute paths the
    script mentions and let the caller bind their install trees. A path that no longer
    exists is skipped — it cannot be a live runtime dependency.
    """
    if not real.is_file():
        return []
    # Peek the shebang with a 2-byte read rather than slurping the whole file: a resolved
    # executable is often a binary (node is ~80 MB), and decoding it as text just to learn it
    # is not a script costs seconds and ate the tight station-budget fixtures (agents-wza).
    try:
        with real.open("rb") as f:
            if f.read(2) != b"#!":
                return []
    except OSError:
        return []
    try:
        text = real.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    paths: List[str] = []
    for tok in re.findall(r"/[^\s'\"`;|&()<>]+", text):
        if os.path.exists(tok):
            paths.append(tok)
    return paths


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
            # agents-7bj: authenticate a pinned trusted tool's content (and configured path)
            # before binding it into the child. A pinned tool whose binary does not hash-match,
            # or whose real path is not the configured path, fails the wrap closed rather than
            # binding an unverified binary. A trusted tool with NO pin also fails closed here
            # (unless FACTORY_ALLOW_UNPINNED_TOOLS=1) — see lib.tool_pins._require_pin. Untrusted
            # names (bash/sh/env/python3) are never passed to verify_pin and need no pin.
            if name in PINNED_TOOLS:
                verify_pin(name, str(real))
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
            # A wrapper launcher may exec a runtime in another tree (agents-wza: pi's
            # launcher execs `node <abs>/dist/bundle/cli.js` under ~/.pi/agent/npm, which is
            # hidden once $HOME is tmpfs'd). Bind that runtime's package root too, so the
            # module resolves. The package root is inferred narrowly (nearest package.json),
            # never a whole PATH dir or $HOME, so the agents-9n7/ejm invariants hold.
            for runtime in _wrapper_runtime_paths(real):
                rp = Path(runtime)
                pkg = _package_json_root(rp) or _package_root(rp)
                if pkg is None or _is_broad_root(pkg, home):
                    continue
                # Bind the package's REAL content AT the path the launcher references, not at
                # its resolved location. A symlinked bundle (pi: ~/.pi/agent/npm/... ->
                # ~/fleet/sdk-host/...) must be reachable at the hardcoded path node opens,
                # or the entry still fails MODULE_NOT_FOUND even though the resolved tree is
                # bound. ro_bind(dest=) mounts the real content at the symlink path (bwrap
                # creates missing parents); for a non-symlinked package dest == source.
                if not plan.visible(str(pkg)):
                    plan.ro_bind(str(pkg), dest=str(pkg))


def sandbox_command(
    inner: Sequence[str],
    *,
    target_dir: os.PathLike | str,
    factory_root: os.PathLike | str,
    run_dir: os.PathLike | str,
    env: Optional[Dict[str, str]] = None,
    executables: Sequence[str] = (),
    egress_forwards: Optional[Sequence[Tuple[int, str]]] = None,
    rw_binds: Sequence[str] = (),
    ro_binds: Sequence[str] = (),
    mask_findings: bool = False,
) -> List[str]:
    """Wrap `inner` (adapter or pre-pass argv) in a bubblewrap invocation.

    `env` is the child's environment (lib/child_env.py allowlist). `executables` is the
    narrow allowlist of program names the child may exec; each is resolved across env's
    PATH and bound as its install tree / launch path — PATH directories themselves are
    never bound (review P1, agents-9n7). The child runs in a private PID namespace with a
    real procfs mounted inside it: bun/pi needs a genuine /proc/self (verified by strace),
    and the private namespace keeps every host process — and its environ — invisible.

    agents-kwi: before returning, the plan is exercised once with a sentinel child (see
    _verify_wrap) — a wrap that cannot start a child inside the sandbox raises SandboxError
    here, so "bwrap is available" is never reported as "this child started inside it".

    `egress_forwards` (agents-2x6) turns on network egress control. When it is not None the
    child also gets a private network namespace (--unshare-net): it has no route off-box, so
    a direct connect() to any external address fails ENETUNREACH and DNS does not resolve —
    kernel-enforced, not a proxy-env convention. Its only egress is lib/net_forward.py, which
    `inner` is wrapped behind: each (port, unix_socket_path) pair makes net_forward listen on
    the child's 127.0.0.1:port and relay to that host-side UNIX socket (the credential broker
    and/or the egress allowlist proxy), reached through the run_dir rw-bind. Pass None (the
    default) to keep the host network shared — the honest fallback when a run cannot broker
    every provider, where policy.json must keep reporting network-egress as not enforced.
    """
    try:
        bwrap = _resolve_bwrap()
    except ToolPinError as e:
        # Fail the station loudly, like the bwrap-missing path: a wrap built by an
        # unauthenticated bwrap is no wrap at all (agents-28nn).
        raise SandboxError(f"{BWRAP} cannot be authenticated: {e}") from e
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

    # agents-854: extra writable config directories the engine needs. pi's agent directory
    # (PI_CODING_AGENT_DIR) holds BOTH its models.json provider override AND its auth.json
    # credential store, and pi opens auth.json for read-write even when auth comes from env, so
    # the directory must be writable. It is factory-controlled, per-run, and holds no secrets
    # (models.json + an empty auth.json), so writability does not weaken containment.
    for path in rw_binds:
        plan.rw_bind(path)

    # agents-28nn round 5 (review P0 — the effective-pins TOCTOU): caller-declared
    # READ-ONLY binds, applied after the run directory's rw-bind. PROJECT RULE: A FILE THE
    # PIN RESOLVER TRUSTS MUST NOT BE A FILE THE PINNED PROCESS CAN REWRITE — trust is not
    # a property of WHAT is read, it is a property of WHO CAN WRITE WHAT IS READ. The
    # effective pins were written into the rw-bound run directory, so code in the child
    # could overwrite the file that constrains it and resolve_tool then validated the
    # injected hash (constructed by the round-4 reviewer). The read-only bind is the
    # codebase's own machinery REUSED — bwrap's ro-bind makes the kernel, not a
    # convention, enforce who can write — and the alternative (over-mounting a file that
    # still lives inside the rw-bound run dir) is worse twice over: _BindPlan treats an
    # rw ancestor as already covering an ro request (the over-mount would be silently
    # skipped), and a correct over-mount would still leave the file exposed to every
    # OTHER wrap that rw-binds the run dir, the engine session included. The file must
    # live OUTSIDE every rw-bound tree and be bound here, read-only, at the same absolute
    # path the child's FACTORY_TOOL_PINS names.
    for path in ro_binds:
        plan.ro_bind(path)

    # agents-x8l: egress sockets may live outside run_dir (a short per-run dir under /tmp,
    # because run_dir embeds the worktree path and can exceed AF_UNIX's sun_path limit). Bind
    # each socket's parent dir so the in-sandbox net_forward relay reaches the host-side
    # listener, and refuse a path too long to bind loudly rather than fail at bind() time.
    if egress_forwards is not None:
        for _port, sock in egress_forwards:
            if len(sock) > SUN_PATH_LIMIT:
                raise SandboxError(
                    f"egress socket path {sock!r} is {len(sock)} bytes, over the "
                    f"{SUN_PATH_LIMIT}-byte AF_UNIX sun_path limit; use a shorter socket path")
            parent = os.path.dirname(sock)
            if parent and not plan.visible(parent):
                plan.rw_bind(parent)

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
    try:
        _executable_binds(plan, executables, child_env.get("PATH", ""), home)
    except ToolPinError as e:
        # A trusted tool whose content stopped matching its pin between the probe and this
        # wrap build fails the wrap closed — exactly like an unauthenticated bwrap, the
        # station fails loudly rather than binding an unverified binary (agents-28nn round
        # 2: with the pin machinery's failures all surfaced as ToolPinError, no filesystem
        # error can crash past this boundary either).
        raise SandboxError(
            f"a trusted tool bound into the sandbox cannot be authenticated: {e}") from e

    # Host tool pins file (agents-ebm7): when child_env forwards FACTORY_TOOL_PINS,
    # the target file is often under $HOME (e.g. ~/.config/factory/tools.pins.yaml).
    # Since $HOME and /home are tmpfs'd above, bind the pins file into the wrap
    # read-only at the exact host path so the sandboxed child can authenticate its tools.
    pins_env = child_env.get("FACTORY_TOOL_PINS")
    if pins_env:
        pins_path = Path(os.path.expanduser(pins_env)).resolve()
        if pins_path.is_file():
            plan.ro_bind(str(pins_path), dest=str(pins_path))

    # agents-4zg: the findings store aggregates raw scanner matches from EVERY target, so a run
    # for target A could read target B's credentials from it. The engine has no reason to read
    # findings; the deterministic pre-pass keeps it (default) for bundle baseline / pr-fixer /
    # qa-station. Mask it LAST, after every other bind, so no later bind — including a raw target
    # whose path overlaps the store (--target <factory>/findings) — can overmount the mask and
    # re-expose other targets' raw matches. bwrap applies mounts in order, so last wins.
    if mask_findings:
        factory_findings = Path(factory) / "findings"
        if factory_findings.is_dir():
            plan.tmpfs(str(factory_findings))

    head = [bwrap, *plan.argv, "--unshare-pid", "--proc", "/proc"]
    net_forward_py = Path(factory_root) / "lib" / "net_forward.py"
    if egress_forwards is not None:
        # Egress control (agents-2x6): isolate the network namespace and wrap `inner` behind
        # the net_forward relay, so the child's only way off-box is the host-side broker /
        # allowlist proxy on the bind-mounted UNIX sockets. net_forward binds its listeners
        # before spawning `inner`, so the endpoints exist before the engine's first API call.
        head += ["--unshare-net"]

    def tail(command: Sequence[str]) -> List[str]:
        """The wrap's argv after its mount/namespace flags, for a given final command: the
        net_forward relay layer when egress is controlled, else no layer at all."""
        out = ["--die-with-parent", "--new-session", "--"]
        if egress_forwards is not None:
            out += [str(interpreter), str(net_forward_py)]
            for port, sock in egress_forwards:
                out += ["--forward", f"{port}={sock}"]
            out += ["--"]
        return out + [str(item) for item in command]

    argv = head + tail(inner)
    # agents-kwi: never hand back a wrap that has not been shown to start a child inside its
    # own plan. The station builds both wraps before it prints the banner or writes
    # policy.json, so a raise here means no run record ever claims the run was sandboxed.
    _verify_wrap(head, tail, inner=inner, run_dir=Path(runs), env=child_env)
    return argv
