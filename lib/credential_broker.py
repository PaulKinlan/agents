"""Dispatcher-side credential broker (agents-8h4).

Why this exists
---------------
The OS sandbox (agents-9n7) hides ``$HOME``, so a sandboxed engine authenticates
only from environment API keys (lib/child_env.py's allowlist). But bun/pi needs a
real procfs, so the engine's own ``/proc/self/environ`` is readable by its own read
tool: without brokering those keys are in reach of a prompt-injected session.
policy.json keeps ``not_enforced: env-credentials`` unless a running broker's
swap of the engine's actual environment to placeholders has been verified
(agents-2dj) — on either sandbox state, since the broker is no longer
sandbox-gated (agents-28nn round 6).

The broker removes the secret from the sandbox. The dispatcher runs this localhost
HTTP proxy *outside* the sandbox. The sandboxed engine is given only a base URL
pointing here (``ANTHROPIC_BASE_URL`` / ``OPENAI_BASE_URL`` / ``GOOGLE_GEMINI_BASE_URL``)
and a PER-RUN placeholder key. The proxy injects the real credential — read from
the dispatcher's own environment, which never crosses into the sandbox — and
forwards the request to the real provider over HTTPS, streaming the response back
so SSE is not buffered. No credential shape then exists in the engine's env, fs or
``/proc``, because the only provider secret lives in this process, on the host side
of the sandbox boundary.

Peer identity first, the placeholder second (agents-28nn round 8, the verdict's P0)
----------------------------------------------------------------------------------
The broker no longer starts only on the sandboxed path (round 6 closed that inverted
polarity), and on the UNSANDBOXED path its TCP loopback is the HOST's loopback — a
shared interface any local process can dial. Round 7 authenticated that reachability
with the placeholder turned per-run random secret — and round 8's verdict falsified
the secret as THE boundary, by construction: the unsandboxed engine runs as the
operator's uid, the same uid as every process that could abuse the broker, so the
placeholder in the engine's environ (or in the models.json the engine reads) is
readable by any same-uid process via /proc/<pid>/environ — the reviewer's
pre-pass-spawned attacker read exactly that value and authenticated with it. A secret
confines by KNOWLEDGE, and between processes of one uid there is no knowledge
asymmetry: any value the engine can see, the attacker can see. So BOTH listeners
authenticate by PEER IDENTITY first: a connection is accepted only when the kernel's
own attribution of its peer puts that peer inside the dispatcher's process tree,
narrowed to the ENGINE SESSION's tree the moment the engine exists
(restrict_peer_root). The root is identified by (pid, process start time) and not by
the pid alone — a pid is reused and a start time is not — so a recycled pid cannot
stand in for the root it was narrowed to (agents-28nn round 11); reaching the broker
still requires holding a connection the kernel attributes into that tree, and the
identity decides which connections those are. The decision is ONE function
(_peer_is_permitted); each
transport only names the mechanism that supplies the peer's identity — the UNIX
listener asks the connecting socket for the peer's credentials
(getsockopt(SOL_SOCKET, SO_PEERCRED): pid/uid/gid recorded by the kernel at connect,
no scan, no parse, and no time-of-check/time-of-use window), and the TCP listener uses
/proc/net/tcp's inode -> /proc/<pid>/fd owner with the ppid chain (the TCP analogue,
because SO_PEERCRED does not exist on an AF_INET socket). WHO CAN REACH the broker is
thereby a property of the OPERATION — which process is calling — not of the OS
environment's uid rules. Chosen over moving the unsandboxed transport to a UNIX
socket: the engine's SDK dials a TCP base URL and cannot dial a UNIX socket, so a
TCP->UNIX relay would have to sit on the same shared loopback and would itself need
this same peer check — the check IS the mechanism; the socket move would only relocate
it and add a process. Chosen over failing closed when the kernel cannot attribute a
peer: the gate refuses, never opens, which is the same posture as an empty
attribution. The per-run secret stays as the second factor on BOTH listeners, never as
the boundary — any value the engine can see, a same-uid attacker can read out of
/proc/<pid>/environ or the engine's models.json. Both gates live in _broker, so GET and
POST are gated alike, and the secret comparison stays constant-time.

WHY THE UNIX LISTENER IS PEER-GATED TOO (agents-28nn round 9, the verdict's P0)
------------------------------------------------------------------------------
Round 8 gated the TCP listener and exempted the UNIX one *by comment*: the docstring
recorded that the listener was "behind the netns boundary". That was an assumption,
not a mechanism, and it was false — the socket file is created on the HOST filesystem
(a per-run directory under /tmp, mode 0700) BEFORE its directory is bind-mounted into
the sandbox. So a same-uid host process could read the placeholder out of the engine's
environ (or the models.json pi reads), read the socket path, dial the host socket
directly and reach the upstream hop: the round-9 reviewer constructed exactly that and
got a 502 back, i.e. past the gate and onto the wire. A network namespace confines a
sandboxed process; it says nothing about a filesystem path on the host. What confines
this listener is therefore this peer gate, and only this: every connection must be
attributable to a pid inside the permitted process root, and a connection that cannot
be attributed at all is REFUSED. The process that dials here in production is the
in-sandbox net_forward relay, which lives inside the engine session's own process
tree, so the run's traffic is served and everything else on the host is not.

Design (detail on the agents-8h4 bead)
--------------------------------------
* stdlib only: the repo declares no HTTP dependency and uses urllib elsewhere, so
  this uses ``http.server`` for the listener and ``http.client`` for the upstream
  hop. ``requests`` happens to be installed but is undeclared, so it is not relied
  on.
* Routing is prefix-based and explicit: the dispatcher points each engine base URL
  at ``http://127.0.0.1:<port>/proxy/<provider>``; the SDK appends its own path, so
  the broker sees ``/proxy/<provider>/<rest>`` and forwards ``<rest>`` onto that
  provider's real upstream base. This avoids guessing the provider from the shape
  of the path.
* The listener binds 127.0.0.1 only and never logs (a request carries the prompt
  and, on the upstream side, the real key).

This module is the broker only; lib/child_env.py decides when to hand the engine a
placeholder + base URL, and the dispatcher (factory) owns the start/stop lifecycle
around a sandboxed engine run.
"""
from __future__ import annotations

import hmac
import http.client
import os
import posixpath
import secrets
import socket
import socketserver
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Iterable, Mapping, Optional, Set, Tuple
from urllib.parse import unquote, urlsplit

from lib.sandbox import SUN_PATH_LIMIT

__all__ = [
    "CredentialBroker",
    "credentials_from_env",
    "keyless_providers",
    "PROVIDERS",
    "BROKER_ENV_CONFIGS",
    "BrokerError",
    "BrokerPayloadTooLarge",
    "MAX_BROKER_BODY_BYTES",
    "MAX_BROKER_AGGREGATE_BODY_BYTES",
    "PLACEHOLDER_PREFIX",
]

MAX_BROKER_BODY_BYTES = 32 * 1024 * 1024  # 32 MiB per-request hard limit (agents-ce2)
# agents-wwd: the per-request cap alone lets N concurrent connections each hold 32 MiB of
# in-flight body => N x 32 MiB RSS via ThreadingHTTPServer. A shared budget bounds the sum.
MAX_BROKER_AGGREGATE_BODY_BYTES = 64 * 1024 * 1024  # 64 MiB aggregate across in-flight bodies

# agents-wwd: aggregate in-flight body reservation, shared across every request thread of
# every broker instance in the process. Each read reserves its declared length and releases
# it in a finally, so the sum of declared lengths can never exceed the aggregate budget.
_aggregate_body_bytes = 0
_aggregate_lock = threading.Lock()


class BrokerError(RuntimeError):
    """The broker could not be started or configured."""


class BrokerPayloadTooLarge(BrokerError):
    """Request body exceeded MAX_BROKER_BODY_BYTES."""

# provider -> (upstream base URL, auth style, env vars that may hold the real key).
# The upstream base carries whatever the SDK does NOT append: Anthropic's SDK
# appends /v1/messages to a bare origin, whereas OpenAI's SDK appends /chat/...
# to a base that already ends in /v1, so openai's upstream base includes /v1.
# Auth style is "header:<name>", "bearer", or "none" (keyless: the upstream does
# server-side auth, so the broker forwards WITHOUT injecting a key).
PROVIDERS: Dict[str, Tuple[str, str, Tuple[str, ...]]] = {
    "anthropic": ("https://api.anthropic.com", "header:x-api-key",
                  ("ANTHROPIC_API_KEY",)),
    "openai": ("https://api.openai.com/v1", "bearer",
               ("OPENAI_API_KEY",)),
    "google": ("https://generativelanguage.googleapis.com", "header:x-goog-api-key",
               ("GEMINI_API_KEY", "GOOGLE_API_KEY")),
    # Keyless BYOK providers (agents-3y2): the exe.dev managed endpoints inject auth
    # server-side, so the broker forwards these with NO key (auth style "none"). deepseek
    # and qwen serve OpenAI-style /v1 (the SDK appends /chat/completions); zai and kimi
    # serve Anthropic-style /v1/messages off the bare origin. The env-var tuple still names
    # the key the engine may read (a placeholder/dummy satisfies an SDK's non-empty check);
    # the broker never forwards that value upstream.
    "deepseek": ("https://deepseek.int.exe.xyz/v1", "none", ("DEEPSEEK_API_KEY",)),
    "zai": ("https://zai.int.exe.xyz", "none", ("ZAI_API_KEY",)),
    "kimi": ("https://kimi.int.exe.xyz", "none", ("KIMI_API_KEY",)),
    "qwen": ("https://qwen.int.exe.xyz/v1", "none", ("QWEN_API_KEY",)),
    # openrouter is OpenAI-compatible with a bearer key; its base ends in /api/v1.
    "openrouter": ("https://openrouter.ai/api/v1", "bearer", ("OPENROUTER_API_KEY",)),
}

# Per provider: (placeholder var the engine reads, base-URL var, every var that could carry a real secret for it)
BROKER_ENV_CONFIGS: Dict[str, Tuple[str, str, Tuple[str, ...]]] = {
    "anthropic": ("ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL",
                  ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN")),
    "openai": ("OPENAI_API_KEY", "OPENAI_BASE_URL", ("OPENAI_API_KEY",)),
    "google": ("GEMINI_API_KEY", "GOOGLE_GEMINI_BASE_URL",
               ("GEMINI_API_KEY", "GOOGLE_API_KEY")),
    "deepseek": ("DEEPSEEK_API_KEY", "DEEPSEEK_BASE_URL", ("DEEPSEEK_API_KEY",)),
    "zai": ("ZAI_API_KEY", "ZAI_BASE_URL", ("ZAI_API_KEY",)),
    "kimi": ("KIMI_API_KEY", "KIMI_BASE_URL", ("KIMI_API_KEY",)),
    "qwen": ("QWEN_API_KEY", "QWEN_BASE_URL", ("QWEN_API_KEY",)),
    "openrouter": ("OPENROUTER_API_KEY", "OPENROUTER_BASE_URL", ("OPENROUTER_API_KEY",)),
}

# Ensure the tables match exactly
if set(PROVIDERS) != set(BROKER_ENV_CONFIGS):
    diff = sorted(set(PROVIDERS) ^ set(BROKER_ENV_CONFIGS))
    raise BrokerError(
        f"broker mapping mismatch: PROVIDERS and BROKER_ENV_CONFIGS must define the same providers (differ on: {', '.join(diff)})"
    )

# RFC 7230 6.1 hop-by-hop headers: never forwarded in either direction.
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
})
# Headers the broker manages itself: the engine's Host/Content-Length are wrong for
# the upstream, and any auth header the engine sends carries only the placeholder,
# so all of these are dropped and re-set from the real credential.
_MANAGED_REQUEST = frozenset({
    "host", "content-length",
    "x-api-key", "authorization", "x-goog-api-key", "api-key", "key",
})
# Response headers the broker must not pass through: it re-chunks the body itself,
# so the upstream's framing headers are dropped.
_MANAGED_RESPONSE = frozenset({"content-length", "transfer-encoding", "connection"})

# The placeholder prefix. The placeholder itself is NOT a constant (agents-28nn round 7):
# each CredentialBroker generates its own at construction — `factory-broker-` plus a
# random token — and demands it back on every request, so the value the engine carries
# is the run's authentication, not a publicly known string. The prefix keeps the value
# recognisably non-vendor-shaped (no sk-/AIza/ghp_ form) for redaction and log scanning
# while the random suffix is what an unauthenticated local process cannot guess.
PLACEHOLDER_PREFIX = "factory-broker-"

# Generous upstream read timeout: a model generation can run for minutes. The
# engine's own budget (lib/budget.py) bounds the whole run; this only stops a wedged
# socket from leaking a broker thread forever.
_UPSTREAM_TIMEOUT_SECONDS = 900.0


def credentials_from_env(providers: Iterable[str] = tuple(PROVIDERS),
                         environ: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
    """The real keys present in `environ` (default os.environ), keyed by provider.

    Only providers with a usable key are returned, so the dispatcher brokers exactly
    the credentials it actually holds and leaves the rest to the normal allowlist.
    """
    source = os.environ if environ is None else environ
    found: Dict[str, str] = {}
    for provider in providers:
        if provider not in PROVIDERS:
            raise BrokerError(f"unknown provider {provider!r}")
        for var in PROVIDERS[provider][2]:
            value = source.get(var)
            if value:
                found[provider] = value
                break
    return found


def keyless_providers() -> Tuple[str, ...]:
    """Providers whose upstream does server-side auth (auth style "none").

    These are the exe.dev managed BYOK endpoints (agents-3y2): the broker forwards their
    requests with NO injected key, so they can be brokered even when the host holds no real
    credential for them. The dispatcher adds them to the broker's provider set so a
    sandboxed engine still reaches them through the host-side forwarder.
    """
    return tuple(p for p, (_base, auth, _vars) in PROVIDERS.items() if auth == "none")


def _established_tcp_peer_pids(peer_port: int, proc_root: str = "/proc") -> Set[int]:
    """The pids holding an ESTABLISHED 127.0.0.1:<peer_port> TCP socket — the kernel's own
    record of who is on the other end of a loopback connection (agents-28nn round 8).

    /proc/net/tcp maps the connection's local address to a socket inode; /proc/<pid>/fd
    maps the inode to its owning processes. Both are kernel truth a same-uid process
    cannot forge: it can rename itself or its argv, but it cannot make the kernel
    attribute its socket to another pid. Anything unreadable — no row, no fd owner, no
    /proc at all — yields an EMPTY set, so the caller fails closed.
    """
    inodes: Set[str] = set()
    want = f"0100007F:{peer_port:04X}"  # 127.0.0.1:<port>, /proc/net/tcp hex
    try:
        with open(f"{proc_root}/net/tcp", "r", encoding="ascii") as fh:
            rows = fh.readlines()[1:]
    except OSError:
        return set()
    for row in rows:
        parts = row.split()
        # sl, local_address, rem_address, st, ..., inode. 01 is ESTABLISHED — the state
        # accept() returns a connection in; a TIME_WAIT (06) socket has no owning fd and
        # so can never attribute a pid, and a 4-tuple can be held ESTABLISHED by exactly
        # one connection, so the port identifies this connection and no other.
        if len(parts) < 10 or parts[3] != "01" or parts[1] != want:
            continue
        inodes.add(parts[9])
    if not inodes:
        return set()
    pids: Set[int] = set()
    try:
        entries = os.listdir(proc_root)
    except OSError:
        return set()
    for entry in entries:
        if not entry.isdigit():
            continue
        fd_dir = os.path.join(proc_root, entry, "fd")
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue  # the process exited mid-scan, or its fds are unreadable
        for fd in fds:
            try:
                target = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if target.startswith("socket:[") and target[8:-1] in inodes:
                pids.add(int(entry))
                break
    return pids


def _stat_start_time(stat: str) -> Optional[int]:
    """Field 22 of a /proc/<pid>/stat line — the process's START TIME, in clock ticks
    since boot — or None when the line is too short or malformed, which the callers treat
    as "no identity" and refuse (agents-28nn round 11).

    `comm` is the parenthesised second field and may itself contain spaces or a ')', so
    every index is counted from the LAST ')' : field 3 (state) is fields[0] and field 22
    (starttime) is fields[19] (proc(5))."""
    close = stat.rfind(")")
    if close < 0:
        return None
    fields = stat[close + 1:].split()
    if len(fields) < 20:
        return None
    try:
        return int(fields[19])
    except ValueError:
        return None


def _proc_start_time(pid: int, proc_root: str = "/proc") -> Optional[int]:
    """The start time of the process holding `pid` NOW — captured from /proc, never
    inferred (agents-28nn round 11). This is the half of the peer root's identity that a
    pid cannot supply: the kernel reuses pids, so two different processes answer to one
    pid at different times, and only the start time tells them apart. Returns None when
    /proc/<pid>/stat cannot be read or parsed; the gate REFUSES every peer in that case
    rather than falling back to trusting the pid, so an unestablishable identity fails
    closed."""
    try:
        with open(f"{proc_root}/{pid}/stat", "r", encoding="ascii") as fh:
            stat = fh.read()
    except OSError:
        return None
    return _stat_start_time(stat)


def _pid_in_tree(pid: int, root: Optional[int], root_start: Optional[int],
                 proc_root: str = "/proc", _limit: int = 128) -> bool:
    """Whether `pid` is `root` or one of its descendants, by the kernel's ppid chain
    (agents-28nn round 8). A process cannot re-parent itself INTO a tree — ppid only
    ever moves toward init (orphaning) — so the chain is forgery-proof, and a
    pre-pass-spawned attacker that outlived the pre-pass reads as a child of init, not
    of the engine. The walk reads only LIVE /proc state, so a dead or unreadable link
    fails closed, and a REUSED pid is refused: for a descendant because its ppid chain no
    longer reaches the root, and for THE ROOT because its start time no longer matches
    `root_start`, the value captured when the root was set (agents-28nn round 11 — the
    root is the one link the chain cannot vouch for, so it is pinned to (pid, start
    time); a root_start of None REFUSES). `_limit` bounds the walk against a corrupt
    chain."""
    current = pid
    for _ in range(_limit):
        if current <= 1:
            # A root of pid 1 is refused here before the root check below, and that is
            # unreachable BY CONSTRUCTION: restrict_peer_root receives a spawned child's pid.
            return False
        try:
            with open(f"{proc_root}/{current}/stat", "r", encoding="ascii") as fh:
                stat = fh.read()
        except OSError:
            return False  # the process exited mid-check: nothing left to trust
        # Below the /proc read on purpose: a short-circuit before a verification is an
        # unverified path — the root must not skip whether it still EXISTS, nor WHICH
        # process holds that pid. A PID IS REUSED AND A START TIME IS NOT, so the root is
        # (pid, start time): a recycled pid has a different start time and is refused. An
        # unreadable start time (None) refuses too, never a fall-back to trusting the pid.
        if current == root:
            return root_start is not None and _stat_start_time(stat) == root_start
        close = stat.rfind(")")  # comm is parenthesised and may contain spaces or ')'
        if close < 0:
            return False
        fields = stat[close + 1:].split()  # field 3 (state) onward; ppid is next
        if len(fields) < 2:
            return False
        try:
            current = int(fields[1])
        except ValueError:
            return False
    return False


def _unix_peer_pids(connection: socket.socket) -> Set[int]:
    """The kernel's attribution of an AF_UNIX connection's peer (agents-28nn round 9).

    getsockopt(SOL_SOCKET, SO_PEERCRED) returns the struct ucred the kernel recorded for
    the peer AT CONNECT: pid, uid and gid. unix(7): the pid is reported in the PID
    namespace of the CALLING process — this broker runs in the host namespace, so the
    pid it receives is the host pid that owns the peer's end of the connection, which is
    what /proc (and _pid_in_tree) can speak about. Nothing is scanned or parsed here, so
    there is no /proc race and no time-of-check/time-of-use window, and the value cannot
    be forged from userspace: no process can make the kernel attribute its connection to
    another process. A socket that cannot answer the call, or a kernel that reports no
    pid, yields an EMPTY set so the caller refuses.
    """
    try:
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                    struct.calcsize("3i"))
    except OSError:
        return set()
    pid = struct.unpack("3i", raw)[0]
    return {pid} if pid > 0 else set()


def _peer_pids(connection: socket.socket, client_address) -> Set[int]:
    """The kernel's attribution of the process on the other end of `connection`,
    resolved per transport (agents-28nn round 9). Transports differ in the mechanism and
    nowhere else: an AF_UNIX peer answers SO_PEERCRED, and an AF_INET loopback peer is
    found through /proc/net/tcp's inode -> owning fd. Anything else — another address
    family, a non-loopback TCP peer — yields an EMPTY set, which the decision below
    REFUSES, so a transport added later fails closed until it names a mechanism of its
    own rather than silently inheriting an exemption (which is how the round-9 hole
    appeared).
    """
    if getattr(connection, "family", None) == socket.AF_UNIX:
        return _unix_peer_pids(connection)
    if (getattr(connection, "family", None) == socket.AF_INET
            and client_address and client_address[0] == "127.0.0.1"):
        return _established_tcp_peer_pids(client_address[1])
    return set()


def _peer_is_permitted(pids: Iterable[int], root: Optional[int],
                       root_start: Optional[int]) -> bool:
    """THE decision every transport reaches (agents-28nn rounds 8-9): a connection is
    served only when the kernel attributes its peer to `root` or to a descendant of it.

    There is deliberately ONE such function. The round-9 verdict's hole existed because
    the two listeners had two code paths and one of them answered "trusted" without
    checking anything; a second decision is a second place for that to happen. `root` is
    the permitted process root the broker was started with, which restrict_peer_root
    narrows to the engine session, and `root_start` is that process's start time
    (agents-28nn round 11): the root is identified by the PAIR, because a pid alone can be
    reused by an unrelated process and would otherwise stand in for the root. A root that
    is not a pid (never set), a start time that could not be read, and an empty
    attribution all REFUSE.
    """
    return any(_pid_in_tree(pid, root, root_start) for pid in pids)


class _Handler(BaseHTTPRequestHandler):
    """Forwards one engine request to its provider, injecting the real credential.

    `credentials` is bound by CredentialBroker.start() to a per-server subclass; it
    maps provider -> real key and lives only in this (host-side) process.
    """

    protocol_version = "HTTP/1.1"
    server_version = "factory-credential-broker/1.0"
    credentials: Dict[str, Optional[str]] = {}
    allowed_providers: Optional[Set[str]] = None
    # The run's per-run secret (agents-28nn round 7), bound by start(). Every request
    # must present it in a provider auth header; without it the listener is an open
    # proxy that injects the raw credentials for any local process that dials.
    run_secret: str = ""

    # --- helpers -------------------------------------------------------------
    def _respond_error(self, code: int, message: str) -> None:
        self.close_connection = True
        body = message.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if self.close_connection:
            # agents-wwd: a 413/400 that rejected an unread or oversized body must tell the
            # client the connection is closing, else a keep-alive client would re-send onto a
            # stream whose unread bytes are still queued.
            self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _read_request_body(self) -> Optional[bytes]:
        global _aggregate_body_bytes
        length_str = self.headers.get("Content-Length")
        if length_str is not None:
            length_raw = length_str.strip()
            # agents-wwd: RFC 7230 Content-Length is 1*DIGIT. Reject non-canonical forms
            # (int() would silently accept "1_0" -> 10 and "+5" -> 5); keep the distinct
            # message for a negative value.
            if length_raw.startswith("-") and length_raw[1:].isdigit():
                self.close_connection = True
                raise BrokerError("negative Content-Length header is not allowed")
            if not length_raw.isdigit():
                self.close_connection = True
                raise BrokerError("invalid Content-Length header (must be an integer)")
            length = int(length_raw)
            if length > MAX_BROKER_BODY_BYTES:
                self.close_connection = True
                raise BrokerPayloadTooLarge(
                    f"request body ({length} bytes) exceeds maximum limit of {MAX_BROKER_BODY_BYTES} bytes"
                )

            # agents-wwd: reserve this request's declared length against the shared aggregate
            # budget BEFORE reading, so N concurrent near-cap bodies cannot sum to N x 32 MiB.
            with _aggregate_lock:
                if _aggregate_body_bytes + length > MAX_BROKER_AGGREGATE_BODY_BYTES:
                    self.close_connection = True
                    raise BrokerPayloadTooLarge("aggregate in-flight request body budget exceeded")
                _aggregate_body_bytes += length

            try:
                # Add a timeout so a stalled engine connection cannot pin the daemon thread
                # (agents-wwd: this is per-read, not a total deadline — a trickling client can
                # still hold the thread one read at a time; the broker is localhost-only and
                # dies with the run, so that slowloris shape is accepted).
                old_timeout = self.connection.gettimeout()
                self.connection.settimeout(15.0)
                try:
                    chunks = []
                    remaining = length
                    chunk_size = 64 * 1024
                    # agents-wwd: the body cap is the declared Content-Length checked above —
                    # `remaining` counts down to exactly `length` and read(n) never over-reads,
                    # so no independent byte counter is needed (the old `total_read` counter
                    # was unreachable dead code).
                    while remaining > 0:
                        to_read = min(remaining, chunk_size)
                        chunk = self.rfile.read(to_read)
                        if not chunk:
                            self.close_connection = True
                            raise BrokerError("unexpected end of stream while reading request body")
                        chunks.append(chunk)
                        remaining -= len(chunk)
                    return b"".join(chunks)
                finally:
                    self.connection.settimeout(old_timeout)
            except (BrokerPayloadTooLarge, BrokerError):
                raise
            except OSError as e:
                self.close_connection = True
                raise BrokerError(f"failed to read request body: {e}") from e
            finally:
                with _aggregate_lock:
                    _aggregate_body_bytes -= length
        # A chunked request body from the engine is not expected (SDKs send
        # Content-Length); refuse rather than guess.
        if (self.headers.get("Transfer-Encoding") or "").lower() == "chunked":
            self.close_connection = True
            raise BrokerError("chunked request body from the engine is not supported")
        return None

    def _upstream_headers(self) -> Dict[str, str]:
        headers = {}
        for name, value in self.headers.items():
            low = name.lower()
            if low in _HOP_BY_HOP or low in _MANAGED_REQUEST:
                continue
            headers[name] = value
        return headers

    # --- the broker hop ------------------------------------------------------
    def _request_authenticated(self) -> bool:
        """Whether the request presented the run's per-run secret in a provider auth
        header (agents-28nn round 7, the verdict's P0). On the unsandboxed path this
        listener sits on the HOST's loopback — a shared interface — so possession of
        the placeholder is what distinguishes the engine the broker serves from any
        other local process. Constant-time comparison; any of the auth header shapes
        the SDKs use counts (x-api-key / Authorization Bearer / x-goog-api-key /
        api-key), and the broker strips and re-sets them all downstream regardless.

        The general form this fix instances (agents-28nn round 7): WHEN A FIX MOVES A
        CONTROL TO A DIFFERENT LEVEL, THE NEXT QUESTION IS NOT "IS IT IN THE RIGHT
        PLACE" BUT "WHO CAN REACH IT FROM HERE" — the old level carried an implied
        boundary (a namespace, a uid, a mount) that the new level does not inherit;
        the sandboxed loopback was confined by the network namespace, the unsandboxed
        one is the host's, same code, same address, no confinement."""
        secret = self.run_secret
        if not secret:  # pragma: no cover - start() always binds one
            return False
        candidates = []
        for name in ("x-api-key", "x-goog-api-key", "api-key"):
            value = self.headers.get(name)
            if value:
                candidates.append(value.strip())
        authorization = (self.headers.get("authorization") or "").strip()
        if authorization:
            candidates.append(authorization)
            if authorization.lower().startswith("bearer "):
                candidates.append(authorization[7:].strip())
        return any(hmac.compare_digest(candidate, secret) for candidate in candidates)

    def _peer_is_trusted(self) -> bool:
        """Whether the process holding THIS connection is inside the process tree the
        broker serves (agents-28nn rounds 8-9, both verdicts' P0). Identity before
        knowledge: the per-run secret is readable by any same-uid process (the engine's
        /proc/<pid>/environ, the models.json pi reads), so possession cannot distinguish
        the engine from an attacker — the kernel's attribution of the connecting socket
        can. Every transport reaches this one decision through _peer_is_permitted; a
        transport only names the kernel mechanism that supplies the peer's identity
        (_peer_pids). There is NO exempt listener, and round 9's P0 was exactly a path
        that skipped this check on a comment's authority.

        WHAT IS ENFORCED HERE, stated instead of assumed (agents-28nn round 9):
        * the UNIX listener's socket file lives on the HOST filesystem, created before
          its directory is bind-mounted into the sandbox — the netns confines the
          sandboxed process, not the host path — so this peer gate, not a namespace, is
          what confines who may use that listener;
        * that peer's identity comes from getsockopt(SO_PEERCRED), which the kernel
          records at connect: no /proc scan, no parsing, no time-of-check/time-of-use
          window, and nothing a peer can forge from userspace;
        * a connection whose peer cannot be attributed yields no pids and is REFUSED,
          never assumed good: an unattributable peer on a host-visible socket is the
          attacker, not the engine;
        * the kernel fixes the peer's ATTRIBUTION at connect (SO_PEERCRED) while the
          GATE IS DECIDED PER REQUEST, not per connection: every GET and POST reaches
          this decision again, and it is answered from LIVE /proc during request
          processing (http.server reads all request headers before dispatching to
          do_GET/do_POST). So the capability is not the CONNECTION — a socket served
          once is refused on a later request once its peer's identity no longer holds,
          and round 10 constructed a request IN FLIGHT as the root exited and it was
          refused. A hand-off still works, because attribution follows the socket: the
          process that opened it may use it, and anything it hands that socket to
          reaches nothing the engine could not reach directly (pinned by the FD test).

        KEPT AS JUDGED (round 9), each recorded so a reader need not re-derive it:
        * the default root — this process's own pid — is safe because nothing untrusted
          runs between broker.start() and restrict_peer_root(): the pre-pass has been
          reaped before the broker starts (run_station_command blocks on it) and an
          orphaned background process re-parents to init, outside this tree;
        * the orphan boundary is INTENDED, not a leak: once the gate's root exits its
          descendants re-parent toward init, so the gate closes WITH THE SESSION rather
          than at broker teardown.

        THE LEVEL THESIS THIS GATE IMPLEMENTS (coord, round 8): the reachability
        question must be asked about the new level in the new level's OWN TERMS — a
        namespace answers "everything inside it", a secret answers "everyone who does
        not know it", and those are different questions; that is why the netns's
        confinement vanished the moment the control moved to a secret. Peer identity
        is the PRIMARY mechanism — it converts WHO CAN REACH the broker from a hope
        into a kernel-supplied fact — and it binds LIFETIME as a second layer, never
        a substitute: the moment the gate's root exits, its descendants re-parent
        toward init and their ppid chains no longer contain it, so the gate closes
        WITH THE SESSION rather than at teardown (constructed: an orphaned descendant
        still holding the placeholder is refused, no upstream hop). Lifetime binding
        only narrows the window; the peer attack needs no window, only the engine
        running — so the identity check, not the lifetime, carries the weight."""
        return _peer_is_permitted(_peer_pids(self.connection, self.client_address),
                                  self.server.peer_gate_root,
                                  self.server.peer_gate_root_start)

    def _broker(self, method: str) -> None:
        if not self._peer_is_trusted():
            # Refused BEFORE the secret is even consulted and before any path processing
            # or upstream hop: a same-uid process outside the run's process tree holding
            # the STOLEN placeholder gets the same 403 as one holding nothing.
            return self._respond_error(
                403, "the credential broker serves only the run's own process tree; "
                     "this connection's peer is not in it")
        if not self._request_authenticated():
            # Refused BEFORE any path processing or upstream hop: an unauthenticated
            # caller learns nothing (not even whether a provider is configured) and
            # the broker never injects a credential on its behalf.
            return self._respond_error(
                403, "the credential broker requires the run's per-run secret; "
                     "unauthenticated requests are refused")
        path_only, _, query = self.path.partition("?")
        decoded_path = posixpath.normpath(unquote(path_only))
        segments = [s for s in decoded_path.split("/") if s != ""]
        # Expect: proxy / <provider> / <rest...>
        if len(segments) < 2 or segments[0] != "proxy":
            return self._respond_error(404, "not a broker path (expected /proxy/<provider>/...)")
        provider = segments[1].lower()
        if provider not in PROVIDERS:
            return self._respond_error(404, f"unknown provider {provider!r}")
        if self.allowed_providers is not None and provider not in self.allowed_providers:
            return self._respond_error(403, f"provider {provider!r} is not allowed for this run")
        rest = "/" + "/".join(segments[2:])
        if provider not in self.credentials:
            # Not configured for this provider: fail closed rather than forward the
            # engine's placeholder (which the provider would reject anyway, and
            # which must never be mistaken for a working credential).
            return self._respond_error(502, f"broker holds no credential for {provider!r}")

        upstream_base, auth_style, _ = PROVIDERS[provider]
        key = self.credentials[provider]
        if key is None and auth_style != "none":
            # A keyed provider with no key: fail closed rather than send "Bearer None".
            return self._respond_error(502, f"broker holds no credential for {provider!r}")
        try:
            body = self._read_request_body()
        except BrokerPayloadTooLarge as e:
            return self._respond_error(413, str(e))
        except BrokerError as e:
            return self._respond_error(400, str(e))

        headers = self._upstream_headers()
        if auth_style == "bearer":
            headers["Authorization"] = f"Bearer {key}"
        elif auth_style.startswith("header:"):
            headers[auth_style.split(":", 1)[1]] = key
        elif auth_style == "none":
            pass  # keyless upstream: it injects auth server-side (agents-3y2)
        else:  # pragma: no cover - guarded by PROVIDERS being a fixed table
            return self._respond_error(500, f"bad auth style {auth_style!r}")

        split = urlsplit(upstream_base)
        upstream_path = split.path.rstrip("/") + rest
        if query:
            upstream_path += "?" + query

        conn = http.client.HTTPSConnection(split.hostname, split.port or 443,
                                           timeout=_UPSTREAM_TIMEOUT_SECONDS)
        try:
            conn.request(method, upstream_path, body=body, headers=headers)
            response = conn.getresponse()
        except Exception as e:  # the upstream is unreachable / TLS failed
            # Never echo the exception verbatim: it can contain the URL, and we keep
            # the operator's key out of anything that reaches the engine.
            return self._respond_error(502, f"upstream request failed: {type(e).__name__}")

        try:
            self.send_response(response.status, response.reason)
            for name, value in response.getheaders():
                if name.lower() in _HOP_BY_HOP or name.lower() in _MANAGED_RESPONSE:
                    continue
                self.send_header(name, value)
            # Stream the body back chunk-by-chunk so an SSE response reaches the
            # engine incrementally instead of being buffered to completion.
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            while True:
                chunk = response.read1(65536)
                if not chunk:
                    break
                self.wfile.write(b"%x\r\n" % len(chunk) + chunk + b"\r\n")
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass  # the engine went away mid-stream; nothing to salvage
        finally:
            conn.close()

    def do_POST(self) -> None:  # noqa: N802 - http.server hook
        self._broker("POST")

    def do_GET(self) -> None:  # noqa: N802 - http.server hook
        self._broker("GET")

    # Never log: a request carries the prompt and the upstream side carries the key.
    def log_message(self, *args, **kwargs) -> None:  # noqa: D102
        return


class _PeerGated:
    """Every broker listener carries the permitted peer root, and there is no listener
    without one (agents-28nn round 9). Declaring it once is the structural half of this
    fix: round 9's P0 was a listener that carried no root and therefore answered
    "trusted" without checking anything, so a new transport must now take this attribute
    or fail in a way no reader can mistake for a review. None is NOT an exemption — a
    root that is not a pid refuses every peer (see _peer_is_permitted) — and start()
    always sets the dispatcher's own pid.

    THE ROOT IS A PAIR, NEVER A PID ALONE (agents-28nn round 11): `peer_gate_root` is the
    pid and `peer_gate_root_start` is that process's start time, read from /proc when the
    root is set, and the gate requires BOTH to match. A pid is reused by the kernel and a
    start time is not, so a pid on its own cannot say which process holds it; any site
    that sets `peer_gate_root` must set `peer_gate_root_start` from that same live
    process, and a start time that could not be read (None) refuses every peer rather
    than falling back to trusting the pid."""
    peer_gate_root: Optional[int] = None
    peer_gate_root_start: Optional[int] = None


class _BrokerServer(_PeerGated, ThreadingHTTPServer):
    """A ThreadingHTTPServer whose request threads are daemons, so a wedged upstream
    cannot outlive the run. Subclassed rather than mutating the class attribute, which
    would leak the setting to every other ThreadingHTTPServer in the process."""
    daemon_threads = True


class _BrokerUnixServer(_PeerGated, socketserver.ThreadingUnixStreamServer):
    """The UNIX-socket twin of _BrokerServer, for a sandboxed engine under
    bwrap --unshare-net (agents-2x6): the child has no route to a host TCP loopback, so
    the broker listens on a UNIX socket bind-mounted into the sandbox and reached through
    the in-sandbox net_forward relay. Same handler, same daemon-thread teardown.

    PEER-GATED LIKE THE TCP LISTENER (agents-28nn round 9). The socket file is created
    on the HOST filesystem before its directory is bind-mounted into the sandbox, so a
    same-uid host process can reach the path and the netns — which confines the
    sandboxed child, not a host path — is not what protects this listener. The peer
    decision is: the kernel answers who connected (SO_PEERCRED), and the connection is
    served only if that process is the dispatcher's or, once narrowed, inside the engine
    session's tree. The in-sandbox relay that carries the engine's traffic lives in that
    session's tree, so the run is served and anything else on the host is not."""
    daemon_threads = True


class CredentialBroker:
    """A localhost credential-broker proxy, started and stopped by the dispatcher.

    Usage::

        creds = credentials_from_env()          # {'anthropic': 'sk-ant-...'}
        with CredentialBroker(creds) as broker:
            url = broker.base_url("anthropic")  # http://127.0.0.1:<port>/proxy/anthropic
            # hand `url` + broker.placeholder to the engine's env

    The real keys live only in this object (host side); the engine gets `url` and the
    per-run placeholder, which IS the run's authentication: the broker refuses any
    request that does not present it (agents-28nn round 7 — on the unsandboxed path
    the listener sits on the host's shared loopback, so an unauthenticated broker
    would be an open proxy injecting the raw credentials for any local process).
    stop() is idempotent and always runs (context manager / finally), so no listener
    leaks.
    """

    def __init__(self, credentials: Mapping[str, Optional[str]],
                 allowed_providers: Optional[Iterable[str]] = None):
        unknown = sorted(set(credentials) - set(PROVIDERS))
        if unknown:
            raise BrokerError(f"unknown provider(s): {', '.join(unknown)}")
        self._allowed_providers: Optional[Set[str]] = None
        if allowed_providers is not None:
            allowed_set = set(allowed_providers)
            unknown_allowed = sorted(allowed_set - set(PROVIDERS))
            if unknown_allowed:
                raise BrokerError(f"unknown allowed provider(s): {', '.join(unknown_allowed)}")
            self._allowed_providers = allowed_set

        # Keyless providers (auth "none") carry a None value: the broker forwards them
        # without a key (agents-3y2). Keyed providers carry the real key, held only here.
        self._credentials: Dict[str, Optional[str]] = dict(credentials)
        # The per-run secret the engine receives as its placeholder API key and the
        # broker demands back on every request. Generated here so each run — and each
        # test — gets a value no other process can know in advance. Round 8: the
        # second factor on the TCP listener, not the boundary — the peer gate is.
        self._placeholder = PLACEHOLDER_PREFIX + secrets.token_urlsafe(18)
        self._server: Optional[socketserver.BaseServer] = None
        self._thread: Optional[threading.Thread] = None
        self.port: Optional[int] = None
        self.unix_path: Optional[str] = None
        # In UNIX mode the sandboxed child dials the net_forward relay's port, not the
        # broker; the dispatcher passes that port so base_url() can name it (agents-2x6).
        self._child_port: Optional[int] = None

    @property
    def placeholder(self) -> str:
        """The run's per-run secret: the engine's placeholder API key AND the second
        factor the broker requires on every request. It is NOT the boundary on either
        listener — a same-uid process can read it from the engine's environ, and the
        round-9 verdict read it and dialled the UNIX socket with it — the peer gate is
        (agents-28nn rounds 8-9); the secret remains as defence in depth on both paths.
        Not a provider key — exfiltrating it yields only broker access, for this run's
        lifetime, to this run's allowed providers."""
        return self._placeholder

    @property
    def providers(self) -> Tuple[str, ...]:
        if self._allowed_providers is not None:
            return tuple(p for p in self._credentials if p in self._allowed_providers)
        return tuple(self._credentials)

    @property
    def allowed_providers(self) -> Optional[Tuple[str, ...]]:
        if self._allowed_providers is not None:
            return tuple(sorted(self._allowed_providers))
        return None

    def start(self, unix_path: Optional[str] = None,
              child_port: Optional[int] = None) -> int:
        """Serve in a daemon thread. By default bind 127.0.0.1 on a dynamic TCP port and
        return it. When `unix_path` is given (agents-2x6: a sandboxed engine under
        bwrap --unshare-net cannot reach a host TCP loopback), bind a UNIX socket there
        instead and return 0; the child reaches it through the net_forward relay listening
        on `child_port`, which base_url() then names. `child_port` is required with
        `unix_path` so the engine's *_BASE_URL can point at the relay."""
        if self._server is not None:
            raise BrokerError("broker already started")
        if not self._credentials:
            raise BrokerError("refusing to start a broker with no credentials")
        handler = type("_BoundBrokerHandler", (_Handler,),
                       {"credentials": dict(self._credentials),
                        "allowed_providers": set(self._allowed_providers) if self._allowed_providers is not None else None,
                        "run_secret": self._placeholder})
        if unix_path is not None:
            if child_port is None:
                raise BrokerError("unix_path requires child_port (the net_forward relay "
                                  "port the engine's base URL names)")
            # agents-x8l: AF_UNIX sun_path holds at most 107 bytes; refuse a long path loudly
            # instead of failing bind() with a cryptic ENAMETOOLONG deep in the server thread.
            if len(unix_path) > SUN_PATH_LIMIT:
                raise BrokerError(
                    f"UNIX socket path {unix_path!r} is {len(unix_path)} bytes, over the "
                    f"{SUN_PATH_LIMIT}-byte AF_UNIX sun_path limit; use a shorter socket path")
            # A stale socket file from a crashed run would make bind() fail EADDRINUSE.
            try:
                if os.path.exists(unix_path):
                    os.unlink(unix_path)
            except OSError:
                pass
            self._server = _BrokerUnixServer(unix_path, handler)
            self.unix_path = unix_path
            self._child_port = child_port
            self.port = None
        else:
            self._server = _BrokerServer(("127.0.0.1", 0), handler)
            self.port = self._server.server_address[1]
        # agents-28nn rounds 8-9: BOTH listeners are peer-gated from birth, because both
        # are reachable from outside the sandbox — the TCP one on the HOST's shared
        # loopback (agents-28nn round 8), the UNIX one through its socket file on the
        # HOST filesystem (agents-28nn round 9, whose verdict connected to it directly).
        # From here the gate serves only connections whose peer is in THIS process's tree
        # (the dispatcher's; the engine session it is about to spawn is a child of it),
        # and the dispatcher narrows it to the engine session's own pid the moment the
        # engine exists (restrict_peer_root, via run_station_command's on_spawn).
        # Round 11: the default root is pinned the same way a narrowed one is — the pid
        # AND the start time of this process, read live here.
        self._server.peer_gate_root = os.getpid()
        self._server.peer_gate_root_start = _proc_start_time(os.getpid())
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        name="credential-broker", daemon=True)
        self._thread.start()
        return self.port or 0

    def restrict_peer_root(self, pid: int) -> None:
        """Narrow EVERY listener's peer gate to `pid`'s subtree (agents-28nn rounds
        8-9): the dispatcher calls this with the engine session's pid the moment the
        engine is spawned, so the broker serves exactly the process it was started for —
        the engine and its descendants — and no other descendant of the dispatcher.

        There is no listener this leaves alone. Round 8 exempted the UNIX listener from
        this call on the ground that its peer is "an ancestor of the engine", which was
        the same mistaken assumption the gate itself rested on; it is also wrong about
        the tree. The pid passed here is the ENGINE SESSION's spawned pid (the bwrap
        wrap, or the command itself), and the in-sandbox net_forward relay is INSIDE
        that tree — the wrap's tree is wrap -> relay -> engine — so narrowing serves the
        run's own relay, while the socket file on the host filesystem stops being
        reachable by everything else.

        The root is pinned to (pid, START TIME) as well as named by pid (agents-28nn
        round 11): the pid alone is not an identity, because the kernel reuses pids, so a
        root that exits and whose pid is later handed to an unrelated process would
        otherwise be found "alive" by the gate. The start time is captured HERE, from the
        live process, at the moment the root is established. If it cannot be read, the
        gate fails CLOSED: the start time is left as None, which refuses every peer (see
        _pid_in_tree) rather than falling back to trusting the pid."""
        server = self._server
        if server is not None:
            server.peer_gate_root = pid
            server.peer_gate_root_start = _proc_start_time(pid)

    def base_url(self, provider: str) -> str:
        """The engine-side base URL for `provider` (points at this broker). In UNIX mode
        the engine dials the net_forward relay's child_port (which forwards to the broker
        socket); in TCP mode it dials the broker's own loopback port."""
        if provider not in PROVIDERS:
            raise BrokerError(f"unknown provider {provider!r}")
        if self._allowed_providers is not None and provider not in self._allowed_providers:
            raise BrokerError(f"provider {provider!r} is not allowed for this run")
        if provider not in self._credentials:
            raise BrokerError(f"broker has no credential for {provider!r}")
        port = self._child_port if self._child_port is not None else self.port
        if port is None:
            raise BrokerError("broker not started")
        return f"http://127.0.0.1:{port}/proxy/{provider}"

    def stop(self) -> None:
        """Shut the listener down. Idempotent; safe to call from a finally."""
        server, self._server = self._server, None
        thread, self._thread = self._thread, None
        if server is not None:
            try:
                server.shutdown()
                server.server_close()
            except Exception:  # noqa: BLE001 - teardown is best-effort
                pass
        if thread is not None:
            thread.join(timeout=5)
        # A UNIX listener leaves its socket file behind; remove it so a later run (or a
        # crash recovery) does not hit EADDRINUSE and no stale inode lingers in run_dir.
        unix_path, self.unix_path = self.unix_path, None
        if unix_path is not None:
            try:
                if os.path.exists(unix_path):
                    os.unlink(unix_path)
            except OSError:
                pass
        self.port = None
        self._child_port = None

    def __enter__(self) -> "CredentialBroker":
        self.start()
        return self

    def __exit__(self, *exc_info) -> bool:
        self.stop()
        return False
