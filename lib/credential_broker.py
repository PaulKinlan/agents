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
asymmetry: any value the engine can see, the attacker can see. So the TCP listener
authenticates by PEER IDENTITY first: the kernel's own attribution of the connecting
socket (/proc/net/tcp's inode -> /proc/<pid>/fd owner, then the ppid chain — the TCP
analogue of SO_PEERCRED on a UNIX socket), accepting only the dispatcher's process
tree, narrowed to the ENGINE SESSION's tree the moment the engine exists
(restrict_peer_root). WHO CAN REACH the broker is thereby a property of the OPERATION
— which process is calling — not of the OS environment's uid rules. Chosen over moving
the transport to a UNIX socket with SO_PEERCRED: the engine's SDK dials a TCP base URL
and cannot dial a UNIX socket, so a TCP->UNIX relay would have to sit on the same
shared loopback and would itself need this same peer check — the check IS the
mechanism; the socket move would only relocate it and add a process. Chosen over
failing closed on the unsandboxed path: that posture remains for when the kernel's
tables are unreadable (the gate refuses, never opens), but with /proc present the
operation can confine the broker itself. The per-run secret stays as the second
factor — and as the only check the UNIX listener needs, its boundary being the sandbox
netns. Both gates live in _broker, so GET and POST are gated alike, and the secret
comparison stays constant-time.

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
import socketserver
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


def _pid_in_tree(pid: int, root: int, proc_root: str = "/proc", _limit: int = 128) -> bool:
    """Whether `pid` is `root` or one of its descendants, by the kernel's ppid chain
    (agents-28nn round 8). A process cannot re-parent itself INTO a tree — ppid only
    ever moves toward init (orphaning) — so the chain is forgery-proof, and a
    pre-pass-spawned attacker that outlived the pre-pass reads as a child of init, not
    of the engine. The walk reads only LIVE /proc state, so a reused pid answers for
    the process that holds it now; a dead or unreadable link fails closed. `_limit`
    bounds the walk against a corrupt chain."""
    current = pid
    for _ in range(_limit):
        if current == root:
            return True
        if current <= 1:
            return False
        try:
            with open(f"{proc_root}/{current}/stat", "r", encoding="ascii") as fh:
                stat = fh.read()
        except OSError:
            return False  # the process exited mid-check: nothing left to trust
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
        broker serves (agents-28nn round 8, the verdict's reopened P0). Identity before
        knowledge: on the host's shared loopback the per-run secret is readable by any
        same-uid process (the engine's /proc/<pid>/environ, models.json), so possession
        cannot distinguish the engine from an attacker — the kernel's attribution of
        the connecting socket can. The gate exists only where no stronger kernel
        boundary already does the work: the UNIX listener serves the in-sandbox relay
        behind the netns boundary and never carries peer_gate_root.

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
        root = getattr(self.server, "peer_gate_root", None)
        if root is None:
            return True
        if self.client_address[0] != "127.0.0.1":
            return False
        pids = _established_tcp_peer_pids(self.client_address[1])
        return any(_pid_in_tree(pid, root) for pid in pids)

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


class _BrokerServer(ThreadingHTTPServer):
    """A ThreadingHTTPServer whose request threads are daemons, so a wedged upstream
    cannot outlive the run. Subclassed rather than mutating the class attribute, which
    would leak the setting to every other ThreadingHTTPServer in the process."""
    daemon_threads = True


class _BrokerUnixServer(socketserver.ThreadingUnixStreamServer):
    """The UNIX-socket twin of _BrokerServer, for a sandboxed engine under
    bwrap --unshare-net (agents-2x6): the child has no route to a host TCP loopback, so
    the broker listens on a UNIX socket bind-mounted into the sandbox and reached through
    the in-sandbox net_forward relay. Same handler, same daemon-thread teardown."""
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
        factor the broker requires on every request. On the unsandboxed path it is NOT
        the boundary — a same-uid process can read it from the engine's environ — the
        peer gate is (agents-28nn round 8); the secret remains as defence in depth and
        as the only check the UNIX listener needs, its boundary being the sandbox
        netns. Not a provider key — exfiltrating it yields only broker access, for this
        run's lifetime, to this run's allowed providers."""
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
            # agents-28nn round 8 (the verdict's reopened P0): this TCP listener sits on
            # the HOST's shared loopback, so it is peer-gated from birth — it serves only
            # connections whose owning process is in THIS process's tree (the
            # dispatcher's; the engine session it is about to spawn is a child of it).
            # The dispatcher narrows the gate to the engine session's own pid the moment
            # the engine exists (restrict_peer_root, via run_station_command's on_spawn).
            self._server.peer_gate_root = os.getpid()
            self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        name="credential-broker", daemon=True)
        self._thread.start()
        return self.port or 0

    def restrict_peer_root(self, pid: int) -> None:
        """Narrow the TCP listener's peer gate to `pid`'s subtree (agents-28nn round 8):
        the dispatcher calls this with the engine session's pid the moment the engine is
        spawned, so the broker serves exactly the process it was started for — the
        engine and its descendants — and no other descendant of the dispatcher. A no-op
        on a UNIX listener: that listener's boundary is the sandbox netns, and its peer
        is the in-sandbox relay, an ANCESTOR of the engine rather than a descendant, so
        a tree check there would refuse the run's own traffic."""
        server = self._server
        if server is not None and hasattr(server, "peer_gate_root"):
            server.peer_gate_root = pid

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
