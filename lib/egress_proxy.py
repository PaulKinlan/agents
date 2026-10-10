#!/usr/bin/env python3
"""Dispatcher-side egress proxy: a UNIX-socket HTTP(S) forward proxy that enforces a
per-run host allowlist (agents-2x6).

A sandboxed run uses ``bwrap --unshare-net``, so the child has no route off its network
namespace: a direct ``connect()`` to any external address fails with ENETUNREACH and DNS
does not resolve (validated on a real host). That is the kernel-level enforcement, and it
is why policy.json can honestly move ``network-egress`` out of not_enforced. The only
egress path left is this proxy, which the child reaches over a bind-mounted UNIX socket
via the in-sandbox net_forward relay: the child dials its own ``127.0.0.1:<proxyport>``
(exported as ``HTTP(S)_PROXY``), net_forward relays the bytes to ``proxy.sock`` here, and
this proxy decides what may leave.

Enforcement:

* Every request must name an allowlisted host. HTTPS arrives as ``CONNECT host:port``
  and is tunnelled as opaque bytes (allowlisted by the CONNECT target); plain HTTP
  arrives as an absolute-URI request and is forwarded. A host that is not allowlisted
  gets ``403`` and the dispatcher never opens a socket for it.
* Every request must also use a permitted PORT: a bare allowlist entry permits the
  standard web ports (80/443), and a ``host:port`` entry pins that port. A non-standard
  port on an allowlisted host (e.g. ``CONNECT api.github.com:22`` for SSH) gets ``403``
  (agents-cn3).
* DNS is resolved HERE (host side), and every resolved address must be public: a name
  that resolves to loopback, private, link-local, multicast or reserved space is refused,
  so an allowlisted-but-rebinding hostname cannot pivot the proxy into the dispatcher's
  own network or the host's localhost (SSRF).

Scope: the model API is NOT proxied here -- it goes through the credential broker
(agents-8h4), which injects the real key. This proxy carries only the hosts a pre-pass
needs, implied by the agent's ``requires`` (``gh`` -> api.github.com, ``npm`` ->
registry.npmjs.org, and so on), so the allowlist is deliberately narrow.

Like the broker it never logs a request line: a proxied URL can carry a token in its
query string, and the proxy runs dispatcher-side where a log would outlive the run.
"""
from __future__ import annotations

import ipaddress
import os
import select
import socket
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from lib.sandbox import SUN_PATH_LIMIT

# Hop-by-hop headers (RFC 7230 6.1) that belong to one transport connection and must not
# be forwarded upstream; Connection: close is re-added so the upstream closes after the
# response and the relay can end on EOF.
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "proxy-connection",
})

_CHUNK = 65536
# Idle ceiling for a CONNECT tunnel. Data-bearing transfers (git clone, npm install) keep
# resetting it; only a genuinely stalled tunnel is torn down, so no socket leaks forever.
_TUNNEL_IDLE_TIMEOUT = 120.0
_UPSTREAM_CONNECT_TIMEOUT = 30.0

# Upper bound on a forwarded request body (agents-2l7). The child controls its own
# Content-Length, so without a cap a sandboxed process could ask this dispatcher-side
# proxy to buffer an unbounded body and OOM the shared host. Bodies are small CLI payloads
# (gh/npm metadata), so 1 MiB is generous; operators may raise or lower it per fleet via
# FACTORY_EGRESS_MAX_BODY_BYTES. An oversized body is refused (413), never truncated,
# because forwarding a partial body would risk request smuggling.
_DEFAULT_MAX_BODY_BYTES = 1_048_576  # 1 MiB


def _resolve_max_body_bytes() -> int:
    """Resolve FACTORY_EGRESS_MAX_BODY_BYTES to a positive integer, else the default.

    A missing, non-integer or non-positive value falls back to the safe default rather
    than widening the limit (or crashing at import time)."""
    raw = os.environ.get("FACTORY_EGRESS_MAX_BODY_BYTES")
    if raw is None or raw == "":
        return _DEFAULT_MAX_BODY_BYTES
    try:
        value = int(raw)
    except ValueError:
        return _DEFAULT_MAX_BODY_BYTES
    return value if value > 0 else _DEFAULT_MAX_BODY_BYTES


MAX_BODY_BYTES = _resolve_max_body_bytes()


# The standard web ports an allowlisted host may be reached on when its entry does not pin
# one: 80 (plain HTTP) and 443 (HTTPS/CONNECT). Any other port — SSH 22, SMTP 25, an
# alternate admin port — is refused unless the entry pins it explicitly (agents-cn3).
_DEFAULT_PORTS = frozenset({80, 443})


def _parse_entry(raw: str) -> Tuple[str, frozenset]:
    """Split an allowlist entry ``host`` or ``host:port`` into ``(host, permitted_ports)``.

    A bare host permits the standard web ports; a ``host:port`` entry pins exactly that
    port. IPv6 literals (``[::1]:8443``) are handled. A malformed port falls back to the
    bare host's default."""
    entry = (raw or "").strip()
    if not entry:
        return "", _DEFAULT_PORTS
    if entry.startswith("["):  # IPv6 literal [::1]:8443
        host, _, rest = entry.partition("]")
        host = host[1:]
        port_s = rest.lstrip(":")
    else:
        host, sep, port_s = entry.rpartition(":")
        if not sep:  # no colon at all: bare host
            host, port_s = entry, ""
    host = host.lower().rstrip(".")
    if port_s.isdigit():
        return host, frozenset({int(port_s)})
    return host, _DEFAULT_PORTS


class Allowlist:
    """The per-run set of hostnames this proxy may reach, each with permitted ports.

    An entry is either an exact host (``api.github.com``) or a ``*.``-prefixed suffix
    (``*.github.com``, matching any subdomain but not the apex); either may pin a port
    (``api.github.com:443``). Matching is case-insensitive and ignores a trailing dot,
    mirroring how HTTP clients normalise a Host header."""

    def __init__(self, hosts: Iterable[str]):
        self._exact: Dict[str, frozenset] = {}
        self._suffixes: List[Tuple[str, frozenset]] = []
        for raw in hosts:
            host, ports = _parse_entry(raw)
            if not host:
                continue
            if host.startswith("*."):
                self._suffixes.append((host[1:], ports))  # keep the leading dot
            else:
                # Union ports across duplicate entries (e.g. host:80 + host:443), so a
                # later entry adds a port instead of overwriting the earlier one (agents-cn3).
                self._exact[host] = self._exact.get(host, frozenset()) | ports

    def allows(self, host: str) -> bool:
        host = (host or "").strip().lower().rstrip(".")
        if not host:
            return False
        if host in self._exact:
            return True
        return any(host.endswith(suffix) for suffix, _ in self._suffixes)

    def allows_port(self, host: str, port: int) -> bool:
        """Whether ``port`` is permitted for an allowlisted ``host`` (agents-cn3)."""
        host = (host or "").strip().lower().rstrip(".")
        if not host:
            return False
        if host in self._exact:
            return port in self._exact[host]
        for suffix, ports in self._suffixes:
            if host.endswith(suffix) and port in ports:
                return True
        return False

    def hosts(self) -> Tuple[str, ...]:
        """The allowlist in a stable, human-readable form (for a banner or record)."""
        return tuple(sorted(self._exact.keys() | {f"*{s}" for s, _ in self._suffixes}))

    def __len__(self) -> int:
        return len(self._exact) + len(self._suffixes)


def _public_addresses(host: str, port: int) -> List[str]:
    """Resolve ``host`` and return only its PUBLIC TCP addresses. Empty when the name
    does not resolve, or resolves solely to loopback / private / link-local / multicast /
    reserved space -- which the caller treats as a refusal. This is the SSRF guard: an
    allowlisted hostname that (maliciously or via rebinding) points at 127.0.0.1 or an
    RFC1918 address must never become a pivot into the dispatcher's own network."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError):
        return []
    out: List[str] = []
    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if (ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
            continue
        # And the catch-all (review P3, agents-2x6): ip.is_global is False for CGNAT
        # 100.64.0.0/10 and any other special range the named predicates above miss — an
        # allowlisted host that resolves there must not become a pivot either.
        if not ip.is_global:
            continue
        if ip_str not in out:
            out.append(ip_str)
    return out


def _tunnel(client: socket.socket, upstream: socket.socket) -> None:
    """Relay raw bytes both directions until one side ends or the tunnel idles out. Used
    for a CONNECT TLS tunnel, so the bytes are opaque and never parsed here."""
    sockets = [client, upstream]
    try:
        while sockets:
            readable, _, exceptional = select.select(sockets, [], sockets,
                                                     _TUNNEL_IDLE_TIMEOUT)
            if exceptional or not readable:
                break  # an error, or an idle timeout: tear the tunnel down
            for sock in readable:
                data = sock.recv(_CHUNK)
                if not data:
                    sockets = []  # peer finished; end the tunnel
                    break
                target = upstream if sock is client else client
                target.sendall(data)
    except (OSError, ValueError):
        pass
    finally:
        try:
            upstream.close()
        except OSError:
            pass


def _split_authority(authority: str) -> Tuple[str, Optional[int]]:
    """Split a CONNECT target (``host:port``, ``host``, or ``[::1]:443``) into host and
    port. A missing port yields None so the caller can refuse rather than guess."""
    authority = authority.strip()
    if authority.startswith("["):  # IPv6 literal
        host, _, rest = authority.partition("]")
        host = host[1:]
        port_s = rest.lstrip(":")
    else:
        host, sep, port_s = authority.rpartition(":")
        if not sep:  # no colon at all: the whole string is the host
            host, port_s = authority, ""
    try:
        return host, int(port_s)
    except ValueError:
        return host, None


class _ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "factory-egress/1.0"

    # Never log: a proxied URL can carry a token in its query string.
    def log_message(self, fmt, *args):  # noqa: A003 - stdlib signature
        pass

    @property
    def _allowlist(self) -> Allowlist:
        return self.server.allowlist  # type: ignore[attr-defined]

    def _deny(self, message: str, status: int = 403) -> None:
        phrase = {400: "Bad Request", 403: "Forbidden",
                  413: "Payload Too Large"}.get(status, "Error")
        body = f"{status} {phrase}: {message}\n".encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass
        self.close_connection = True

    def _resolve_allowed(self, host: str, port: int) -> Optional[str]:
        """Allowlist + port + SSRF gate. Returns a public IP to dial, or None (already denied)."""
        if not self._allowlist.allows(host):
            self._deny(f"host not on this run's egress allowlist: {host}")
            return None
        if not self._allowlist.allows_port(host, port):
            self._deny(f"port {port} not permitted for allowlisted host {host}")
            return None
        addrs = _public_addresses(host, port)
        if not addrs:
            self._deny(f"host does not resolve to a public address (refusing possible "
                       f"SSRF): {host}")
            return None
        return addrs[0]

    def _read_request_body(self) -> Optional[bytes]:
        """Return the request body to forward, or None after refusing it.

        Only Content-Length bodies are forwarded; a chunked body is refused rather than
        mis-forwarded. The declared length is parsed as RFC 7230 ``1*DIGIT`` and checked
        against ``MAX_BODY_BYTES`` BEFORE any bytes are read, so an oversized declaration
        is refused without allocating (agents-2l7)."""
        length_str = self.headers.get("Content-Length")
        if length_str is not None:
            raw = length_str.strip()
            # int() would silently accept "+5" -> 5 and "1_0" -> 10, so require canonical
            # digits; keep a distinct message for a negative value.
            if raw.startswith("-") and raw[1:].isdigit():
                self._deny("negative Content-Length is not allowed", 400)
                return None
            if not raw.isdigit():
                self._deny("invalid Content-Length header (must be an integer)", 400)
                return None
            length = int(raw)
            if length > MAX_BODY_BYTES:
                self._deny(
                    f"request body ({length} bytes) exceeds maximum limit of "
                    f"{MAX_BODY_BYTES} bytes", 413)
                return None
            if length == 0:
                return b""
            try:
                body = self.rfile.read(length)
            except OSError:
                self._deny("failed to read request body", 400)
                return None
            if len(body) != length:
                # The client ended the stream short of its declared length; forwarding the
                # short body under the original Content-Length would desync the upstream.
                self._deny("unexpected end of stream while reading request body", 400)
                return None
            return body
        if self.headers.get("Transfer-Encoding"):
            self._deny("chunked request bodies are not forwarded")
            return None
        return b""

    # --- CONNECT: opaque TLS tunnel -----------------------------------------
    def do_CONNECT(self):  # noqa: N802 - stdlib dispatch name
        host, port = _split_authority(self.path)
        if port is None:
            return self._deny(f"bad CONNECT authority {self.path!r}")
        ip = self._resolve_allowed(host, port)
        if ip is None:
            return
        try:
            upstream = socket.create_connection((ip, port),
                                                timeout=_UPSTREAM_CONNECT_TIMEOUT)
        except OSError as exc:
            return self._deny(f"cannot reach {host}:{port}: {type(exc).__name__}")
        # A CONNECT client waits for this 200 before it sends any tunnelled byte, so the
        # raw self.connection has no read-ahead to lose; relay it opaquely from here.
        try:
            self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.wfile.flush()
        except OSError:
            upstream.close()
            self.close_connection = True
            return
        self.close_connection = True
        _tunnel(self.connection, upstream)

    # --- plain HTTP: absolute-URI forward -----------------------------------
    def _forward_plain(self):
        parts = urlsplit(self.path)
        host = parts.hostname
        if not host:
            return self._deny("expected an absolute-form request URI (proxy mode)")
        try:
            port = parts.port or 80
        except ValueError:
            # urlsplit defers port validation to access (review P3, agents-2x6): a URI
            # like http://host:abc/ must be refused cleanly, not raise through the handler.
            return self._deny(f"bad port in request URI {self.path!r}")
        ip = self._resolve_allowed(host, port)
        if ip is None:
            return
        body = self._read_request_body()
        if body is None:
            return
        target = parts.path or "/"
        if parts.query:
            target += "?" + parts.query
        try:
            upstream = socket.create_connection((ip, port),
                                                timeout=_UPSTREAM_CONNECT_TIMEOUT)
        except OSError as exc:
            return self._deny(f"cannot reach {host}:{port}: {type(exc).__name__}")
        with upstream:
            head = f"{self.command} {target} {self.request_version}\r\n"
            for name, value in self.headers.items():
                if name.lower() in _HOP_BY_HOP:
                    continue
                head += f"{name}: {value}\r\n"
            head += "Connection: close\r\n\r\n"
            try:
                upstream.sendall(head.encode("latin-1") + body)
                upstream.shutdown(socket.SHUT_WR)
                while True:
                    chunk = upstream.recv(_CHUNK)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                self.wfile.flush()
            except OSError:
                pass
        self.close_connection = True

    do_GET = _forward_plain
    do_POST = _forward_plain
    do_HEAD = _forward_plain
    do_PUT = _forward_plain
    do_DELETE = _forward_plain
    do_PATCH = _forward_plain
    do_OPTIONS = _forward_plain


class _EgressServer(socketserver.ThreadingUnixStreamServer):
    """A ThreadingUnixStreamServer whose request threads are daemons, so a wedged tunnel
    cannot outlive stop() -- set here, not globally, to avoid leaking it process-wide.
    block_on_close=False (review P3, agents-2x6): stop() must not join handler threads,
    or a wedged CONNECT tunnel / stalled upstream could delay the run's teardown by up
    to the tunnel idle timeout; the daemon threads drain on their own afterwards."""
    daemon_threads = True
    block_on_close = False


class _EgressTCPServer(ThreadingHTTPServer):
    """The TCP-loopback twin of _EgressServer, for the UNSANDBOXED pre-pass (agents-28nn
    round 7): with no network namespace there is no net_forward relay, so the child dials
    the proxy on host 127.0.0.1 directly. Same handler, same allowlist, same SSRF guard,
    same daemon-thread teardown. The listener needs NO authentication, and this is the
    deliberate asymmetry with the credential broker's loopback listener (which requires
    the run secret): this proxy injects no credential and only ever RESTRICTS where a
    caller may connect (host allowlist + port gate + public-IP SSRF check), so any other
    host-local process that found the port gains nothing it cannot already dial directly.
    The broker HANDS OUT authority; this proxy only ever takes it away."""
    daemon_threads = True
    block_on_close = False


class EgressProxy:
    """A dispatcher-side, UNIX-socket HTTP(S) forward proxy with a per-run allowlist.

    start() binds ``socket_path`` and serves on a daemon thread; stop() shuts it down and
    unlinks the socket file. This mirrors CredentialBroker's lifecycle (agents-8h4) so the
    dispatcher starts and stops both the same way, inside the same try/finally, and a
    crashed run never leaves a stale socket behind (start() unlinks one first)."""

    def __init__(self, allowlist: Iterable[str], socket_path: str):
        self.allowlist = Allowlist(allowlist)
        self.socket_path = socket_path
        self._server: Optional[socketserver.BaseServer] = None
        self._thread: Optional[threading.Thread] = None
        # In TCP-loopback mode (agents-28nn round 7, the unsandboxed pre-pass) the bound
        # port, so the dispatcher can name it in the child's HTTP(S)_PROXY.
        self.tcp_port: Optional[int] = None

    def start(self, tcp_loopback: bool = False) -> str:
        """Bind and serve on a daemon thread. By default bind the UNIX socket at
        ``socket_path`` (the sandboxed pre-pass reaches it through the net_forward
        relay). With ``tcp_loopback=True`` (agents-28nn round 7: an UNSANDBOXED pre-pass
        has no netns relay, and the control belongs to the pre-pass OPERATION, not to
        the path taken to it) bind host 127.0.0.1 on a dynamic TCP port instead and
        record it on ``self.tcp_port``; no socket file is created."""
        if self._server is not None:
            return self.socket_path
        if tcp_loopback:
            self._server = _EgressTCPServer(("127.0.0.1", 0), _ProxyHandler)
            self.tcp_port = self._server.server_address[1]
        else:
            # agents-x8l: AF_UNIX sun_path holds at most 107 bytes; refuse a long path loudly
            # instead of failing bind() with a cryptic ENAMETOOLONG deep in the server thread.
            if len(self.socket_path) > SUN_PATH_LIMIT:
                raise OSError(
                    f"UNIX socket path {self.socket_path!r} is {len(self.socket_path)} bytes, over "
                    f"the {SUN_PATH_LIMIT}-byte AF_UNIX sun_path limit; use a shorter socket path")
            # A stale socket file from a crashed run would make bind() fail with EADDRINUSE.
            try:
                if os.path.exists(self.socket_path):
                    os.unlink(self.socket_path)
            except OSError:
                pass
            self._server = _EgressServer(self.socket_path, _ProxyHandler)
        self._server.allowlist = self.allowlist  # set before serving: no accept yet
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        name="egress-proxy", daemon=True)
        self._thread.start()
        return self.socket_path

    def stop(self) -> None:
        server, self._server = self._server, None
        thread, self._thread = self._thread, None
        if server is not None:
            try:
                server.shutdown()
                server.server_close()
            finally:
                if thread is not None:
                    thread.join(timeout=5)
        try:
            if os.path.exists(self.socket_path):
                os.unlink(self.socket_path)
        except OSError:
            pass
        self.tcp_port = None

    def hosts(self) -> Tuple[str, ...]:
        return self.allowlist.hosts()
