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
from http.server import BaseHTTPRequestHandler
from typing import Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

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


class Allowlist:
    """The per-run set of hostnames this proxy may reach. An entry is either an exact
    host (``api.github.com``) or a ``*.``-prefixed suffix (``*.github.com``, matching any
    subdomain but not the apex). Matching is case-insensitive and ignores a trailing dot,
    mirroring how HTTP clients normalise a Host header."""

    def __init__(self, hosts: Iterable[str]):
        self._exact: set = set()
        self._suffixes: List[str] = []
        for raw in hosts:
            host = (raw or "").strip().lower().rstrip(".")
            if not host:
                continue
            if host.startswith("*."):
                self._suffixes.append(host[1:])  # keep the leading dot: ".github.com"
            else:
                self._exact.add(host)

    def allows(self, host: str) -> bool:
        host = (host or "").strip().lower().rstrip(".")
        if not host:
            return False
        if host in self._exact:
            return True
        return any(host.endswith(suffix) for suffix in self._suffixes)

    def hosts(self) -> Tuple[str, ...]:
        """The allowlist in a stable, human-readable form (for a banner or record)."""
        return tuple(sorted(self._exact | {f"*{s}" for s in self._suffixes}))

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

    def _deny(self, message: str) -> None:
        body = f"403 Forbidden: {message}\n".encode("utf-8")
        try:
            self.send_response(403)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass
        self.close_connection = True

    def _resolve_allowed(self, host: str, port: int) -> Optional[str]:
        """Allowlist + SSRF gate. Returns a public IP to dial, or None (already denied)."""
        if not self._allowlist.allows(host):
            self._deny(f"host not on this run's egress allowlist: {host}")
            return None
        addrs = _public_addresses(host, port)
        if not addrs:
            self._deny(f"host does not resolve to a public address (refusing possible "
                       f"SSRF): {host}")
            return None
        return addrs[0]

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
        # Read the request body. Only Content-Length bodies are forwarded; a chunked
        # request body is refused rather than mis-forwarded (the CLI tools this serves
        # do not send one, and guessing would risk request smuggling).
        length = self.headers.get("Content-Length")
        if length:
            try:
                body = self.rfile.read(int(length))
            except (ValueError, OSError):
                return self._deny("bad Content-Length")
        elif self.headers.get("Transfer-Encoding"):
            return self._deny("chunked request bodies are not forwarded")
        else:
            body = b""
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


class EgressProxy:
    """A dispatcher-side, UNIX-socket HTTP(S) forward proxy with a per-run allowlist.

    start() binds ``socket_path`` and serves on a daemon thread; stop() shuts it down and
    unlinks the socket file. This mirrors CredentialBroker's lifecycle (agents-8h4) so the
    dispatcher starts and stops both the same way, inside the same try/finally, and a
    crashed run never leaves a stale socket behind (start() unlinks one first)."""

    def __init__(self, allowlist: Iterable[str], socket_path: str):
        self.allowlist = Allowlist(allowlist)
        self.socket_path = socket_path
        self._server: Optional[_EgressServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> str:
        if self._server is not None:
            return self.socket_path
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

    def hosts(self) -> Tuple[str, ...]:
        return self.allowlist.hosts()
