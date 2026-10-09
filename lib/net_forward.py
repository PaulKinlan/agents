#!/usr/bin/env python3
"""In-sandbox TCP -> UNIX-socket forwarder and command supervisor (agents-2x6).

Why this exists: an egress-controlled run uses ``bwrap --unshare-net``, so the child
gets a working loopback but NO route off its network namespace -- a direct
``connect()`` to any external address fails with ENETUNREACH and DNS does not resolve
(validated on a real host). That is the enforcement: the only way out is through the
host-side services the dispatcher chose to expose, and those live on UNIX-domain
sockets bind-mounted into the sandbox. A filesystem path crosses the netns boundary;
a TCP loopback does not, so the child cannot reach a host ``127.0.0.1:port`` listener.

But TCP-only clients cannot dial a UNIX socket: the engine's model SDK reads a plain
``*_BASE_URL=http://127.0.0.1:PORT`` (agents-8h4's credential broker), and pre-pass
tools (curl/npm/gh) read ``HTTP(S)_PROXY``. So this forwarder listens on
``127.0.0.1:PORT`` *inside* the sandbox and relays each connection byte-for-byte to the
matching UNIX socket. It parses nothing, so HTTP, TLS (CONNECT) and SSE all pass
through transparently and it needs no per-protocol logic.

It also supervises the real command, because bwrap execs a single inner argv: it binds
every listener FIRST, then spawns the command as a child with inherited stdio, relays
for as long as the child runs, forwards SIGTERM/SIGINT to the child, and exits with the
child's exit code. Binding before spawning means the endpoints exist before the engine's
first API call -- there is no readiness race to lose.
"""
from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import threading
from typing import List, Sequence, Tuple

# Relay buffer. 64 KiB is plenty for HTTP/SSE framing and keeps memory bounded.
_CHUNK = 65536


def _pump(src: socket.socket, dst: socket.socket) -> None:
    """Copy bytes src -> dst until EOF or error, then half-close dst so the peer sees
    the end of the stream. Never raises: a relay is best-effort and a broken pipe on
    one side simply ends that direction."""
    try:
        while True:
            data = src.recv(_CHUNK)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _handle(tcp: socket.socket, unix_path: str) -> None:
    """Relay one accepted TCP connection to a fresh UNIX-socket connection. If the
    UNIX socket is gone (host service stopped) the TCP side is closed immediately, so
    the client sees a normal connection error rather than a hang."""
    try:
        upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        upstream.connect(unix_path)
    except OSError:
        try:
            tcp.close()
        except OSError:
            pass
        return
    with tcp, upstream:
        # One direction on a helper thread, the other inline; join before closing so
        # a long-lived stream (SSE) is relayed for its whole life.
        reverse = threading.Thread(target=_pump, args=(upstream, tcp), daemon=True)
        reverse.start()
        _pump(tcp, upstream)
        reverse.join()


def _accept_loop(listener: socket.socket, unix_path: str) -> None:
    while True:
        try:
            tcp, _ = listener.accept()
        except OSError:
            return  # listener closed on shutdown
        threading.Thread(target=_handle, args=(tcp, unix_path), daemon=True).start()


def _parse(argv: Sequence[str]) -> Tuple[List[Tuple[int, str]], List[str]]:
    """Parse ``[--forward PORT=UNIX_PATH]... -- COMMAND...`` into the forward table and
    the command to supervise. Everything after ``--`` is the command, verbatim."""
    forwards: List[Tuple[int, str]] = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--forward":
            i += 1
            if i >= len(argv):
                raise SystemExit("net_forward: --forward needs a PORT=PATH argument")
            port_s, sep, path = argv[i].partition("=")
            if not sep or not path:
                raise SystemExit(f"net_forward: bad --forward {argv[i]!r} (want PORT=PATH)")
            try:
                if not (port_s.isascii() and port_s.isdigit()):
                    raise ValueError
                port = int(port_s)
                if not (1 <= port <= 65535):
                    raise ValueError
            except ValueError:
                raise SystemExit(
                    f"net_forward: bad port in --forward {argv[i]!r} "
                    f"(expected integer 1..65535, got {port_s!r})"
                )
            forwards.append((port, path))
        elif arg == "--":
            return forwards, list(argv[i + 1:])
        else:
            raise SystemExit(f"net_forward: unexpected argument {arg!r} before --")
        i += 1
    return forwards, []


def main(argv: Sequence[str]) -> int:
    forwards, command = _parse(argv)
    if not command:
        print("net_forward: no command after --", file=sys.stderr)
        return 2

    # Bind every listener before spawning the command, so the endpoints the command
    # will dial already exist when it starts. A bind failure is fatal and loud: better
    # to fail the run than to let the engine dial a dead endpoint and mis-report.
    listeners: List[Tuple[socket.socket, str]] = []
    try:
        for port, path in forwards:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", port))
            listener.listen(128)
            listeners.append((listener, path))
    except OSError as exc:
        print(f"net_forward: cannot bind listener: {exc}", file=sys.stderr)
        return 1

    for listener, path in listeners:
        threading.Thread(target=_accept_loop, args=(listener, path), daemon=True).start()

    child = subprocess.Popen(command)

    def _forward_signal(signum, _frame):
        # Pass the sandbox's teardown signals to the engine so it can shut down cleanly.
        try:
            child.send_signal(signum)
        except (ProcessLookupError, OSError):
            pass

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _forward_signal)
        except (ValueError, OSError):
            pass  # not on the main thread, or the platform lacks the signal

    return child.wait()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
