"""Unit tests for lib/net_forward.py — the in-sandbox TCP->UNIX relay + supervisor.

These run with no bubblewrap and no network egress: the relay is exercised over the
host loopback (the mechanism is identical inside a netns), against a throwaway
UNIX-socket echo server standing in for the host-side broker/proxy.
"""
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib import net_forward  # noqa: E402

_FORWARD = str(ROOT / "lib" / "net_forward.py")


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _unix_echo_server(path: str, ready: threading.Event, stop: threading.Event) -> None:
    """A stand-in host service: accept on the UNIX socket and echo each connection."""
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(8)
    srv.settimeout(0.2)
    ready.set()
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break

        def _echo(c: socket.socket) -> None:
            with c:
                while True:
                    data = c.recv(4096)
                    if not data:
                        break
                    c.sendall(data)

        threading.Thread(target=_echo, args=(conn,), daemon=True).start()
    srv.close()


class ParseTest(unittest.TestCase):
    def test_parse_multiple_forwards_then_command(self):
        forwards, cmd = net_forward._parse(
            ["--forward", "8000=/tmp/a.sock", "--forward", "8001=/tmp/b.sock",
             "--", "echo", "hi"])
        self.assertEqual(forwards, [(8000, "/tmp/a.sock"), (8001, "/tmp/b.sock")])
        self.assertEqual(cmd, ["echo", "hi"])

    def test_parse_no_forwards(self):
        forwards, cmd = net_forward._parse(["--", "true"])
        self.assertEqual(forwards, [])
        self.assertEqual(cmd, ["true"])

    def test_parse_command_with_dashes(self):
        # Everything after -- is verbatim, even if it looks like a flag.
        _, cmd = net_forward._parse(["--", "pi", "--forward", "--weird"])
        self.assertEqual(cmd, ["pi", "--forward", "--weird"])

    def test_parse_bad_forward_exits(self):
        with self.assertRaises(SystemExit):
            net_forward._parse(["--forward", "not-a-spec", "--", "true"])


class SupervisorTest(unittest.TestCase):
    def test_propagates_child_exit_code(self):
        rc = subprocess.call(
            [sys.executable, _FORWARD, "--", sys.executable, "-c", "import sys; sys.exit(7)"],
            timeout=30)
        self.assertEqual(rc, 7)

    def test_no_command_exits_2(self):
        rc = subprocess.call([sys.executable, _FORWARD], timeout=30)
        self.assertEqual(rc, 2)


class RelayTest(unittest.TestCase):
    def test_tcp_relays_to_unix_socket(self):
        with tempfile.TemporaryDirectory() as d:
            sock = os.path.join(d, "echo.sock")
            ready, stop = threading.Event(), threading.Event()
            srv = threading.Thread(target=_unix_echo_server, args=(sock, ready, stop),
                                   daemon=True)
            srv.start()
            self.assertTrue(ready.wait(5), "echo server never bound")
            port = _free_port()
            # net_forward supervises a sleep so it stays alive while we drive the relay.
            proc = subprocess.Popen(
                [sys.executable, _FORWARD, "--forward", f"{port}={sock}", "--",
                 "sleep", "15"])
            try:
                conn = None
                deadline = time.time() + 5
                while time.time() < deadline:
                    try:
                        conn = socket.create_connection(("127.0.0.1", port), timeout=1)
                        break
                    except OSError:
                        time.sleep(0.05)
                self.assertIsNotNone(conn, "forwarder listener never opened")
                conn.sendall(b"hello-relay")
                got = conn.recv(4096)
                self.assertEqual(got, b"hello-relay")
                conn.close()
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                stop.set()

    def test_dead_unix_socket_closes_tcp_not_hang(self):
        # If the host service is gone, the client gets a closed connection, not a hang.
        with tempfile.TemporaryDirectory() as d:
            missing = os.path.join(d, "nope.sock")  # nothing listening here
            port = _free_port()
            proc = subprocess.Popen(
                [sys.executable, _FORWARD, "--forward", f"{port}={missing}", "--",
                 "sleep", "15"])
            try:
                conn = None
                deadline = time.time() + 5
                while time.time() < deadline:
                    try:
                        conn = socket.create_connection(("127.0.0.1", port), timeout=1)
                        break
                    except OSError:
                        time.sleep(0.05)
                self.assertIsNotNone(conn, "forwarder listener never opened")
                conn.sendall(b"hello")
                # The relay closes the TCP side when the UNIX connect fails. Because the
                # client's bytes are still unread in the buffer, the kernel may send RST
                # (ConnectionResetError) instead of a clean FIN (b""); either proves the
                # connection was closed promptly rather than hanging.
                try:
                    self.assertEqual(conn.recv(4096), b"")
                except ConnectionResetError:
                    pass
                conn.close()
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()


if __name__ == "__main__":
    unittest.main(verbosity=2)
