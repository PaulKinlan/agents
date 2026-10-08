"""Unit tests for lib/egress_proxy.py — the UNIX-socket HTTP(S) forward proxy with a
per-run host allowlist and SSRF guard (agents-2x6).

No real network egress: allow/deny decisions are asserted directly against a proxy on a
throwaway UNIX socket, and the tunnel/forward happy paths run against a localhost mock
upstream with _public_addresses patched (the SSRF guard would otherwise — correctly —
refuse to dial a loopback upstream, which is exactly what SsrfGuardTest asserts).
"""
import os
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib import egress_proxy as ep  # noqa: E402


def _tcp_echo_server(port_holder, ready, stop):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    srv.settimeout(0.2)
    port_holder.append(srv.getsockname()[1])
    ready.set()
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break

        def echo(c):
            with c:
                while True:
                    data = c.recv(4096)
                    if not data:
                        break
                    c.sendall(data)
        threading.Thread(target=echo, args=(conn,), daemon=True).start()
    srv.close()


def _http_server(port_holder, ready, stop, body=b"hello"):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    srv.settimeout(0.2)
    port_holder.append(srv.getsockname()[1])
    ready.set()
    while not stop.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break

        def handle(c):
            with c:
                c.recv(65536)  # best-effort read of the forwarded request
                resp = (b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode()
                        + b"\r\nConnection: close\r\n\r\n" + body)
                c.sendall(resp)
        threading.Thread(target=handle, args=(conn,), daemon=True).start()
    srv.close()


def _recv_some(sock, n=65536, timeout=5):
    sock.settimeout(timeout)
    try:
        return sock.recv(n)
    except socket.timeout:
        return b""


class AllowlistTest(unittest.TestCase):
    def test_exact_and_wildcard(self):
        al = ep.Allowlist(["api.github.com", "*.npmjs.org"])
        self.assertTrue(al.allows("api.github.com"))
        self.assertTrue(al.allows("API.GitHub.Com"))    # case-insensitive
        self.assertTrue(al.allows("api.github.com."))   # trailing dot
        self.assertFalse(al.allows("github.com"))        # apex not in the exact set
        self.assertTrue(al.allows("registry.npmjs.org"))
        self.assertTrue(al.allows("sub.registry.npmjs.org"))
        self.assertFalse(al.allows("npmjs.org"))         # *. does not match the apex
        self.assertFalse(al.allows("evil.com"))
        self.assertFalse(al.allows(""))

    def test_hosts_and_len(self):
        al = ep.Allowlist(["b.com", "*.a.com", "b.com"])  # duplicate collapses
        self.assertEqual(al.hosts(), ("*.a.com", "b.com"))
        self.assertEqual(len(al), 2)


class SsrfGuardTest(unittest.TestCase):
    def _addrinfo(self, ips):
        def fake(host, port, **kw):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in ips]
        return mock.patch.object(ep.socket, "getaddrinfo", side_effect=fake)

    def test_loopback_refused(self):
        with self._addrinfo(["127.0.0.1"]):
            self.assertEqual(ep._public_addresses("x", 443), [])

    def test_private_refused(self):
        with self._addrinfo(["10.1.2.3", "192.168.0.1"]):
            self.assertEqual(ep._public_addresses("x", 443), [])

    def test_public_allowed(self):
        with self._addrinfo(["93.184.216.34"]):
            self.assertEqual(ep._public_addresses("x", 443), ["93.184.216.34"])

    def test_mixed_returns_only_public(self):
        with self._addrinfo(["127.0.0.1", "93.184.216.34"]):
            self.assertEqual(ep._public_addresses("x", 443), ["93.184.216.34"])

    def test_unresolvable_empty(self):
        with mock.patch.object(ep.socket, "getaddrinfo", side_effect=socket.gaierror):
            self.assertEqual(ep._public_addresses("nope.invalid", 443), [])

    def test_cgnat_refused(self):
        # Review P3 (agents-2x6): 100.64.0.0/10 is not loopback/private/link-local by the
        # named predicates — only the is_global catch-all refuses it.
        with self._addrinfo(["100.64.0.1"]):
            self.assertEqual(ep._public_addresses("cgnat.test", 443), [])


class SplitAuthorityTest(unittest.TestCase):
    def test_host_port(self):
        self.assertEqual(ep._split_authority("api.github.com:443"), ("api.github.com", 443))

    def test_host_only(self):
        self.assertEqual(ep._split_authority("api.github.com"), ("api.github.com", None))

    def test_ipv6(self):
        self.assertEqual(ep._split_authority("[2001:db8::1]:443"), ("2001:db8::1", 443))


class ProxyLifecycleTest(unittest.TestCase):
    def test_start_binds_and_stop_unlinks(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "proxy.sock")
            proxy = ep.EgressProxy(["allowed.test"], path)
            proxy.start()
            self.assertTrue(os.path.exists(path))
            proxy.stop()
            self.assertFalse(os.path.exists(path))

    def test_start_unlinks_stale_socket(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "proxy.sock")
            Path(path).write_text("stale")  # a crashed run left a file behind
            proxy = ep.EgressProxy(["allowed.test"], path)
            proxy.start()  # must not raise EADDRINUSE
            self.assertTrue(os.path.exists(path))
            proxy.stop()

    def test_a_long_socket_path_is_refused_loudly(self):
        # agents-x8l: AF_UNIX sun_path holds at most 107 bytes; refuse before bind() so the
        # failure is a clear OSError, not a cryptic ENAMETOOLONG from the server thread.
        proxy = ep.EgressProxy(["allowed.test"], "/" * 108)
        with self.assertRaises(OSError) as cm:
            proxy.start()
        self.assertIn("sun_path", str(cm.exception))
        self.assertIn("107", str(cm.exception))


class ProxyEnforcementTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._tmp.name, "proxy.sock")

    def tearDown(self):
        self._tmp.cleanup()

    def _client(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(self.path)
        return s

    def test_connect_denied_not_allowlisted(self):
        proxy = ep.EgressProxy(["allowed.test"], self.path)
        proxy.start()
        try:
            c = self._client()
            c.sendall(b"CONNECT denied.test:443 HTTP/1.1\r\nHost: denied.test:443\r\n\r\n")
            self.assertIn(b"403", _recv_some(c))
            c.close()
        finally:
            proxy.stop()

    def test_plain_denied_not_allowlisted(self):
        proxy = ep.EgressProxy(["allowed.test"], self.path)
        proxy.start()
        try:
            c = self._client()
            c.sendall(b"GET http://denied.test/x HTTP/1.1\r\nHost: denied.test\r\n\r\n")
            self.assertIn(b"403", _recv_some(c))
            c.close()
        finally:
            proxy.stop()

    def test_bad_port_refused_cleanly(self):
        # Review P3 (agents-2x6): urlsplit defers port validation to access — a URI like
        # http://allowed.test:abc/ must be denied with a 403, not raise through the
        # handler into the dispatcher's stderr.
        proxy = ep.EgressProxy(["allowed.test"], self.path)
        proxy.start()
        try:
            c = self._client()
            c.sendall(b"GET http://allowed.test:abc/x HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
            self.assertIn(b"403", _recv_some(c))
            c.close()
        finally:
            proxy.stop()

    def test_connect_denied_ssrf_loopback(self):
        # An allowlisted host that resolves to loopback must be refused (rebinding guard).
        proxy = ep.EgressProxy(["rebind.test"], self.path)
        proxy.start()
        try:
            with mock.patch.object(
                    ep.socket, "getaddrinfo",
                    return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                                   ("127.0.0.1", 443))]):
                c = self._client()
                c.sendall(b"CONNECT rebind.test:443 HTTP/1.1\r\nHost: rebind.test\r\n\r\n")
                self.assertIn(b"403", _recv_some(c))
                c.close()
        finally:
            proxy.stop()

    def test_connect_allowed_tunnels(self):
        port_holder, ready, stop = [], threading.Event(), threading.Event()
        threading.Thread(target=_tcp_echo_server, args=(port_holder, ready, stop),
                         daemon=True).start()
        self.assertTrue(ready.wait(5))
        upstream_port = port_holder[0]
        proxy = ep.EgressProxy(["upstream.test"], self.path)
        proxy.start()
        try:
            with mock.patch.object(ep, "_public_addresses", return_value=["127.0.0.1"]):
                c = self._client()
                req = (f"CONNECT upstream.test:{upstream_port} HTTP/1.1\r\n"
                       f"Host: upstream.test:{upstream_port}\r\n\r\n")
                c.sendall(req.encode())
                head = b""
                while b"\r\n\r\n" not in head:
                    chunk = _recv_some(c, 4096)
                    if not chunk:
                        break
                    head += chunk
                self.assertIn(b"200", head)
                c.sendall(b"tunnel-ping")
                self.assertEqual(_recv_some(c), b"tunnel-ping")
                c.close()
        finally:
            stop.set()
            proxy.stop()

    def test_plain_forward_allowed(self):
        port_holder, ready, stop = [], threading.Event(), threading.Event()
        threading.Thread(target=_http_server, args=(port_holder, ready, stop),
                         daemon=True).start()
        self.assertTrue(ready.wait(5))
        upstream_port = port_holder[0]
        proxy = ep.EgressProxy(["upstream.test"], self.path)
        proxy.start()
        try:
            with mock.patch.object(ep, "_public_addresses", return_value=["127.0.0.1"]):
                c = self._client()
                req = (f"GET http://upstream.test:{upstream_port}/path HTTP/1.1\r\n"
                       f"Host: upstream.test\r\n\r\n")
                c.sendall(req.encode())
                resp = b""
                while True:
                    chunk = _recv_some(c)
                    if not chunk:
                        break
                    resp += chunk
                self.assertIn(b"200 OK", resp)
                self.assertIn(b"hello", resp)
                c.close()
        finally:
            stop.set()
            proxy.stop()


if __name__ == "__main__":
    unittest.main(verbosity=2)
