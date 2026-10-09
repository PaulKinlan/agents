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


def _capture_server(port_holder, ready, stop, received):
    """A loopback upstream that records the whole forwarded request before replying 200."""
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
            data = b""
            try:
                while True:
                    chunk = c.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                received.append(data)
                c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
                          b"Connection: close\r\n\r\nhello")
            finally:
                c.close()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()
    srv.close()


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

    def test_ports_default_to_standard_and_pin(self):
        # A bare host permits the standard web ports; a host:port entry pins that port.
        al = ep.Allowlist(["api.github.com", "custom.test:8443", "*.npmjs.org"])
        self.assertTrue(al.allows_port("api.github.com", 443))
        self.assertTrue(al.allows_port("api.github.com", 80))
        self.assertFalse(al.allows_port("api.github.com", 22))   # SSH
        self.assertFalse(al.allows_port("api.github.com", 8080))
        self.assertTrue(al.allows_port("custom.test", 8443))
        self.assertFalse(al.allows_port("custom.test", 443))
        self.assertFalse(al.allows_port("custom.test", 80))
        self.assertTrue(al.allows_port("registry.npmjs.org", 443))
        self.assertFalse(al.allows_port("registry.npmjs.org", 25))  # SMTP
        self.assertFalse(al.allows_port("npmjs.org", 443))  # *. does not match the apex

    def test_duplicate_host_ports_union(self):
        # agents-cn3 review note: a second entry for the same host must ADD its port,
        # not overwrite the first (host:80 + host:443 => both allowed).
        al = ep.Allowlist(["example.com:80", "example.com:443"])
        self.assertTrue(al.allows_port("example.com", 80))
        self.assertTrue(al.allows_port("example.com", 443))
        self.assertFalse(al.allows_port("example.com", 22))

    def test_overlapping_wildcard_ports_union(self):
        # agents-cn3 review note: allows_port must not short-circuit on the first matching
        # suffix — an overlapping broader suffix can still permit the port.
        al = ep.Allowlist(["*.corp.example.com:8443", "*.example.com"])
        self.assertTrue(al.allows_port("x.corp.example.com", 8443))  # the pinned suffix
        self.assertTrue(al.allows_port("x.corp.example.com", 80))    # the broader suffix
        self.assertTrue(al.allows_port("x.corp.example.com", 443))
        self.assertFalse(al.allows_port("x.corp.example.com", 22))


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

    def test_connect_non_standard_port_denied(self):
        # agents-cn3: an allowlisted host on a non-standard port (SSH/admin) must be refused.
        proxy = ep.EgressProxy(["allowed.test"], self.path)
        proxy.start()
        try:
            with mock.patch.object(ep, "_public_addresses", return_value=["127.0.0.1"]):
                c = self._client()
                c.sendall(b"CONNECT allowed.test:22 HTTP/1.1\r\nHost: allowed.test:22\r\n\r\n")
                self.assertIn(b"403", _recv_some(c))
                c.close()
        finally:
            proxy.stop()

    def test_plain_non_standard_port_denied(self):
        # agents-cn3: the absolute-URI path must also refuse a non-standard port.
        proxy = ep.EgressProxy(["allowed.test"], self.path)
        proxy.start()
        try:
            with mock.patch.object(ep, "_public_addresses", return_value=["127.0.0.1"]):
                c = self._client()
                c.sendall(b"GET http://allowed.test:25/x HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
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
        # The mock upstream listens on a random (non-standard) port, so pin it explicitly.
        proxy = ep.EgressProxy([f"upstream.test:{upstream_port}"], self.path)
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
        # The mock upstream listens on a random (non-standard) port, so pin it explicitly.
        proxy = ep.EgressProxy([f"upstream.test:{upstream_port}"], self.path)
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

    def test_oversized_content_length_is_refused_413_without_reading_body(self):
        # agents-2l7: an oversized declared Content-Length must be refused BEFORE any body
        # bytes are read. Only headers are sent (no payload), so the old unbounded
        # ``read(int(length))`` would block waiting for the declared bytes and this test
        # would time out instead of seeing an immediate 413.
        proxy = ep.EgressProxy(["allowed.test"], self.path)
        proxy.start()
        try:
            with mock.patch.object(ep, "_public_addresses", return_value=["127.0.0.1"]), \
                    mock.patch.object(ep.socket, "create_connection") as dial:
                c = self._client()
                req = (f"POST http://allowed.test/ HTTP/1.1\r\n"
                       f"Host: allowed.test\r\n"
                       f"Content-Length: {ep.MAX_BODY_BYTES + 1}\r\n\r\n")
                c.sendall(req.encode())
                resp = b""
                while True:
                    chunk = _recv_some(c)
                    if not chunk:
                        break
                    resp += chunk
                c.close()
            self.assertIn(b"413", resp)
            self.assertIn(b"Payload Too Large", resp)
            dial.assert_not_called()  # no upstream socket was opened
        finally:
            proxy.stop()

    def test_normal_body_still_forwards(self):
        # agents-2l7 regression guard: a body within the cap must still be forwarded whole.
        received = []
        port_holder, ready, stop = [], threading.Event(), threading.Event()
        threading.Thread(target=_capture_server,
                         args=(port_holder, ready, stop, received), daemon=True).start()
        self.assertTrue(ready.wait(5))
        upstream_port = port_holder[0]
        proxy = ep.EgressProxy([f"upstream.test:{upstream_port}"], self.path)
        proxy.start()
        try:
            with mock.patch.object(ep, "_public_addresses", return_value=["127.0.0.1"]):
                c = self._client()
                body = b"hello"
                req = (f"POST http://upstream.test:{upstream_port}/upload HTTP/1.1\r\n"
                       f"Host: upstream.test\r\n"
                       f"Content-Length: {len(body)}\r\n\r\n").encode() + body
                c.sendall(req)
                resp = b""
                while True:
                    chunk = _recv_some(c)
                    if not chunk:
                        break
                    resp += chunk
                c.close()
            self.assertIn(b"200 OK", resp)
            self.assertIn(b"hello", resp)
            self.assertEqual(len(received), 1)
            self.assertIn(b"Content-Length: 5", received[0])
            self.assertTrue(received[0].endswith(body))
        finally:
            stop.set()
            proxy.stop()


class RequestBodyParseTest(unittest.TestCase):
    """Handler-level parse/refusal tests: prove the body cap is checked before any read."""

    def _handler(self, headers):
        handler = ep._ProxyHandler.__new__(ep._ProxyHandler)
        handler.headers = headers
        handler.rfile = mock.Mock()
        handler.rfile.read.return_value = b""
        handler.close_connection = False
        handler._deny = mock.Mock()
        return handler

    def test_oversized_negative_and_non_integer_lengths_are_refused_without_reading(self):
        for bad, status in (
            (str(ep.MAX_BODY_BYTES + 1), 413),
            ("-10", 400),
            ("not-a-number", 400),
        ):
            handler = self._handler({"Content-Length": bad})
            self.assertIsNone(handler._read_request_body())
            handler.rfile.read.assert_not_called()
            handler._deny.assert_called_once()
            self.assertEqual(handler._deny.call_args[0][1], status)

    def test_non_canonical_integer_forms_are_refused(self):
        # int() would silently accept these; RFC 7230 Content-Length is 1*DIGIT.
        for bad in ("+5", "1_0"):
            handler = self._handler({"Content-Length": bad})
            self.assertIsNone(handler._read_request_body())
            handler.rfile.read.assert_not_called()

    def test_valid_length_reads_exactly_and_returns_body(self):
        handler = self._handler({"Content-Length": "5"})
        handler.rfile.read.return_value = b"hello"
        self.assertEqual(handler._read_request_body(), b"hello")
        handler.rfile.read.assert_called_once_with(5)
        handler._deny.assert_not_called()

    def test_short_body_is_refused(self):
        # A client that ends the stream short of its declared length must not be forwarded
        # under the original (larger) Content-Length header.
        handler = self._handler({"Content-Length": "5"})
        handler.rfile.read.return_value = b"hi"
        self.assertIsNone(handler._read_request_body())
        handler._deny.assert_called_once()
        self.assertEqual(handler._deny.call_args[0][1], 400)

    def test_zero_content_length_is_empty_body(self):
        handler = self._handler({"Content-Length": "0"})
        self.assertEqual(handler._read_request_body(), b"")
        handler.rfile.read.assert_not_called()
        handler._deny.assert_not_called()

    def test_chunked_is_refused_without_reading(self):
        handler = self._handler({"Transfer-Encoding": "chunked"})
        self.assertIsNone(handler._read_request_body())
        handler.rfile.read.assert_not_called()
        handler._deny.assert_called_once()


class MaxBodyBytesResolutionTest(unittest.TestCase):
    def test_env_override_and_safe_fallbacks(self):
        with mock.patch.dict(os.environ, {"FACTORY_EGRESS_MAX_BODY_BYTES": "123"}):
            self.assertEqual(ep._resolve_max_body_bytes(), 123)
        for bad in ("not-an-int", "-5", "0"):
            with mock.patch.dict(os.environ, {"FACTORY_EGRESS_MAX_BODY_BYTES": bad}):
                self.assertEqual(ep._resolve_max_body_bytes(), ep._DEFAULT_MAX_BODY_BYTES)
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(ep._resolve_max_body_bytes(), ep._DEFAULT_MAX_BODY_BYTES)


if __name__ == "__main__":
    unittest.main(verbosity=2)
