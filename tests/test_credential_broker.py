"""Unit tests for the dispatcher-side credential broker (agents-8h4).

The upstream provider is mocked at http.client.HTTPSConnection, so these tests run
with no network and no real credential: they assert what the broker FORWARDS (the
reconstructed upstream URL and the injected real key) and what it RETURNS to the
engine (the streamed body, with the real key never appearing on the engine side).
"""
import http.client
import io
import os
import shutil
import socket
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from lib import credential_broker as cb  # noqa: E402
from lib.child_env import child_environment  # noqa: E402

REAL = {
    "anthropic": "sk-ant-REAL-DO-NOT-LEAK",
    "openai": "sk-REAL-DO-NOT-LEAK",
    "google": "AIza-REAL-DO-NOT-LEAK",
}


class _FakeUpstreamResponse:
    def __init__(self, status, reason, headers, chunks):
        self.status = status
        self.reason = reason
        self._headers = headers
        self._chunks = list(chunks)

    def getheaders(self):
        return self._headers

    def read1(self, _n=-1):
        return self._chunks.pop(0) if self._chunks else b""


class _FakeHTTPSConnection:
    """Stands in for http.client.HTTPSConnection: records the forwarded request and
    returns a canned upstream response."""
    calls = []
    response = None  # a _FakeUpstreamResponse

    def __init__(self, host, port=None, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout

    def request(self, method, path, body=None, headers=None):
        _FakeHTTPSConnection.calls.append({
            "host": self.host, "port": self.port, "timeout": self.timeout,
            "method": method, "path": path, "body": body, "headers": dict(headers or {}),
        })

    def getresponse(self):
        return _FakeHTTPSConnection.response

    def close(self):
        pass


def _client_request(port, method, path, headers=None, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    status, resp_headers = resp.status, dict(resp.getheaders())
    conn.close()
    return status, resp_headers, data


class _UnixHTTPConnection(http.client.HTTPConnection):
    """An HTTPConnection over a UNIX-domain socket, so a test can drive the broker the way
    the in-sandbox net_forward relay does (agents-2x6): bytes arrive on the broker's UNIX
    listener, not a TCP loopback."""

    def __init__(self, socket_path, timeout=15):
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._socket_path)


def _unix_client_request(socket_path, method, path, headers=None, body=None):
    conn = _UnixHTTPConnection(socket_path)
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    status, resp_headers = resp.status, dict(resp.getheaders())
    conn.close()
    return status, resp_headers, data


class BrokerTestBase(unittest.TestCase):
    def setUp(self):
        _FakeHTTPSConnection.calls = []
        _FakeHTTPSConnection.response = _FakeUpstreamResponse(
            200, "OK", [("Content-Type", "application/json")], [b'{"ok": true}'])
        self._patcher = mock.patch.object(http.client, "HTTPSConnection", _FakeHTTPSConnection)
        self._patcher.start()
        self.addCleanup(self._patcher.stop)

    def start_broker(self, credentials):
        broker = cb.CredentialBroker(credentials)
        broker.start()
        self.addCleanup(broker.stop)
        return broker


class TestRoutingAndInjection(BrokerTestBase):
    def test_anthropic_prefix_is_stripped_and_the_real_key_injected(self):
        broker = self.start_broker({"anthropic": REAL["anthropic"]})
        status, headers, body = _client_request(
            broker.port, "POST", "/proxy/anthropic/v1/messages",
            headers={"x-api-key": broker.placeholder, "anthropic-version": "2023-06-01",
                     "content-type": "application/json", "content-length": "2"},
            body=b"{}")
        self.assertEqual(status, 200)
        self.assertEqual(body, b'{"ok": true}')
        call = _FakeHTTPSConnection.calls[0]
        self.assertEqual(call["host"], "api.anthropic.com")
        self.assertEqual(call["path"], "/v1/messages")
        self.assertEqual(call["method"], "POST")
        # The real key is injected; the engine's placeholder is gone.
        self.assertEqual(call["headers"]["x-api-key"], REAL["anthropic"])
        self.assertNotIn(broker.placeholder, call["headers"].values())
        # The engine's own Host/Content-Length are not forwarded (http.client sets them).
        self.assertNotIn("host", {k.lower() for k in call["headers"]})
        # A passthrough header survives.
        self.assertEqual(call["headers"]["anthropic-version"], "2023-06-01")
        # The real key never appears on the engine side.
        self.assertNotIn(REAL["anthropic"].encode(), body)
        self.assertNotIn(REAL["anthropic"], str(headers))

    def test_openai_uses_bearer_and_a_v1_upstream_base(self):
        broker = self.start_broker({"openai": REAL["openai"]})
        _client_request(broker.port, "POST", "/proxy/openai/chat/completions",
                        headers={"authorization": f"Bearer {broker.placeholder}",
                                 "content-type": "application/json", "content-length": "2"},
                        body=b"{}")
        call = _FakeHTTPSConnection.calls[0]
        self.assertEqual(call["host"], "api.openai.com")
        self.assertEqual(call["path"], "/v1/chat/completions")  # upstream base carries /v1
        self.assertEqual(call["headers"]["Authorization"], f"Bearer {REAL['openai']}")
        self.assertNotIn(broker.placeholder, call["headers"]["Authorization"])

    def test_google_uses_x_goog_api_key(self):
        broker = self.start_broker({"google": REAL["google"]})
        _client_request(broker.port, "POST",
                        "/proxy/google/v1beta/models/gemini:generateContent",
                        headers={"x-goog-api-key": broker.placeholder, "content-length": "2"},
                        body=b"{}")
        call = _FakeHTTPSConnection.calls[0]
        self.assertEqual(call["host"], "generativelanguage.googleapis.com")
        self.assertEqual(call["path"], "/v1beta/models/gemini:generateContent")
        self.assertEqual(call["headers"]["x-goog-api-key"], REAL["google"])

    def test_query_string_is_preserved(self):
        broker = self.start_broker({"google": REAL["google"]})
        _client_request(broker.port, "GET", "/proxy/google/v1beta/models?pageSize=1",
                        headers={"x-goog-api-key": broker.placeholder})
        self.assertEqual(_FakeHTTPSConnection.calls[0]["path"],
                         "/v1beta/models?pageSize=1")


class TestUnauthenticatedRefusal(BrokerTestBase):
    """agents-28nn round 7, the verdict's P0: on the unsandboxed path the broker's TCP
    listener sits on the HOST's loopback — a shared interface any local process can dial —
    so a broker that does not authenticate is an open proxy injecting the raw credentials
    for whoever asks. The verdict CONSTRUCTED exactly that: start the broker with
    {"anthropic": "sk-ant"} and a plain curl to /proxy/anthropic/v1/messages routed WITH
    THE KEY ATTACHED. The fix: the placeholder is a per-run random secret the broker
    demands back on every request, refused with 403 BEFORE any path processing or upstream
    hop. These tests drive the REAL broker listener over real loopback TCP (only the
    upstream HTTPSConnection is faked, so nothing leaves the host and the assertion can
    prove nothing was forwarded).

    MUTATION PROOF (performed, not merely asserted — agents-28nn round 7): neutralising
    the check (`_request_authenticated` -> `return True`) turns the refusal tests red:
    the same unauthenticated request then reaches the (faked) upstream with the REAL KEY
    attached, which is the verdict's constructed attack exactly. Re-verified this round by
    mutating the worktree, watching this class fail, and reverting the mutation.
    """

    # The verdict's constructed request, verbatim in shape: a plain local call to the
    # broker's loopback port presenting NO credential of any kind.
    def _unauthenticated_request(self, broker):
        return _client_request(
            broker.port, "POST", "/proxy/anthropic/v1/messages",
            headers={"content-type": "application/json", "content-length": "2"},
            body=b"{}")

    def test_a_request_without_the_run_secret_is_refused_before_any_upstream_hop(self):
        broker = self.start_broker({"anthropic": REAL["anthropic"]})
        status, headers, body = self._unauthenticated_request(broker)
        self.assertEqual(status, 403)
        self.assertIn(b"per-run secret", body)
        # Nothing was forwarded: the raw key was never attached to anything.
        self.assertEqual(_FakeHTTPSConnection.calls, [],
                         "an unauthenticated request must NEVER reach the upstream")
        # And the refusal leaks nothing: not the key, not the secret, not even whether
        # the provider is configured.
        self.assertNotIn(REAL["anthropic"].encode(), body)
        self.assertNotIn(broker.placeholder.encode(), body)
        self.assertNotIn(REAL["anthropic"], str(headers))

    def test_a_wrong_or_malformed_secret_is_refused(self):
        broker = self.start_broker({"anthropic": REAL["anthropic"]})
        wrong_values = (
            {"x-api-key": "factory-broker-not-the-runs-secret"},
            {"x-api-key": cb.PLACEHOLDER_PREFIX},  # the prefix alone, no random suffix
            {"authorization": "Bearer factory-broker-guessed"},
            {"authorization": "Bearer "},          # an empty bearer token
            {"x-goog-api-key": "nope", "api-key": "nope"},
            # The REAL key is not the run secret: holding a stolen raw key must not
            # authenticate against the broker either (it is a credential, not a ticket).
            {"x-api-key": REAL["anthropic"]},
        )
        for headers in wrong_values:
            with self.subTest(headers=headers):
                status, _, body = _client_request(
                    broker.port, "POST", "/proxy/anthropic/v1/messages",
                    headers={**headers, "content-length": "2"}, body=b"{}")
                self.assertEqual(status, 403)
                self.assertEqual(_FakeHTTPSConnection.calls, [],
                                 "a wrong secret must never be forwarded upstream")

    def test_the_run_secret_authenticates_and_the_real_key_is_injected(self):
        # The other direction of the contract: the process that WAS handed the run's
        # placeholder — the engine — is served, and the broker injects the real key.
        broker = self.start_broker({"anthropic": REAL["anthropic"]})
        status, _, body = _client_request(
            broker.port, "POST", "/proxy/anthropic/v1/messages",
            headers={"x-api-key": broker.placeholder, "content-length": "2"},
            body=b"{}")
        self.assertEqual(status, 200)
        call = _FakeHTTPSConnection.calls[0]
        self.assertEqual(call["headers"]["x-api-key"], REAL["anthropic"])
        self.assertNotIn(REAL["anthropic"].encode(), body)

    def test_the_secret_is_per_run_unguessable_and_not_portable_between_brokers(self):
        broker_a = self.start_broker({"anthropic": REAL["anthropic"]})
        broker_b = self.start_broker({"anthropic": REAL["anthropic"]})
        # Per-run: two brokers in the same process get different secrets...
        self.assertNotEqual(broker_a.placeholder, broker_b.placeholder)
        # ...both recognisably placeholders (not vendor-shaped: no sk-/AIza form)...
        for placeholder in (broker_a.placeholder, broker_b.placeholder):
            self.assertTrue(placeholder.startswith(cb.PLACEHOLDER_PREFIX))
            self.assertGreater(len(placeholder), len(cb.PLACEHOLDER_PREFIX) + 16)
            self.assertFalse(placeholder.startswith(("sk-", "AIza")))
        # ...and one run's secret is refused by another run's broker: possession is the
        # authentication, so a secret only licences the broker that issued it.
        status, _, _ = _client_request(
            broker_b.port, "POST", "/proxy/anthropic/v1/messages",
            headers={"x-api-key": broker_a.placeholder, "content-length": "2"},
            body=b"{}")
        self.assertEqual(status, 403)
        self.assertEqual(_FakeHTTPSConnection.calls, [])

    def test_a_keyless_broker_also_refuses_the_unauthenticated(self):
        # The refusal does not depend on holding a keyed credential: a keyless managed
        # endpoint broker (agents-3y2) must not be an unauthenticated forwarder either.
        broker = self.start_broker({"deepseek": None})
        status, _, _ = _client_request(
            broker.port, "POST", "/proxy/deepseek/chat/completions",
            headers={"content-length": "2"}, body=b"{}")
        self.assertEqual(status, 403)
        self.assertEqual(_FakeHTTPSConnection.calls, [])

    def test_the_unix_listener_demands_the_secret_too(self):
        # The sandboxed path's UNIX listener runs the same handler; its confinement is the
        # netns, but the authentication is the broker's own and holds on both shapes.
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        sock = os.path.join(d, "broker.sock")
        broker = cb.CredentialBroker({"anthropic": REAL["anthropic"]})
        broker.start(unix_path=sock, child_port=8384)
        self.addCleanup(broker.stop)
        status, _, _ = _unix_client_request(
            sock, "POST", "/proxy/anthropic/v1/messages",
            headers={"content-length": "2"}, body=b"{}")
        self.assertEqual(status, 403)
        self.assertEqual(_FakeHTTPSConnection.calls, [])


class TestFailClosedAndEdgeCases(BrokerTestBase):
    def test_a_provider_without_a_real_key_is_refused_not_forwarded(self):
        # The broker holds only an anthropic key; a request for openai must fail closed
        # (502) rather than forward the engine's placeholder as if it were a credential.
        broker = self.start_broker({"anthropic": REAL["anthropic"]})
        status, _, body = _client_request(
            broker.port, "POST", "/proxy/openai/chat/completions",
            headers={"authorization": f"Bearer {broker.placeholder}", "content-length": "2"},
            body=b"{}")
        self.assertEqual(status, 502)
        self.assertEqual(_FakeHTTPSConnection.calls, [], "nothing may be forwarded")
        self.assertNotIn(REAL["anthropic"].encode(), body)

    def test_an_unknown_provider_path_is_404(self):
        broker = self.start_broker({"anthropic": REAL["anthropic"]})
        status, _, _ = _client_request(broker.port, "POST", "/proxy/nope/v1/x",
                                       headers={"x-api-key": broker.placeholder,
                                                "content-length": "0"})
        self.assertEqual(status, 404)
        self.assertEqual(_FakeHTTPSConnection.calls, [])

    def test_a_non_broker_path_is_404(self):
        broker = self.start_broker({"anthropic": REAL["anthropic"]})
        status, _, _ = _client_request(broker.port, "GET", "/healthz",
                                       headers={"x-api-key": broker.placeholder})
        self.assertEqual(status, 404)

    def test_content_length_above_cap_returns_413_without_forwarding_upstream(self):
        """agents-ce2: request body with Content-Length above 32 MiB returns 413 without reading into memory or forwarding."""
        broker = self.start_broker({"anthropic": REAL["anthropic"]})
        oversized = cb.MAX_BROKER_BODY_BYTES + 1024
        # Send headers with Content-Length > 32 MiB, but no massive payload body
        status, _, body = _client_request(
            broker.port, "POST", "/proxy/anthropic/v1/messages",
            headers={"x-api-key": broker.placeholder, "content-type": "application/json",
                     "content-length": str(oversized)},
            body=None)
        self.assertEqual(status, 413)
        self.assertIn(b"exceeds", body.lower())
        self.assertEqual(_FakeHTTPSConnection.calls, [], "oversized request must NEVER be forwarded upstream")

    def test_negative_content_length_returns_400_without_forwarding(self):
        """agents-ce2: negative Content-Length is rejected as 400 Bad Request."""
        broker = self.start_broker({"anthropic": REAL["anthropic"]})
        status, _, body = _client_request(
            broker.port, "POST", "/proxy/anthropic/v1/messages",
            headers={"x-api-key": broker.placeholder, "content-type": "application/json",
                     "content-length": "-10"},
            body=None)
        self.assertEqual(status, 400)
        self.assertIn(b"negative", body.lower())
        self.assertEqual(_FakeHTTPSConnection.calls, [])

    def test_invalid_content_length_returns_400_without_forwarding(self):
        """agents-ce2: non-integer Content-Length is rejected as 400 Bad Request."""
        broker = self.start_broker({"anthropic": REAL["anthropic"]})
        status, _, body = _client_request(
            broker.port, "POST", "/proxy/anthropic/v1/messages",
            headers={"x-api-key": broker.placeholder, "content-type": "application/json",
                     "content-length": "not-a-number"},
            body=None)
        self.assertEqual(status, 400)
        self.assertIn(b"invalid content-length", body.lower())
        self.assertEqual(_FakeHTTPSConnection.calls, [])

    def test_base_url_shape(self):
        broker = self.start_broker({"anthropic": REAL["anthropic"]})
        self.assertEqual(broker.base_url("anthropic"),
                         f"http://127.0.0.1:{broker.port}/proxy/anthropic")
        with self.assertRaises(cb.BrokerError):
            broker.base_url("openai")  # no credential brokered for it

    def test_cross_provider_request_is_rejected_with_403(self):
        """agents-3z8: a broker restricted to allowed_providers rejects requests to other providers with 403."""
        # Host holds both Anthropic and OpenAI keys, but this run is restricted to anthropic
        broker = cb.CredentialBroker(
            {"anthropic": REAL["anthropic"], "openai": REAL["openai"]},
            allowed_providers=["anthropic"],
        )
        broker.start()
        self.addCleanup(broker.stop)

        # 1. Allowed provider request succeeds (positive case)
        status, _, body = _client_request(
            broker.port, "POST", "/proxy/anthropic/v1/messages",
            headers={"x-api-key": broker.placeholder, "content-length": "2"},
            body=b"{}")
        self.assertEqual(status, 200)
        self.assertEqual(len(_FakeHTTPSConnection.calls), 1)
        self.assertEqual(_FakeHTTPSConnection.calls[0]["host"], "api.anthropic.com")
        self.assertEqual(_FakeHTTPSConnection.calls[0]["headers"]["x-api-key"], REAL["anthropic"])

        # 2. Cross-provider request to openai is rejected with 403 (negative case)
        # Assert clean denial: 403 status, no credentials returned or leaked in body, no upstream call
        status, _, body = _client_request(
            broker.port, "POST", "/proxy/openai/chat/completions",
            headers={"authorization": f"Bearer {broker.placeholder}", "content-length": "2"},
            body=b"{}")
        self.assertEqual(status, 403)
        self.assertIn(b"not allowed for this run", body)
        self.assertNotIn(REAL["openai"].encode(), body)
        self.assertNotIn(REAL["anthropic"].encode(), body)
        self.assertEqual(len(_FakeHTTPSConnection.calls), 1, "cross-provider request must not be forwarded")

    def test_path_traversal_and_encoding_cannot_widen_provider_restriction(self):
        """agents-3z8: path traversal and URL-encoding tricks cannot bypass provider restriction."""
        broker = cb.CredentialBroker(
            {"anthropic": REAL["anthropic"], "openai": REAL["openai"]},
            allowed_providers=["anthropic"],
        )
        broker.start()
        self.addCleanup(broker.stop)

        # Path traversal attempting to reach openai via allowed anthropic prefix
        status, _, body = _client_request(
            broker.port, "POST", "/proxy/anthropic/../openai/chat/completions",
            headers={"authorization": f"Bearer {broker.placeholder}", "content-length": "2"},
            body=b"{}")
        self.assertEqual(status, 403)
        self.assertIn(b"not allowed for this run", body)
        self.assertEqual(len(_FakeHTTPSConnection.calls), 0)

        # URL-encoded provider name (%6f%70%65%6e%61%69 == openai)
        status, _, body = _client_request(
            broker.port, "POST", "/proxy/%6f%70%65%6e%61%69/chat/completions",
            headers={"authorization": f"Bearer {broker.placeholder}", "content-length": "2"},
            body=b"{}")
        self.assertEqual(status, 403)
        self.assertIn(b"not allowed for this run", body)
        self.assertEqual(len(_FakeHTTPSConnection.calls), 0)

        # Case variation (/proxy/OpenAI/...)
        status, _, body = _client_request(
            broker.port, "POST", "/proxy/OpenAI/chat/completions",
            headers={"authorization": f"Bearer {broker.placeholder}", "content-length": "2"},
            body=b"{}")
        self.assertEqual(status, 403)
        self.assertIn(b"not allowed for this run", body)
        self.assertEqual(len(_FakeHTTPSConnection.calls), 0)

        # Double-slash normalization (/proxy//openai/...)
        status, _, body = _client_request(
            broker.port, "POST", "/proxy//openai/chat/completions",
            headers={"authorization": f"Bearer {broker.placeholder}", "content-length": "2"},
            body=b"{}")
        self.assertEqual(status, 403)
        self.assertIn(b"not allowed for this run", body)
        self.assertEqual(len(_FakeHTTPSConnection.calls), 0)

    def test_request_headers_cannot_widen_provider_restriction(self):
        """agents-3z8: request headers cannot manipulate or widen provider selection."""
        broker = cb.CredentialBroker(
            {"anthropic": REAL["anthropic"], "openai": REAL["openai"]},
            allowed_providers=["anthropic"],
        )
        broker.start()
        self.addCleanup(broker.stop)

        # Client sends custom headers attempting to steer to openai
        status, _, body = _client_request(
            broker.port, "POST", "/proxy/anthropic/v1/messages",
            headers={
                "x-api-key": broker.placeholder,
                "x-provider": "openai",
                "x-forwarded-host": "api.openai.com",
                "host": "api.openai.com",
                "content-length": "2",
            },
            body=b"{}")
        self.assertEqual(status, 200)
        self.assertEqual(len(_FakeHTTPSConnection.calls), 1)
        # Verify host and headers strictly follow the allowed provider (anthropic)
        call = _FakeHTTPSConnection.calls[0]
        self.assertEqual(call["host"], "api.anthropic.com")
        self.assertEqual(call["headers"]["x-api-key"], REAL["anthropic"])
        self.assertNotIn("authorization", [k.lower() for k in call["headers"]])
        self.assertNotIn(REAL["openai"].encode(), body)

    def test_disallowed_provider_base_url_raises_broker_error(self):
        """agents-3z8: base_url for a disallowed provider raises BrokerError."""
        broker = cb.CredentialBroker(
            {"anthropic": REAL["anthropic"], "openai": REAL["openai"]},
            allowed_providers=["anthropic"],
        )
        broker.start()
        self.addCleanup(broker.stop)
        self.assertEqual(broker.providers, ("anthropic",))
        self.assertIn("/proxy/anthropic", broker.base_url("anthropic"))
        with self.assertRaises(cb.BrokerError) as ctx:
            broker.base_url("openai")
        self.assertIn("not allowed for this run", str(ctx.exception))

    def test_unknown_allowed_provider_rejected_at_construction(self):
        """agents-3z8: declaring an unrecognised provider in allowed_providers raises BrokerError."""
        with self.assertRaises(cb.BrokerError):
            cb.CredentialBroker({"anthropic": REAL["anthropic"]}, allowed_providers=["non-existent-provider"])


class TestStreaming(BrokerTestBase):
    def test_an_sse_body_is_streamed_back_whole(self):
        # An SSE response in several chunks must reach the engine intact (the broker
        # re-chunks it); assert the full byte stream, not a buffered single read.
        sse = [b"event: message\n", b'data: {"t":1}\n\n', b'data: {"t":2}\n\n', b"event: done\n"]
        _FakeHTTPSConnection.response = _FakeUpstreamResponse(
            200, "OK", [("Content-Type", "text/event-stream")], sse)
        broker = self.start_broker({"anthropic": REAL["anthropic"]})
        status, headers, body = _client_request(
            broker.port, "POST", "/proxy/anthropic/v1/messages",
            headers={"x-api-key": broker.placeholder, "content-length": "2"}, body=b"{}")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Type"), "text/event-stream")
        self.assertEqual(body, b"".join(sse))


class TestCredentialsFromEnv(unittest.TestCase):
    def test_only_providers_with_a_key_are_returned(self):
        env = {"ANTHROPIC_API_KEY": "a", "OPENAI_API_KEY": "o", "PATH": "/bin"}
        self.assertEqual(cb.credentials_from_env(environ=env),
                         {"anthropic": "a", "openai": "o"})

    def test_an_alternate_var_satisfies_a_provider(self):
        self.assertEqual(cb.credentials_from_env(environ={"GOOGLE_API_KEY": "g"}),
                         {"google": "g"})

    def test_empty_env_brokers_nothing(self):
        self.assertEqual(cb.credentials_from_env(environ={}), {})


class TestLifecycle(unittest.TestCase):
    def test_context_manager_starts_and_stops_without_leaking_a_listener(self):
        with cb.CredentialBroker({"anthropic": REAL["anthropic"]}) as broker:
            port = broker.port
            self.assertIsNotNone(port)
            # An authenticated non-broker path 404s at the handler BEFORE any upstream hop,
            # proving the listener is up with no network call and no real credential involved.
            status, _, _ = _client_request(port, "GET", "/healthz",
                                           headers={"x-api-key": broker.placeholder})
            self.assertEqual(status, 404)
        # After stop(), the port no longer accepts connections.
        with self.assertRaises(OSError):
            _client_request(port, "GET", "/healthz")

    def test_stop_is_idempotent(self):
        broker = cb.CredentialBroker({"anthropic": REAL["anthropic"]})
        broker.start()
        broker.stop()
        broker.stop()  # must not raise
        self.assertIsNone(broker.port)

    def test_refuses_to_start_with_no_credentials(self):
        with self.assertRaises(cb.BrokerError):
            cb.CredentialBroker({}).start()

    def test_a_keyless_only_broker_starts(self):
        # agents-3y2: a broker holding only keyless providers (None values) is not empty, so
        # it must start and serve the managed endpoints with no host key.
        broker = cb.CredentialBroker({"deepseek": None})
        broker.start()
        self.addCleanup(broker.stop)
        self.assertIsNotNone(broker.port)

    def test_a_long_unix_socket_path_is_refused_loudly(self):
        # agents-x8l: AF_UNIX sun_path holds at most 107 bytes; refuse before bind() so the
        # failure is a clear BrokerError, not a cryptic ENAMETOOLONG from the server thread.
        broker = cb.CredentialBroker({"anthropic": REAL["anthropic"]})
        with self.assertRaises(cb.BrokerError) as cm:
            broker.start(unix_path="/" * 108, child_port=8384)
        self.assertIn("sun_path", str(cm.exception))
        self.assertIn("107", str(cm.exception))

    def test_unknown_provider_is_rejected_at_construction(self):
        with self.assertRaises(cb.BrokerError):
            cb.CredentialBroker({"azure": "x"})

    def test_broker_error_is_runtime_error_and_tables_match(self):
        # BrokerError is a RuntimeError; table divergence diagnostic is fail-closed (agents-8k9).
        self.assertTrue(issubclass(cb.BrokerError, RuntimeError))
        self.assertEqual(set(cb.PROVIDERS), set(cb.BROKER_ENV_CONFIGS))

    def test_read_request_body_timeout_sets_close_connection(self):
        # Mid-body read timeout must set close_connection = True to prevent keep-alive desync (agents-8k9 item 5).
        handler = cb._Handler.__new__(cb._Handler)
        handler.headers = {"Content-Length": "100"}
        handler.connection = mock.Mock()
        handler.connection.gettimeout.return_value = 10.0
        handler.rfile = mock.Mock()
        handler.rfile.read.side_effect = TimeoutError("read timed out")
        handler.close_connection = False

        with self.assertRaises(cb.BrokerError):
            handler._read_request_body()

        self.assertTrue(handler.close_connection)

    def test_read_request_body_chunked_refusal_sets_close_connection(self):
        # Refusing chunked encoding must set close_connection = True.
        handler = cb._Handler.__new__(cb._Handler)
        handler.headers = {"Transfer-Encoding": "chunked"}
        handler.close_connection = False

        with self.assertRaises(cb.BrokerError):
            handler._read_request_body()

        self.assertTrue(handler.close_connection)

    def test_read_request_body_payload_too_large_sets_close_connection(self):
        # agents-ce2: body exceeding MAX_BROKER_BODY_BYTES raises BrokerPayloadTooLarge and sets close_connection = True.
        handler = cb._Handler.__new__(cb._Handler)
        handler.headers = {"Content-Length": str(cb.MAX_BROKER_BODY_BYTES + 1)}
        handler.close_connection = False

        with self.assertRaises(cb.BrokerPayloadTooLarge):
            handler._read_request_body()

        self.assertTrue(handler.close_connection)

    def test_read_request_body_defensive_integer_parse(self):
        # agents-ce2: non-integer or negative Content-Length raises BrokerError and sets close_connection = True.
        for bad in ("bad-length", "12.34", "-1", "-1000"):
            handler = cb._Handler.__new__(cb._Handler)
            handler.headers = {"Content-Length": bad}
            handler.close_connection = False
            with self.assertRaises(cb.BrokerError):
                handler._read_request_body()
            self.assertTrue(handler.close_connection)


class TestChildEnvBrokerComposition(BrokerTestBase):
    """The two committed 8h4 components compose: child_environment(broker_urls) hands the engine
    a placeholder + base URL, and a request to THAT base URL with THAT placeholder is routed by
    the broker to the right upstream with the REAL key injected. This is the integration point
    the two unit suites each cover only one side of. (The sandboxed /proc/self/environ leg is
    9n7's proven property; the full run_agent-wired acceptance test lands with the integration,
    which is deferred until agents-6ce lands since both touch factory run_agent.)"""

    def test_child_env_base_url_and_placeholder_drive_the_broker_to_inject_the_real_key(self):
        # The dispatcher holds the real key and starts the broker with it.
        parent = {"PATH": "/usr/bin", "ANTHROPIC_API_KEY": REAL["anthropic"]}
        broker = self.start_broker({"anthropic": REAL["anthropic"]})
        # The engine's env, built the way run_agent will: placeholder + base URL, no real key.
        env = child_environment(engine="pi", parent=parent,
                                broker_urls={"anthropic": broker.base_url("anthropic")},
                                broker_placeholder=broker.placeholder)
        self.assertEqual(env["ANTHROPIC_API_KEY"], broker.placeholder)
        self.assertNotIn(REAL["anthropic"], env.values())
        # Simulate the engine's SDK: POST {base_url}/v1/messages with the placeholder key.
        split = urlsplit(env["ANTHROPIC_BASE_URL"])
        status, _, body = _client_request(
            split.port, "POST", split.path + "/v1/messages",
            headers={"x-api-key": env["ANTHROPIC_API_KEY"], "anthropic-version": "2023-06-01",
                     "content-type": "application/json", "content-length": "2"},
            body=b"{}")
        self.assertEqual(status, 200)
        call = _FakeHTTPSConnection.calls[0]
        self.assertEqual(call["host"], "api.anthropic.com")
        self.assertEqual(call["path"], "/v1/messages")
        # The broker stripped the placeholder the engine sent and injected the real key.
        self.assertEqual(call["headers"]["x-api-key"], REAL["anthropic"])
        self.assertNotIn(broker.placeholder, call["headers"].values())
        # And the real key never comes back to the engine side.
        self.assertNotIn(REAL["anthropic"].encode(), body)

    def test_keyless_deepseek_base_url_and_placeholder_reach_the_managed_upstream(self):
        # agents-3y2: with NO real key anywhere, child_environment hands the engine a
        # placeholder + the broker's base URL, and a request to THAT URL reaches the keyless
        # managed upstream with no Authorization header injected.
        parent = {"PATH": "/usr/bin"}
        broker = self.start_broker({"deepseek": None})
        env = child_environment(engine="pi", parent=parent,
                                broker_urls={"deepseek": broker.base_url("deepseek")},
                                broker_placeholder=broker.placeholder)
        self.assertEqual(env["DEEPSEEK_API_KEY"], broker.placeholder)
        split = urlsplit(env["DEEPSEEK_BASE_URL"])
        status, _, body = _client_request(
            split.port, "POST", split.path + "/chat/completions",
            headers={"authorization": f"Bearer {env['DEEPSEEK_API_KEY']}",
                     "content-type": "application/json", "content-length": "2"},
            body=b"{}")
        self.assertEqual(status, 200)
        call = _FakeHTTPSConnection.calls[0]
        self.assertEqual(call["host"], "deepseek.int.exe.xyz")
        self.assertNotIn("Authorization", call["headers"])


class TestUnixSocketMode(BrokerTestBase):
    """agents-2x6: a sandboxed engine under bwrap --unshare-net cannot reach a host TCP
    loopback, so the broker also listens on a UNIX socket bind-mounted into the sandbox and
    reached through the net_forward relay. These prove the UNIX listener serves identically
    (routing + key injection), that base_url names the relay's child_port, that stop() unlinks
    the socket, and that the deepseek/openrouter extension routes to the right upstream."""

    def _start_unix(self, credentials, child_port=8384):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        sock = os.path.join(d, "broker.sock")
        broker = cb.CredentialBroker(credentials)
        broker.start(unix_path=sock, child_port=child_port)
        self.addCleanup(broker.stop)
        return broker, sock

    def test_base_url_names_the_child_relay_port(self):
        broker, sock = self._start_unix({"anthropic": REAL["anthropic"]})
        self.assertEqual(broker.base_url("anthropic"),
                         "http://127.0.0.1:8384/proxy/anthropic")
        self.assertTrue(os.path.exists(sock))

    def test_unix_listener_serves_and_injects_the_real_key(self):
        broker, sock = self._start_unix({"anthropic": REAL["anthropic"]})
        status, _, body = _unix_client_request(
            sock, "POST", "/proxy/anthropic/v1/messages",
            headers={"x-api-key": broker.placeholder, "anthropic-version": "2023-06-01",
                     "content-type": "application/json", "content-length": "2"},
            body=b"{}")
        self.assertEqual(status, 200)
        self.assertEqual(body, b'{"ok": true}')
        call = _FakeHTTPSConnection.calls[0]
        self.assertEqual(call["host"], "api.anthropic.com")
        self.assertEqual(call["headers"]["x-api-key"], REAL["anthropic"])
        self.assertNotIn(REAL["anthropic"].encode(), body)

    def test_unix_listener_rejects_cross_provider_requests_with_403(self):
        """agents-3z8: unix socket broker rejects cross-provider requests with 403."""
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        sock = os.path.join(d, "broker.sock")
        broker = cb.CredentialBroker(
            {"anthropic": REAL["anthropic"], "openai": REAL["openai"]},
            allowed_providers=["anthropic"],
        )
        broker.start(unix_path=sock, child_port=8384)
        self.addCleanup(broker.stop)

        status, _, body = _unix_client_request(
            sock, "POST", "/proxy/openai/chat/completions",
            headers={"authorization": f"Bearer {broker.placeholder}", "content-length": "2"},
            body=b"{}")
        self.assertEqual(status, 403)
        self.assertIn(b"not allowed for this run", body)
        self.assertEqual(_FakeHTTPSConnection.calls, [])

    def test_unix_mode_requires_child_port(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        broker = cb.CredentialBroker({"anthropic": REAL["anthropic"]})
        with self.assertRaises(cb.BrokerError):
            broker.start(unix_path=os.path.join(d, "b.sock"))  # no child_port

    def test_stop_unlinks_the_unix_socket(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        sock = os.path.join(d, "broker.sock")
        broker = cb.CredentialBroker({"anthropic": REAL["anthropic"]})
        broker.start(unix_path=sock, child_port=8384)
        self.assertTrue(os.path.exists(sock))
        broker.stop()
        self.assertFalse(os.path.exists(sock))

    def test_deepseek_is_keyless_and_openrouter_is_bearer(self):
        # agents-3y2: deepseek routes to the keyless managed endpoint with NO injected key
        # (auth style "none"); openrouter stays a bearer-keyed provider.
        broker = self.start_broker({"deepseek": None, "openrouter": "or-real"})
        _client_request(broker.port, "POST", "/proxy/deepseek/chat/completions",
                        headers={"authorization": f"Bearer {broker.placeholder}",
                                 "content-type": "application/json", "content-length": "2"},
                        body=b"{}")
        call = _FakeHTTPSConnection.calls[0]
        self.assertEqual(call["host"], "deepseek.int.exe.xyz")
        self.assertEqual(call["path"], "/v1/chat/completions")  # upstream base carries /v1
        self.assertNotIn("Authorization", call["headers"])  # keyless: no key injected
        _FakeHTTPSConnection.calls = []
        _client_request(broker.port, "POST", "/proxy/openrouter/chat/completions",
                        headers={"authorization": f"Bearer {broker.placeholder}",
                                 "content-type": "application/json", "content-length": "2"},
                        body=b"{}")
        call = _FakeHTTPSConnection.calls[0]
        self.assertEqual(call["host"], "openrouter.ai")
        self.assertEqual(call["path"], "/api/v1/chat/completions")
        self.assertEqual(call["headers"]["Authorization"], "Bearer or-real")

    def test_keyless_providers_are_the_managed_byok_endpoints(self):
        self.assertEqual(cb.keyless_providers(), ("deepseek", "zai", "kimi", "qwen"))


class TestBodyBoundAndBudget(BrokerTestBase):
    """agents-wwd: declared-length-only cap, shared aggregate budget, and error hygiene."""

    def setUp(self):
        super().setUp()
        cb._aggregate_body_bytes = 0  # isolate each test from any prior reservation leak

    @staticmethod
    def _raw_send(port, request_bytes):
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.sendall(request_bytes)
        return s

    def test_non_canonical_content_length_is_rejected(self):
        """agents-wwd: int() would accept '1_0' -> 10 and '+5' -> 5; both must be rejected."""
        broker = self.start_broker({"anthropic": REAL["anthropic"]})
        for bad in ("1_0", "+5", "0x10", "1e3", "1.0"):
            status, _, body = _client_request(
                broker.port, "POST", "/proxy/anthropic/v1/messages",
                headers={"x-api-key": broker.placeholder, "content-length": bad},
                body=None)
            self.assertEqual(status, 400, bad)
            self.assertIn(b"invalid content-length", body.lower(), bad)
            self.assertEqual(_FakeHTTPSConnection.calls, [], bad)

    def test_error_responses_declare_connection_close(self):
        """agents-wwd: a 413 that left the body unread must tell the client to close."""
        broker = self.start_broker({"anthropic": REAL["anthropic"]})
        status, headers, _ = _client_request(
            broker.port, "POST", "/proxy/anthropic/v1/messages",
            headers={"x-api-key": broker.placeholder,
                     "content-length": str(cb.MAX_BROKER_BODY_BYTES + 1)},
            body=None)
        self.assertEqual(status, 413)
        self.assertEqual(headers.get("Connection"), "close")

    def test_declared_length_bounds_the_read_not_the_actual_body(self):
        """agents-wwd: an under-declared body is read to exactly the declared length.

        The deleted `total_read` counter could never fire because read(n) is bounded by the
        declared length; this proves the bound directly: Content-Length: 5 with 12 bytes on
        the wire forwards only the first 5.
        """
        broker = self.start_broker({"anthropic": REAL["anthropic"]})
        s = self._raw_send(
            broker.port,
            b"POST /proxy/anthropic/v1/messages HTTP/1.1\r\n"
            b"Host: localhost\r\nx-api-key: " + broker.placeholder.encode() + b"\r\n"
            b"Content-Length: 5\r\n\r\nhelloEXTRA")
        status_line = s.makefile("rb").readline()
        s.close()
        self.assertEqual(status_line.split()[1], b"200")
        self.assertEqual(_FakeHTTPSConnection.calls[0]["body"], b"hello")  # exactly the declared 5

    def test_absent_content_length_body_is_not_read(self):
        """agents-wwd: a body sent with no Content-Length (and not chunked) is not read."""
        broker = self.start_broker({"anthropic": REAL["anthropic"]})
        s = self._raw_send(
            broker.port,
            b"POST /proxy/anthropic/v1/messages HTTP/1.1\r\n"
            b"Host: localhost\r\nx-api-key: " + broker.placeholder.encode() + b"\r\n\r\n"
            b"{\"ignored\": true}")
        status_line = s.makefile("rb").readline()
        s.close()
        self.assertEqual(status_line.split()[1], b"200")
        self.assertIsNone(_FakeHTTPSConnection.calls[0]["body"])

    def test_aggregate_body_budget_refuses_an_overrun(self):
        """agents-wwd: a body under the per-request cap but over the aggregate is 413'd."""
        broker = self.start_broker({"anthropic": REAL["anthropic"]})
        with mock.patch.object(cb, "MAX_BROKER_AGGREGATE_BODY_BYTES", 10):
            status, _, body = _client_request(
                broker.port, "POST", "/proxy/anthropic/v1/messages",
                headers={"x-api-key": broker.placeholder, "content-type": "application/json"},
                body=b"x" * 20)
            self.assertEqual(status, 413)
            self.assertIn(b"aggregate", body.lower())
            self.assertEqual(_FakeHTTPSConnection.calls, [])
        self.assertEqual(cb._aggregate_body_bytes, 0)

    def test_aggregate_budget_is_shared_across_concurrent_requests(self):
        """agents-wwd: two in-flight bodies summing over the aggregate -> the second is 413'd."""
        broker = self.start_broker({"anthropic": REAL["anthropic"]})
        with mock.patch.object(cb, "MAX_BROKER_AGGREGATE_BODY_BYTES", 100):
            # Request 1 declares 60 bytes and holds them in-flight (never finishing the body),
            # so its 60 bytes stay reserved while request 2 tries to reserve another 60.
            s1 = self._raw_send(
                broker.port,
                b"POST /proxy/anthropic/v1/messages HTTP/1.1\r\n"
                b"Host: localhost\r\nx-api-key: " + broker.placeholder.encode() + b"\r\n"
                b"Content-Length: 60\r\n\r\n")
            deadline = time.time() + 5
            while cb._aggregate_body_bytes < 60 and time.time() < deadline:
                time.sleep(0.05)
            self.assertEqual(cb._aggregate_body_bytes, 60)
            status, _, body = _client_request(
                broker.port, "POST", "/proxy/anthropic/v1/messages",
                headers={"x-api-key": broker.placeholder, "content-length": "60"},
                body=None)
            self.assertEqual(status, 413)
            self.assertIn(b"aggregate", body.lower())
            s1.close()
            # closing request 1 makes its blocked read fail, releasing its 60-byte reservation
            deadline = time.time() + 5
            while cb._aggregate_body_bytes > 0 and time.time() < deadline:
                time.sleep(0.05)
        self.assertEqual(cb._aggregate_body_bytes, 0)


if __name__ == "__main__":
    unittest.main()
