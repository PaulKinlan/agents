"""Unit tests for the dispatcher-side credential broker (agents-8h4).

The upstream provider is mocked at http.client.HTTPSConnection, so these tests run
with no network and no real credential: they assert what the broker FORWARDS (the
reconstructed upstream URL and the injected real key) and what it RETURNS to the
engine (the streamed body, with the real key never appearing on the engine side).
"""
import http.client
import io
import os
import sys
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
            headers={"x-api-key": cb.PLACEHOLDER_KEY, "anthropic-version": "2023-06-01",
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
        self.assertNotIn(cb.PLACEHOLDER_KEY, call["headers"].values())
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
                        headers={"authorization": f"Bearer {cb.PLACEHOLDER_KEY}",
                                 "content-type": "application/json", "content-length": "2"},
                        body=b"{}")
        call = _FakeHTTPSConnection.calls[0]
        self.assertEqual(call["host"], "api.openai.com")
        self.assertEqual(call["path"], "/v1/chat/completions")  # upstream base carries /v1
        self.assertEqual(call["headers"]["Authorization"], f"Bearer {REAL['openai']}")
        self.assertNotIn(cb.PLACEHOLDER_KEY, call["headers"]["Authorization"])

    def test_google_uses_x_goog_api_key(self):
        broker = self.start_broker({"google": REAL["google"]})
        _client_request(broker.port, "POST",
                        "/proxy/google/v1beta/models/gemini:generateContent",
                        headers={"x-goog-api-key": cb.PLACEHOLDER_KEY, "content-length": "2"},
                        body=b"{}")
        call = _FakeHTTPSConnection.calls[0]
        self.assertEqual(call["host"], "generativelanguage.googleapis.com")
        self.assertEqual(call["path"], "/v1beta/models/gemini:generateContent")
        self.assertEqual(call["headers"]["x-goog-api-key"], REAL["google"])

    def test_query_string_is_preserved(self):
        broker = self.start_broker({"google": REAL["google"]})
        _client_request(broker.port, "GET", "/proxy/google/v1beta/models?pageSize=1",
                        headers={"x-goog-api-key": cb.PLACEHOLDER_KEY})
        self.assertEqual(_FakeHTTPSConnection.calls[0]["path"],
                         "/v1beta/models?pageSize=1")


class TestFailClosedAndEdgeCases(BrokerTestBase):
    def test_a_provider_without_a_real_key_is_refused_not_forwarded(self):
        # The broker holds only an anthropic key; a request for openai must fail closed
        # (502) rather than forward the engine's placeholder as if it were a credential.
        broker = self.start_broker({"anthropic": REAL["anthropic"]})
        status, _, body = _client_request(
            broker.port, "POST", "/proxy/openai/chat/completions",
            headers={"authorization": f"Bearer {cb.PLACEHOLDER_KEY}", "content-length": "2"},
            body=b"{}")
        self.assertEqual(status, 502)
        self.assertEqual(_FakeHTTPSConnection.calls, [], "nothing may be forwarded")
        self.assertNotIn(REAL["anthropic"].encode(), body)

    def test_an_unknown_provider_path_is_404(self):
        broker = self.start_broker({"anthropic": REAL["anthropic"]})
        status, _, _ = _client_request(broker.port, "POST", "/proxy/nope/v1/x",
                                       headers={"content-length": "0"})
        self.assertEqual(status, 404)
        self.assertEqual(_FakeHTTPSConnection.calls, [])

    def test_a_non_broker_path_is_404(self):
        broker = self.start_broker({"anthropic": REAL["anthropic"]})
        status, _, _ = _client_request(broker.port, "GET", "/healthz")
        self.assertEqual(status, 404)

    def test_base_url_shape(self):
        broker = self.start_broker({"anthropic": REAL["anthropic"]})
        self.assertEqual(broker.base_url("anthropic"),
                         f"http://127.0.0.1:{broker.port}/proxy/anthropic")
        with self.assertRaises(cb.BrokerError):
            broker.base_url("openai")  # no credential brokered for it


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
            headers={"x-api-key": cb.PLACEHOLDER_KEY, "content-length": "2"}, body=b"{}")
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
            # A non-broker path 404s at the handler BEFORE any upstream hop, proving the
            # listener is up with no network call and no credential needed.
            status, _, _ = _client_request(port, "GET", "/healthz")
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

    def test_unknown_provider_is_rejected_at_construction(self):
        with self.assertRaises(cb.BrokerError):
            cb.CredentialBroker({"azure": "x"})


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
                                broker_urls={"anthropic": broker.base_url("anthropic")})
        self.assertEqual(env["ANTHROPIC_API_KEY"], cb.PLACEHOLDER_KEY)
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
        self.assertNotIn(cb.PLACEHOLDER_KEY, call["headers"].values())
        # And the real key never comes back to the engine side.
        self.assertNotIn(REAL["anthropic"].encode(), body)


if __name__ == "__main__":
    unittest.main()
