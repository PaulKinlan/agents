"""Dispatcher-side credential broker (agents-8h4).

Why this exists
---------------
The OS sandbox (agents-9n7) hides ``$HOME``, so a sandboxed engine authenticates
only from environment API keys (lib/child_env.py's allowlist). But bun/pi needs a
real procfs, so the engine's own ``/proc/self/environ`` is readable by its own read
tool: those keys are in reach of a prompt-injected session. policy.json lists this
as ``not_enforced: env-credentials``.

The broker removes the secret from the sandbox. The dispatcher runs this localhost
HTTP proxy *outside* the sandbox. The sandboxed engine is given only a base URL
pointing here (``ANTHROPIC_BASE_URL`` / ``OPENAI_BASE_URL`` / ``GOOGLE_GEMINI_BASE_URL``)
and a NON-SECRET placeholder key. The proxy injects the real credential — read from
the dispatcher's own environment, which never crosses into the sandbox — and
forwards the request to the real provider over HTTPS, streaming the response back
so SSE is not buffered. No credential shape then exists in the engine's env, fs or
``/proc``, because the only secret lives in this process, on the host side of the
sandbox boundary.

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

import http.client
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Iterable, Mapping, Optional, Tuple
from urllib.parse import urlsplit

__all__ = [
    "CredentialBroker",
    "credentials_from_env",
    "provider_base_url_var",
    "PROVIDERS",
    "BrokerError",
]

# The base URL environment variable each engine/provider reads. pi honours these
# (verified in the pi dist for agents-9n7); the Anthropic/OpenAI/Google SDKs treat
# them as the request base and append their own path.
_BASE_URL_VARS = {
    "anthropic": "ANTHROPIC_BASE_URL",
    "openai": "OPENAI_BASE_URL",
    "google": "GOOGLE_GEMINI_BASE_URL",
}

# provider -> (upstream base URL, auth style, env vars that may hold the real key).
# The upstream base carries whatever the SDK does NOT append: Anthropic's SDK
# appends /v1/messages to a bare origin, whereas OpenAI's SDK appends /chat/...
# to a base that already ends in /v1, so openai's upstream base includes /v1.
# Auth style is "header:<name>" or "bearer".
PROVIDERS: Dict[str, Tuple[str, str, Tuple[str, ...]]] = {
    "anthropic": ("https://api.anthropic.com", "header:x-api-key",
                  ("ANTHROPIC_API_KEY",)),
    "openai": ("https://api.openai.com/v1", "bearer",
               ("OPENAI_API_KEY",)),
    "google": ("https://generativelanguage.googleapis.com", "header:x-goog-api-key",
               ("GEMINI_API_KEY", "GOOGLE_API_KEY")),
}

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

# A non-secret value that satisfies an SDK's "api key must be non-empty" check while
# carrying no credential shape (no vendor prefix, no key=value form), so nothing in the
# sandbox environ looks like a secret to lib/redaction.py or a prompt-injected engine.
PLACEHOLDER_KEY = "factory-broker-placeholder"

# Generous upstream read timeout: a model generation can run for minutes. The
# engine's own budget (lib/budget.py) bounds the whole run; this only stops a wedged
# socket from leaking a broker thread forever.
_UPSTREAM_TIMEOUT_SECONDS = 900.0


class BrokerError(RuntimeError):
    """The broker could not be started or configured."""


def provider_base_url_var(provider: str) -> str:
    """The engine env var that points `provider` at the broker."""
    try:
        return _BASE_URL_VARS[provider]
    except KeyError:
        raise BrokerError(f"unknown provider {provider!r}") from None


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


class _Handler(BaseHTTPRequestHandler):
    """Forwards one engine request to its provider, injecting the real credential.

    `credentials` is bound by CredentialBroker.start() to a per-server subclass; it
    maps provider -> real key and lives only in this (host-side) process.
    """

    protocol_version = "HTTP/1.1"
    server_version = "factory-credential-broker/1.0"
    credentials: Dict[str, str] = {}

    # --- helpers -------------------------------------------------------------
    def _respond_error(self, code: int, message: str) -> None:
        body = message.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _read_request_body(self) -> Optional[bytes]:
        length = self.headers.get("Content-Length")
        if length:
            try:
                return self.rfile.read(int(length))
            except ValueError:
                return None
        # A chunked request body from the engine is not expected (SDKs send
        # Content-Length); refuse rather than guess.
        if (self.headers.get("Transfer-Encoding") or "").lower() == "chunked":
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
    def _broker(self, method: str) -> None:
        path_only, _, query = self.path.partition("?")
        segments = [s for s in path_only.split("/") if s != ""]
        # Expect: proxy / <provider> / <rest...>
        if len(segments) < 2 or segments[0] != "proxy":
            return self._respond_error(404, "not a broker path (expected /proxy/<provider>/...)")
        provider = segments[1]
        if provider not in PROVIDERS:
            return self._respond_error(404, f"unknown provider {provider!r}")
        rest = "/" + "/".join(segments[2:])
        if provider not in self.credentials:
            # No real key for this provider: fail closed rather than forward the
            # engine's placeholder (which the provider would reject anyway, and
            # which must never be mistaken for a working credential).
            return self._respond_error(502, f"broker holds no credential for {provider!r}")

        upstream_base, auth_style, _ = PROVIDERS[provider]
        key = self.credentials[provider]
        try:
            body = self._read_request_body()
        except BrokerError as e:
            return self._respond_error(400, str(e))

        headers = self._upstream_headers()
        if auth_style == "bearer":
            headers["Authorization"] = f"Bearer {key}"
        elif auth_style.startswith("header:"):
            headers[auth_style.split(":", 1)[1]] = key
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


class CredentialBroker:
    """A localhost credential-broker proxy, started and stopped by the dispatcher.

    Usage::

        creds = credentials_from_env()          # {'anthropic': 'sk-ant-...'}
        with CredentialBroker(creds) as broker:
            url = broker.base_url("anthropic")  # http://127.0.0.1:<port>/proxy/anthropic
            # hand `url` + PLACEHOLDER_KEY to the sandboxed engine's env

    The real keys live only in this object (host side); the engine gets `url` and a
    placeholder. stop() is idempotent and always runs (context manager / finally), so
    no listener leaks.
    """

    def __init__(self, credentials: Mapping[str, str]):
        unknown = sorted(set(credentials) - set(PROVIDERS))
        if unknown:
            raise BrokerError(f"unknown provider(s): {', '.join(unknown)}")
        self._credentials: Dict[str, str] = dict(credentials)
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.port: Optional[int] = None

    @property
    def providers(self) -> Tuple[str, ...]:
        return tuple(self._credentials)

    def start(self) -> int:
        """Bind 127.0.0.1 on a dynamic port and serve in a daemon thread."""
        if self._server is not None:
            raise BrokerError("broker already started")
        if not self._credentials:
            raise BrokerError("refusing to start a broker with no credentials")
        handler = type("_BoundBrokerHandler", (_Handler,),
                       {"credentials": dict(self._credentials)})
        self._server = _BrokerServer(("127.0.0.1", 0), handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        name="credential-broker", daemon=True)
        self._thread.start()
        return self.port

    def base_url(self, provider: str) -> str:
        """The engine-side base URL for `provider` (points at this broker)."""
        if self.port is None:
            raise BrokerError("broker not started")
        if provider not in self._credentials:
            raise BrokerError(f"broker has no credential for {provider!r}")
        return f"http://127.0.0.1:{self.port}/proxy/{provider}"

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
        self.port = None

    def __enter__(self) -> "CredentialBroker":
        self.start()
        return self

    def __exit__(self, *exc_info) -> bool:
        self.stop()
        return False
