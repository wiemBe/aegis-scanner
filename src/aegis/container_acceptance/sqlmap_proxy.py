"""Controller-owned inline counting proxy that strictly caps SQLMap's HTTP requests.

The reactive watchdog (:mod:`aegis.container_acceptance.sqlmap_budget`) kills the SQLMap container
*after* it has already logged N requests, so request N+1 can still reach the target before the kill
lands. This module closes that gap: SQLMap is pointed at a controller-owned forward proxy
(``--proxy=http://<proxy>``) that counts every request and **rejects request N+1 before it is
forwarded**, so the target never receives it. The ceiling is supplied by the controller at proxy
construction; the model-facing :class:`SqlmapPlan` (``extra="forbid"``) cannot carry or widen it.

Deliberate hardening decisions:

* **Plaintext only.** ``CONNECT`` tunnelling is denied, because an opaque TLS tunnel cannot be
  counted per request. The synthetic range is internal HTTP, so this loses nothing and guarantees
  every request is individually accountable.
* **Single authorized upstream.** Only the one controller-approved ``host:port`` is forwarded; any
  other authority (a redirect or discovered host that escapes scope) is rejected and counted
  separately, never forwarded.
* **Safe metadata only.** The ledger records a monotonic sequence number, method, decision and the
  request *path* with its query stripped. Request/response bodies, headers and query values never
  enter persisted evidence.

The proxy runs in-process (used directly by the offline tests, driving strict enforcement without a
container) and is the same object a container entrypoint would host.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import SplitResult, urlsplit

from aegis.container_acceptance.contracts import SqlmapProxyOutcome

# Hop-by-hop headers are never forwarded (RFC 7230 §6.1); "proxy-connection" is added defensively.
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    }
)
_OVER_BUDGET_STATUS = 429
_OUT_OF_SCOPE_STATUS = 403
# 1 MiB request-body ceiling; larger requests are refused rather than proxied.
_MAX_FORWARD_BODY = 1_000_000


@dataclass(frozen=True)
class ProxyLedgerEntry:
    """One safe-metadata record. Never contains bodies, headers or query values."""

    sequence: int
    method: str
    path: str  # query stripped
    decision: str  # FORWARDED | REJECTED_OVER_BUDGET | REJECTED_OUT_OF_SCOPE | REJECTED_METHOD


@dataclass
class _Counters:
    forwarded: int = 0
    rejected_over_budget: int = 0
    rejected_out_of_scope: int = 0
    rejected_method: int = 0
    ledger: list[ProxyLedgerEntry] = field(default_factory=list)


class CountingForwardProxy:
    """A controller-owned forward proxy enforcing an exact per-run HTTP request ceiling."""

    def __init__(self, *, upstream_authority: str, max_http_requests: int) -> None:
        if max_http_requests < 1:
            raise ValueError("max_http_requests must be >= 1")
        if not upstream_authority or "/" in upstream_authority:
            raise ValueError("upstream_authority must be a bare host[:port]")
        self._upstream = upstream_authority
        self._max = max_http_requests
        self._lock = threading.Lock()
        self._counters = _Counters()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # -- lifecycle ------------------------------------------------------------------------------- #

    def start(self, host: str = "127.0.0.1", port: int = 0) -> tuple[str, int]:
        """Bind and serve on a background thread; return the bound (host, port)."""

        handler = self._build_handler()
        server = ThreadingHTTPServer((host, port), handler)
        self._server = server
        thread = threading.Thread(target=server.serve_forever, name="sqlmap-counting-proxy")
        thread.daemon = True
        thread.start()
        self._thread = thread
        bound_host, bound_port = server.server_address[0], server.server_address[1]
        return str(bound_host), int(bound_port)

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def __enter__(self) -> CountingForwardProxy:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # -- observation ----------------------------------------------------------------------------- #

    @property
    def outcome(self) -> SqlmapProxyOutcome:
        with self._lock:
            return SqlmapProxyOutcome(
                max_http_requests=self._max,
                forwarded_requests=self._counters.forwarded,
                rejected_over_budget=self._counters.rejected_over_budget,
                rejected_out_of_scope=self._counters.rejected_out_of_scope,
                upstream_authority=self._upstream,
            )

    @property
    def ledger(self) -> tuple[ProxyLedgerEntry, ...]:
        with self._lock:
            return tuple(self._counters.ledger)

    # -- decision core (thread-safe) ------------------------------------------------------------- #

    def _authorize(self, method: str, authority: str, path: str) -> str:
        """Decide FORWARDED / REJECTED_* under the lock. Records only safe metadata."""

        with self._lock:
            sequence = (
                self._counters.forwarded
                + self._counters.rejected_over_budget
                + self._counters.rejected_out_of_scope
                + self._counters.rejected_method
                + 1
            )
            if authority != self._upstream:
                self._counters.rejected_out_of_scope += 1
                decision = "REJECTED_OUT_OF_SCOPE"
            elif self._counters.forwarded >= self._max:
                self._counters.rejected_over_budget += 1
                decision = "REJECTED_OVER_BUDGET"
            else:
                self._counters.forwarded += 1
                decision = "FORWARDED"
            self._counters.ledger.append(
                ProxyLedgerEntry(sequence=sequence, method=method, path=path, decision=decision)
            )
            return decision

    def _reject_method(self, method: str, path: str) -> None:
        with self._lock:
            self._counters.rejected_method += 1
            sequence = (
                self._counters.forwarded
                + self._counters.rejected_over_budget
                + self._counters.rejected_out_of_scope
                + self._counters.rejected_method
            )
            self._counters.ledger.append(
                ProxyLedgerEntry(
                    sequence=sequence, method=method, path=path, decision="REJECTED_METHOD"
                )
            )

    # -- request handler ------------------------------------------------------------------------- #

    def _build_handler(self) -> type[BaseHTTPRequestHandler]:
        proxy = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_: object) -> None:  # silence default stderr logging
                return

            def do_CONNECT(self) -> None:  # noqa: N802 - http.server dispatch name
                # Deny TLS tunnelling: an opaque tunnel cannot be counted per request.
                proxy._reject_method("CONNECT", "")
                self.send_error(405, "CONNECT tunnelling is denied by the counting proxy")

            def _dispatch(self) -> None:
                parts = urlsplit(self.path)  # proxy form: absolute URI
                if not parts.scheme or not parts.netloc:
                    proxy._reject_method(self.command, "")
                    self.send_error(400, "proxy requires an absolute-form request URI")
                    return
                path = parts.path or "/"
                decision = proxy._authorize(self.command, parts.netloc, path)
                if decision == "REJECTED_OUT_OF_SCOPE":
                    self._respond(_OUT_OF_SCOPE_STATUS, b"out-of-scope upstream rejected")
                    return
                if decision == "REJECTED_OVER_BUDGET":
                    self._respond(_OVER_BUDGET_STATUS, b"request budget exhausted; not forwarded")
                    return
                self._forward(parts)

            def _forward(self, parts: SplitResult) -> None:
                length = int(self.headers.get("Content-Length", "0") or "0")
                if length > _MAX_FORWARD_BODY:
                    self.send_error(413, "request body exceeds forward ceiling")
                    return
                body = self.rfile.read(length) if length else b""
                forward_path = parts.path or "/"
                if parts.query:
                    forward_path = f"{forward_path}?{parts.query}"
                headers = {
                    key: value
                    for key, value in self.headers.items()
                    if key.lower() not in _HOP_BY_HOP
                }
                connection = HTTPConnection(proxy._upstream, timeout=15)
                try:
                    connection.request(self.command, forward_path, body=body, headers=headers)
                    response = connection.getresponse()
                    payload = response.read()
                    status = response.status
                    passthrough = [
                        (key, value)
                        for key, value in response.getheaders()
                        if key.lower() not in _HOP_BY_HOP and key.lower() != "content-length"
                    ]
                finally:
                    connection.close()
                self.send_response(status)
                for key, value in passthrough:
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def _respond(self, status: int, message: bytes) -> None:
                self.send_response(status)
                self.send_header("Content-Length", str(len(message)))
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(message)

            def do_GET(self) -> None:  # noqa: N802 - http.server dispatch name
                self._dispatch()

            def do_POST(self) -> None:  # noqa: N802
                self._dispatch()

            def do_PUT(self) -> None:  # noqa: N802
                self._dispatch()

            def do_DELETE(self) -> None:  # noqa: N802
                self._dispatch()

            def do_HEAD(self) -> None:  # noqa: N802
                self._dispatch()

            def do_OPTIONS(self) -> None:  # noqa: N802
                self._dispatch()

            def do_PATCH(self) -> None:  # noqa: N802
                self._dispatch()

        return _Handler
