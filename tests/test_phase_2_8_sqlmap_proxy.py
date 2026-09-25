"""WS4 — strict, inline SQLMap request-budget enforcement via the controller-owned counting proxy.

These are OFFLINE_INTEGRATION tests: no container, no provider. A local stub upstream stands in for
the synthetic range; the proxy is driven with real HTTP over loopback. They prove the property the
reactive watchdog cannot guarantee — request N+1 is rejected *before* it reaches the target.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import ProxyHandler, build_opener

import pytest

from aegis.container_acceptance.sqlmap_proxy import CountingForwardProxy


class _Upstream:
    """A loopback stub target that records how many requests actually reached it."""

    def __init__(self) -> None:
        self.received = 0
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> str:
        recorder = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_: object) -> None:
                return

            def do_GET(self) -> None:  # noqa: N802
                with recorder._lock:
                    recorder.received += 1
                body = b"ok"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:  # noqa: N802
                self.do_GET()

        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._server = server
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self._thread = thread
        return f"127.0.0.1:{server.server_address[1]}"

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)


@pytest.fixture
def upstream() -> Iterator[_Upstream]:
    stub = _Upstream()
    stub.start()
    yield stub
    stub.stop()


def _get(proxy_authority: str, url: str) -> int:
    opener = build_opener(ProxyHandler({"http": f"http://{proxy_authority}"}))
    try:
        with opener.open(url, timeout=15) as response:
            return int(response.status)
    except HTTPError as exc:
        return int(exc.code)


def test_proxy_forwards_exactly_the_ceiling_and_rejects_overflow(upstream: _Upstream) -> None:
    authority = _authority(upstream)
    proxy = CountingForwardProxy(upstream_authority=authority, max_http_requests=3)
    proxy.start()
    try:
        proxy_authority = _authority_of(proxy)
        statuses = [_get(proxy_authority, f"http://{authority}/p{i}") for i in range(5)]
    finally:
        proxy.stop()

    # Exactly three requests reached the target; requests 4 and 5 were rejected before forwarding.
    assert upstream.received == 3
    assert statuses[:3] == [200, 200, 200]
    assert statuses[3:] == [429, 429]
    outcome = proxy.outcome
    assert outcome.forwarded_requests == 3
    assert outcome.rejected_over_budget == 2
    assert outcome.within_budget is True
    assert outcome.ceiling_reached is True


def test_proxy_rejects_out_of_scope_upstream_without_forwarding(upstream: _Upstream) -> None:
    authority = _authority(upstream)
    proxy = CountingForwardProxy(upstream_authority=authority, max_http_requests=5)
    proxy.start()
    try:
        proxy_authority = _authority_of(proxy)
        # A different host (a redirect/discovered host escaping scope) must never be forwarded.
        status = _get(proxy_authority, "http://127.0.0.1:9/escape")
    finally:
        proxy.stop()

    assert status == 403
    assert upstream.received == 0
    outcome = proxy.outcome
    assert outcome.rejected_out_of_scope == 1
    assert outcome.forwarded_requests == 0
    assert outcome.escape_attempted is True


def test_proxy_ledger_retains_only_safe_metadata(upstream: _Upstream) -> None:
    authority = _authority(upstream)
    proxy = CountingForwardProxy(upstream_authority=authority, max_http_requests=1)
    proxy.start()
    try:
        proxy_authority = _authority_of(proxy)
        _get(proxy_authority, f"http://{authority}/secret-path?token=SECRETVALUE&id=42")
        _get(proxy_authority, f"http://{authority}/secret-path?token=SECRETVALUE&id=43")
    finally:
        proxy.stop()

    entries = proxy.ledger
    assert [entry.decision for entry in entries] == ["FORWARDED", "REJECTED_OVER_BUDGET"]
    # The query (which could carry a secret) is stripped; only the path is retained.
    for entry in entries:
        assert entry.path == "/secret-path"
        assert "SECRETVALUE" not in entry.path
        assert "?" not in entry.path


def test_ceiling_is_not_settable_below_one() -> None:
    with pytest.raises(ValueError, match="max_http_requests"):
        CountingForwardProxy(upstream_authority="127.0.0.1:8600", max_http_requests=0)


def _authority(stub: _Upstream) -> str:
    assert stub._server is not None
    return f"127.0.0.1:{stub._server.server_address[1]}"


def _authority_of(proxy: CountingForwardProxy) -> str:
    server = proxy._server
    assert server is not None
    return f"127.0.0.1:{server.server_address[1]}"
