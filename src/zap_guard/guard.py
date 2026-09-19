"""The Aegis ZAP scope guard: the only network path between ZAP and the synthetic target.

It runs in its own container that joins exactly two internal networks: ``zap-egress`` (shared only
with the zap-runner) and ``zap-target`` (shared only with lab-api). The zap-runner container has
NO route to the target, so every ZAP request must pass through this forward proxy.

Proxy port (ZAP's configured upstream proxy):

- forwards nothing unless the runner has ARMED it for one execution;
- forwards only absolute-form ``http://`` GET/HEAD requests whose origin is the armed origin (which
  must also be in the guard's own hard-coded allowlist) and whose exact path is in the armed
  allowlist; CONNECT/TLS tunnelling, every other method, query strings and user-info are refused;
- enforces the controller's hard request budget atomically BEFORE forwarding: an extra request is
  refused, never sent;
- forwards only ``User-Agent`` and ``Accept`` (no cookies, no Authorization, nothing else);
- counts received / forwarded / blocked (with reason) / redirect responses / upstream failures and
  timeouts, independently of ZAP. A refused request never reaches the target.

Control port (runner only): ``/v1/arm`` returns a one-time token; ``/v1/counters`` and
``/v1/disarm`` require it. Arming is refused while armed, so ZAP (which never sees the token and is
only running while the guard is armed) cannot re-arm or widen it.
"""

from __future__ import annotations

import http.client
import json
import re
import secrets
import sys
import threading
import time
from collections import Counter
from collections.abc import Callable
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

GUARD_VERSION = "zap-scope-guard/1.3.0"
GUARD_SCHEMA = "aegis.zap.guard/1"
ALLOWED_ORIGINS: tuple[str, ...] = ("http://lab-api:8001",)
UPSTREAM_TIMEOUT_SECONDS = 5.0
MAX_RELAY_BYTES = 1_048_576
MAX_CONTROL_BYTES = 4_096
FORWARD_HEADERS = ("User-Agent", "Accept")
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "content-length",
        "set-cookie",
    }
)
_PATH = re.compile(r"^/[A-Za-z0-9/_-]{1,200}$")
_EXEC = re.compile(r"^exec-[a-f0-9]{12}$")
_TOKEN = re.compile(r"^[a-f0-9]{32}$")
_ARM_KEYS = frozenset(
    {"schema_version", "execution_id", "origin", "allowlist", "max_requests", "ttl_ms"}
)


def _now() -> str:
    return datetime.now(UTC).isoformat()


class GuardState:
    """All mutable guard state, guarded by one lock. Budget reservation is atomic."""

    def __init__(
        self,
        allowed_origins: tuple[str, ...] = ALLOWED_ORIGINS,
        upstream_timeout: float = UPSTREAM_TIMEOUT_SECONDS,
        resolver: Callable[[str, int], tuple[str, int]] | None = None,
    ) -> None:
        self.allowed_origins = allowed_origins
        self.upstream_timeout = upstream_timeout
        # Where to open the upstream TCP connection for an admitted (host, port). Production uses
        # the admitted host itself (Docker DNS on zap-target); the offline suite maps the fixed
        # inventory origin onto a loopback test server. Admission decisions never use it.
        self.resolve = resolver or (lambda host, port: (host, port))
        self.lock = threading.Lock()
        self.booted_at = _now()
        self.executions_total = 0
        self.forwarded_total = 0
        self.blocked_total = 0
        self.blocked_while_idle = 0
        self._reset()

    def _reset(self) -> None:
        self.armed = False
        self.execution_id: str | None = None
        self.token: str | None = None
        self.origin: str | None = None
        self.allowlist: frozenset[tuple[str, str]] = frozenset()
        self.max_requests = 0
        self.deadline = 0.0
        self.received = 0
        self.forwarded = 0
        self.blocked: Counter[str] = Counter()
        self.redirects = 0
        self.upstream_failures = 0
        self.upstream_timeouts = 0
        self.budget_exceeded = False
        self.per_path: Counter[tuple[str, str]] = Counter()
        self.statuses: Counter[str] = Counter()

    # --- control ------------------------------------------------------------------------------

    def is_armed(self) -> bool:
        return self.armed and time.monotonic() < self.deadline

    def arm(self, payload: Any) -> tuple[int, dict[str, Any]]:
        if not isinstance(payload, dict) or set(payload) != _ARM_KEYS:
            return 400, {"error": "INVALID_ARM"}
        execution_id, origin = payload["execution_id"], payload["origin"]
        allowlist, max_requests = payload["allowlist"], payload["max_requests"]
        ttl = payload["ttl_ms"]
        if (
            payload["schema_version"] != GUARD_SCHEMA
            or not isinstance(execution_id, str)
            or not _EXEC.fullmatch(execution_id)
            or origin not in self.allowed_origins
            or not isinstance(allowlist, list)
            or not 1 <= len(allowlist) <= 8
            or type(max_requests) is not int
            or not 1 <= max_requests <= 8
            or type(ttl) is not int
            or not 1_000 <= ttl <= 330_000
        ):
            return 400, {"error": "INVALID_ARM"}
        pairs: set[tuple[str, str]] = set()
        for item in allowlist:
            if (
                not isinstance(item, dict)
                or set(item) != {"method", "path"}
                or item["method"] not in {"GET", "HEAD"}
                or not isinstance(item["path"], str)
                or not _PATH.fullmatch(item["path"])
            ):
                return 400, {"error": "INVALID_ARM"}
            pairs.add((item["method"], item["path"]))
        if max_requests != len(pairs):
            # The hard budget is exactly one request per approved operation.
            return 400, {"error": "INVALID_ARM"}
        with self.lock:
            if self.is_armed():
                return 409, {"error": "BUSY"}
            self._reset()
            self.armed = True
            self.execution_id = execution_id
            self.token = secrets.token_hex(16)
            self.origin = origin
            self.allowlist = frozenset(pairs)
            self.max_requests = max_requests
            self.deadline = time.monotonic() + ttl / 1000
            return 200, {
                "schema_version": GUARD_SCHEMA,
                "token": self.token,
                "execution_id": execution_id,
            }

    def _counters(self) -> dict[str, Any]:
        return {
            "received": self.received,
            "forwarded": self.forwarded,
            "blocked": sum(self.blocked.values()),
            "blocked_reasons": sorted([k, v] for k, v in self.blocked.items()),
            "redirects": self.redirects,
            "upstream_failures": self.upstream_failures,
            "upstream_timeouts": self.upstream_timeouts,
            "budget_exceeded": self.budget_exceeded,
            "per_path": sorted([m, p, c] for (m, p), c in self.per_path.items()),
            "statuses": sorted([k, v] for k, v in self.statuses.items()),
        }

    def counters(self, payload: Any, *, disarm: bool) -> tuple[int, dict[str, Any]]:
        token = payload.get("token") if isinstance(payload, dict) else None
        if not isinstance(payload, dict) or set(payload) != {"token"} or not isinstance(token, str):
            return 400, {"error": "INVALID_TOKEN"}
        with self.lock:
            if not _TOKEN.fullmatch(token) or self.token is None or not secrets.compare_digest(
                token, self.token
            ):
                return 403, {"error": "INVALID_TOKEN"}
            body = {
                "schema_version": GUARD_SCHEMA,
                "execution_id": self.execution_id,
                "state": "DISARMED" if disarm else "ARMED",
                "counters": self._counters(),
            }
            if disarm:
                self.executions_total += 1
                self._reset()
            return 200, body

    def attestation(self) -> dict[str, Any]:
        with self.lock:
            return {
                "schema_version": GUARD_SCHEMA,
                "guard_version": GUARD_VERSION,
                "state": "ARMED" if self.is_armed() else "IDLE",
                "allowed_origins": list(self.allowed_origins),
                "booted_at": self.booted_at,
                "executions_total": self.executions_total,
                "forwarded_total": self.forwarded_total,
                "blocked_total": self.blocked_total,
                "blocked_while_idle": self.blocked_while_idle,
            }

    # --- proxy decisions ----------------------------------------------------------------------

    def admit(self, method: str, target: str) -> tuple[str | None, tuple[str, int, str] | None]:
        """Decide one proxied request. Returns (block reason, None) or (None, (host, port, path)).
        The budget slot is reserved here, under the lock, before any byte is forwarded."""

        with self.lock:
            if not self.is_armed():
                self.blocked_total += 1
                self.blocked_while_idle += 1
                return "NOT_ARMED", None
            self.received += 1

            def block(reason: str) -> tuple[str, None]:
                self.blocked[reason] += 1
                self.blocked_total += 1
                return reason, None

            if method not in {"GET", "HEAD"}:
                return block("METHOD")
            parsed = urlsplit(target)
            try:
                port = parsed.port
            except ValueError:
                return block("MALFORMED_TARGET")
            if (
                parsed.scheme != "http"
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
                or port is None
            ):
                return block("MALFORMED_TARGET")
            origin = f"http://{parsed.hostname.lower()}:{port}"
            if origin != self.origin or origin not in self.allowed_origins:
                return block("ORIGIN")
            if not _PATH.fullmatch(parsed.path) or (method, parsed.path) not in self.allowlist:
                return block("PATH")
            if self.forwarded >= self.max_requests:
                self.budget_exceeded = True
                return block("BUDGET")
            self.forwarded += 1
            self.forwarded_total += 1
            self.per_path[(method, parsed.path)] += 1
            return None, (parsed.hostname.lower(), port, parsed.path)

    def record_response(self, status: int) -> None:
        with self.lock:
            self.statuses[str(status)] += 1
            if 300 <= status < 400:
                self.redirects += 1

    def record_failure(self, *, timeout: bool) -> None:
        with self.lock:
            if timeout:
                self.upstream_timeouts += 1
            else:
                self.upstream_failures += 1


def _proxy_handler(state: GuardState) -> type[BaseHTTPRequestHandler]:
    class ProxyHandler(BaseHTTPRequestHandler):
        server_version = "aegis-zap-scope-guard"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            return  # decisions are logged explicitly, without URLs of refused requests

        def _refuse(self, reason: str) -> None:
            body = json.dumps({"blocked": reason}).encode()
            self.close_connection = True
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Aegis-Scope-Guard", "blocked")
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
            sys.stderr.write(f"guard BLOCKED reason={reason} method={self.command[:8]}\n")

        def _handle(self) -> None:
            reason, target = state.admit(self.command, self.path)
            if reason is not None or target is None:
                self._refuse(reason or "UNKNOWN")
                return
            host, port, path = target
            headers = {name: self.headers[name] for name in FORWARD_HEADERS if self.headers[name]}
            headers["Host"] = f"{host}:{port}"
            connect_host, connect_port = state.resolve(host, port)
            connection = http.client.HTTPConnection(
                connect_host, connect_port, timeout=state.upstream_timeout
            )
            try:
                connection.request(self.command, path, headers=headers)
                response = connection.getresponse()
                body = response.read(MAX_RELAY_BYTES + 1)
                if len(body) > MAX_RELAY_BYTES:
                    raise http.client.HTTPException("oversized upstream body")
                status = response.status
                relay = [
                    (k, v) for k, v in response.getheaders() if k.lower() not in _HOP_BY_HOP
                ]
            except TimeoutError:
                state.record_failure(timeout=True)
                self.close_connection = True  # mirror the failure: no response is fabricated
                sys.stderr.write(f"guard UPSTREAM_TIMEOUT method={self.command} path={path}\n")
                return
            except (http.client.HTTPException, OSError):
                state.record_failure(timeout=False)
                self.close_connection = True
                sys.stderr.write(f"guard UPSTREAM_FAILURE method={self.command} path={path}\n")
                return
            finally:
                connection.close()
            state.record_response(status)
            sys.stderr.write(f"guard FORWARDED method={self.command} path={path} status={status}\n")
            self.send_response(status)
            for key, value in relay:
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        do_GET = do_HEAD = _handle  # noqa: N815

        def _method(self) -> None:
            reason, _ = state.admit(self.command, self.path)
            self._refuse(reason or "METHOD")

        do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_CONNECT = do_TRACE = _method  # noqa: N815

    return ProxyHandler


def _control_handler(state: GuardState) -> type[BaseHTTPRequestHandler]:
    class ControlHandler(BaseHTTPRequestHandler):
        server_version = "aegis-zap-scope-guard-control"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            route = self.path if self.path in _ROUTES else "-"
            status = args[1] if len(args) > 1 else "-"
            sys.stderr.write(f"guard-control {self.command} {route} {status}\n")

        def _send(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health":
                self._send(200, {"status": "READY"})
            elif self.path == "/v1/attestation":
                self._send(200, state.attestation())
            else:
                self._send(404, {"error": "NOT_FOUND"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path not in {"/v1/arm", "/v1/counters", "/v1/disarm"}:
                self._send(404, {"error": "NOT_FOUND"})
                return
            if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                self._send(415, {"error": "INVALID_REQUEST"})
                return
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._send(411, {"error": "INVALID_REQUEST"})
                return
            if length <= 0 or length > MAX_CONTROL_BYTES:
                self._send(413, {"error": "INVALID_REQUEST"})
                return
            try:
                payload = json.loads(self.rfile.read(length))
            except (ValueError, UnicodeDecodeError):
                self._send(400, {"error": "INVALID_REQUEST"})
                return
            if self.path == "/v1/arm":
                self._send(*state.arm(payload))
            else:
                self._send(*state.counters(payload, disarm=self.path == "/v1/disarm"))

    return ControlHandler


_ROUTES = frozenset({"/health", "/v1/attestation", "/v1/arm", "/v1/counters", "/v1/disarm"})


def serve(
    state: GuardState, host: str, proxy_port: int, control_port: int
) -> tuple[ThreadingHTTPServer, ThreadingHTTPServer]:
    proxy = ThreadingHTTPServer((host, proxy_port), _proxy_handler(state))
    control = ThreadingHTTPServer((host, control_port), _control_handler(state))
    proxy.daemon_threads = control.daemon_threads = True
    return proxy, control
