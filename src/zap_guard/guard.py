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

import hmac
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
from urllib.parse import parse_qs, urlsplit

GUARD_VERSION = "zap-scope-guard/1.3.0"
GUARD_SCHEMA = "aegis.zap.guard/1"
ALLOWED_ORIGINS: tuple[str, ...] = ("http://lab-api:8001",)
# Phase 1.5 active mode: a much larger but still hard-capped request budget, and query mutation
# allowed only on an explicit set of projected parameters. The passive mode is unchanged.
ACTIVE_MAX_REQUESTS = 512
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
_PARAM_NAME = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_EXEC = re.compile(r"^exec-[a-f0-9]{12}$")
_TOKEN = re.compile(r"^[a-f0-9]{32}$")
_ARM_KEYS = frozenset(
    {"schema_version", "execution_id", "origin", "allowlist", "max_requests", "ttl_ms"}
)
_ACTIVE_ARM_KEYS = frozenset(
    {
        "schema_version",
        "execution_id",
        "origin",
        "allowlist",
        "max_requests",
        "ttl_ms",
        "mode",
        "allowed_query_params",
        # Phase 1.5 lease binding. The guard does not verify the lease signature — that belongs to
        # the root-owned admission component — but it records the identity and the bindings the
        # runner consumed, echoes them back so the runner can confirm both sides agree, and stops
        # forwarding the moment the lease expires or is revoked.
        "lease_id",
        "lease_expires_at",
        "projection_digest",
        "allowlist_digest",
    }
)
_LEASE_ID = re.compile(r"^lease-[a-f0-9]{16}$")
_DIGEST = re.compile(r"^[a-f0-9]{64}$")


def _now() -> str:
    return datetime.now(UTC).isoformat()


class GuardState:
    """All mutable guard state, guarded by one lock. Budget reservation is atomic."""

    def __init__(
        self,
        allowed_origins: tuple[str, ...] = ALLOWED_ORIGINS,
        upstream_timeout: float = UPSTREAM_TIMEOUT_SECONDS,
        resolver: Callable[[str, int], tuple[str, int]] | None = None,
        control_secret: bytes = b"",
    ) -> None:
        self.allowed_origins = allowed_origins
        self.upstream_timeout = upstream_timeout
        # Where to open the upstream TCP connection for an admitted (host, port). Production uses
        # the admitted host itself (Docker DNS on zap-target); the offline suite maps the fixed
        # inventory origin onto a loopback test server. Admission decisions never use it.
        self.resolve = resolver or (lambda host, port: (host, port))
        self.control_secret = control_secret
        self.lock = threading.Lock()
        self.booted_at = _now()
        self.executions_total = 0
        self.forwarded_total = 0
        self.blocked_total = 0
        self.blocked_while_idle = 0
        self._reset()

    def _reset(self) -> None:
        self.armed = False
        self.mode = "PASSIVE"
        self.lease_id: str | None = None
        self.lease_expires_at: int | None = None
        self.projection_digest: str | None = None
        self.allowlist_digest: str | None = None
        self.lease_revoked = False
        self.execution_id: str | None = None
        self.token: str | None = None
        self.origin: str | None = None
        self.allowlist: frozenset[tuple[str, str]] = frozenset()
        self.allowed_params: frozenset[str] = frozenset()
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
        """Armed AND inside both the arm TTL and the lease expiry, and not revoked.

        Expiry and revocation are checked here rather than only at arm time, so a lease that runs
        out or is revoked mid-scan stops forwarding on the very next request without anyone having
        to remember to disarm."""

        if not self.armed or self.lease_revoked or time.monotonic() >= self.deadline:
            return False
        if self.lease_expires_at is not None and time.time() >= self.lease_expires_at:
            return False
        return True

    def arm(self, payload: Any) -> tuple[int, dict[str, Any]]:
        if not isinstance(payload, dict):
            return 400, {"error": "INVALID_ARM"}
        if payload.get("mode") == "ACTIVE":
            return self._arm_active(payload)
        if set(payload) != _ARM_KEYS:
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

    def _arm_active(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        """Arm for one active scan: a larger hard request budget and query mutation on an explicit
        parameter allowlist only. The passive arm path is untouched."""

        if set(payload) != _ACTIVE_ARM_KEYS:
            return 400, {"error": "INVALID_ARM"}
        execution_id, origin = payload["execution_id"], payload["origin"]
        allowlist, max_requests, ttl = (
            payload["allowlist"],
            payload["max_requests"],
            payload["ttl_ms"],
        )
        params = payload["allowed_query_params"]
        lease_id, lease_expires_at = payload["lease_id"], payload["lease_expires_at"]
        projection_digest = payload["projection_digest"]
        allowlist_digest = payload["allowlist_digest"]
        if (
            not isinstance(lease_id, str)
            or not _LEASE_ID.fullmatch(lease_id)
            or type(lease_expires_at) is not int
            or not 1_600_000_000 <= lease_expires_at <= 4_102_444_800
            or not isinstance(projection_digest, str)
            or not _DIGEST.fullmatch(projection_digest)
            or not isinstance(allowlist_digest, str)
            or not _DIGEST.fullmatch(allowlist_digest)
        ):
            return 400, {"error": "INVALID_ARM"}
        if lease_expires_at <= time.time():
            # An already-expired lease is never armed: the guard refuses before ZAP is started.
            return 400, {"error": "LEASE_EXPIRED"}
        if (
            payload["schema_version"] != GUARD_SCHEMA
            or not isinstance(execution_id, str)
            or not _EXEC.fullmatch(execution_id)
            or origin not in self.allowed_origins
            or not isinstance(allowlist, list)
            or not 1 <= len(allowlist) <= 4
            or type(max_requests) is not int
            or not 1 <= max_requests <= ACTIVE_MAX_REQUESTS
            or type(ttl) is not int
            or not 1_000 <= ttl <= 660_000
            or not isinstance(params, list)
            or not 1 <= len(params) <= 4
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
        param_set: set[str] = set()
        for name in params:
            if not isinstance(name, str) or not _PARAM_NAME.fullmatch(name):
                return 400, {"error": "INVALID_ARM"}
            param_set.add(name)
        with self.lock:
            if self.is_armed():
                return 409, {"error": "BUSY"}
            self._reset()
            self.armed = True
            self.mode = "ACTIVE"
            self.execution_id = execution_id
            self.token = secrets.token_hex(16)
            self.origin = origin
            self.allowlist = frozenset(pairs)
            self.allowed_params = frozenset(param_set)
            self.max_requests = max_requests
            self.lease_id = lease_id
            self.lease_expires_at = lease_expires_at
            self.projection_digest = projection_digest
            self.allowlist_digest = allowlist_digest
            self.lease_revoked = False
            # The guard never outlives the lease, whatever TTL the runner asked for.
            self.deadline = min(
                time.monotonic() + ttl / 1000,
                time.monotonic() + max(0.0, lease_expires_at - time.time()),
            )
            return 200, {
                "schema_version": GUARD_SCHEMA,
                "token": self.token,
                "execution_id": execution_id,
                "lease_id": lease_id,
                "lease_expires_at": lease_expires_at,
                "projection_digest": projection_digest,
                "allowlist_digest": allowlist_digest,
                "max_requests": max_requests,
            }

    def revoke(self, payload: Any) -> tuple[int, dict[str, Any]]:
        """Immediate, terminal disarm for one lease. Step 2 of the emergency-stop order.

        Unlike ``/v1/disarm`` this does not require the arm token: the operator's stop path must
        work even if the runner has lost it. It is still bound to the exact armed lease id, so it
        can only ever stop the run that is actually in flight."""

        lease_id = payload.get("lease_id") if isinstance(payload, dict) else None
        if (
            not isinstance(payload, dict)
            or set(payload) - {"lease_id", "reason"}
            or not isinstance(lease_id, str)
            or not _LEASE_ID.fullmatch(lease_id)
        ):
            return 400, {"error": "INVALID_REVOKE"}
        with self.lock:
            if self.lease_id != lease_id:
                return 404, {"error": "UNKNOWN_LEASE"}
            self.lease_revoked = True
            counters = self._counters()
            return 200, {
                "schema_version": GUARD_SCHEMA,
                "lease_id": lease_id,
                "state": "REVOKED",
                "counters": counters,
            }

    def binding(self) -> dict[str, Any]:
        """What the guard believes it is armed for. The runner compares this with the lease."""

        with self.lock:
            return {
                "schema_version": GUARD_SCHEMA,
                "armed": self.is_armed(),
                "mode": self.mode,
                "execution_id": self.execution_id,
                "lease_id": self.lease_id,
                "lease_expires_at": self.lease_expires_at,
                "projection_digest": self.projection_digest,
                "allowlist_digest": self.allowlist_digest,
                "origin": self.origin,
                "max_requests": self.max_requests,
                "lease_revoked": self.lease_revoked,
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
            if (
                not _TOKEN.fullmatch(token)
                or self.token is None
                or not secrets.compare_digest(token, self.token)
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
                # A stop-side revocation is durable evidence: disarming the (already dead) run
                # must not erase the fact that this lease was revoked before the kill. The next
                # arm calls _reset() and starts clean, so the marker never leaks across runs.
                revoked = self.lease_revoked
                self._reset()
                self.lease_revoked = revoked
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
                or parsed.fragment
                or port is None
                or (parsed.query and self.mode != "ACTIVE")
            ):
                # A query string is only ever allowed in active mode, on the projected parameter.
                return block("MALFORMED_TARGET")
            origin = f"http://{parsed.hostname.lower()}:{port}"
            if origin != self.origin or origin not in self.allowed_origins:
                return block("ORIGIN")
            if not _PATH.fullmatch(parsed.path) or (method, parsed.path) not in self.allowlist:
                return block("PATH")
            if parsed.query and not (
                set(parse_qs(parsed.query, keep_blank_values=True)) <= self.allowed_params
            ):
                # ZAP tried to mutate a parameter other than the projected one.
                return block("PARAM")
            if self.forwarded >= self.max_requests:
                self.budget_exceeded = True
                return block("BUDGET")
            self.forwarded += 1
            self.forwarded_total += 1
            # Traffic is accounted by the bare path; the query (active mode only) is forwarded so
            # ZAP's payload reaches the target, but never widens the per-path/allowlist accounting.
            self.per_path[(method, parsed.path)] += 1
            forward_path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
            return None, (parsed.hostname.lower(), port, forward_path)

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
            # Active-mode forwarding carries ZAP's payload in the query string; only the bare path
            # is ever logged, so a raw attack string is never written to the guard's output.
            logged = path.split("?", 1)[0]
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
                relay = [(k, v) for k, v in response.getheaders() if k.lower() not in _HOP_BY_HOP]
            except TimeoutError:
                state.record_failure(timeout=True)
                self.close_connection = True  # mirror the failure: no response is fabricated
                sys.stderr.write(f"guard UPSTREAM_TIMEOUT method={self.command} path={logged}\n")
                return
            except (http.client.HTTPException, OSError):
                state.record_failure(timeout=False)
                self.close_connection = True
                sys.stderr.write(f"guard UPSTREAM_FAILURE method={self.command} path={logged}\n")
                return
            finally:
                connection.close()
            state.record_response(status)
            sys.stderr.write(
                f"guard FORWARDED method={self.command} path={logged} status={status}\n"
            )
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

        def _authorized(self) -> bool:
            if not state.control_secret:  # in-process legacy fixture only; entrypoint rejects this
                return True
            supplied = self.headers.get("X-Aegis-Guard-Control", "").encode()
            return bool(supplied) and hmac.compare_digest(supplied, state.control_secret)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health":
                self._send(200, {"status": "READY"})
            elif not self._authorized():
                self._send(403, {"error": "CONTROL_UNAUTHORIZED"})
            elif self.path == "/v1/attestation":
                self._send(200, state.attestation())
            elif self.path == "/v1/binding":
                self._send(200, state.binding())
            else:
                self._send(404, {"error": "NOT_FOUND"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path not in {"/v1/arm", "/v1/counters", "/v1/disarm", "/v1/revoke"}:
                self._send(404, {"error": "NOT_FOUND"})
                return
            if not self._authorized():
                self._send(403, {"error": "CONTROL_UNAUTHORIZED"})
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
            elif self.path == "/v1/revoke":
                self._send(*state.revoke(payload))
            else:
                self._send(*state.counters(payload, disarm=self.path == "/v1/disarm"))

    return ControlHandler


_ROUTES = frozenset(
    {
        "/health",
        "/v1/attestation",
        "/v1/binding",
        "/v1/arm",
        "/v1/counters",
        "/v1/disarm",
        "/v1/revoke",
    }
)


def serve(
    state: GuardState, host: str, proxy_port: int, control_port: int
) -> tuple[ThreadingHTTPServer, ThreadingHTTPServer]:
    proxy = ThreadingHTTPServer((host, proxy_port), _proxy_handler(state))
    control = ThreadingHTTPServer((host, control_port), _control_handler(state))
    proxy.daemon_threads = control.daemon_threads = True
    return proxy, control
