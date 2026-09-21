"""Minimal, strict HTTP server for the lease admission component (standard library only).

Endpoints (nothing else is served):

- ``GET  /health``        readiness only;
- ``GET  /v1/status``     redacted registry projection;
- ``POST /v1/arm``        admit one signed lease;
- ``POST /v1/consume``    atomically consume the armed lease for one execution;
- ``POST /v1/revoke``     terminal revoke.

Every mutating call requires the runner supervisor's client credential in ``X-Admission-Client``,
compared in constant time. The credential is given to the runner *supervisor* process only; the ZAP
child is started with an environment constructed from scratch, so the engine has no way to obtain
it even though it shares the runner's network namespace. Nothing here logs a token, a credential,
a claim value or an exception message.
"""

from __future__ import annotations

import hmac
import json
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from pydantic import ValidationError

from aegis_zap_active.lease import LeaseRejected
from zap_active_admission.contracts import (
    ADMISSION_SCHEMA,
    MAX_ADMISSION_REQUEST_BYTES,
    AdmissionStatus,
    ArmRequest,
    ConsumeRequest,
    RevokeRequest,
)
from zap_active_admission.registry import AdmissionRegistry

_ROUTES = frozenset({"/health", "/v1/status", "/v1/arm", "/v1/consume", "/v1/revoke"})


def make_handler(registry: AdmissionRegistry, client_token: bytes) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "aegis-zap-active-admission"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            route = self.path if self.path in _ROUTES else "-"
            status = args[1] if len(args) > 1 else "-"
            sys.stderr.write(f"admission-rpc {self.command} {route} {status}\n")

        def _send(self, status: int, payload: dict[str, object]) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _error(self, status: int, code: str) -> None:
            self._send(
                status,
                {"schema_version": ADMISSION_SCHEMA, "status": "REJECTED", "error_code": code},
            )

        def _authorized(self) -> bool:
            presented = self.headers.get("X-Admission-Client", "")
            return bool(presented) and hmac.compare_digest(presented.encode(), client_token)

        def _read_body(self) -> bytes | None:
            if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                return None
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                return None
            if length <= 0 or length > MAX_ADMISSION_REQUEST_BYTES:
                return None
            return self.rfile.read(length)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health":
                self._send(200, {"status": "READY"})
                return
            if self.path != "/v1/status":
                self._error(HTTPStatus.NOT_FOUND, "UNKNOWN_ROUTE")
                return
            if not self._authorized():
                self._error(HTTPStatus.FORBIDDEN, "ADMISSION_CLIENT_UNAUTHORIZED")
                return
            snapshot = registry.snapshot()
            self._send(200, AdmissionStatus.model_validate(snapshot).model_dump(mode="json"))

        def do_POST(self) -> None:  # noqa: N802
            if self.path not in {"/v1/arm", "/v1/consume", "/v1/revoke"}:
                self._error(HTTPStatus.NOT_FOUND, "UNKNOWN_ROUTE")
                return
            if not self._authorized():
                self._error(HTTPStatus.FORBIDDEN, "ADMISSION_CLIENT_UNAUTHORIZED")
                return
            raw = self._read_body()
            if raw is None:
                self._error(HTTPStatus.FORBIDDEN, "LEASE_AUTHORIZATION_REFUSED")
                return
            try:
                if self.path == "/v1/arm":
                    record = registry.arm(ArmRequest.model_validate_json(raw).token)
                elif self.path == "/v1/consume":
                    record = registry.consume(ConsumeRequest.model_validate_json(raw))
                else:
                    request = RevokeRequest.model_validate_json(raw)
                    revoked = registry.revoke(request.lease_id, request.reason)
                    if revoked is None:
                        self._error(HTTPStatus.NOT_FOUND, "LEASE_NOT_ARMED")
                        return
                    record = revoked
            except ValidationError:
                self._error(HTTPStatus.FORBIDDEN, "LEASE_AUTHORIZATION_REFUSED")
                return
            except LeaseRejected:
                # The admission boundary is intentionally non-oracular. Detailed labels remain
                # in protected in-process telemetry only, never in an RPC response.
                self._error(HTTPStatus.FORBIDDEN, "LEASE_AUTHORIZATION_REFUSED")
                return
            except Exception:  # pragma: no cover - never leak an exception message
                self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "LEASE_REGISTRY_UNAVAILABLE")
                return
            self._send(200, record.model_dump(mode="json"))

        def _method_not_allowed(self) -> None:
            self._error(HTTPStatus.METHOD_NOT_ALLOWED, "UNKNOWN_ROUTE")

        do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = _method_not_allowed  # noqa: N815

    return Handler


def serve(
    registry: AdmissionRegistry, client_token: bytes, host: str, port: int
) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), make_handler(registry, client_token))
    server.daemon_threads = True
    return server
