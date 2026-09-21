"""Minimal, strict HTTP RPC server for the active zap-runner (standard library only).

Endpoints (nothing else is served):

- ``GET  /health``          readiness only (``200`` READY / ``503`` NOT_READY);
- ``GET  /v1/attestation``  typed :class:`ZapActiveRunnerAttestation`;
- ``POST /v1/run``          typed :class:`ZapActiveRunRequest` -> :class:`ZapActiveRunResponse`;
- ``POST /v1/lease/arm``    admit one controller-signed lease into the root-owned registry;
- ``POST /v1/lease/revoke`` terminal revoke (also disarms the guard for that lease);
- ``GET  /v1/lease/status`` redacted lease status — never a token, a signature or a nonce;
- ``POST /v1/emergency-stop``  the kill switch: revoke, disarm, kill, mark STOPPED, keep evidence.

Arming is separate from running on purpose. A signature proves the controller issued the lease; it
cannot prove the lease is still live, unused and un-revoked. Only a lease that is *armed here* can
be consumed, so a valid token alone never executes anything.

Requests are size-bounded and must be ``application/json``; the body is validated strictly. No
request data is logged, and no exception text is ever returned.
"""

from __future__ import annotations

import hmac
import json
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from pydantic import ValidationError

from aegis_zap_active.contracts import (
    MAX_RPC_REQUEST_BYTES,
    RPC_SCHEMA,
    ZapActiveErrorCode,
    ZapActiveLeaseArmRequest,
    ZapActiveLeaseRevokeRequest,
    ZapActiveRunRequest,
)
from zap_active_runner.execution import Executor

_ROUTES = frozenset(
    {
        "/health",
        "/v1/attestation",
        "/v1/run",
        "/v1/lease/arm",
        "/v1/lease/revoke",
        "/v1/lease/status",
        "/v1/emergency-stop",
    }
)
_POST_ROUTES = frozenset({"/v1/run", "/v1/lease/arm", "/v1/lease/revoke", "/v1/emergency-stop"})


def make_handler(executor: Executor, client_token: bytes = b"") -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "aegis-zap-active-runner"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            route = self.path if self.path in _ROUTES else "-"
            status = args[1] if len(args) > 1 else "-"
            sys.stderr.write(f"active-runner-rpc {self.command} {route} {status}\n")

        def _send(self, status: int, payload: dict[str, object] | str) -> None:
            body = (payload if isinstance(payload, str) else json.dumps(payload)).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _error(self, status: int, code: ZapActiveErrorCode) -> None:
            self._send(
                status, {"schema_version": RPC_SCHEMA, "status": "REJECTED", "error_code": code}
            )

        def _authorized(self) -> bool:
            # Empty is permitted only by in-process fixtures. The production entrypoint refuses it.
            if not client_token:
                return True
            supplied = self.headers.get("X-Aegis-Active-Runner-Client", "").encode()
            return bool(supplied) and hmac.compare_digest(supplied, client_token)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health":
                ready = executor.state.ready
                self._send(200 if ready else 503, {"status": "READY" if ready else "NOT_READY"})
            elif not self._authorized():
                self._error(HTTPStatus.FORBIDDEN, ZapActiveErrorCode.INVALID_REQUEST)
            elif self.path == "/v1/attestation":
                self._send(200, executor.state.attestation().model_dump_json())
            elif self.path == "/v1/lease/status":
                self._send(200, executor.lease_status().model_dump_json())
            else:
                self._error(HTTPStatus.NOT_FOUND, ZapActiveErrorCode.INVALID_REQUEST)

        def _body(self) -> bytes | None:
            if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                self._error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, ZapActiveErrorCode.INVALID_REQUEST)
                return None
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._error(HTTPStatus.LENGTH_REQUIRED, ZapActiveErrorCode.INVALID_REQUEST)
                return None
            if length <= 0 or length > MAX_RPC_REQUEST_BYTES:
                self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, ZapActiveErrorCode.INVALID_REQUEST)
                return None
            return self.rfile.read(length)

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/health" and not self._authorized():
                self._error(HTTPStatus.FORBIDDEN, ZapActiveErrorCode.INVALID_REQUEST)
                return
            if self.path == "/v1/emergency-stop":
                steps = executor.emergency_stop()
                self._send(
                    200, {"schema_version": RPC_SCHEMA, "status": "STOPPING", "steps": steps}
                )
                return
            if self.path not in _POST_ROUTES:
                self._error(HTTPStatus.NOT_FOUND, ZapActiveErrorCode.INVALID_REQUEST)
                return
            raw = self._body()
            if raw is None:
                return
            if self.path == "/v1/lease/arm":
                self._lease_arm(raw)
                return
            if self.path == "/v1/lease/revoke":
                self._lease_revoke(raw)
                return
            try:
                request = ZapActiveRunRequest.model_validate_json(raw)
            except ValidationError:
                executor.state.rejections_total += 1
                self._error(HTTPStatus.BAD_REQUEST, ZapActiveErrorCode.INVALID_REQUEST)
                return
            try:
                response = executor.run(request)
            except Exception:
                self._error(HTTPStatus.INTERNAL_SERVER_ERROR, ZapActiveErrorCode.SPAWN_FAILED)
                return
            self._send(200, response.model_dump_json())

        def _lease_arm(self, raw: bytes) -> None:
            try:
                armed = ZapActiveLeaseArmRequest.model_validate_json(raw)
            except ValidationError:
                # A token that is not even shaped like one never reaches the admission component.
                executor.state.rejections_total += 1
                self._error(HTTPStatus.BAD_REQUEST, ZapActiveErrorCode.LEASE_MALFORMED)
                return
            outcome = executor.arm_lease(armed.lease_token)
            if isinstance(outcome, ZapActiveErrorCode):
                executor.state.rejections_total += 1
                self._error(HTTPStatus.FORBIDDEN, outcome)
                return
            self._send(200, outcome.model_dump_json())

        def _lease_revoke(self, raw: bytes) -> None:
            try:
                revoke = ZapActiveLeaseRevokeRequest.model_validate_json(raw)
            except ValidationError:
                self._error(HTTPStatus.BAD_REQUEST, ZapActiveErrorCode.INVALID_REQUEST)
                return
            record = executor.revoke_lease(revoke.lease_id, revoke.reason)
            if record is None:
                self._error(HTTPStatus.NOT_FOUND, ZapActiveErrorCode.LEASE_NOT_ARMED)
                return
            self._send(200, record.model_dump_json())

        def _method_not_allowed(self) -> None:
            self._error(HTTPStatus.METHOD_NOT_ALLOWED, ZapActiveErrorCode.INVALID_REQUEST)

        do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = _method_not_allowed  # noqa: N815

    return Handler


def serve(
    executor: Executor, host: str, port: int, client_token: bytes = b""
) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), make_handler(executor, client_token))
    server.daemon_threads = True
    return server
