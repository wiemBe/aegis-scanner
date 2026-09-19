"""Minimal, strict HTTP RPC server for the zap-runner (standard library only).

Endpoints (nothing else is served):

- ``GET  /health``          readiness only (``200`` READY / ``503`` NOT_READY);
- ``GET  /v1/attestation``  typed :class:`ZapRunnerAttestation`;
- ``POST /v1/run``          typed :class:`ZapRunRequest` -> :class:`ZapRunResponse`.

Requests are size-bounded and must be ``application/json``; the body is validated strictly. No
request data is logged, and no exception text is ever returned.
"""

from __future__ import annotations

import json
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from pydantic import ValidationError

from aegis_zap.contracts import (
    MAX_RPC_REQUEST_BYTES,
    RPC_SCHEMA,
    ZapRunnerErrorCode,
    ZapRunRequest,
)
from zap_runner.execution import Executor

_ROUTES = frozenset({"/health", "/v1/attestation", "/v1/run"})


def make_handler(executor: Executor) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "aegis-zap-runner"
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            route = self.path if self.path in _ROUTES else "-"
            status = args[1] if len(args) > 1 else "-"
            sys.stderr.write(f"runner-rpc {self.command} {route} {status}\n")

        def _send(self, status: int, payload: dict[str, object] | str) -> None:
            body = (payload if isinstance(payload, str) else json.dumps(payload)).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _error(self, status: int, code: ZapRunnerErrorCode) -> None:
            self._send(
                status, {"schema_version": RPC_SCHEMA, "status": "REJECTED", "error_code": code}
            )

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health":
                ready = executor.state.ready
                self._send(200 if ready else 503, {"status": "READY" if ready else "NOT_READY"})
            elif self.path == "/v1/attestation":
                self._send(200, executor.state.attestation().model_dump_json())
            else:
                self._error(HTTPStatus.NOT_FOUND, ZapRunnerErrorCode.INVALID_REQUEST)

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/v1/run":
                self._error(HTTPStatus.NOT_FOUND, ZapRunnerErrorCode.INVALID_REQUEST)
                return
            if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                self._error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, ZapRunnerErrorCode.INVALID_REQUEST)
                return
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._error(HTTPStatus.LENGTH_REQUIRED, ZapRunnerErrorCode.INVALID_REQUEST)
                return
            if length <= 0 or length > MAX_RPC_REQUEST_BYTES:
                self._error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, ZapRunnerErrorCode.INVALID_REQUEST)
                return
            raw = self.rfile.read(length)
            try:
                request = ZapRunRequest.model_validate_json(raw)
            except ValidationError:
                executor.state.rejections_total += 1
                self._error(HTTPStatus.BAD_REQUEST, ZapRunnerErrorCode.INVALID_REQUEST)
                return
            try:
                response = executor.run(request)
            except Exception:
                # Never drop the connection with a traceback: a typed refusal fails closed at the
                # controller (it is not a COMPLETED response, so it can never become PASS).
                self._error(HTTPStatus.INTERNAL_SERVER_ERROR, ZapRunnerErrorCode.SPAWN_FAILED)
                return
            self._send(200, response.model_dump_json())

        def _method_not_allowed(self) -> None:
            self._error(HTTPStatus.METHOD_NOT_ALLOWED, ZapRunnerErrorCode.INVALID_REQUEST)

        do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = _method_not_allowed  # noqa: N815

    return Handler


def serve(executor: Executor, host: str, port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), make_handler(executor))
    server.daemon_threads = True
    return server
