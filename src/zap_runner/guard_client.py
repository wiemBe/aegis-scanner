"""Runner-side client for the scope guard's control port. Standard library only, no proxies.

Every response is size-bounded and strictly validated; any transport or validation failure is
reported as ``None`` so the caller fails closed.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from aegis_zap.contracts import (
    GUARD_SCHEMA,
    GuardArmResponse,
    GuardAttestation,
    GuardCountersResponse,
)
from aegis_zap.projection import ProjectedOperation

MAX_GUARD_RESPONSE_BYTES = 16_384
_Model = TypeVar("_Model", bound=BaseModel)


class GuardClient:
    def __init__(self, control_url: str, *, timeout: float = 3.0) -> None:
        self.control_url = control_url.rstrip("/")
        self.timeout = timeout
        # An explicit empty ProxyHandler: ambient proxy variables are never honoured.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _call(
        self, path: str, payload: dict[str, Any] | None, model: type[_Model]
    ) -> _Model | None:
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(  # noqa: S310 - fixed internal http URL
            f"{self.control_url}{path}",
            data=data,
            method="POST" if payload is not None else "GET",
            headers={"Content-Type": "application/json"} if payload is not None else {},
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                if response.status != 200:
                    return None
                body = response.read(MAX_GUARD_RESPONSE_BYTES + 1)
        except (urllib.error.URLError, OSError, ValueError):
            return None
        if len(body) > MAX_GUARD_RESPONSE_BYTES:
            return None
        try:
            return model.model_validate_json(body, strict=False)
        except ValidationError:
            return None

    def attestation(self) -> GuardAttestation | None:
        return self._call("/v1/attestation", None, GuardAttestation)

    def arm(
        self,
        *,
        execution_id: str,
        origin: str,
        operations: tuple[ProjectedOperation, ...],
        ttl_ms: int,
    ) -> GuardArmResponse | None:
        payload = {
            "schema_version": GUARD_SCHEMA,
            "execution_id": execution_id,
            "origin": origin,
            "allowlist": [{"method": op.method, "path": op.path} for op in operations],
            "max_requests": len(operations),
            "ttl_ms": ttl_ms,
        }
        armed = self._call("/v1/arm", payload, GuardArmResponse)
        if armed is None or armed.execution_id != execution_id:
            return None
        return armed

    def counters(self, token: str) -> GuardCountersResponse | None:
        return self._call("/v1/counters", {"token": token}, GuardCountersResponse)

    def disarm(self, token: str) -> GuardCountersResponse | None:
        return self._call("/v1/disarm", {"token": token}, GuardCountersResponse)
