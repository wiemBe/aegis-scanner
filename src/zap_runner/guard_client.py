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
    GuardRevokeResponse,
)
from aegis_zap.projection import ProjectedOperation

MAX_GUARD_RESPONSE_BYTES = 16_384
_Model = TypeVar("_Model", bound=BaseModel)


class GuardClient:
    def __init__(self, control_url: str, *, control_secret: str = "", timeout: float = 3.0) -> None:
        self.control_url = control_url.rstrip("/")
        self._control_secret = control_secret
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
            headers={
                **({"Content-Type": "application/json"} if payload is not None else {}),
                **({"X-Aegis-Guard-Control": self._control_secret} if self._control_secret else {}),
            },
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

    def arm_active(
        self,
        *,
        execution_id: str,
        origin: str,
        method: str,
        path: str,
        allowed_params: tuple[str, ...],
        max_requests: int,
        ttl_ms: int,
        lease_id: str,
        lease_expires_at: int,
        projection_digest: str,
        allowlist_digest: str,
    ) -> GuardArmResponse | None:
        """Arm the guard in ACTIVE mode: query mutation on ``allowed_params`` only, a larger
        (still hard-capped) request budget, and the consumed lease's binding.

        The guard echoes the binding back and this method refuses anything that does not match
        exactly, so the runner can never proceed while the two sides disagree about which lease,
        target or projection they are armed for."""

        payload = {
            "schema_version": GUARD_SCHEMA,
            "execution_id": execution_id,
            "origin": origin,
            "allowlist": [{"method": method, "path": path}],
            "max_requests": max_requests,
            "ttl_ms": ttl_ms,
            "mode": "ACTIVE",
            "allowed_query_params": list(allowed_params),
            "lease_id": lease_id,
            "lease_expires_at": lease_expires_at,
            "projection_digest": projection_digest,
            "allowlist_digest": allowlist_digest,
        }
        armed = self._call("/v1/arm", payload, GuardArmResponse)
        if armed is None or armed.execution_id != execution_id:
            return None
        if (
            armed.lease_id != lease_id
            or armed.lease_expires_at != lease_expires_at
            or armed.projection_digest != projection_digest
            or armed.allowlist_digest != allowlist_digest
            or armed.max_requests != max_requests
        ):
            # The guard confirmed a different binding than the one the lease authorized. Fail
            # closed and disarm: no ZAP process is started.
            self.disarm(armed.token)
            return None
        return armed

    def revoke_lease(self, lease_id: str, reason: str = "revoked") -> GuardRevokeResponse | None:
        """Disarm immediately for one lease id. Does not require the arm token (stop must work)."""

        return self._call(
            "/v1/revoke", {"lease_id": lease_id, "reason": reason}, GuardRevokeResponse
        )

    def counters(self, token: str) -> GuardCountersResponse | None:
        return self._call("/v1/counters", {"token": token}, GuardCountersResponse)

    def disarm(self, token: str) -> GuardCountersResponse | None:
        return self._call("/v1/disarm", {"token": token}, GuardCountersResponse)
