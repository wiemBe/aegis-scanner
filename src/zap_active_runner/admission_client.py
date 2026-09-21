"""Runner-supervisor client for the root-owned lease admission component.

The supervisor holds the admission *client credential* but never the lease-signing secret: the
container that hosts the untrusted ZAP engine contains no signing material at all. The credential
is read from the supervisor's environment at boot and removed from ``os.environ`` immediately, and
the ZAP child is started with an environment built from scratch, so the engine cannot present it
even though it shares this container's network namespace.

Standard library only, no proxies, bounded responses, strict validation. Any transport or
validation failure is reported as a typed rejection so the caller fails closed.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from aegis_zap_active.contracts import (
    ADMISSION_SCHEMA,
    MAX_ADMISSION_RESPONSE_BYTES,
    AdmissionStatus,
    RedactedLeaseRecord,
    ZapActiveLeaseStatusResponse,
)

DEFAULT_ADMISSION_URL = "http://zap-active-admission:8095"


@dataclass(frozen=True)
class AdmissionRejected:
    """A bounded refusal label. Never carries token bytes or cryptographic detail."""

    code: str


class AdmissionClient:
    def __init__(self, url: str, client_token: str, *, timeout: float = 4.0) -> None:
        self.url = url.rstrip("/")
        self._client_token = client_token
        self.timeout = timeout
        # An explicit empty ProxyHandler: ambient proxy variables are never honoured.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _call(self, path: str, payload: dict[str, Any] | None) -> tuple[dict[str, Any] | None, str]:
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {"X-Admission-Client": self._client_token}
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(  # noqa: S310 - fixed internal http URL
            f"{self.url}{path}",
            data=data,
            method="POST" if payload is not None else "GET",
            headers=headers,
        )
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                body = response.read(MAX_ADMISSION_RESPONSE_BYTES + 1)
                status = response.status
        except urllib.error.HTTPError as error:
            try:
                problem = json.loads(error.read(MAX_ADMISSION_RESPONSE_BYTES))
            except (ValueError, OSError):
                return None, "LEASE_REGISTRY_UNAVAILABLE"
            code = problem.get("error_code") if isinstance(problem, dict) else None
            return None, code if isinstance(code, str) and len(code) <= 40 else "LEASE_INVALID"
        except (urllib.error.URLError, OSError, ValueError):
            return None, "LEASE_REGISTRY_UNAVAILABLE"
        if status != 200 or len(body) > MAX_ADMISSION_RESPONSE_BYTES:
            return None, "LEASE_REGISTRY_UNAVAILABLE"
        try:
            decoded = json.loads(body)
        except ValueError:
            return None, "LEASE_REGISTRY_UNAVAILABLE"
        if not isinstance(decoded, dict):
            return None, "LEASE_REGISTRY_UNAVAILABLE"
        return decoded, ""

    def _record(
        self, path: str, payload: dict[str, Any]
    ) -> RedactedLeaseRecord | AdmissionRejected:
        decoded, code = self._call(path, payload)
        if decoded is None:
            return AdmissionRejected(code or "LEASE_REGISTRY_UNAVAILABLE")
        decoded.pop("schema_version", None)
        try:
            return RedactedLeaseRecord.model_validate(decoded)
        except ValidationError:
            return AdmissionRejected("LEASE_REGISTRY_UNAVAILABLE")

    def arm(self, lease_token: str) -> RedactedLeaseRecord | AdmissionRejected:
        return self._record("/v1/arm", {"schema_version": ADMISSION_SCHEMA, "token": lease_token})

    def consume(
        self,
        *,
        lease_token: str,
        execution_id: str,
        capability_id: str,
        profile_id: str,
        target_ref: str,
        target_origin: str,
        projection_digest: str,
        allowlist_digest: str,
        manifest_digest: str,
    ) -> RedactedLeaseRecord | AdmissionRejected:
        """Consume the armed lease against facts the RUNNER computed, not facts it was handed."""

        return self._record(
            "/v1/consume",
            {
                "schema_version": ADMISSION_SCHEMA,
                "token": lease_token,
                "execution_id": execution_id,
                "capability_id": capability_id,
                "profile_id": profile_id,
                "target_ref": target_ref,
                "target_origin": target_origin,
                "projection_digest": projection_digest,
                "allowlist_digest": allowlist_digest,
                "manifest_digest": manifest_digest,
            },
        )

    def revoke(
        self, lease_id: str, reason: str = "revoked"
    ) -> RedactedLeaseRecord | AdmissionRejected:
        return self._record(
            "/v1/revoke",
            {"schema_version": ADMISSION_SCHEMA, "lease_id": lease_id, "reason": reason},
        )

    def status(self) -> ZapActiveLeaseStatusResponse:
        decoded, _ = self._call("/v1/status", None)
        if decoded is None:
            return ZapActiveLeaseStatusResponse(admission_reachable=False)
        decoded.pop("schema_version", None)
        decoded.pop("admission_version", None)
        try:
            status = AdmissionStatus.model_validate({"schema_version": ADMISSION_SCHEMA, **decoded})
        except ValidationError:
            return ZapActiveLeaseStatusResponse(admission_reachable=False)
        return ZapActiveLeaseStatusResponse(
            admission_reachable=True,
            state_root_owned=status.state_root_owned,
            armed=status.armed,
            recent=status.recent,
            armed_total=status.armed_total,
            consumed_total=status.consumed_total,
            revoked_total=status.revoked_total,
            rejected_total=status.rejected_total,
            restart_revoked_total=status.restart_revoked_total,
        )

    def reachable(self) -> bool:
        decoded, _ = self._call("/health", None)
        return decoded is not None and decoded.get("status") == "READY"
