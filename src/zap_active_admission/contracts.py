"""Compatibility re-export of the runner-side lease admission contracts.

The canonical definitions of these shapes live in
:mod:`aegis_zap_active.contracts` (``AdmissionArmRequest`` / ``AdmissionConsumeRequest`` /
``AdmissionRevokeRequest`` / ``AdmissionStatus`` / ``AdmissionError`` and the admission schema
constants), next to the active RPC contracts both sides of the boundary already depend on. That
placement is deliberate: the runner supervisor needs the same shapes to speak to the admission
component, and it must NOT need to carry the admission package (which holds the signing-secret
authority and its registry) inside its image.

This module re-exports the shared names under the historical short names
(``ArmRequest`` / ``ConsumeRequest`` / ``RevokeRequest``) so the admission server and the offline
tests keep their existing imports.
"""

from __future__ import annotations

from aegis_zap_active.contracts import (
    ADMISSION_SCHEMA,
    ADMISSION_VERSION,
    MAX_ADMISSION_REQUEST_BYTES,
    MAX_ADMISSION_RESPONSE_BYTES,
    AdmissionArmRequest,
    AdmissionConsumeRequest,
    AdmissionError,
    AdmissionRevokeRequest,
    AdmissionStatus,
    LeaseState,
    RedactedLeaseRecord,
)

# The redacted lease record is the controller/runner contract shape; admission reuses it verbatim
# so there is exactly one definition of what may leave the admission boundary.
LeaseRecord = RedactedLeaseRecord

ArmRequest = AdmissionArmRequest
ConsumeRequest = AdmissionConsumeRequest
RevokeRequest = AdmissionRevokeRequest

__all__ = [
    "ADMISSION_SCHEMA",
    "ADMISSION_VERSION",
    "MAX_ADMISSION_REQUEST_BYTES",
    "MAX_ADMISSION_RESPONSE_BYTES",
    "LeaseState",
    "LeaseRecord",
    "ArmRequest",
    "ConsumeRequest",
    "RevokeRequest",
    "AdmissionStatus",
    "AdmissionError",
]
