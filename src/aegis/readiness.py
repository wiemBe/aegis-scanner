"""Deterministic, fail-closed readiness evaluation for the control plane.

The control plane's ``GET /health`` endpoint is a *liveness* probe: it answers ``200`` as soon as
the process is up. This module adds a distinct *readiness* verdict — the concrete preconditions the
control plane must satisfy before it is safe to route traffic to it — and it fails closed: any check
whose outcome cannot be positively confirmed is treated as ``NOT_READY``.

The evaluation is a pure function over :class:`~aegis.settings.Settings` and the
:class:`~aegis.storage.ScanStore`. It performs no mutation, opens the existing database in
read-write mode without creating it, does no network I/O, and never places a secret (or any
secret-derived value) in its output — only the *presence* of a forbidden credential is checked,
never its value, and check details are fixed strings rather than raw exception text.

The readiness contract mirrors the ``200 READY / 503 NOT_READY`` convention already used by the
isolated runner services (see ``zap_runner.server``), bringing the control plane in line.
"""

from __future__ import annotations

import os
import sqlite3
from enum import Enum
from pathlib import Path
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field

from aegis.settings import OPENROUTER_QWEN_MODEL, Settings
from aegis.storage import ScanStore

READINESS_CONTRACT_VERSION = "readiness-v3"

# Providers that reach a real model endpoint over TLS. The offline ``demo`` provider needs no
# endpoint and is exempt from the endpoint-coherence checks below.
_HTTPS_ENDPOINT_PROVIDERS = frozenset(
    {"internal_openai_compatible", "openai_responses", "deepseek", "openrouter"}
)

# The persisted table/column contracts the control plane requires before it can accept a scan or
# serve the audit trail. Kept in lock-step with ``ScanStore.initialize()``.
REQUIRED_SCHEMA: dict[str, frozenset[str]] = {
    "scans": frozenset({"id", "status", "created_at", "payload"}),
    "audit_events": frozenset({"id", "scan_id", "event", "created_at", "details"}),
    "audit_access_log": frozenset({"id", "request_id", "route", "outcome", "created_at"}),
}


class CheckStatus(str, Enum):
    """A single readiness check outcome. ``UNKNOWN`` is never ready — it fails closed."""

    PASS = "PASS"  # noqa: S105 — a readiness verdict label, not a credential
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


class ReadinessCheck(BaseModel):
    """One deterministic precondition. ``detail`` is a fixed, secret-free description."""

    model_config = ConfigDict(frozen=True)

    name: str
    status: CheckStatus
    required: bool = True
    detail: str


class ReadinessReport(BaseModel):
    """Aggregate readiness verdict. ``ready`` is true only when every required check passed."""

    model_config = ConfigDict(frozen=True)

    contract_version: str = READINESS_CONTRACT_VERSION
    ready: bool
    checks: list[ReadinessCheck] = Field(default_factory=list)


def _check_persistence(database_path: str) -> ReadinessCheck:
    """Confirm the existing scan/audit store is usable at probe time, without mutation.

    ``mode=rw`` proves that SQLite can open the existing file read-write without creating a stray
    database. ``statvfs`` separately rejects a volume with no caller-available blocks. This is a
    point-in-time signal, not a guarantee that a later write cannot race with capacity loss. Any
    state that cannot be positively confirmed resolves to ``UNKNOWN`` (fails closed).
    """

    name = "persistence"
    try:
        path = Path(database_path)
        parent = path.parent
        if not parent.exists() or not os.access(parent, os.W_OK):
            return ReadinessCheck(
                name=name, status=CheckStatus.FAIL, detail="data volume is not writable"
            )
        if not path.exists():
            return ReadinessCheck(
                name=name, status=CheckStatus.FAIL, detail="persistence store is not initialized"
            )
        if not path.is_file():
            return ReadinessCheck(
                name=name,
                status=CheckStatus.FAIL,
                detail="persistence store is not a regular file",
            )
        filesystem = os.statvfs(parent)
        if filesystem.f_bavail <= 0 or filesystem.f_frsize <= 0:
            return ReadinessCheck(
                name=name,
                status=CheckStatus.FAIL,
                detail="data volume has no available capacity",
            )
        database_uri = f"{path.absolute().as_uri()}?mode=rw"
        with sqlite3.connect(database_uri, uri=True, timeout=1.0) as connection:
            connection.execute("PRAGMA query_only = ON")
            rows = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            present: set[str] = {str(row[0]) for row in rows}
            if set(REQUIRED_SCHEMA) - present:
                return ReadinessCheck(
                    name=name, status=CheckStatus.FAIL, detail="persistence schema is incomplete"
                )
            for table, required_columns in REQUIRED_SCHEMA.items():
                columns = {
                    str(row[1])
                    for row in connection.execute(f'PRAGMA table_info("{table}")').fetchall()
                }
                if required_columns - columns:
                    return ReadinessCheck(
                        name=name,
                        status=CheckStatus.FAIL,
                        detail="persistence schema is incomplete",
                    )
        return ReadinessCheck(
            name=name,
            status=CheckStatus.PASS,
            detail="persistence store passed point-in-time availability checks",
        )
    except (sqlite3.Error, OSError, ValueError):
        return ReadinessCheck(
            name=name,
            status=CheckStatus.UNKNOWN,
            detail="persistence state could not be determined",
        )


def _check_credential_isolation(settings: Settings) -> ReadinessCheck:
    """Reassert the core invariant that the control plane holds no provider credential.

    Only credential *presence* is inspected; the secret value is never read. This restates the
    import-time guard in ``main`` as a runtime readiness assertion (defense in depth).
    """

    name = "credential_isolation"
    if (
        settings.ai_auth_token is not None
        or settings.ai_auth_token_file is not None
        or settings.deepseek_api_key is not None
        or settings.openrouter_api_key is not None
        or settings.openrouter_api_key_file is not None
    ):
        return ReadinessCheck(
            name=name,
            status=CheckStatus.FAIL,
            detail="control plane must not hold a provider credential",
        )
    return ReadinessCheck(
        name=name, status=CheckStatus.PASS, detail="no provider credential present on control plane"
    )


def _check_provider_configuration(settings: Settings) -> ReadinessCheck:
    """Reject an incoherent model-provider configuration before any traffic is admitted.

    The control plane is given the non-secret provider selector, model and allowlist (never the
    credential — that stays in the gateway), so it can prove at ``/ready`` time that the deployed
    configuration is internally consistent. Without this a mismatch such as a model absent from the
    exact allowlist, a missing or non-HTTPS endpoint, or an OpenRouter profile that is not pinned to
    the exact model/host would pass readiness and only fail on the first (possibly paid) live call.
    The offline demo provider needs no endpoint and always passes. Any inconsistency fails closed.
    """

    name = "provider_configuration"
    provider = settings.ai_provider
    if provider == "demo":
        return ReadinessCheck(
            name=name,
            status=CheckStatus.PASS,
            detail="offline demo provider requires no model endpoint",
        )

    model = settings.ai_model.strip()
    if not model:
        return ReadinessCheck(
            name=name, status=CheckStatus.FAIL, detail="AI_MODEL is not configured"
        )
    if model not in settings.allowed_model_set:
        return ReadinessCheck(
            name=name,
            status=CheckStatus.FAIL,
            detail="AI_MODEL is not present in the exact AI_ALLOWED_MODELS allowlist",
        )

    if provider in _HTTPS_ENDPOINT_PROVIDERS:
        parsed = urlparse(settings.ai_base_url)
        if parsed.scheme != "https":
            return ReadinessCheck(
                name=name,
                status=CheckStatus.FAIL,
                detail="selected provider requires an https AI_BASE_URL",
            )
        if not parsed.hostname:
            return ReadinessCheck(
                name=name, status=CheckStatus.FAIL, detail="AI_BASE_URL has no host"
            )
        if provider == "openrouter":
            if model != OPENROUTER_QWEN_MODEL:
                return ReadinessCheck(
                    name=name,
                    status=CheckStatus.FAIL,
                    detail="openrouter requires the exact pinned model",
                )
            if settings.allowed_model_set != {OPENROUTER_QWEN_MODEL}:
                return ReadinessCheck(
                    name=name,
                    status=CheckStatus.FAIL,
                    detail="openrouter allowlist must contain only the pinned model",
                )
            if parsed.hostname != "openrouter.ai":
                return ReadinessCheck(
                    name=name,
                    status=CheckStatus.FAIL,
                    detail="openrouter requires AI_BASE_URL host openrouter.ai",
                )

    return ReadinessCheck(
        name=name,
        status=CheckStatus.PASS,
        detail="provider configuration is internally consistent",
    )


def _check_process_lifecycle(process_state: str) -> ReadinessCheck:
    """Ready only while admission is explicitly SERVING."""

    if process_state == "SERVING":
        return ReadinessCheck(
            name="process_lifecycle",
            status=CheckStatus.PASS,
            detail="process is serving and accepting work",
        )
    details = {
        "STARTING": "process is starting and not accepting work",
        "DRAINING": "process is draining and not accepting work",
        "STOPPED": "process is stopped and not accepting work",
    }
    return ReadinessCheck(
        name="process_lifecycle",
        status=CheckStatus.FAIL,
        detail=details.get(process_state, "process lifecycle is unknown and not accepting work"),
    )


def evaluate_readiness(
    settings: Settings, store: ScanStore, *, process_state: str = "SERVING"
) -> ReadinessReport:
    """Deterministically decide whether the control plane is safe to serve.

    Ready only when every *required* check is ``PASS``; any ``FAIL`` or ``UNKNOWN`` — including a
    check that raised — yields ``NOT_READY``. Pure and side-effect free.
    """

    checks = [
        _check_persistence(store.database_path),
        _check_credential_isolation(settings),
        _check_provider_configuration(settings),
        _check_process_lifecycle(process_state),
    ]
    ready = all(check.status is CheckStatus.PASS for check in checks if check.required)
    return ReadinessReport(ready=ready, checks=checks)
