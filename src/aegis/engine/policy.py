"""Deterministic engine execution policy (Phase 1.1).

The controller builds every :class:`EngineJob` through :func:`build_engine_job`. The job is
constructed ONLY from controller-owned inputs — the approved target inventory, the approved scope,
approved credential-profile references, validated model hypotheses (already reduced to a compiled
read-only request set by :mod:`aegis.candidates`), configured engine profiles and deterministic
budgets.

Every rejection raises :class:`EnginePolicyRejection` carrying a structured :class:`EngineError`.
The controller records that error as an ``ENGINE_JOB_REJECTED`` audit event and issues ZERO tool
traffic: the adapter is never reached. This is the procedural half of "no arbitrary command/flag"
— the structural half is that :class:`EngineJob` has nowhere to put one.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any
from uuid import uuid4

from pydantic import ValidationError

from aegis.engine.catalog import get_engine_capability, get_engine_profile
from aegis.engine.contracts import (
    EngineActivity,
    EngineBudget,
    EngineEnvironment,
    EngineError,
    EngineErrorCode,
    EngineJob,
    EngineJobRequest,
    SecurityEngine,
    TargetReference,
)

# Fields that must never appear on a job payload. If a caller (or a deserialized record, or a
# mis-wired integration) tries to smuggle a raw command line, flag set, template or scan config,
# the policy maps it to a precise, safe error instead of a generic validation failure.
_COMMAND_FIELDS = frozenset({"command", "args", "argv", "cmd", "flags", "shell", "raw_url", "url"})
_CONFIG_FIELDS = frozenset({"template", "templates", "scan_config", "scan_profile", "config"})

READ_ONLY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class EnginePolicyRejection(Exception):
    """Raised when the deterministic policy refuses to build a job. Carries a safe EngineError."""

    def __init__(self, error: EngineError) -> None:
        super().__init__(error.code.value)
        self.error = error


def _reject(
    engine: SecurityEngine, code: EngineErrorCode, detail: str = ""
) -> EnginePolicyRejection:
    return EnginePolicyRejection(EngineError(engine=engine, code=code, detail=detail[:200]))


def guard_no_raw_command_fields(payload: Mapping[str, Any], engine: SecurityEngine) -> None:
    """Fail closed if a payload carries any command/flag/template/scan-config field.

    :class:`EngineJob` already forbids extra properties, so these fields can never live on a real
    job. This guard exists to turn that structural guarantee into a precise, testable rejection when
    a raw payload is offered to the policy."""

    for key in payload:
        lowered = str(key).lower()
        if lowered in _COMMAND_FIELDS:
            raise _reject(engine, EngineErrorCode.ARBITRARY_COMMAND_FIELD, lowered)
        if lowered in _CONFIG_FIELDS:
            raise _reject(engine, EngineErrorCode.UNKNOWN_TEMPLATE_OR_SCAN_CONFIG, lowered)


def _new_job_id() -> str:
    return f"job-{uuid4().hex[:12]}"


def build_engine_job(
    *,
    engine: SecurityEngine,
    profile_id: str,
    capability_id: str,
    run_id: str,
    environment: EngineEnvironment,
    target: TargetReference,
    credential_profile_refs: list[str],
    requests: list[EngineJobRequest],
    remaining: Mapping[str, int],
    allowed_origins: Iterable[str],
    authenticated_profiles: Iterable[str],
    adapter_enabled: bool,
    time_budget_ms: int | None = None,
    concurrency: int = 1,
) -> EngineJob:
    """Construct a validated :class:`EngineJob`, or raise :class:`EnginePolicyRejection`.

    Rejections (each before any adapter/engine invocation):

    * unknown engine / profile / capability
    * disabled adapter (or disabled profile)
    * disallowed environment
    * out-of-scope origin or operation
    * unapproved state-changing behaviour / non-read-only method
    * missing authentication context
    * unsupported method
    * arbitrary command / CLI-flag / unknown template or scan-config fields
    * budget excess
    """

    profile = get_engine_profile(profile_id)
    if profile is None:
        raise _reject(engine, EngineErrorCode.UNKNOWN_PROFILE, profile_id)
    if profile.engine is not engine:
        raise _reject(engine, EngineErrorCode.UNKNOWN_ENGINE, engine.value)

    capability = get_engine_capability(capability_id)
    if capability is None or capability_id not in profile.capability_ids:
        raise _reject(engine, EngineErrorCode.UNKNOWN_CAPABILITY, capability_id)
    if capability.engine is not engine:
        raise _reject(engine, EngineErrorCode.UNKNOWN_CAPABILITY, capability_id)

    if not profile.enabled or not adapter_enabled:
        raise _reject(engine, EngineErrorCode.ENGINE_DISABLED, profile_id)

    if environment not in capability.allowed_environments:
        raise _reject(engine, EngineErrorCode.DISALLOWED_ENVIRONMENT, environment.value)
    if target.environment is not environment:
        raise _reject(engine, EngineErrorCode.DISALLOWED_ENVIRONMENT, target.environment.value)

    origins = {o.rstrip("/") for o in allowed_origins}
    if target.origin.rstrip("/") not in origins:
        raise _reject(engine, EngineErrorCode.OUT_OF_SCOPE_ORIGIN, target.origin)

    # Operation/scope: the target operation must be the capability's operation, and every compiled
    # request path must stay under the target's normalized operation path template's base.
    if target.method not in capability.supported_methods:
        raise _reject(engine, EngineErrorCode.UNSUPPORTED_METHOD, target.method)

    # State-changing behaviour is never approved in Phase 1.1.
    if capability.state_changing_possible:
        raise _reject(engine, EngineErrorCode.UNAPPROVED_STATE_CHANGE, capability_id)
    if target.method not in READ_ONLY_METHODS:
        raise _reject(engine, EngineErrorCode.UNAPPROVED_STATE_CHANGE, target.method)

    # Authentication context.
    authed = {p for p in authenticated_profiles}
    if capability.requires_authentication:
        referenced_auth = {p for p in credential_profile_refs if p != "anonymous"}
        if not referenced_auth or not referenced_auth.issubset(authed):
            raise _reject(engine, EngineErrorCode.MISSING_AUTH_CONTEXT, capability_id)

    # Per-request checks: read-only method, supported method, scope.
    for request in requests:
        if request.method not in READ_ONLY_METHODS:
            raise _reject(engine, EngineErrorCode.UNAPPROVED_STATE_CHANGE, request.method)
        if request.method not in capability.supported_methods:
            raise _reject(engine, EngineErrorCode.UNSUPPORTED_METHOD, request.method)
        if not _path_in_scope(request.path, target.normalized_path):
            raise _reject(engine, EngineErrorCode.OUT_OF_SCOPE_OPERATION, request.path)

    # Budgets.
    remaining_requests = int(remaining.get("requests", 0))
    if len(requests) > remaining_requests:
        raise _reject(engine, EngineErrorCode.BUDGET_EXCEEDED, "requests")
    if len(requests) > capability.request_budget:
        raise _reject(engine, EngineErrorCode.BUDGET_EXCEEDED, "capability_requests")
    effective_time = min(
        capability.time_budget_ms, time_budget_ms or capability.time_budget_ms
    )
    if effective_time < 1:
        raise _reject(engine, EngineErrorCode.BUDGET_EXCEEDED, "time")

    budget = EngineBudget(
        max_requests=min(capability.request_budget, remaining_requests),
        max_concurrency=min(concurrency, capability.concurrency_budget),
        time_budget_ms=effective_time,
    )
    activity = capability.activity if isinstance(capability.activity, EngineActivity) else (
        EngineActivity.ACTIVE
    )

    try:
        return EngineJob(
            job_id=_new_job_id(),
            engine=engine,
            profile_id=profile_id,
            capability_id=capability_id,
            adapter_version=capability.adapter_version,
            run_id=run_id,
            environment=environment,
            activity=activity,
            target=target,
            credential_profile_refs=credential_profile_refs,  # type: ignore[arg-type]
            requests=requests,
            budget=budget,
        )
    except ValidationError as exc:  # pragma: no cover - defensive; inputs are already typed
        raise _reject(engine, EngineErrorCode.MALFORMED_ENGINE_OUTPUT, "job_validation") from exc


def _path_in_scope(request_path: str, target_template: str) -> bool:
    """A compiled request path is in scope iff it shares the target operation's fixed prefix.

    The target's ``normalized_path`` is an operation template such as
    ``/api/v1/accounts/{account_id}``.
    Every compiled request must live under its fixed prefix (``/api/v1/accounts/``), so a request
    can never widen scope to a sibling route."""

    prefix = target_template.split("{", 1)[0].rstrip("/")
    if not prefix:
        return False
    return request_path == prefix or request_path.startswith(prefix + "/")
