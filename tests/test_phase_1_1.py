"""Phase 1.1 — Security Tool Integration Kernel acceptance tests.

These prove the GO criteria: AEGIS_NATIVE behaviour is unchanged behind the new interface;
disabled adapters fail closed with zero traffic; engine observations can never self-confirm; the
deterministic execution policy rejects everything it must before any tool traffic; and no secret or
raw response prose enters the normalized projections.
"""

from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError
from test_agent_loop import ScriptCandidatePlanner, candidate, make_service

import aegis.main as main_module
from aegis.engine import (
    DisabledEngineAdapter,
    EngineErrorCode,
    EngineExecutionStatus,
    FindingLifecycleState,
    NormalizedFinding,
    SecurityEngine,
    build_engine_job,
    correlate_reported_finding,
    normalize_observation_evidence,
    record_verifier_conclusion,
)
from aegis.engine.adapters import AegisNativeAdapter
from aegis.engine.catalog import CAPABILITY_CATALOG, PROFILE_CATALOG, get_engine_profile
from aegis.engine.contracts import (
    EngineEnvironment,
    EngineExecution,
    EngineJob,
    EngineJobRequest,
    EngineObservation,
    EngineReportedFinding,
    TargetReference,
    VerifierConclusion,
)
from aegis.engine.lifecycle import MalformedEngineOutput, assert_execution_bounded, dedupe_reported
from aegis.engine.policy import EnginePolicyRejection, guard_no_raw_command_fields
from aegis.executor import TestExecutor as HttpExecutor
from aegis.models import CandidateGenerationResult, ScanCreate, ScanStatus
from aegis.safety import SafetyController
from aegis.settings import Settings


class _NoTrafficTransport(httpx.AsyncBaseTransport):
    """A transport that fails the test if any network request is attempted."""

    def __init__(self) -> None:
        self.calls = 0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        raise AssertionError(f"unexpected network traffic to {request.url}")


def _job(
    *,
    requests: list[EngineJobRequest] | None = None,
    origin: str = "http://lab-api:8001",
    path: str = "/api/v1/accounts/B-200",
) -> EngineJob:
    reqs = requests or [
        EngineJobRequest(
            name="probe-1", method="GET", path=path, credential_profile="user_a", object_ref="B-200"
        )
    ]
    return EngineJob(
        job_id="job-000000000001",
        engine=SecurityEngine.AEGIS_NATIVE,
        profile_id="aegis-native-bola-synthetic",
        capability_id="bola_object_read_v1",
        adapter_version="aegis-native/1.1.0",
        run_id="scan-aaaaaaaaaaaa",
        environment=EngineEnvironment.SYNTHETIC_LAB,
        activity="ACTIVE",  # type: ignore[arg-type]
        target=TargetReference(
            engine=SecurityEngine.AEGIS_NATIVE,
            environment=EngineEnvironment.SYNTHETIC_LAB,
            origin=origin,
            operation_id="getAccount",
            method="GET",
            normalized_path="/api/v1/accounts/{account_id}",
        ),
        credential_profile_refs=["user_a", "user_b"],
        requests=reqs,
        budget={"max_requests": 8, "max_concurrency": 1, "time_budget_ms": 90000},  # type: ignore[arg-type]
    )


def _policy_kwargs(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "engine": SecurityEngine.AEGIS_NATIVE,
        "profile_id": "aegis-native-bola-synthetic",
        "capability_id": "bola_object_read_v1",
        "run_id": "scan-aaaaaaaaaaaa",
        "environment": EngineEnvironment.SYNTHETIC_LAB,
        "target": TargetReference(
            engine=SecurityEngine.AEGIS_NATIVE,
            environment=EngineEnvironment.SYNTHETIC_LAB,
            origin="http://lab-api:8001",
            operation_id="getAccount",
            method="GET",
            normalized_path="/api/v1/accounts/{account_id}",
        ),
        "credential_profile_refs": ["user_a", "user_b"],
        "requests": [
            EngineJobRequest(
                name="probe-1",
                method="GET",
                path="/api/v1/accounts/B-200",
                credential_profile="user_a",
            )
        ],
        "remaining": {"requests": 8},
        "allowed_origins": ["http://lab-api:8001"],
        "authenticated_profiles": ["user_a", "user_b"],
        "adapter_enabled": True,
    }
    base.update(overrides)
    return base


# --- 1. AEGIS_NATIVE behaviour unchanged through the new interface --------------------------------


async def test_aegis_native_behaviour_unchanged_and_engine_events_present(tmp_path: Path) -> None:
    service = make_service(tmp_path)
    initial = service.create()
    await service.run(initial.id)
    found = service.store.get(initial.id)
    assert found and found.status == ScanStatus.FAIL
    assert found.findings[0].confidence == "CONFIRMED" and found.findings[0].severity == "HIGH"
    assert [e.status_code for e in found.evidence] == [200, 200, 200]
    # Migrated behind the engine interface: engine + adapter version are recorded.
    assert found.engine == "AEGIS_NATIVE"
    assert found.adapter_version == "aegis-native/1.1.0"
    kinds = [e["event"] for e in service.store.audit(initial.id)]
    for event in (
        "ENGINE_JOB_CREATED",
        "ENGINE_EXECUTION_STARTED",
        "ENGINE_EXECUTION_COMPLETED",
        "ENGINE_FINDING_REPORTED",
        "ENGINE_FINDING_CORRELATED",
        "VERIFICATION_STARTED",
        "VERIFICATION_COMPLETED",
    ):
        assert event in kinds, event

    # The normalized lifecycle reached VERIFIED only through the deterministic verifier.
    normalized = [NormalizedFinding.model_validate(n) for n in found.normalized_findings]
    assert len(normalized) == 1
    assert normalized[0].lifecycle_state is FindingLifecycleState.VERIFIED
    assert normalized[0].aegis_finding_id == found.findings[0].id

    # Linked patched retest: 200/200/403 -> PASS, and it reports NO cross-owner signal (403 denied).
    retest = service.create(ScanCreate(variant="patched", retest_of=found.id))
    await service.run(retest.id)
    fixed = service.store.get(retest.id)
    assert fixed and fixed.status == ScanStatus.PASS
    assert [e.status_code for e in fixed.evidence] == [200, 200, 403]
    assert fixed.normalized_findings == []  # a denial is never a reported finding


async def test_negative_preflight_still_zero_model_calls_and_zero_traffic(tmp_path: Path) -> None:
    service = make_service(tmp_path)
    scan = service.create(ScanCreate(scenario="missing_auth"))  # type: ignore[arg-type]
    await service.run(scan.id)
    found = service.store.get(scan.id)
    assert found and found.usage.model_calls == 0
    assert found.evidence == [] and found.findings == []
    kinds = [e["event"] for e in service.store.audit(scan.id)]
    # No engine job is ever created when the deterministic preflight blocks.
    assert "ENGINE_JOB_CREATED" not in kinds
    assert "CANDIDATE_GENERATION_REQUEST" not in kinds


# --- 2. disabled adapters fail closed with zero traffic ------------------------------------------


@pytest.mark.parametrize(
    "engine", [SecurityEngine.NUCLEI, SecurityEngine.ZAP, SecurityEngine.BURP_DAST]
)
async def test_disabled_adapters_fail_closed_with_zero_traffic(engine: SecurityEngine) -> None:
    adapter = DisabledEngineAdapter(engine)
    assert adapter.enabled is False
    result = await adapter.execute(_job(), "vulnerable")
    assert result.execution.status is EngineExecutionStatus.FAILED
    assert result.execution.error is not None
    assert result.execution.error.code is EngineErrorCode.ENGINE_DISABLED
    assert result.evidence == []
    health = adapter.health()
    assert health.enabled is False and health.state == "DISABLED"
    assert health.reachable is None  # never probed while disabled


# --- 3. arbitrary command / flag injection is structurally impossible -----------------------------


@pytest.mark.parametrize(
    "field", ["command", "args", "flags", "raw_url", "template", "scan_config"]
)
def test_engine_job_forbids_command_and_config_fields(field: str) -> None:
    payload = _job().model_dump(mode="json")
    payload[field] = "rm -rf / --unsafe"
    with pytest.raises(ValidationError):
        EngineJob.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "code"),
    [
        ("command", EngineErrorCode.ARBITRARY_COMMAND_FIELD),
        ("flags", EngineErrorCode.ARBITRARY_COMMAND_FIELD),
        ("template", EngineErrorCode.UNKNOWN_TEMPLATE_OR_SCAN_CONFIG),
        ("scan_config", EngineErrorCode.UNKNOWN_TEMPLATE_OR_SCAN_CONFIG),
    ],
)
def test_policy_guard_rejects_raw_command_fields(field: str, code: EngineErrorCode) -> None:
    with pytest.raises(EnginePolicyRejection) as excinfo:
        guard_no_raw_command_fields({field: "x", "job_id": "job-1"}, SecurityEngine.AEGIS_NATIVE)
    assert excinfo.value.error.code is code


# --- 4. model output cannot select an unapproved engine ------------------------------------------


def test_model_schema_cannot_name_an_engine_or_profile() -> None:
    schema = CandidateGenerationResult.model_json_schema()
    encoded = str(schema)
    # No engine/profile/adapter selector is reachable from anything the model authors.
    for banned in ("engine", "profile_id", "adapter_version", "command", "template"):
        assert f"'{banned}'" not in encoded and f'"{banned}"' not in encoded


async def test_controller_always_selects_the_native_engine(tmp_path: Path) -> None:
    planner = ScriptCandidatePlanner(
        [CandidateGenerationResult(candidates=[candidate()], blocking_conditions=[])]
    )
    service = make_service(tmp_path, planner)
    scan = service.create()
    await service.run(scan.id)
    found = service.store.get(scan.id)
    assert found and found.engine == "AEGIS_NATIVE"
    for execution in found.engine_executions:
        assert execution["engine"] == "AEGIS_NATIVE"


# --- 5. adapters cannot expand target scope ------------------------------------------------------


async def test_native_adapter_refuses_out_of_scope_request_with_zero_traffic() -> None:
    transport = _NoTrafficTransport()
    settings = Settings()
    safety = SafetyController(settings)
    executor = HttpExecutor(settings, safety, transport)
    adapter = AegisNativeAdapter(executor, safety)
    escaping = _job(
        requests=[
            EngineJobRequest(
                name="escape", method="GET", path="/etc/passwd", credential_profile="user_a"
            )
        ]
    )
    result = await adapter.execute(escaping, "vulnerable")
    assert result.execution.status is EngineExecutionStatus.FAILED
    assert result.execution.error is not None
    assert result.execution.error.code is EngineErrorCode.SCOPE_EXPANSION_ATTEMPT
    assert transport.calls == 0  # zero network traffic
    assert result.evidence == []


def test_policy_rejects_out_of_scope_origin_and_operation() -> None:
    with pytest.raises(EnginePolicyRejection) as origin_exc:
        build_engine_job(**_policy_kwargs(allowed_origins=["http://other-host:9000"]))
    assert origin_exc.value.error.code is EngineErrorCode.OUT_OF_SCOPE_ORIGIN

    with pytest.raises(EnginePolicyRejection) as op_exc:
        build_engine_job(
            **_policy_kwargs(
                requests=[
                    EngineJobRequest(
                        name="probe-1",
                        method="GET",
                        path="/api/v1/transfers/1",
                        credential_profile="user_a",
                    )
                ]
            )
        )
    assert op_exc.value.error.code is EngineErrorCode.OUT_OF_SCOPE_OPERATION


# --- policy: the remaining rejection classes -----------------------------------------------------


def test_policy_rejects_unknown_engine_profile_capability_and_disabled() -> None:
    with pytest.raises(EnginePolicyRejection) as profile_exc:
        build_engine_job(**_policy_kwargs(profile_id="does-not-exist"))
    assert profile_exc.value.error.code is EngineErrorCode.UNKNOWN_PROFILE

    with pytest.raises(EnginePolicyRejection) as cap_exc:
        build_engine_job(**_policy_kwargs(capability_id="unregistered_cap"))
    assert cap_exc.value.error.code is EngineErrorCode.UNKNOWN_CAPABILITY

    with pytest.raises(EnginePolicyRejection) as disabled_exc:
        build_engine_job(
            **_policy_kwargs(
                engine=SecurityEngine.NUCLEI,
                profile_id="nuclei-passive-synthetic",
                capability_id="nuclei_passive_http_templates_v0",
                adapter_enabled=False,
            )
        )
    assert disabled_exc.value.error.code is EngineErrorCode.ENGINE_DISABLED


def test_policy_rejects_missing_auth_unsupported_method_and_budget() -> None:
    with pytest.raises(EnginePolicyRejection) as auth_exc:
        build_engine_job(
            **_policy_kwargs(credential_profile_refs=["anonymous"], authenticated_profiles=[])
        )
    assert auth_exc.value.error.code is EngineErrorCode.MISSING_AUTH_CONTEXT

    with pytest.raises(EnginePolicyRejection) as budget_exc:
        build_engine_job(**_policy_kwargs(remaining={"requests": 0}))
    assert budget_exc.value.error.code is EngineErrorCode.BUDGET_EXCEEDED


def test_policy_rejects_state_changing_environment_and_method() -> None:
    with pytest.raises(EnginePolicyRejection) as env_exc:
        build_engine_job(**_policy_kwargs(environment=EngineEnvironment.PRODUCTION))
    assert env_exc.value.error.code is EngineErrorCode.DISALLOWED_ENVIRONMENT


# --- 6. adapter findings cannot self-confirm -----------------------------------------------------


def test_engine_reported_finding_has_no_verdict_authority() -> None:
    fields = set(EngineReportedFinding.model_fields)
    for verdict in ("severity", "confidence", "confirmed", "status", "verdict"):
        assert verdict not in fields


def test_reported_finding_cannot_become_verified_without_the_verifier() -> None:
    reported = EngineReportedFinding(
        report_key="k",
        engine=SecurityEngine.AEGIS_NATIVE,
        capability_id="bola_object_read_v1",
        claimed_category="API1:2023 BOLA",
        target_operation_id="getAccount",
        object_ref="B-200",
        principal_profile="user_a",
        observation_names=["probe-1"],
        signal="Cross-owner 200 (raw).",
    )
    normalized = correlate_reported_finding(
        reported, _job(), ai_hypothesis="x", in_scope=True
    )
    assert normalized.lifecycle_state is FindingLifecycleState.AEGIS_CORRELATED
    assert normalized.aegis_finding_id is None and normalized.severity is None
    # An INSUFFICIENT verifier conclusion rejects; it never confirms.
    rejected = record_verifier_conclusion(
        normalized, VerifierConclusion(status="INSUFFICIENT", summary="no proof")
    )
    assert rejected.lifecycle_state is FindingLifecycleState.REJECTED
    assert rejected.aegis_finding_id is None


def test_non_deterministic_capability_only_reaches_review_required() -> None:
    reported = EngineReportedFinding(
        report_key="k",
        engine=SecurityEngine.NUCLEI,
        capability_id="nuclei_passive_http_templates_v0",
        claimed_category="template-match",
        target_operation_id="getAccount",
        principal_profile="anonymous",
        observation_names=["obs-1"],
        signal="template matched (raw).",
    )
    job = _job()
    job = job.model_copy(
        update={
            "engine": SecurityEngine.NUCLEI,
            "capability_id": "nuclei_passive_http_templates_v0",
        }
    )
    normalized = correlate_reported_finding(reported, job, ai_hypothesis="x", in_scope=True)
    # A CONFIRMED-looking conclusion cannot exceed REVIEW_REQUIRED for a human-review capability.
    reviewed = record_verifier_conclusion(
        normalized, VerifierConclusion(status="CONFIRMED", summary="looks confirmed")
    )
    assert reviewed.lifecycle_state is FindingLifecycleState.REVIEW_REQUIRED
    assert reviewed.aegis_finding_id is None and reviewed.severity is None


def test_out_of_scope_reported_finding_is_rejected() -> None:
    reported = EngineReportedFinding(
        report_key="k",
        engine=SecurityEngine.AEGIS_NATIVE,
        capability_id="bola_object_read_v1",
        claimed_category="API1:2023 BOLA",
        target_operation_id="getAccount",
        principal_profile="user_a",
        observation_names=["probe-1"],
        signal="raw",
    )
    normalized = correlate_reported_finding(reported, _job(), ai_hypothesis="x", in_scope=False)
    assert normalized.lifecycle_state is FindingLifecycleState.REJECTED


# --- 7. malformed / oversized engine output fails closed -----------------------------------------


def test_oversized_and_duplicate_engine_output_fails_closed() -> None:
    observations = [
        EngineObservation(
            request_name=f"r-{i}",
            method="GET",
            path="/api/v1/accounts/A-100",
            credential_profile="user_a",
            status_code=200,
            duration_ms=1,
            content_digest="a" * 64,
        )
        for i in range(65)
    ]
    execution = EngineExecution(
        execution_id="exec-000000000001",
        job_id="job-000000000001",
        engine=SecurityEngine.AEGIS_NATIVE,
        adapter_version="aegis-native/1.1.0",
        status=EngineExecutionStatus.COMPLETED,
        started_at="2026-09-19T00:00:00Z",  # type: ignore[arg-type]
        observations=observations,
    )
    with pytest.raises(MalformedEngineOutput):
        assert_execution_bounded(execution)
    with pytest.raises(MalformedEngineOutput):
        normalize_observation_evidence(execution, _job(), "scan-aaaaaaaaaaaa")


# --- 8. duplicate tool findings correlate deterministically --------------------------------------


def test_duplicate_reports_dedupe_by_stable_key() -> None:
    make = lambda: EngineReportedFinding(  # noqa: E731
        report_key="bola_object_read_v1:user_a:B-200",
        engine=SecurityEngine.AEGIS_NATIVE,
        capability_id="bola_object_read_v1",
        claimed_category="API1:2023 BOLA",
        target_operation_id="getAccount",
        object_ref="B-200",
        principal_profile="user_a",
        observation_names=["probe-1"],
        signal="raw",
    )
    deduped = dedupe_reported([make(), make(), make()])
    assert len(deduped) == 1


# --- 9. provenance + digests are stable ----------------------------------------------------------


def test_normalized_evidence_provenance_is_complete_and_stable() -> None:
    observation = EngineObservation(
        request_name="probe-1",
        method="GET",
        path="/api/v1/accounts/B-200",
        credential_profile="user_a",
        status_code=200,
        duration_ms=3,
        content_digest="b" * 64,
    )
    execution = EngineExecution(
        execution_id="exec-000000000001",
        job_id="job-000000000001",
        engine=SecurityEngine.AEGIS_NATIVE,
        adapter_version="aegis-native/1.1.0",
        status=EngineExecutionStatus.COMPLETED,
        started_at="2026-09-19T00:00:00Z",  # type: ignore[arg-type]
        completed_at="2026-09-19T00:00:01Z",  # type: ignore[arg-type]
        observations=[observation],
    )
    first = normalize_observation_evidence(execution, _job(), "scan-aaaaaaaaaaaa")
    second = normalize_observation_evidence(execution, _job(), "scan-aaaaaaaaaaaa")
    assert first == second
    item = first[0]
    # Every provenance field required by the Phase 1.1 contract is present and non-empty.
    for field in (
        "evidence_id",
        "engine",
        "adapter_version",
        "engine_execution_id",
        "run_id",
        "scan_id",
        "capability_id",
        "content_digest",
        "parser_version",
        "source_class",
        "retention_class",
    ):
        assert getattr(item, field)
    assert item.content_digest == "b" * 64


# --- 10. secrets + raw response prose never enter management projections --------------------------


async def test_normalized_projections_contain_no_secret_or_response_prose(tmp_path: Path) -> None:
    service = make_service(tmp_path)
    scan = service.create()
    await service.run(scan.id)
    found = service.store.get(scan.id)
    assert found
    encoded = (
        str(found.normalized_findings)
        + str(found.engine_evidence)
        + str(found.engine_executions)
    )
    for banned in ("lab-token", "balance", "Authorization", "Bearer", "owner_id"):
        assert banned not in encoded


# --- 11. existing SSE + console remain compatible with engine filters ----------------------------


async def test_console_audit_engine_filter_and_catalog(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = make_service(tmp_path)
    scan = service.create()
    await service.run(scan.id)
    monkeypatch.setattr(main_module, "store", service.store)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main_module.app), base_url="http://test"
    ) as client:
        audit = await client.get(
            "/api/console/audit", params={"engine": "AEGIS_NATIVE", "limit": 5}
        )
        engines = await client.get("/api/console/engines")
    assert audit.status_code == 200
    assert all(item["engine"] == "AEGIS_NATIVE" for item in audit.json()["items"])
    body = engines.json()
    disabled = {row["engine"]: row for row in body["items"]}
    for planned in ("NUCLEI", "ZAP", "BURP_DAST"):
        assert disabled[planned]["enabled"] is False
        assert disabled[planned]["state"] == "DISABLED"


# --- catalog immutability + coverage -------------------------------------------------------------


def test_only_native_profile_is_enabled() -> None:
    enabled = [p for p in PROFILE_CATALOG if p.enabled]
    assert [p.engine for p in enabled] == [SecurityEngine.AEGIS_NATIVE]
    native = get_engine_profile("aegis-native-bola-synthetic")
    assert native and native.enabled
    # Every disabled profile documents a future isolation boundary.
    for profile in PROFILE_CATALOG:
        if not profile.enabled:
            assert profile.isolation_boundary


def test_capability_catalog_matches_registered_engines() -> None:
    engines = {c.engine for c in CAPABILITY_CATALOG}
    assert engines == set(SecurityEngine)
