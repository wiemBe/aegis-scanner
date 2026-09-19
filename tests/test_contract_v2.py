"""Planner Contract V2 tests: discriminated decision union, per-state permitted types, congruent
generation schema with dynamic identifier enums, and the fail-closed guarantees that survive the
V1 -> V2 change. All offline; no network is used.
"""

import hashlib
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError
from test_agent_loop import ScriptPlanner, make_service  # reuse helpers (sibling test module)

from aegis.contract import (
    DECISION_MODELS,
    FULL_DECISION_ADAPTER,
    build_generation_schema,
    permitted_decision_types,
    projected_request_enums,
    state_adapter,
)
from aegis.models import (
    PLANNER_CONTRACT_VERSION,
    ContinueDecision,
    ExecuteDecision,
    HypothesisDecision,
    ReviewDecision,
    ScanResult,
    StopDecision,
)
from aegis.planner import DemoPlanner
from aegis.safety import SafetyController, SafetyViolation
from aegis.settings import Settings
from aegis.surface import account_path
from lab_api.main import app

REPO_ROOT = Path(__file__).resolve().parent.parent

SURFACE: dict[str, Any] = {
    "paths": {account_path("vulnerable"): {"get": {"path_parameter": "account_id"}}},
    "available_credentials": ["anonymous", "user_a", "user_b"],
    "known_test_objects": {"user_a": ["A-100"], "user_b": ["B-200"]},
}

GOOD_HYPOTHESIS: dict[str, Any] = {
    "id": "bola-x",
    "title": "Cross-owner read",
    "category": "BOLA",
    "rationale": "Caller-selected object IDs require ownership checks.",
    "confidence": 0.8,
    "requests": [
        {
            "name": "cross-owner",
            "method": "GET",
            "path": "/api/v1/accounts/B-200",
            "credential_profile": "user_a",
            "purpose": "Read another owner's synthetic object.",
        }
    ],
}


# --- discrimination and strictness --------------------------------------------------------------


@pytest.mark.parametrize(
    "decision_type,cls",
    [
        ("hypothesis", HypothesisDecision),
        ("execute", ExecuteDecision),
        ("continue", ContinueDecision),
        ("stop", StopDecision),
        ("review", ReviewDecision),
    ],
)
def test_every_decision_is_discriminated_by_decision_type(decision_type: str, cls: type) -> None:
    payload: dict[str, Any] = {"decision_type": decision_type, "summary": "a valid summary"}
    if decision_type in {"hypothesis", "execute"}:
        payload["hypothesis"] = GOOD_HYPOTHESIS
    decision = FULL_DECISION_ADAPTER.validate_python(payload)
    assert isinstance(decision, cls)
    assert decision.decision_type == decision_type


def test_missing_discriminator_is_rejected() -> None:
    with pytest.raises(ValidationError):
        FULL_DECISION_ADAPTER.validate_python({"summary": "no decision_type here"})


@pytest.mark.parametrize("decision_type", ["stop", "review", "continue"])
def test_illegal_cross_variant_hypothesis_field_rejected(decision_type: str) -> None:
    # stop/review/continue have no hypothesis field: supplying one is an extra property, rejected
    # (never silently dropped).
    with pytest.raises(ValidationError):
        FULL_DECISION_ADAPTER.validate_python(
            {"decision_type": decision_type, "summary": "x y z", "hypothesis": GOOD_HYPOTHESIS}
        )


@pytest.mark.parametrize("decision_type", ["hypothesis", "execute"])
def test_hypothesis_bearing_decision_requires_hypothesis(decision_type: str) -> None:
    with pytest.raises(ValidationError):
        FULL_DECISION_ADAPTER.validate_python(
            {"decision_type": decision_type, "summary": "missing hypothesis"}
        )


@pytest.mark.parametrize(
    "decision_type", ["hypothesis", "execute", "continue", "stop", "review"]
)
def test_additional_properties_rejected(decision_type: str) -> None:
    payload: dict[str, Any] = {
        "decision_type": decision_type,
        "summary": "a valid summary",
        "unexpected_field": "nope",
    }
    if decision_type in {"hypothesis", "execute"}:
        payload["hypothesis"] = GOOD_HYPOTHESIS
    with pytest.raises(ValidationError):
        FULL_DECISION_ADAPTER.validate_python(payload)


# --- per-state permitted types ------------------------------------------------------------------


def test_permitted_decision_types_by_state() -> None:
    assert permitted_decision_types(retest=False, verification_status=None) == (
        "hypothesis",
        "stop",
        "review",
    )
    assert permitted_decision_types(retest=False, verification_status="CONFIRMED") == (
        "continue",
        "stop",
        "review",
    )
    assert permitted_decision_types(retest=True, verification_status=None) == (
        "execute",
        "stop",
        "review",
    )
    assert permitted_decision_types(retest=True, verification_status="PASS") == (
        "continue",
        "stop",
        "review",
    )


@pytest.mark.parametrize(
    "permitted,illegal",
    [
        (("hypothesis", "stop", "review"), "execute"),
        (("hypothesis", "stop", "review"), "continue"),
        (("execute", "stop", "review"), "hypothesis"),
        (("continue", "stop", "review"), "hypothesis"),
    ],
)
def test_state_incompatible_decision_type_rejected_by_subset_adapter(
    permitted: tuple[str, ...], illegal: str
) -> None:
    payload: dict[str, Any] = {"decision_type": illegal, "summary": "a valid summary"}
    if illegal in {"hypothesis", "execute"}:
        payload["hypothesis"] = GOOD_HYPOTHESIS
    with pytest.raises(ValidationError):
        state_adapter(permitted).validate_python(payload)


# --- congruent generation schema + dynamic enums ------------------------------------------------


def test_generation_schema_decision_type_enum_matches_permitted() -> None:
    permitted = permitted_decision_types(retest=False, verification_status=None)
    schema = build_generation_schema(permitted, SURFACE)
    mapping = schema["discriminator"]["mapping"]
    assert set(mapping) == set(permitted)


def test_generation_schema_dynamic_enums_scope_identifiers() -> None:
    permitted = permitted_decision_types(retest=False, verification_status=None)
    schema = build_generation_schema(permitted, SURFACE)
    props = schema["$defs"]["PlannedRequest"]["properties"]
    assert props["path"]["enum"] == ["/api/v1/accounts/A-100", "/api/v1/accounts/B-200"]
    assert props["credential_profile"]["enum"] == ["anonymous", "user_a", "user_b"]
    assert props["method"]["enum"] == ["GET", "HEAD", "OPTIONS"]


def test_generation_is_subset_of_validation() -> None:
    # Every identifier the generation schema offers must be accepted by the strict validator, so the
    # schema never permits a document the Pydantic union would reject (no new structural failures).
    permitted = permitted_decision_types(retest=False, verification_status=None)
    enums = projected_request_enums(SURFACE)
    for path in enums["paths"]:
        for profile in enums["profiles"]:
            payload = {
                "decision_type": "hypothesis",
                "summary": "generation subset check",
                "hypothesis": {
                    **GOOD_HYPOTHESIS,
                    "requests": [
                        {
                            "name": "probe",
                            "method": "GET",
                            "path": path,
                            "credential_profile": profile,
                            "purpose": "subset check",
                        }
                    ],
                },
            }
            state_adapter(permitted).validate_python(payload)  # must not raise


def test_dynamic_enums_do_not_select_a_decision() -> None:
    # The enums constrain syntax/scope but leave the model >1 choice at every axis, and never
    # pre-fill a decision: an empty object does not validate to some default decision.
    permitted = permitted_decision_types(retest=False, verification_status=None)
    schema = build_generation_schema(permitted, SURFACE)
    assert len(schema["discriminator"]["mapping"]) >= 3  # model must pick a decision_type
    props = schema["$defs"]["PlannedRequest"]["properties"]
    assert len(props["path"]["enum"]) >= 2 and len(props["credential_profile"]["enum"]) >= 2
    with pytest.raises(ValidationError):
        state_adapter(permitted).validate_python({})


# --- safety/scope: unknown identifiers rejected -------------------------------------------------


def test_unknown_object_id_rejected_by_safety() -> None:
    from aegis.models import PlannedRequest

    safety = SafetyController(Settings())
    invented = PlannedRequest(
        name="invented",
        method="GET",
        path="/api/v1/accounts/C-300",
        credential_profile="user_a",
        purpose="Read an object that is not a projected synthetic object.",
    )
    with pytest.raises(SafetyViolation):
        safety.approve_request("http://lab-api:8001", invented, "vulnerable")


@pytest.mark.parametrize("profile", ["admin", "root", "user_c"])
def test_unknown_principal_rejected(profile: str) -> None:
    from aegis.models import PlannedRequest

    with pytest.raises(ValidationError):
        PlannedRequest(
            name="probe",
            method="GET",
            path="/api/v1/accounts/A-100",
            credential_profile=profile,  # type: ignore[arg-type]
            purpose="Unknown principal",
        )


# --- loop: invalid / state-incompatible decisions never execute ---------------------------------


async def test_state_incompatible_decision_never_executes(tmp_path: Path) -> None:
    # Contract V3 never calls the legacy decision method. A V2-only planner fails closed before
    # target traffic instead of being silently adapted into a candidate.
    plan = await DemoPlanner().create_plan(app.openapi())
    planner = ScriptPlanner(
        [ExecuteDecision(summary="execute in the wrong state", hypothesis=plan.hypotheses[0])]
    )
    service = make_service(tmp_path, planner)
    result = service.create()
    await service.run(result.id)
    saved = service.store.get(result.id)
    assert saved is not None and not saved.evidence
    assert saved.stop_reason == "PLANNER_REJECTED"
    assert saved.error == "CANDIDATE_ENUMERATION_UNSUPPORTED"


async def test_stale_discovery_evidence_cannot_satisfy_retest_coverage(tmp_path: Path) -> None:
    # A patched scan that collects VALID owner/deny evidence but not the parent's confirmed
    # direction must not satisfy the linked retest objective: coverage stays INSUFFICIENT.
    from aegis.models import RetestObjective

    service = make_service(tmp_path)
    original = service.create()
    await service.run(original.id)
    confirmed = service.store.get(original.id)
    assert confirmed and confirmed.status.value == "FAIL"

    # A fresh vulnerable scan collects VALID evidence but not the parent's confirmed direction.
    unrelated = service.create()
    await service.run(unrelated.id)
    stale = service.store.get(unrelated.id)
    assert stale is not None
    # Force the parent's retest objectives onto this wrong-direction evidence and re-verify: the
    # linked retest objective must NOT be satisfied by stale/wrong-direction evidence.
    stale.variant = "patched"
    stale.retest_objectives = [RetestObjective(credential_profile="user_a", account_id="B-200")]
    service._verify(stale)
    assert stale.verification is not None and stale.verification.status != "PASS"


# --- no model-specific control-plane branch -----------------------------------------------------


def test_no_model_specific_control_plane_branch() -> None:
    # The control-plane decision logic must contain no model-name branch. Model names legitimately
    # appear only as configuration (settings allowlist) and gateway-side provider wiring, never as
    # control-flow in the planner/loop/contract/safety/verifier.
    control_plane = [
        "src/aegis/planner.py",
        "src/aegis/service.py",
        "src/aegis/contract.py",
        "src/aegis/safety.py",
        "src/aegis/verifier.py",
    ]
    needles = ("qwen", "foundation-sec", "llama", "gpt-")
    for rel in control_plane:
        text = (REPO_ROOT / rel).read_text().lower()
        for needle in needles:
            assert needle not in text, f"{rel} contains model-specific token {needle!r}"


# --- contract version + baseline evidence integrity ---------------------------------------------


def test_contract_version_is_three_and_recorded() -> None:
    assert PLANNER_CONTRACT_VERSION == 3
    result = ScanResult(
        id="scan-000000000000",
        target_name="t",
        target_base_url="http://lab-api:8001",
        status="QUEUED",  # type: ignore[arg-type]
        planner="LOCAL_LLM",
    )
    assert result.planner_contract_version == 3


def test_contract_v1_baseline_evidence_unchanged() -> None:
    # The immutable qwen3:4b V1 baseline must match its recorded checksum sidecar, byte for byte.
    baseline = REPO_ROOT / "artifacts" / "local-llm-acceptance.json"
    sidecar = REPO_ROOT / "artifacts" / "local-llm-acceptance.json.sha256"
    if not baseline.exists() or not sidecar.exists():
        pytest.skip("V1 baseline evidence not present in this checkout")
    expected = sidecar.read_text().split()[0]
    actual = hashlib.sha256(baseline.read_bytes()).hexdigest()
    assert actual == expected


def test_gateway_planner_is_provider_agnostic() -> None:
    from aegis.planner import GatewayPlanner

    planner = GatewayPlanner(
        Settings(ai_provider="ollama", ai_base_url="http://ollama.test:11434"),
        "LOCAL_LLM",
        httpx.MockTransport(lambda r: httpx.Response(200)),
    )
    # No credential, no provider-specific attributes on the control-plane planner.
    assert not hasattr(planner, "_token") and not hasattr(planner, "api_key")


def test_decision_models_registry_is_complete() -> None:
    assert set(DECISION_MODELS) == {"hypothesis", "execute", "continue", "stop", "review"}
