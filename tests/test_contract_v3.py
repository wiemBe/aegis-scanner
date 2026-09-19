import hashlib
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError
from test_agent_loop import ScriptCandidatePlanner, candidate

from aegis.candidates import (
    build_context,
    candidate_generation_schema,
    deterministic_blocking_condition,
    validate_blockers,
    validate_candidates,
)
from aegis.models import (
    BlockingCondition,
    BlockingReason,
    CandidateGenerationResult,
    HypothesisCandidate,
    ObjectAuthorizationCandidate,
    ScenarioClass,
)
from aegis.safety import SafetyController
from aegis.scenarios import project
from aegis.service import ScanService
from aegis.settings import Settings
from aegis.storage import ScanStore
from lab_api.main import app


def context(scenario: str = "positive_vulnerable") -> dict[str, Any]:
    projection = project(app.openapi(), ScenarioClass(scenario))
    return build_context(
        proj=projection,
        stage="discovery",
        observations=[],
        verification={"status": "INSUFFICIENT"},
        retest=False,
        prior_finding=None,
        retest_objectives=[],
        remaining={
            "requests": 7,
            "iterations": 6,
            "model_calls": 6,
            "token_reservations": 80000,
            "time_ms": 90000,
        },
        max_candidates=3,
    )


def condition(ctx: dict[str, Any], reason: BlockingReason) -> BlockingCondition:
    return deterministic_blocking_condition(ctx, reason)


def test_enumeration_contract_has_no_terminal_or_finding_fields() -> None:
    schema = candidate_generation_schema(context())
    properties = schema["$defs"]["ObjectAuthorizationCandidate"]["properties"]
    prohibited = {
        "decision_type",
        "finding",
        "severity",
        "confirmed",
        "status",
        "url",
        "headers",
        "cookies",
        "credentials",
        "request_body",
        "raw_response",
        "reasoning",
        "remediation",
        "confidence",
        "confidence_category",
        "method",
    }
    assert prohibited.isdisjoint(properties)
    # The candidate cannot carry a terminal decision or any extra field.
    with pytest.raises(ValidationError):
        CandidateGenerationResult.model_validate(
            {"candidates": [], "blocking_conditions": [], "stop": True}
        )


def test_object_ref_is_required_and_never_null_or_blank() -> None:
    base = candidate().model_dump()
    # object_ref is required, so omitting it is a hard ValidationError, never completed.
    with pytest.raises(ValidationError):
        ObjectAuthorizationCandidate.model_validate(
            {k: v for k, v in base.items() if k != "object_ref"}
        )
    for bad in (None, "", "   "):
        with pytest.raises(ValidationError):
            ObjectAuthorizationCandidate.model_validate({**base, "object_ref": bad})


def test_object_ref_generation_enum_is_exactly_the_projected_objects() -> None:
    props = candidate_generation_schema(context())["$defs"]["ObjectAuthorizationCandidate"][
        "properties"
    ]
    assert props["object_ref"] == {"type": "string", "enum": ["A-100", "B-200"]}
    # A reference outside the dynamic enum is deterministically rejected (never queued).
    validated, rejected = validate_candidates(context(), [candidate(obj="C-300", owner="user_b")])
    assert not validated and rejected[0].code == "UNKNOWN_OBJECT"


def test_empty_generation_requires_a_blocker_at_orchestration(tmp_path: Path) -> None:
    service = make_scripted_service(tmp_path, [CandidateGenerationResult()])
    scan = service.create()
    run(service, scan.id)
    saved = service.store.get(scan.id)
    assert saved and saved.terminal_reason == "GENERATION_INCOMPLETE"
    assert saved.evidence == [] and saved.findings == []


def test_invalid_blocker_fails_closed_without_traffic(tmp_path: Path) -> None:
    positive = context()
    forged = condition(positive, BlockingReason.AUTHENTICATION_UNAVAILABLE)
    forged.claims[0].value = 0
    service = make_scripted_service(
        tmp_path, [CandidateGenerationResult(blocking_conditions=[forged])]
    )
    scan = service.create()
    run(service, scan.id)
    saved = service.store.get(scan.id)
    assert saved and saved.terminal_reason == "BLOCKER_VALIDATION_FAILED"
    assert saved.evidence == [] and saved.findings == []


@pytest.mark.parametrize(
    "scenario,reason",
    [
        ("missing_auth", BlockingReason.AUTHENTICATION_UNAVAILABLE),
        ("out_of_scope", BlockingReason.SCOPE_AMBIGUITY),
        ("state_changing_only", BlockingReason.SAFETY_CONFLICT),
        ("state_changing_only", BlockingReason.NO_SUPPORTED_TEST_CAPABILITY),
    ],
)
def test_blocker_reason_preconditions(scenario: str, reason: BlockingReason) -> None:
    ctx = context(scenario)
    assert validate_blockers(ctx, [condition(ctx, reason)])[0].valid
    assert not validate_blockers(context(), [condition(ctx, reason)])[0].valid


def test_context_and_budget_blocker_preconditions() -> None:
    insufficient = context()
    insufficient["known_objects"] = ["A-100"]
    for reason in (BlockingReason.INSUFFICIENT_CONTEXT, BlockingReason.NO_TESTABLE_HYPOTHESIS):
        assert validate_blockers(insufficient, [condition(insufficient, reason)])[0].valid
        assert not validate_blockers(context(), [condition(insufficient, reason)])[0].valid
    exhausted = context()
    exhausted["remaining"]["requests"] = 0
    blocker = condition(exhausted, BlockingReason.BUDGET_UNAVAILABLE)
    assert validate_blockers(exhausted, [blocker])[0].valid
    assert not validate_blockers(context(), [blocker])[0].valid


def test_blocker_text_without_structured_claim_is_rejected() -> None:
    with pytest.raises(ValidationError):
        BlockingCondition.model_validate({"reason": "NO_TESTABLE_HYPOTHESIS"})


def test_controller_assigns_ids_only_after_validation() -> None:
    proposed = [candidate(), candidate(alternate="user_b", obj="A-100")]
    assert "candidate_id" not in proposed[0].model_dump()
    validated, rejected = validate_candidates(context(), proposed)
    assert not rejected
    assert [item.candidate_id for item in validated] == ["cand-001", "cand-002"]


@pytest.mark.parametrize(
    "update,code",
    [
        ({"operation_id": "unknown"}, "UNKNOWN_OPERATION"),
        ({"object_ref": "C-300"}, "UNKNOWN_OBJECT"),
        ({"projected_context_refs": ["unprojected"]}, "UNPROJECTED_REFERENCE"),
    ],
)
def test_unprojected_candidate_identifiers_are_rejected(update: dict[str, Any], code: str) -> None:
    proposed = candidate().model_copy(update=update)
    validated, rejected = validate_candidates(context(), [proposed])
    assert not validated and rejected[0].code == code


def test_unregistered_capability_cannot_be_constructed() -> None:
    # capability is a Literal discriminator: an unregistered capability is a hard ValidationError,
    # stronger than a post-hoc rejection code.
    with pytest.raises(ValidationError):
        ObjectAuthorizationCandidate.model_validate({**candidate().model_dump(), "capability": "x"})


def test_principal_enum_is_dynamically_projected() -> None:
    schema = candidate_generation_schema(context("missing_auth"))
    props = schema["$defs"]["ObjectAuthorizationCandidate"]["properties"]
    # Only anonymous is projected for missing_auth, so no authenticated principal is enumerable.
    assert props["owner_principal_ref"]["enum"] == []
    assert props["alternate_principal_ref"]["enum"] == []
    with pytest.raises(ValidationError):
        ObjectAuthorizationCandidate.model_validate(
            {**candidate().model_dump(), "owner_principal_ref": "anonymous"}
        )


def test_state_changing_candidate_is_rejected() -> None:
    ctx = context("state_changing_only")
    proposed = candidate(operation="createTransfer")
    validated, rejected = validate_candidates(ctx, [proposed])
    assert not validated and rejected[0].code == "STATE_CHANGING_OPERATION"


def test_duplicate_semantic_candidate_is_rejected() -> None:
    validated, rejected = validate_candidates(context(), [candidate(), candidate()])
    assert len(validated) == 1 and rejected[0].code == "DUPLICATE_CANDIDATE"


def test_positive_and_negative_scenarios_remain_distinct() -> None:
    positive = project(app.openapi(), ScenarioClass.POSITIVE_VULNERABLE)
    negative = project(app.openapi(), ScenarioClass.PATCHED_NEGATIVE)
    assert positive.variant == "vulnerable" and negative.variant == "patched"
    assert positive.operations[0].operation_id != negative.operations[0].operation_id


def test_deprecated_generic_candidate_shape_is_not_used_by_the_live_result() -> None:
    # The Phase 0.7 shape is retained for historical readability but is not the live candidate type.
    result = CandidateGenerationResult(candidates=[candidate()])
    assert all(isinstance(c, ObjectAuthorizationCandidate) for c in result.candidates)
    # It is still importable and constructible for reading historical records.
    legacy = HypothesisCandidate.model_validate(
        {
            "test_type": "BOLA",
            "capability": "bola_object_read_v1",
            "operation_id": "getAccount",
            "principal_profile": "user_a",
            "principal_relationship": "cross_owner",
            "object_ref": "B-200",
            "object_relationship": "owned_by_other",
            "expected_invariant": "xxx",
            "observation": "yyy",
            "method": "GET",
            "confidence_category": "MEDIUM",
        }
    )
    assert legacy.object_ref == "B-200"


def test_control_plane_has_no_model_specific_branch() -> None:
    root = Path(__file__).parents[1] / "src" / "aegis"
    control_plane = "\n".join(
        (root / name).read_text()
        for name in ("service.py", "candidates.py", "scenarios.py", "verifier.py", "planner.py")
    )
    for model_name in ("qwen3:8b", "foundation-sec:8b-q4", "qwen3:4b"):
        assert model_name not in control_plane


def test_prior_evidence_manifest_is_byte_identical() -> None:
    root = Path(__file__).parents[1]
    for name in (
        "phase-0.7-prior-evidence-manifest.sha256",
        "phase-0.8-prior-evidence-manifest.sha256",
    ):
        manifest = root / "artifacts" / name
        for line in manifest.read_text().splitlines():
            digest, relative = line.split("  ", 1)
            assert hashlib.sha256((root / relative).read_bytes()).hexdigest() == digest


def make_scripted_service(
    tmp_path: Path, generations: list[CandidateGenerationResult]
) -> ScanService:
    settings = Settings(database_path=str(tmp_path / "v3.db"))
    store = ScanStore(settings.database_path)
    store.initialize()
    return ScanService(
        settings,
        store,
        ScriptCandidatePlanner(generations),
        SafetyController(settings),
        httpx.ASGITransport(app=app),
    )


def run(service: ScanService, scan_id: str) -> None:
    import asyncio

    asyncio.run(service.run(scan_id))
