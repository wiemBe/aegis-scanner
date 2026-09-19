"""Phase 0.8 proofs (docs/phase-0.8, Part I).

The model proposes bounded security hypotheses; the deterministic controller validates, orders,
compiles, authorizes, executes and verifies them. These tests pin that responsibility boundary.
"""

from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError
from test_agent_loop import ScriptCandidatePlanner, candidate, make_service
from test_contract_v3 import context, make_scripted_service, run

from aegis.candidates import (
    candidate_generation_schema,
    compile_probe,
    compile_retest,
    execution_queue,
    ordered_validated,
    preflight,
    validate_candidates,
)
from aegis.models import (
    CandidateGenerationResult,
    ObjectAuthorizationCandidate,
    RetestObjective,
    ScanCreate,
    ScanStatus,
    ScenarioClass,
)
from aegis.planner import DemoPlanner, Planner
from aegis.registry import registered_ids
from aegis.scenarios import project
from aegis.settings import Settings
from aegis.surface import account_path
from lab_api.main import app

# --- Part B: candidate schema invariants ---------------------------------------------------------


def test_object_authorization_capability_is_registered() -> None:
    # Keeps the discriminator Literal in sync with the registry (single source of truth).
    assert "bola_object_read_v1" in registered_ids()


def test_principals_are_required_approved_and_different() -> None:
    base = candidate().model_dump()
    for field in ("owner_principal_ref", "alternate_principal_ref"):
        with pytest.raises(ValidationError):
            ObjectAuthorizationCandidate.model_validate(
                {k: v for k, v in base.items() if k != field}
            )
        with pytest.raises(ValidationError):  # not an approved authenticated profile
            ObjectAuthorizationCandidate.model_validate({**base, field: "anonymous"})
    # Same owner and alternate is a testable-direction violation, rejected deterministically.
    same = candidate(alternate="user_b", obj="B-200", owner="user_b")
    validated, rejected = validate_candidates(context(), [same])
    assert not validated and rejected[0].code == "PRINCIPALS_NOT_DISTINCT"


def test_capability_discriminated_candidate_rejects_cross_variant_fields() -> None:
    # A field for a different (future) capability variant is a hard rejection (extra=forbid).
    with pytest.raises(ValidationError):
        ObjectAuthorizationCandidate.model_validate(
            {**candidate().model_dump(), "token_field": "value"}
        )
    for forbidden in ("url", "headers", "credentials", "severity", "finding"):
        with pytest.raises(ValidationError):
            ObjectAuthorizationCandidate.model_validate(
                {**candidate().model_dump(), forbidden: "x"}
            )


def test_generation_schema_is_a_subset_of_validation_schema() -> None:
    ctx = context()
    props = candidate_generation_schema(ctx)["$defs"]["ObjectAuthorizationCandidate"]["properties"]
    # Every enumerated identifier the model can emit is one deterministic validation accepts.
    assert set(props["capability"]["enum"]) <= registered_ids()
    assert set(props["owner_principal_ref"]["enum"]) <= {"user_a", "user_b"}
    assert set(props["alternate_principal_ref"]["enum"]) <= {"user_a", "user_b"}
    assert set(props["object_ref"]["enum"]) <= set(ctx["known_objects"])
    # A candidate built from each enumerated object validates (constructing a distinct direction).
    for obj in props["object_ref"]["enum"]:
        owner = "user_a" if obj == "A-100" else "user_b"
        alternate = "user_b" if owner == "user_a" else "user_a"
        validated, rejected = validate_candidates(
            ctx, [candidate(alternate=alternate, obj=obj, owner=owner)]
        )
        assert validated and not rejected


# --- Part A: deterministic queue -----------------------------------------------------------------


def _validated(*cands: ObjectAuthorizationCandidate) -> list[Any]:
    validated, rejected = validate_candidates(context(), list(cands))
    assert not rejected, rejected
    return validated


def test_invalid_candidate_is_never_queued() -> None:
    validated, rejected = validate_candidates(context(), [candidate(obj="C-300", owner="user_b")])
    assert not validated
    queue = execution_queue(validated, context()["remaining"])
    assert queue == []


def test_deterministic_ordering_is_stable() -> None:
    validated = _validated(candidate(), candidate(alternate="user_b", obj="A-100"))
    first = [v.candidate.model_dump() for v in ordered_validated(validated)]
    second = [v.candidate.model_dump() for v in ordered_validated(validated)]
    assert first == second


def test_deterministic_ordering_is_model_independent() -> None:
    a = candidate()  # user_a -> B-200
    b = candidate(alternate="user_b", obj="A-100")  # user_b -> A-100
    one, _ = validate_candidates(context(), [a, b])
    two, _ = validate_candidates(context(), [b, a])  # different model output order
    assert [v.candidate.model_dump() for v in ordered_validated(one)] == [
        v.candidate.model_dump() for v in ordered_validated(two)
    ]


def test_execution_policy_cannot_change_candidate_semantics() -> None:
    validated = _validated(candidate(), candidate(alternate="user_b", obj="A-100"))
    before = [v.candidate.model_dump() for v in validated]
    execution_queue(validated, context()["remaining"])
    ordered_validated(validated)
    after = [v.candidate.model_dump() for v in validated]
    # Queueing/ordering never mutates, fills or reinterprets any candidate field.
    assert before == after


def test_queue_admits_within_request_budget_only() -> None:
    validated = _validated(candidate(), candidate(alternate="user_b", obj="A-100"))
    # Each candidate costs three reads; a 4-request remainder admits exactly one.
    queue = execution_queue(validated, {"requests": 4})
    assert [q.admitted for q in queue] == [True, False]
    assert queue[1].reason == "BUDGET_UNAVAILABLE"


# --- Part C: deterministic request compiler ------------------------------------------------------


def test_compilation_uses_canonical_openapi_and_no_model_secret() -> None:
    proj = project(app.openapi(), ScenarioClass.POSITIVE_VULNERABLE)
    validated = _validated(candidate())  # user_a -> B-200
    hypothesis = compile_probe(validated[0], proj, 1)
    probe = hypothesis.requests[-1]
    assert probe.method == "GET"
    assert probe.path == account_path("vulnerable").replace("{account_id}", "B-200")
    assert probe.credential_profile == "user_a"
    # The candidate never carried a URL, header or credential; the compiled request carries none
    # either — the executor resolves the credential profile to a secret outside the model.
    dumped = hypothesis.model_dump_json()
    assert "lab-token" not in dumped and "Authorization" not in dumped


def test_compilation_failure_issues_no_traffic(tmp_path: Path, monkeypatch: Any) -> None:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise ValueError("unresolvable reference")

    service = make_scripted_service(tmp_path, [CandidateGenerationResult(candidates=[candidate()])])
    monkeypatch.setattr("aegis.service.compile_probe", boom)
    scan = service.create()
    run(service, scan.id)
    saved = service.store.get(scan.id)
    assert saved and saved.evidence == [] and saved.findings == []
    assert saved.terminal_reason == "PLANNER_REJECTED_REQUEST_COMPILATION_FAILED"


def test_controller_never_fills_missing_model_selected_reference() -> None:
    # A structurally incomplete candidate is a ValidationError; validation never completes it.
    base = candidate().model_dump()
    with pytest.raises(ValidationError):
        ObjectAuthorizationCandidate.model_validate(
            {k: v for k, v in base.items() if k != "object_ref"}
        )
    # A candidate whose declared owner does not actually own the object is rejected, not corrected.
    wrong_owner = candidate(alternate="user_a", obj="B-200", owner="user_a")
    validated, rejected = validate_candidates(context(), [wrong_owner])
    assert not validated
    assert rejected[0].code in {"PRINCIPALS_NOT_DISTINCT", "OWNER_PRINCIPAL_MISMATCH"}


# --- Part D: deterministic preflight -------------------------------------------------------------


class _RaisingEnumPlanner(Planner):
    name = "TEST_RAISING_NOT_LLM"

    def __init__(self) -> None:
        self.enumerated = False

    async def decide(self, context: dict[str, Any], budget: Any) -> Any:  # pragma: no cover
        raise AssertionError("decide must not be called")

    async def enumerate_candidates(self, context: dict[str, Any], budget: Any, n: int) -> Any:
        self.enumerated = True
        raise AssertionError("the model must not be called when preflight already blocks")


@pytest.mark.parametrize(
    "scenario,blocker",
    [
        ("missing_auth", "BLOCKED_AUTHENTICATION_UNAVAILABLE"),
        ("out_of_scope", "BLOCKED_SCOPE_AMBIGUITY"),
        ("state_changing_only", "BLOCKED_SAFETY_CONFLICT"),
    ],
)
async def test_preflight_prevents_model_and_target_calls(
    tmp_path: Path, scenario: str, blocker: str
) -> None:
    planner = _RaisingEnumPlanner()
    service = make_service(tmp_path, planner)
    scan = service.create(ScanCreate(scenario=scenario))
    await service.run(scan.id)
    saved = service.store.get(scan.id)
    assert saved and not planner.enumerated
    assert saved.terminal_reason == blocker
    assert saved.usage.model_calls == 0
    assert saved.evidence == [] and saved.findings == []
    events = [e["event"] for e in service.store.audit(scan.id)]
    assert "PREFLIGHT" in events and "CANDIDATE_GENERATION_REQUEST" not in events


def test_preflight_is_the_deterministic_blocker() -> None:
    assert preflight(context("missing_auth")) is not None
    assert preflight(context()) is None


# --- Part A/E: no model-based selection ----------------------------------------------------------


async def test_model_based_selection_is_not_called_in_the_new_flow(tmp_path: Path) -> None:
    class SelectionSpyPlanner(DemoPlanner):
        name = "DEMO_HEURISTIC"

        def __init__(self) -> None:
            self.selected = False

        async def select_candidate(self, *a: Any, **k: Any) -> Any:  # pragma: no cover
            self.selected = True
            raise AssertionError("select_candidate must never be called by the Phase 0.8 flow")

    planner = SelectionSpyPlanner()
    service = make_service(tmp_path, planner)
    scan = service.create()
    await service.run(scan.id)
    found = service.store.get(scan.id)
    assert found and found.status == ScanStatus.FAIL and not planner.selected
    retest = service.create(ScanCreate(variant="patched", retest_of=found.id))
    await service.run(retest.id)
    assert not planner.selected
    for scan_id in (scan.id, retest.id):
        events = [e["event"] for e in service.store.audit(scan_id)]
        assert "CANDIDATE_SELECTION" not in events
        assert "CANDIDATE_SELECTION_REQUEST" not in events


# --- Part F: linked retest -----------------------------------------------------------------------


async def test_linked_retest_uses_confirmed_direction_and_fresh_evidence(tmp_path: Path) -> None:
    service = make_service(tmp_path)
    initial = service.create()
    await service.run(initial.id)
    found = service.store.get(initial.id)
    assert found and found.findings
    confirmed = found.evidence[-1]  # the cross-owner probe that confirmed the finding
    retest = service.create(ScanCreate(variant="patched", retest_of=found.id))
    await service.run(retest.id)
    fixed = service.store.get(retest.id)
    assert fixed and fixed.status == ScanStatus.PASS
    # Same confirmed principal/object access direction is repeated (on the patched surface).
    probe = fixed.evidence[-1]
    assert probe.credential_profile == confirmed.credential_profile
    assert probe.path.rsplit("/", 1)[-1] == confirmed.path.rsplit("/", 1)[-1]
    assert probe.status_code == 403
    # Fresh evidence: retest names are distinct from the discovery evidence names.
    discovery_names = {e.name for e in found.evidence}
    assert all(e.name not in discovery_names for e in fixed.evidence)
    assert all(e.name.startswith("retest") for e in fixed.evidence)


def test_retest_plan_repeats_same_operation_and_object_relationship() -> None:
    proj = project(app.openapi(), ScenarioClass.PATCHED_NEGATIVE)
    objective = RetestObjective(credential_profile="user_a", account_id="B-200")
    hypothesis = compile_retest([objective], proj)
    # Two fresh owner controls plus the cross-owner probe, all read-only on the patched operation.
    assert [r.method for r in hypothesis.requests] == ["GET", "GET", "GET"]
    probe = hypothesis.requests[-1]
    assert probe.credential_profile == "user_a" and probe.path.endswith("/B-200")
    assert hypothesis.requests[0].credential_profile == "user_a"  # fresh alternate control
    assert hypothesis.requests[1].credential_profile == "user_b"  # fresh owner control


def test_retest_cannot_pass_on_wrong_direction_coverage(tmp_path: Path) -> None:
    # A patched scan whose evidence misses the confirmed objective is INSUFFICIENT, not PASS.
    service = make_service(
        tmp_path,
        ScriptCandidatePlanner(
            [CandidateGenerationResult(candidates=[candidate(alternate="user_b", obj="A-100")])]
        ),
    )
    unrelated = service.create(ScanCreate(variant="patched"))
    import asyncio

    asyncio.run(service.run(unrelated.id))
    wrong = service.store.get(unrelated.id)
    assert wrong is not None
    wrong.retest_objectives = [RetestObjective(credential_profile="user_a", account_id="B-200")]
    service._verify(wrong)
    assert wrong.verification and wrong.verification.status == "INSUFFICIENT"


# --- Part E: verifier is the sole finding authority ----------------------------------------------


async def test_deterministic_verifier_is_the_only_finding_authority(tmp_path: Path) -> None:
    loud = candidate()
    loud.expected_authorization_invariant = "A CRITICAL confirmed BOLA finding is expected here."
    service = make_service(
        tmp_path, ScriptCandidatePlanner([CandidateGenerationResult(candidates=[loud])])
    )

    def deny(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json=app.openapi())
        return httpx.Response(403, json={"detail": "Forbidden"})

    service.transport = httpx.MockTransport(deny)
    service.executor.transport = service.transport
    scan = service.create()
    await service.run(scan.id)
    saved = service.store.get(scan.id)
    # No cross-owner 200 read was observed, so the invariant prose creates no finding.
    assert saved and saved.findings == [] and saved.status != ScanStatus.FAIL


def test_no_provider_specific_control_plane_branch() -> None:
    root = Path(__file__).parents[1] / "src" / "aegis"
    control_plane = "\n".join(
        (root / name).read_text()
        for name in ("service.py", "candidates.py", "scenarios.py", "verifier.py")
    )
    for token in ("ollama", "openai", "internal_openai", "foundation-sec", "qwen"):
        assert token not in control_plane.lower()


def test_control_plane_settings_have_no_gateway_secret() -> None:
    # The control plane refuses to hold a provider credential; secrets live only in the gateway.
    settings = Settings()
    assert settings.ai_auth_token is None
