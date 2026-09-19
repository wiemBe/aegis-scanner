from aegis.models import Hypothesis, PlannedRequest, RequestEvidence
from aegis.verifier import DeterministicVerifier


def hypothesis() -> Hypothesis:
    return Hypothesis(
        id="bola-check",
        title="Cross owner read",
        category="BOLA",
        rationale="Compare actor and owner.",
        confidence=0.9,
        requests=[
            PlannedRequest(
                name="cross-owner-probe",
                method="GET",
                path="/api/v1/accounts/B-200",
                credential_profile="user_a",
                purpose="Test cross owner access",
            )
        ],
    )


def test_confirms_cross_owner_access() -> None:
    evidence = RequestEvidence(
        name="cross-owner-probe",
        method="GET",
        path="/api/v1/accounts/B-200",
        credential_profile="user_a",
        status_code=200,
        duration_ms=4,
        response_excerpt={"account_id": "B-200", "owner_id": "user-b"},
    )
    findings = DeterministicVerifier().verify([hypothesis()], [evidence])
    assert len(findings) == 1
    assert findings[0].confidence == "CONFIRMED"
    assert findings[0].severity == "HIGH"


def test_finding_id_is_stable_per_scan_and_fresh_across_scans() -> None:
    evidence = RequestEvidence(
        name="cross-owner-probe",
        method="GET",
        path="/api/v1/accounts/B-200",
        credential_profile="user_a",
        status_code=200,
        duration_ms=4,
        response_excerpt={"account_id": "B-200", "owner_id": "user-b"},
    )
    verifier = DeterministicVerifier()
    first = verifier.verify([hypothesis()], [evidence], scan_id="scan-aaaaaaaaaaaa")[0]
    repeated = verifier.verify([hypothesis()], [evidence], scan_id="scan-aaaaaaaaaaaa")[0]
    second = verifier.verify([hypothesis()], [evidence], scan_id="scan-bbbbbbbbbbbb")[0]
    assert first.id == repeated.id
    assert first.id == "finding-scan-aaaaaaaaaaaa-cross-owner-probe"
    assert second.id == "finding-scan-bbbbbbbbbbbb-cross-owner-probe"
    assert first.id != second.id


def test_does_not_promote_denied_probe() -> None:
    evidence = RequestEvidence(
        name="cross-owner-probe",
        method="GET",
        path="/api/v1/accounts/B-200",
        credential_profile="user_a",
        status_code=403,
        duration_ms=4,
        response_excerpt={"detail": "Forbidden"},
    )
    assert DeterministicVerifier().verify([hypothesis()], [evidence]) == []


def test_mismatched_evidence_cannot_confirm() -> None:
    for change in (
        {"credential_profile": "user_b"},
        {"path": "/api/v1/accounts/A-100"},
        {"method": "HEAD"},
        {"response_excerpt": {"owner_id": "user-b"}},
        {"error": "ReadTimeout"},
    ):
        evidence = RequestEvidence.model_validate(
            {
                "name": "cross-owner-probe",
                "method": "GET",
                "path": "/api/v1/accounts/B-200",
                "credential_profile": "user_a",
                "status_code": 200,
                "duration_ms": 1,
                "response_excerpt": {"account_id": "B-200", "owner_id": "user-b"},
                **change,
            }
        )
        assert not DeterministicVerifier().verify([hypothesis()], [evidence])


def test_denial_and_empty_evidence_cannot_pass() -> None:
    verifier = DeterministicVerifier()
    assert verifier.evaluate([], [], "vulnerable").status == "INSUFFICIENT"
    evidence = RequestEvidence(
        name="cross-owner-probe",
        method="GET",
        path="/api/v1/accounts/B-200",
        credential_profile="user_a",
        status_code=403,
        duration_ms=1,
        response_excerpt={"detail": "Forbidden"},
    )
    assert verifier.evaluate([hypothesis()], [evidence], "vulnerable").status == "INSUFFICIENT"
