import pytest

from aegis.models import Hypothesis, PlannedRequest
from aegis.safety import SafetyController, SafetyViolation
from aegis.settings import Settings


def controller() -> SafetyController:
    return SafetyController(Settings(allowed_target_hosts="lab-api"))


def test_rejects_host_outside_allowlist() -> None:
    with pytest.raises(SafetyViolation, match="outside the exact allowlist"):
        controller().validate_absolute_url("https://example.com/openapi.json")


def test_rejects_origin_escape() -> None:
    with pytest.raises(ValueError, match="authority"):
        PlannedRequest(
            name="safe-looking",
            method="GET",
            path="//evil.example/path",
            credential_profile="anonymous",
            purpose="Verify scope enforcement",
        )


def test_approves_read_only_bounded_plan() -> None:
    hypothesis = Hypothesis(
        id="auth-check",
        title="Authorization check",
        category="BOLA",
        rationale="Object identity is caller controlled.",
        confidence=0.8,
        requests=[
            PlannedRequest(
                name="object-read",
                method="GET",
                path="/api/v1/accounts/A-100",
                credential_profile="user_a",
                purpose="Read owned object",
            )
        ],
    )
    events = controller().approve_plan("http://lab-api:8001", [hypothesis])
    assert events == ["APPROVED GET /api/v1/accounts/A-100 as user_a"]


@pytest.mark.parametrize(
    "url",
    [
        "http://lab-api:8002/openapi.json",
        "https://lab-api:8001/openapi.json",
        "http://user:pass@lab-api:8001/openapi.json",
    ],
)
def test_import_cannot_escape_origin(url: str) -> None:
    settings = Settings(lab_openapi_url=url)
    with pytest.raises(SafetyViolation):
        SafetyController(settings).approve_import()
