"""Phase 1.5 controlled active scanning for an authorized closed test environment.

This is a SEPARATE profile from the synthetic-lab one. It is intentionally inert until the operator
supplies an exact registered target: this repository ships no test-environment target, OpenAPI
document or origin, so :func:`required_configuration` reports exactly what must be provided and no
live test-environment scan can run without it.

The fixed bounds below are the ceilings the operator authorized for the first real test-env scan;
:func:`preflight` encodes the deterministic pre-live checks that must all pass before any traffic.
``CONTROLLED_TEST_ENV`` is the only non-synthetic classification that may proceed; staging and
production fail closed. No AI/model (including DeepSeek) is involved on this path.
"""

from __future__ import annotations

from dataclasses import dataclass, field

TEST_ENV_PROFILE_ID = "ZAP_TEST_ENV_ACTIVE_V1"
TEST_ENV_PROFILE_VERSION = "1.5.0"

# Fixed, operator-authorized ceilings for the first real test-environment scan.
ADMITTED_RULE_IDS: tuple[int, ...] = (40012,)  # reviewed release reflected-XSS subset
ALLOWED_METHODS: tuple[str, ...] = ("GET", "HEAD")
EXCLUDED_METHODS: tuple[str, ...] = ("POST", "PUT", "PATCH", "DELETE")
STRENGTH = "low"
THRESHOLD = "medium"
CONCURRENCY = 1
MAX_RATE_PER_SECOND = 2.0
MIN_DELAY_MS = 500  # rate <= 2 req/s
HARD_REQUEST_CEILING = 500
MAX_WALL_CLOCK_MS = 600_000  # 10 minutes
FORBIDDEN_FEATURES: tuple[str, ...] = (
    "spider",
    "ajaxSpider",
    "clientSpider",
    "oastCallbacks",
    "authentication",
    "scripts",
    "publicModelCall",
    "deepseekCall",
)


@dataclass(frozen=True)
class TestEnvScanConfig:
    """The exact configuration the operator must register before a test-env scan can run."""

    target_origin: str
    openapi_file: str
    allowed_path_prefix: str | None = None
    max_requests: int = HARD_REQUEST_CEILING
    rate_per_second: float = MAX_RATE_PER_SECOND
    wall_clock_ms: int = MAX_WALL_CLOCK_MS


@dataclass(frozen=True)
class PreflightInputs:
    """Observed facts the controller gathers immediately before live traffic. All must hold."""

    resolved_origin: str
    registered_origin: str
    classification: str
    guard_armed: bool
    kill_switch_ok: bool
    request_budget_installed: bool
    guard_route_isolated: bool  # ZAP has NO network route that bypasses the guard
    secrets_absent_from_zap_and_guard: bool
    max_requests: int
    rate_per_second: float
    wall_clock_ms: int
    admitted_rule_ids: tuple[int, ...] = field(default_factory=tuple)
    allowed_methods: tuple[str, ...] = field(default_factory=tuple)


def required_configuration() -> dict[str, str]:
    """What must be supplied to enable a test-env scan. Secrets are never requested here."""

    return {
        "TARGET_ORIGIN": "required — the exact registered http(s) origin of the closed test target",
        "OPENAPI_FILE": "required — path to the approved LOCAL OpenAPI document (not a URL)",
        "ALLOWED_PATH_PREFIX": "optional — restrict the projection to paths under this prefix",
    }


def preflight(inputs: PreflightInputs) -> list[str]:
    """Return every failed pre-live check (empty list = clear to proceed). Fail-closed by design."""

    failures: list[str] = []
    if inputs.resolved_origin.rstrip("/") != inputs.registered_origin.rstrip("/"):
        failures.append("ORIGIN_NOT_REGISTERED_TARGET")
    if inputs.classification != "CONTROLLED_TEST_ENV":
        # PRODUCTION and any unregistered classification fail closed.
        failures.append("CLASSIFICATION_NOT_CONTROLLED_TEST_ENV")
    if not inputs.guard_armed:
        failures.append("SCOPE_GUARD_NOT_ARMED")
    if not inputs.kill_switch_ok:
        failures.append("KILL_SWITCH_NOT_VERIFIED")
    if not inputs.request_budget_installed:
        failures.append("REQUEST_BUDGET_NOT_INSTALLED")
    if not inputs.guard_route_isolated:
        failures.append("GUARD_BYPASS_ROUTE_PRESENT")
    if not inputs.secrets_absent_from_zap_and_guard:
        failures.append("SECRETS_PRESENT")
    if not 1 <= inputs.max_requests <= HARD_REQUEST_CEILING:
        failures.append("REQUEST_CEILING_OUT_OF_BOUNDS")
    if not 0 < inputs.rate_per_second <= MAX_RATE_PER_SECOND:
        failures.append("RATE_OUT_OF_BOUNDS")
    if not 0 < inputs.wall_clock_ms <= MAX_WALL_CLOCK_MS:
        failures.append("WALL_CLOCK_OUT_OF_BOUNDS")
    if inputs.admitted_rule_ids and tuple(inputs.admitted_rule_ids) != ADMITTED_RULE_IDS:
        failures.append("RULE_SUBSET_MISMATCH")
    if inputs.allowed_methods and not set(inputs.allowed_methods) <= set(ALLOWED_METHODS):
        failures.append("NON_READ_ONLY_METHOD")
    return failures
