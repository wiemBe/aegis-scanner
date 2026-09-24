"""Controller-only ground truth. Never serialize this module into scanner/planner projections."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class ScenarioTruth:
    ground_truth_id: str
    application_id: str
    scenario_id: str
    vulnerability_class_id: str
    title: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    severity_rationale: str
    evidence_requirements: tuple[str, ...]
    supported_modes: tuple[str, str] = ("vulnerable", "patched")
    verifier_id: str = "range-verifier-v1"
    reset_dependencies: tuple[str, ...] = ()
    compatible_engines: tuple[str, ...] = ("BEAST_MODE",)


GROUND_TRUTH: tuple[ScenarioTruth, ...] = (
    ScenarioTruth(
        "GT-RANGE-BANK-001",
        "aegis-bank",
        "bank-object-access-v1",
        "CWE-639",
        "Cross-customer account object access",
        "HIGH",
        "A low-privilege authenticated user can read another customer's financial objects.",
        (
            "owner control succeeds",
            "cross-owner account identity proven",
            "transaction access proven",
        ),
        compatible_engines=("AEGIS_NATIVE", "BEAST_MODE"),
    ),
    ScenarioTruth(
        "GT-RANGE-BANK-002",
        "aegis-bank",
        "bank-operation-access-v1",
        "CWE-862",
        "Business operation authorization",
        "HIGH",
        "A customer can invoke an operator-only business function.",
        ("customer control", "restricted operation result", "patched rejection"),
        compatible_engines=("AEGIS_NATIVE", "BEAST_MODE"),
    ),
    ScenarioTruth(
        "GT-RANGE-BANK-003",
        "aegis-bank",
        "bank-session-validation-v1",
        "CWE-347",
        "Session token validation",
        "CRITICAL",
        "An unsigned synthetic token can impersonate another subject.",
        ("valid login control", "fresh unsigned token", "subject proof", "patched rejection"),
    ),
    ScenarioTruth(
        "GT-RANGE-BANK-004",
        "aegis-bank",
        "bank-profile-update-v1",
        "CWE-915",
        "Profile field binding",
        "HIGH",
        "An undocumented security-sensitive account field can be client-controlled.",
        ("legitimate update", "hidden field mutation", "patched field rejection"),
        compatible_engines=("AEGIS_NATIVE", "BEAST_MODE"),
    ),
    ScenarioTruth(
        "GT-RANGE-BANK-005",
        "aegis-bank",
        "bank-recovery-response-v1",
        "CWE-204",
        "Recovery response and request limiting",
        "MEDIUM",
        "Recovery responses disclose registration and permit an unbounded request sequence.",
        (
            "registered/unregistered comparison",
            "bounded fourth request",
            "uniform patched response",
        ),
    ),
    ScenarioTruth(
        "GT-RANGE-BANK-006",
        "aegis-bank",
        "bank-login-rate-limit-v1",
        "CWE-307",
        "Excessive authentication attempt restriction",
        "HIGH",
        (
            "Invalid credential submissions against a synthetic account are neither rate-limited "
            "nor locked out, permitting an unbounded credential-guessing sequence."
        ),
        (
            "positive-control login usable",
            "bounded invalid-attempt sequence executed",
            "rate-limit/lockout signal present (patched) or absent (vulnerable)",
        ),
    ),
    ScenarioTruth(
        "GT-RANGE-SHOP-001",
        "aegis-shop",
        "shop-catalog-query-v1",
        "CWE-89",
        "Catalog query manipulation",
        "HIGH",
        "A crafted search changes query semantics and returns records outside the requested match.",
        (
            "benign search is selective",
            "probe expands result set",
            "seeded product identities match",
        ),
        compatible_engines=("ZAP_ACTIVE", "BEAST_MODE"),
    ),
    ScenarioTruth(
        "GT-RANGE-SHOP-003",
        "aegis-shop",
        "shop-review-content-v1",
        "CWE-79",
        "Persisted review rendering",
        "HIGH",
        "Persisted customer content executes for a privileged synthetic viewer.",
        ("stored content", "fresh browser process", "fresh effect canary"),
        reset_dependencies=("shop-browser", "shop-effect-canary"),
        compatible_engines=("ZAP_ACTIVE", "BEAST_MODE"),
    ),
    ScenarioTruth(
        "GT-RANGE-SHOP-004",
        "aegis-shop",
        "shop-preference-request-v1",
        "CWE-352",
        "Preference request integrity",
        "MEDIUM",
        "A cross-site request can change an authenticated synthetic preference.",
        ("authorized control", "cross-site attempt", "state comparison"),
    ),
    ScenarioTruth(
        "GT-RANGE-SHOP-005",
        "aegis-shop",
        "shop-attachment-policy-v1",
        "CWE-434",
        "Support attachment validation",
        "HIGH",
        "Active inert markup can be stored under a caller-controlled name and rendered inline.",
        ("benign attachment", "active-content fixture", "disposition and naming facts"),
        compatible_engines=("BEAST_MODE",),
    ),
    ScenarioTruth(
        "GT-RANGE-SHOP-002",
        "aegis-shop",
        "shop-promotion-preview-v1",
        "CWE-79",
        "Promotion preview output encoding",
        "MEDIUM",
        "Untrusted promotion copy can enter an executable HTML context in an operator preview.",
        ("benign preview succeeds", "probe is raw or contextually encoded", "response is HTML"),
        compatible_engines=("ZAP_ACTIVE", "BEAST_MODE"),
    ),
    ScenarioTruth(
        "GT-RANGE-OPS-002",
        "aegis-ops",
        "ops-diagnostic-input-v1",
        "CWE-78",
        "Diagnostic argument handling",
        "CRITICAL",
        "Shell metacharacters can create a fresh effect inside the disposable worker.",
        (
            "benign diagnostic",
            "fresh worker canary",
            "patched typed rejection",
            "workspace cleanup",
        ),
        reset_dependencies=("ops-worker",),
    ),
    ScenarioTruth(
        "GT-RANGE-OPS-003",
        "aegis-ops",
        "ops-report-preview-v1",
        "CWE-1336",
        "Operational template preview",
        "HIGH",
        "User-controlled template syntax is evaluated inside the isolated worker.",
        ("benign preview", "fresh calculation", "patched literal rendering"),
        reset_dependencies=("ops-worker",),
    ),
    ScenarioTruth(
        "GT-RANGE-OPS-004",
        "aegis-ops",
        "ops-support-status-v1",
        "CWE-200",
        "Support configuration projection",
        "HIGH",
        "A reset-specific synthetic configuration secret is returned by a support surface.",
        ("fresh reset marker", "exposed value", "patched redaction"),
        compatible_engines=("NUCLEI", "BEAST_MODE"),
    ),
    ScenarioTruth(
        "GT-RANGE-OPS-001",
        "aegis-ops",
        "ops-report-selection-v1",
        "CWE-22",
        "Operational report boundary",
        "HIGH",
        (
            "A report selector can cross the published directory and read a synthetic internal "
            "fixture."
        ),
        (
            "published report succeeds",
            "archive marker is returned or rejected",
            "fixture boundary holds",
        ),
    ),
    ScenarioTruth(
        "GT-RANGE-CLOUD-001",
        "aegis-cloud",
        "cloud-integration-fetch-v1",
        "CWE-918",
        "Integration destination boundary",
        "HIGH",
        (
            "A user-controlled check can reach a dedicated internal service and return its "
            "synthetic proof."
        ),
        (
            "approved benign check succeeds",
            "canary proof is returned or rejected",
            "destination is exact",
        ),
    ),
    ScenarioTruth(
        "GT-RANGE-CLOUD-002",
        "aegis-cloud",
        "cloud-xml-import-v1",
        "CWE-611",
        "Integration XML resource handling",
        "HIGH",
        "A controlled external entity resolves a local synthetic fixture.",
        ("benign XML", "synthetic resource marker", "patched DTD rejection"),
    ),
    ScenarioTruth(
        "GT-RANGE-CLOUD-003",
        "aegis-cloud",
        "cloud-workspace-sharing-v1",
        "CWE-942",
        "Workspace cross-origin policy",
        "HIGH",
        "Credentialed responses reflect an untrusted origin.",
        ("trusted-origin control", "untrusted preflight", "untrusted actual response"),
    ),
    ScenarioTruth(
        "GT-RANGE-CLOUD-004",
        "aegis-cloud",
        "cloud-metadata-response-v1",
        "CWE-200",
        "Integration metadata filtering",
        "HIGH",
        "A reset-specific synthetic credential is returned from the internal metadata response.",
        ("internal canary reach", "fresh credential", "patched field omission"),
        reset_dependencies=("cloud-integration-fetch-v1", "range-canary"),
        compatible_engines=("NUCLEI", "BEAST_MODE"),
    ),
    ScenarioTruth(
        "GT-RANGE-CLOUD-005",
        "aegis-cloud",
        "cloud-service-access-v1",
        "CWE-285",
        "Internal service credential authorization",
        "CRITICAL",
        "A metadata-scoped credential is accepted by the private administration service.",
        (
            "valid service control",
            "wrong-audience credential",
            "private effect",
            "patched rejection",
        ),
        reset_dependencies=(
            "cloud-integration-fetch-v1",
            "cloud-metadata-response-v1",
            "cloud-admin",
        ),
    ),
)

GROUND_TRUTH_BY_SCENARIO = {item.scenario_id: item for item in GROUND_TRUTH}


@dataclass(frozen=True)
class ChainTruth:
    chain_id: str
    application_id: str
    prerequisites: tuple[str, ...]
    terminal_evidence: str


CHAIN_GROUND_TRUTH: tuple[ChainTruth, ...] = (
    ChainTruth(
        "bank-recovery-chain-v1",
        "aegis-bank",
        ("bank-object-access-v1",),
        "cross-owner authenticated profile after recovery",
    ),
    ChainTruth(
        "cloud-service-chain-v1",
        "aegis-cloud",
        ("cloud-integration-fetch-v1", "cloud-metadata-response-v1", "cloud-service-access-v1"),
        "private administration effect",
    ),
    ChainTruth(
        "shop-viewer-chain-v1",
        "aegis-shop",
        ("shop-review-content-v1",),
        "fresh privileged-viewer effect canary",
    ),
)
