"""Operator-facing projections for the Phase 1.9.5 console: authorized targets and
plain-language assessment profiles.

These are pure projections over controller-owned sources of truth (the engine capability/profile
catalog and the range inventory). They add operator-readable names and one-sentence descriptions,
never new capabilities. Availability is decided by the caller from real adapter state and passed in;
nothing here widens what an engine may do or invents an executable option.
"""

from __future__ import annotations

from typing import TypedDict

from aegis.beast.inventory import LAUNCHABLE_BEAST_TARGETS
from aegis.beast.inventory import target as beast_target
from aegis.engine.catalog import (
    PROFILE_CATALOG,
    get_engine_capability,
    get_engine_profile,
)
from aegis.range_inventory import scanner_inventory


class ProfileAvailability(TypedDict):
    available: bool
    # A precise operator-readable reason shown when ``available`` is False. Empty when available.
    reason: str


# Plain-language operator copy for each *enabled* catalog profile. The key is the real catalog
# ``profile_id``; the copy never changes what the profile does. Profiles absent here are not shown
# in the operator assessment list (they remain visible in engine diagnostics).
_PROFILE_COPY: dict[str, dict[str, object]] = {
    "aegis-native-bola-synthetic": {
        "display_name": "Web & API Authorization",
        "operator_summary": (
            "Examines authorized API object-access boundaries and produces hypotheses for "
            "independent verification."
        ),
        "how_it_runs": (
            "Runs the Aegis-native object-authorization capability: the controller compiles and "
            "executes read-only requests that compare cross-owner object access. The deterministic "
            "Aegis verifier is the sole authority that can confirm a finding."
        ),
        "advanced": False,
        "order": 1,
    },
    "NUCLEI_LAB_SAFE_HTTP_V1": {
        "display_name": "Exposure & Misconfiguration Scan",
        "operator_summary": (
            "Checks the authorized target for exposed source-control metadata using a pinned, "
            "signed detection template."
        ),
        "how_it_runs": (
            "Runs one anonymous read-only request per admitted Nuclei template inside an isolated, "
            "egress-restricted runner. Matches enter as unconfirmed until the Aegis verifier "
            "promotes them."
        ),
        "advanced": False,
        "order": 2,
    },
    "ZAP_LAB_PASSIVE_OPENAPI_V1": {
        "display_name": "Passive Web Header Assessment",
        "operator_summary": (
            "Passively analyzes responses from approved read-only operations for missing security "
            "headers."
        ),
        "how_it_runs": (
            "Imports a controller-projected OpenAPI of approved GET/HEAD operations into ZAP and "
            "passively analyzes the responses with the admitted rule set. Alerts enter as "
            "unconfirmed until the Aegis verifier promotes them."
        ),
        "advanced": False,
        "order": 3,
    },
    "ZAP_LAB_ACTIVE_REFLECTED_XSS_V1": {
        "display_name": "Reflected XSS (Active)",
        "operator_summary": (
            "Tests one approved query parameter for reflected cross-site scripting under a "
            "single-use activation lease."
        ),
        "how_it_runs": (
            "Runs one reviewed active-scan rule against one projected query parameter on one "
            "approved read-only endpoint. Requires the operator to confirm a single-use activation "
            "lease. Alerts enter as unconfirmed until the Aegis verifier promotes them."
        ),
        "advanced": True,
        "order": 4,
    },
}

# Operator-facing capability packs that live outside the Phase 1 engine catalog. They appear in the
# same assessment picker as every other capability; the disposable toolbox is an implementation
# boundary, not a separate operator mode.
_SUPPLEMENTAL_PROFILES: tuple[dict[str, object], ...] = (
    {
        "profile_id": "OUTSIDE_IN_WEB_DISCOVERY_V1",
        "display_name": "Outside-in Web Discovery",
        "operator_summary": (
            "Enumerates the authorized web surface with FFUF and Gobuster from the disposable "
            "adversary environment."
        ),
        "how_it_runs": (
            "FFUF and Gobuster run from the normal assessment workflow inside a disposable "
            "toolbox and can reach only the controller-selected target boundary."
        ),
        "advanced": True,
        "order": 5,
        "engine": "TOOLBOX",
        "environment": "AUTHORIZED_INVENTORY",
        "execution_mode": "STANDARD",
        "tools": ["ffuf", "gobuster"],
        "isolation_boundary": "Disposable assessment sandbox behind the controller target gateway.",
        "capabilities": [
            {
                "capability_id": "aegis.recon.content_discovery",
                "title": "Authorized content discovery (FFUF / Gobuster)",
                "activity": "ACTIVE",
                "request_budget": 64,
                "concurrency_budget": 4,
                "time_budget_ms": 120_000,
                "requires_authentication": False,
                "state_changing_possible": False,
                "verified_severity": "UNKNOWN",
                "required_approvals": ["OPERATOR_AUTHORIZATION_REFERENCE", "TOOLBOX_PREFLIGHT"],
            }
        ],
    },
    {
        "profile_id": "SQLMAP_AUTHORIZED_WEB_V1",
        "display_name": "SQL Injection Assessment",
        "operator_summary": (
            "Runs SQLMap against an observed parameter inside the authorized assessment boundary."
        ),
        "how_it_runs": (
            "SQLMap runs from the normal assessment workflow in the disposable toolbox. Tool "
            "output remains evidence; the independent verifier owns confirmation."
        ),
        "advanced": True,
        "order": 8,
        "engine": "TOOLBOX",
        "environment": "AUTHORIZED_INVENTORY",
        "execution_mode": "STANDARD",
        "tools": ["sqlmap"],
        "isolation_boundary": "Disposable assessment sandbox behind the controller target gateway.",
        "capabilities": [
            {
                "capability_id": "aegis.injection.sqlmap",
                "title": "SQLMap injection assessment",
                "activity": "ACTIVE",
                "request_budget": 800,
                "concurrency_budget": 1,
                "time_budget_ms": 180_000,
                "requires_authentication": False,
                "state_changing_possible": False,
                "verified_severity": "HIGH",
                "required_approvals": ["OPERATOR_AUTHORIZATION_REFERENCE", "TOOLBOX_PREFLIGHT"],
            }
        ],
    },
    {
        "profile_id": "TOOLBOX_INFORMATION_EXPOSURE_V1",
        "display_name": "Source-control & Configuration Exposure",
        "operator_summary": (
            "Checks the authorized surface for publicly exposed source-control metadata and "
            "configuration artifacts with bounded read-only requests."
        ),
        "how_it_runs": (
            "The disposable toolbox uses Curl and the pinned Nuclei binary only inside the "
            "controller-selected target boundary. Direct response evidence is retained for the "
            "independent verifier."
        ),
        "advanced": True,
        "order": 6,
        "engine": "TOOLBOX",
        "environment": "AUTHORIZED_INVENTORY",
        "execution_mode": "STANDARD",
        "tools": ["curl", "nuclei"],
        "isolation_boundary": "Disposable assessment sandbox behind the controller target gateway.",
        "capabilities": [
            {
                "capability_id": "aegis.exposure.source_control",
                "title": "Source-control and configuration exposure review",
                "activity": "ACTIVE",
                "request_budget": 40,
                "concurrency_budget": 2,
                "time_budget_ms": 180_000,
                "requires_authentication": False,
                "state_changing_possible": False,
                "verified_severity": "MEDIUM",
                "required_approvals": [
                    "OPERATOR_AUTHORIZATION_REFERENCE",
                    "TOOLBOX_PREFLIGHT",
                ],
            }
        ],
    },
    {
        "profile_id": "TOOLBOX_BOLA_READONLY_V1",
        "display_name": "Read-only Object Authorization",
        "operator_summary": (
            "Compares bounded cross-owner object reads on the authorized synthetic API without "
            "changing target state."
        ),
        "how_it_runs": (
            "The disposable toolbox establishes synthetic controls and performs read-only "
            "cross-owner requests. The deterministic verifier, not the model, decides whether an "
            "authorization boundary failed."
        ),
        "advanced": True,
        "order": 7,
        "engine": "TOOLBOX",
        "environment": "AUTHORIZED_INVENTORY",
        "execution_mode": "STANDARD",
        "tools": ["curl", "httpie"],
        "isolation_boundary": "Disposable assessment sandbox behind the controller target gateway.",
        "capabilities": [
            {
                "capability_id": "aegis.authorization.bola_readonly",
                "title": "Read-only cross-owner object authorization comparison",
                "activity": "ACTIVE",
                "request_budget": 20,
                "concurrency_budget": 2,
                "time_budget_ms": 180_000,
                "requires_authentication": False,
                "state_changing_possible": False,
                "verified_severity": "HIGH",
                "required_approvals": [
                    "OPERATOR_AUTHORIZATION_REFERENCE",
                    "TOOLBOX_PREFLIGHT",
                ],
            }
        ],
    },
    {
        "profile_id": "IP_NETWORK_ASSESSMENT_V1",
        "display_name": "IP & Network Service Assessment",
        "operator_summary": (
            "Discovers TCP/UDP services on an explicitly authorized IP address or CIDR with Nmap."
        ),
        "how_it_runs": (
            "Uses the controller-owned AUTHORIZED_ENV_RECON profile and requires a signed lease "
            "binding the exact saved IP/CIDR scope before the network runner can execute."
        ),
        "advanced": True,
        "order": 9,
        "engine": "RECON_NMAP",
        "environment": "AUTHORIZED_INVENTORY",
        "execution_mode": "NETWORK_RUNNER",
        "tools": ["nmap"],
        "isolation_boundary": "Dedicated network runner bound to an authorized inventory lease.",
        "capabilities": [
            {
                "capability_id": "aegis.recon.network_service_discovery",
                "title": "Authorized network service discovery (Nmap)",
                "activity": "ACTIVE",
                "request_budget": 1000,
                "concurrency_budget": 1,
                "time_budget_ms": 90_000,
                "requires_authentication": False,
                "state_changing_possible": False,
                "verified_severity": "UNKNOWN",
                "required_approvals": ["SIGNED_TARGET_LEASE"],
            }
        ],
    },
)

# The controller-registered default AEGIS_NATIVE target used by the unqualified ``/api/scans``
# flow. Presented alongside the range inventory so the operator selects from real authorized
# targets only. No management origin, credential or answer-key material is projected.
_NATIVE_TARGET: dict[str, object] = {
    "target_ref": "synthetic-bank-api",
    "name": "Synthetic Bank API",
    "type": "REST API",
    "target_type": "SYNTHETIC",
    "environment": "SYNTHETIC_LAB",
    "description": "Authorized in-process synthetic banking API with approved account routes.",
    "supported_profile_ids": ["aegis-native-bola-synthetic"],
    "origin_source": "CONTROLLER_SEEDED",
    "synthetic": True,
    "status": "AVAILABLE_FOR_ASSESSMENT",
    "enabled": True,
    "authorized_scope": ["synthetic-bank-api (in-process synthetic lab)"],
    "authorization_reference": "SYNTHETIC_LAB_SCOPE",
    "allowed_path_prefixes": [],
    "excluded_path_prefixes": [],
    "credential_reference": None,
    "last_assessment_at": None,
}


def target_directory() -> list[dict[str, object]]:
    """Authorized target inventory for the New Assessment flow.

    Combines the controller's default synthetic-lab target with the range inventory's safe scanner
    projection (which already omits mode, management origin and answer keys). Engine-backed range
    targets advertise the engine profiles that could run against them; whether those profiles are
    *executable* in this deployment is decided separately by :func:`profile_directory`.
    """

    targets: list[dict[str, object]] = [dict(_NATIVE_TARGET)]
    for target_ref in LAUNCHABLE_BEAST_TARGETS:
        item = beast_target(target_ref)
        variant = "Patched" if target_ref.endswith("patched") else "Vulnerable"
        targets.append(
            {
                "target_ref": item.target_ref,
                "name": f"Disposable Toolbox Lab ({variant})",
                "type": "Toolbox-enabled REST API",
                "target_type": "SYNTHETIC",
                "environment": item.environment.value,
                "description": (
                    "Controller-seeded disposable API target for autonomous normal-workflow "
                    "tool assessments."
                ),
                "supported_profile_ids": [
                    "OUTSIDE_IN_WEB_DISCOVERY_V1",
                    "TOOLBOX_INFORMATION_EXPOSURE_V1",
                    "TOOLBOX_BOLA_READONLY_V1",
                    "SQLMAP_AUTHORIZED_WEB_V1",
                ],
                "origin_source": "CONTROLLER_SEEDED",
                "synthetic": True,
                "status": "AVAILABLE_FOR_ASSESSMENT",
                "enabled": True,
                "authorized_scope": [f"{item.origin}{item.base_path}"],
                "authorization_reference": item.approval_reference,
                "allowed_path_prefixes": [item.allowed_path_prefix],
                "excluded_path_prefixes": [],
                "credential_reference": None,
                "last_assessment_at": None,
            }
        )
    for scanner_item in scanner_inventory():
        targets.append(
            {
                "target_ref": scanner_item["target_ref"],
                "name": scanner_item["name"],
                "type": "REST API",
                "target_type": "SYNTHETIC",
                "environment": scanner_item["environment"],
                "description": (
                    f"Authorized synthetic range application ({scanner_item['application_id']})."
                ),
                # Range applications are assessed by the isolated engine profiles. Whether those
                # profiles can execute in this deployment is decided by :func:`profile_directory`;
                # when their adapter is disabled the profile is shown unavailable with a reason.
                "supported_profile_ids": [
                    "NUCLEI_LAB_SAFE_HTTP_V1",
                    "ZAP_LAB_PASSIVE_OPENAPI_V1",
                ],
                "origin_source": "CONTROLLER_SEEDED",
                "synthetic": True,
                "status": "AVAILABLE_FOR_ASSESSMENT",
                "enabled": True,
                "authorized_scope": [f"{scanner_item['origin']} (synthetic range)"],
                "authorization_reference": "SYNTHETIC_RANGE_SCOPE",
                "allowed_path_prefixes": [],
                "excluded_path_prefixes": [],
                "credential_reference": None,
                "last_assessment_at": None,
            }
        )
    return targets


def profile_directory(
    availability: dict[str, ProfileAvailability],
) -> list[dict[str, object]]:
    """Plain-language assessment profiles backed by the real enabled catalog profiles.

    ``availability`` maps a catalog ``profile_id`` to whether the backend can currently execute it
    and, if not, a precise reason. A profile with no entry is treated as unavailable with a generic
    reason so the UI never renders a clickable option the controller cannot run.
    """

    projected: list[dict[str, object]] = []
    for profile in PROFILE_CATALOG:
        copy = _PROFILE_COPY.get(profile.profile_id)
        if copy is None:
            continue  # Not an operator-facing assessment (retired/placeholder/disabled catalog).
        state = availability.get(
            profile.profile_id,
            {"available": False, "reason": "Not available in this deployment."},
        )
        capabilities = [
            _project_capability(capability_id) for capability_id in profile.capability_ids
        ]
        projected.append(
            {
                "profile_id": profile.profile_id,
                "display_name": copy["display_name"],
                "operator_summary": copy["operator_summary"],
                "how_it_runs": copy["how_it_runs"],
                "advanced": copy["advanced"],
                "engine": profile.engine.value,
                "environment": profile.environment.value,
                "available": state["available"],
                "unavailable_reason": "" if state["available"] else state["reason"],
                "capabilities": capabilities,
                "isolation_boundary": profile.isolation_boundary,
                "execution_mode": "STANDARD",
                "tools": [],
            }
        )
    for supplemental in _SUPPLEMENTAL_PROFILES:
        profile_id = str(supplemental["profile_id"])
        state = availability.get(
            profile_id,
            {"available": False, "reason": "Not available in this deployment."},
        )
        projected.append(
            {
                **supplemental,
                "available": state["available"],
                "unavailable_reason": "" if state["available"] else state["reason"],
            }
        )
    projected.sort(key=_profile_sort_order)
    return projected


def _project_capability(capability_id: str) -> dict[str, object]:
    """Project one engine capability into the console-facing dict, tolerating an unknown id."""

    cap = get_engine_capability(capability_id)
    if cap is None:
        return {
            "capability_id": capability_id,
            "title": capability_id,
            "activity": "UNKNOWN",
            "request_budget": 0,
            "concurrency_budget": 1,
            "time_budget_ms": 0,
            "requires_authentication": False,
            "state_changing_possible": False,
            "verified_severity": "UNKNOWN",
            "required_approvals": [],
        }
    return {
        "capability_id": capability_id,
        "title": cap.title,
        "activity": cap.activity.value,
        "request_budget": cap.request_budget,
        "concurrency_budget": cap.concurrency_budget,
        "time_budget_ms": cap.time_budget_ms,
        "requires_authentication": cap.requires_authentication,
        "state_changing_possible": cap.state_changing_possible,
        "verified_severity": cap.verified_severity,
        "required_approvals": list(cap.required_approvals),
    }


def _profile_sort_order(item: dict[str, object]) -> int:
    """Stable display order for a projected profile; unmapped profiles sort last."""

    profile_id = str(item["profile_id"])
    if profile_id in _PROFILE_COPY:
        order = _PROFILE_COPY[profile_id]["order"]
    else:
        supplemental = next(
            (profile for profile in _SUPPLEMENTAL_PROFILES if profile["profile_id"] == profile_id),
            None,
        )
        order = supplemental["order"] if supplemental else 999
    return order if isinstance(order, int) else 0


def profile_display_name(profile_id: str) -> str:
    """The operator display name for a catalog profile id, or the raw id if unmapped."""

    copy = _PROFILE_COPY.get(profile_id)
    if copy is not None:
        return str(copy["display_name"])
    profile = get_engine_profile(profile_id)
    return profile.title if profile else profile_id
