"""Operator-facing projections for the Phase 1.9.5 console: authorized targets and
plain-language assessment profiles.

These are pure projections over controller-owned sources of truth (the engine capability/profile
catalog and the range inventory). They add operator-readable names and one-sentence descriptions,
never new capabilities. Availability is decided by the caller from real adapter state and passed in;
nothing here widens what an engine may do or invents an executable option.
"""

from __future__ import annotations

from typing import TypedDict

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
    for item in scanner_inventory():
        targets.append(
            {
                "target_ref": item["target_ref"],
                "name": item["name"],
                "type": "REST API",
                "target_type": "SYNTHETIC",
                "environment": item["environment"],
                "description": (
                    f"Authorized synthetic range application ({item['application_id']})."
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
                "authorized_scope": [f"{item['origin']} (synthetic range)"],
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
            {
                "capability_id": capability_id,
                "title": cap.title if (cap := get_engine_capability(capability_id)) else capability_id,
                "activity": cap.activity.value if cap else "UNKNOWN",
                "request_budget": cap.request_budget if cap else 0,
                "concurrency_budget": cap.concurrency_budget if cap else 1,
                "time_budget_ms": cap.time_budget_ms if cap else 0,
                "requires_authentication": cap.requires_authentication if cap else False,
                "state_changing_possible": cap.state_changing_possible if cap else False,
                "verified_severity": cap.verified_severity if cap else "UNKNOWN",
                "required_approvals": list(cap.required_approvals) if cap else [],
            }
            for capability_id in profile.capability_ids
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
            }
        )
    projected.sort(key=lambda item: _PROFILE_COPY[str(item["profile_id"])]["order"])  # type: ignore[index]
    return projected


def profile_display_name(profile_id: str) -> str:
    """The operator display name for a catalog profile id, or the raw id if unmapped."""

    copy = _PROFILE_COPY.get(profile_id)
    if copy is not None:
        return str(copy["display_name"])
    profile = get_engine_profile(profile_id)
    return profile.title if profile else profile_id
