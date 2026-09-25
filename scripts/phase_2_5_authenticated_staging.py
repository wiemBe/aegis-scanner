"""Phase 2.5 — OFFLINE authenticated staging-progression mechanics (no real staging, no provider).

A bounded, in-process demonstration of the controlled progression path from synthetic authenticated
testing toward isolated staging, and proof that real ``AUTHORIZED_STAGING`` is fail-closed
(``DEPLOYMENT_DISABLED``) this sprint. It exercises the whole mechanism deterministically:

    controller classifies the environment (fail-closed default)
      -> controller assembles the progression gates (inventory, authorization, lease, approved
         profile, opaque credential ref, session policy, capability allowlist, budgets, cleanup)
      -> evaluate_progression -> ALLOWED (one tier step)
      -> deterministic SessionWorker acquires an opaque session (positive control authenticates,
         negative control rejected, off-origin redirect blocked, origin binding enforced)
      -> use the session for the protected op (authenticated)
      -> revoke the session -> a subsequent use fails closed
      -> account reset
      -> a model-facing projection carries metadata only (no credential/session value)
      -> AUTHORIZED_STAGING requested -> STAGING_DEPLOYMENT_DISABLED (fail closed)

No provider call, no socket, no Docker. Allowed offline claim: "OFFLINE PASS for controller-governed
authenticated environment progression and opaque session handling."
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from aegis.multi_agent.staging import (
    CredentialReference,
    EnvironmentTier,
    OpaqueSecretStore,
    ProgressionRejection,
    SessionPolicy,
    SessionWorker,
    StagingActivationState,
    StagingProgressionRequest,
    StagingReferenceError,
    SyntheticStagingApp,
    build_staging_projection,
    classify_environment,
    evaluate_progression,
    staging_capability_state,
)

# A synthetic, in-process-only credential value. It is never a real secret; it lives only in the
# offline OpaqueSecretStore to exercise the positive/negative controls.
CREDENTIAL_VALUE = "synthetic-staging-passphrase-value"  # noqa: S105 - synthetic offline fixture
ORIGIN = "https://staging.synthetic.local:8443"
TARGET_REF = "range-staging-bank"
SCENARIO_ID = "staging-authenticated-probe-v1"
NOW = datetime(2026, 9, 25, 12, 0, 0, tzinfo=UTC)


def _credential(store: OpaqueSecretStore) -> CredentialReference:
    secret_ref_id = "secret-00000000000000c1"  # noqa: S105 - opaque reference id, not a secret
    store.put(secret_ref_id, CREDENTIAL_VALUE)
    return CredentialReference(
        credential_ref_id="cred-00000000000000a1",
        secret_ref_id=secret_ref_id,
        target_ref=TARGET_REF,
        scenario_id=SCENARIO_ID,
        environment_tier=EnvironmentTier.ISOLATED_STAGING,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
    )


def _request(tier: EnvironmentTier, credential: CredentialReference) -> StagingProgressionRequest:
    profile = {
        EnvironmentTier.ISOLATED_STAGING: "isolated_staging_authenticated_probe_v1",
        EnvironmentTier.AUTHORIZED_STAGING: "authorized_staging_authenticated_probe_v1",
    }[tier]
    return StagingProgressionRequest(
        campaign_id="phase-2.5-offline",
        target_inventory_ref="targetinv-range-staging-bank",
        current_tier=EnvironmentTier.SYNTHETIC_RANGE,
        requested_tier=tier,
        model_requested_tier=tier,  # hint agrees with the controller (no tier change attempted)
        authorization_reference="authz-range-staging-001",
        operator_lease_ref="lease-range-staging-001",
        lease_valid=True,
        approved_profile_id=profile,
        credential_reference_id=credential.credential_ref_id,
        session_policy=SessionPolicy(bound_origin=ORIGIN, max_lifetime_seconds=300),
        capability_allowlist=("aegis.staging.authenticated_probe",),
        requested_capability_id="aegis.staging.authenticated_probe",
        call_budget=4,
        tool_budget=8,
        cleanup_plan=("REVOKE_SESSION", "RESET_ACCOUNT", "REVOKE_CREDENTIAL_REFERENCE"),
    )


def run_offline() -> dict[str, Any]:
    checks: dict[str, bool] = {}

    # Fail-closed classification.
    checks["unknown_environment_fails_closed"] = (
        classify_environment("PRODUCTION") is EnvironmentTier.PRODUCTION_PROHIBITED
        and classify_environment(None) is EnvironmentTier.PRODUCTION_PROHIBITED
    )
    checks["synthetic_and_isolated_classified"] = (
        classify_environment("SYNTHETIC_RANGE") is EnvironmentTier.SYNTHETIC_RANGE
        and classify_environment("ISOLATED_STAGING") is EnvironmentTier.ISOLATED_STAGING
    )

    store = OpaqueSecretStore()
    credential = _credential(store)
    app = SyntheticStagingApp(origin=ORIGIN, valid_credential_value=CREDENTIAL_VALUE)
    worker = SessionWorker(store, app)

    # Progress SYNTHETIC_RANGE -> ISOLATED_STAGING with all gates satisfied.
    isolated_decision = evaluate_progression(_request(EnvironmentTier.ISOLATED_STAGING, credential))
    checks["isolated_progression_allowed"] = isolated_decision.allowed
    checks["isolated_resulting_tier_correct"] = (
        isolated_decision.resulting_tier is EnvironmentTier.ISOLATED_STAGING
    )

    # Acquire a session (positive + negative + redirect controls).
    acquisition = worker.acquire_session(
        credential,
        policy=SessionPolicy(bound_origin=ORIGIN, max_lifetime_seconds=300),
        now=NOW,
    )
    session = acquisition.session_reference
    checks["positive_control_authenticated"] = (
        acquisition.control_outcome.positive_control_authenticated
    )
    checks["negative_control_rejected"] = acquisition.control_outcome.negative_control_rejected
    checks["redirect_escape_blocked"] = acquisition.control_outcome.redirect_escape_blocked

    # Use the session (authenticated) on the bound origin.
    used = worker.use_session(session, origin=ORIGIN, now=NOW + timedelta(seconds=1))
    checks["authenticated_operation_succeeds"] = used.authenticated and used.status_code == 200

    # Cross-origin misuse fails closed.
    cross_origin_blocked = False
    try:
        worker.use_session(session, origin="https://other.local", now=NOW + timedelta(seconds=1))
    except StagingReferenceError:
        cross_origin_blocked = True
    checks["cross_origin_session_use_blocked"] = cross_origin_blocked

    # Expiry fails closed.
    expiry_blocked = False
    try:
        worker.use_session(session, origin=ORIGIN, now=NOW + timedelta(hours=1))
    except StagingReferenceError:
        expiry_blocked = True
    checks["expired_session_blocked"] = expiry_blocked

    # Revocation fails closed on subsequent use.
    worker.revoke_session(session)
    revoked_blocked = False
    try:
        worker.use_session(session, origin=ORIGIN, now=NOW + timedelta(seconds=2))
    except StagingReferenceError:
        revoked_blocked = True
    checks["revoked_session_blocked"] = revoked_blocked
    checks["secret_zeroized_after_revoke"] = not store.is_resolvable(session.secret_ref_id)

    # Account reset.
    app.reset_account()
    checks["account_reset_supported"] = True

    # Model-facing projection carries metadata only (never a value).
    projection = build_staging_projection(
        target_ref=TARGET_REF,
        environment_tier=EnvironmentTier.ISOLATED_STAGING,
        credential=credential,
        session=session,
        authorized=True,
    )
    blob = json.dumps(projection).lower()
    checks["projection_metadata_only"] = (
        "synthetic-staging-passphrase-value" not in blob and projection[
            "authorized_credential_reference_present"
        ]
        is True
    )

    # Isolated staging is synthetically active; AUTHORIZED_STAGING real connection is DISABLED.
    checks["isolated_capability_active"] = (
        staging_capability_state(EnvironmentTier.ISOLATED_STAGING, gates_satisfied=True)
        is StagingActivationState.ISOLATED_STAGING_ACTIVE
    )
    authorized_decision = evaluate_progression(
        _request(EnvironmentTier.AUTHORIZED_STAGING, credential).model_copy(
            update={"current_tier": EnvironmentTier.ISOLATED_STAGING}
        )
    )
    checks["authorized_staging_deployment_disabled"] = (
        not authorized_decision.allowed
        and ProgressionRejection.STAGING_DEPLOYMENT_DISABLED
        in authorized_decision.rejection_reasons
    )
    checks["authorized_capability_state_disabled"] = (
        staging_capability_state(EnvironmentTier.AUTHORIZED_STAGING, gates_satisfied=True)
        is StagingActivationState.DEPLOYMENT_DISABLED
    )

    # The model can never change the tier.
    tier_change = evaluate_progression(
        _request(EnvironmentTier.ISOLATED_STAGING, credential).model_copy(
            update={"model_requested_tier": EnvironmentTier.AUTHORIZED_STAGING}
        )
    )
    checks["model_cannot_change_tier"] = (
        ProgressionRejection.MODEL_ATTEMPTED_TIER_CHANGE in tier_change.rejection_reasons
    )

    # Onboarding is not execution readiness.
    onboarded = evaluate_progression(
        _request(EnvironmentTier.ISOLATED_STAGING, credential).model_copy(
            update={"onboarding_only": True}
        )
    )
    checks["onboarding_not_execution_ready"] = (
        ProgressionRejection.ONBOARDING_ONLY_NOT_EXECUTION_READY in onboarded.rejection_reasons
    )

    passed = all(checks.values())
    verdict = {
        "phase": "2.5",
        "authenticated_progression_framework_status": "OFFLINE_PASS" if passed else "OFFLINE_FAIL",
        "live_authenticated_staging_status": "NOT_EVALUATED",
        "evidence_type": "OFFLINE_INTEGRATION",
        "checks": checks,
        "passed": passed,
    }
    return {"verdict": verdict, "projection": projection}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = run_offline()
    print(json.dumps(result if args.json else result["verdict"], indent=2, sort_keys=True))
    return 0 if result["verdict"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
