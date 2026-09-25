"""Offline targeted tests for the Phase 2.5 authenticated staging-progression slice.

No live provider, no real staging, no Docker. These cover the *new* surface 2.5 adds: environment
tiers + fail-closed classification, controller-owned progression gates and every typed rejection,
opaque target/scenario-bound credential references and environment-bound session references, the
deterministic session worker (positive/negative controls, origin binding, redirect escape,
expiry/revocation), secret zeroization, cross-target misuse, secret redaction in projections, the
deployment-disabled AUTHORIZED_STAGING state, account reset, audit events and UNKNOWN/NOT_EVALUATED
behaviour. Offline tests are NOT live acceptance.
"""

from __future__ import annotations

import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from aegis.multi_agent.staging import (
    CredentialReference,
    EnvironmentTier,
    OpaqueSecretStore,
    ProgressionRejection,
    SessionPolicy,
    SessionWorker,
    StagingActivationState,
    StagingAuditEvent,
    StagingLedger,
    StagingProgressionRequest,
    StagingReferenceError,
    StagingRejection,
    SyntheticStagingApp,
    assert_staging_projection_clean,
    build_staging_projection,
    classify_environment,
    deployment_disabled,
    evaluate_progression,
    staging_capability_state,
    tier_is_executable,
)

ORIGIN = "https://staging.synthetic.local:8443"
TARGET_REF = "range-staging-bank"
CRED_VALUE = "synthetic-passphrase"  # noqa: S105 - synthetic offline fixture
NOW = datetime(2026, 9, 25, 12, 0, 0, tzinfo=UTC)


def _load_harness() -> Any:
    path = Path(__file__).resolve().parent.parent / "scripts" / "phase_2_5_authenticated_staging.py"
    spec = importlib.util.spec_from_file_location("phase_2_5_authenticated_staging", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _credential(
    store: OpaqueSecretStore,
    *,
    tier: EnvironmentTier = EnvironmentTier.ISOLATED_STAGING,
    target_ref: str = TARGET_REF,
    expires_minutes: int = 10,
    value: str = CRED_VALUE,
) -> CredentialReference:
    secret_ref_id = "secret-0000000000000abc"  # noqa: S105 - opaque reference id
    store.put(secret_ref_id, value)
    return CredentialReference(
        credential_ref_id="cred-0000000000000abc",
        secret_ref_id=secret_ref_id,
        target_ref=target_ref,
        scenario_id="staging-authenticated-probe-v1",
        environment_tier=tier,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=expires_minutes),
    )


def _request(**o: Any) -> StagingProgressionRequest:
    base: dict[str, Any] = {
        "campaign_id": "phase-2.5-test",
        "target_inventory_ref": "targetinv-1",
        "current_tier": EnvironmentTier.SYNTHETIC_RANGE,
        "requested_tier": EnvironmentTier.ISOLATED_STAGING,
        "model_requested_tier": EnvironmentTier.ISOLATED_STAGING,
        "authorization_reference": "authz-1",
        "operator_lease_ref": "lease-1",
        "lease_valid": True,
        "approved_profile_id": "isolated_staging_authenticated_probe_v1",
        "credential_reference_id": "cred-0000000000000abc",
        "session_policy": SessionPolicy(bound_origin=ORIGIN, max_lifetime_seconds=300),
        "capability_allowlist": ("aegis.staging.authenticated_probe",),
        "requested_capability_id": "aegis.staging.authenticated_probe",
        "call_budget": 4,
        "tool_budget": 8,
        "cleanup_plan": ("REVOKE_SESSION", "RESET_ACCOUNT"),
    }
    base.update(o)
    return StagingProgressionRequest(**base)


# --------------------------------------------------------------------------- #
# Tier classification (fail-closed).
# --------------------------------------------------------------------------- #


def test_classification_fails_closed() -> None:
    assert classify_environment("PRODUCTION") is EnvironmentTier.PRODUCTION_PROHIBITED
    assert classify_environment("banana") is EnvironmentTier.PRODUCTION_PROHIBITED
    assert classify_environment(None) is EnvironmentTier.PRODUCTION_PROHIBITED
    assert classify_environment("synthetic_range") is EnvironmentTier.SYNTHETIC_RANGE
    assert classify_environment("AUTHORIZED_STAGING") is EnvironmentTier.AUTHORIZED_STAGING


def test_production_prohibited_not_executable() -> None:
    assert not tier_is_executable(EnvironmentTier.PRODUCTION_PROHIBITED)
    assert tier_is_executable(EnvironmentTier.ISOLATED_STAGING)
    assert deployment_disabled(EnvironmentTier.AUTHORIZED_STAGING)
    assert not deployment_disabled(EnvironmentTier.ISOLATED_STAGING)


# --------------------------------------------------------------------------- #
# Progression gates.
# --------------------------------------------------------------------------- #


def test_full_gates_allow_isolated_progression() -> None:
    decision = evaluate_progression(_request())
    assert decision.allowed
    assert decision.resulting_tier is EnvironmentTier.ISOLATED_STAGING
    assert decision.rejection_reasons == ()


def test_missing_authorization_rejected() -> None:
    decision = evaluate_progression(_request(authorization_reference=None))
    assert not decision.allowed
    assert ProgressionRejection.MISSING_AUTHORIZATION_REFERENCE in decision.rejection_reasons
    assert decision.resulting_tier is EnvironmentTier.PRODUCTION_PROHIBITED


def test_expired_lease_rejected() -> None:
    decision = evaluate_progression(_request(lease_valid=False))
    assert ProgressionRejection.MISSING_OR_EXPIRED_OPERATOR_LEASE in decision.rejection_reasons


def test_unapproved_profile_rejected() -> None:
    decision = evaluate_progression(_request(approved_profile_id="some_other_profile"))
    assert ProgressionRejection.PROFILE_NOT_APPROVED in decision.rejection_reasons


def test_capability_not_allowlisted_rejected() -> None:
    decision = evaluate_progression(_request(requested_capability_id="aegis.staging.exploit"))
    assert ProgressionRejection.CAPABILITY_NOT_ALLOWLISTED in decision.rejection_reasons


def test_missing_budget_and_cleanup_rejected() -> None:
    decision = evaluate_progression(_request(call_budget=None, cleanup_plan=()))
    assert ProgressionRejection.BUDGET_NOT_DECLARED in decision.rejection_reasons
    assert ProgressionRejection.CLEANUP_PLAN_MISSING in decision.rejection_reasons


def test_missing_credential_and_session_policy_rejected() -> None:
    decision = evaluate_progression(_request(credential_reference_id=None, session_policy=None))
    assert ProgressionRejection.MISSING_CREDENTIAL_REFERENCE in decision.rejection_reasons
    assert ProgressionRejection.MISSING_SESSION_POLICY in decision.rejection_reasons


def test_authorized_staging_deployment_disabled() -> None:
    decision = evaluate_progression(
        _request(
            current_tier=EnvironmentTier.ISOLATED_STAGING,
            requested_tier=EnvironmentTier.AUTHORIZED_STAGING,
            model_requested_tier=EnvironmentTier.AUTHORIZED_STAGING,
            approved_profile_id="authorized_staging_authenticated_probe_v1",
        )
    )
    assert not decision.allowed
    assert ProgressionRejection.STAGING_DEPLOYMENT_DISABLED in decision.rejection_reasons


def test_production_requested_rejected() -> None:
    decision = evaluate_progression(
        _request(requested_tier=EnvironmentTier.PRODUCTION_PROHIBITED, model_requested_tier=None)
    )
    assert not decision.allowed
    assert (
        ProgressionRejection.UNCLASSIFIED_OR_PRODUCTION_ENVIRONMENT in decision.rejection_reasons
    )


def test_model_cannot_change_tier() -> None:
    decision = evaluate_progression(
        _request(model_requested_tier=EnvironmentTier.AUTHORIZED_STAGING)
    )
    assert ProgressionRejection.MODEL_ATTEMPTED_TIER_CHANGE in decision.rejection_reasons


def test_onboarding_not_execution_ready() -> None:
    decision = evaluate_progression(_request(onboarding_only=True))
    assert ProgressionRejection.ONBOARDING_ONLY_NOT_EXECUTION_READY in decision.rejection_reasons


def test_tier_skip_rejected() -> None:
    # SYNTHETIC_RANGE -> AUTHORIZED_STAGING is a 2-step skip (also deployment-disabled).
    decision = evaluate_progression(
        _request(
            requested_tier=EnvironmentTier.AUTHORIZED_STAGING,
            model_requested_tier=EnvironmentTier.AUTHORIZED_STAGING,
            approved_profile_id="authorized_staging_authenticated_probe_v1",
        )
    )
    assert ProgressionRejection.ILLEGAL_TIER_SKIP in decision.rejection_reasons


# --------------------------------------------------------------------------- #
# Opaque references + secret store.
# --------------------------------------------------------------------------- #


def test_credential_and_session_uris_are_opaque() -> None:
    store = OpaqueSecretStore()
    credential = _credential(store)
    assert credential.credential_uri == f"credentialref://{TARGET_REF}/cred-0000000000000abc"
    assert CRED_VALUE not in credential.model_dump_json()


def test_secret_store_revoke_zeroizes() -> None:
    store = OpaqueSecretStore()
    store.put("secret-0000000000000fff", "value")  # noqa: S106 - offline fixture
    assert store.resolve("secret-0000000000000fff") == "value"
    store.revoke("secret-0000000000000fff")
    assert not store.is_resolvable("secret-0000000000000fff")
    with pytest.raises(StagingReferenceError):
        store.resolve("secret-0000000000000fff")


# --------------------------------------------------------------------------- #
# Session worker: controls + binding + lifecycle.
# --------------------------------------------------------------------------- #


def _worker(store: OpaqueSecretStore) -> SessionWorker:
    app = SyntheticStagingApp(origin=ORIGIN, valid_credential_value=CRED_VALUE)
    return SessionWorker(store, app)


def test_session_acquisition_runs_controls() -> None:
    store = OpaqueSecretStore()
    credential = _credential(store)
    worker = _worker(store)
    result = worker.acquire_session(
        credential, policy=SessionPolicy(bound_origin=ORIGIN, max_lifetime_seconds=300), now=NOW
    )
    assert result.control_outcome.positive_control_authenticated
    assert result.control_outcome.negative_control_rejected
    assert result.control_outcome.redirect_escape_blocked
    # The returned session reference carries no material value.
    assert "material" not in result.session_reference.model_dump_json().lower()


def test_authenticated_use_then_cross_origin_blocked() -> None:
    store = OpaqueSecretStore()
    worker = _worker(store)
    session = worker.acquire_session(
        _credential(store),
        policy=SessionPolicy(bound_origin=ORIGIN, max_lifetime_seconds=300),
        now=NOW,
    ).session_reference
    ok = worker.use_session(session, origin=ORIGIN, now=NOW + timedelta(seconds=1))
    assert ok.authenticated and ok.status_code == 200
    with pytest.raises(StagingReferenceError):
        worker.use_session(session, origin="https://evil.local", now=NOW + timedelta(seconds=1))


def test_expired_session_blocked() -> None:
    store = OpaqueSecretStore()
    worker = _worker(store)
    session = worker.acquire_session(
        _credential(store),
        policy=SessionPolicy(bound_origin=ORIGIN, max_lifetime_seconds=60),
        now=NOW,
    ).session_reference
    with pytest.raises(StagingReferenceError):
        worker.use_session(session, origin=ORIGIN, now=NOW + timedelta(hours=1))


def test_revoked_session_blocked_and_zeroized() -> None:
    store = OpaqueSecretStore()
    worker = _worker(store)
    session = worker.acquire_session(
        _credential(store),
        policy=SessionPolicy(bound_origin=ORIGIN, max_lifetime_seconds=300),
        now=NOW,
    ).session_reference
    worker.revoke_session(session)
    assert not store.is_resolvable(session.secret_ref_id)
    with pytest.raises(StagingReferenceError):
        worker.use_session(session, origin=ORIGIN, now=NOW + timedelta(seconds=1))


def test_credential_origin_binding_mismatch() -> None:
    store = OpaqueSecretStore()
    worker = _worker(store)  # app bound to ORIGIN
    with pytest.raises(StagingReferenceError):
        worker.acquire_session(
            _credential(store),
            policy=SessionPolicy(bound_origin="https://other.local", max_lifetime_seconds=300),
            now=NOW,
        )


def test_expired_credential_cannot_acquire() -> None:
    store = OpaqueSecretStore()
    worker = _worker(store)
    credential = _credential(store, expires_minutes=1)
    with pytest.raises(StagingReferenceError):
        worker.acquire_session(
            credential,
            policy=SessionPolicy(bound_origin=ORIGIN, max_lifetime_seconds=300),
            now=NOW + timedelta(minutes=5),
        )


def test_cross_target_credential_value_cannot_authenticate() -> None:
    # A credential whose secret value is wrong for the app never authenticates (positive control
    # fails), so a reference minted for a different target/value cannot be used here.
    store = OpaqueSecretStore()
    worker = _worker(store)
    bad = _credential(store, value="wrong-value")  # noqa: S106 - offline fixture
    with pytest.raises(StagingReferenceError):
        worker.acquire_session(
            bad, policy=SessionPolicy(bound_origin=ORIGIN, max_lifetime_seconds=300), now=NOW
        )


# --------------------------------------------------------------------------- #
# Projection secret redaction.
# --------------------------------------------------------------------------- #


def test_projection_is_metadata_only() -> None:
    store = OpaqueSecretStore()
    credential = _credential(store)
    projection = build_staging_projection(
        target_ref=TARGET_REF,
        environment_tier=EnvironmentTier.ISOLATED_STAGING,
        credential=credential,
        session=None,
        authorized=True,
    )
    assert projection["authorized_credential_reference_present"] is True
    assert CRED_VALUE not in str(projection)


def test_projection_rejects_forbidden_token() -> None:
    with pytest.raises(StagingRejection):
        assert_staging_projection_clean({"leak": "Bearer abc.def.ghi"})
    with pytest.raises(StagingRejection):
        assert_staging_projection_clean({"h": "Set-Cookie: session=1"})


# --------------------------------------------------------------------------- #
# Capability activation state.
# --------------------------------------------------------------------------- #


def test_capability_state() -> None:
    assert (
        staging_capability_state(EnvironmentTier.SYNTHETIC_RANGE, gates_satisfied=True)
        is StagingActivationState.SYNTHETIC_ACTIVE
    )
    assert (
        staging_capability_state(EnvironmentTier.ISOLATED_STAGING, gates_satisfied=True)
        is StagingActivationState.ISOLATED_STAGING_ACTIVE
    )
    assert (
        staging_capability_state(EnvironmentTier.AUTHORIZED_STAGING, gates_satisfied=True)
        is StagingActivationState.DEPLOYMENT_DISABLED
    )
    assert (
        staging_capability_state(EnvironmentTier.ISOLATED_STAGING, gates_satisfied=False)
        is StagingActivationState.DEPLOYMENT_DISABLED
    )


# --------------------------------------------------------------------------- #
# Ledger + audit events.
# --------------------------------------------------------------------------- #


def test_ledger_records_progression_reference_and_events(tmp_path: Path) -> None:
    ledger = StagingLedger(str(tmp_path / "staging.db"))
    ledger.initialize()
    request = _request()
    decision = evaluate_progression(request)
    ledger.record_progression(request, decision)

    store = OpaqueSecretStore()
    credential = _credential(store)
    uri = ledger.record_reference("phase-2.5-test", "CREDENTIAL", credential)
    assert uri == credential.credential_uri
    with pytest.raises(StagingReferenceError):
        ledger.record_reference("phase-2.5-test", "CREDENTIAL", credential)

    event = StagingAuditEvent(
        event_id="stgevt-0000000000000abc",
        campaign_id="phase-2.5-test",
        event_type="SESSION_ACQUIRED",
        environment_tier=EnvironmentTier.ISOLATED_STAGING,
        reference_uri=credential.credential_uri,
        summary="acquired opaque session (positive+negative controls held)",
    )
    ledger.record_event(event)
    events = ledger.events("phase-2.5-test")
    assert len(events) == 1
    assert events[0].event_type == "SESSION_ACQUIRED"
    # No value leaks into the ledger row.
    assert CRED_VALUE not in events[0].model_dump_json()


# --------------------------------------------------------------------------- #
# Offline harness verdict.
# --------------------------------------------------------------------------- #


def test_offline_harness_verdict_passes() -> None:
    harness = _load_harness()
    result = harness.run_offline()
    verdict = result["verdict"]
    assert verdict["authenticated_progression_framework_status"] == "OFFLINE_PASS"
    assert verdict["live_authenticated_staging_status"] == "NOT_EVALUATED"
    assert verdict["passed"] is True
    assert all(verdict["checks"].values())
