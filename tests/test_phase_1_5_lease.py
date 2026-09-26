"""Phase 1.5 — the authenticated single-use activation lease: crypto, registry lifecycle,
concurrency, restart, redaction and secret isolation.

These tests exercise the exact properties the Phase 1.5 lease contract requires (prompt section 1
and 2): a valid signature alone never executes anything — the lease must additionally be ARMED in
the runner's root-owned registry — and every refusal is one bounded :class:`LeaseRejected` code.
No test here needs a runner subprocess, a guard or a target; the executor-facing behaviours
(unarmed token, second execution, guard/runner binding disagreement, stop-before-spawn) live in
``test_phase_1_5.py``, and the countersign drift matrix lives in
``test_phase_1_5_countersign.py``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import inspect
import json
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError
from zap_active_fakes import ADMISSION_TEST_SECRET, signed_lease_token

from aegis_zap_active.contracts import LeaseState, ZapActiveLeaseStatusResponse
from aegis_zap_active.inventory import target_for_variant
from aegis_zap_active.lease import (
    AUDIENCE,
    CLAIM_NAMES,
    MAX_CLOCK_SKEW_SECONDS,
    MAX_TOKEN_BYTES,
    MIN_SECRET_BYTES,
    PLACEHOLDER_SECRETS,
    TOKEN_PREFIX,
    LeaseBinding,
    LeaseClaims,
    LeaseRejected,
    canonical_claims,
    normalize_secret,
    sign_lease,
    verify_lease,
)
from aegis_zap_active.manifest import manifest_digest
from aegis_zap_active.projection import project
from zap_active_admission.contracts import ConsumeRequest
from zap_active_admission.registry import AdmissionRegistry

CAPABILITY = "zap_active_reflected_xss_v1"
PROFILE = "ZAP_LAB_ACTIVE_REFLECTED_XSS_V1"
VULN = target_for_variant("vulnerable")
PATCHED = target_for_variant("patched")
VULN_PROJECTION = project(VULN)
PATCHED_PROJECTION = project(PATCHED)


def _binding(
    *,
    target: Any = VULN,
    projection: Any = None,
    audience: str = AUDIENCE,
    manifest_digest_value: str | None = None,
) -> LeaseBinding:
    projection = projection if projection is not None else VULN_PROJECTION
    return LeaseBinding(
        capability_id=CAPABILITY,
        profile_id=PROFILE,
        target_ref=target.target_ref,
        target_origin=target.origin,
        projection_digest=projection.digest,
        allowlist_digest=projection.allowlist_digest,
        manifest_digest=manifest_digest_value or manifest_digest(),
        audience=audience,
    )


def _mint(**overrides: Any) -> tuple[str, LeaseClaims]:
    return signed_lease_token(target=VULN, projection=VULN_PROJECTION, **overrides)


def _resign(claims_dict: dict[str, Any], secret: str) -> str:
    payload = base64.urlsafe_b64encode(canonical_claims(claims_dict)).decode().rstrip("=")
    signed = f"{TOKEN_PREFIX}.{payload}"
    mac = hmac.new(secret.encode(), signed.encode("ascii"), hashlib.sha256).digest()
    return f"{signed}.{base64.urlsafe_b64encode(mac).decode().rstrip('=')}"


def _resign_bytes(payload_bytes: bytes) -> str:
    payload = base64.urlsafe_b64encode(payload_bytes).decode().rstrip("=")
    signed = f"{TOKEN_PREFIX}.{payload}"
    mac = hmac.new(ADMISSION_TEST_SECRET.encode(), signed.encode("ascii"), hashlib.sha256).digest()
    return f"{signed}.{base64.urlsafe_b64encode(mac).decode().rstrip('=')}"


# --- the signed-claims format -----------------------------------------------------------------


def test_valid_token_verifies_against_its_exact_binding() -> None:
    token, claims = _mint()
    verified = verify_lease(token, ADMISSION_TEST_SECRET, binding=_binding())
    assert verified == claims
    assert verified.audience == AUDIENCE
    assert verified.lease_id == claims.lease_id
    assert verified.nonce == claims.nonce
    assert token.startswith(f"{TOKEN_PREFIX}.")
    assert len(token) <= MAX_TOKEN_BYTES


def test_malformed_and_unknown_format_tokens_are_rejected() -> None:
    token, _ = _mint()
    with pytest.raises(LeaseRejected) as empty:
        verify_lease("", ADMISSION_TEST_SECRET, binding=_binding())
    assert empty.value.code == "LEASE_REQUIRED"
    for malformed in (
        token.split(".")[0],  # no payload or signature
        f"{token}.extra",  # four parts
        token + "x" * (MAX_TOKEN_BYTES + 1),  # oversized
        f"JWT.{token.split('.')[1]}.{token.split('.')[2]}",  # wrong prefix
        f"{TOKEN_PREFIX}.!!!!!.{token.split('.')[2]}",  # non-alphabet payload
        f"{TOKEN_PREFIX}.{token.split('.')[1]}.!!!!!",  # non-alphabet signature
    ):
        with pytest.raises(LeaseRejected) as refused:
            verify_lease(malformed, ADMISSION_TEST_SECRET, binding=_binding())
        assert refused.value.code in {
            "LEASE_MALFORMED",
            "LEASE_UNKNOWN_FORMAT",
        }, (malformed, refused.value.code)


def test_signature_tampering_is_rejected() -> None:
    token, _ = _mint()
    prefix, payload, signature = token.split(".")
    # Flip one payload byte: the MAC no longer matches (or the payload stops decoding).
    raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    flipped = base64.urlsafe_b64encode(bytes([raw[0] ^ 0x01, *raw[1:]])).decode().rstrip("=")
    # Flip one signature byte. NB: appending a char (e.g. signature[:-1]+"x") is NOT reliable — the
    # final base64 char carries only some significant bits, so a swap can decode to identical bytes
    # and leave the signature valid. Decode/flip/re-encode always alters the MAC deterministically.
    sig_raw = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
    sig_flipped = bytes([sig_raw[0] ^ 0xFF, *sig_raw[1:]])
    tampered_sig = base64.urlsafe_b64encode(sig_flipped).decode().rstrip("=")
    for candidate in (
        f"{prefix}.{flipped}.{signature}",
        f"{prefix}.{payload}.{tampered_sig}",
    ):
        with pytest.raises(LeaseRejected) as refused:
            verify_lease(candidate, ADMISSION_TEST_SECRET, binding=_binding())
        assert refused.value.code in {"LEASE_SIGNATURE_INVALID", "LEASE_MALFORMED"}, (
            candidate,
            refused.value.code,
        )
    # A token signed with a different key is refused identically.
    token_other, _ = _mint(secret="a-different-signing-secret-0123456789abcdef")  # noqa: S106
    with pytest.raises(LeaseRejected) as refused:
        verify_lease(token_other, ADMISSION_TEST_SECRET, binding=_binding())
    assert refused.value.code == "LEASE_SIGNATURE_INVALID"


def test_claim_insertion_and_removal_are_rejected_even_when_re_signed() -> None:
    """The exact claim set is a contract: even a party holding the signing secret cannot widen or
    narrow a lease by adding or dropping a claim — the runner rejects the exact-set violation."""
    _, claims = _mint()
    base = claims.model_dump(mode="json")
    inserted = {**base, "privileged": True}
    with pytest.raises(LeaseRejected) as added:
        verify_lease(
            _resign(inserted, ADMISSION_TEST_SECRET), ADMISSION_TEST_SECRET, binding=_binding()
        )
    assert added.value.code == "LEASE_CLAIMS_INVALID"
    removed = {key: value for key, value in base.items() if key != "budget_id"}
    with pytest.raises(LeaseRejected) as missing:
        verify_lease(
            _resign(removed, ADMISSION_TEST_SECRET), ADMISSION_TEST_SECRET, binding=_binding()
        )
    assert missing.value.code == "LEASE_CLAIMS_INVALID"


def test_non_canonical_encodings_are_rejected() -> None:
    """Sorted keys, no whitespace, no duplicate keys: exactly one encoding per claim set."""
    _, claims = _mint()
    raw = claims.canonical().decode()
    # Whitespace inside the signed payload: decodes fine, but is not the canonical serialization.
    with pytest.raises(LeaseRejected) as spaced:
        verify_lease(
            _resign_bytes(raw.replace(",", ", ").encode()),
            ADMISSION_TEST_SECRET,
            binding=_binding(),
        )
    assert spaced.value.code == "LEASE_NOT_CANONICAL"
    # A duplicated JSON key (last-wins in most parsers) is refused outright.
    lease_id = claims.lease_id
    duplicated = raw.replace(
        f'"lease_id":"{lease_id}"', f'"lease_id":"{lease_id}","lease_id":"{lease_id}"'
    )
    with pytest.raises(LeaseRejected) as dup:
        verify_lease(
            _resign_bytes(duplicated.encode()), ADMISSION_TEST_SECRET, binding=_binding()
        )
    assert dup.value.code == "LEASE_NOT_CANONICAL"


def test_claim_values_outside_the_contract_are_refused() -> None:
    for override in (
        {"lease_id": "not-a-lease-id"},
        {"budget_id": "arbitrary-budget"},
        {"target_origin": "file:///etc/passwd"},
        {"nonce": "short"},
        {"projection_digest": "z" * 64},
        {"expires_at": 12_345},  # outside the sane epoch window
    ):
        with pytest.raises(ValidationError):
            _mint(**override)


def test_wrong_audience_is_rejected() -> None:
    token, _ = _mint(audience="some-other-runner")
    with pytest.raises(LeaseRejected) as refused:
        verify_lease(token, ADMISSION_TEST_SECRET, binding=_binding())
    assert refused.value.code == "LEASE_AUDIENCE_MISMATCH"


def test_wrong_capability_profile_target_or_origin_are_rejected() -> None:
    mismatches = (
        {"capability_id": "zap_active_sql_injection_v1"},
        {"profile_id": "ZAP_LAB_PASSIVE_OPENAPI_V1"},
        {"target_ref": PATCHED.target_ref},
        {"target_origin": "http://evil.example:8001"},
    )
    for override in mismatches:
        token, _ = _mint(**override)
        # The caller's binding describes the real target; the claim names another -> mismatch.
        with pytest.raises(LeaseRejected) as refused:
            verify_lease(token, ADMISSION_TEST_SECRET, binding=_binding())
        assert refused.value.code == "LEASE_BINDING_MISMATCH", override


def test_digest_binding_mismatches_are_rejected() -> None:
    for override in (
        {"projection_digest": "f" * 64},
        {"allowlist_digest": "e" * 64},
        {"manifest_digest_value": "d" * 64},
    ):
        token, _ = _mint(**override)
        with pytest.raises(LeaseRejected) as refused:
            verify_lease(token, ADMISSION_TEST_SECRET, binding=_binding())
        assert refused.value.code == "LEASE_BINDING_MISMATCH", override


def test_expired_not_yet_valid_and_excessive_lifetime_are_rejected() -> None:
    token, _ = _mint(offset=-2_000, lifetime=600)
    with pytest.raises(LeaseRejected) as expired:
        verify_lease(token, ADMISSION_TEST_SECRET, binding=_binding())
    assert expired.value.code == "LEASE_EXPIRED"
    token, _ = _mint(offset=+300, lifetime=600)
    with pytest.raises(LeaseRejected) as future:
        verify_lease(token, ADMISSION_TEST_SECRET, binding=_binding())
    assert future.value.code == "LEASE_NOT_YET_VALID"
    token, _ = _mint(lifetime=901)
    with pytest.raises(LeaseRejected) as long_lived:
        verify_lease(token, ADMISSION_TEST_SECRET, binding=_binding())
    assert long_lived.value.code == "LEASE_LIFETIME_EXCESSIVE"
    # The 15-minute ceiling applies from issuance too, not only from not_before.
    now = int(datetime.now(UTC).timestamp())
    token, _ = _mint(issued_at=now - 1_000, not_before=now - 900, expires_at=now + 10)
    with pytest.raises(LeaseRejected) as stretched:
        verify_lease(token, ADMISSION_TEST_SECRET, binding=_binding())
    assert stretched.value.code == "LEASE_LIFETIME_EXCESSIVE"


def test_clock_skew_is_bounded_and_explicit() -> None:
    now = datetime.now(UTC)
    assert MAX_CLOCK_SKEW_SECONDS == 60  # the offsets below straddle this bound deliberately
    claims = LeaseClaims.model_validate(
        {
            **_mint()[1].model_dump(mode="json"),
            "issued_at": int(now.timestamp()) - 10,
            "not_before": int(now.timestamp()) + 50,
            "expires_at": int(now.timestamp()) + 600,
        }
    )
    token = sign_lease(claims, ADMISSION_TEST_SECRET)
    # A clock behind the lease's not_before is tolerated inside the skew window...
    verify_lease(token, ADMISSION_TEST_SECRET, binding=_binding(), now=now)
    # ...and 12 seconds behind refuses: the lease is not yet valid.
    with pytest.raises(LeaseRejected) as early:
        verify_lease(
            token, ADMISSION_TEST_SECRET, binding=_binding(), now=now - timedelta(seconds=12)
        )
    assert early.value.code == "LEASE_NOT_YET_VALID"
    # Symmetrically on expiry: 59 seconds of skew are tolerated, 61 are not.
    verify_lease(
        token,
        ADMISSION_TEST_SECRET,
        binding=_binding(),
        now=now + timedelta(seconds=600 + 59),
    )
    with pytest.raises(LeaseRejected) as late:
        verify_lease(
            token, ADMISSION_TEST_SECRET, binding=_binding(), now=now + timedelta(seconds=600 + 61)
        )
    assert late.value.code == "LEASE_EXPIRED"


def test_the_algorithm_is_fixed_not_selected() -> None:
    """No ``alg`` field exists anywhere in the claim set, and the prefix is compared for exact
    equality — there is no algorithm selector a caller could point at 'none'."""
    assert "alg" not in CLAIM_NAMES
    assert CLAIM_NAMES == tuple(sorted(CLAIM_NAMES))
    assert len(set(CLAIM_NAMES)) == len(CLAIM_NAMES)
    _, claims = _mint()
    assert "alg" not in claims.model_dump()


def test_there_is_no_unsigned_mode_or_fallback() -> None:
    token, _ = _mint()
    prefix, payload, _ = token.split(".")
    with pytest.raises(LeaseRejected) as unsigned:
        verify_lease(f"{prefix}.{payload}.", ADMISSION_TEST_SECRET, binding=_binding())
    assert unsigned.value.code == "LEASE_MALFORMED"
    # verify_lease has no keyword that could switch verification off, and the runner has no
    # "lease optional" mode: the executor refuses to execute without an admission client.
    parameters = inspect.signature(verify_lease).parameters
    assert not any("skip" in name or "off" in name or "disable" in name for name in parameters)


# --- the armed-lease registry -----------------------------------------------------------------


def _registry(tmp_path: Path) -> AdmissionRegistry:
    state_file = tmp_path / "admission" / "leases.json"
    return AdmissionRegistry(ADMISSION_TEST_SECRET, state_file=state_file)


def _arm(registry: AdmissionRegistry, **overrides: Any) -> tuple[str, LeaseClaims]:
    token, claims = _mint(**overrides)
    registry.arm(token)
    return token, claims


def _consume(
    registry: AdmissionRegistry,
    token: str,
    *,
    execution_id: str = "exec-0000000000aa",
    **overrides: Any,
) -> Any:
    fields: dict[str, Any] = {
        "token": token,
        "execution_id": execution_id,
        "capability_id": CAPABILITY,
        "profile_id": PROFILE,
        "target_ref": VULN.target_ref,
        "target_origin": VULN.origin,
        "projection_digest": VULN_PROJECTION.digest,
        "allowlist_digest": VULN_PROJECTION.allowlist_digest,
        "manifest_digest": manifest_digest(),
    }
    fields.update(overrides)
    return registry.consume(ConsumeRequest(**fields))


def test_arm_then_consume_is_the_only_authorized_path(tmp_path: Path) -> None:
    registry = _registry(tmp_path)
    token, claims = _arm(registry)
    armed = registry.armed_record()
    assert armed is not None and armed.state is LeaseState.ARMED
    assert armed.lease_id == claims.lease_id
    record = _consume(registry, token)
    assert record.state is LeaseState.CONSUMED
    assert record.consumed_by == "exec-0000000000aa"
    assert registry.consumed_total == 1
    # The record is redacted: the nonce and the token never leave the boundary.
    dumped = record.model_dump(mode="json")
    assert "nonce" not in dumped and "token" not in dumped
    assert token not in json.dumps(dumped)


def test_a_valid_signature_alone_is_insufficient(tmp_path: Path) -> None:
    """The signature proves who issued the lease. Only the ARMED registry lets it execute."""
    registry = _registry(tmp_path)
    token, _ = _mint()
    with pytest.raises(LeaseRejected) as refused:
        _consume(registry, token)
    assert refused.value.code == "LEASE_NOT_ARMED"
    assert registry.rejected_total == 1


def test_second_execution_with_the_same_lease_is_rejected(tmp_path: Path) -> None:
    registry = _registry(tmp_path)
    token, _ = _arm(registry)
    _consume(registry, token)
    with pytest.raises(LeaseRejected) as reused:
        _consume(registry, token, execution_id="exec-0000000000ab")
    assert reused.value.code == "LEASE_ALREADY_CONSUMED"


def test_nonce_replay_across_leases_is_rejected(tmp_path: Path) -> None:
    registry = _registry(tmp_path)
    token, claims = _arm(registry)
    _consume(registry, token)
    # A second lease with the SAME nonce but a fresh lease id is refused at arm time.
    replay_token, replay_claims = _mint(lease_id="lease-ffffffffffffffff", nonce=claims.nonce)
    assert replay_claims.lease_id != claims.lease_id
    with pytest.raises(LeaseRejected) as replayed:
        registry.arm(replay_token)
    assert replayed.value.code == "LEASE_ALREADY_CONSUMED"


def test_revocation_before_execution_blocks_consume(tmp_path: Path) -> None:
    registry = _registry(tmp_path)
    token, claims = _arm(registry)
    revoked = registry.revoke(claims.lease_id, "operator_stop")
    assert revoked is not None and revoked.state is LeaseState.REVOKED
    assert revoked.termination_reason == "operator_stop"
    with pytest.raises(LeaseRejected) as refused:
        _consume(registry, token)
    assert refused.value.code == "LEASE_REVOKED"


def test_revocation_after_consume_is_terminal_and_a_completion_never_moves_it_back(
    tmp_path: Path,
) -> None:
    registry = _registry(tmp_path)
    token, claims = _arm(registry)
    _consume(registry, token)
    stopped = registry.revoke(claims.lease_id, "emergency_stop")
    assert stopped is not None and stopped.state is LeaseState.REVOKED
    assert stopped.termination_reason == "emergency_stop"
    # An in-flight completion revoking afterwards finds the REVOKED record and cannot overwrite it.
    later = registry.revoke(claims.lease_id, "execution_finished")
    assert later is not None and later.state is LeaseState.REVOKED
    assert later.termination_reason == "emergency_stop"


def test_concurrent_double_consume_has_exactly_one_winner(tmp_path: Path) -> None:
    registry = _registry(tmp_path)
    token, _ = _arm(registry)
    outcomes: list[str] = []
    barrier = threading.Barrier(2)

    def consume() -> None:
        barrier.wait()
        try:
            record = _consume(registry, token)
            outcomes.append(f"WIN:{record.state.value}")
        except LeaseRejected as refused:
            outcomes.append(f"LOSS:{refused.code}")

    threads = [threading.Thread(target=consume) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert sorted(outcomes) == ["LOSS:LEASE_ALREADY_CONSUMED", "WIN:CONSUMED"]
    assert registry.consumed_total == 1
    armed = registry.armed_record()
    assert armed is not None and armed.state is LeaseState.CONSUMED


def test_restart_revokes_armed_leases_and_blocks_replay(tmp_path: Path) -> None:
    registry = _registry(tmp_path)
    token, claims = _arm(registry)
    _consume(registry, token)
    # A new process over the same root-owned state: a consumed lease stays consumed (it can never
    # be re-consumed), and nothing survives armed.
    restarted = AdmissionRegistry(
        ADMISSION_TEST_SECRET, state_file=tmp_path / "admission" / "leases.json"
    )
    assert restarted.armed_record() is None
    assert restarted.restart_revoked_total == 0  # nothing was ARMED at restart
    recent = restarted.snapshot()["recent"]
    assert recent and recent[-1].lease_id == claims.lease_id
    assert recent[-1].state is LeaseState.CONSUMED
    # The consumed nonce survived the restart: the old token fails on the nonce before it even
    # reaches the (empty) armed slot, so a replay after restart fails twice over.
    with pytest.raises(LeaseRejected) as replayed:
        _consume(restarted, token)
    assert replayed.value.code == "LEASE_ALREADY_CONSUMED"
    replay_token, replay_claims = _mint(lease_id="lease-eeeeeeeeeeeeeeee", nonce=claims.nonce)
    assert replay_claims.lease_id != claims.lease_id
    with pytest.raises(LeaseRejected) as nonce:
        restarted.arm(replay_token)
    assert nonce.value.code == "LEASE_ALREADY_CONSUMED"
    # The registry is fully operational after a restart: a fresh lease arms and consumes.
    fresh, fresh_claims = _mint()
    restarted.arm(fresh)
    assert restarted.armed_record().lease_id == fresh_claims.lease_id  # type: ignore[union-attr]
    assert _consume(restarted, fresh).state is LeaseState.CONSUMED


def test_an_armed_lease_surviving_a_restart_is_revoked_not_kept(tmp_path: Path) -> None:
    registry = _registry(tmp_path)
    token, claims = _arm(registry)  # armed, never consumed
    restarted = AdmissionRegistry(
        ADMISSION_TEST_SECRET, state_file=tmp_path / "admission" / "leases.json"
    )
    assert restarted.armed_record() is None
    assert restarted.restart_revoked_total == 1
    recent = restarted.snapshot()["recent"]
    assert recent[-1].lease_id == claims.lease_id
    assert recent[-1].state is LeaseState.REVOKED
    with pytest.raises(LeaseRejected) as refused:
        _consume(restarted, token)
    assert refused.value.code == "LEASE_REVOKED"


def test_registry_fails_closed_without_rewriting_tampered_or_missing_durable_state(
    tmp_path: Path,
) -> None:
    registry = _registry(tmp_path)
    token, _ = _arm(registry)
    state_file = tmp_path / "admission" / "leases.json"
    original = state_file.read_bytes()
    state_file.write_bytes(original.replace(b'"integrity":"', b'"integrity":"0', 1))
    corrupted = AdmissionRegistry(ADMISSION_TEST_SECRET, state_file=state_file)
    assert not corrupted.healthy
    assert state_file.read_bytes() != original  # corrupted bytes stay available for diagnosis
    with pytest.raises(LeaseRejected, match="LEASE_REGISTRY_UNAVAILABLE"):
        corrupted.arm(token)

    # Once a volume has been initialized, a missing state file is loss/corruption, not a new lease
    # registry. It must not silently permit replay after a restart.
    state_file.unlink()
    missing = AdmissionRegistry(ADMISSION_TEST_SECRET, state_file=state_file)
    assert not missing.healthy
    with pytest.raises(LeaseRejected, match="LEASE_REGISTRY_UNAVAILABLE"):
        missing.arm(token)


def test_expiry_retires_an_armed_lease(tmp_path: Path) -> None:
    registry = _registry(tmp_path)
    token, claims = _arm(registry)
    past = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    assert registry._armed is not None  # noqa: SLF001 - simulate the clock passing
    registry._armed = registry._armed.model_copy(  # noqa: SLF001
        update={"expires_at": past}
    )
    assert registry.armed_record() is None
    with pytest.raises(LeaseRejected) as refused:
        _consume(registry, token)
    assert refused.value.code == "LEASE_NOT_ARMED"
    recent = registry.snapshot()["recent"]
    assert recent[-1].lease_id == claims.lease_id and recent[-1].state is LeaseState.EXPIRED


def test_arming_refuses_while_another_lease_is_armed(tmp_path: Path) -> None:
    registry = _registry(tmp_path)
    _arm(registry)
    second, _ = _mint(lease_id="lease-ffffffffffffffff")
    with pytest.raises(LeaseRejected) as busy:
        registry.arm(second)
    assert busy.value.code == "LEASE_REGISTRY_UNAVAILABLE"


def test_registry_fails_closed_on_unknown_capability_or_profile(tmp_path: Path) -> None:
    """The admission component admits exactly one capability on one profile and is not
    configurable into admitting another, however validly signed."""
    registry = _registry(tmp_path)
    for override in (
        {"capability_id": "some_other_capability"},
        {"profile_id": "ZAP_LAB_ACTIVE_SQL_INJECTION_V1"},
    ):
        token, _ = _mint(**override)
        with pytest.raises(LeaseRejected) as refused:
            registry.arm(token)
        assert refused.value.code == "LEASE_BINDING_MISMATCH", override


def test_consume_binding_is_enforced_against_runner_computed_facts(tmp_path: Path) -> None:
    """The runner recomputes target/origin/digests for itself; any disagreement refuses."""
    registry = _registry(tmp_path)
    token, _ = _arm(registry)
    for override, expected in (
        ({"target_ref": PATCHED.target_ref}, "LEASE_BINDING_MISMATCH"),
        ({"target_origin": "http://evil.example:8001"}, "LEASE_BINDING_MISMATCH"),
        ({"projection_digest": "a" * 64}, "LEASE_BINDING_MISMATCH"),
        ({"allowlist_digest": "b" * 64}, "LEASE_BINDING_MISMATCH"),
        ({"manifest_digest": "c" * 64}, "LEASE_BINDING_MISMATCH"),
        ({"profile_id": "ZAP_LAB_PASSIVE_OPENAPI_V1"}, "LEASE_BINDING_MISMATCH"),
        ({"capability_id": "zap_passive_header_openapi_v1"}, "LEASE_BINDING_MISMATCH"),
    ):
        with pytest.raises(LeaseRejected) as refused:
            _consume(registry, token, **override)
        assert refused.value.code == expected, override
    assert registry.armed_record() is not None  # still armed: the failed consume changed nothing
    assert registry.armed_record().state is LeaseState.ARMED  # type: ignore[union-attr]


def test_status_projection_is_redacted_and_bounded(tmp_path: Path) -> None:
    registry = _registry(tmp_path)
    token, _ = _arm(registry)
    snapshot = registry.snapshot()
    status = ZapActiveLeaseStatusResponse(
        admission_reachable=True,
        state_root_owned=snapshot["state_root_owned"],
        armed=snapshot["armed"],
        recent=snapshot["recent"],
        armed_total=snapshot["armed_total"],
        consumed_total=snapshot["consumed_total"],
        revoked_total=snapshot["revoked_total"],
        rejected_total=snapshot["rejected_total"],
        restart_revoked_total=snapshot["restart_revoked_total"],
    )
    dumped = status.model_dump_json()
    assert token not in dumped
    assert "nonce" not in dumped
    # Every field of the redacted record is bounded; nothing can carry a credential.
    for record in (status.armed, *status.recent):
        assert record is not None
        for name in ("token", "nonce", "signature", "secret"):
            assert not hasattr(record, name)
        json.dumps(record.model_dump(mode="json"))  # always serializable


def test_full_registry_history_stays_under_the_admission_response_bound(tmp_path: Path) -> None:
    """A registry holding its maximum history must still serialize under the bounded client's
    response ceiling — a full recent set can never look like an oversized hostile response."""
    from aegis_zap_active.contracts import MAX_ADMISSION_RESPONSE_BYTES, AdmissionStatus
    from zap_active_admission.registry import RECENT_LIMIT

    registry = _registry(tmp_path)
    for _ in range(RECENT_LIMIT):
        token, claims = _arm(registry)
        _consume(registry, token)
        registry.revoke(claims.lease_id, "execution_finished")
    snapshot = registry.snapshot()
    assert len(snapshot["recent"]) == RECENT_LIMIT
    status = AdmissionStatus.model_validate(
        {"schema_version": "aegis.zap.active-admission/1", **snapshot}
    )
    body = json.dumps(status.model_dump(mode="json")).encode()
    assert len(body) <= MAX_ADMISSION_RESPONSE_BYTES, len(body)


# --- secret isolation -------------------------------------------------------------------------


def test_normalize_secret_refuses_missing_empty_short_and_placeholder_secrets() -> None:
    for bad in (None, "", "   ", "a" * (MIN_SECRET_BYTES - 1), *PLACEHOLDER_SECRETS, "Changeme"):
        with pytest.raises(LeaseRejected) as refused:
            normalize_secret(bad)
        assert refused.value.code == "LEASE_SECRET_UNAVAILABLE", repr(bad)
    good = normalize_secret(ADMISSION_TEST_SECRET)
    assert len(good) >= MIN_SECRET_BYTES
    assert normalize_secret(b" " + ADMISSION_TEST_SECRET.encode() + b"\n") == good


def test_registry_refuses_construction_without_a_real_secret(tmp_path: Path) -> None:
    with pytest.raises(LeaseRejected):
        AdmissionRegistry("placeholder", state_file=tmp_path / "admission" / "leases.json")
    with pytest.raises(LeaseRejected):
        AdmissionRegistry("", state_file=tmp_path / "admission" / "leases.json")


def test_compose_places_the_lease_secret_only_in_controller_and_admission() -> None:
    """The signing secret may exist only in the controller and the root-owned admission component.
    The runner supervisor, the guard, ZAP and the lab must never receive it."""

    overlay = Path("docker-compose.zap-active.yml")
    compose = yaml.safe_load(overlay.read_text())
    secret_name = "AEGIS_ZAP_ACTIVE_LEASE_SECRET"  # noqa: S105 - an env var NAME, not a secret
    client_name = "AEGIS_ZAP_ACTIVE_ADMISSION_CLIENT"
    holders: set[str] = set()
    for service, definition in compose["services"].items():
        env = definition.get("environment", {}) or {}
        text = json.dumps(env)
        if secret_name in text:
            holders.add(service)
        if service == "zap-active-admission":
            assert secret_name in text  # the only runner-side holder
        if service == "zap-active-runner":
            assert client_name in text and secret_name not in text
        if service in {"zap-active-scope-guard", "lab-api"}:
            assert secret_name not in text, service
    assert holders == {"control-plane", "zap-active-admission"}
    # The secret comes from the operator's shell, never from a committed file: the reference is an
    # interpolation that fails closed when unset.
    for holder in holders:
        text = json.dumps(compose["services"][holder]["environment"])
        assert "${AEGIS_ZAP_ACTIVE_LEASE_SECRET:?" in text, holder
