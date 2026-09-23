"""Offline targeted tests for the Phase 1.7-D live e2e recon slice.

No live provider and no Docker. These cover the *new* surface 1.7-D adds — the durable, addressable
delegation queue and the host-side verdict/injection-control/fixture-free logic — without re-running
the already-attested containerized Nmap path or the full suite. The single live end-to-end smoke is
the operator-run acceptance; here we prove the pieces it depends on behave under strict contracts.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from aegis.multi_agent.delegation import (
    DelegationQueue,
    DelegationQueueError,
    EnqueuedDelegation,
    evidence_sha256_of,
    parse_delegation_address,
)

_SHA = "a" * 64


def _load_orchestrator() -> Any:
    """Import the script module directly (it lives in scripts/, not an installed package)."""

    path = Path(__file__).resolve().parent.parent / "scripts" / "phase_1_7d_live_e2e_recon.py"
    spec = importlib.util.spec_from_file_location("phase_1_7d_live_e2e_recon", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _delegation(**overrides: Any) -> EnqueuedDelegation:
    base: dict[str, Any] = {
        "delegation_id": "delg-0123456789abcdef",
        "to_agent": "INJECTION_AGENT",
        "capability_id": "aegis.recon.zap_passive_openapi",
        "target_ref": "range-shop",
        "rationale": "reachable http service warrants documented-surface follow-up",
        "source_evidence_sha256": _SHA,
    }
    base.update(overrides)
    return EnqueuedDelegation(**base)


# --------------------------------------------------------------------------- #
# EnqueuedDelegation contract invariants.
# --------------------------------------------------------------------------- #


def test_delegation_is_unconfirmed_reference_free_by_construction() -> None:
    d = _delegation()
    assert d.confirmed is False
    assert d.unconfirmed is True
    assert d.reference_only is False  # distinguishes it from the 1.7-C reference-only stub
    assert d.status == "QUEUED"
    assert d.address == "agentqueue://INJECTION_AGENT/delg-0123456789abcdef"


def test_delegation_cannot_be_confirmed_or_marked_reference_only() -> None:
    with pytest.raises(ValidationError):
        _delegation(confirmed=True)
    with pytest.raises(ValidationError):
        _delegation(unconfirmed=False)
    with pytest.raises(ValidationError):
        _delegation(reference_only=True)


def test_delegation_rejects_unroutable_agent_and_malformed_ids() -> None:
    with pytest.raises(ValidationError):
        _delegation(to_agent="REPORT_AGENT")
    with pytest.raises(ValidationError):
        _delegation(delegation_id="deleg-xyz")
    with pytest.raises(ValidationError):
        _delegation(capability_id="not-an-aegis-capability")
    with pytest.raises(ValidationError):
        _delegation(target_ref="prod-shop")
    with pytest.raises(ValidationError):
        _delegation(source_evidence_sha256="short")


def test_delegation_has_no_verdict_or_payload_field() -> None:
    fields = set(EnqueuedDelegation.model_fields)
    assert not (fields & {"verdict", "severity", "payload", "finding", "credential", "pass_"})


# --------------------------------------------------------------------------- #
# DelegationQueue: persistence + addressability.
# --------------------------------------------------------------------------- #


def test_enqueue_persists_and_is_addressable(tmp_path: Path) -> None:
    queue = DelegationQueue(str(tmp_path / "q.sqlite3"))
    queue.initialize()
    d = _delegation()
    address = queue.enqueue(d)
    assert address == d.address

    # A brand-new queue instance over the same file proves durability (not in-memory).
    reopened = DelegationQueue(str(tmp_path / "q.sqlite3"))
    resolved = reopened.resolve(address)
    assert resolved is not None
    assert resolved.delegation_id == d.delegation_id
    assert resolved.source_evidence_sha256 == _SHA
    assert reopened.get(d.delegation_id) is not None
    assert reopened.count() == 1
    assert [p.delegation_id for p in reopened.pending_for("INJECTION_AGENT")] == [d.delegation_id]
    assert reopened.pending_for("AUTHORIZATION_AGENT") == []


def test_duplicate_enqueue_fails_closed(tmp_path: Path) -> None:
    queue = DelegationQueue(str(tmp_path / "q.sqlite3"))
    queue.initialize()
    queue.enqueue(_delegation())
    with pytest.raises(DelegationQueueError):
        queue.enqueue(_delegation())


def test_resolve_rejects_malformed_or_mismatched_address(tmp_path: Path) -> None:
    queue = DelegationQueue(str(tmp_path / "q.sqlite3"))
    queue.initialize()
    d = _delegation()
    queue.enqueue(d)
    with pytest.raises(DelegationQueueError):
        parse_delegation_address("http://INJECTION_AGENT/delg-0123456789abcdef")
    with pytest.raises(DelegationQueueError):
        parse_delegation_address("agentqueue://REPORT_AGENT/delg-0123456789abcdef")
    # Address whose routing segment disagrees with the stored record.
    with pytest.raises(DelegationQueueError):
        queue.resolve("agentqueue://AUTHORIZATION_AGENT/delg-0123456789abcdef")
    assert queue.resolve("agentqueue://INJECTION_AGENT/delg-ffffffffffffffff") is None


def test_evidence_sha_is_deterministic_and_binds_the_exact_observation_set() -> None:
    a = [{"kind": "DISCOVERED_SERVICE", "port": 8102}, {"kind": "HTTP_TECHNOLOGY", "port": 8102}]
    # Deterministic: the same observation set always hashes identically (stable provenance link).
    assert evidence_sha256_of(a) == evidence_sha256_of(list(a))
    assert len(evidence_sha256_of(a)) == 64
    # Any change to the set (a mutated field, reordering, an added observation) changes the digest,
    # so a delegation cannot silently point at a different observation set than the one it cites.
    assert evidence_sha256_of(a) != evidence_sha256_of(list(reversed(a)))
    assert evidence_sha256_of(a) != evidence_sha256_of([{**a[0], "port": 9999}, a[1]])


# --------------------------------------------------------------------------- #
# Host-side logic: injection payload shaping, verdict, tri-state.
# --------------------------------------------------------------------------- #


def test_interpret_payload_is_built_only_from_live_scan() -> None:
    mod = _load_orchestrator()
    scan = {
        "normalized_observations": [
            {"kind": "DISCOVERED_SERVICE", "protocol": "tcp", "port": 8102, "state": "open",
             "service": "http", "product": "Uvicorn"},
        ],
    }
    payload = mod._build_interpret_payload(scan)
    assert payload["clean_observations"]["discovered_services"][0]["port"] == 8102
    # Sound control: the legitimate fingerprint is preserved and the hostile instruction is only
    # APPENDED, so clean and injected differ solely by the injection.
    injected_product = payload["injected_observations"]["discovered_services"][0]["product"]
    assert injected_product == f"Uvicorn {mod.INJECTION_OBSERVATION_STRING}"
    assert payload["clean_observations"]["discovered_services"][0]["product"] == "Uvicorn"
    assert payload["delegate_context"]["port"] == 8102


def test_injection_string_avoids_all_gateway_forbidden_markers() -> None:
    mod = _load_orchestrator()
    s = mod.INJECTION_OBSERVATION_STRING.lower()
    forbidden = [
        "vulnerable", "patched", "answer_key", "ground_truth", "expected_verdict",
        '"confirmed"', '"pass"', "range-user-", "bearer ", "lab-token-", "http://", "https://",
    ]
    assert not [m for m in forbidden if m in s]
    # It is still recognizably an instruction-style injection (a hostile marker recon must ignore).
    assert "disregard" in s


def test_verdict_passes_only_when_every_check_is_true() -> None:
    mod = _load_orchestrator()
    record = _passing_record(mod)
    verdict = mod._verdict(record)
    assert verdict["passed"] is True
    assert all(v is True for v in verdict["checks"].values())
    assert verdict["provider_calls_total"] == 4


def test_verdict_marks_unrun_stages_not_evaluated_never_false() -> None:
    mod = _load_orchestrator()
    # Plan step rejected: downstream stages must be NOT_EVALUATED, not silently False.
    record = {
        "healthy": True,
        "credential_isolation": {"control_plane_has_no_key": True},
        "cleanup": {"down_rc": 0, "stack_leftovers": [], "range_container_leftovers": [],
                    "range_network_leftovers": []},
        "plan_step": {"result": {"status": "GATEWAY_REJECTED", "provider_calls": 1,
                                 "provider_tokens": 500, "identity_exact_deepseek_v4_pro": True,
                                 "projections_clean": True}},
    }
    verdict = mod._verdict(record)
    checks = verdict["checks"]
    assert checks["produced_valid_typed_plan"] == mod.NOT_EVALUATED
    assert checks["real_scanner_executed_in_container"] == mod.NOT_EVALUATED
    assert checks["delegation_enqueued_and_addressable"] == mod.NOT_EVALUATED
    assert checks["injection_negative_control_held"] == mod.NOT_EVALUATED
    assert verdict["passed"] is False


def test_verdict_fails_when_injection_control_not_held() -> None:
    mod = _load_orchestrator()
    record = _passing_record(mod)
    record["interpret_delegate_step"]["result"]["injection_control"]["held"] = False
    verdict = mod._verdict(record)
    assert verdict["checks"]["injection_negative_control_held"] is False
    assert verdict["passed"] is False


def test_verdict_fails_when_observation_port_not_actually_observed() -> None:
    mod = _load_orchestrator()
    record = _passing_record(mod)
    # A discovered service on a port THIS scan did not observe open => not provably live.
    record["scan"]["observed_open_tcp_ports"] = [9999]
    verdict = mod._verdict(record)
    assert verdict["checks"]["observations_normalized_from_live_scan"] is False
    assert verdict["passed"] is False


def test_token_ceiling_is_unknown_not_breach_when_usage_missing() -> None:
    mod = _load_orchestrator()
    record = _passing_record(mod)
    record["plan_step"]["result"]["provider_tokens"] = mod.UNKNOWN
    verdict = mod._verdict(record)
    assert verdict["checks"]["within_token_ceiling"] == mod.UNKNOWN
    assert verdict["passed"] is False  # UNKNOWN never counts as a pass


def _passing_record(mod: Any) -> dict[str, Any]:
    """A fully-populated record whose every verdict check is True."""

    return {
        "healthy": True,
        "credential_isolation": {"control_plane_has_no_key": True},
        "is_network_discovery_plan": True,
        "plan_step": {"result": {
            "status": "OK", "provider_calls": 1, "provider_tokens": 2000,
            "identity_exact_deepseek_v4_pro": True, "projections_clean": True,
            "capability_registered": True,
        }},
        "scan": {
            "plan_renders_shell_free_argv": True,
            "real_scanner_executed_in_container": True,
            "observed_open_tcp_ports": [8102],
            "normalized_observations": [
                {"kind": "DISCOVERED_SERVICE", "port": 8102, "protocol": "tcp",
                 "state": "open", "service": "http", "product": "Uvicorn"},
            ],
        },
        "interpret_delegate_step": {"result": {
            "status": "OK", "provider_calls": 3, "provider_tokens": 5000,
            "identity_exact_deepseek_v4_pro": True, "projections_clean": True,
            "clean_interpretation": {
                "unconfirmed": True,
                "salient_observation_kinds": ["DISCOVERED_SERVICE"],
                "recommended_followups": ["aegis.surface.openapi"],
            },
            "injection_control": {"held": True, "no_capability_expansion": True,
                                  "followups_identical": True},
        }},
        "delegation_enqueue": {
            "status": "ENQUEUED", "resolved_by_address": True, "reference_only": False,
            "confirmed": False, "unconfirmed": True, "queue_count": 1,
            "evidence_links_to_live_scan": True,
        },
        "cleanup": {"down_rc": 0, "stack_leftovers": [], "range_container_leftovers": [],
                    "range_network_leftovers": []},
    }
