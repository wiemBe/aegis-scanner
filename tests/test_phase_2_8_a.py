"""Offline focused tests for the Phase 2.8-A Recon Capability Pack.

No container, no live tool, no provider. These cover the controller-owned typed profiles, the
model-blind selection contract (no raw shell/argv/URL/wordlist/header/concurrency/timeout/redirect/
target override), deterministic argv rendering + the defence-in-depth denylist, scope/redirect/tier/
lease/provenance enforcement, untrusted-output sanitation, normalized observations + manifest, and
real persisted Recon->Injection delegation. Container/live execution is NOT_EVALUATED this phase.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest
from pydantic import ValidationError

from aegis.multi_agent.contracts import AgentRole
from aegis.multi_agent.delegation import DelegationQueue
from aegis.multi_agent.recon_capabilities import (
    CONTENT_WORDLISTS,
    RECON_PACK_CAPABILITY_IDS,
    RECON_PROFILES,
    NormalizedReconObservation,
    ReconCapabilityError,
    ReconDiscoveryPlan,
    ReconLease,
    ReconObservationKind,
    assert_container_pinned,
    build_discovery_job,
    build_manifest,
    build_recon_to_injection_delegation,
    persist_recon_to_injection_delegation,
    sanitize_tool_output,
)
from aegis.multi_agent.registry import authorize
from aegis.multi_agent.staging import EnvironmentTier

_ALL = [
    ("aegis.recon.http_probe", "http_probe_discovery_v1", "httpx"),
    ("aegis.recon.web_crawl", "web_crawl_bounded_v1", "katana"),
    ("aegis.recon.content_discovery", "content_discovery_bounded_v1", "ffuf"),
    ("aegis.recon.api_http_probe", "api_http_probe_v1", "httpx"),
    ("aegis.recon.dns_discovery", "dns_discovery_bounded_v1", "dnsx"),
    ("aegis.recon.tls_inspect", "tls_inspect_v1", "tlsx"),
]


def _plan(capability_id: str, profile_id: str, **o: object) -> ReconDiscoveryPlan:
    return ReconDiscoveryPlan(
        capability_id=capability_id,  # type: ignore[arg-type]
        profile_id=profile_id,  # type: ignore[arg-type]
        target_ref="range-shop",
        **o,
    )


# --------------------------------------------------------------------------- #
# Registry + role boundary (Tool Broker capabilities, not AI agents).
# --------------------------------------------------------------------------- #


def test_all_recon_pack_capabilities_authorized_for_recon_agent() -> None:
    for cid in RECON_PACK_CAPABILITY_IDS:
        authorize(AgentRole.RECON_AGENT, cid)  # must not raise
    assert set(RECON_PACK_CAPABILITY_IDS) == {c for _c, _p, _t in _ALL for c in [_c]}


def test_recon_capabilities_not_granted_to_other_roles() -> None:
    for cid in RECON_PACK_CAPABILITY_IDS:
        with pytest.raises(ValueError, match="CAPABILITY_NOT_AUTHORIZED"):
            authorize(AgentRole.INJECTION_AGENT, cid)


def test_sqlmap_is_not_a_recon_capability() -> None:
    assert not any("sqlmap" in cid for cid in RECON_PACK_CAPABILITY_IDS)
    with pytest.raises(ValueError, match="CAPABILITY_NOT_AUTHORIZED"):
        authorize(AgentRole.RECON_AGENT, "aegis.injection.sqlmap")


# --------------------------------------------------------------------------- #
# Deterministic rendering + bounds + redirect/scope fail-closed.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(("cid", "pid", "tool"), _ALL)
def test_each_profile_renders_bounded_shell_free_job(cid: str, pid: str, tool: str) -> None:
    job = build_discovery_job(_plan(cid, pid))
    assert job.argv[0] == tool
    assert job.redirect_policy == "DENY"
    assert job.scope_host == "aegis-shop"
    assert job.scope_host in " ".join(job.argv)
    profile = RECON_PROFILES[pid]
    assert job.max_requests == profile.max_requests
    assert job.max_concurrency == profile.max_concurrency
    assert job.max_output_bytes == profile.max_output_bytes
    # No shell metacharacters anywhere in the rendered argv.
    assert not ({";", "|", "&", "`", ">", "<"} & set("".join(job.argv)))


def test_http_argv_disables_redirects() -> None:
    job = build_discovery_job(_plan("aegis.recon.http_probe", "http_probe_discovery_v1"))
    assert "-disable-redirects" in job.argv
    assert "-fr" not in job.argv and "-L" not in job.argv


def test_rendering_is_deterministic() -> None:
    a = build_discovery_job(_plan("aegis.recon.http_probe", "http_probe_discovery_v1"))
    b = build_discovery_job(_plan("aegis.recon.http_probe", "http_probe_discovery_v1"))
    assert a.argv == b.argv and a.argv_digest == b.argv_digest and a.job_id == b.job_id


# --------------------------------------------------------------------------- #
# Model-blind selection contract: no raw override is representable.
# --------------------------------------------------------------------------- #


def test_plan_rejects_raw_overrides() -> None:
    for bad in (
        {"raw_url": "http://evil"},
        {"wordlist": ["a", "b"]},
        {"headers": {"X": "y"}},
        {"concurrency": 500},
        {"timeout_ms": 1},
        {"follow_redirects": True},
        {"argv": ["httpx", "-x", "http://evil"]},
    ):
        with pytest.raises(ValidationError):
            ReconDiscoveryPlan(
                capability_id="aegis.recon.http_probe",  # type: ignore[arg-type]
                profile_id="http_probe_discovery_v1",  # type: ignore[arg-type]
                target_ref="range-shop",
                **bad,  # type: ignore[arg-type]
            )


def test_profile_capability_mismatch_fails_closed() -> None:
    with pytest.raises(ReconCapabilityError, match="CAPABILITY_MISMATCH"):
        build_discovery_job(_plan("aegis.recon.http_probe", "web_crawl_bounded_v1"))


def test_unknown_target_fails_closed() -> None:
    with pytest.raises(ReconCapabilityError, match="TARGET_REF_NOT_IN_INVENTORY"):
        build_discovery_job(
            ReconDiscoveryPlan(
                capability_id="aegis.recon.http_probe",  # type: ignore[arg-type]
                profile_id="http_probe_discovery_v1",  # type: ignore[arg-type]
                target_ref="range-nonexistent",
            )
        )


def test_content_discovery_uses_only_registered_wordlist() -> None:
    profile = RECON_PROFILES["content_discovery_bounded_v1"]
    assert profile.wordlist_id in CONTENT_WORDLISTS
    job = build_discovery_job(
        _plan("aegis.recon.content_discovery", "content_discovery_bounded_v1")
    )
    assert f"/wordlists/{profile.wordlist_id}.txt" in job.argv


# --------------------------------------------------------------------------- #
# Environment-tier + lease fail-closed.
# --------------------------------------------------------------------------- #


def test_non_range_tier_requires_lease(monkeypatch: pytest.MonkeyPatch) -> None:
    staged = dataclasses.replace(
        RECON_PROFILES["http_probe_discovery_v1"],
        environment=EnvironmentTier.ISOLATED_STAGING,
    )
    monkeypatch.setitem(RECON_PROFILES, "http_probe_discovery_v1", staged)
    with pytest.raises(ReconCapabilityError, match="RECON_LEASE_MISSING"):
        build_discovery_job(_plan("aegis.recon.http_probe", "http_probe_discovery_v1"))
    # With a signed but target-mismatched lease, still closed.
    wrong = ReconLease(
        signed=True, authorized=True, target_ref="range-bank",
        environment_tier=EnvironmentTier.ISOLATED_STAGING,
    )
    with pytest.raises(ReconCapabilityError, match="LEASE_TARGET_MISMATCH"):
        build_discovery_job(
            _plan("aegis.recon.http_probe", "http_probe_discovery_v1"), lease=wrong
        )


def test_non_range_signed_lease_still_has_no_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    staged = dataclasses.replace(
        RECON_PROFILES["http_probe_discovery_v1"],
        environment=EnvironmentTier.ISOLATED_STAGING,
    )
    monkeypatch.setitem(RECON_PROFILES, "http_probe_discovery_v1", staged)
    lease = ReconLease(
        signed=True, authorized=True, target_ref="range-shop",
        environment_tier=EnvironmentTier.ISOLATED_STAGING,
    )
    with pytest.raises(ReconCapabilityError, match="NON_RANGE_INVENTORY_UNAVAILABLE"):
        build_discovery_job(
            _plan("aegis.recon.http_probe", "http_probe_discovery_v1"), lease=lease
        )


# --------------------------------------------------------------------------- #
# Provenance (container NOT_EVALUATED until pinned).
# --------------------------------------------------------------------------- #


def test_provenance_present_but_unpinned_fails_closed_for_container() -> None:
    job = build_discovery_job(_plan("aegis.recon.http_probe", "http_probe_discovery_v1"))
    assert job.image_ref.startswith("projectdiscovery/httpx@sha256:")
    assert job.digest_pinned is False
    from aegis.multi_agent.recon_capabilities import TOOL_PROVENANCE

    with pytest.raises(ReconCapabilityError, match="DIGEST_NOT_PINNED"):
        assert_container_pinned(TOOL_PROVENANCE["httpx"])


# --------------------------------------------------------------------------- #
# argv denylist (defence in depth) + untrusted-output sanitation.
# --------------------------------------------------------------------------- #


def test_argv_denylist_rejects_forbidden_token() -> None:
    from aegis.multi_agent.recon_capabilities import _assert_argv_safe

    with pytest.raises(ReconCapabilityError, match="UNSAFE_TOKEN"):
        _assert_argv_safe(["httpx", "-u", "http://aegis-shop:8102", "-o", "loot.txt"])
    with pytest.raises(ReconCapabilityError, match="UNSAFE_TOKEN"):
        _assert_argv_safe(["httpx", "-u", "http://aegis-shop:8102", ";", "rm"])


def test_sanitize_output_truncates_and_redacts_secrets() -> None:
    profile = RECON_PROFILES["http_probe_discovery_v1"]
    raw = (b"clean line\n" + b"Authorization: Bearer lab-token-secret\n" + b"x" * 100_000)
    text, truncated = sanitize_tool_output(raw, max_bytes=profile.max_output_bytes)
    assert truncated is True
    assert len(text.encode()) <= profile.max_output_bytes
    assert "lab-token-secret" not in text
    assert "bearer" not in text.lower()
    assert "REDACTED_SANITIZED_LINE" in text


def test_sanitize_strips_control_characters() -> None:
    text, _ = sanitize_tool_output(b"ok\x00\x07evil\n", max_bytes=1024)
    assert "\x00" not in text and "\x07" not in text and "okevil" in text


# --------------------------------------------------------------------------- #
# Normalized observations + manifest.
# --------------------------------------------------------------------------- #


def test_manifest_records_provenance_and_cleanup() -> None:
    job = build_discovery_job(_plan("aegis.recon.http_probe", "http_probe_discovery_v1"))
    obs = (
        NormalizedReconObservation(
            kind=ReconObservationKind.PARAMETER_CANDIDATE,
            route="/api/products", parameter="q", injectable_candidate=True,
        ),
    )
    manifest = build_manifest(
        job, output_bytes=1234, output_truncated=False, observations=obs, cleanup_complete=True
    )
    assert manifest.container_status == "NOT_EVALUATED"
    assert manifest.argv_digest == job.argv_digest
    assert manifest.observation_count == 1
    assert manifest.cleanup_complete is True
    assert manifest.digest_pinned is False


# --------------------------------------------------------------------------- #
# Recon -> Injection delegation (real, persisted; SQLMap is on the injection side).
# --------------------------------------------------------------------------- #


def test_recon_to_injection_delegation_persists_and_resolves(tmp_path: Path) -> None:
    queue = DelegationQueue(str(tmp_path / "delg.db"))
    queue.initialize()
    candidate = NormalizedReconObservation(
        kind=ReconObservationKind.PARAMETER_CANDIDATE,
        route="/api/products", parameter="q", injectable_candidate=True,
    )
    delegation = build_recon_to_injection_delegation(
        target_ref="range-shop",
        candidate=candidate,
        source_evidence_sha256="a" * 64,
        injection_capability_id="aegis.injection.sql_boolean",
        delegation_id="delg-" + "a" * 16,
    )
    assert delegation.to_agent == "INJECTION_AGENT"
    assert delegation.confirmed is False and delegation.unconfirmed is True
    address = persist_recon_to_injection_delegation(queue, delegation)
    resolved = queue.resolve(address)
    assert resolved is not None
    assert resolved.route == "/api/products" and resolved.parameter == "q"


def test_non_injectable_candidate_cannot_be_delegated() -> None:
    candidate = NormalizedReconObservation(
        kind=ReconObservationKind.HTTP_TECHNOLOGY, detail="nginx", injectable_candidate=False
    )
    with pytest.raises(ReconCapabilityError, match="NOT_INJECTABLE"):
        build_recon_to_injection_delegation(
            target_ref="range-shop",
            candidate=candidate,
            source_evidence_sha256="a" * 64,
            delegation_id="delg-" + "b" * 16,
        )
