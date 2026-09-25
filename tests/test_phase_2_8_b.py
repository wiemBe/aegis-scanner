"""Offline focused tests for the Phase 2.8-B Injection (SQLMap) Capability Pack.

No container, no live SQLMap, no provider. These cover the controller-owned bounded profiles, the
model-blind selection contract, deterministic argv rendering + the exclusions (no OS shell, file
access, unrestricted dump, persistence, out-of-scope crawl), scope/tier/lease/provenance checks,
untrusted-output sanitation, the manifest, the independent verifier adjudicating WORKER evidence
(SQLMap output alone never sets a verdict; the verifier sends no injection traffic), and the full
offline vulnerable->CONFIRMED / patched->PASS scenario harness. Container/live is NOT_EVALUATED.
"""

from __future__ import annotations

import dataclasses
import importlib.util
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from aegis.multi_agent.contracts import AgentRole
from aegis.multi_agent.registry import authorize
from aegis.multi_agent.sqlmap_capability import (
    SQLMAP_CAPABILITY_ID,
    SQLMAP_PROFILES,
    SQLMAP_PROVENANCE,
    SqlmapCapabilityError,
    SqlmapLease,
    SqlmapPlan,
    SqlmapResultSlot,
    SqlmapWorkerEvidence,
    assert_container_pinned,
    build_manifest,
    build_sqlmap_job,
    render_sqlmap_argv,
    sanitize_sqlmap_output,
)
from aegis.multi_agent.staging import EnvironmentTier
from aegis_range.verifier import RangeVerifier

_PROFILE_IDS = (
    "sqlmap_sqli_detect_v1",
    "sqlmap_sqli_confirm_bounded_v1",
    "sqlmap_sqli_canary_impact_v1",
)
# Everything a default/canary profile must NEVER render.
_NEVER_TOKENS = (
    "--os-shell", "--os-cmd", "--os-pwn", "--file-read", "--file-write", "--file-dest",
    "--sql-shell", "--dump-all", "--dbs", "--passwords", "--crawl", "--forms", "--tamper",
    "--proxy", "-r", "--eval",
)


def _plan(profile_id: str, **o: Any) -> SqlmapPlan:
    base: dict[str, Any] = {
        "capability_id": SQLMAP_CAPABILITY_ID,
        "profile_id": profile_id,
        "target_ref": "range-shop",
        "route": "/api/products",
        "parameter": "q",
    }
    base.update(o)
    return SqlmapPlan(**base)


def _load_harness() -> Any:
    path = Path(__file__).resolve().parent.parent / "scripts" / "phase_2_8_b_sqli.py"
    spec = importlib.util.spec_from_file_location("phase_2_8_b_sqli", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------- #
# Registry / role boundary (INJECTION_AGENT only; never recon).
# --------------------------------------------------------------------------- #


def test_sqlmap_authorized_for_injection_agent_only() -> None:
    authorize(AgentRole.INJECTION_AGENT, SQLMAP_CAPABILITY_ID)  # must not raise
    for role in (AgentRole.RECON_AGENT, AgentRole.AUTHORIZATION_AGENT, AgentRole.CHAIN_AGENT):
        with pytest.raises(ValueError, match="CAPABILITY_NOT_AUTHORIZED"):
            authorize(role, SQLMAP_CAPABILITY_ID)


# --------------------------------------------------------------------------- #
# Deterministic rendering + default exclusions.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("profile_id", _PROFILE_IDS)
def test_each_profile_renders_bounded_shell_free_argv(profile_id: str) -> None:
    job = build_sqlmap_job(_plan(profile_id))
    assert job.argv[0] == "sqlmap"
    assert "--batch" in job.argv and "--threads" in job.argv
    assert job.scope_host == "aegis-shop"
    assert job.target_url in job.argv
    assert not ({";", "|", "&", "`", ">", "<"} & set("".join(job.argv)))
    for token in _NEVER_TOKENS:
        assert token not in job.argv, token


def test_detect_profile_has_no_dump_or_banner() -> None:
    job = build_sqlmap_job(_plan("sqlmap_sqli_detect_v1"))
    assert "--dump" not in job.argv and "--banner" not in job.argv
    assert job.allows_canary_read is False


def test_confirm_profile_fingerprints_but_never_dumps() -> None:
    job = build_sqlmap_job(_plan("sqlmap_sqli_confirm_bounded_v1"))
    assert "--banner" in job.argv
    assert "--dump" not in job.argv and job.allows_canary_read is False


def test_canary_profile_reads_one_bounded_row_only() -> None:
    job = build_sqlmap_job(_plan("sqlmap_sqli_canary_impact_v1"))
    assert job.allows_canary_read is True
    assert "--dump" in job.argv and "--dump-all" not in job.argv
    # Bounded to one table, one column, one row.
    assert "-T" in job.argv and "-C" in job.argv and "--stop" in job.argv
    assert job.argv[job.argv.index("--stop") + 1] == "1"


def test_rendering_is_deterministic() -> None:
    a = build_sqlmap_job(_plan("sqlmap_sqli_detect_v1"))
    b = build_sqlmap_job(_plan("sqlmap_sqli_detect_v1"))
    assert a.argv == b.argv and a.job_id == b.job_id and a.argv_digest == b.argv_digest


# --------------------------------------------------------------------------- #
# Model-blind selection contract.
# --------------------------------------------------------------------------- #


def test_plan_rejects_raw_overrides() -> None:
    for bad in (
        {"raw_url": "http://evil"},
        {"options": ["--os-shell"]},
        {"payload": "' OR 1=1 --"},
        {"technique": "T"},
        {"risk": 3},
        {"level": 5},
        {"threads": 50},
        {"timeout_ms": 1},
        {"argv": ["sqlmap", "--os-shell"]},
    ):
        with pytest.raises(ValidationError):
            SqlmapPlan(
                capability_id=SQLMAP_CAPABILITY_ID,
                profile_id="sqlmap_sqli_detect_v1",
                target_ref="range-shop",
                route="/api/products",
                parameter="q",
                **bad,
            )


def test_capability_mismatch_and_unknown_profile_and_target() -> None:
    with pytest.raises(ValidationError):
        SqlmapPlan(
            capability_id="aegis.injection.sql_boolean",  # type: ignore[arg-type]
            profile_id="sqlmap_sqli_detect_v1",
            target_ref="range-shop", route="/api/products", parameter="q",
        )
    with pytest.raises(ValidationError):
        _plan("sqlmap_unknown_v9")
    with pytest.raises(SqlmapCapabilityError, match="TARGET_REF_NOT_IN_INVENTORY"):
        build_sqlmap_job(_plan("sqlmap_sqli_detect_v1", target_ref="range-nope"))


# --------------------------------------------------------------------------- #
# Environment-tier + lease + canary synthetic-range-only.
# --------------------------------------------------------------------------- #


def test_canary_is_synthetic_range_only(monkeypatch: pytest.MonkeyPatch) -> None:
    staged = dataclasses.replace(
        SQLMAP_PROFILES["sqlmap_sqli_canary_impact_v1"],
        environment=EnvironmentTier.ISOLATED_STAGING,
    )
    monkeypatch.setitem(SQLMAP_PROFILES, "sqlmap_sqli_canary_impact_v1", staged)
    lease = SqlmapLease(
        signed=True, authorized=True, target_ref="range-shop",
        environment_tier=EnvironmentTier.ISOLATED_STAGING,
    )
    with pytest.raises(SqlmapCapabilityError, match="SYNTHETIC_RANGE_ONLY"):
        build_sqlmap_job(_plan("sqlmap_sqli_canary_impact_v1"), lease=lease)


def test_non_range_tier_requires_lease(monkeypatch: pytest.MonkeyPatch) -> None:
    staged = dataclasses.replace(
        SQLMAP_PROFILES["sqlmap_sqli_detect_v1"],
        environment=EnvironmentTier.ISOLATED_STAGING,
    )
    monkeypatch.setitem(SQLMAP_PROFILES, "sqlmap_sqli_detect_v1", staged)
    with pytest.raises(SqlmapCapabilityError, match="SQLMAP_LEASE_MISSING"):
        build_sqlmap_job(_plan("sqlmap_sqli_detect_v1"))
    wrong = SqlmapLease(
        signed=True, authorized=True, target_ref="range-bank",
        environment_tier=EnvironmentTier.ISOLATED_STAGING,
    )
    with pytest.raises(SqlmapCapabilityError, match="LEASE_TARGET_MISMATCH"):
        build_sqlmap_job(_plan("sqlmap_sqli_detect_v1"), lease=wrong)
    ok = SqlmapLease(
        signed=True, authorized=True, target_ref="range-shop",
        environment_tier=EnvironmentTier.ISOLATED_STAGING,
    )
    with pytest.raises(SqlmapCapabilityError, match="NON_RANGE_INVENTORY_UNAVAILABLE"):
        build_sqlmap_job(_plan("sqlmap_sqli_detect_v1"), lease=ok)


# --------------------------------------------------------------------------- #
# argv denylist + provenance + sanitation + manifest.
# --------------------------------------------------------------------------- #


def test_argv_denylist_rejects_forbidden_option() -> None:
    profile = SQLMAP_PROFILES["sqlmap_sqli_detect_v1"]
    with pytest.raises(SqlmapCapabilityError, match="UNSAFE_TOKEN"):
        from aegis.multi_agent.sqlmap_capability import _assert_argv_safe

        _assert_argv_safe([*render_sqlmap_argv(profile, "http://aegis-shop:8102/x?q=1", "q"),
                           "--os-shell"])


def test_provenance_unpinned_fails_closed_for_container() -> None:
    job = build_sqlmap_job(_plan("sqlmap_sqli_detect_v1"))
    assert job.image_ref.startswith("sqlmapproject/sqlmap@sha256:")
    assert job.digest_pinned is False
    with pytest.raises(SqlmapCapabilityError, match="DIGEST_NOT_PINNED"):
        assert_container_pinned(SQLMAP_PROVENANCE)


def test_sanitize_output_truncates_and_redacts() -> None:
    raw = b"injectable parameter q\nAuthorization: Bearer lab-token-x\n" + b"y" * 200_000
    text, truncated = sanitize_sqlmap_output(raw, max_bytes=131_072)
    assert truncated is True
    assert "lab-token-x" not in text and "REDACTED_SANITIZED_LINE" in text


def test_manifest_container_not_evaluated() -> None:
    job = build_sqlmap_job(_plan("sqlmap_sqli_canary_impact_v1"))
    manifest = build_manifest(
        job, output_bytes=100, output_truncated=False,
        canary_read_performed=True, cleanup_complete=True,
    )
    assert manifest.container_status == "NOT_EVALUATED"
    assert manifest.canary_read_performed is True
    assert manifest.digest_pinned is False


# --------------------------------------------------------------------------- #
# Independent verifier: adjudicates WORKER evidence; SQLMap output alone sets no verdict.
# --------------------------------------------------------------------------- #


def _evidence(control: int, true: int, false: int, *, tool_says: bool) -> SqlmapWorkerEvidence:
    return SqlmapWorkerEvidence(
        job_id="sqlmj-" + "a" * 16,
        parameter="q",
        control=SqlmapResultSlot(status_code=200, result_count=control),
        boolean_true=SqlmapResultSlot(status_code=200, result_count=true),
        boolean_false=SqlmapResultSlot(status_code=200, result_count=false),
        tool_reported_injectable=tool_says,
    )


def test_verifier_confirms_vulnerable_differential() -> None:
    result = RangeVerifier().adjudicate_sqli_offline(
        "aegis-shop", _evidence(1, 3, 0, tool_says=True).as_verifier_input(),
        seeded_total=3, control_selective_count=1,
    )
    assert result.status.value == "CONFIRMED"
    assert result.facts["verifier_generated_injection_traffic"] is False
    assert result.facts["verifier_probe_requests"] == 0


def test_verifier_passes_patched_no_differential() -> None:
    result = RangeVerifier().adjudicate_sqli_offline(
        "aegis-shop", _evidence(1, 0, 0, tool_says=False).as_verifier_input(),
        seeded_total=3, control_selective_count=1,
    )
    assert result.status.value == "PASS"


def test_sqlmap_verdict_alone_never_sets_confirmed() -> None:
    # Tool CLAIMS injectable, but the patched differential shows no effect -> verifier PASS, not
    # CONFIRMED. The tool's claim is not an input (as_verifier_input excludes it).
    evidence = _evidence(1, 0, 0, tool_says=True)
    assert "tool_reported_injectable" not in evidence.as_verifier_input()
    result = RangeVerifier().adjudicate_sqli_offline(
        "aegis-shop", evidence.as_verifier_input(), seeded_total=3, control_selective_count=1,
    )
    assert result.status.value == "PASS"


def test_verifier_incomplete_on_inconclusive_evidence() -> None:
    result = RangeVerifier().adjudicate_sqli_offline(
        "aegis-shop", _evidence(1, 2, 1, tool_says=True).as_verifier_input(),
        seeded_total=3, control_selective_count=1,
    )
    assert result.status.value == "INCOMPLETE"


# --------------------------------------------------------------------------- #
# Full offline scenario harness.
# --------------------------------------------------------------------------- #


def test_offline_sqli_scenario_confirms_then_passes() -> None:
    harness = _load_harness()
    verdict = harness.run_offline()["verdict"]
    assert verdict["sqlmap_capability_status"] == "OFFLINE_PASS"
    assert verdict["container_sqlmap_status"] == "NOT_EVALUATED"
    assert verdict["live_sqlmap_status"] == "NOT_EVALUATED"
    assert verdict["vulnerable"]["verifier_status"] == "CONFIRMED"
    assert verdict["patched"]["verifier_status"] == "PASS"
    assert verdict["passed"] is True
    assert all(verdict["checks"].values())
