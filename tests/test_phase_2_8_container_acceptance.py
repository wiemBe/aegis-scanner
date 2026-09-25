"""Phase 2.8 — containerized synthetic capability acceptance tests.

Guardrail-unit tests run everywhere; tests that need a docker daemon are skipped when one is not
reachable. Includes the nine required negative container tests: target escape, cross-origin
redirect, unknown profile, forbidden argv, output-size limit, timeout, cleanup failure, unpinned
image, and stale evidence reuse.
"""

from __future__ import annotations

import pytest

from aegis.container_acceptance.contracts import (
    CleanupProof,
    ContainerAcceptanceError,
    assert_arms_fresh,
)
from aegis.container_acceptance.docker_cli import daemon_available, docker
from aegis.container_acceptance.images import (
    PINNED_IMAGES,
    UnpinnedImageError,
    require_pinned,
    resolve_local_build,
)
from aegis.container_acceptance.recon_runner import _count_json_lines
from aegis.container_acceptance.runner import run_tool
from aegis.container_acceptance.sqlmap_worker import parse_sqlmap_stdout
from aegis.multi_agent.recon_capabilities import (
    RECON_PROFILES,
    ReconCapabilityError,
    ReconDiscoveryPlan,
    build_discovery_job,
)
from aegis.multi_agent.sqlmap_capability import (
    SQLMAP_CAPABILITY_ID,
    SQLMAP_PROVENANCE,
    SqlmapCapabilityError,
    SqlmapPlan,
    SqlmapToolImage,
    _assert_argv_safe,
    assert_container_pinned,
    build_sqlmap_job,
)

DOCKER = daemon_available()
needs_docker = pytest.mark.skipif(not DOCKER, reason="docker daemon not available")

_PY_BASE = PINNED_IMAGES["python-base"].run_reference()
_SQLMAP_TAG_ID = "sha256:" + "c" * 64  # a well-formed local image id for pin construction in tests


def _sqlmap_plan() -> SqlmapPlan:
    return SqlmapPlan(
        capability_id=SQLMAP_CAPABILITY_ID,
        profile_id="sqlmap_sqli_confirm_bounded_v1",
        target_ref="range-shop",
        route="/api/products",
        parameter="q",
    )


# --------------------------------------------------------------------------- positive guardrails


def test_pinned_registry_images_are_immutable() -> None:
    for key in ("python-base", "httpx", "katana"):
        assert require_pinned(PINNED_IMAGES[key].run_reference())


def test_api_capability_renamed_to_http_probe() -> None:
    ids = {p.capability_id for p in RECON_PROFILES.values()}
    assert "aegis.recon.api_http_probe" in ids
    assert "aegis.recon.api_discovery" not in ids
    assert "api_http_probe_v1" in RECON_PROFILES


def test_sqlmap_injectable_claim_excluded_from_verifier_input() -> None:
    # SQLMap's own "injectable" claim is audit-only; it is never in the verifier's input dict.
    parsed = parse_sqlmap_stdout(
        "sqlmap identified the following injection point(s) with a total of 207 HTTP(s) requests:\n"
        "    Type: boolean-based blind\n"
    )
    injectable, total, types = parsed
    assert injectable is True and total == 207 and types
    not_inj = parse_sqlmap_stdout("all tested parameters do not appear to be injectable")
    assert not_inj[0] is False


def test_container_argv_override_pins_sqlmap_image() -> None:
    pinned = SqlmapToolImage(
        tool="sqlmap", image="aegis-sqlmap-runner", tag="2.8.0", version="1.10.9",
        image_digest=_SQLMAP_TAG_ID, digest_pinned=True,
    )
    job = build_sqlmap_job(_sqlmap_plan(), image=pinned)
    assert job.digest_pinned is True
    assert job.image_ref == f"aegis-sqlmap-runner@{_SQLMAP_TAG_ID}"
    # Default (no override) still keeps the preserved offline placeholder unpinned.
    assert build_sqlmap_job(_sqlmap_plan()).digest_pinned is False


# --------------------------------------------------------------------------- negative (1) escape


def test_negative_target_escape_out_of_scope_ref() -> None:
    with pytest.raises(SqlmapCapabilityError):
        build_sqlmap_job(
            SqlmapPlan(
                capability_id=SQLMAP_CAPABILITY_ID, profile_id="sqlmap_sqli_detect_v1",
                target_ref="range-not-in-inventory", route="/api/products", parameter="q",
            )
        )
    with pytest.raises(ReconCapabilityError):
        build_discovery_job(
            ReconDiscoveryPlan(
                capability_id="aegis.recon.http_probe", profile_id="http_probe_discovery_v1",
                target_ref="range-not-in-inventory",
            )
        )


# --------------------------------------------------------------------------- negative (2) redirect


def test_negative_cross_origin_redirect_denied_by_render() -> None:
    job = build_discovery_job(
        ReconDiscoveryPlan(
            capability_id="aegis.recon.http_probe", profile_id="http_probe_discovery_v1",
            target_ref="range-shop",
        )
    )
    assert job.redirect_policy == "DENY"
    assert "-disable-redirects" in job.argv
    assert "-fr" not in job.argv and "-L" not in job.argv and "--location" not in job.argv


# --------------------------------------------------------------------------- negative (3) profile


def test_negative_unknown_profile_fails_closed() -> None:
    with pytest.raises(SqlmapCapabilityError):
        build_sqlmap_job(
            SqlmapPlan(
                capability_id=SQLMAP_CAPABILITY_ID, profile_id="sqlmap_sqli_detect_v1",
                target_ref="range-shop", route="/api/products", parameter="q",
            ).model_copy(update={"profile_id": "no_such_profile"})
        )


# --------------------------------------------------------------------------- negative (4) argv


def test_negative_forbidden_argv_tokens_rejected() -> None:
    for bad in (["sqlmap", "--os-shell"], ["sqlmap", "--dump-all"], ["sqlmap", ";", "rm"]):
        with pytest.raises(SqlmapCapabilityError):
            _assert_argv_safe(bad)


# --------------------------------------------------------------------------- negative (5) output


@needs_docker
def test_negative_output_size_limit_truncates() -> None:
    from aegis.container_acceptance.docker_cli import image_id

    sqlmap_ref = image_id("aegis-sqlmap-runner:2.8.0")
    if sqlmap_ref is None:
        pytest.skip("sqlmap runner image not built")
    # sqlmap --version prints a banner well over the tiny limit; the runner must mark it truncated.
    raw = run_tool(
        image_reference=sqlmap_ref,
        argv=("sqlmap", "--version"),
        network="bridge",
        label="aegis.phase28-test",
        output_limit_bytes=8,
        timeout_seconds=30,
    )
    assert raw.result.output_truncated is True
    assert raw.result.output_bytes > 8


# --------------------------------------------------------------------------- negative (6) timeout


@needs_docker
def test_negative_timeout_is_enforced() -> None:
    result = docker(
        "run", "--rm", _PY_BASE, "python", "-c", "import time; time.sleep(30)", timeout=3
    )
    assert result.timed_out is True


# --------------------------------------------------------------------------- negative (7) cleanup


def test_negative_cleanup_failure_detected() -> None:
    dirty = CleanupProof(
        stack_containers_remaining=1, volumes_remaining=0, networks_remaining=1,
        network_was_internal=True, egress_blocked_proof="EGRESS_BLOCKED:OSError",
    )
    assert dirty.clean is False
    clean = CleanupProof(
        stack_containers_remaining=0, volumes_remaining=0, networks_remaining=0,
        network_was_internal=True,
    )
    assert clean.clean is True


# --------------------------------------------------------------------------- negative (8) unpinned


def test_negative_unpinned_image_rejected() -> None:
    for bad in ("python:3.12-slim", "python:latest", "aegis-runner:2.8.0", "repo@sha256:short"):
        with pytest.raises(UnpinnedImageError):
            require_pinned(bad)
    # The preserved offline SQLMap provenance is an unpinned placeholder: it must fail closed.
    with pytest.raises(SqlmapCapabilityError):
        assert_container_pinned(SQLMAP_PROVENANCE)


def test_local_build_resolver_requires_digest_pin() -> None:
    resolved = resolve_local_build(PINNED_IMAGES["sqlmap-runner"], "sha256:" + "a" * 64)
    assert resolved.run_reference() == "sha256:" + "a" * 64
    with pytest.raises(UnpinnedImageError):
        resolve_local_build(PINNED_IMAGES["sqlmap-runner"], "aegis-sqlmap-runner:2.8.0")


# --------------------------------------------------------------------------- negative (9) stale


def test_negative_stale_evidence_reuse_rejected() -> None:
    assert_arms_fresh(["run-A", "run-A"], "run-A")  # fresh: ok
    with pytest.raises(ContainerAcceptanceError):
        assert_arms_fresh(["run-A", "run-STALE"], "run-A")


# --------------------------------------------------------------------------- helper coverage


def test_json_line_counter() -> None:
    assert _count_json_lines('{"a":1}\nnot json\n{"b":2}\n') == 2
