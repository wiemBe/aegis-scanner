"""Independent deterministic verifier for the missing anti-MIME-sniffing header (Phase 1.3).

This verifier is the ONLY automated authority that can promote a ZAP-reported
``zap_passive_header_openapi_v1`` alert, and the only authority for a patched PASS. It trusts
nothing ZAP produced — not its risk, confidence, alert name, description, solution, evidence, rule
id, report or exit code. The controller constructs two fresh, typed, read-only requests from the
fixed inventory and this module evaluates the security property from their responses:

- ``BASE_CONTROL``  ``GET <control operation>`` must return the lab's synthetic marker for the exact
                    inventory variant AND carry exactly ``X-Content-Type-Options: nosniff`` (proves
                    reachability, correct routing and that the header is observable at all);
- ``HEADER_PROBE``  ``GET <scenario operation>`` must return the synthetic catalog marker; its
                    ``X-Content-Type-Options`` header is then evaluated.

Verdicts:

- ``CONFIRMED``    control OK, probe marker OK and the probe response has NO such header;
- ``PASS``         control OK, probe marker OK and the probe carries exactly one ``nosniff`` value;
- ``INSUFFICIENT`` anything else (unreachable, redirect, error status, wrong content type, missing
                   marker, duplicate or unexpected header values, oversized body).

Only structured facts and digests are persisted; response bodies never leave this module.
"""

from __future__ import annotations

import hashlib
import json
from typing import Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

from aegis.http import bounded_body
from aegis.safety import SafetyController
from aegis_zap.inventory import ZapTarget
from aegis_zap.projection import project

VERIFIER_VERSION = "aegis-zap-header-verifier/1.3.0"
MAX_PROBE_BYTES = 4096
LAB_MARKER = "zap-passive-header"

ProbeRole = Literal["BASE_CONTROL", "HEADER_PROBE"]
ContentClass = Literal["JSON", "TEXT_PLAIN", "HTML", "OTHER", "NONE"]
HeaderState = Literal["PRESENT_NOSNIFF", "ABSENT", "INVALID", "NOT_OBSERVED"]


class ZapProbeFacts(BaseModel):
    """Structured, body-free facts about one verifier request."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(max_length=100)
    role: ProbeRole
    method: Literal["GET"] = "GET"
    path: str = Field(max_length=200)
    status_code: int | None = None
    content_class: ContentClass = "NONE"
    body_bytes: int = Field(default=0, ge=0)
    body_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    synthetic_marker_ok: bool = False
    nosniff_header: HeaderState = "NOT_OBSERVED"
    redirect: bool = False
    transport_error: bool = False


class ZapVerification(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verifier_version: str = VERIFIER_VERSION
    status: Literal["CONFIRMED", "PASS", "INSUFFICIENT"]
    summary: str = Field(max_length=300)
    evidence_names: list[str] = Field(default_factory=list, max_length=8)


def _content_class(content_type: str | None) -> ContentClass:
    value = (content_type or "").split(";")[0].strip().lower()
    if value == "application/json":
        return "JSON"
    if value == "text/plain":
        return "TEXT_PLAIN"
    if value == "text/html":
        return "HTML"
    return "OTHER" if value else "NONE"


def header_state(values: list[str]) -> HeaderState:
    """Classify every ``X-Content-Type-Options`` value on a response (case-insensitive name)."""

    if not values:
        return "ABSENT"
    if len(values) == 1 and values[0].strip().lower() == "nosniff":
        return "PRESENT_NOSNIFF"
    return "INVALID"


def probe_plan(target: ZapTarget, scan_id: str) -> list[tuple[str, ProbeRole, str]]:
    """The fixed, controller-constructed verification request set for one acceptance target."""

    if target.purpose != "ACCEPTANCE" or not (
        target.control_operation_id and target.scenario_operation_id
    ):
        return []
    by_id = {op.operation_id: op.path for op in project(target).operations}
    return [
        (f"{scan_id}-verify-control", "BASE_CONTROL", by_id[target.control_operation_id]),
        (f"{scan_id}-verify-header", "HEADER_PROBE", by_id[target.scenario_operation_id]),
    ]


def _marker_ok(payload: object, target: ZapTarget, role: ProbeRole) -> bool:
    if not isinstance(payload, dict):
        return False
    expected: dict[str, object] = {
        "lab": LAB_MARKER,
        "variant": target.variant,
        "route": "status" if role == "BASE_CONTROL" else "catalog",
        "synthetic": True,
    }
    if role == "HEADER_PROBE":
        catalog = target.path_value("catalog_id")
        expected["catalog_id"] = catalog
    return payload == expected


async def collect(
    *,
    target: ZapTarget,
    scan_id: str,
    safety: SafetyController,
    transport: httpx.AsyncBaseTransport | None,
    timeout_seconds: float,
) -> list[ZapProbeFacts]:
    """Issue the fresh read-only verification requests from the control plane (not the runner)."""

    facts: list[ZapProbeFacts] = []
    async with httpx.AsyncClient(
        timeout=timeout_seconds,
        follow_redirects=False,
        trust_env=False,
        transport=transport,
    ) as client:
        for name, role, path in probe_plan(target, scan_id):
            url = safety.approve_zap_verification(target.origin, path)
            try:
                async with client.stream("GET", url) as response:
                    body = await bounded_body(response, MAX_PROBE_BYTES + 1)
                    status: int | None = response.status_code
                    content_class = _content_class(response.headers.get("content-type"))
                    header_values = response.headers.get_list("x-content-type-options")
            except (httpx.HTTPError, ValueError):
                facts.append(ZapProbeFacts(name=name, role=role, path=path, transport_error=True))
                continue
            try:
                payload: object = (
                    json.loads(body.decode("utf-8")) if content_class == "JSON" else None
                )
            except (UnicodeDecodeError, ValueError):
                payload = None
            facts.append(
                ZapProbeFacts(
                    name=name,
                    role=role,
                    path=path,
                    status_code=status,
                    content_class=content_class,
                    body_bytes=len(body),
                    body_sha256=hashlib.sha256(body).hexdigest(),
                    synthetic_marker_ok=(
                        status == 200
                        and len(body) <= MAX_PROBE_BYTES
                        and _marker_ok(payload, target, role)
                    ),
                    nosniff_header=header_state(header_values),
                    redirect=status is not None and 300 <= status < 400,
                )
            )
    return facts


def evaluate(facts: list[ZapProbeFacts]) -> ZapVerification:
    """Deterministic verdict over structured facts. Also used to re-verify persisted facts."""

    control = next((f for f in facts if f.role == "BASE_CONTROL"), None)
    probe = next((f for f in facts if f.role == "HEADER_PROBE"), None)
    if (
        control is None
        or probe is None
        or len(facts) != 2
        or control.transport_error
        or probe.transport_error
        or control.redirect
        or probe.redirect
        or not control.synthetic_marker_ok
        or control.nosniff_header != "PRESENT_NOSNIFF"
        or not probe.synthetic_marker_ok
        or probe.content_class != "JSON"
    ):
        return ZapVerification(
            status="INSUFFICIENT",
            summary="Control/probe did not prove a reachable, correctly-routed synthetic target.",
        )
    names = [control.name, probe.name]
    if probe.nosniff_header == "ABSENT":
        return ZapVerification(
            status="CONFIRMED",
            summary="Fresh read-only probe: JSON response without X-Content-Type-Options: nosniff.",
            evidence_names=names,
        )
    if probe.nosniff_header == "PRESENT_NOSNIFF":
        return ZapVerification(
            status="PASS",
            summary="Fresh read-only probe: the route now sets X-Content-Type-Options: nosniff.",
            evidence_names=names,
        )
    return ZapVerification(
        status="INSUFFICIENT",
        summary="Probe header was neither clearly absent nor exactly nosniff.",
    )
