"""Independent deterministic verifier for reflected cross-site scripting (Phase 1.5).

This verifier is the ONLY automated authority that can promote a ZAP-reported
``zap_active_reflected_xss_v1`` alert, and the only authority for a patched PASS. It trusts nothing
ZAP produced — not its risk, confidence, alert name, evidence, attack payload, rule id, report or
exit code. The controller mints a FRESH random marker for the active execution and this module
issues two fresh, read-only GET requests itself and evaluates the reflected-XSS property from their
responses:

- ``BASE_CONTROL``  ``GET <search>?q=<benign marker>`` must return 200 ``text/html`` carrying the
                    synthetic lab marker for the exact inventory variant (proves reachability,
                    correct routing and the expected variant);
- ``XSS_PROBE``     ``GET <search>?q=<script>marker</script>`` — the fresh marker payload is sent
                    directly by the verifier; the response is then inspected for whether the marker
                    reached an executable HTML element context UNESCAPED or was contextually
                    HTML-entity encoded.

Verdicts:

- ``CONFIRMED``    control OK, and the probe response contains the raw, unescaped ``<script>``
                   element bearing the fresh marker (an executable HTML context) — reflected XSS;
- ``PASS``         control OK, and the probe response contains ONLY the HTML-entity-encoded marker
                   (and not the raw executable form) — correct contextual output encoding;
- ``INSUFFICIENT`` anything else (unreachable, redirect, wrong status/content type, missing variant
                   marker, neither clearly raw nor clearly encoded, oversized body).

No real isolated browser executes the marker, so this verifier NEVER claims browser execution: it
proves that controller-controlled input reaches an executable HTML context without contextual output
encoding, which is the defining condition of the reflected-XSS vulnerability class. Only structured
facts and digests are persisted; response bodies never leave this module.
"""

from __future__ import annotations

import hashlib
import html
import secrets
from typing import Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

from aegis.http import bounded_body
from aegis.safety import SafetyController
from aegis_zap_active.inventory import ZapActiveTarget

VERIFIER_VERSION = "aegis-zap-xss-verifier/1.5.0"
MAX_PROBE_BYTES = 16_384
LAB_MARKER = "zap-active-reflected-xss"

ProbeRole = Literal["BASE_CONTROL", "XSS_PROBE"]
ContentClass = Literal["JSON", "TEXT_PLAIN", "HTML", "OTHER", "NONE"]
Reflection = Literal["RAW_EXECUTABLE", "ENTITY_ENCODED", "ABSENT", "AMBIGUOUS", "NOT_OBSERVED"]


def fresh_marker() -> str:
    """A controller-generated, per-execution marker token."""

    return f"AEGIS{secrets.token_hex(8)}"


def _payload(marker: str) -> str:
    return f"<script>{marker}</script>"


class ZapXssProbeFacts(BaseModel):
    """Structured, body-free facts about one verifier request."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(max_length=100)
    role: ProbeRole
    method: Literal["GET"] = "GET"
    path: str = Field(max_length=200)
    marker: str = Field(max_length=64)
    status_code: int | None = None
    content_class: ContentClass = "NONE"
    body_bytes: int = Field(default=0, ge=0)
    body_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    variant_marker_ok: bool = False
    reflection: Reflection = "NOT_OBSERVED"
    redirect: bool = False
    transport_error: bool = False


class ZapXssVerification(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verifier_version: str = VERIFIER_VERSION
    status: Literal["CONFIRMED", "PASS", "INSUFFICIENT"]
    summary: str = Field(max_length=300)
    marker: str = Field(default="", max_length=64)
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


def _variant_marker(variant: str) -> str:
    return f'data-lab="{LAB_MARKER}" data-variant="{variant}"'


def classify_reflection(body_text: str, marker: str) -> Reflection:
    """Deterministic classification of how the fresh marker payload was reflected."""

    raw = _payload(marker)
    encoded = html.escape(raw, quote=True)
    has_raw = raw in body_text
    has_encoded = encoded in body_text
    if has_raw:
        # The raw executable <script>marker</script> is present verbatim: executable context.
        return "RAW_EXECUTABLE"
    if has_encoded:
        return "ENTITY_ENCODED"
    if marker in body_text:
        # The marker survived but neither the raw element nor the fully-encoded form is present.
        return "AMBIGUOUS"
    return "ABSENT"


def probe_plan(target: ZapActiveTarget, scan_id: str) -> list[tuple[str, ProbeRole]]:
    if target.purpose != "ACCEPTANCE":
        return []
    return [
        (f"{scan_id}-verify-control", "BASE_CONTROL"),
        (f"{scan_id}-verify-xss", "XSS_PROBE"),
    ]


async def collect(
    *,
    target: ZapActiveTarget,
    scan_id: str,
    marker: str,
    safety: SafetyController,
    transport: httpx.AsyncBaseTransport | None,
    timeout_seconds: float,
) -> list[ZapXssProbeFacts]:
    """Issue the fresh read-only verification requests from the control plane (not the runner)."""

    facts: list[ZapXssProbeFacts] = []
    path = target.search_path
    async with httpx.AsyncClient(
        timeout=timeout_seconds,
        follow_redirects=False,
        trust_env=False,
        transport=transport,
    ) as client:
        for name, role in probe_plan(target, scan_id):
            url = safety.approve_zap_active_verification(target.origin, path)
            q_value = f"benign-{marker}" if role == "BASE_CONTROL" else _payload(marker)
            try:
                async with client.stream("GET", url, params={target.query_param: q_value}) as resp:
                    body = await bounded_body(resp, MAX_PROBE_BYTES + 1)
                    status: int | None = resp.status_code
                    content_class = _content_class(resp.headers.get("content-type"))
            except (httpx.HTTPError, ValueError):
                facts.append(
                    ZapXssProbeFacts(
                        name=name, role=role, path=path, marker=marker, transport_error=True
                    )
                )
                continue
            oversized = len(body) > MAX_PROBE_BYTES
            body_text = "" if oversized else body.decode("utf-8", errors="replace")
            reflection: Reflection = (
                "NOT_OBSERVED"
                if role == "BASE_CONTROL"
                else ("NOT_OBSERVED" if oversized else classify_reflection(body_text, marker))
            )
            facts.append(
                ZapXssProbeFacts(
                    name=name,
                    role=role,
                    path=path,
                    marker=marker,
                    status_code=status,
                    content_class=content_class,
                    body_bytes=len(body),
                    body_sha256=hashlib.sha256(body).hexdigest(),
                    variant_marker_ok=(
                        status == 200
                        and not oversized
                        and content_class == "HTML"
                        and _variant_marker(target.variant) in body_text
                    ),
                    reflection=reflection,
                    redirect=status is not None and 300 <= status < 400,
                )
            )
    return facts


def evaluate(facts: list[ZapXssProbeFacts]) -> ZapXssVerification:
    """Deterministic verdict over structured facts. Also used to re-verify persisted facts."""

    control = next((f for f in facts if f.role == "BASE_CONTROL"), None)
    probe = next((f for f in facts if f.role == "XSS_PROBE"), None)
    marker = probe.marker if probe else ""
    if (
        control is None
        or probe is None
        or len(facts) != 2
        or control.transport_error
        or probe.transport_error
        or control.redirect
        or probe.redirect
        or not control.variant_marker_ok
        or not probe.variant_marker_ok
        or probe.marker != control.marker
        or not marker
    ):
        return ZapXssVerification(
            status="INSUFFICIENT",
            summary="Control/probe did not prove a reachable, correctly-routed synthetic endpoint.",
            marker=marker,
        )
    names = [control.name, probe.name]
    if probe.reflection == "RAW_EXECUTABLE":
        return ZapXssVerification(
            status="CONFIRMED",
            summary=(
                "Fresh marker reached an executable HTML script context unescaped (reflected XSS); "
                "no browser execution was performed or claimed."
            ),
            marker=marker,
            evidence_names=names,
        )
    if probe.reflection == "ENTITY_ENCODED":
        return ZapXssVerification(
            status="PASS",
            summary="Fresh marker was contextually HTML-entity encoded; no executable element",
            marker=marker,
            evidence_names=names,
        )
    return ZapXssVerification(
        status="INSUFFICIENT",
        summary="Probe reflection was neither a raw executable element nor cleanly entity-encoded.",
        marker=marker,
    )
