"""Independent deterministic verifier for source-control metadata exposure (Phase 1.2).

This verifier is the ONLY automated authority that can promote a Nuclei-reported
``nuclei_scm_metadata_exposure_v1`` result. It trusts nothing Nuclei produced — not its severity,
template prose, matcher name, extracted text, classification or conclusion. The controller
constructs two fresh, typed, read-only requests from the fixed target inventory and this module
evaluates the property from their responses:

- ``BASE_CONTROL``   ``GET <base>``             must return the lab's synthetic route marker for the
                                                exact inventory variant (proves reachability and
                                                that the right route family answered);
- ``METADATA_PROBE`` ``GET <base>/.git/config`` is evaluated structurally.

Verdicts:

- ``CONFIRMED``    control OK and the probe returns ``200 text/plain`` whose body parses as a git
                   config with a ``[core]`` section declaring ``repositoryformatversion``;
- ``PASS``         control OK and the probe returns the deterministic remediation denial
                   (``404`` + exact JSON body) with no git-config structure;
- ``INSUFFICIENT`` anything else (unreachable, errors, ambiguous 404, HTML, redirects, oversize).

Only structured facts and digests are persisted; response bodies never leave this module.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

from aegis.http import bounded_body
from aegis.safety import SafetyController
from aegis_nuclei.targets import NucleiTarget

VERIFIER_VERSION = "aegis-scm-metadata-verifier/1.2.0"
MAX_PROBE_BYTES = 4096
DENIAL_BODY = {"detail": "Repository metadata is not served"}
LAB_MARKER = "scm-metadata-exposure"
_REPO_FORMAT = re.compile(r"^\s*repositoryformatversion\s*=\s*[0-9]+\s*$")

ProbeRole = Literal["BASE_CONTROL", "METADATA_PROBE"]
ContentClass = Literal["TEXT_PLAIN", "JSON", "HTML", "OTHER", "NONE"]


class ScmProbeFacts(BaseModel):
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
    git_config_structure: bool = False
    deliberate_denial: bool = False
    transport_error: bool = False


class ScmVerification(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verifier_version: str = VERIFIER_VERSION
    status: Literal["CONFIRMED", "PASS", "INSUFFICIENT"]
    summary: str = Field(max_length=300)
    evidence_names: list[str] = Field(default_factory=list, max_length=8)


def _content_class(content_type: str | None) -> ContentClass:
    value = (content_type or "").split(";")[0].strip().lower()
    if value == "text/plain":
        return "TEXT_PLAIN"
    if value == "application/json":
        return "JSON"
    if value == "text/html":
        return "HTML"
    return "OTHER" if value else "NONE"


def has_git_config_structure(body: bytes) -> bool:
    """True iff the body is a small UTF-8 git config whose first section is ``[core]`` and that
    section declares ``repositoryformatversion``. Pure structural evaluation, no Nuclei input."""

    if not body or len(body) > MAX_PROBE_BYTES:
        return False
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if "<html" in text.lower() or "<body" in text.lower():
        return False
    section: str | None = None
    first_section: str | None = None
    declared = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped
            first_section = first_section or stripped
            continue
        if section is None:
            return False  # key outside any section: not a git config
        if section == "[core]" and _REPO_FORMAT.match(stripped):
            declared = True
    return first_section == "[core]" and declared


def _json(body: bytes) -> object:
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None


def probe_plan(target: NucleiTarget, scan_id: str) -> list[tuple[str, ProbeRole, str]]:
    """The fixed, controller-constructed verification request set for one target."""

    return [
        (f"{scan_id}-verify-base", "BASE_CONTROL", target.base_path),
        (f"{scan_id}-verify-metadata", "METADATA_PROBE", f"{target.base_path}/.git/config"),
    ]


async def collect(
    *,
    target: NucleiTarget,
    scan_id: str,
    safety: SafetyController,
    transport: httpx.AsyncBaseTransport | None,
    timeout_seconds: float,
) -> list[ScmProbeFacts]:
    """Issue the fresh read-only verification requests from the control plane (not the runner)."""

    facts: list[ScmProbeFacts] = []
    async with httpx.AsyncClient(
        timeout=timeout_seconds,
        follow_redirects=False,
        trust_env=False,
        transport=transport,
    ) as client:
        for name, role, path in probe_plan(target, scan_id):
            url = safety.approve_scm_verification(target.origin, path)
            try:
                async with client.stream("GET", url) as response:
                    body = await bounded_body(response, MAX_PROBE_BYTES + 1)
                    status: int | None = response.status_code
                    content_class = _content_class(response.headers.get("content-type"))
            except (httpx.HTTPError, ValueError):
                facts.append(ScmProbeFacts(name=name, role=role, path=path, transport_error=True))
                continue
            payload = _json(body) if content_class == "JSON" else None
            facts.append(
                ScmProbeFacts(
                    name=name,
                    role=role,
                    path=path,
                    status_code=status,
                    content_class=content_class,
                    body_bytes=len(body),
                    body_sha256=hashlib.sha256(body).hexdigest(),
                    synthetic_marker_ok=(
                        role == "BASE_CONTROL"
                        and status == 200
                        and payload
                        == {"lab": LAB_MARKER, "variant": target.variant, "synthetic": True}
                    ),
                    git_config_structure=(
                        role == "METADATA_PROBE"
                        and content_class == "TEXT_PLAIN"
                        and has_git_config_structure(body)
                    ),
                    deliberate_denial=(
                        role == "METADATA_PROBE" and status == 404 and payload == DENIAL_BODY
                    ),
                )
            )
    return facts


def evaluate(facts: list[ScmProbeFacts]) -> ScmVerification:
    """Deterministic verdict over structured facts. Also used to re-verify persisted facts."""

    base = next((f for f in facts if f.role == "BASE_CONTROL"), None)
    probe = next((f for f in facts if f.role == "METADATA_PROBE"), None)
    if (
        base is None
        or probe is None
        or len(facts) != 2
        or base.transport_error
        or probe.transport_error
        or not base.synthetic_marker_ok
    ):
        return ScmVerification(
            status="INSUFFICIENT",
            summary="Base control did not prove a reachable, correctly-routed synthetic target.",
        )
    names = [base.name, probe.name]
    if (
        probe.status_code == 200
        and probe.content_class == "TEXT_PLAIN"
        and probe.git_config_structure
        and probe.body_bytes <= MAX_PROBE_BYTES
    ):
        return ScmVerification(
            status="CONFIRMED",
            summary="Fresh read-only probe served git repository metadata (core config section).",
            evidence_names=names,
        )
    if probe.status_code == 404 and probe.deliberate_denial and not probe.git_config_structure:
        return ScmVerification(
            status="PASS",
            summary="Fresh read-only probe observed the deterministic remediation denial.",
            evidence_names=names,
        )
    return ScmVerification(
        status="INSUFFICIENT",
        summary="Probe outcome was neither conclusive exposure nor the deterministic denial.",
    )
