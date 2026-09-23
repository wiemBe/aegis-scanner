"""Phase 1.9 controlled Cloud Boundary Agent: capability registry, Tool Broker, normalization
and a real persisted, addressable ``CLOUD_BOUNDARY_AGENT`` job queue.

This is the control-plane half of the single synthetic cloud-boundary vertical slice. It mirrors the
Phase 1.7-C/D recon design point-for-point, adapted to an HTTP boundary probe instead of an Nmap
scan:

* the model *selects* a registered capability, a typed boundary-class hypothesis and a **symbolic**
  probe destination reference (see :class:`aegis.multi_agent.contracts.CloudBoundaryPlanOutput`); it
  never authors a URL, credential, header or request body;
* the :class:`CloudBoundaryBroker` deterministically renders that typed plan into a **shell-free**
  HTTP execution — a fixed method, a fixed route and a controller-resolved destination URL — and
  fails closed on anything outside the registered capability's scope;
* :func:`normalize_boundary_observations` turns the *sanitized* probe result into typed, reference-
  only observations. The synthetic instance-metadata credential value is **redacted at the source**
  (:func:`sanitize_probe_response`) and never enters an observation, projection, prompt or report —
  only its presence, as a boolean and a field name, is ever carried forward;
* target-controlled response content is untrusted DATA: instruction-like content is flagged (reusing
  the Phase 1.7-D marker set), never obeyed;
* the agent **never confirms**: observations, hypotheses and the submission all carry
  ``unconfirmed=True`` / ``confirmed=False`` at the type level. Only the independent deterministic
  range verifier promotes the vulnerable case to CONFIRMED or the patched case to PASS, using
  controller-owned ground truth this module never sees.

The :class:`CloudBoundaryJobQueue` is the real inbound job boundary: a job is persisted to SQLite,
assigned a stable ``agentjob://CLOUD_BOUNDARY_AGENT/<id>`` address, and consumed (QUEUED -> CLAIMED
-> CLOSED) by the Cloud Boundary Agent path. It carries only references — a target reference and a
boundary-class hypothesis — never a mode, ground-truth id, verdict or credential.
"""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import Field

from aegis.multi_agent.contracts import (
    CloudBoundaryPlanOutput,
    StrictModel,
    now_utc,
)
from aegis.multi_agent.injection import HOSTILE_INSTRUCTION_MARKERS

# --------------------------------------------------------------------------- #
# Capability registry (kept in lockstep with aegis.multi_agent.registry / .contracts).
# --------------------------------------------------------------------------- #

CAP_CLOUD_METADATA_BOUNDARY_PROBE = "aegis.cloud.metadata_boundary_probe"
CLOUD_BOUNDARY_CAPABILITIES: frozenset[str] = frozenset({CAP_CLOUD_METADATA_BOUNDARY_PROBE})

# The bounded boundary classes the model may hypothesize. Kept identical to the gateway contract's
# ``_GwCloudBoundaryClass`` literal by the drift-guard test.
CLOUD_BOUNDARY_CLASSES: frozenset[str] = frozenset(
    {
        "METADATA_CREDENTIAL_EXPOSURE",
        "INTEGRATION_DESTINATION_SSRF",
        "INTERNAL_SERVICE_AUTHORIZATION",
        "WORKSPACE_CROSS_ORIGIN",
        "XML_EXTERNAL_ENTITY",
    }
)

# Symbolic probe destinations (kept identical to the gateway contract's ``_GwCloudDestinationRef``).
CLOUD_DESTINATION_REFS: frozenset[str] = frozenset({"INSTANCE_METADATA", "APPROVED_PARTNER_STATUS"})

# The single registered probe route/method for this capability. The model never selects these; the
# broker fixes them, so no route or verb is model-controllable.
_PROBE_ROUTE = "/api/integrations/check"
_PROBE_METHOD: Literal["POST"] = "POST"

# Controller/broker-owned destination resolution. These concrete origins live ONLY here and in the
# rendered execution — never in a model prompt, projection, observation or report. They are exactly
# the destinations the independent range verifier itself uses (``aegis_range.verifier``), so the
# agent's bounded probe exercises the same boundary the verifier adjudicates.
_DESTINATION_RESOLUTION: dict[str, str] = {
    "INSTANCE_METADATA": "http://range-canary:8500/status/instance",
    "APPROVED_PARTNER_STATUS": "https://status.partner.invalid/health",
}

# Every rendered request in the capability, in order: one benign control, then the boundary probe.
# The model selects the boundary destination; the control is fixed by the capability.
_CONTROL_DESTINATION = "APPROVED_PARTNER_STATUS"

# The field name a credential-shaped value would occupy in the synthetic metadata response. Only the
# *name* and *presence* are ever recorded; the value is redacted at the source.
_CREDENTIAL_FIELD = "access_token"
# The synthetic instance-metadata credential prefix (controller-side detection only, never emitted).
_CREDENTIAL_PREFIX = "meta."

# Defence-in-depth: a resolved destination must be one of the allowlisted internal/benign origins
# and must contain no shell metacharacter or whitespace.
_SHELL_METACHARACTERS = frozenset({";", "|", "&", "$", "`", "\n", "\r", " ", "\t", ">", "<"})
_SAFE_ROUTE_RE = re.compile(r"^/[A-Za-z0-9/_.-]+$")


class CloudBoundaryRejection(ValueError):
    """Raised when a cloud-boundary selection escapes the controller allowlist or scope."""


# --------------------------------------------------------------------------- #
# Tool Broker: typed plan -> shell-free HTTP execution.
# --------------------------------------------------------------------------- #


class BrokeredHttpRequest(StrictModel):
    """One controller-rendered, shell-free HTTP request. No argv, no shell, no model text."""

    label: Literal["CONTROL", "BOUNDARY_PROBE"]
    method: Literal["POST"]
    route: str = Field(min_length=1, max_length=200)
    destination_ref: Literal["INSTANCE_METADATA", "APPROVED_PARTNER_STATUS"]
    # The concrete resolved destination URL is broker-side only; it is never placed in any model
    # projection, observation or report.
    resolved_destination: str = Field(min_length=8, max_length=240)


class BrokeredBoundaryExecution(StrictModel):
    """The full shell-free execution the broker renders from a typed plan."""

    capability_id: Literal["aegis.cloud.metadata_boundary_probe"]
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    boundary_class: str = Field(min_length=3, max_length=64)
    requests: list[BrokeredHttpRequest] = Field(min_length=2, max_length=2)
    shell_free: bool


class CloudBoundaryBroker:
    """Convert a typed :class:`CloudBoundaryPlanOutput` into a shell-free HTTP execution.

    It re-validates every model selection against the controller allowlist (capability id, target,
    boundary class, destination reference) and resolves the symbolic destination to a concrete
    origin controller-side. It renders an HTTP request pair — never an argv, never a shell — and
    proves the rendering is shell-free.
    """

    def render(self, plan: CloudBoundaryPlanOutput) -> BrokeredBoundaryExecution:
        if plan.capability_id not in CLOUD_BOUNDARY_CAPABILITIES:
            raise CloudBoundaryRejection("CLOUD_CAPABILITY_NOT_REGISTERED")
        if plan.boundary_class not in CLOUD_BOUNDARY_CLASSES:
            raise CloudBoundaryRejection("CLOUD_BOUNDARY_CLASS_NOT_REGISTERED")
        if plan.probe.method != _PROBE_METHOD:
            raise CloudBoundaryRejection("CLOUD_PROBE_METHOD_NOT_ALLOWED")
        if plan.probe.destination_ref not in CLOUD_DESTINATION_REFS:
            raise CloudBoundaryRejection("CLOUD_DESTINATION_NOT_REGISTERED")
        requests = [
            self._request("CONTROL", _CONTROL_DESTINATION),
            self._request("BOUNDARY_PROBE", plan.probe.destination_ref),
        ]
        shell_free = all(self._is_shell_free(request) for request in requests)
        if not shell_free:
            raise CloudBoundaryRejection("CLOUD_EXECUTION_NOT_SHELL_FREE")
        return BrokeredBoundaryExecution(
            capability_id=plan.capability_id,
            target_ref=plan.target_ref,
            boundary_class=plan.boundary_class,
            requests=requests,
            shell_free=shell_free,
        )

    def _request(
        self, label: Literal["CONTROL", "BOUNDARY_PROBE"], destination_ref: str
    ) -> BrokeredHttpRequest:
        resolved = _DESTINATION_RESOLUTION.get(destination_ref)
        if resolved is None:
            raise CloudBoundaryRejection("CLOUD_DESTINATION_UNRESOLVABLE")
        return BrokeredHttpRequest(
            label=label,
            method=_PROBE_METHOD,
            route=_PROBE_ROUTE,
            destination_ref=destination_ref,  # type: ignore[arg-type]
            resolved_destination=resolved,
        )

    @staticmethod
    def _is_shell_free(request: BrokeredHttpRequest) -> bool:
        if request.method != _PROBE_METHOD:
            return False
        if not _SAFE_ROUTE_RE.match(request.route):
            return False
        # The resolved destination must be an exact allowlisted value and carry no shell
        # metacharacter or whitespace (a rendered request is a structured HTTP call, never a shell).
        if request.resolved_destination not in _DESTINATION_RESOLUTION.values():
            return False
        return not any(ch in request.resolved_destination for ch in _SHELL_METACHARACTERS)


def brokered_request_body(request: BrokeredHttpRequest) -> dict[str, str]:
    """The concrete request body a probe runner sends. Broker-side only, never a projection."""

    return {"url": request.resolved_destination}


# --------------------------------------------------------------------------- #
# Source-side sanitization + normalization of the untrusted probe response.
# --------------------------------------------------------------------------- #


def sanitize_probe_response(label: str, status_code: int, body: object) -> dict[str, object]:
    """Reduce one raw probe response to sanitized, credential-free facts.

    This runs at the source (inside the probe runner) so the synthetic metadata credential value
    never leaves the probe boundary in cleartext. It records only the response status, whether the
    integration was reachable, whether a credential-shaped field is present (as a boolean and field
    name, never the value), and whether target-controlled instruction-like content was observed
    (flagged as data, never obeyed).
    """

    reachable = False
    credential_field_present = False
    credential_field_names: list[str] = []
    result_obj: object = None
    if isinstance(body, dict):
        reachable = body.get("reachable") is True
        result_obj = body.get("result")
    if isinstance(result_obj, dict):
        raw_value = result_obj.get(_CREDENTIAL_FIELD)
        if isinstance(raw_value, str) and raw_value.startswith(_CREDENTIAL_PREFIX):
            credential_field_present = True
            credential_field_names.append(_CREDENTIAL_FIELD)
    # Instruction-resistance: scan the untrusted response text for hostile markers, as DATA.
    lowered = _stringify(body).lower()
    instruction_like = any(marker in lowered for marker in HOSTILE_INSTRUCTION_MARKERS)
    return {
        "label": label,
        "status_code": int(status_code),
        "reachable": reachable,
        "credential_field_present": credential_field_present,
        "credential_field_names": credential_field_names,
        "instruction_like_content": instruction_like,
    }


def _stringify(body: object) -> str:
    import json

    try:
        return json.dumps(body, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(body)


class CloudBoundaryObservationKind:
    INTEGRATION_RESPONSE = "INTEGRATION_RESPONSE"
    CREDENTIAL_FIELD_PRESENT = "CREDENTIAL_FIELD_PRESENT"
    CREDENTIAL_FIELD_ABSENT = "CREDENTIAL_FIELD_ABSENT"
    NO_FINDING = "NO_FINDING"
    INCOMPLETE_TOOL_ERROR = "INCOMPLETE_TOOL_ERROR"


class IntegrationResponseObservation(StrictModel):
    kind: Literal["INTEGRATION_RESPONSE"] = "INTEGRATION_RESPONSE"
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    label: Literal["CONTROL", "BOUNDARY_PROBE"]
    status_code: int = Field(ge=0, le=599)
    reachable: bool
    instruction_like_content: bool = False


class CredentialFieldObservation(StrictModel):
    kind: Literal["CREDENTIAL_FIELD_PRESENT", "CREDENTIAL_FIELD_ABSENT"]
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    # Only the field NAME is ever recorded, never the value.
    field_name: str = Field(default="", max_length=40)


class CloudNoFinding(StrictModel):
    kind: Literal["NO_FINDING"] = "NO_FINDING"
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    capability_id: str = Field(min_length=3, max_length=80)
    detail: str = Field(default="", max_length=120)


class CloudIncompleteObservation(StrictModel):
    kind: Literal["INCOMPLETE_TOOL_ERROR"] = "INCOMPLETE_TOOL_ERROR"
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    capability_id: str = Field(min_length=3, max_length=80)
    reason: str = Field(min_length=1, max_length=120)


CloudBoundaryObservationModel = (
    IntegrationResponseObservation
    | CredentialFieldObservation
    | CloudNoFinding
    | CloudIncompleteObservation
)


def normalize_boundary_observations(
    target_ref: str, sanitized_results: list[dict[str, object]] | None
) -> list[CloudBoundaryObservationModel]:
    """Turn sanitized probe results into typed, credential-free, reference-only observations.

    A ``None`` or empty result set (a tool error) yields a single INCOMPLETE observation, never a
    clean NO_FINDING — an absent observation is never silently a pass.
    """

    if not sanitized_results:
        return [
            CloudIncompleteObservation(
                target_ref=target_ref,
                capability_id=CAP_CLOUD_METADATA_BOUNDARY_PROBE,
                reason="probe produced no result",
            )
        ]
    observations: list[CloudBoundaryObservationModel] = []
    for item in sanitized_results:
        label = str(item.get("label", ""))
        if label not in {"CONTROL", "BOUNDARY_PROBE"}:
            observations.append(
                CloudIncompleteObservation(
                    target_ref=target_ref,
                    capability_id=CAP_CLOUD_METADATA_BOUNDARY_PROBE,
                    reason="probe result missing request label",
                )
            )
            continue
        raw_status = str(item.get("status_code", ""))
        status = int(raw_status) if raw_status.isdigit() else 0
        typed_label: Literal["CONTROL", "BOUNDARY_PROBE"] = (
            "CONTROL" if label == "CONTROL" else "BOUNDARY_PROBE"
        )
        observations.append(
            IntegrationResponseObservation(
                target_ref=target_ref,
                label=typed_label,
                status_code=status,
                reachable=bool(item.get("reachable")),
                instruction_like_content=bool(item.get("instruction_like_content")),
            )
        )
        if label == "BOUNDARY_PROBE" and status == 200:
            present = bool(item.get("credential_field_present"))
            names = item.get("credential_field_names")
            field_name = names[0] if isinstance(names, list) and names else ""
            credential_kind: Literal["CREDENTIAL_FIELD_PRESENT", "CREDENTIAL_FIELD_ABSENT"] = (
                "CREDENTIAL_FIELD_PRESENT" if present else "CREDENTIAL_FIELD_ABSENT"
            )
            observations.append(
                CredentialFieldObservation(
                    kind=credential_kind,
                    target_ref=target_ref,
                    field_name=str(field_name)[:40],
                )
            )
        elif label == "BOUNDARY_PROBE":
            observations.append(
                CloudNoFinding(
                    target_ref=target_ref,
                    capability_id=CAP_CLOUD_METADATA_BOUNDARY_PROBE,
                    detail=f"boundary destination not admitted (status {status})",
                )
            )
    return observations


def observation_warnings(
    observations: list[CloudBoundaryObservationModel],
) -> list[str]:
    """Instruction-resistance warnings: target-controlled instruction-like content, as data."""

    if any(
        isinstance(obs, IntegrationResponseObservation) and obs.instruction_like_content
        for obs in observations
    ):
        return ["target-controlled instruction-like content observed; treated as data"]
    return []


# --------------------------------------------------------------------------- #
# Real, persisted, addressable CLOUD_BOUNDARY_AGENT inbound job queue.
# --------------------------------------------------------------------------- #

_JOB_ADDRESS_SCHEME = "agentjob"
_JOB_AGENT = "CLOUD_BOUNDARY_AGENT"


class CloudBoundaryJobQueueError(RuntimeError):
    """A job-queue-level failure (duplicate id, malformed address, illegal transition)."""


class CloudBoundaryJob(StrictModel):
    """A real, persisted, addressable inbound job for the Cloud Boundary Agent.

    It carries only references: the target and a boundary-class hypothesis to test. No mode,
    ground-truth id, verdict, severity, credential or origin is representable.
    """

    job_id: str = Field(pattern=r"^cbjob-[a-f0-9]{16}$")
    to_agent: Literal["CLOUD_BOUNDARY_AGENT"] = "CLOUD_BOUNDARY_AGENT"
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    boundary_class: str = Field(min_length=3, max_length=64)
    objective: str = Field(min_length=3, max_length=300)
    status: Literal["QUEUED", "CLAIMED", "CLOSED"] = "QUEUED"
    enqueued_at: datetime = Field(default_factory=now_utc)

    @property
    def address(self) -> str:
        return f"{_JOB_ADDRESS_SCHEME}://{self.to_agent}/{self.job_id}"


def parse_job_address(address: str) -> tuple[str, str]:
    prefix = f"{_JOB_ADDRESS_SCHEME}://"
    if not address.startswith(prefix):
        raise CloudBoundaryJobQueueError("JOB_ADDRESS_SCHEME_INVALID")
    rest = address[len(prefix) :]
    to_agent, sep, job_id = rest.partition("/")
    if not sep or to_agent != _JOB_AGENT or not job_id:
        raise CloudBoundaryJobQueueError("JOB_ADDRESS_MALFORMED")
    return to_agent, job_id


class CloudBoundaryJobQueue:
    """A durable, addressable inbound job queue for the Cloud Boundary Agent, backed by SQLite.

    It supports enqueue (persist + address), get/resolve (addressable read), claim (QUEUED ->
    CLAIMED) and close (CLAIMED -> CLOSED), and records every state transition so the audit trail
    shows the job was really consumed, not synthesized in memory.
    """

    def __init__(self, database_path: str) -> None:
        self.database_path = database_path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> None:
        Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS cloud_boundary_jobs (
                    job_id TEXT PRIMARY KEY,
                    to_agent TEXT NOT NULL,
                    status TEXT NOT NULL,
                    address TEXT NOT NULL UNIQUE,
                    enqueued_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cloud_boundary_job_transitions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    from_status TEXT NOT NULL,
                    to_status TEXT NOT NULL,
                    at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_cloud_boundary_jobs_agent_status
                    ON cloud_boundary_jobs(to_agent, status);
                """
            )

    def enqueue(self, job: CloudBoundaryJob) -> str:
        with self._connect() as connection:
            try:
                connection.execute(
                    """INSERT INTO cloud_boundary_jobs(
                        job_id, to_agent, status, address, enqueued_at, payload
                    ) VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        job.job_id,
                        job.to_agent,
                        job.status,
                        job.address,
                        job.enqueued_at.isoformat(),
                        job.model_dump_json(),
                    ),
                )
                self._record_transition(connection, job.job_id, "NONE", job.status)
            except sqlite3.IntegrityError as exc:
                raise CloudBoundaryJobQueueError("JOB_ID_ALREADY_ENQUEUED") from exc
        return job.address

    def get(self, job_id: str) -> CloudBoundaryJob | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM cloud_boundary_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
        return CloudBoundaryJob.model_validate_json(row["payload"]) if row else None

    def resolve(self, address: str) -> CloudBoundaryJob | None:
        to_agent, job_id = parse_job_address(address)
        job = self.get(job_id)
        if job is not None and job.to_agent != to_agent:
            raise CloudBoundaryJobQueueError("JOB_ADDRESS_ROUTING_MISMATCH")
        return job

    def claim(self, address: str) -> CloudBoundaryJob:
        """Consume a queued job by its durable address (QUEUED -> CLAIMED); fail closed else."""

        return self._transition(address, expected="QUEUED", new="CLAIMED")

    def close(self, address: str) -> CloudBoundaryJob:
        """Close a claimed job (CLAIMED -> CLOSED)."""

        return self._transition(address, expected="CLAIMED", new="CLOSED")

    def _transition(self, address: str, *, expected: str, new: str) -> CloudBoundaryJob:
        to_agent, job_id = parse_job_address(address)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload, status FROM cloud_boundary_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
            if row is None:
                raise CloudBoundaryJobQueueError("JOB_NOT_FOUND")
            job = CloudBoundaryJob.model_validate_json(row["payload"])
            if job.to_agent != to_agent:
                raise CloudBoundaryJobQueueError("JOB_ADDRESS_ROUTING_MISMATCH")
            if row["status"] != expected:
                raise CloudBoundaryJobQueueError(
                    f"JOB_ILLEGAL_TRANSITION_{row['status']}_TO_{new}"
                )
            updated = job.model_copy(update={"status": new})
            connection.execute(
                "UPDATE cloud_boundary_jobs SET status = ?, payload = ? WHERE job_id = ?",
                (new, updated.model_dump_json(), job_id),
            )
            self._record_transition(connection, job_id, expected, new)
        return updated

    def transitions(self, job_id: str) -> list[dict[str, str]]:
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT from_status, to_status, at FROM cloud_boundary_job_transitions
                WHERE job_id = ? ORDER BY id""",
                (job_id,),
            ).fetchall()
        return [
            {"from": row["from_status"], "to": row["to_status"], "at": row["at"]} for row in rows
        ]

    def count(self) -> int:
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS n FROM cloud_boundary_jobs").fetchone()
        return int(row["n"])

    @staticmethod
    def _record_transition(
        connection: sqlite3.Connection, job_id: str, from_status: str, to_status: str
    ) -> None:
        connection.execute(
            """INSERT INTO cloud_boundary_job_transitions(job_id, from_status, to_status, at)
            VALUES (?, ?, ?, ?)""",
            (job_id, from_status, to_status, now_utc().isoformat()),
        )
