"""Phase 2.0 — verified multi-primitive attack-chain substrate.

This is the control-plane half of a single, real, causally-connected two-primitive attack chain
against the operator-authorized synthetic ``aegis-cloud`` range. It is *not* the Phase 1.7-B
``DELEGATION_WORKFLOW_CHAIN`` (that composes recon -> injection -> verification as a delegation
workflow and confirms nothing). Here two **distinct** security primitives are linked by a real,
opaque credential handoff, and the whole chain is adjudicated only by the independent deterministic
range verifier:

* **Stage A — METADATA_CREDENTIAL_EXPOSURE** (``cloud-metadata-response-v1``, GT-RANGE-CLOUD-004,
  CWE-200): the synthetic instance-metadata response reachable through the integration-check surface
  returns a fresh credential-shaped field. The broker captures that value **at the source**, into an
  isolated ephemeral secret store, and emits only an opaque ``credentialref://`` reference. The raw
  value never enters an observation, a model prompt, a queue payload, a projection, a log or an
  artifact.
* **Stage B — INTERNAL_SERVICE_AUTHORIZATION** (``cloud-service-access-v1``, GT-RANGE-CLOUD-005,
  CWE-285): the private administration service accepts that metadata-scoped (wrong-audience)
  credential and performs a privileged operation. Stage B **cannot** succeed without Stage A's
  captured credential: the broker resolves the opaque reference *broker-side* and the downstream
  capability never sees the value either.

Causal dependency is the point: Stage B requires an artifact only Stage A can produce. With an
absent or unrelated/invalid reference the private operation is rejected; when Stage A is patched no
usable reference is created at all and the chain stops before protected-resource access.

Authority model (unchanged): the model interprets observations, constructs typed chain hypotheses
and *selects* registered capabilities and symbolic destinations. It is never authoritative for
authorization, ground truth, credential values, confirmation, severity, PASS/FAIL, causal-link
truth, final impact or cleanup. Every link and the final chain are confirmed only by the
controller-owned ground truth and the independent deterministic verifier.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Literal

from pydantic import Field

from aegis.multi_agent.contracts import StrictModel, now_utc
from aegis.multi_agent.injection import HOSTILE_INSTRUCTION_MARKERS

# --------------------------------------------------------------------------- #
# Chain vocabulary. Kept in lockstep with the gateway contracts by a drift-guard test.
# --------------------------------------------------------------------------- #

CHAIN_CLASS = "VERIFIED_MULTI_PRIMITIVE_CHAIN"
CHAIN_ID = "cloud-service-chain-v1"

# The two DISTINCT security primitives this chain composes, in order.
PRIMITIVE_METADATA_CREDENTIAL_EXPOSURE = "METADATA_CREDENTIAL_EXPOSURE"
PRIMITIVE_INTERNAL_SERVICE_AUTHORIZATION = "INTERNAL_SERVICE_AUTHORIZATION"
CHAIN_PRIMITIVE_TYPES: tuple[str, str] = (
    PRIMITIVE_METADATA_CREDENTIAL_EXPOSURE,
    PRIMITIVE_INTERNAL_SERVICE_AUTHORIZATION,
)

# The registered capabilities each stage may use. Stage A reuses the Phase 1.9 metadata probe; Stage
# B is the new bounded credential-backed internal-service access capability.
CAP_METADATA_BOUNDARY_PROBE = "aegis.cloud.metadata_boundary_probe"
CAP_INTERNAL_SERVICE_ACCESS = "aegis.cloud.internal_service_access"
CHAIN_CAPABILITIES: frozenset[str] = frozenset(
    {CAP_METADATA_BOUNDARY_PROBE, CAP_INTERNAL_SERVICE_ACCESS}
)

# Symbolic destinations the model may name. Neither is a URL: the broker resolves each to a concrete
# internal origin+route controller-side.
CHAIN_DESTINATION_REFS: frozenset[str] = frozenset({"INSTANCE_METADATA", "PRIVATE_ADMIN_OPERATION"})

# The two aegis-cloud scenarios the two primitives map to (controller-owned; model-unseen).
STAGE_A_SCENARIO = "cloud-metadata-response-v1"
STAGE_B_SCENARIO = "cloud-service-access-v1"

# Broker-owned routes/origins. These concrete values live ONLY here and in the rendered execution —
# never in a model prompt, projection, observation or report.
_STAGE_A_ROUTE = "/api/integrations/check"
_STAGE_B_CONTROL_ROUTE = "/api/operations/summary"
_STAGE_B_PROBE_ROUTE = "/api/integrations/execute"
_METADATA_DESTINATION_URL = "http://range-canary:8500/status/instance"
_PARTNER_CONTROL_URL = "https://status.partner.invalid/health"

# The field a credential-shaped value occupies in the synthetic metadata response, and the synthetic
# credential prefix (controller-side detection only, never emitted).
_CREDENTIAL_FIELD = "access_token"
_CREDENTIAL_PREFIX = "meta."
# The synthetic private-operation effect marker. Only its *presence* (a boolean) is ever recorded.
_ADMIN_EFFECT_MARKER = "ADMIN-EFFECT"

_SHELL_METACHARACTERS = frozenset({";", "|", "&", "$", "`", "\n", "\r", " ", "\t", ">", "<"})
_SAFE_ROUTE_RE = re.compile(r"^/[A-Za-z0-9/_.-]+$")


class ChainRejection(ValueError):
    """Raised when a chain selection escapes the controller allowlist or scope."""


class SecretStoreError(RuntimeError):
    """A secret-store-level failure (unknown, revoked or expired reference). Fails closed."""


# --------------------------------------------------------------------------- #
# Isolated ephemeral secret store + opaque credential references.
# --------------------------------------------------------------------------- #

_CREDENTIAL_REF_SCHEME = "credentialref"
_CREDENTIAL_REF_RE = re.compile(r"^credentialref://[a-z0-9-]+/[a-f0-9]{32}$")


class CredentialBinding(StrictModel):
    """The non-secret binding of an opaque credential reference. No value is representable here."""

    reference: str = Field(pattern=r"^credentialref://[a-z0-9-]+/[a-f0-9]{32}$")
    chain_id: str = Field(min_length=3, max_length=64)
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    capability_id: str = Field(min_length=3, max_length=80)
    lease_id: str = Field(pattern=r"^lease-[a-f0-9]{16}$")
    expires_at: datetime
    revoked: bool = False


class EphemeralSecretStore:
    """An isolated, in-process, ephemeral store for a captured synthetic credential value.

    The raw value lives ONLY inside this store and the code that resolves it broker-side. There is
    no accessor that returns the binding *and* the value together, and :meth:`resolve` is the only
    path to the value — it fails closed for an unknown, expired or revoked reference, and after
    :meth:`revoke`/:meth:`zeroize` the value is overwritten and unrecoverable. The store never
    serializes the value; :meth:`bindings` exposes only non-secret bindings.
    """

    def __init__(self, *, ttl_seconds: int = 300) -> None:
        self._ttl = timedelta(seconds=ttl_seconds)
        self._values: dict[str, str] = {}
        self._bindings: dict[str, CredentialBinding] = {}

    def capture(
        self, *, chain_id: str, target_ref: str, capability_id: str, value: str
    ) -> CredentialBinding:
        """Capture a raw credential value and mint an opaque, bound reference. Value stays here."""

        if not value:
            raise SecretStoreError("SECRET_STORE_EMPTY_VALUE")
        reference = f"{_CREDENTIAL_REF_SCHEME}://{chain_id}/{secrets.token_hex(16)}"
        binding = CredentialBinding(
            reference=reference,
            chain_id=chain_id,
            target_ref=target_ref,
            capability_id=capability_id,
            lease_id=f"lease-{secrets.token_hex(8)}",
            expires_at=now_utc() + self._ttl,
        )
        self._values[reference] = value
        self._bindings[reference] = binding
        return binding

    def resolve(self, reference: str, *, expected_capability_id: str | None = None) -> str:
        """Resolve a reference to its raw value broker-side, or fail closed. Never logged."""

        binding = self._bindings.get(reference)
        if binding is None or reference not in self._values:
            raise SecretStoreError("SECRET_STORE_UNKNOWN_REFERENCE")
        if binding.revoked:
            raise SecretStoreError("SECRET_STORE_REFERENCE_REVOKED")
        if now_utc() >= binding.expires_at:
            raise SecretStoreError("SECRET_STORE_REFERENCE_EXPIRED")
        if expected_capability_id is not None and expected_capability_id not in CHAIN_CAPABILITIES:
            # A reference is scoped to the authorized chain: only a registered chain capability may
            # resolve it (Stage A produces it, Stage B consumes it). Any out-of-chain capability is
            # rejected, so the credential cannot be reused outside the authorized chain.
            raise SecretStoreError("SECRET_STORE_CAPABILITY_NOT_IN_CHAIN")
        return self._values[reference]

    def revoke(self, reference: str) -> bool:
        """Revoke and zeroize one reference's value. Idempotent; returns whether it existed."""

        existed = reference in self._bindings
        if reference in self._values:
            # Overwrite before delete so the value cannot linger.
            self._values[reference] = "0" * len(self._values[reference])
            del self._values[reference]
        binding = self._bindings.get(reference)
        if binding is not None:
            self._bindings[reference] = binding.model_copy(update={"revoked": True})
        return existed

    def zeroize(self) -> int:
        """Revoke every reference; return how many were held. Cleanup path."""

        references = list(self._bindings)
        for reference in references:
            self.revoke(reference)
        return len(references)

    def is_resolvable(self, reference: str) -> bool:
        try:
            self.resolve(reference)
        except SecretStoreError:
            return False
        return True

    def binding(self, reference: str) -> CredentialBinding | None:
        return self._bindings.get(reference)

    def bindings(self) -> list[CredentialBinding]:
        return list(self._bindings.values())


def is_credential_reference(value: str) -> bool:
    return bool(_CREDENTIAL_REF_RE.match(value))


# --------------------------------------------------------------------------- #
# Stage A capture: sanitize the untrusted metadata response, credential value -> secret store only.
# --------------------------------------------------------------------------- #


def capture_stage_a_response(
    store: EphemeralSecretStore,
    *,
    chain_id: str,
    target_ref: str,
    label: str,
    status_code: int,
    body: object,
) -> dict[str, object]:
    """Reduce one Stage-A probe response to sanitized facts and capture any credential value.

    Runs at the source (inside the probe boundary). If a credential-shaped field is present, its
    value is captured into ``store`` and only the opaque reference (plus a boolean) is returned; the
    value itself is never placed in the returned facts. Instruction-like content is flagged as DATA.
    """

    reachable = False
    result_obj: object = None
    if isinstance(body, dict):
        reachable = body.get("reachable") is True
        result_obj = body.get("result")
    credential_reference: str | None = None
    credential_field_present = False
    if label == "BOUNDARY_PROBE" and status_code == 200 and isinstance(result_obj, dict):
        raw_value = result_obj.get(_CREDENTIAL_FIELD)
        if isinstance(raw_value, str) and raw_value.startswith(_CREDENTIAL_PREFIX):
            credential_field_present = True
            binding = store.capture(
                chain_id=chain_id,
                target_ref=target_ref,
                capability_id=CAP_METADATA_BOUNDARY_PROBE,
                value=raw_value,
            )
            credential_reference = binding.reference
    lowered = _stringify(body).lower()
    instruction_like = any(marker in lowered for marker in HOSTILE_INSTRUCTION_MARKERS)
    return {
        "label": label,
        "status_code": int(status_code),
        "reachable": reachable,
        "credential_field_present": credential_field_present,
        "credential_reference": credential_reference,
        "instruction_like_content": instruction_like,
    }


# --------------------------------------------------------------------------- #
# Stage B broker: opaque reference -> shell-free credential-backed internal-service access.
# --------------------------------------------------------------------------- #


class BrokeredServiceRequest(StrictModel):
    """One controller-rendered, shell-free Stage-B HTTP request. No argv, no shell, no text."""

    label: Literal["CONTROL", "SERVICE_ACCESS"]
    method: Literal["GET", "POST"]
    route: str = Field(min_length=1, max_length=200)
    # Whether this request consumes the resolved credential (SERVICE_ACCESS) or not (CONTROL). The
    # value itself is never represented here — the broker injects it at send time from the store.
    uses_credential_reference: bool = False


class BrokeredServiceExecution(StrictModel):
    """The full shell-free Stage-B execution the broker renders for the service capability."""

    capability_id: Literal["aegis.cloud.internal_service_access"]
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    primitive_type: Literal["INTERNAL_SERVICE_AUTHORIZATION"]
    credential_reference: str = Field(pattern=r"^credentialref://[a-z0-9-]+/[a-f0-9]{32}$")
    requests: list[BrokeredServiceRequest] = Field(min_length=2, max_length=2)
    shell_free: bool


class InternalServiceAccessBroker:
    """Render Stage-B credential-backed internal-service access; resolve the reference broker-side.

    The model never authors a URL, credential or body; it selects the registered capability and the
    symbolic ``PRIVATE_ADMIN_OPERATION`` destination, and the chain binds an opaque credential
    reference produced by Stage A. This broker re-validates every selection, renders a shell-free
    control+probe pair, and (at send time) resolves the reference through the isolated secret store.
    A missing, unrelated or revoked reference fails closed before any request is rendered.
    """

    def render(
        self,
        *,
        target_ref: str,
        capability_id: str,
        destination_ref: str,
        credential_reference: str,
        store: EphemeralSecretStore,
    ) -> BrokeredServiceExecution:
        if capability_id != CAP_INTERNAL_SERVICE_ACCESS:
            raise ChainRejection("CHAIN_CAPABILITY_NOT_REGISTERED")
        if destination_ref != "PRIVATE_ADMIN_OPERATION":
            raise ChainRejection("CHAIN_DESTINATION_NOT_REGISTERED")
        if not is_credential_reference(credential_reference):
            raise ChainRejection("CHAIN_CREDENTIAL_REFERENCE_MALFORMED")
        # The reference must resolve broker-side for THIS capability, or Stage B cannot proceed.
        if not store.is_resolvable(credential_reference):
            raise ChainRejection("CHAIN_CREDENTIAL_REFERENCE_UNRESOLVABLE")
        requests = [
            BrokeredServiceRequest(label="CONTROL", method="GET", route=_STAGE_B_CONTROL_ROUTE),
            BrokeredServiceRequest(
                label="SERVICE_ACCESS",
                method="POST",
                route=_STAGE_B_PROBE_ROUTE,
                uses_credential_reference=True,
            ),
        ]
        shell_free = all(self._is_shell_free(request) for request in requests)
        if not shell_free:
            raise ChainRejection("CHAIN_EXECUTION_NOT_SHELL_FREE")
        return BrokeredServiceExecution(
            capability_id="aegis.cloud.internal_service_access",
            target_ref=target_ref,
            primitive_type=PRIMITIVE_INTERNAL_SERVICE_AUTHORIZATION,  # type: ignore[arg-type]
            credential_reference=credential_reference,
            requests=requests,
            shell_free=shell_free,
        )

    @staticmethod
    def _is_shell_free(request: BrokeredServiceRequest) -> bool:
        if request.method not in {"GET", "POST"}:
            return False
        if not _SAFE_ROUTE_RE.match(request.route):
            return False
        return not any(ch in request.route for ch in _SHELL_METACHARACTERS)


def stage_a_control_url() -> str:
    """Broker-side benign control destination for Stage A. Never a model projection."""

    return _PARTNER_CONTROL_URL


def stage_a_probe_url() -> str:
    """Broker-side metadata destination for Stage A. Never a model projection."""

    return _METADATA_DESTINATION_URL


def sanitize_service_response(label: str, status_code: int, body: object) -> dict[str, object]:
    """Reduce one Stage-B response to sanitized, value-free facts.

    Records only the response status, whether the private-operation effect was produced (a boolean,
    from the presence of the synthetic marker), and whether instruction-like content was observed.
    The credential value and the raw effect string are never carried forward.
    """

    admin_effect_present = False
    if isinstance(body, dict):
        effect = body.get("effect")
        if isinstance(effect, str) and effect.startswith(_ADMIN_EFFECT_MARKER):
            admin_effect_present = True
    lowered = _stringify(body).lower()
    instruction_like = any(marker in lowered for marker in HOSTILE_INSTRUCTION_MARKERS)
    return {
        "label": label,
        "status_code": int(status_code),
        "admin_effect_present": admin_effect_present,
        "instruction_like_content": instruction_like,
    }


def _stringify(body: object) -> str:
    try:
        return json.dumps(body, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(body)


# --------------------------------------------------------------------------- #
# Typed chain data model + persistence.
# --------------------------------------------------------------------------- #


class ChainState(StrEnum):
    PLANNED = "PLANNED"
    RUNNING = "RUNNING"
    LINK_UNCONFIRMED = "LINK_UNCONFIRMED"
    LINK_CONFIRMED = "LINK_CONFIRMED"
    BLOCKED_BY_PATCH = "BLOCKED_BY_PATCH"
    CHAIN_CONFIRMED = "CHAIN_CONFIRMED"
    FAILED = "FAILED"
    CLEANED = "CLEANED"


class LinkHypothesisState(StrEnum):
    HYPOTHESIS = "HYPOTHESIS"
    EXECUTED = "EXECUTED"


class LinkVerificationState(StrEnum):
    UNVERIFIED = "UNVERIFIED"
    CONFIRMED = "CONFIRMED"
    PASS = "PASS"  # noqa: S105 - verification label, not a credential
    BLOCKED = "BLOCKED"
    INCOMPLETE = "INCOMPLETE"


class ChainLink(StrictModel):
    """One causally-ordered link. Only references, hashes, states — never a credential value.

    ``hypothesis_confirmed`` is fixed False at the type level: a link is a hypothesis until the
    independent verifier promotes ``verification_state``. ``depends_on_link_id`` records the causal
    dependency on the prior link's output; the first link has none.
    """

    link_id: str = Field(pattern=r"^clink-[a-f0-9]{16}$")
    chain_id: str = Field(min_length=3, max_length=64)
    stage_index: int = Field(ge=0, le=8)
    primitive_type: Literal["METADATA_CREDENTIAL_EXPOSURE", "INTERNAL_SERVICE_AUTHORIZATION"]
    capability_id: str = Field(min_length=3, max_length=80)
    producing_agent: str = Field(min_length=3, max_length=40)
    consuming_agent: str = Field(min_length=3, max_length=40)
    input_evidence_refs: list[str] = Field(default_factory=list, max_length=8)
    output_evidence_refs: list[str] = Field(default_factory=list, max_length=8)
    source_evidence_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    depends_on_link_id: str | None = Field(default=None, pattern=r"^clink-[a-f0-9]{16}$")
    # Whether this link's execution required consuming the prior link's opaque credential reference.
    consumes_prior_credential_reference: bool = False
    credential_reference: str | None = Field(
        default=None, pattern=r"^credentialref://[a-z0-9-]+/[a-f0-9]{32}$"
    )
    hypothesis_confirmed: Literal[False] = False
    hypothesis_state: LinkHypothesisState = LinkHypothesisState.HYPOTHESIS
    verification_state: LinkVerificationState = LinkVerificationState.UNVERIFIED
    # Controller-owned severity/impact reference (a ground-truth id), never a model-authored value.
    severity_ref: str | None = Field(default=None, max_length=64)
    cleanup_required: bool = True
    created_at: datetime = Field(default_factory=now_utc)


class AttackChainRecord(StrictModel):
    """The typed chain header. Ordered link ids, authorized targets, overall state, severity ref."""

    chain_id: str = Field(min_length=3, max_length=64)
    chain_class: Literal["VERIFIED_MULTI_PRIMITIVE_CHAIN"] = CHAIN_CLASS  # type: ignore[assignment]
    objective: str = Field(min_length=3, max_length=300)
    authorized_target_refs: list[str] = Field(min_length=1, max_length=4)
    ordered_link_ids: list[str] = Field(default_factory=list, max_length=8)
    overall_state: ChainState = ChainState.PLANNED
    severity_ref: str | None = Field(default=None, max_length=64)
    created_at: datetime = Field(default_factory=now_utc)


def new_link_id() -> str:
    return f"clink-{secrets.token_hex(8)}"


# Addressable inbound CHAIN_AGENT job (mirrors the Phase 1.9 CloudBoundaryJobQueue pattern).
_JOB_ADDRESS_SCHEME = "agentjob"
_JOB_AGENT = "CHAIN_AGENT"


class ChainJobQueueError(RuntimeError):
    """A chain-job-queue-level failure (duplicate id, malformed address, illegal transition)."""


class ChainJob(StrictModel):
    """A real, persisted, addressable inbound job for the Chain Agent. References only."""

    job_id: str = Field(pattern=r"^chjob-[a-f0-9]{16}$")
    to_agent: Literal["CHAIN_AGENT"] = "CHAIN_AGENT"
    chain_id: str = Field(min_length=3, max_length=64)
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    objective: str = Field(min_length=3, max_length=300)
    status: Literal["QUEUED", "CLAIMED", "CLOSED"] = "QUEUED"
    enqueued_at: datetime = Field(default_factory=now_utc)

    @property
    def address(self) -> str:
        return f"{_JOB_ADDRESS_SCHEME}://{self.to_agent}/{self.job_id}"


def parse_chain_job_address(address: str) -> tuple[str, str]:
    prefix = f"{_JOB_ADDRESS_SCHEME}://"
    if not address.startswith(prefix):
        raise ChainJobQueueError("CHAIN_JOB_ADDRESS_SCHEME_INVALID")
    rest = address[len(prefix) :]
    to_agent, sep, job_id = rest.partition("/")
    if not sep or to_agent != _JOB_AGENT or not job_id:
        raise ChainJobQueueError("CHAIN_JOB_ADDRESS_MALFORMED")
    return to_agent, job_id


class AttackChainLedger:
    """Durable, addressable persistence for the chain: the inbound job, the chain record, ordered
    links (real handoffs carrying typed evidence references), and every state transition.

    Reference-only and value-free by construction: there is no column through which a credential
    value, a raw request body, an origin, a verdict or a severity value could be stored — only the
    strict :class:`ChainJob`, :class:`AttackChainRecord` and :class:`ChainLink` payloads, whose
    schemas forbid all of those.
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
                CREATE TABLE IF NOT EXISTS chain_jobs (
                    job_id TEXT PRIMARY KEY,
                    to_agent TEXT NOT NULL,
                    status TEXT NOT NULL,
                    address TEXT NOT NULL UNIQUE,
                    enqueued_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS chain_job_transitions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    from_status TEXT NOT NULL,
                    to_status TEXT NOT NULL,
                    at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS chains (
                    chain_id TEXT NOT NULL,
                    job_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (chain_id, job_id)
                );
                CREATE TABLE IF NOT EXISTS chain_links (
                    link_id TEXT PRIMARY KEY,
                    chain_id TEXT NOT NULL,
                    job_id TEXT NOT NULL,
                    stage_index INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS chain_state_transitions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chain_id TEXT NOT NULL,
                    job_id TEXT NOT NULL,
                    from_state TEXT NOT NULL,
                    to_state TEXT NOT NULL,
                    at TEXT NOT NULL
                );
                """
            )

    # --- addressable inbound job ------------------------------------------------ #

    def enqueue_job(self, job: ChainJob) -> str:
        with self._connect() as connection:
            try:
                connection.execute(
                    """INSERT INTO chain_jobs(
                        job_id, to_agent, status, address, enqueued_at, payload)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        job.job_id,
                        job.to_agent,
                        job.status,
                        job.address,
                        job.enqueued_at.isoformat(),
                        job.model_dump_json(),
                    ),
                )
                self._record_job_transition(connection, job.job_id, "NONE", job.status)
            except sqlite3.IntegrityError as exc:
                raise ChainJobQueueError("CHAIN_JOB_ID_ALREADY_ENQUEUED") from exc
        return job.address

    def get_job(self, job_id: str) -> ChainJob | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM chain_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
        return ChainJob.model_validate_json(row["payload"]) if row else None

    def resolve_job(self, address: str) -> ChainJob | None:
        to_agent, job_id = parse_chain_job_address(address)
        job = self.get_job(job_id)
        if job is not None and job.to_agent != to_agent:
            raise ChainJobQueueError("CHAIN_JOB_ADDRESS_ROUTING_MISMATCH")
        return job

    def claim_job(self, address: str) -> ChainJob:
        return self._transition_job(address, expected="QUEUED", new="CLAIMED")

    def close_job(self, address: str) -> ChainJob:
        return self._transition_job(address, expected="CLAIMED", new="CLOSED")

    def _transition_job(self, address: str, *, expected: str, new: str) -> ChainJob:
        to_agent, job_id = parse_chain_job_address(address)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload, status FROM chain_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
            if row is None:
                raise ChainJobQueueError("CHAIN_JOB_NOT_FOUND")
            job = ChainJob.model_validate_json(row["payload"])
            if job.to_agent != to_agent:
                raise ChainJobQueueError("CHAIN_JOB_ADDRESS_ROUTING_MISMATCH")
            if row["status"] != expected:
                raise ChainJobQueueError(f"CHAIN_JOB_ILLEGAL_TRANSITION_{row['status']}_TO_{new}")
            updated = job.model_copy(update={"status": new})
            connection.execute(
                "UPDATE chain_jobs SET status = ?, payload = ? WHERE job_id = ?",
                (new, updated.model_dump_json(), job_id),
            )
            self._record_job_transition(connection, job_id, expected, new)
        return updated

    def job_transitions(self, job_id: str) -> list[dict[str, str]]:
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT from_status, to_status, at FROM chain_job_transitions
                WHERE job_id = ? ORDER BY id""",
                (job_id,),
            ).fetchall()
        return [{"from": r["from_status"], "to": r["to_status"], "at": r["at"]} for r in rows]

    # --- chain record + links --------------------------------------------------- #

    def upsert_chain(self, job_id: str, record: AttackChainRecord) -> None:
        with self._connect() as connection:
            prior = connection.execute(
                "SELECT state FROM chains WHERE chain_id = ? AND job_id = ?",
                (record.chain_id, job_id),
            ).fetchone()
            connection.execute(
                """INSERT INTO chains(chain_id, job_id, state, payload, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(chain_id, job_id) DO UPDATE SET
                    state = excluded.state, payload = excluded.payload,
                    updated_at = excluded.updated_at""",
                (
                    record.chain_id,
                    job_id,
                    record.overall_state.value,
                    record.model_dump_json(),
                    now_utc().isoformat(),
                ),
            )
            from_state = prior["state"] if prior else "NONE"
            if from_state != record.overall_state.value:
                connection.execute(
                    """INSERT INTO chain_state_transitions(
                        chain_id, job_id, from_state, to_state, at)
                    VALUES (?, ?, ?, ?, ?)""",
                    (
                        record.chain_id,
                        job_id,
                        from_state,
                        record.overall_state.value,
                        now_utc().isoformat(),
                    ),
                )

    def upsert_link(self, job_id: str, link: ChainLink) -> None:
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO chain_links(
                    link_id, chain_id, job_id, stage_index, payload, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(link_id) DO UPDATE SET
                    payload = excluded.payload, updated_at = excluded.updated_at""",
                (
                    link.link_id,
                    link.chain_id,
                    job_id,
                    link.stage_index,
                    link.model_dump_json(),
                    now_utc().isoformat(),
                ),
            )

    def links(self, chain_id: str, job_id: str) -> list[ChainLink]:
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT payload FROM chain_links WHERE chain_id = ? AND job_id = ?
                ORDER BY stage_index""",
                (chain_id, job_id),
            ).fetchall()
        return [ChainLink.model_validate_json(r["payload"]) for r in rows]

    def chain(self, chain_id: str, job_id: str) -> AttackChainRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM chains WHERE chain_id = ? AND job_id = ?",
                (chain_id, job_id),
            ).fetchone()
        return AttackChainRecord.model_validate_json(row["payload"]) if row else None

    def chain_transitions(self, chain_id: str, job_id: str) -> list[dict[str, str]]:
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT from_state, to_state, at FROM chain_state_transitions
                WHERE chain_id = ? AND job_id = ? ORDER BY id""",
                (chain_id, job_id),
            ).fetchall()
        return [{"from": r["from_state"], "to": r["to_state"], "at": r["at"]} for r in rows]

    @staticmethod
    def _record_job_transition(
        connection: sqlite3.Connection, job_id: str, from_status: str, to_status: str
    ) -> None:
        connection.execute(
            """INSERT INTO chain_job_transitions(job_id, from_status, to_status, at)
            VALUES (?, ?, ?, ?)""",
            (job_id, from_status, to_status, now_utc().isoformat()),
        )


def source_sha256(payload: object) -> str:
    """Stable hash of a link's source evidence, for the audit trail."""

    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def _synthetic_credential(generation: int, audience: str) -> str:
    """Mirror of the range fixture credential, for offline tests only (never used live)."""

    body = f"meta.{generation}.{audience}"
    signature = hashlib.sha256(f"AEGIS-SYNTHETIC-CLOUD:{body}".encode()).hexdigest()[:24]
    return f"{body}.{signature}"


def _hmac_ok(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


# --------------------------------------------------------------------------- #
# Isolated chain-broker execution (runs inside a throwaway container on the range's internal
# network). Stage A capture, the causal-dependency control, Stage B and reference revocation all
# happen in this one process so the raw credential value is confined to a single execution boundary
# and never leaves the container in cleartext: only opaque references and value-free sanitized facts
# are returned. Injectable transport + base_url make the whole live data path offline-testable.
# --------------------------------------------------------------------------- #

# An unrelated/invalid, syntactically-shaped credential for the causal-dependency control. The wrong
# generation makes the private service reject it at the authorization layer (not input validation),
# proving Stage B fails with an unrelated reference. Confined to the boundary; never emitted.
_CAUSAL_CONTROL_VALUE = "meta.999999.metadata-read." + ("0" * 24)


def run_isolated_chain_probe(
    stage_a_requests: list[dict[str, str]],
    mode: str,
    *,
    base_url: str = "http://aegis-cloud:8104",
    transport: object | None = None,
) -> dict[str, object]:
    """Execute Stage A, the causal control and Stage B against the live target, all in-process.

    Returns only opaque references and value-free sanitized facts. ``mode`` is "full" (both stages)
    or "stage_a_only" (Stage A alone, for the patched arm). The raw credential value is held
    an in-process store and used only inside outbound request bodies; it is never returned.
    """

    import httpx

    store = EphemeralSecretStore()
    out: dict[str, object] = {
        "stage_a": [],
        "causal_control": None,
        "stage_b": [],
        "credential_reference_present": False,
        "post_revoke_resolvable": None,
        "revoked_reference_rejected": None,
    }
    stage_a: list[dict[str, object]] = out["stage_a"]  # type: ignore[assignment]
    stage_b: list[dict[str, object]] = out["stage_b"]  # type: ignore[assignment]
    reference: str | None = None
    client_kwargs: dict[str, object] = {
        "base_url": base_url,
        "timeout": 5,
        "trust_env": False,
        "follow_redirects": False,
    }
    if transport is not None:
        client_kwargs["transport"] = transport
    with httpx.Client(**client_kwargs) as client:  # type: ignore[arg-type]
        for request in stage_a_requests:
            try:
                response = client.post(request["route"], json={"url": request["url"]})
                body = _safe_json(response)
                facts = capture_stage_a_response(
                    store,
                    chain_id=CHAIN_ID,
                    target_ref="range-cloud",
                    label=request["label"],
                    status_code=response.status_code,
                    body=body,
                )
                if facts.get("credential_reference"):
                    reference = str(facts["credential_reference"])
                stage_a.append(facts)
            except httpx.HTTPError as exc:
                stage_a.append(_probe_error(request["label"], exc))
        out["credential_reference_present"] = bool(reference)
        if mode == "full" and reference is not None:
            out["causal_control"] = _run_causal_control(client, store)
            _run_stage_b(client, store, reference, stage_b)
            store.revoke(reference)
            out["post_revoke_resolvable"] = store.is_resolvable(reference)
            out["revoked_reference_rejected"] = _revoked_reference_rejected(store, reference)
        store.zeroize()
    return out


def _safe_json(response: object) -> object:
    try:
        return response.json()  # type: ignore[attr-defined]
    except (ValueError, TypeError):
        return None


def _probe_error(label: str, exc: Exception) -> dict[str, object]:
    return {
        "label": label,
        "status_code": 0,
        "reachable": False,
        "credential_field_present": False,
        "credential_reference": None,
        "instruction_like_content": False,
        "error": type(exc).__name__,
    }


def _run_causal_control(client: object, store: EphemeralSecretStore) -> dict[str, object]:
    """Prove an unrelated/invalid credential reference is rejected by the private operation."""

    import httpx

    bogus = store.capture(
        chain_id=CHAIN_ID,
        target_ref="range-cloud",
        capability_id=CAP_INTERNAL_SERVICE_ACCESS,
        value=_CAUSAL_CONTROL_VALUE,
    )
    try:
        InternalServiceAccessBroker().render(
            target_ref="range-cloud",
            capability_id=CAP_INTERNAL_SERVICE_ACCESS,
            destination_ref="PRIVATE_ADMIN_OPERATION",
            credential_reference=bogus.reference,
            store=store,
        )
        token = store.resolve(bogus.reference, expected_capability_id=CAP_INTERNAL_SERVICE_ACCESS)
        response = client.post(  # type: ignore[attr-defined]
            _STAGE_B_PROBE_ROUTE, json={"access_token": token}
        )
        return sanitize_service_response(
            "SERVICE_ACCESS", response.status_code, _safe_json(response)
        )
    except (httpx.HTTPError, ChainRejection, SecretStoreError) as exc:
        return {
            "label": "SERVICE_ACCESS",
            "status_code": 0,
            "admin_effect_present": False,
            "error": type(exc).__name__,
        }


def _run_stage_b(
    client: object, store: EphemeralSecretStore, reference: str, stage_b: list[dict[str, object]]
) -> None:
    """Resolve the REAL Stage-A reference broker-side and reach the private operation."""

    import httpx

    execution = InternalServiceAccessBroker().render(
        target_ref="range-cloud",
        capability_id=CAP_INTERNAL_SERVICE_ACCESS,
        destination_ref="PRIVATE_ADMIN_OPERATION",
        credential_reference=reference,
        store=store,
    )
    for request in execution.requests:
        try:
            if request.label == "CONTROL":
                response = client.get(request.route)  # type: ignore[attr-defined]
                stage_b.append(
                    sanitize_service_response("CONTROL", response.status_code, _safe_json(response))
                )
            else:
                token = store.resolve(reference, expected_capability_id=CAP_INTERNAL_SERVICE_ACCESS)
                response = client.post(  # type: ignore[attr-defined]
                    request.route, json={"access_token": token}
                )
                stage_b.append(
                    sanitize_service_response(
                        "SERVICE_ACCESS", response.status_code, _safe_json(response)
                    )
                )
        except (httpx.HTTPError, SecretStoreError) as exc:
            stage_b.append(
                {
                    "label": request.label,
                    "status_code": 0,
                    "admin_effect_present": False,
                    "error": type(exc).__name__,
                }
            )


def _revoked_reference_rejected(store: EphemeralSecretStore, reference: str) -> bool:
    """A revoked reference must no longer render a Stage-B execution (post-cleanup unusable)."""

    try:
        InternalServiceAccessBroker().render(
            target_ref="range-cloud",
            capability_id=CAP_INTERNAL_SERVICE_ACCESS,
            destination_ref="PRIVATE_ADMIN_OPERATION",
            credential_reference=reference,
            store=store,
        )
    except ChainRejection:
        return True
    return False
