"""Phase 1.7-D real, persisted, addressable recon-hypothesis delegation queue.

This is the *real* delegation boundary the Phase 1.7-C smoke deliberately stopped short of. In
1.7-C a ``DELEGATE_RECON_HYPOTHESIS`` result was **reference-only**: a validated in-memory object
that was never persisted, never assigned a durable address, and never enqueued to a downstream
consumer. Here a delegation is validated, written to SQLite, assigned a stable queue *address*, and
retrievable by that address by the next-stage boundary (the Authorization / Injection agent queue).
The downstream agent need not run — *routable and enqueued* is the contract.

Invariants (do not weaken):

* A delegation carries only *references*: a registered destination agent, an ``aegis.*`` capability
  id, a target reference, and an optional documented route/parameter. No payload, no origin, no
  credential, no verdict, no severity is representable.
* Recon never confirms. ``confirmed`` is fixed ``False`` and ``unconfirmed`` fixed ``True`` at the
  type level, so the schema itself restates that confirmation is the verifier's authority.
* ``reference_only`` is fixed ``False`` so a 1.7-D enqueued delegation is trivially distinguishable
  in the audit trail from the 1.7-C reference-only stub.
* ``source_evidence_sha256`` binds the delegation to the exact normalized observation set it was
  derived from, so the audit trail links the handoff back to the live scan that produced it.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import Field

from aegis.multi_agent.contracts import StrictModel, now_utc

# The only two downstream boundaries a recon hypothesis may be routed to (mirrors the strict
# ``ReconDelegationOutput.to_agent`` enum; duplicated, not imported across the queue boundary).
_ROUTABLE_AGENTS = ("AUTHORIZATION_AGENT", "INJECTION_AGENT")
_ADDRESS_SCHEME = "agentqueue"


class DelegationQueueError(RuntimeError):
    """A queue-level failure (duplicate id, malformed address). Always fails closed."""


class EnqueuedDelegation(StrictModel):
    """A real, persisted, addressable recon-hypothesis handoff. No payload, no verdict."""

    delegation_id: str = Field(pattern=r"^delg-[a-f0-9]{16}$")
    from_agent: Literal["RECON_AGENT"] = "RECON_AGENT"
    to_agent: Literal["AUTHORIZATION_AGENT", "INJECTION_AGENT"]
    capability_id: str = Field(pattern=r"^aegis\.[a-z0-9_.]+$")
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    route: str = Field(default="", max_length=200, pattern=r"^(/[A-Za-z0-9/._{}~-]*)?$")
    parameter: str = Field(default="", max_length=64, pattern=r"^[A-Za-z0-9_.-]*$")
    rationale: str = Field(min_length=3, max_length=300)
    # Recon never confirms; these three restate that and mark this as a real (not reference-only)
    # enqueued delegation, distinguishable in the audit trail from the 1.7-C stub.
    reference_only: Literal[False] = False
    confirmed: Literal[False] = False
    unconfirmed: Literal[True] = True
    status: Literal["QUEUED", "CLAIMED", "CLOSED"] = "QUEUED"
    # Binds the delegation to the exact live normalized observation set it was derived from.
    source_evidence_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    enqueued_at: datetime = Field(default_factory=now_utc)

    @property
    def address(self) -> str:
        """A stable, routable address the downstream consumer dequeues by."""
        return f"{_ADDRESS_SCHEME}://{self.to_agent}/{self.delegation_id}"


def parse_delegation_address(address: str) -> tuple[str, str]:
    """Split a queue address into ``(to_agent, delegation_id)`` or fail closed."""

    prefix = f"{_ADDRESS_SCHEME}://"
    if not address.startswith(prefix):
        raise DelegationQueueError("DELEGATION_ADDRESS_SCHEME_INVALID")
    rest = address[len(prefix) :]
    to_agent, sep, delegation_id = rest.partition("/")
    if not sep or to_agent not in _ROUTABLE_AGENTS or not delegation_id:
        raise DelegationQueueError("DELEGATION_ADDRESS_MALFORMED")
    return to_agent, delegation_id


class DelegationQueue:
    """A durable, addressable queue for recon-hypothesis handoffs, backed by SQLite.

    It is intentionally small: enqueue (persist + address), get/resolve (addressable read), and
    ``pending_for`` (what a downstream agent would find waiting). It stores only the strict
    :class:`EnqueuedDelegation` payload; there is no field through which a payload, origin, verdict
    or severity could be persisted.
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
                CREATE TABLE IF NOT EXISTS agent_delegations (
                    delegation_id TEXT PRIMARY KEY,
                    to_agent TEXT NOT NULL,
                    status TEXT NOT NULL,
                    address TEXT NOT NULL UNIQUE,
                    enqueued_at TEXT NOT NULL,
                    source_evidence_sha256 TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_agent_delegations_agent_status
                    ON agent_delegations(to_agent, status);
                """
            )

    def enqueue(self, delegation: EnqueuedDelegation) -> str:
        """Persist a delegation and return its durable address. Fail closed on a duplicate id."""

        with self._connect() as connection:
            try:
                connection.execute(
                    """INSERT INTO agent_delegations(
                        delegation_id, to_agent, status, address, enqueued_at,
                        source_evidence_sha256, payload
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        delegation.delegation_id,
                        delegation.to_agent,
                        delegation.status,
                        delegation.address,
                        delegation.enqueued_at.isoformat(),
                        delegation.source_evidence_sha256,
                        delegation.model_dump_json(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise DelegationQueueError("DELEGATION_ID_ALREADY_ENQUEUED") from exc
        return delegation.address

    def get(self, delegation_id: str) -> EnqueuedDelegation | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM agent_delegations WHERE delegation_id = ?",
                (delegation_id,),
            ).fetchone()
        return EnqueuedDelegation.model_validate_json(row["payload"]) if row else None

    def resolve(self, address: str) -> EnqueuedDelegation | None:
        """Read a delegation back by its durable address (what the consumer holds)."""

        to_agent, delegation_id = parse_delegation_address(address)
        delegation = self.get(delegation_id)
        if delegation is not None and delegation.to_agent != to_agent:
            # The address' routing segment must agree with the stored record.
            raise DelegationQueueError("DELEGATION_ADDRESS_ROUTING_MISMATCH")
        return delegation

    def pending_for(self, to_agent: str) -> list[EnqueuedDelegation]:
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT payload FROM agent_delegations
                WHERE to_agent = ? AND status = 'QUEUED' ORDER BY enqueued_at, delegation_id""",
                (to_agent,),
            ).fetchall()
        return [EnqueuedDelegation.model_validate_json(row["payload"]) for row in rows]

    def count(self) -> int:
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS n FROM agent_delegations").fetchone()
        return int(row["n"])


def evidence_sha256_of(observations: list[dict[str, object]]) -> str:
    """Deterministic digest of a normalized observation set, for delegation provenance linking."""

    import hashlib

    payload = json.dumps(observations, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()
