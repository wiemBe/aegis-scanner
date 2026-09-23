"""Controlled tool broker over the existing synthetic range and HTTP kernel semantics."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import httpx

from aegis.multi_agent.budget import AtomicBudget
from aegis.multi_agent.contracts import (
    AgentActionRequest,
    AgentActionResult,
    AgentObservation,
    AgentRole,
    AgentTask,
    BudgetUsage,
    ObservationType,
)
from aegis.multi_agent.registry import authorize
from aegis_range.inventory import RANGE_TARGETS

_CREDENTIALS = {
    "cred-bank-alex": "range-user-alex",
    "cred-bank-blair": "range-user-blair",
}
_RESOURCES = {
    "resource-account-owner": "ACC-100",
    "resource-account-alternate": "ACC-200",
}
_OPERATIONS = {
    "getAccount": "/api/accounts/{resource}",
    "listAccountTransactions": "/api/accounts/{resource}/transactions",
}


class BrokerRejection(ValueError):
    pass


class ControlledToolBroker:
    def __init__(
        self,
        budget: AtomicBudget,
        transports: dict[str, httpx.AsyncBaseTransport] | None = None,
    ) -> None:
        self._budget = budget
        self._transports = transports or {}
        self._used_nonces: set[str] = set()

    @staticmethod
    def _bind(request: AgentActionRequest, task: AgentTask) -> None:
        if (
            request.run_id != task.run_id
            or request.task_id != task.task_id
            or request.agent_id != task.agent_id
            or request.role is not task.role
        ):
            raise BrokerRejection("ACTION_IDENTITY_BINDING_MISMATCH")

    def _target(self, target_ref: str) -> tuple[str, str]:
        matches = [
            (item.application_id, item.origin)
            for item in RANGE_TARGETS.values()
            if item.target_ref == target_ref
        ]
        if len(matches) != 1:
            raise BrokerRejection("TARGET_REF_NOT_IN_INVENTORY")
        return matches[0]

    async def _get(
        self, application_id: str, origin: str, path: str, alias: str | None
    ) -> httpx.Response:
        headers = {"User-Agent": "Aegis-Multi-Agent-Runtime/1.7"}
        if alias is not None:
            secret = _CREDENTIALS.get(alias)
            if secret is None:
                raise BrokerRejection("CREDENTIAL_ALIAS_UNKNOWN")
            headers["Authorization"] = f"Bearer {secret}"
        async with httpx.AsyncClient(
            base_url=origin,
            timeout=3,
            follow_redirects=False,
            trust_env=False,
            transport=self._transports.get(application_id),
        ) as client:
            return await client.get(path, headers=headers)

    async def discover_surface(
        self, *, run_id: str, task: AgentTask, target_ref: str, observation_id: str
    ) -> AgentObservation:
        if task.role not in {AgentRole.SURFACE_AGENT, AgentRole.AUTHORIZATION_AGENT}:
            raise BrokerRejection("SURFACE_ROLE_REQUIRED")
        authorize(task.role, "aegis.surface.openapi")
        application_id, origin = self._target(target_ref)
        await self._budget.consume(task.agent_id, BudgetUsage(target_requests=1))
        response = await self._get(application_id, origin, "/openapi.json", None)
        if response.status_code != 200 or len(response.content) > 262_144:
            raise BrokerRejection("SURFACE_OBSERVATION_FAILED")
        document: object = response.json()
        if not isinstance(document, dict):
            raise BrokerRejection("SURFACE_OUTPUT_MALFORMED")
        operation_ids: list[str] = []
        paths = document.get("paths", {})
        if isinstance(paths, dict):
            for item in paths.values():
                if isinstance(item, dict):
                    for operation in item.values():
                        if isinstance(operation, dict) and isinstance(
                            operation.get("operationId"), str
                        ):
                            operation_ids.append(operation["operationId"])
        bounded = json.dumps(sorted(operation_ids), separators=(",", ":")).encode()
        await self._budget.consume(task.agent_id, BudgetUsage(evidence_bytes=len(bounded)))
        return AgentObservation(
            observation_id=observation_id,
            run_id=run_id,
            task_id=task.task_id,
            agent_id=task.agent_id,
            observation_type=ObservationType.SURFACE,
            summary=f"Observed {len(operation_ids)} documented operation identifiers.",
            operation_ids=sorted(operation_ids)[:32],
            resource_refs=["resource-account-owner", "resource-account-alternate"],
            evidence_sha256=hashlib.sha256(bounded).hexdigest(),
            evidence_bytes=len(bounded),
        )

    async def execute(
        self,
        request: AgentActionRequest,
        task: AgentTask,
        observation_id: str,
    ) -> tuple[AgentActionResult, AgentObservation]:
        self._bind(request, task)
        authorize(request.role, request.capability_id)
        now = datetime.now(UTC)
        if request.expires_at <= now:
            raise BrokerRejection("ACTION_EXPIRED")
        if request.issued_at > now:
            raise BrokerRejection("ACTION_NOT_YET_VALID")
        if request.nonce in self._used_nonces:
            raise BrokerRejection("ACTION_REPLAYED")
        self._used_nonces.add(request.nonce)
        if request.operation_id not in task.context.allowed_operation_ids:
            raise BrokerRejection("OPERATION_NOT_AUTHORIZED")
        if any(
            alias not in task.context.credential_aliases for alias in request.credential_aliases
        ):
            raise BrokerRejection("CREDENTIAL_ALIAS_NOT_AUTHORIZED")
        if any(ref not in task.context.resource_refs for ref in request.resource_refs):
            raise BrokerRejection("RESOURCE_NOT_AUTHORIZED")
        if len(request.credential_aliases) != 2 or len(request.resource_refs) != 2:
            raise BrokerRejection("COMPARISON_SHAPE_INVALID")
        application_id, origin = self._target(task.context.target_ref)
        owner_alias = request.credential_aliases[0]
        owner_ref, alternate_ref = request.resource_refs
        paths = (
            _OPERATIONS["getAccount"].format(resource=_RESOURCES[owner_ref]),
            _OPERATIONS["getAccount"].format(resource=_RESOURCES[alternate_ref]),
            _OPERATIONS["listAccountTransactions"].format(resource=_RESOURCES[alternate_ref]),
        )
        await self._budget.consume(task.agent_id, BudgetUsage(target_requests=3))
        responses = [await self._get(application_id, origin, path, owner_alias) for path in paths]
        statuses = {
            "owner_control": responses[0].status_code,
            "cross_owner": responses[1].status_code,
            "cross_owner_transactions": responses[2].status_code,
        }
        bounded = json.dumps(statuses, sort_keys=True, separators=(",", ":")).encode()
        await self._budget.consume(task.agent_id, BudgetUsage(evidence_bytes=len(bounded)))
        observation = AgentObservation(
            observation_id=observation_id,
            run_id=request.run_id,
            task_id=request.task_id,
            agent_id=request.agent_id,
            observation_type=ObservationType.AUTHORIZATION_COMPARISON,
            summary="Controller executed owner-control and cross-owner comparison requests.",
            operation_ids=["getAccount", "listAccountTransactions"],
            resource_refs=[owner_ref, alternate_ref],
            statuses=statuses,
            evidence_sha256=hashlib.sha256(bounded).hexdigest(),
            evidence_bytes=len(bounded),
        )
        return (
            AgentActionResult(
                action_id=request.action_id,
                run_id=request.run_id,
                task_id=request.task_id,
                agent_id=request.agent_id,
                capability_id=request.capability_id,
                accepted=True,
                observation_ref=observation.observation_id,
                target_requests=3,
            ),
            observation,
        )
