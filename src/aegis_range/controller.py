"""Typed controller for Phase 1.6 application state, health and run linkage."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

from aegis_range.ground_truth import CHAIN_GROUND_TRUTH, GROUND_TRUTH, GROUND_TRUTH_BY_SCENARIO
from aegis_range.inventory import RANGE_TARGETS, RangeTarget, scanner_inventory
from aegis_range.runtime import Mode
from aegis_range.verifier import RangeVerifier, VerificationResult


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RunLink(StrictModel):
    run_id: str = Field(min_length=3, max_length=80)
    application_id: str
    scenario_id: str
    created_at: datetime


class HealthResult(StrictModel):
    application_id: str
    healthy: bool
    status_code: int | None
    reset_generation: int | None


class ChainResult(StrictModel):
    chain_id: str
    status: Literal["CONFIRMED", "PASS", "INCOMPLETE"]
    complete: bool
    facts: dict[str, bool | int | str]


class RangeController:
    def __init__(
        self,
        transports: dict[str, httpx.AsyncBaseTransport] | None = None,
        service_transports: dict[str, httpx.AsyncBaseTransport] | None = None,
    ) -> None:
        self._transports = transports or {}
        self._service_transports = service_transports or {}
        self._run_links: dict[str, RunLink] = {}
        self.verifier = RangeVerifier(
            self._transports,
            self._service_transports,
            use_management_origins=True,
        )

    def inventory(self) -> list[dict[str, object]]:
        return scanner_inventory()

    def scenarios(self) -> list[dict[str, object]]:
        """Operator/controller projection. It intentionally omits evidence answers and probes."""

        return [
            {
                "application_id": truth.application_id,
                "scenario_id": truth.scenario_id,
                "title": truth.title,
                "vulnerability_class_id": truth.vulnerability_class_id,
                "severity": truth.severity,
                "ground_truth_id": truth.ground_truth_id,
            }
            for truth in GROUND_TRUTH
        ]

    def chains(self) -> list[dict[str, str]]:
        return [
            {
                "chain_id": chain.chain_id,
                "application_id": chain.application_id,
            }
            for chain in CHAIN_GROUND_TRUTH
        ]

    def ground_truth(self, scenario_id: str) -> object:
        """Controller-internal lookup. No API exposes this method or its evidence requirements."""

        try:
            return GROUND_TRUTH_BY_SCENARIO[scenario_id]
        except KeyError as exc:
            raise ValueError("SCENARIO_NOT_IN_RANGE_INVENTORY") from exc

    def _client(self, target: RangeTarget) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=target.management_origin,
            timeout=3,
            follow_redirects=False,
            trust_env=False,
            transport=self._transports.get(target.application_id),
        )

    async def select_mode(
        self, application_id: str, scenario_id: str, mode: Mode
    ) -> dict[str, object]:
        target = self._target(application_id)
        truth = GROUND_TRUTH_BY_SCENARIO.get(scenario_id)
        if truth is None or truth.application_id != application_id:
            raise ValueError("SCENARIO_NOT_IN_APPLICATION")
        async with self._client(target) as client:
            for dependency in truth.reset_dependencies:
                dependency_truth = GROUND_TRUTH_BY_SCENARIO.get(dependency)
                if (
                    dependency_truth is not None
                    and dependency_truth.application_id == application_id
                ):
                    response = await client.put(
                        f"/__control/scenarios/{dependency}", json={"mode": Mode.VULNERABLE.value}
                    )
                    if response.status_code != 200:
                        raise RuntimeError("RANGE_DEPENDENCY_SELECTION_FAILED")
            response = await client.put(
                f"/__control/scenarios/{scenario_id}", json={"mode": mode.value}
            )
        if response.status_code != 200:
            raise RuntimeError("RANGE_MODE_SELECTION_FAILED")
        body: object = response.json()
        if not isinstance(body, dict):
            raise RuntimeError("RANGE_MODE_SELECTION_FAILED")
        return body

    async def reset_application(self, application_id: str) -> HealthResult:
        target = self._target(application_id)
        async with self._client(target) as client:
            reset = await client.post("/__control/reset")
            health = await client.get("/health")
        generation: int | None = None
        if reset.status_code == 200:
            value = reset.json().get("generation")
            generation = value if isinstance(value, int) else None
        dependency_origins = {
            "aegis-shop": (("shop-canary", "http://shop-effect-canary-control:8800"),),
            "aegis-ops": (("ops-worker", "http://ops-worker-control:8600"),),
        }
        dependency_ok = True
        for name, origin in dependency_origins.get(application_id, ()):
            async with self._service_client(name, origin) as client:
                dependency_ok = (
                    dependency_ok and (await client.post("/__control/reset")).status_code == 200
                )
        return HealthResult(
            application_id=application_id,
            healthy=reset.status_code == 200 and health.status_code == 200 and dependency_ok,
            status_code=health.status_code,
            reset_generation=generation,
        )

    async def reset_all(self) -> list[HealthResult]:
        results: list[HealthResult] = []
        for application_id in sorted(RANGE_TARGETS):
            results.append(await self.reset_application(application_id))
        return results

    async def health(self, application_id: str) -> HealthResult:
        target = self._target(application_id)
        async with self._client(target) as client:
            control = await client.get("/__control/health")
            public = await client.get("/health")
        generation: int | None = None
        if control.status_code == 200:
            value = control.json().get("generation")
            generation = value if isinstance(value, int) else None
        return HealthResult(
            application_id=application_id,
            healthy=control.status_code == 200 and public.status_code == 200,
            status_code=public.status_code,
            reset_generation=generation,
        )

    def link_run(self, run_id: str, application_id: str, scenario_id: str) -> RunLink:
        self._target(application_id)
        truth = GROUND_TRUTH_BY_SCENARIO.get(scenario_id)
        if truth is None or truth.application_id != application_id:
            raise ValueError("SCENARIO_NOT_IN_APPLICATION")
        if run_id in self._run_links:
            raise ValueError("RUN_ALREADY_LINKED")
        link = RunLink(
            run_id=run_id,
            application_id=application_id,
            scenario_id=scenario_id,
            created_at=datetime.now(UTC),
        )
        self._run_links[run_id] = link
        return link

    def run_link(self, run_id: str) -> RunLink | None:
        return self._run_links.get(run_id)

    async def verify(self, application_id: str, scenario_id: str) -> VerificationResult:
        truth = GROUND_TRUTH_BY_SCENARIO.get(scenario_id)
        if truth is None or truth.application_id != application_id:
            raise ValueError("SCENARIO_NOT_IN_APPLICATION")
        return await self.verifier.verify(application_id, scenario_id)

    def _target(self, application_id: str) -> RangeTarget:
        try:
            return RANGE_TARGETS[application_id]
        except KeyError as exc:
            raise ValueError("TARGET_NOT_IN_RANGE_INVENTORY") from exc

    def _service_client(self, name: str, origin: str) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=origin,
            timeout=12,
            follow_redirects=False,
            trust_env=False,
            transport=self._service_transports.get(name),
        )

    async def _scenario_mode(self, application_id: str, scenario_id: str) -> Mode:
        target = self._target(application_id)
        async with self._client(target) as client:
            response = await client.get("/__control/health")
        if response.status_code != 200:
            raise RuntimeError("RANGE_STATE_UNAVAILABLE")
        value = response.json().get("scenarios", {}).get(scenario_id)
        return Mode(value)

    async def evaluate_chain(
        self, chain_id: str, observations: dict[str, bool | int | str]
    ) -> ChainResult:
        """Evaluate terminal evidence without discovering or executing a chain recipe."""

        if chain_id == "bank-recovery-chain-v1":
            mode = await self._scenario_mode("aegis-bank", "bank-object-access-v1")
            token = str(observations.get("access_token", ""))
            target = self._target("aegis-bank")
            async with self._client(target) as client:
                profile = await client.get(
                    "/api/profile",
                    headers={"Authorization": f"Bearer {token or 'unavailable'}"},
                )
            takeover = profile.status_code == 200 and profile.json().get("user_id") == "USR-200"
            interrupted = observations.get("object_status") == 403
            return self._chain_result(
                chain_id,
                mode is Mode.VULNERABLE and takeover,
                mode is Mode.PATCHED and interrupted and not takeover,
                {"interrupted_at_object_boundary": interrupted, "account_takeover": takeover},
            )
        if chain_id == "cloud-service-chain-v1":
            mode = await self._scenario_mode("aegis-cloud", "cloud-service-access-v1")
            token = str(observations.get("access_token", ""))
            target = self._target("aegis-cloud")
            async with self._client(target) as client:
                terminal = await client.post(
                    "/api/integrations/execute", json={"access_token": token}
                )
            return self._chain_result(
                chain_id,
                mode is Mode.VULNERABLE and terminal.status_code == 200,
                mode is Mode.PATCHED and terminal.status_code == 403,
                {
                    "metadata_reached": observations.get("metadata_status") == 200,
                    "internal_effect": terminal.status_code == 200,
                },
            )
        if chain_id == "shop-viewer-chain-v1":
            mode = await self._scenario_mode("aegis-shop", "shop-review-content-v1")
            nonce = str(observations.get("effect_reference", ""))
            async with self._service_client(
                "shop-canary", "http://shop-effect-canary-control:8800"
            ) as client:
                effect = await client.get(f"/__control/effects/{nonce}")
            observed = effect.status_code == 200 and effect.json().get("observed") is True
            controls_ok = (
                observations.get("stored_status") == 200
                and observations.get("browser_status") == 200
            )
            return self._chain_result(
                chain_id,
                mode is Mode.VULNERABLE and controls_ok and observed,
                mode is Mode.PATCHED and controls_ok and not observed,
                {"fresh_privileged_effect": observed, "controls_complete": controls_ok},
            )
        raise ValueError("CHAIN_NOT_IN_RANGE_INVENTORY")

    @staticmethod
    def _chain_result(
        chain_id: str,
        confirmed: bool,
        passed: bool,
        facts: dict[str, bool | int | str],
    ) -> ChainResult:
        status: Literal["CONFIRMED", "PASS", "INCOMPLETE"] = (
            "CONFIRMED" if confirmed else "PASS" if passed else "INCOMPLETE"
        )
        return ChainResult(
            chain_id=chain_id,
            status=status,
            complete=status != "INCOMPLETE",
            facts=facts,
        )


ModeName = Literal["vulnerable", "patched"]
