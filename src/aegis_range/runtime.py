"""Shared deterministic state and management-plane contracts for range applications."""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum
from threading import RLock

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict


class Mode(StrEnum):
    VULNERABLE = "vulnerable"
    PATCHED = "patched"


class ModeSelection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Mode


class ScenarioRuntime:
    """Process-local deterministic scenario modes, mutable only via the control router."""

    def __init__(self, service: str, scenario_ids: tuple[str, ...]) -> None:
        self.service = service
        self._scenario_ids = scenario_ids
        self._lock = RLock()
        self._modes: dict[str, Mode] = {}
        self._generation = 0
        self._reset_hooks: list[Callable[[int], None]] = []
        self.reset()

    @property
    def scenario_ids(self) -> tuple[str, ...]:
        return self._scenario_ids

    @property
    def generation(self) -> int:
        with self._lock:
            return self._generation

    def add_reset_hook(self, hook: Callable[[int], None]) -> None:
        with self._lock:
            self._reset_hooks.append(hook)
            hook(self._generation)

    def mode(self, scenario_id: str) -> Mode:
        with self._lock:
            try:
                return self._modes[scenario_id]
            except KeyError as exc:
                raise ValueError("UNKNOWN_SCENARIO") from exc

    def select(self, scenario_id: str, mode: Mode) -> dict[str, object]:
        with self._lock:
            if scenario_id not in self._modes:
                raise ValueError("UNKNOWN_SCENARIO")
            self._modes[scenario_id] = mode
            self._generation += 1
            return self.snapshot()

    def reset(self) -> dict[str, object]:
        with self._lock:
            self._modes = {scenario_id: Mode.PATCHED for scenario_id in self._scenario_ids}
            self._generation += 1
            for hook in self._reset_hooks:
                hook(self._generation)
            return self.snapshot()

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {
                "service": self.service,
                "generation": self._generation,
                "scenarios": {key: value.value for key, value in sorted(self._modes.items())},
            }


def management_router(runtime: ScenarioRuntime) -> APIRouter:
    """Build routes that are reachable only on controller-owned management networks."""

    router = APIRouter(prefix="/__control", include_in_schema=False)

    @router.get("/health")
    def control_health() -> dict[str, object]:
        return {"status": "ok", **runtime.snapshot()}

    @router.post("/reset")
    def reset() -> dict[str, object]:
        return {"status": "reset", **runtime.reset()}

    @router.put("/scenarios/{scenario_id}")
    def select(scenario_id: str, selection: ModeSelection) -> dict[str, object]:
        try:
            state = runtime.select(scenario_id, selection.mode)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail="Scenario not found") from exc
        return {"status": "updated", **state}

    return router
