"""Planner Contract V2: state-driven decision typing and congruent generation schemas.

This module is the single source of truth for:

- which decision types are legal in a given orchestrator state (``permitted_decision_types``);
- the strict Pydantic validator for the permitted subset (``state_adapter``);
- the JSON Schema handed to the model at generation time (``build_generation_schema``), derived from
  the same Pydantic subset union and then *narrowed* with dynamic identifier enums so that the set
  of documents the model can generate is a subset of the set the validator accepts.

Constraining the legal response types for a state the orchestrator already knows, and constraining
identifier syntax/scope to the already-approved projected surface, is not attack hard-coding: it
never selects a decision, a principal, an object, an operation or an attack direction on the model's
behalf. Dynamic enums are subsets of the static strict types, so generation stays within validation
and no new structural rejection class is introduced.
"""

from typing import Annotated, Any, Union

from pydantic import Field, TypeAdapter

from aegis.models import (
    ContinueDecision,
    ExecuteDecision,
    HypothesisDecision,
    PlannerDecision,
    ReviewDecision,
    StopDecision,
)

# Decision-type vocabulary, keyed by the `decision_type` discriminator.
DECISION_MODELS: dict[str, type] = {
    "hypothesis": HypothesisDecision,
    "execute": ExecuteDecision,
    "continue": ContinueDecision,
    "stop": StopDecision,
    "review": ReviewDecision,
}
# Decision types that carry a hypothesis and therefore drive a bounded network action.
NETWORK_DECISION_TYPES = frozenset({"hypothesis", "execute"})
# Decision types that terminate the loop.
TERMINAL_DECISION_TYPES = frozenset({"stop", "review"})

# The read-only method and category vocabularies mirror the strict Literals on the Pydantic models.
READ_ONLY_METHODS = ("GET", "HEAD", "OPTIONS")
HYPOTHESIS_CATEGORIES = ("AUTHN", "BOLA", "EXPOSURE")

_CONFIRMED_STATUSES = frozenset({"CONFIRMED", "PASS"})


def permitted_decision_types(*, retest: bool, verification_status: str | None) -> tuple[str, ...]:
    """Legal response types for the current orchestrator state.

    Mapping (canonical terms adapted to this single-network-action-per-step loop):

    - discovery, not yet verified          -> hypothesis | stop | review   (generative step)
    - after deterministic verification      -> continue   | stop | review   (post-verification step)
    - linked patched retest, not yet passed -> execute    | stop | review   (confirmatory step)
    - linked patched retest, after PASS      -> continue   | stop | review

    ``stop`` and ``review`` are always legal so the model can always fail safe. The mapping depends
    only on state the orchestrator already owns (retest flag, deterministic verifier status); it
    never depends on model output and never encodes the expected attack sequence.
    """
    confirmed = verification_status in _CONFIRMED_STATUSES
    if confirmed:
        return ("continue", "stop", "review")
    if retest:
        return ("execute", "stop", "review")
    return ("hypothesis", "stop", "review")


def state_adapter(permitted: tuple[str, ...]) -> TypeAdapter[Any]:
    """Strict validator for exactly the permitted decision subset (still discriminated)."""
    models = [DECISION_MODELS[name] for name in permitted]
    if not models:
        raise ValueError("At least one permitted decision type is required")
    if len(models) == 1:
        return TypeAdapter(models[0])
    union = Union[tuple(models)]  # type: ignore[valid-type]  # noqa: UP007 - dynamic Union
    return TypeAdapter(Annotated[union, Field(discriminator="decision_type")])


def projected_request_enums(surface: dict[str, Any]) -> dict[str, list[str]]:
    """Derive dynamic identifier enums from the already-approved projected surface.

    - concrete object paths from projected OpenAPI path templates x projected synthetic objects
    - principal profiles from the projected approved credential list
    - read-only methods and hypothesis categories from the fixed strict vocabularies
    """
    templates = [t for t in surface.get("paths", {}) if isinstance(t, str)]
    profiles = [p for p in surface.get("available_credentials", []) if isinstance(p, str)]
    objects = sorted(
        {
            obj
            for ids in surface.get("known_test_objects", {}).values()
            if isinstance(ids, list)
            for obj in ids
            if isinstance(obj, str)
        }
    )
    paths = sorted(
        {template.replace("{account_id}", obj) for template in templates for obj in objects}
    )
    return {
        "paths": paths,
        "profiles": sorted(profiles),
        "methods": list(READ_ONLY_METHODS),
        "categories": list(HYPOTHESIS_CATEGORIES),
    }


def build_generation_schema(
    permitted: tuple[str, ...], surface: dict[str, Any]
) -> dict[str, Any]:
    """JSON Schema for constrained decoding: the permitted subset union, narrowed by dynamic enums.

    The base schema comes from the same strict Pydantic subset union that validates the reply, so
    the two are congruent. We then replace identifier fields with dynamic enums scoped to the
    projected surface. Every enum value is a subset of the corresponding strict type, so any
    document the schema permits is also accepted by the Pydantic validator.
    """
    schema = state_adapter(permitted).json_schema()
    enums = projected_request_enums(surface)
    defs = schema.get("$defs", {})
    request_def = defs.get("PlannedRequest")
    if isinstance(request_def, dict) and isinstance(request_def.get("properties"), dict):
        props = request_def["properties"]
        if enums["paths"]:
            props["path"] = {"type": "string", "enum": enums["paths"]}
        if enums["profiles"]:
            props["credential_profile"] = {"type": "string", "enum": enums["profiles"]}
        props["method"] = {"type": "string", "enum": enums["methods"]}
    hypothesis_def = defs.get("Hypothesis")
    if isinstance(hypothesis_def, dict) and isinstance(hypothesis_def.get("properties"), dict):
        hypothesis_def["properties"]["category"] = {"type": "string", "enum": enums["categories"]}
    return schema


def sanitized_error_paths(errors: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Reduce Pydantic validation errors to safe location + type + generic message.

    Drops the offending input value and any URL: only the structural location path, the error type
    and Pydantic's own generic message (e.g. "Field required", "Extra inputs are not permitted")
    survive. No model-authored prose, target data or secret value is retained.
    """
    safe: list[dict[str, str]] = []
    for error in errors:
        loc = ".".join(str(part) for part in error.get("loc", ()))
        safe.append(
            {
                "loc": loc,
                "type": str(error.get("type", "")),
                "msg": str(error.get("msg", "")),
            }
        )
    return safe


# Re-export for callers that validate against the full union.
FULL_DECISION_ADAPTER: TypeAdapter[Any] = TypeAdapter(PlannerDecision)
