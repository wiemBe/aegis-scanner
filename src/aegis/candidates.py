"""Candidate-First Planning Protocol V3 + Phase 0.8 deterministic controller (docs/phase-0.8).

This module owns everything the model is NOT allowed to decide:

- the projected context handed to the model (capabilities, operations, principals, objects);
- the strict JSON Schema for candidate enumeration, narrowed by dynamic enums so that generation
  stays a subset of validation (candidate_generation_schema / proof in the offline tests);
- the deterministic precondition for every blocking reason code, and the deterministic PREFLIGHT
  that evaluates controller-known facts BEFORE any model call (Part D);
- per-candidate validation and the controller-assigned candidate IDs;
- the DETERMINISTIC execution queue: a model-independent stable ordering of validated candidates and
  budget-bounded admission (Part A). Phase 0.8 removes the model-based selection call entirely;
- the deterministic compilation of an admitted candidate (or a confirmed finding, on retest) into
  the existing typed, read-only execution request (Part C). The compiler resolves references into
  controller-owned values but never invents or replaces a missing candidate reference.

None of this selects a decision, capability, operation, principal, object or attack direction on the
model's behalf. Constraining identifiers to the already-approved projected surface, and rejecting
anything outside it, is scope enforcement, not attack hard-coding.
"""

from collections.abc import Sequence
from typing import Any

from pydantic import TypeAdapter

from aegis.models import (
    EXECUTION_POLICY_VERSION,
    BlockerEvaluation,
    BlockingClaim,
    BlockingCondition,
    BlockingFact,
    BlockingReason,
    CandidateGenerationResult,
    CandidateRejection,
    CandidateSelection,
    Hypothesis,
    ObjectAuthorizationCandidate,
    PlannedRequest,
    QueuedCandidate,
    RejectAllSelection,
    RetestObjective,
    ReviewSelection,
    SelectionCandidateView,
    TestCandidate,
    ValidatedCandidate,
)
from aegis.registry import (
    CAPABILITY_REGISTRY,
    Capability,
    get_capability,
    registered_ids,
)
from aegis.registry import projection as capability_projection
from aegis.scenarios import ScenarioProjection, authenticated_profiles
from aegis.surface import OBJECTS, PROFILE_ACTORS

# BOLA needs owner + cross-owner authenticated principals and at least two comparable objects.
_MIN_AUTHENTICATED_PRINCIPALS = 2
_MIN_OBJECTS = 2

_GENERATION_ADAPTER: TypeAdapter[Any] = TypeAdapter(CandidateGenerationResult)


# --- context projection --------------------------------------------------------------------------


def build_context(
    *,
    proj: ScenarioProjection,
    stage: str,
    observations: list[dict[str, Any]],
    verification: dict[str, Any],
    retest: bool,
    prior_finding: str | None,
    retest_objectives: list[dict[str, Any]],
    remaining: dict[str, int],
    max_candidates: int,
) -> dict[str, Any]:
    """Assemble the strict projected context for the current stage. No secrets, no raw prose."""
    operations = [op.projection() for op in proj.operations]
    evidence_refs = [o["name"] for o in observations if isinstance(o.get("name"), str)]
    return {
        "surface": proj.surface(),
        "capabilities": capability_projection(),
        "operations": operations,
        "available_credentials": list(proj.available_credentials),
        "known_objects": list(proj.known_objects),
        "evidence_refs": evidence_refs,
        "scope_ambiguity": proj.scope_ambiguity,
        "stage": stage,
        "max_candidates": max_candidates,
        "observations": observations,
        "verification": verification,
        "retest": retest,
        "prior_finding": prior_finding,
        "retest_objectives": retest_objectives,
        "remaining": remaining,
    }


def _projected_refs(context: dict[str, Any]) -> set[str]:
    refs: set[str] = set()
    refs.update(op["operation_id"] for op in context.get("operations", []))
    refs.update(str(o) for o in context.get("known_objects", []))
    refs.update(str(c) for c in context.get("available_credentials", []))
    refs.update(c["id"] for c in context.get("capabilities", []))
    refs.update(str(r) for r in context.get("evidence_refs", []))
    return refs


def context_capability_ids(context: dict[str, Any]) -> set[str]:
    return {c["id"] for c in context.get("capabilities", [])}


def _authenticated(context: dict[str, Any]) -> list[str]:
    return authenticated_profiles(list(context.get("available_credentials", [])))


# --- dynamic generation schema (Part B) ----------------------------------------------------------


def candidate_generation_schema(context: dict[str, Any]) -> dict[str, Any]:
    """Strict schema for CandidateGenerationResult, narrowed by the projected identifier enums so
    that any candidate the model can generate is one deterministic validation could accept.

    The object-authorization candidate's object_ref is enumerated to the approved projected objects
    only: it can never be null, blank or an unrestricted string. Owner and alternate principals are
    enumerated to the approved AUTHENTICATED credential profiles only, and remain constrained to be
    non-empty by the underlying Pydantic model."""
    schema = _GENERATION_ADAPTER.json_schema()
    defs = schema.get("$defs", {})
    operation_ids = sorted({op["operation_id"] for op in context.get("operations", [])})
    objects = sorted({str(o) for o in context.get("known_objects", [])})
    authenticated = sorted(_authenticated(context))
    capabilities = sorted(context_capability_ids(context) & registered_ids())
    refs = sorted(_projected_refs(context))

    cand = defs.get("ObjectAuthorizationCandidate")
    if isinstance(cand, dict) and isinstance(cand.get("properties"), dict):
        props = cand["properties"]
        # capability is already a Literal enum; intersect with the registered/projected set.
        props["capability"] = {"type": "string", "enum": capabilities}
        props["operation_id"] = {"type": "string", "enum": operation_ids}
        props["owner_principal_ref"] = {"type": "string", "enum": authenticated}
        props["alternate_principal_ref"] = {"type": "string", "enum": authenticated}
        # object_ref: always a non-empty string constrained to the approved projected objects. When
        # no object is projected the enum is empty, so no object-authorization candidate is even
        # expressible and the model must return a blocking condition instead.
        props["object_ref"] = {"type": "string", "enum": objects}
        props["projected_context_refs"] = {
            "type": "array",
            "items": {"type": "string", "enum": refs},
            "minItems": 1,
            "maxItems": 12,
        }
    result_props = schema.get("properties", {})
    if isinstance(result_props.get("candidates"), dict):
        result_props["candidates"]["maxItems"] = int(context.get("max_candidates", 3))
    blocker = defs.get("BlockingCondition")
    if isinstance(blocker, dict) and isinstance(blocker.get("properties"), dict):
        props = blocker["properties"]
        props["context_refs"] = {
            "type": "array",
            "items": {"type": "string", "enum": refs},
            "maxItems": 12,
        }
        props["operation_id"] = {
            "anyOf": [{"type": "string", "enum": operation_ids}, {"type": "null"}]
        }
        props["capability"] = {
            "anyOf": [{"type": "string", "enum": capabilities}, {"type": "null"}]
        }
    return schema


# --- deterministic blocker preconditions ---------------------------------------------------------


def _capability_can_evaluate(cap: Capability, op: dict[str, Any]) -> bool:
    return (
        cap.read_only
        and bool(op.get("read_only"))
        and op.get("method") in cap.methods
        and op.get("object_parameter") is not None
    )


def any_supported_operation(context: dict[str, Any]) -> bool:
    """True if some registered capability can evaluate some projected operation."""
    ops = context.get("operations", [])
    for cap_id in context_capability_ids(context):
        cap = get_capability(cap_id)
        if cap is None:
            continue
        if any(_capability_can_evaluate(cap, op) for op in ops):
            return True
    return False


def constructible_read_only_test(context: dict[str, Any]) -> bool:
    """True iff a bounded read-only test can genuinely be posed from the projection: a supported
    operation, at least two authenticated principals, and at least two comparable objects."""
    if context.get("scope_ambiguity"):
        return False
    if not any_supported_operation(context):
        return False
    if len(_authenticated(context)) < _MIN_AUTHENTICATED_PRINCIPALS:
        return False
    return len(context.get("known_objects", [])) >= _MIN_OBJECTS


def _remaining_ok(context: dict[str, Any]) -> bool:
    remaining = context.get("remaining", {})
    values = (
        remaining.get("requests", 0),
        remaining.get("model_calls", 0),
        remaining.get("token_reservations", 0),
        remaining.get("time_ms", 0),
    )
    return all(isinstance(value, int) and value >= 1 for value in values)


def _fact_values(context: dict[str, Any]) -> dict[BlockingFact, bool | int | str]:
    remaining = context.get("remaining", {})
    supported = sum(
        1
        for op in context.get("operations", [])
        if any(
            (cap := get_capability(cap_id)) is not None
            and _capability_can_evaluate(cap, op)
            for cap_id in context_capability_ids(context)
        )
    )
    safe = sum(1 for op in context.get("operations", []) if op.get("read_only"))
    return {
        BlockingFact.AUTHENTICATED_PRINCIPAL_COUNT: len(_authenticated(context)),
        BlockingFact.KNOWN_OBJECT_COUNT: len(context.get("known_objects", [])),
        BlockingFact.SUPPORTED_OPERATION_COUNT: supported,
        BlockingFact.SAFE_OPERATION_COUNT: safe,
        BlockingFact.SCOPE_AMBIGUITY: bool(context.get("scope_ambiguity")),
        BlockingFact.CONSTRUCTIBLE_TEST: constructible_read_only_test(context),
        BlockingFact.REMAINING_REQUESTS: int(remaining.get("requests", 0)),
        BlockingFact.REMAINING_MODEL_CALLS: int(remaining.get("model_calls", 0)),
        BlockingFact.REMAINING_TOKEN_RESERVATIONS: int(remaining.get("token_reservations", 0)),
        BlockingFact.REMAINING_TIME_MS: int(remaining.get("time_ms", 0)),
    }


_REQUIRED_FACTS: dict[BlockingReason, frozenset[BlockingFact]] = {
    BlockingReason.AUTHENTICATION_UNAVAILABLE: frozenset(
        {BlockingFact.AUTHENTICATED_PRINCIPAL_COUNT}
    ),
    BlockingReason.BUDGET_UNAVAILABLE: frozenset(
        {
            BlockingFact.REMAINING_REQUESTS,
            BlockingFact.REMAINING_MODEL_CALLS,
            BlockingFact.REMAINING_TOKEN_RESERVATIONS,
            BlockingFact.REMAINING_TIME_MS,
        }
    ),
    BlockingReason.NO_SUPPORTED_TEST_CAPABILITY: frozenset(
        {BlockingFact.SUPPORTED_OPERATION_COUNT}
    ),
    BlockingReason.SCOPE_AMBIGUITY: frozenset({BlockingFact.SCOPE_AMBIGUITY}),
    BlockingReason.SAFETY_CONFLICT: frozenset({BlockingFact.SAFE_OPERATION_COUNT}),
    BlockingReason.INSUFFICIENT_CONTEXT: frozenset({BlockingFact.KNOWN_OBJECT_COUNT}),
    BlockingReason.NO_TESTABLE_HYPOTHESIS: frozenset({BlockingFact.CONSTRUCTIBLE_TEST}),
}


def _blocker_valid(reason: BlockingReason, context: dict[str, Any]) -> bool:
    """Deterministic precondition for one reason code, derived only from projected context and the
    verifier/budget state. A model-supplied blocker is accepted ONLY if its precondition holds."""
    if reason is BlockingReason.AUTHENTICATION_UNAVAILABLE:
        return len(_authenticated(context)) < _MIN_AUTHENTICATED_PRINCIPALS
    if reason is BlockingReason.BUDGET_UNAVAILABLE:
        return not _remaining_ok(context)
    if reason is BlockingReason.NO_SUPPORTED_TEST_CAPABILITY:
        return not any_supported_operation(context)
    if reason is BlockingReason.SCOPE_AMBIGUITY:
        return bool(context.get("scope_ambiguity"))
    if reason is BlockingReason.SAFETY_CONFLICT:
        ops = context.get("operations", [])
        return bool(ops) and all(not op.get("read_only") for op in ops)
    if reason is BlockingReason.INSUFFICIENT_CONTEXT:
        # A read-only object operation exists but there are too few objects to compare.
        return (
            any_supported_operation(context)
            and len(context.get("known_objects", [])) < _MIN_OBJECTS
        )
    if reason is BlockingReason.NO_TESTABLE_HYPOTHESIS:
        return not constructible_read_only_test(context)
    return False


def validate_blockers(
    context: dict[str, Any], blocking_conditions: list[BlockingCondition]
) -> list[BlockerEvaluation]:
    """Evaluate each model-supplied blocking condition against its deterministic precondition."""
    evaluations: list[BlockerEvaluation] = []
    facts = _fact_values(context)
    refs = _projected_refs(context)
    operation_ids = {op["operation_id"] for op in context.get("operations", [])}
    capability_ids = context_capability_ids(context)
    for condition in blocking_conditions:
        supplied = {claim.fact: claim.value for claim in condition.claims}
        duplicate_facts = len(supplied) != len(condition.claims)
        required = _REQUIRED_FACTS[condition.reason]
        claims_valid = required.issubset(supplied) and all(
            fact in facts and type(facts[fact]) is type(value) and facts[fact] == value
            for fact, value in supplied.items()
        )
        refs_valid = all(ref in refs for ref in condition.context_refs)
        affected_valid = (
            condition.operation_id is None or condition.operation_id in operation_ids
        ) and (condition.capability is None or condition.capability in capability_ids)
        missing_valid = True
        if condition.reason is BlockingReason.INSUFFICIENT_CONTEXT:
            missing_valid = (
                bool(condition.missing_context_fields)
                and set(condition.missing_context_fields) == {"known_objects"}
            )
        elif condition.missing_context_fields:
            missing_valid = False
        valid = (
            _blocker_valid(condition.reason, context)
            and claims_valid
            and refs_valid
            and affected_valid
            and missing_valid
            and not duplicate_facts
        )
        if valid:
            detail = None
        elif not _blocker_valid(condition.reason, context):
            detail = "precondition_not_satisfied"
        elif not claims_valid or duplicate_facts:
            detail = "factual_claims_invalid"
        elif not refs_valid:
            detail = "unprojected_context_reference"
        elif not affected_valid:
            detail = "unprojected_affected_identifier"
        else:
            detail = "missing_context_fields_invalid"
        evaluations.append(BlockerEvaluation(reason=condition.reason, valid=valid, detail=detail))
    return evaluations


def first_valid_blocker(evaluations: list[BlockerEvaluation]) -> BlockingReason | None:
    for evaluation in evaluations:
        if evaluation.valid:
            return evaluation.reason
    return None


# Priority order used only by the deterministic reference planner and by the deterministic PREFLIGHT
# to pick the most specific valid blocker. It is never used to accept a model-supplied blocker; that
# always goes through validate_blockers, which checks each precondition independently.
_BLOCKER_PRIORITY = (
    BlockingReason.AUTHENTICATION_UNAVAILABLE,
    BlockingReason.SAFETY_CONFLICT,
    BlockingReason.NO_SUPPORTED_TEST_CAPABILITY,
    BlockingReason.SCOPE_AMBIGUITY,
    BlockingReason.INSUFFICIENT_CONTEXT,
    BlockingReason.BUDGET_UNAVAILABLE,
    BlockingReason.NO_TESTABLE_HYPOTHESIS,
)


def deterministic_blocker(context: dict[str, Any]) -> BlockingReason | None:
    """The most specific valid blocker for a context, or None if a test is constructible."""
    for reason in _BLOCKER_PRIORITY:
        if _blocker_valid(reason, context):
            return reason
    return None


def preflight(context: dict[str, Any]) -> BlockingReason | None:
    """Deterministic preflight (Part D): evaluate controller-KNOWN facts before any model call.

    Returns the most specific controller-owned blocker (scope uniqueness, credential availability,
    supported read-only capability, sufficient object context, budgets, no state-changing-only
    surface), or None if a bounded read-only test is genuinely constructible and the model may be
    consulted. These are controller-owned facts, not a heuristic fallback: when one fails, the
    controller must not call the model and must not issue target traffic."""
    return deterministic_blocker(context)


def deterministic_blocking_condition(
    context: dict[str, Any], reason: BlockingReason
) -> BlockingCondition:
    """Build a fully factual blocker for the offline reference planner.

    Live models must author their own conditions; this helper is intentionally used only by the
    explicitly labelled deterministic demo provider."""
    values = _fact_values(context)
    claims = [
        BlockingClaim(fact=fact, value=values[fact])
        for fact in sorted(_REQUIRED_FACTS[reason], key=lambda item: item.value)
    ]
    missing = ["known_objects"] if reason is BlockingReason.INSUFFICIENT_CONTEXT else []
    return BlockingCondition(reason=reason, claims=claims, missing_context_fields=missing)


# --- per-candidate validation (Part B / Part E) --------------------------------------------------


def _owner_profile_of(context: dict[str, Any], obj: str) -> str | None:
    owners = context.get("surface", {}).get("known_test_objects", {})
    return next(
        (
            profile
            for profile, objects in owners.items()
            if isinstance(objects, list) and obj in objects
        ),
        None,
    )


def _semantic_key(candidate: ObjectAuthorizationCandidate) -> tuple[str, ...]:
    """Content identity of a candidate. Independent of the order the model returned candidates
    and of the controller-assigned id, so it also serves as the deterministic ordering key."""
    return (
        candidate.capability,
        candidate.operation_id,
        candidate.alternate_principal_ref,
        candidate.owner_principal_ref,
        candidate.object_ref,
    )


def _reject_reason(
    candidate: ObjectAuthorizationCandidate, context: dict[str, Any]
) -> tuple[str, str] | None:
    """Return a (code, detail) rejection for a candidate, or None if it passes validation.

    Validation never fills, repairs or substitutes a model-selected field; it only accepts or
    rejects. object_ref is required by the model, so an omitted object reference is a structural
    ValidationError upstream, never something this function completes."""
    if candidate.capability not in registered_ids():
        return ("UNKNOWN_CAPABILITY", candidate.capability)
    cap = get_capability(candidate.capability)
    if cap is None:
        return ("UNKNOWN_CAPABILITY", candidate.capability)
    operations = {op["operation_id"]: op for op in context.get("operations", [])}
    op = operations.get(candidate.operation_id)
    if op is None:
        return ("UNKNOWN_OPERATION", candidate.operation_id)
    if not op.get("read_only"):
        return ("STATE_CHANGING_OPERATION", candidate.operation_id)
    method = op.get("method")
    if method not in cap.methods:
        return ("UNSUPPORTED_METHOD", str(method))
    if op.get("object_parameter") is None:
        return ("OPERATION_HAS_NO_OBJECT_BINDING", candidate.operation_id)
    available = context.get("available_credentials", [])
    authenticated = _authenticated(context)
    if (
        candidate.owner_principal_ref not in available
        or candidate.owner_principal_ref not in authenticated
    ):
        return ("PRINCIPAL_UNAVAILABLE", candidate.owner_principal_ref)
    if (
        candidate.alternate_principal_ref not in available
        or candidate.alternate_principal_ref not in authenticated
    ):
        return ("PRINCIPAL_UNAVAILABLE", candidate.alternate_principal_ref)
    if candidate.owner_principal_ref == candidate.alternate_principal_ref:
        return ("PRINCIPALS_NOT_DISTINCT", candidate.alternate_principal_ref)
    if context.get("scope_ambiguity"):
        return ("SCOPE_AMBIGUITY", candidate.operation_id)
    if candidate.object_ref not in context.get("known_objects", []):
        return ("UNKNOWN_OBJECT", candidate.object_ref)
    # The declared owner must actually own object_ref, and the alternate must not: this is what
    # makes the direction a testable cross-owner access. The controller re-derives ownership; never
    # trusts the model's ownership claim on its own.
    actual_owner = _owner_profile_of(context, candidate.object_ref)
    if candidate.owner_principal_ref != actual_owner:
        return ("OWNER_PRINCIPAL_MISMATCH", candidate.object_ref)
    if candidate.alternate_principal_ref == actual_owner:
        return ("ALTERNATE_IS_OWNER", candidate.object_ref)
    stray = [ref for ref in candidate.projected_context_refs if ref not in _projected_refs(context)]
    if stray:
        return ("UNPROJECTED_REFERENCE", stray[0])
    # The alternate must own its own comparable object so the deterministic verifier can establish
    # the cross-owner comparison; with only two synthetic objects this always holds, but check it.
    if _own_object_of(candidate.alternate_principal_ref) is None:
        return ("ALTERNATE_HAS_NO_OWN_OBJECT", candidate.alternate_principal_ref)
    # Do not re-run a probe already observed this scan (avoids duplicate, wasted target traffic).
    if any(
        observation.get("credential_profile") == candidate.alternate_principal_ref
        and observation.get("account_id") == candidate.object_ref
        and observation.get("method") == method
        for observation in context.get("observations", [])
    ):
        return ("ALREADY_OBSERVED", candidate.object_ref)
    if not _remaining_ok(context):
        return ("BUDGET_INSUFFICIENT", "remaining")
    return None


def validate_candidates(
    context: dict[str, Any], candidates: list[TestCandidate]
) -> tuple[list[ValidatedCandidate], list[CandidateRejection]]:
    """Validate every candidate deterministically; assign controller IDs to survivors.

    Rejection never creates a finding and never executes traffic. Candidate IDs are assigned here by
    the control plane in deterministic order; the model never invents a canonical ID."""
    validated: list[ValidatedCandidate] = []
    rejections: list[CandidateRejection] = []
    seen: set[tuple[str, ...]] = set()
    counter = 0
    for index, candidate in enumerate(candidates):
        # Re-validate the structural shape defensively (callers may construct raw models).
        candidate = ObjectAuthorizationCandidate.model_validate(candidate.model_dump())
        rejection = _reject_reason(candidate, context)
        if rejection is None and _semantic_key(candidate) in seen:
            rejection = ("DUPLICATE_CANDIDATE", "semantic")
        if rejection is not None:
            rejections.append(
                CandidateRejection(candidate_index=index, code=rejection[0], detail=rejection[1])
            )
            continue
        seen.add(_semantic_key(candidate))
        counter += 1
        validated.append(
            ValidatedCandidate(candidate_id=f"cand-{counter:03d}", candidate=candidate)
        )
    return validated, rejections


def get_validated(validated: list[ValidatedCandidate], candidate_id: str) -> ValidatedCandidate:
    for v in validated:
        if v.candidate_id == candidate_id:
            return v
    raise KeyError(candidate_id)


# --- deterministic execution queue (Part A) ------------------------------------------------------


_CAPABILITY_ORDER: tuple[str, ...] = tuple(c.id for c in CAPABILITY_REGISTRY)


def _capability_priority(capability_id: str) -> int:
    """Registered capability priority: earlier in the registry ranks first. Controller-owned."""
    return (
        _CAPABILITY_ORDER.index(capability_id)
        if capability_id in _CAPABILITY_ORDER
        else len(_CAPABILITY_ORDER)
    )


def _order_key(validated: ValidatedCandidate) -> tuple[Any, ...]:
    """Deterministic, MODEL-INDEPENDENT ordering key (Part A.6): registered capability priority, the
    approved operation id, then the principal relationship tuple and object reference. The
    controller-assigned candidate id is only a final, never-reached tiebreaker (content keys are
    unique because semantic duplicates are rejected)."""
    c = validated.candidate
    return (
        _capability_priority(c.capability),
        c.operation_id,
        c.alternate_principal_ref,
        c.owner_principal_ref,
        c.object_ref,
        validated.candidate_id,
    )


# A single object-authorization direction compiles to two fresh owner controls plus one cross-owner
# probe (aegis.candidates._authorization_reads). This is the per-candidate request cost used for
# deterministic budget admission.
REQUESTS_PER_OBJECT_AUTH_CANDIDATE = 3


def execution_queue(
    validated: list[ValidatedCandidate],
    remaining: dict[str, int],
    requests_per_candidate: int = REQUESTS_PER_OBJECT_AUTH_CANDIDATE,
) -> list[QueuedCandidate]:
    """Order validated candidates deterministically and admit as many as fit within the remaining
    request budget (each candidate compiles to ``requests_per_candidate`` read-only requests).
    Ordering depends ONLY on controller-owned candidate content, never on model output order or
    model confidence, so it is stable and model-independent (Part A.6)."""
    ordered = sorted(validated, key=_order_key)
    request_budget = max(0, int(remaining.get("requests", 0)))
    cost = max(1, requests_per_candidate)
    queue: list[QueuedCandidate] = []
    for index, item in enumerate(ordered):
        admitted = (index + 1) * cost <= request_budget
        queue.append(
            QueuedCandidate(
                candidate_id=item.candidate_id,
                order_index=index,
                admitted=admitted,
                reason="ADMITTED" if admitted else "BUDGET_UNAVAILABLE",
            )
        )
    return queue


def ordered_validated(validated: list[ValidatedCandidate]) -> list[ValidatedCandidate]:
    """The validated candidates in deterministic execution order (used by the controller loop)."""
    return sorted(validated, key=_order_key)


# --- deterministic request compiler (Part C) -----------------------------------------------------


def _own_object_of(profile: str) -> str | None:
    """The synthetic object owned by an authenticated principal profile (controller-owned)."""
    actor = PROFILE_ACTORS.get(profile)
    return next((obj for obj, owner in OBJECTS.items() if owner == actor), None)


def _object_read_operation(proj: ScenarioProjection) -> Any:
    op = next((o for o in proj.operations if o.object_parameter is not None and o.read_only), None)
    if op is None or op.object_parameter is None:
        raise ValueError("Projected surface has no read-only object operation to compile")
    return op


def _authorization_reads(
    directions: Sequence[tuple[str, str]], proj: ScenarioProjection, name_prefix: str
) -> list[PlannedRequest]:
    """Build the deterministic read sequence that the DETERMINISTIC verifier requires to judge a set
    of cross-owner access directions: fresh legitimate controls for every involved principal (each
    reads its OWN object), then the cross-owner probe for each direction. Controls come first so the
    conservative [200, 200, 403] denial sequence is produced only when actually observed, never from
    a single denial. The controls use controller-owned ownership/credential resolution; they are the
    controller's fixed test procedure for the model's direction, not new model-chosen directions."""
    op = _object_read_operation(proj)

    def path_for(obj: str) -> str:
        if obj not in OBJECTS or obj not in op.objects:
            raise ValueError("Object reference is outside the approved projected objects")
        # ``op`` is intentionally Any (see _object_read_operation), so cast the concrete result.
        return str(op.path_template.replace("{" + op.object_parameter + "}", obj))

    control_profiles: set[str] = set()
    for alternate, obj in directions:
        control_profiles.add(alternate)
        owner = _owner_profile_of_object(obj)
        if owner is None:
            raise ValueError("Direction object has no resolvable owner principal")
        control_profiles.add(owner)
    requests: list[PlannedRequest] = []
    for profile in sorted(control_profiles):
        own = _own_object_of(profile)
        if own is None:
            raise ValueError("Control principal has no owned object")
        requests.append(
            PlannedRequest(
                name=f"{name_prefix}-control-{profile}",
                method=op.method,  # op is Any (see _object_read_operation)
                path=path_for(own),
                credential_profile=profile,  # type: ignore[arg-type]
                purpose="Fresh legitimate owner control read for the authorization comparison.",
            )
        )
    for alternate, obj in sorted(set(directions)):
        requests.append(
            PlannedRequest(
                name=f"{name_prefix}-probe-{alternate}-{obj}",
                method=op.method,  # op is Any (see _object_read_operation)
                path=path_for(obj),
                credential_profile=alternate,  # type: ignore[arg-type]
                purpose="Read another owner's object by identifier to test object authorization.",
            )
        )
    return requests


def compile_probe(
    validated: ValidatedCandidate, proj: ScenarioProjection, ordinal: int
) -> Hypothesis:
    """Compile ONE admitted validated candidate into the existing typed read-only authorization
    sequence (Part C): the alternate and owner controls plus the alternate's cross-owner probe of
    the candidate's object_ref. Uses ONLY projected/approved values and controller-owned credential
    ownership resolution. Fails closed (ValueError) if a reference cannot be resolved; it never
    invents or substitutes a missing candidate reference."""
    candidate = validated.candidate
    operations = {op.operation_id: op for op in proj.operations}
    op = operations.get(candidate.operation_id)
    if op is None or op.object_parameter is None or not op.read_only:
        raise ValueError("Candidate operation cannot be compiled into a read-only object request")
    prefix = f"{validated.candidate_id}-{ordinal:02d}"
    requests = _authorization_reads(
        [(candidate.alternate_principal_ref, candidate.object_ref)], proj, prefix
    )
    return Hypothesis(
        id=prefix,
        title=candidate.expected_authorization_invariant[:200],
        category="BOLA",
        rationale="Cross-owner object read compared against the projected ownership boundary.",
        # Categorical, controller-assigned floor. Model text NEVER sets finding confidence, severity
        # or execution authority (Part A.7); only the deterministic verifier confirms a finding.
        confidence=0.86,
        requests=requests,
    )


def compile_retest(objectives: list[RetestObjective], proj: ScenarioProjection) -> Hypothesis:
    """Deterministically construct the linked patched retest plan from the confirmed finding's
    structured objectives (Part F). This is verification of a KNOWN direction, not a new generative
    task: the model is never consulted. It repeats the same operation and object relationship and
    collects FRESH owner controls plus the fresh cross-owner probe, so a single denial cannot
    establish PASS."""
    if not objectives:
        raise ValueError("A linked retest requires at least one confirmed objective")
    directions = [(o.credential_profile, o.account_id) for o in objectives]
    requests = _authorization_reads(directions, proj, "retest")
    return Hypothesis(
        id="linked-patched-retest",
        title="Linked patched retest of the confirmed cross-owner access direction",
        category="BOLA",
        rationale="Repeat the confirmed principal/object direction with fresh evidence.",
        confidence=0.86,
        requests=requests,
    )


def _owner_profile_of_object(obj: str) -> str | None:
    actor = OBJECTS.get(obj)
    return next((profile for profile, a in PROFILE_ACTORS.items() if a == actor), None)


# --- DEPRECATED Phase 0.7 model-based selection (retained for historical readability only) --------
# The Phase 0.8 live flow NEVER calls these. They remain so historical Phase 0.7 evidence, schemas
# and the deprecated gateway /v1/select path stay importable and readable (docs/phase-0.8 Part A.2).


def selection_views(validated: list[ValidatedCandidate]) -> list[SelectionCandidateView]:
    return [
        SelectionCandidateView(candidate_id=v.candidate_id, candidate=v.candidate)
        for v in validated
    ]


def selection_schema(
    validated_ids: list[str], context: dict[str, Any] | None = None
) -> dict[str, Any]:
    """DEPRECATED. Strict schema for the removed model-based selection call."""
    adapter: TypeAdapter[Any] = TypeAdapter(CandidateSelection)
    schema = adapter.json_schema()
    defs = schema.get("$defs", {})
    for def_name in ("SelectOneSelection", "PerCandidateRejection"):
        entry = defs.get(def_name)
        if isinstance(entry, dict) and isinstance(entry.get("properties"), dict):
            entry["properties"]["candidate_id"] = {"type": "string", "enum": sorted(validated_ids)}
    if context is not None:
        refs = sorted(_projected_refs(context))
        operations = sorted({op["operation_id"] for op in context.get("operations", [])})
        capabilities = sorted(context_capability_ids(context))
        review = defs.get("ReviewSelection")
        if isinstance(review, dict) and isinstance(review.get("properties"), dict):
            props = review["properties"]
            props["context_refs"] = {
                "type": "array",
                "items": {"type": "string", "enum": refs},
                "maxItems": 12,
            }
            props["operation_id"] = {
                "anyOf": [{"type": "string", "enum": operations}, {"type": "null"}]
            }
            props["capability"] = {
                "anyOf": [{"type": "string", "enum": capabilities}, {"type": "null"}]
            }
        rejection = defs.get("PerCandidateRejection")
        if isinstance(rejection, dict) and isinstance(rejection.get("properties"), dict):
            rejection["properties"]["context_refs"] = {
                "type": "array",
                "items": {"type": "string", "enum": refs},
                "maxItems": 12,
            }
    return schema


def validate_selection(
    selection: CandidateSelection,
    validated: list[ValidatedCandidate],
    context: dict[str, Any],
) -> tuple[str, str | None]:
    """DEPRECATED. Validation for the removed model-based selection call. Unused by live flow."""
    ids = {v.candidate_id for v in validated}
    if isinstance(selection, RejectAllSelection):
        covered = {r.candidate_id for r in selection.rejections}
        refs = _projected_refs(context)
        if any(r.candidate_id not in ids for r in selection.rejections):
            return ("INVALID", "unknown_candidate_id")
        if covered != ids or len(selection.rejections) != len(ids):
            return ("INVALID", "reject_all_requires_reason_for_every_candidate")
        if any(
            ref not in refs
            for rejection in selection.rejections
            for ref in rejection.context_refs
        ):
            return ("INVALID", "reject_all_contains_unprojected_reference")
        return ("REJECT_ALL", None)
    if selection.selection_type == "review":
        review = ReviewSelection.model_validate(selection.model_dump())
        condition = BlockingCondition(
            reason=review.reason,
            context_refs=review.context_refs,
            claims=review.claims,
            operation_id=review.operation_id,
            capability=review.capability,
            missing_context_fields=review.missing_context_fields,
        )
        if not validate_blockers(context, [condition])[0].valid:
            return ("INVALID", "review_reason_precondition_not_satisfied")
        return ("REVIEW", selection.reason.value)
    if selection.candidate_id not in ids:
        return ("INVALID", "unknown_candidate_id")
    return ("SELECT", selection.candidate_id)


__all__ = [
    "EXECUTION_POLICY_VERSION",
    "any_supported_operation",
    "build_context",
    "candidate_generation_schema",
    "compile_probe",
    "compile_retest",
    "constructible_read_only_test",
    "deterministic_blocker",
    "deterministic_blocking_condition",
    "execution_queue",
    "first_valid_blocker",
    "get_validated",
    "ordered_validated",
    "preflight",
    "selection_schema",
    "selection_views",
    "validate_blockers",
    "validate_candidates",
    "validate_selection",
]
