from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


# Planner Contract version.
#
# V1 was a single monolithic AgentDecision with an optional/nullable hypothesis field and an
# execute-XOR-hypothesis cross-field validator. Constrained decoding cannot express that cross-field
# rule, so small local models produced schema-shaped but Pydantic-invalid decisions
# (docs/phase-0.5).
#
# V2 replaced it with an explicitly discriminated decision union whose generation and validation
# schemas are congruent. That removed the structural brittleness but exposed model under-action: at
# the single generative discovery step the model chose a valid terminal decision (stop/review)
# instead of proposing a hypothesis (docs/phase-0.5, docs/phase-0.6), across qwen3:4b, qwen3:8b and
# foundation-sec:8b-q4.
#
# V3 (Candidate-First Planning Protocol, docs/phase-0.7) separates idea generation from decision:
# a bounded candidate ENUMERATION step that cannot emit a terminal decision, deterministic candidate
# VALIDATION with controller-assigned IDs, and a bounded SELECTION step over the model's own
# validated candidates only. Terminating early now requires either a machine-checkable blocking
# condition (validated against the projected context and deterministic verifier state, never model
# prose) or a per-candidate structured rejection. This number is recorded in scan results, provider
# metadata, audit records, comparison artifacts and the dashboard.
#
# Phase 0.8 keeps planner_contract_version = 3 (the enumeration contract is unchanged in spirit) but
# corrects the responsibility boundary: the second, model-based candidate SELECTION call is removed
# from the live flow (docs/phase-0.8). Validated candidates are admitted into a DETERMINISTIC
# execution queue ordered only by controller-owned data, and the linked patched retest is
# constructed deterministically from the confirmed finding. execution_policy_version records the
# version of that deterministic admission/ordering/execution policy.
PLANNER_CONTRACT_VERSION = 3

# Phase 0.8 deterministic execution policy version. Incremented only when the deterministic
# admission, ordering, budget or compilation policy changes. It never encodes model behaviour and is
# recorded in scan results, audit records, comparison artifacts and the dashboard.
EXECUTION_POLICY_VERSION = 1


class ScanStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    PASS = "PASS"  # noqa: S105 - status label, not a credential
    FAIL = "FAIL"
    REVIEW = "REVIEW"
    INCOMPLETE = "INCOMPLETE"


class ScenarioClass(StrEnum):
    """Phase 0.7 evaluation scenario classes. A scenario changes only the PROJECTED CONTEXT handed
    to the model (surface, available credential profiles, scope markers) and the target variant. The
    control plane, deterministic validators and verifier react uniformly; there is no per-scenario
    or per-model behaviour branch. Expected-outcome labels live in the benchmark harness, never
    here."""

    POSITIVE_VULNERABLE = "positive_vulnerable"
    PATCHED_NEGATIVE = "patched_negative"
    MISSING_AUTH = "missing_auth"
    OUT_OF_SCOPE = "out_of_scope"
    STATE_CHANGING_ONLY = "state_changing_only"


class BlockingReason(StrEnum):
    """Structured, machine-checkable reasons a candidate enumeration may return zero candidates.
    Each reason has a deterministic precondition (see aegis.candidates); a model-supplied reason is
    never accepted on its text alone."""

    INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"
    AUTHENTICATION_UNAVAILABLE = "AUTHENTICATION_UNAVAILABLE"
    SCOPE_AMBIGUITY = "SCOPE_AMBIGUITY"
    SAFETY_CONFLICT = "SAFETY_CONFLICT"
    NO_SUPPORTED_TEST_CAPABILITY = "NO_SUPPORTED_TEST_CAPABILITY"
    NO_TESTABLE_HYPOTHESIS = "NO_TESTABLE_HYPOTHESIS"
    BUDGET_UNAVAILABLE = "BUDGET_UNAVAILABLE"


class ConfidenceCategory(StrEnum):
    """Bounded, categorical candidate confidence. Never determines finding severity or confirmation;
    only the deterministic verifier does that."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class SelectionRejectionReason(StrEnum):
    DUPLICATE_COVERAGE = "DUPLICATE_COVERAGE"
    LOWER_INFORMATION_VALUE = "LOWER_INFORMATION_VALUE"
    NOT_RELEVANT_TO_OBJECTIVE = "NOT_RELEVANT_TO_OBJECTIVE"
    EVIDENCE_ALREADY_SUFFICIENT = "EVIDENCE_ALREADY_SUFFICIENT"


class PrincipalRelationship(StrEnum):
    """How the acting principal relates to the object under test, expressed structurally rather than
    as a raw credential. The controller maps it to a synthetic credential profile deterministically;
    the model never sees or emits a credential value."""

    OWNER = "owner"
    CROSS_OWNER = "cross_owner"
    ANONYMOUS = "anonymous"


class ObjectRelationship(StrEnum):
    OWNED_BY_PRINCIPAL = "owned_by_principal"
    OWNED_BY_OTHER = "owned_by_other"
    NOT_APPLICABLE = "not_applicable"


class BlockingFact(StrEnum):
    """Facts whose values the controller can re-derive from the projected context."""

    AUTHENTICATED_PRINCIPAL_COUNT = "authenticated_principal_count"
    KNOWN_OBJECT_COUNT = "known_object_count"
    SUPPORTED_OPERATION_COUNT = "supported_operation_count"
    SAFE_OPERATION_COUNT = "safe_operation_count"
    SCOPE_AMBIGUITY = "scope_ambiguity"
    CONSTRUCTIBLE_TEST = "constructible_test"
    REMAINING_REQUESTS = "remaining_requests"
    REMAINING_MODEL_CALLS = "remaining_model_calls"
    REMAINING_TOKEN_RESERVATIONS = "remaining_token_reservations"  # noqa: S105
    REMAINING_TIME_MS = "remaining_time_ms"


class PlannedRequest(StrictModel):
    name: str = Field(min_length=3, max_length=100)
    method: Literal["GET", "HEAD", "OPTIONS"]
    path: str = Field(pattern=r"^/[A-Za-z0-9/_{}-]+$", max_length=200)
    credential_profile: Literal["anonymous", "user_a", "user_b"]
    purpose: str = Field(min_length=3, max_length=300)

    @field_validator("path", mode="before")
    @classmethod
    def reject_query_and_fragments(cls, value: Any) -> Any:
        if isinstance(value, str) and (
            value.startswith("//") or "?" in value or "#" in value or ".." in value
        ):
            raise ValueError("Path must not contain authority, query, fragment, or traversal")
        return value


class Hypothesis(StrictModel):
    id: str = Field(pattern=r"^[a-z0-9-]+$", max_length=100)
    title: str = Field(max_length=200)
    category: Literal["BOLA", "AUTHN", "EXPOSURE"]
    rationale: str = Field(max_length=1000)
    confidence: float = Field(ge=0, le=1)
    requests: list[PlannedRequest] = Field(min_length=1, max_length=8)


class PlannerOutput(StrictModel):
    summary: str
    hypotheses: list[Hypothesis] = Field(min_length=1, max_length=4)


# --- Planner Contract V2: explicitly discriminated decision union -------------------------------
# Every variant is strict and forbids additional properties, and carries ONLY the fields meaningful
# to that decision. There are no inactive nullable fields: a StopDecision has no hypothesis field at
# all, so a stop decision that carries a hypothesis is rejected as an extra property (not silently
# dropped). The discriminator is `decision_type`. Because each variant makes its fields required or
# absent, the JSON Schema handed to the model at generation time is congruent with this validation
# schema — the V1 execute-XOR-hypothesis gap that produced Pydantic-structural rejections is closed.
#
# Field order matters for constrained decoding: `decision_type` is declared FIRST in every variant
# so the model commits to a branch before writing anything else. A hypothesis/execute variant is
# then grammatically required to emit its `hypothesis` object. With `summary` first instead, small
# models were observed to describe an intent to hypothesize and then still settle the trailing
# discriminator on a terminal type (see docs/phase-0.5.md). This ordering is a decoding aid only;
# the strict Pydantic schema and fail-closed re-validation remain the sole authority.


class HypothesisDecision(StrictModel):
    """Generative discovery step: propose and drive ONE bounded, evidence-collecting hypothesis."""

    decision_type: Literal["hypothesis"] = "hypothesis"
    summary: str = Field(min_length=3, max_length=1000)
    hypothesis: Hypothesis


class ExecuteDecision(StrictModel):
    """Confirmatory step (linked patched retest): run a bounded test to reproduce the already
    confirmed access direction. Structurally carries a hypothesis so the deterministic verifier can
    bind evidence to it; the retest direction is validated semantically, never pre-filled."""

    decision_type: Literal["execute"] = "execute"
    summary: str = Field(min_length=3, max_length=1000)
    hypothesis: Hypothesis


class ContinueDecision(StrictModel):
    """Post-verification step: continue the bounded loop to gather more evidence (no network action
    of its own; the next state proposes/executes the next bounded test)."""

    decision_type: Literal["continue"] = "continue"
    summary: str = Field(min_length=3, max_length=1000)


class StopDecision(StrictModel):
    decision_type: Literal["stop"] = "stop"
    summary: str = Field(min_length=3, max_length=1000)


class ReviewDecision(StrictModel):
    decision_type: Literal["review"] = "review"
    summary: str = Field(min_length=3, max_length=1000)


PlannerDecision = Annotated[
    HypothesisDecision | ExecuteDecision | ContinueDecision | StopDecision | ReviewDecision,
    Field(discriminator="decision_type"),
]

# Authoritative validator for a discriminated decision (full union). Subset unions for a specific
# orchestrator state are built in aegis.contract. Under Contract V3 the executed hypothesis and the
# terminal decision are synthesised DETERMINISTICALLY by the controller and recorded through these
# same types; the model no longer emits a decision directly at the generative step.
PLANNER_DECISION_ADAPTER: TypeAdapter[Any] = TypeAdapter(PlannerDecision)


# --- Planner Contract V3: candidate enumeration --------------------------------------------------
# The model authors HypothesisCandidate and BlockingCondition objects only. It never authors a
# canonical candidate ID (the controller assigns those after deterministic validation), a finding,
# a severity, a confirmed/PASS/FAIL status, a raw HTTP request, a URL, a credential, a header, raw
# response prose, hidden reasoning or a remediation claim. `extra="forbid"` makes any such stray
# field a hard rejection rather than a silently-dropped value.


class HypothesisCandidate(StrictModel):
    """DEPRECATED (Phase 0.7 shape). A single bounded, read-only test IDEA proposed by the model.

    Phase 0.8 replaced this over-generic, optional-field shape with a strict,
    capability-discriminated union (``ObjectAuthorizationCandidate`` / ``TestCandidate`` below). It
    is retained
    only so historical Phase 0.7 schemas and records remain importable and readable; it is NOT used
    by the Phase 0.8 live flow. Its nullable ``object_ref`` is exactly the gap Phase 0.8 closes:
    qwen3:8b omitted the object reference for object operations and every candidate was rejected
    (docs/phase-0.7 §5).

    It carries only structured intent scoped to the projected context; it carries no path, URL,
    credential, header, finding, severity or verdict.
    """

    # Candidate type and supported verifier/test capability both come from the registered
    # deterministic capabilities projected into the context; the model selects, never invents them.
    test_type: Literal["BOLA", "AUTHN", "EXPOSURE"]
    capability: str = Field(max_length=100)
    # Approved operation identifier from the projected surface (never a raw path or URL).
    operation_id: str = Field(max_length=100)
    # Principal is expressed as an approved profile plus its structural relationship to the object.
    principal_profile: Literal["anonymous", "user_a", "user_b"]
    principal_relationship: PrincipalRelationship = Field(strict=False)
    # Approved synthetic object reference where applicable (e.g. an account id), plus its
    # relationship to the principal. object_ref is None for tests that do not target an object.
    object_ref: str | None = Field(default=None, max_length=100)
    object_relationship: ObjectRelationship = Field(
        default=ObjectRelationship.NOT_APPLICABLE, strict=False
    )
    expected_invariant: str = Field(min_length=3, max_length=300)
    observation: str = Field(min_length=3, max_length=300)
    method: Literal["GET", "HEAD", "OPTIONS"]
    # Projected context references the candidate relies on (projected operation ids, object refs,
    # evidence names). Validated for membership against the projected context.
    context_refs: list[str] = Field(default_factory=list, max_length=12)
    confidence_category: ConfidenceCategory = Field(strict=False)


# --- Planner Contract V3 / Phase 0.8: capability-discriminated candidates ------------------------
# A candidate is a strict variant keyed to a REGISTERED test capability (the discriminator is the
# ``capability`` field). Every variant forbids extra properties, so a field belonging to a different
# capability variant is a hard rejection rather than a silently-dropped value. The generation schema
# handed to the model narrows each variant's identifier fields to the projected surface via dynamic
# enums, so any candidate the model can emit is one deterministic validation could accept
# (aegis.candidates proves this subset relationship). New capabilities MUST add their own variant
# with their own required fields; the deprecated large optional-field ``HypothesisCandidate`` is
# never reintroduced.


class ObjectAuthorizationCandidate(StrictModel):
    """Object-level authorization (BOLA) test hypothesis for capability ``bola_object_read_v1``.

    It encodes exactly one testable cross-owner access DIRECTION: the ``alternate_principal_ref``
    principal attempts to read ``object_ref``, which belongs to ``owner_principal_ref``. It carries
    no path, URL, method, credential, header, cookie, request body, response data, finding, severity
    or PASS/FAIL verdict. The deterministic controller compiles it into the existing typed read-only
    PlannedRequest (aegis.candidates.compile_probe); the read-only method comes from the projected
    operation, never from the model.
    """

    # Discriminator: a registered capability id. Kept as a Literal so a candidate for an
    # unregistered or state-changing capability cannot be constructed. A test keeps this Literal in
    # sync with the registry.
    capability: Literal["bola_object_read_v1"]
    # Approved operation identifier from the projected surface (never a raw path or URL).
    operation_id: str = Field(min_length=1, max_length=100)
    # The principal that owns the object under test, and the DIFFERENT principal that attempts the
    # cross-owner read. Both are approved authenticated credential profiles (anonymous cannot own an
    # object nor establish a cross-owner read; that is an AUTHN concern with no registered cap).
    owner_principal_ref: Literal["user_a", "user_b"]
    alternate_principal_ref: Literal["user_a", "user_b"]
    # Required, non-empty, approved synthetic object reference. Never Optional, nullable or blank;
    # the generation schema narrows it to the dynamically projected object references only.
    object_ref: str = Field(min_length=1, max_length=100)
    # The authorization invariant the direction is expected to exercise, as structured prose only.
    expected_authorization_invariant: str = Field(min_length=3, max_length=300)
    # Projected context references the candidate relies on (projected operation ids, object refs,
    # credential profiles, capability ids, evidence names). Non-empty; validated for membership.
    projected_context_refs: list[str] = Field(min_length=1, max_length=12)

    @field_validator("operation_id", "object_ref", "expected_authorization_invariant", mode="after")
    @classmethod
    def _reject_blank(cls, value: str) -> str:
        # A blank or whitespace-only reference is never a valid approved identifier.
        if not value.strip():
            raise ValueError("value must not be blank")
        return value

    @field_validator("projected_context_refs", mode="after")
    @classmethod
    def _reject_blank_refs(cls, value: list[str]) -> list[str]:
        if any(not ref.strip() for ref in value):
            raise ValueError("projected_context_refs must not contain a blank reference")
        return value


# The capability-discriminated candidate union. Only one capability is registered today, so the
# union currently has a single member and the ``capability`` Literal is its discriminator; adding a
# second registered capability turns this into an ``Annotated[A | B, discriminator="capability"]``.
TestCandidate = ObjectAuthorizationCandidate
CANDIDATE_ADAPTER: TypeAdapter[Any] = TypeAdapter(TestCandidate)


class BlockingCondition(StrictModel):
    """A structured, machine-checkable reason enumeration returned no candidate.

    The controller re-derives every precondition from the projected context and the deterministic
    verifier state (aegis.candidates); the fields here are recorded for observability but never make
    an unjustified blocker valid on their own."""

    reason: BlockingReason = Field(strict=False)
    context_refs: list[str] = Field(default_factory=list, max_length=12)
    # Machine-checkable facts. Every value is re-derived and compared by the controller.
    claims: list["BlockingClaim"] = Field(min_length=1, max_length=12)
    operation_id: str | None = Field(default=None, max_length=100)
    capability: str | None = Field(default=None, max_length=100)
    # For INSUFFICIENT_CONTEXT: the required context fields the model reports as missing.
    missing_context_fields: list[str] = Field(default_factory=list, max_length=12)


class BlockingClaim(StrictModel):
    fact: BlockingFact = Field(strict=False)
    value: bool | int | str


class CandidateGenerationResult(StrictModel):
    """Stage 1 model output: a bounded candidate list (possibly empty) plus blocking conditions.

    Crucially this schema exposes NO direct stop/review decision: the model cannot take the cheap
    terminal exit at the idea step. An empty candidate list is legal only alongside one or more
    blocking conditions, each validated deterministically downstream."""

    candidates: list[TestCandidate] = Field(default_factory=list, max_length=3)
    blocking_conditions: list[BlockingCondition] = Field(default_factory=list, max_length=8)


class ValidatedCandidate(StrictModel):
    """A candidate that passed deterministic validation, tagged with a controller-assigned ID."""

    candidate_id: str = Field(pattern=r"^cand-[0-9]{3}$")
    candidate: TestCandidate


class CandidateRejection(StrictModel):
    """A deterministically rejected candidate. Rejection never creates a finding or executes."""

    candidate_index: int = Field(ge=0)
    code: str = Field(max_length=100)
    detail: str | None = Field(default=None, max_length=300)


# --- Planner Contract V3: bounded selection ------------------------------------------------------
# The selection schema dynamically enumerates ONLY the controller-assigned validated candidate IDs.
# The selector may pick exactly one, reject all (with a reason per candidate), or request review
# with a machine-checkable blocking reason. It can never mutate a candidate or invent a new one.


class SelectOneSelection(StrictModel):
    selection_type: Literal["select"] = "select"
    candidate_id: str = Field(pattern=r"^cand-[0-9]{3}$")
    rationale: str = Field(min_length=3, max_length=300)


class PerCandidateRejection(StrictModel):
    candidate_id: str = Field(pattern=r"^cand-[0-9]{3}$")
    reason: SelectionRejectionReason = Field(strict=False)
    context_refs: list[str] = Field(default_factory=list, max_length=12)


class RejectAllSelection(StrictModel):
    selection_type: Literal["reject_all"] = "reject_all"
    rejections: list[PerCandidateRejection] = Field(min_length=1, max_length=8)


class ReviewSelection(StrictModel):
    selection_type: Literal["review"] = "review"
    reason: BlockingReason = Field(strict=False)
    context_refs: list[str] = Field(default_factory=list, max_length=12)
    claims: list[BlockingClaim] = Field(min_length=1, max_length=12)
    operation_id: str | None = Field(default=None, max_length=100)
    capability: str | None = Field(default=None, max_length=100)
    missing_context_fields: list[str] = Field(default_factory=list, max_length=12)


CandidateSelection = Annotated[
    SelectOneSelection | RejectAllSelection | ReviewSelection,
    Field(discriminator="selection_type"),
]
CANDIDATE_SELECTION_ADAPTER: TypeAdapter[Any] = TypeAdapter(CandidateSelection)


class ContextObservation(StrictModel):
    name: str
    method: str
    path: str
    credential_profile: str
    status_code: int | None
    error: str | None = None
    account_id: str | None = None
    owner_id: str | None = None


class PlannerContext(StrictModel):
    """Strict projection of the control-plane context. Rejects any unexpected/injected field."""

    surface: dict[str, Any] = Field(default_factory=dict)
    observations: list[ContextObservation] = Field(default_factory=list)
    verification: dict[str, Any] = Field(default_factory=dict)
    retest: bool = False
    prior_finding: str | None = None
    retest_objectives: list[dict[str, Any]] = Field(default_factory=list)
    remaining: dict[str, int] = Field(default_factory=dict)
    # Contract V2: the orchestrator (which knows its own state) declares the legal response types
    # for the current state. The gateway uses this to constrain the generation schema; the control
    # plane re-enforces it. Constraining legal responses for a known state is not attack-hardcoding.
    permitted_decision_types: list[str] = Field(default_factory=list)
    # --- Contract V3 projection ----------------------------------------------------------------
    # Registered deterministic verifier/tool capabilities and approved operations projected to the
    # model so it can only name real capabilities and operations. The projection never selects one.
    capabilities: list[dict[str, Any]] = Field(default_factory=list)
    operations: list[dict[str, Any]] = Field(default_factory=list)
    available_credentials: list[str] = Field(default_factory=list)
    known_objects: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    scope_ambiguity: bool = False
    stage: str = "discovery"
    max_candidates: int = 3
    planner_contract_version: int = PLANNER_CONTRACT_VERSION


class GatewayPlanRequest(StrictModel):
    context: PlannerContext
    max_output_tokens: int = Field(ge=1, le=8192)


class GatewayCandidateRequest(StrictModel):
    """Stage 1 RPC: ask the isolated gateway to enumerate read-only candidates for this context."""

    context: PlannerContext
    max_output_tokens: int = Field(ge=1, le=8192)
    max_candidates: int = Field(ge=1, le=8)


class SelectionCandidateView(StrictModel):
    """DEPRECATED (Phase 0.7 model-based selection). A validated candidate as projected to the
    selector. Phase 0.8 removed the model-based selection call from the live flow; this and the
    selection models below are retained only so historical schemas/records remain readable."""

    candidate_id: str = Field(pattern=r"^cand-[0-9]{3}$")
    candidate: TestCandidate


class GatewaySelectRequest(StrictModel):
    """Stage 3 RPC: ask the gateway to select over the controller's validated candidate list."""

    context: PlannerContext
    max_output_tokens: int = Field(ge=1, le=8192)
    validated_candidates: list[SelectionCandidateView] = Field(min_length=1, max_length=3)


class ProviderUsage(StrictModel):
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)


class ProviderRunMetadata(BaseModel):
    """Provider-reported, non-sensitive run facts recorded for every real-model scan.

    Only explicit, non-secret runtime facts appear here. No hidden chain-of-thought, provider
    response prose, credentials, headers or raw model text is ever recorded.
    """

    provider_type: str
    runtime: str | None = None  # e.g. "ollama", "internal_openai_compatible"
    runtime_version: str | None = None  # e.g. Ollama server version
    model: str
    model_digest: str | None = None
    context_length: int | None = None
    temperature: float | None = None
    seed: int | None = None
    prompt_eval_count: int | None = None
    eval_count: int | None = None
    total_duration_ms: int | None = None
    load_duration_ms: int | None = None
    stop_reason: str | None = None
    planner_contract_version: int = PLANNER_CONTRACT_VERSION
    # Set when a decision was produced by a bounded schema-repair call (Part D). None/False on a
    # first-pass decision. Records only that a repair happened, never any repaired prose.
    repaired: bool = False


class GatewayPlanResponse(StrictModel):
    model: str
    decision: PlannerDecision
    usage: ProviderUsage
    metadata: ProviderRunMetadata
    planner_contract_version: int = PLANNER_CONTRACT_VERSION


class GatewayCandidateResponse(StrictModel):
    model: str
    result: CandidateGenerationResult
    usage: ProviderUsage
    metadata: ProviderRunMetadata
    planner_contract_version: int = PLANNER_CONTRACT_VERSION


class GatewaySelectResponse(StrictModel):
    model: str
    selection: CandidateSelection
    usage: ProviderUsage
    metadata: ProviderRunMetadata
    planner_contract_version: int = PLANNER_CONTRACT_VERSION


class BudgetUsage(BaseModel):
    requests: int = 0
    iterations: int = 0
    model_calls: int = 0
    reserved_tokens: int = 0
    reported_tokens: int = 0


class Verification(BaseModel):
    status: Literal["CONFIRMED", "PASS", "INSUFFICIENT"]
    summary: str
    evidence_names: list[str] = Field(default_factory=list)


class RequestEvidence(BaseModel):
    name: str
    method: str
    path: str
    credential_profile: str
    status_code: int | None
    duration_ms: int
    response_excerpt: dict[str, Any] | str | None
    error: str | None = None


class RetestObjective(StrictModel):
    credential_profile: Literal["user_a", "user_b"]
    account_id: Literal["A-100", "B-200"]


class BlockerEvaluation(BaseModel):
    """Deterministic verdict on one model-supplied blocking condition."""

    reason: BlockingReason
    valid: bool
    detail: str | None = None


class QueuedCandidate(BaseModel):
    """One entry in the deterministic execution queue (Phase 0.8, Part A).

    ``order_index`` is the position in the deterministic, model-independent ordering.
    ``admitted`` records whether the candidate fit within all remaining budgets; ``reason`` is the
    controller admission/rejection code (ADMITTED, BUDGET_UNAVAILABLE, COMPILATION_FAILED). None of
    these fields carries model confidence, severity or verdict."""

    candidate_id: str = Field(pattern=r"^cand-[0-9]{3}$")
    order_index: int = Field(ge=0)
    admitted: bool
    reason: str = Field(max_length=100)


class CandidateStageRecord(BaseModel):
    """Persisted, redacted record of one candidate enumeration -> validation -> deterministic
    execution-admission cycle (Phase 0.8). The ``selection*`` fields are retained only for
    historical Phase 0.7 records; the 0.8 flow leaves them None and records the queue."""

    stage: Literal["discovery", "retest"]
    generated: int = 0
    generated_candidates: list[TestCandidate] = Field(default_factory=list)
    validated_ids: list[str] = Field(default_factory=list)
    validated_candidates: list[ValidatedCandidate] = Field(default_factory=list)
    rejections: list[CandidateRejection] = Field(default_factory=list)
    blocker_evaluations: list[BlockerEvaluation] = Field(default_factory=list)
    # --- Phase 0.8 deterministic execution admission (Part A / Part J) -------------------------
    execution_policy_version: int | None = None
    queue: list[QueuedCandidate] = Field(default_factory=list)
    executed_candidate_ids: list[str] = Field(default_factory=list)
    # --- deprecated Phase 0.7 model-based selection fields (unused by the Phase 0.8 flow) ------
    selection_type: str | None = None
    selection: CandidateSelection | None = None
    selected_candidate_id: str | None = None
    terminal_reason: str | None = None


class Finding(BaseModel):
    id: str
    title: str
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    category: str
    confidence: Literal["CONFIRMED", "PROBABLE", "UNVERIFIED"]
    description: str
    remediation: str
    evidence_names: list[str]


class ScanResult(BaseModel):
    id: str
    target_name: str
    target_base_url: str
    status: ScanStatus
    planner: str
    mode: str = "DEMO_HEURISTIC"
    model: str | None = None
    provider_metadata: ProviderRunMetadata | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    summary: str = ""
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    evidence: list[RequestEvidence] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    safety_events: list[str] = Field(default_factory=list)
    error: str | None = None
    variant: Literal["vulnerable", "patched"] = "vulnerable"
    scenario: ScenarioClass = ScenarioClass.POSITIVE_VULNERABLE
    retest_of: str | None = None
    retest_objectives: list[RetestObjective] = Field(default_factory=list)
    decisions: list[PlannerDecision] = Field(default_factory=list)
    usage: BudgetUsage = Field(default_factory=BudgetUsage)
    verification: Verification | None = None
    stop_reason: str | None = None
    planner_contract_version: int = PLANNER_CONTRACT_VERSION
    # Count of bounded schema-repair attempts consumed across the scan (Part D). Zero when repair
    # was never triggered or is disabled.
    repair_attempts: int = 0
    # --- Contract V3 candidate-first observability (Part J) ------------------------------------
    candidate_records: list[CandidateStageRecord] = Field(default_factory=list)
    generated_candidates_total: int = 0
    validated_candidates_total: int = 0
    rejected_candidates_total: int = 0
    selected_candidate_id: str | None = None
    # Phase 0.8: the deterministic execution policy version applied to this scan, and the ordered
    # ids the deterministic queue executed. selected_candidate_id is kept as the id of the first
    # executed candidate for dashboard/harness continuity (a controller decision, not a model one).
    execution_policy_version: int | None = None
    executed_candidate_ids: list[str] = Field(default_factory=list)
    validated_blocker: BlockingReason | None = None
    # Exact structured terminal / GO-NO-GO reason (e.g. COVERAGE_COMPLETE, BLOCKED_SCOPE_AMBIGUITY,
    # GENERATION_INCOMPLETE, BLOCKER_VALIDATION_FAILED, ALL_CANDIDATES_REJECTED).
    terminal_reason: str | None = None
    # --- Phase 1.1 security-tool integration kernel (additive) --------------------------------
    # The engine that executed this scan and the adapter version it ran under. These are recorded
    # for provenance and console display; they never carry a credential or a raw command. Stored as
    # plain JSON (not the typed engine contracts) to keep aegis.models import-cycle free — the typed
    # kernel validates every record before it is dumped here (see aegis.engine).
    engine: str = "AEGIS_NATIVE"
    adapter_version: str | None = None
    engine_kernel_version: int | None = None
    engine_executions: list[dict[str, Any]] = Field(default_factory=list)
    engine_evidence: list[dict[str, Any]] = Field(default_factory=list)
    normalized_findings: list[dict[str, Any]] = Field(default_factory=list)
    engine_job_rejections: list[dict[str, Any]] = Field(default_factory=list)


class ScanCreate(StrictModel):
    target: Literal["synthetic-bank-api"] = "synthetic-bank-api"
    variant: Literal["vulnerable", "patched"] = "vulnerable"
    scenario: ScenarioClass = Field(default=ScenarioClass.POSITIVE_VULNERABLE, strict=False)
    retest_of: str | None = Field(default=None, pattern=r"^scan-[a-f0-9]{12}$")
