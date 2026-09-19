"""Provider-independent security-tool integration kernel (Phase 1.1).

This package establishes the common, deterministic contracts that let Aegis integrate external
security engines (Nuclei, ZAP, Burp DAST) *behind* the same responsibility boundary that already
governs the native BOLA path — without ever giving the AI planner direct access to a tool, a
credential, an arbitrary target, a command line or a tool-specific flag.

Responsibility boundary (unchanged from Phase 0.8; extended, never weakened):

- the AI planner proposes bounded, structured hypotheses only;
- the DETERMINISTIC controller selects an approved capability + engine profile and constructs the
  typed :class:`EngineJob`;
- the adapter translates that job into engine-specific execution and MUST NOT expand scope or
  interpret arbitrary model prose;
- engine findings are UNTRUSTED observations, never verified Aegis findings;
- only the deterministic Aegis verifier (or explicit human review) may promote a result;
- credentials remain inside the connector boundary; no engine receives unrestricted shell access.

Only ``AEGIS_NATIVE`` is enabled and executable in Phase 1.1. Nuclei, ZAP and Burp DAST are present
only as fail-closed disabled skeletons.
"""

from aegis.engine.adapters import (
    ADAPTERS,
    AegisNativeAdapter,
    DisabledEngineAdapter,
    EngineDispatcher,
    SecurityEngineAdapter,
    get_adapter,
)
from aegis.engine.catalog import (
    CAPABILITY_CATALOG,
    PROFILE_CATALOG,
    EngineCapability,
    EngineProfile,
    get_engine_capability,
    get_engine_profile,
    profiles_for_engine,
)
from aegis.engine.contracts import (
    EngineActivity,
    EngineEnvironment,
    EngineError,
    EngineErrorCode,
    EngineExecution,
    EngineExecutionStatus,
    EngineHealth,
    EngineJob,
    EngineObservation,
    EngineReportedFinding,
    EvidenceSourceClass,
    FindingLifecycleState,
    NormalizedEvidence,
    NormalizedFinding,
    RetentionClass,
    SecurityEngine,
    TargetReference,
    VerificationPolicy,
)
from aegis.engine.lifecycle import (
    correlate_reported_finding,
    normalize_observation_evidence,
    record_human_review,
    record_verifier_conclusion,
)
from aegis.engine.policy import (
    EnginePolicyRejection,
    build_engine_job,
)

__all__ = [
    "ADAPTERS",
    "CAPABILITY_CATALOG",
    "PROFILE_CATALOG",
    "AegisNativeAdapter",
    "DisabledEngineAdapter",
    "EngineActivity",
    "EngineCapability",
    "EngineDispatcher",
    "EngineEnvironment",
    "EngineError",
    "EngineErrorCode",
    "EngineExecution",
    "EngineExecutionStatus",
    "EngineHealth",
    "EngineJob",
    "EngineObservation",
    "EnginePolicyRejection",
    "EngineProfile",
    "EngineReportedFinding",
    "EvidenceSourceClass",
    "FindingLifecycleState",
    "NormalizedEvidence",
    "NormalizedFinding",
    "RetentionClass",
    "SecurityEngine",
    "SecurityEngineAdapter",
    "TargetReference",
    "VerificationPolicy",
    "build_engine_job",
    "correlate_reported_finding",
    "get_adapter",
    "get_engine_capability",
    "get_engine_profile",
    "normalize_observation_evidence",
    "profiles_for_engine",
    "record_human_review",
    "record_verifier_conclusion",
]
