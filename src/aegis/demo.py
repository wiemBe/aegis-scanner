"""Phase 0.9 reproducible management-demo builder (synthetic lab only, docs/phase-0.9).

This module contains ONLY pure, deterministic functions over the already-serialized scan JSON that
the control plane's read-only API returns (``/health`` and ``/api/scans/{id}``). It performs no
network, model or target activity of its own, imports nothing outside the Python standard library,
and never mutates a scan. That keeps it importable by both the host operator runner
(``scripts/demo_runner.py``) and the offline test-suite, and lets ``mypy --strict`` cover every
guard the demo relies on.

Responsibility boundary the demo asserts and renders (it never blurs the two):

* The local model contributes exactly ONE thing: a bounded object-authorization *candidate*
  (a cross-owner access DIRECTION). It never sees or emits a path, credential, response body,
  finding, severity or verdict.
* The deterministic controller validates, admits, compiles, authorizes and executes read-only
  requests, and the deterministic verifier — not the model — creates the finding from fresh bound
  evidence.

Every helper fails closed: a guard raises :class:`DemoGuardError` with a stable code the moment an
invariant is violated, and the runner turns that into an immediate non-zero exit.
"""

from __future__ import annotations

import json
from typing import Any

from aegis import audit as audit_contract

ACTOR_AI_MODEL = audit_contract.ACTOR_AI_MODEL
ACTOR_CONTROLLER = audit_contract.ACTOR_CONTROLLER
ACTOR_SAFETY = audit_contract.ACTOR_SAFETY
ACTOR_VERIFIER = audit_contract.ACTOR_VERIFIER
actor_for_event = audit_contract.actor_for_event
redacted_evidence_ref = audit_contract.redacted_evidence_ref
stable_event_id = audit_contract.stable_event_id

# --- Approved, recorded constants (Phase 0.8 GO state) -------------------------------------------
# These are the values the demo is allowed to accept. They are asserted, never inferred from the
# live run, so a drifted model, digest or contract fails the demo instead of being documented as
# whatever happened to be deployed.
EXPECTED_PLANNER = "LOCAL_LLM"
EXPECTED_PROVIDER_RUNTIME = "ollama"
EXPECTED_MODEL = "qwen3:8b"
# Ollama reports the digest as a long hex string; the Phase 0.8 evidence recorded the 500a1f067a9f…
# prefix. A prefix match is intentional: it pins identity without hard-coding a full 64-char digest.
EXPECTED_MODEL_DIGEST_PREFIX = "500a1f067a9f"
EXPECTED_CONTRACT_VERSION = 3
EXPECTED_EXECUTION_POLICY_VERSION = 1
EXPECTED_TEMPERATURE = 0.0
EXPECTED_SEED = 42
EXPECTED_CONTEXT_LENGTH = 8192

# The exact response sequences the demonstrated claim commits to. The controller emits two fresh
# owner controls followed by the cross-owner probe; the demo refuses to proceed on anything else.
# Typed to match the observed codes (which may be None on a transport error) so the equality guard
# compares like with like.
VULNERABLE_SEQUENCE: list[int | None] = [200, 200, 200]
PATCHED_SEQUENCE: list[int | None] = [200, 200, 403]

READ_ONLY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
VULNERABLE_ROUTE = "/api/v1/accounts/{account_id}"
# The synthetic remediation route. It is a lab construct, not a real patched application; the demo
# labels it as such everywhere it appears.
SYNTHETIC_PATCHED_ROUTE = "/api/v1/patched/accounts/{account_id}"

# Markers whose presence anywhere in the manifest or in a demo-facing payload means a secret,
# balance, raw response body or hidden model reasoning leaked. Scanned case-insensitively. These key
# on concrete secret VALUES and body fragments, never on the substring "authorization" (which
# legitimately appears in schema field names such as safety_authorization).
SECRET_MARKERS: tuple[str, ...] = (
    "lab-token",  # synthetic credential profile value
    "synthetic-password",
    "bearer ",  # a leaked bearer credential value
    "set-cookie",
    "balance",  # a leaked account response body field
    "1250.25",
    "9875.5",
    "<think>",  # hidden model reasoning
    "</think>",
    "chain of thought",
    "chain-of-thought",
    "reasoning_content",
)


class DemoGuardError(AssertionError):
    """A Phase 0.9 invariant was violated. ``code`` is a stable machine identifier the runner prints
    and exits non-zero on; the message adds redacted context only."""

    def __init__(self, code: str, message: str = "") -> None:
        self.code = code
        super().__init__(f"{code}: {message}" if message else code)


# --- small typed accessors -----------------------------------------------------------------------


def _scan(report: dict[str, Any]) -> dict[str, Any]:
    scan = report.get("scan")
    if not isinstance(scan, dict):
        raise DemoGuardError("MALFORMED_REPORT", "report has no scan object")
    return scan


def _audit(report: dict[str, Any]) -> list[dict[str, Any]]:
    audit = report.get("audit")
    return audit if isinstance(audit, list) else []


def _status_codes(scan: dict[str, Any]) -> list[int | None]:
    return [item.get("status_code") for item in scan.get("evidence", [])]


def _methods(scan: dict[str, Any]) -> list[str | None]:
    return [item.get("method") for item in scan.get("evidence", [])]


def _first_record(scan: dict[str, Any]) -> dict[str, Any]:
    records = scan.get("candidate_records", [])
    for record in records:
        if isinstance(record, dict) and record.get("stage") == "discovery":
            return record
    raise DemoGuardError("NO_DISCOVERY_RECORD", "scan has no discovery candidate record")


def _validated_candidate(scan: dict[str, Any]) -> dict[str, Any]:
    record = _first_record(scan)
    validated = record.get("validated_candidates", [])
    if not validated:
        raise DemoGuardError("NO_VALIDATED_CANDIDATE", "no candidate survived validation")
    candidate = validated[0].get("candidate")
    if not isinstance(candidate, dict):
        raise DemoGuardError("NO_VALIDATED_CANDIDATE", "validated candidate has no body")
    return candidate


def _confirmed_candidate(scan: dict[str, Any]) -> dict[str, Any]:
    """The model-proposed candidate the deterministic controller actually EXECUTED and that led to
    the finding (``selected_candidate_id`` / first executed id). The model may propose several valid
    candidates; the demo must surface the one whose direction the finding confirms, not merely the
    first validated one. Falls back to the first validated candidate."""

    record = _first_record(scan)
    validated = {
        v.get("candidate_id"): v.get("candidate")
        for v in record.get("validated_candidates", [])
        if isinstance(v.get("candidate"), dict)
    }
    if not validated:
        raise DemoGuardError("NO_VALIDATED_CANDIDATE", "no candidate survived validation")
    executed = scan.get("executed_candidate_ids") or []
    chosen_id = scan.get("selected_candidate_id") or (executed[0] if executed else None)
    candidate = validated.get(chosen_id)
    if isinstance(candidate, dict):
        return candidate
    return _validated_candidate(scan)


# --- individual guards (Part B.9) ----------------------------------------------------------------


def assert_local_llm_planner(health: dict[str, Any], discovery: dict[str, Any]) -> None:
    """Fail unless the deployed planner is the approved local model on both the health probe and the
    persisted scan record."""

    if health.get("planner") != EXPECTED_PLANNER:
        raise DemoGuardError("PLANNER_NOT_LOCAL_LLM", f"health.planner={health.get('planner')!r}")
    scan = _scan(discovery)
    if scan.get("planner") != EXPECTED_PLANNER or scan.get("mode") != EXPECTED_PLANNER:
        raise DemoGuardError("PLANNER_NOT_LOCAL_LLM", "scan planner/mode is not LOCAL_LLM")


def assert_approved_model(discovery: dict[str, Any]) -> None:
    """Fail unless the recorded provider metadata is the approved Ollama model at the approved
    digest. A missing or mismatched digest is a hard stop, never a warning."""

    scan = _scan(discovery)
    if scan.get("model") != EXPECTED_MODEL:
        raise DemoGuardError("MODEL_NOT_APPROVED", f"scan.model={scan.get('model')!r}")
    metadata = scan.get("provider_metadata")
    if not isinstance(metadata, dict):
        raise DemoGuardError("PROVIDER_METADATA_MISSING", "no provider_metadata on scan")
    if metadata.get("runtime") != EXPECTED_PROVIDER_RUNTIME:
        raise DemoGuardError("PROVIDER_NOT_OLLAMA", f"runtime={metadata.get('runtime')!r}")
    if metadata.get("model") != EXPECTED_MODEL:
        raise DemoGuardError("MODEL_NOT_APPROVED", f"metadata.model={metadata.get('model')!r}")
    digest = metadata.get("model_digest")
    if not isinstance(digest, str) or not digest.startswith(EXPECTED_MODEL_DIGEST_PREFIX):
        raise DemoGuardError("MODEL_DIGEST_MISMATCH", f"digest={str(digest)[:16]!r}")


def assert_generation_parameters(discovery: dict[str, Any]) -> None:
    """Fail unless the recorded run used temperature 0, the recorded seed, the required context and
    the approved contract/execution-policy versions."""

    scan = _scan(discovery)
    if scan.get("planner_contract_version") != EXPECTED_CONTRACT_VERSION:
        raise DemoGuardError("CONTRACT_VERSION_MISMATCH", str(scan.get("planner_contract_version")))
    if scan.get("execution_policy_version") != EXPECTED_EXECUTION_POLICY_VERSION:
        raise DemoGuardError(
            "EXECUTION_POLICY_MISMATCH", str(scan.get("execution_policy_version"))
        )
    metadata = scan.get("provider_metadata")
    if not isinstance(metadata, dict):
        raise DemoGuardError("PROVIDER_METADATA_MISSING", "no provider_metadata on scan")
    if float(metadata.get("temperature", -1)) != EXPECTED_TEMPERATURE:
        raise DemoGuardError("TEMPERATURE_MISMATCH", str(metadata.get("temperature")))
    if int(metadata.get("seed", -1)) != EXPECTED_SEED:
        raise DemoGuardError("SEED_MISMATCH", str(metadata.get("seed")))
    if int(metadata.get("context_length", -1)) != EXPECTED_CONTEXT_LENGTH:
        raise DemoGuardError("CONTEXT_LENGTH_MISMATCH", str(metadata.get("context_length")))


def candidate_generation_record_id(discovery: dict[str, Any]) -> str:
    """Return a stable id for the model's candidate-generation decision, derived from the persisted
    audit event that carried the model's output. Its existence is proof the candidate came from a
    real provider call, not a hard-coded or injected value."""

    scan = _scan(discovery)
    scan_id = str(scan.get("id"))
    for event in _audit(discovery):
        if event.get("event") == "CANDIDATE_GENERATED":
            details = event.get("details", {})
            candidates = details.get("candidates", []) if isinstance(details, dict) else []
            if candidates:
                return f"gen-{scan_id}-{event.get('id')}"
    raise DemoGuardError(
        "CANDIDATE_NOT_MODEL_GENERATED", "no CANDIDATE_GENERATED audit carrying output"
    )


def assert_candidate_model_generated(discovery: dict[str, Any]) -> None:
    """Fail unless the candidate demonstrably originated from a real provider decision: provider
    metadata with a non-zero eval count, an enumeration request, a model-authored
    CANDIDATE_GENERATED event carrying at least one candidate, and a validated candidate."""

    scan = _scan(discovery)
    metadata = scan.get("provider_metadata")
    if not isinstance(metadata, dict):
        raise DemoGuardError("CANDIDATE_NOT_MODEL_GENERATED", "no provider_metadata")
    eval_count = metadata.get("eval_count")
    if not isinstance(eval_count, int) or eval_count <= 0:
        raise DemoGuardError("CANDIDATE_NOT_MODEL_GENERATED", f"eval_count={eval_count!r}")
    events = [event.get("event") for event in _audit(discovery)]
    if "CANDIDATE_GENERATION_REQUEST" not in events:
        raise DemoGuardError("CANDIDATE_NOT_MODEL_GENERATED", "no enumeration request in audit")
    # Its stable record id also proves a model-authored candidate exists.
    candidate_generation_record_id(discovery)
    if int(scan.get("generated_candidates_total", 0)) < 1:
        raise DemoGuardError("CANDIDATE_NOT_MODEL_GENERATED", "generated_candidates_total < 1")
    _validated_candidate(scan)


def assert_no_model_selection(discovery: dict[str, Any]) -> None:
    """Fail if any model-based candidate SELECTION call occurred: Phase 0.8 removed it, and the demo
    must show deterministic queue admission only."""

    for event in _audit(discovery):
        if event.get("event") == "CANDIDATE_SELECTION_REQUEST":
            raise DemoGuardError("MODEL_SELECTION_PRESENT", "a model-based selection call occurred")
    scan = _scan(discovery)
    record = _first_record(scan)
    if record.get("selection") is not None or record.get("selected_candidate_id") is not None:
        raise DemoGuardError("MODEL_SELECTION_PRESENT", "selection fields populated on record")
    if not record.get("queue"):
        raise DemoGuardError("NO_DETERMINISTIC_QUEUE", "no deterministic execution queue recorded")


def assert_read_only_in_scope(report: dict[str, Any]) -> None:
    """Fail unless every issued request is a read-only method against an approved account route."""

    scan = _scan(report)
    for item in scan.get("evidence", []):
        method = item.get("method")
        path = item.get("path")
        if method not in READ_ONLY_METHODS:
            raise DemoGuardError("NON_READ_ONLY_REQUEST", f"method={method!r}")
        if not isinstance(path, str) or "/accounts/" not in path:
            raise DemoGuardError("OUT_OF_SCOPE_REQUEST", f"path={path!r}")


def assert_response_sequence(report: dict[str, Any], expected: list[int | None]) -> None:
    """Fail unless the observed response codes exactly match the committed sequence."""

    observed = _status_codes(_scan(report))
    if observed != expected:
        raise DemoGuardError(
            "RESPONSE_SEQUENCE_MISMATCH", f"observed={observed} expected={expected}"
        )


def assert_verifier_finding(discovery: dict[str, Any]) -> None:
    """Fail unless the discovery finding is a deterministic-verifier HIGH/CONFIRMED BOLA finding
    bound to fresh 200 evidence, and the model authored no finding, severity or verdict."""

    scan = _scan(discovery)
    findings = scan.get("findings", [])
    if len(findings) != 1:
        raise DemoGuardError(
            "NO_VERIFIER_FINDING", f"expected exactly one finding, got {len(findings)}"
        )
    finding = findings[0]
    if finding.get("severity") != "HIGH" or finding.get("confidence") != "CONFIRMED":
        raise DemoGuardError("FINDING_NOT_HIGH_CONFIRMED", str(finding.get("severity")))
    evidence = {item.get("name"): item for item in scan.get("evidence", [])}
    names = finding.get("evidence_names", [])
    if not names:
        raise DemoGuardError("FINDING_EVIDENCE_UNBOUND", "finding has no evidence names")
    for name in names:
        # The verifier namespaces the evidence-derived id by scan. This binds provenance
        # deterministically while ensuring separate runs never reuse a finding identifier.
        if finding.get("id") != f"finding-{scan.get('id')}-{name}":
            raise DemoGuardError("FINDING_NOT_VERIFIER_CREATED", str(finding.get("id")))
        item = evidence.get(name)
        if not item or item.get("status_code") != 200 or item.get("error"):
            raise DemoGuardError("FINDING_EVIDENCE_UNBOUND", f"evidence {name} not a clean 200")
    verification = scan.get("verification") or {}
    if verification.get("status") != "CONFIRMED":
        raise DemoGuardError("VERIFICATION_NOT_CONFIRMED", str(verification.get("status")))


def probe_direction(discovery: dict[str, Any]) -> tuple[str, str]:
    """Return the confirmed cross-owner access DIRECTION as (credential_profile, object_id) from
    the discovery finding's bound probe evidence — the direction a faithful retest must repeat."""

    scan = _scan(discovery)
    evidence = {item.get("name"): item for item in scan.get("evidence", [])}
    findings = scan.get("findings") or []
    if not findings:
        raise DemoGuardError("NO_VERIFIER_FINDING", "no finding to derive a direction from")
    finding = findings[0]
    for name in finding.get("evidence_names", []):
        item = evidence.get(name)
        if item is None:
            continue
        path = str(item.get("path", ""))
        return str(item.get("credential_profile")), path.rsplit("/", 1)[-1]
    raise DemoGuardError("NO_VERIFIER_FINDING", "finding evidence not found")


def assert_candidate_matches_finding(discovery: dict[str, Any]) -> None:
    """Fail unless the model-proposed candidate the controller executed encodes the SAME direction
    the verifier confirmed. This is what lets the demo claim the AI proposed the confirmed
    hypothesis, rather than merely proposing something while the controller confirmed an unrelated
    direction."""

    candidate = _confirmed_candidate(_scan(discovery))
    profile, obj = probe_direction(discovery)
    if candidate.get("alternate_principal_ref") != profile or candidate.get("object_ref") != obj:
        raise DemoGuardError(
            "CANDIDATE_FINDING_DIRECTION_MISMATCH",
            f"candidate {candidate.get('alternate_principal_ref')}->{candidate.get('object_ref')} "
            f"!= finding {profile}->{obj}",
        )


def assert_linked_retest(discovery: dict[str, Any], retest: dict[str, Any]) -> None:
    """Fail unless the retest is the deterministic linked retest of THIS discovery: linked by id,
    controller-reconstructed (no model call), repeating the confirmed direction against the
    synthetic patched route, over fresh evidence, ending in a conservative PASS."""

    d_scan = _scan(discovery)
    r_scan = _scan(retest)
    if r_scan.get("retest_of") != d_scan.get("id"):
        raise DemoGuardError("RETEST_NOT_LINKED", f"retest_of={r_scan.get('retest_of')!r}")
    if r_scan.get("variant") != "patched":
        raise DemoGuardError("RETEST_NOT_PATCHED", str(r_scan.get("variant")))
    # No model re-planning: the linked retest is constructed deterministically from the finding.
    usage = r_scan.get("usage", {})
    if int(usage.get("model_calls", 0)) != 0:
        raise DemoGuardError("RETEST_USED_MODEL", f"model_calls={usage.get('model_calls')}")
    for event in _audit(retest):
        if event.get("event") in {"CANDIDATE_GENERATION_REQUEST", "CANDIDATE_SELECTION_REQUEST"}:
            raise DemoGuardError("RETEST_USED_MODEL", "retest issued a model call")
    # Fresh observations: retest evidence names must not reuse any discovery evidence name.
    d_names = {item.get("name") for item in d_scan.get("evidence", [])}
    r_names = {item.get("name") for item in r_scan.get("evidence", [])}
    if d_names & r_names:
        raise DemoGuardError("RETEST_EVIDENCE_STALE", "retest reused a discovery evidence name")
    # Same access direction against the synthetic patched route, now denied.
    profile, obj = probe_direction(discovery)
    denied = [
        item
        for item in r_scan.get("evidence", [])
        if item.get("credential_profile") == profile
        and str(item.get("path", "")).rsplit("/", 1)[-1] == obj
        and str(item.get("path", "")).startswith("/api/v1/patched/")
        and item.get("status_code") == 403
    ]
    if not denied:
        raise DemoGuardError(
            "RETEST_DIRECTION_MISMATCH", f"{profile} -> {obj} not denied on patched"
        )
    verification = r_scan.get("verification") or {}
    if r_scan.get("status") != "PASS" or verification.get("status") != "PASS":
        raise DemoGuardError("RETEST_NOT_PASS", str(r_scan.get("status")))


def assert_fresh_evidence(discovery: dict[str, Any], retest: dict[str, Any]) -> None:
    """Fail unless both scans carry unique-named evidence and the two runs share no observation
    (no stale-observation reuse across the linked pair)."""

    for report in (discovery, retest):
        names = [item.get("name") for item in _scan(report).get("evidence", [])]
        if len(names) != len(set(names)):
            raise DemoGuardError("DUPLICATE_EVIDENCE_NAME", "evidence names are not unique")
    d_names = {item.get("name") for item in _scan(discovery).get("evidence", [])}
    r_names = {item.get("name") for item in _scan(retest).get("evidence", [])}
    if d_names & r_names:
        raise DemoGuardError("EVIDENCE_STALE", "discovery and retest share an observation")


def distinguishes_routes(discovery: dict[str, Any], retest: dict[str, Any]) -> bool:
    """True when discovery probed the vulnerable route and the retest probed only the synthetic
    patched route — the honest vulnerable/patched distinction the demo must show."""

    d_paths = [str(item.get("path", "")) for item in _scan(discovery).get("evidence", [])]
    r_paths = [str(item.get("path", "")) for item in _scan(retest).get("evidence", [])]
    discovery_vulnerable = all("/patched/" not in p for p in d_paths) and bool(d_paths)
    retest_patched = all("/api/v1/patched/" in p for p in r_paths) and bool(r_paths)
    return discovery_vulnerable and retest_patched


def find_secret_markers(payload: Any) -> list[str]:
    """Return every secret/hidden-reasoning marker found in the JSON-serialized payload."""

    encoded = json.dumps(payload, default=str).lower()
    return [marker for marker in SECRET_MARKERS if marker.lower() in encoded]


def assert_no_secrets(payload: Any, code: str = "SECRET_LEAK") -> None:
    """Fail if any secret, balance, raw response body or hidden-reasoning marker is present."""

    hits = find_secret_markers(payload)
    if hits:
        raise DemoGuardError(code, f"markers={hits}")


# --- timeline (stable ids / actors / links for the Phase 1.0 operator console) -------------------


def build_timeline(
    report: dict[str, Any],
    *,
    finding_id: str | None = None,
    linked_retest_scan_id: str | None = None,
) -> list[dict[str, Any]]:
    """Project a scan's audit trail into stable, typed timeline events for downstream UIs: every
    event carries a stable id, timestamp, actor type and its scan link. No raw details/bodies are
    included — only the event name and a redacted evidence reference where one applies."""

    scan = _scan(report)
    scan_id = str(scan.get("id"))
    if finding_id is None:
        findings = scan.get("findings") or []
        finding_id = str(findings[0].get("id")) if findings and findings[0].get("id") else None
    retest_of_scan_id = scan.get("retest_of")
    finding_names = {n for f in scan.get("findings", []) for n in f.get("evidence_names", [])}
    timeline: list[dict[str, Any]] = []
    for event in _audit(report):
        name = str(event.get("event"))
        raw = event.get("details", {})
        details = raw if isinstance(raw, dict) else {}
        evidence_ref: dict[str, Any] | None = None
        if name == "OBSERVATION":
            evidence_ref = redacted_evidence_ref(details, scan_id)
        entry = {
            "event_id": event.get("event_id") or stable_event_id(scan_id, event.get("id")),
            "audit_id": event.get("id"),
            "scan_id": scan_id,
            "timestamp": event.get("timestamp") or event.get("created_at"),
            "actor_type": event.get("actor_type") or actor_for_event(name),
            # Kept as a compatibility alias for the already-created Phase 0.9 demo view.
            "actor": event.get("actor_type") or actor_for_event(name),
            "event": name,
            "finding_id": finding_id,
            "retest_of_scan_id": retest_of_scan_id,
            "linked_retest_scan_id": linked_retest_scan_id,
            "evidence_ref": evidence_ref,
            "confirms_finding": bool(
                name == "OBSERVATION" and details.get("name") in finding_names
            ),
        }
        timeline.append(entry)
    return timeline


# --- manifest + summary (Part C / Part E) --------------------------------------------------------


def _candidate_view(discovery: dict[str, Any]) -> dict[str, Any]:
    candidate = _confirmed_candidate(_scan(discovery))
    return {
        "capability": candidate.get("capability"),
        "operation_id": candidate.get("operation_id"),
        "owner_principal_ref": candidate.get("owner_principal_ref"),
        "alternate_principal_ref": candidate.get("alternate_principal_ref"),
        "object_ref": candidate.get("object_ref"),
        "expected_authorization_invariant": candidate.get("expected_authorization_invariant"),
        "approved_references": candidate.get("projected_context_refs", []),
    }


def _candidate_timestamp(discovery: dict[str, Any]) -> Any:
    for event in _audit(discovery):
        if event.get("event") == "CANDIDATE_GENERATED":
            return event.get("created_at")
    return None


EXECUTIVE_NARRATIVE = (
    "The local AI model analyzes a projected API surface and independently proposes an "
    "object-authorization attack hypothesis. A deterministic policy layer validates scope and "
    "safety, compiles approved read-only requests, and executes the test. A deterministic verifier "
    "confirms the result from fresh evidence. After remediation, the controller repeats the same "
    "access direction and verifies that the unauthorized request is denied."
)

DEMONSTRATION_DOES_NOT_PROVE = [
    "One read-only object-authorization (BOLA) capability against a synthetic lab route only.",
    "It is not production readiness and not a claim about any real application.",
    "It is not broad vulnerability coverage: exactly one capability is exercised.",
    "It is not unrestricted or autonomous pentesting: every request is deterministic, "
    "read-only, scoped and budgeted.",
    "The patched route is a synthetic remediation in the same lab, not an independently deployed "
    "fixed system.",
]


def validate_demo(
    health: dict[str, Any], discovery: dict[str, Any], retest: dict[str, Any]
) -> None:
    """Run every Phase 0.9 guard in order. Raises :class:`DemoGuardError` on the first violation, so
    a failing demo never produces a manifest."""

    assert_local_llm_planner(health, discovery)
    assert_approved_model(discovery)
    assert_generation_parameters(discovery)
    assert_candidate_model_generated(discovery)
    assert_no_model_selection(discovery)
    assert_read_only_in_scope(discovery)
    assert_read_only_in_scope(retest)
    assert_response_sequence(discovery, VULNERABLE_SEQUENCE)
    assert_response_sequence(retest, PATCHED_SEQUENCE)
    assert_verifier_finding(discovery)
    assert_candidate_matches_finding(discovery)
    assert_fresh_evidence(discovery, retest)
    assert_linked_retest(discovery, retest)
    if not distinguishes_routes(discovery, retest):
        raise DemoGuardError("ROUTES_NOT_DISTINGUISHED", "vulnerable/patched routes not distinct")


def build_manifest(
    run_id: str,
    timestamp: str,
    health: dict[str, Any],
    discovery: dict[str, Any],
    retest: dict[str, Any],
    environment: dict[str, Any],
) -> dict[str, Any]:
    """Build the structured Phase 0.9 manifest (Part C). Assumes :func:`validate_demo` has already
    passed. Contains no credentials, no raw response bodies and no model reasoning; every referenced
    identifier is stable and evidence-bound."""

    d_scan = _scan(discovery)
    r_scan = _scan(retest)
    metadata = d_scan.get("provider_metadata", {}) or {}
    findings = d_scan.get("findings") or [{}]
    finding = findings[0]
    finding_id = str(finding.get("id")) if finding.get("id") else None
    discovery_scan_id = str(d_scan.get("id"))
    retest_scan_id = str(r_scan.get("id"))
    profile, obj = probe_direction(discovery)

    manifest: dict[str, Any] = {
        "demo_run_id": run_id,
        "timestamp": timestamp,
        "phase": "0.9",
        "manifest_schema_version": 1,
        "synthetic_lab": True,
        "synthetic_lab_declaration": (
            "All targets are the synthetic Aegis lab (Synthetic Bank API). No real application, "
            "external host or production system is contacted. The patched route is a synthetic "
            "remediation in the same lab."
        ),
        "scope": ["SYNTHETIC LAB", "LOCAL LLM", "READ-ONLY", "AUTHORIZED TARGET"],
        "links": {
            "discovery_scan_id": discovery_scan_id,
            "finding_id": finding_id,
            "retest_scan_id": retest_scan_id,
            "retest_of_scan_id": r_scan.get("retest_of"),
        },
        "provider": {
            "provider_type": metadata.get("provider_type"),
            "runtime": metadata.get("runtime"),
            "runtime_version": metadata.get("runtime_version"),
            "model": d_scan.get("model"),
            "model_digest": metadata.get("model_digest"),
        },
        "generation": {
            "prompt_version": environment.get("prompt_version"),
            "planner_contract_version": d_scan.get("planner_contract_version"),
            "execution_policy_version": d_scan.get("execution_policy_version"),
            "temperature": metadata.get("temperature"),
            "seed": metadata.get("seed"),
            "context_length": metadata.get("context_length"),
        },
        "ai_contribution": {
            "role": "Proposed one bounded object-authorization hypothesis (a cross-owner access "
            "direction). The model saw no path, credential, response body, finding, severity or "
            "verdict.",
            "candidate_generation_record_id": candidate_generation_record_id(discovery),
            "candidate_timestamp": _candidate_timestamp(discovery),
            **_candidate_view(discovery),
        },
        "controller_contribution": {
            "candidate_validation": {
                "generated_total": d_scan.get("generated_candidates_total"),
                "validated_total": d_scan.get("validated_candidates_total"),
                "rejected_total": d_scan.get("rejected_candidates_total"),
            },
            "queue_admission": _first_record(d_scan).get("queue", []),
            "safety_authorization": "approve_plan (read-only, scoped, budgeted)",
            "request_compilation": "controller compiled typed read-only PlannedRequests",
            "scope_decision": "all requests within approved account route and read-only methods",
        },
        "discovery": {
            "scan_id": d_scan.get("id"),
            "scenario": d_scan.get("scenario"),
            "variant": d_scan.get("variant"),
            "target_request_ids": [
                stable_event_id(discovery_scan_id, item.get("name"))
                for item in d_scan.get("evidence", [])
            ],
            "response_codes": _status_codes(d_scan),
            "methods": _methods(d_scan),
            "evidence": [
                redacted_evidence_ref(i, discovery_scan_id) for i in d_scan.get("evidence", [])
            ],
            "confirmed_direction": {"principal": profile, "object": obj},
            "timeline": build_timeline(
                discovery, finding_id=finding_id, linked_retest_scan_id=retest_scan_id
            ),
        },
        "finding": {
            "id": finding.get("id"),
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "confidence": finding.get("confidence"),
            "category": finding.get("category"),
            "evidence_names": finding.get("evidence_names", []),
            "provenance": "Created by the deterministic verifier from fresh bound evidence. The AI "
            "did not create this finding.",
        },
        "retest": {
            "scan_id": r_scan.get("id"),
            "retest_of": r_scan.get("retest_of"),
            "variant": r_scan.get("variant"),
            "synthetic_patched_route": SYNTHETIC_PATCHED_ROUTE,
            "target_request_ids": [
                stable_event_id(retest_scan_id, item.get("name"))
                for item in r_scan.get("evidence", [])
            ],
            "response_codes": _status_codes(r_scan),
            "evidence": [
                redacted_evidence_ref(i, retest_scan_id) for i in r_scan.get("evidence", [])
            ],
            "reconstructed_direction": {"principal": profile, "object": obj},
            "model_replanning": False,
            "timeline": build_timeline(retest, finding_id=finding_id),
        },
        "final_status": {
            "discovery": d_scan.get("status"),
            "retest": r_scan.get("status"),
            "verdict": "GO"
            if d_scan.get("status") == "FAIL" and r_scan.get("status") == "PASS"
            else "NO-GO",
        },
        "usage": {
            "discovery": d_scan.get("usage", {}),
            "retest": r_scan.get("usage", {}),
            "provider_calls": {
                "discovery": (d_scan.get("usage", {}) or {}).get("model_calls"),
                "retest": (r_scan.get("usage", {}) or {}).get("model_calls"),
            },
        },
        "budgets": {
            "max_requests_per_scan": environment.get("max_requests_per_scan"),
            "max_iterations": environment.get("max_iterations"),
            "max_model_calls": environment.get("max_model_calls"),
            "scan_timeout_seconds": environment.get("scan_timeout_seconds"),
        },
        "checks": {
            "topology_test_result": environment.get("topology_test_result"),
            "secret_scan_result": None,  # filled in below after self-scan
            "routes_distinguished": distinguishes_routes(discovery, retest),
        },
        "executive_narrative": EXECUTIVE_NARRATIVE,
        "does_not_prove": DEMONSTRATION_DOES_NOT_PROVE,
        "environment": {
            "ollama_version": metadata.get("runtime_version"),
            "compose_project": environment.get("compose_project"),
            "dashboard_url": environment.get("dashboard_url"),
        },
    }

    # Self-scan: the manifest must contain no secret, balance, body or hidden-reasoning marker.
    assert_no_secrets(manifest, code="MANIFEST_SECRET_LEAK")
    manifest["checks"]["secret_scan_result"] = "CLEAN"  # noqa: S105 - status label, not a secret
    return manifest


def build_summary_markdown(manifest: dict[str, Any]) -> str:
    """Render the management-readable Markdown summary (Part C/E). It exposes no credentials, no raw
    response bodies and no hidden reasoning — only stable identifiers and observed status codes."""

    ai = manifest["ai_contribution"]
    finding = manifest["finding"]
    discovery = manifest["discovery"]
    retest = manifest["retest"]
    provider = manifest["provider"]
    lines: list[str] = []
    lines.append(f"# Aegis Phase 0.9 — Management Demo `{manifest['demo_run_id']}`")
    lines.append("")
    lines.append(f"_{manifest['timestamp']}_")
    lines.append("")
    lines.append("**Scope:** " + " · ".join(manifest["scope"]))
    lines.append("")
    lines.append("## Executive narrative")
    lines.append("")
    lines.append(manifest["executive_narrative"])
    lines.append("")
    lines.append("## What the AI did (and only this)")
    lines.append("")
    lines.append(
        f"- Proposed capability: `{ai['capability']}` (candidate record "
        f"`{ai['candidate_generation_record_id']}`, {ai['candidate_timestamp']})"
    )
    lines.append(f"- Operation reference: `{ai['operation_id']}`")
    lines.append(
        f"- Principal relationship: `{ai['alternate_principal_ref']}` attempts to read an object "
        f"owned by `{ai['owner_principal_ref']}`"
    )
    lines.append(f"- Object reference: `{ai['object_ref']}`")
    lines.append("")
    lines.append(
        "The model never saw or produced a path, credential, response body, finding, severity or "
        "verdict."
    )
    lines.append("")
    lines.append("## What the deterministic controller did")
    lines.append("")
    controller = manifest["controller_contribution"]
    validation = controller["candidate_validation"]
    lines.append(
        f"- Validated the candidate ({validation['validated_total']} of "
        f"{validation['generated_total']} generated) and admitted it to a deterministic execution "
        "queue (no model-based selection)."
    )
    lines.append("- Authorized and compiled typed read-only requests within scope and budget.")
    lines.append(
        "- Ran the model exactly once for discovery; the linked retest used "
        f"{manifest['usage']['provider_calls']['retest']} model calls (deterministic "
        "reconstruction)."
    )
    lines.append("")
    lines.append("## Evidence sequence")
    lines.append("")
    lines.append("| Stage | Route | Observed responses | Result |")
    lines.append("| --- | --- | --- | --- |")
    lines.append(
        f"| Discovery (vulnerable) | `{VULNERABLE_ROUTE}` | "
        f"{' / '.join(str(c) for c in discovery['response_codes'])} | "
        f"{finding['severity']}/{finding['confidence']} BOLA |"
    )
    lines.append(
        f"| Linked retest (synthetic patched) | `{SYNTHETIC_PATCHED_ROUTE}` | "
        f"{' / '.join(str(c) for c in retest['response_codes'])} | "
        f"remediation {manifest['final_status']['retest']} |"
    )
    lines.append("")
    lines.append("## Finding provenance")
    lines.append("")
    lines.append(f"- {finding['provenance']}")
    lines.append(
        f"- Finding `{finding['id']}` ({finding['category']}) is bound to fresh evidence "
        f"{finding['evidence_names']}."
    )
    lines.append("")
    lines.append("## Verification")
    lines.append("")
    lines.append(
        f"- Provider: `{provider['model']}` on `{provider['runtime']}` "
        f"{provider['runtime_version']} (digest `{str(provider['model_digest'])[:16]}…`)"
    )
    lines.append(
        f"- Deterministic settings: temperature {manifest['generation']['temperature']}, seed "
        f"{manifest['generation']['seed']}, context {manifest['generation']['context_length']}, "
        f"contract v{manifest['generation']['planner_contract_version']}, execution policy v"
        f"{manifest['generation']['execution_policy_version']}"
    )
    lines.append(f"- Topology test: {manifest['checks']['topology_test_result']}")
    lines.append(f"- Secret scan: {manifest['checks']['secret_scan_result']}")
    lines.append("")
    lines.append("## What this demonstration does NOT prove")
    lines.append("")
    for item in manifest["does_not_prove"]:
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)
