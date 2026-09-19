"""Phase 0.9 proofs (docs/phase-0.9, Part G).

These tests pin the reproducible management demo's guarantees over synthetic scan JSON, offline and
with no model, target or network activity. They assert the guards fail closed and that the demo can
never (a) run in heuristic mode, (b) accept an unapproved model/digest, (c) accept a candidate that
did not come from a real provider decision, (d) present a finding the deterministic verifier did not
create, (e) accept a linked retest that does not repeat the confirmed direction over fresh evidence,
(f) blur the vulnerable/patched routes, (g) overwrite prior evidence, (h) leak a secret or hidden
reasoning, (i) overstate capability, or (j) label a controller/verifier action as the AI's.
"""

from pathlib import Path
from typing import Any

import pytest

from aegis import demo

ROOT = Path(__file__).resolve().parent.parent


def _discovery() -> dict[str, Any]:
    candidate = {
        "capability": "bola_object_read_v1",
        "operation_id": "getAccount",
        "owner_principal_ref": "user_b",
        "alternate_principal_ref": "user_a",
        "object_ref": "B-200",
        "expected_authorization_invariant": "user_a must not read user_b's account",
        "projected_context_refs": ["getAccount", "B-200", "user_a", "user_b"],
    }
    return {
        "scan": {
            "id": "scan-aaaaaaaaaaaa",
            "planner": "LOCAL_LLM",
            "mode": "LOCAL_LLM",
            "model": "qwen3:8b",
            "provider_metadata": {
                "provider_type": "local_llm",
                "runtime": "ollama",
                "runtime_version": "0.34.2",
                "model": "qwen3:8b",
                "model_digest": "500a1f067a9f7826abc",
                "context_length": 8192,
                "temperature": 0.0,
                "seed": 42,
                "eval_count": 128,
            },
            "planner_contract_version": 3,
            "execution_policy_version": 1,
            "scenario": "positive_vulnerable",
            "variant": "vulnerable",
            "status": "FAIL",
            "generated_candidates_total": 1,
            "validated_candidates_total": 1,
            "rejected_candidates_total": 0,
            "candidate_records": [
                {
                    "stage": "discovery",
                    "generated": 1,
                    "validated_candidates": [{"candidate_id": "cand-001", "candidate": candidate}],
                    "queue": [
                        {"candidate_id": "cand-001", "order_index": 0, "admitted": True,
                         "reason": "ADMITTED"}
                    ],
                    "selection": None,
                    "selected_candidate_id": None,
                }
            ],
            "evidence": [
                {"name": "cand-001-01-control-user_a", "method": "GET",
                 "path": "/api/v1/accounts/A-100", "credential_profile": "user_a",
                 "status_code": 200, "error": None},
                {"name": "cand-001-01-control-user_b", "method": "GET",
                 "path": "/api/v1/accounts/B-200", "credential_profile": "user_b",
                 "status_code": 200, "error": None},
                {"name": "cand-001-01-probe-user_a-B-200", "method": "GET",
                 "path": "/api/v1/accounts/B-200", "credential_profile": "user_a",
                 "status_code": 200, "error": None},
            ],
            "findings": [
                {"id": "finding-scan-aaaaaaaaaaaa-cand-001-01-probe-user_a-B-200",
                 "title": "Broken Object Level Authorization in account lookup",
                 "severity": "HIGH", "category": "API1:2023 BOLA", "confidence": "CONFIRMED",
                 "description": "cross-owner read", "remediation": "enforce ownership",
                 "evidence_names": ["cand-001-01-probe-user_a-B-200"]}
            ],
            "verification": {"status": "CONFIRMED", "summary": "confirmed",
                             "evidence_names": ["cand-001-01-probe-user_a-B-200"]},
            "usage": {"requests": 4, "iterations": 1, "model_calls": 1},
        },
        "audit": [
            {"id": 1, "event": "CANDIDATE_GENERATION_REQUEST", "created_at": "2026-09-18T00:00:01",
             "details": {}},
            {"id": 2, "event": "CANDIDATE_GENERATED", "created_at": "2026-09-18T00:00:02",
             "details": {"candidates": [candidate]}},
            {"id": 3, "event": "OBSERVATION", "created_at": "2026-09-18T00:00:03",
             "details": {"name": "cand-001-01-probe-user_a-B-200"}},
            {"id": 4, "event": "VERIFIER_RESULT", "created_at": "2026-09-18T00:00:04",
             "details": {"status": "CONFIRMED"}},
        ],
    }


def _retest() -> dict[str, Any]:
    return {
        "scan": {
            "id": "scan-bbbbbbbbbbbb",
            "planner": "LOCAL_LLM",
            "mode": "LOCAL_LLM",
            "model": "qwen3:8b",
            "retest_of": "scan-aaaaaaaaaaaa",
            "variant": "patched",
            "status": "PASS",
            "usage": {"requests": 4, "iterations": 1, "model_calls": 0},
            "evidence": [
                {"name": "rt-01-control-user_a", "method": "GET",
                 "path": "/api/v1/patched/accounts/A-100", "credential_profile": "user_a",
                 "status_code": 200, "error": None},
                {"name": "rt-01-control-user_b", "method": "GET",
                 "path": "/api/v1/patched/accounts/B-200", "credential_profile": "user_b",
                 "status_code": 200, "error": None},
                {"name": "rt-01-probe-user_a-B-200", "method": "GET",
                 "path": "/api/v1/patched/accounts/B-200", "credential_profile": "user_a",
                 "status_code": 403, "error": None},
            ],
            "verification": {"status": "PASS", "summary": "denied"},
        },
        "audit": [
            {"id": 1, "event": "RETEST_PLAN", "created_at": "2026-09-18T00:01:01", "details": {}},
            {"id": 2, "event": "OBSERVATION", "created_at": "2026-09-18T00:01:02",
             "details": {"name": "rt-01-probe-user_a-B-200"}},
            {"id": 3, "event": "VERIFIER_RESULT", "created_at": "2026-09-18T00:01:03",
             "details": {"status": "PASS"}},
        ],
    }


HEALTH = {"status": "ok", "planner": "LOCAL_LLM"}


def test_happy_path_validates_and_builds_manifest() -> None:
    d, r = _discovery(), _retest()
    demo.validate_demo(HEALTH, d, r)
    manifest = demo.build_manifest("demo-x", "2026-09-18T00:00:00Z", HEALTH, d, r, {})
    assert manifest["final_status"]["verdict"] == "GO"
    assert manifest["finding"]["severity"] == "HIGH"
    assert manifest["discovery"]["response_codes"] == [200, 200, 200]
    assert manifest["retest"]["response_codes"] == [200, 200, 403]
    assert manifest["checks"]["secret_scan_result"] == "CLEAN"  # noqa: S105


def test_demo_cannot_use_heuristic_mode() -> None:
    d = _discovery()
    d["scan"]["planner"] = "DEMO_HEURISTIC"
    d["scan"]["mode"] = "DEMO_HEURISTIC"
    with pytest.raises(demo.DemoGuardError) as exc:
        demo.assert_local_llm_planner(HEALTH, d)
    assert exc.value.code == "PLANNER_NOT_LOCAL_LLM"
    with pytest.raises(demo.DemoGuardError):
        demo.assert_local_llm_planner({"planner": "DEMO_HEURISTIC"}, _discovery())


def test_demo_rejects_unapproved_model() -> None:
    d = _discovery()
    d["scan"]["model"] = "qwen3:4b"
    d["scan"]["provider_metadata"]["model"] = "qwen3:4b"
    with pytest.raises(demo.DemoGuardError) as exc:
        demo.assert_approved_model(d)
    assert exc.value.code == "MODEL_NOT_APPROVED"


def test_demo_rejects_wrong_digest() -> None:
    d = _discovery()
    d["scan"]["provider_metadata"]["model_digest"] = "deadbeefdeadbeef"
    with pytest.raises(demo.DemoGuardError) as exc:
        demo.assert_approved_model(d)
    assert exc.value.code == "MODEL_DIGEST_MISMATCH"


def test_generation_parameters_pinned() -> None:
    demo.assert_generation_parameters(_discovery())
    for field, bad in [("temperature", 0.7), ("seed", 7), ("context_length", 4096)]:
        d = _discovery()
        d["scan"]["provider_metadata"][field] = bad
        with pytest.raises(demo.DemoGuardError):
            demo.assert_generation_parameters(d)


def test_candidate_must_come_from_provider_decision() -> None:
    # No provider metadata -> not model-generated.
    d = _discovery()
    d["scan"]["provider_metadata"] = None
    with pytest.raises(demo.DemoGuardError) as exc:
        demo.assert_candidate_model_generated(d)
    assert exc.value.code == "CANDIDATE_NOT_MODEL_GENERATED"
    # Zero eval count -> not a real generation.
    d = _discovery()
    d["scan"]["provider_metadata"]["eval_count"] = 0
    with pytest.raises(demo.DemoGuardError):
        demo.assert_candidate_model_generated(d)
    # No CANDIDATE_GENERATED audit carrying output -> injected/hard-coded candidate.
    d = _discovery()
    d["audit"] = [e for e in d["audit"] if e["event"] != "CANDIDATE_GENERATED"]
    with pytest.raises(demo.DemoGuardError):
        demo.assert_candidate_model_generated(d)


def test_findings_only_from_deterministic_verifier() -> None:
    demo.assert_verifier_finding(_discovery())
    # A finding id not namespaced by its scan and derived from evidence cannot be verifier-created.
    d = _discovery()
    d["scan"]["findings"][0]["id"] = "finding-model-asserted"
    with pytest.raises(demo.DemoGuardError) as exc:
        demo.assert_verifier_finding(d)
    assert exc.value.code == "FINDING_NOT_VERIFIER_CREATED"
    # A non-CONFIRMED / non-HIGH finding is rejected.
    d = _discovery()
    d["scan"]["findings"][0]["confidence"] = "PROBABLE"
    with pytest.raises(demo.DemoGuardError):
        demo.assert_verifier_finding(d)


def test_linked_retest_repeats_confirmed_direction() -> None:
    demo.assert_linked_retest(_discovery(), _retest())
    # Wrong link.
    r = _retest()
    r["scan"]["retest_of"] = "scan-cccccccccccc"
    with pytest.raises(demo.DemoGuardError) as exc:
        demo.assert_linked_retest(_discovery(), r)
    assert exc.value.code == "RETEST_NOT_LINKED"
    # Different direction (probe by the owner, not the confirmed alternate principal).
    r = _retest()
    r["scan"]["evidence"][2]["credential_profile"] = "user_b"
    with pytest.raises(demo.DemoGuardError) as exc:
        demo.assert_linked_retest(_discovery(), r)
    assert exc.value.code == "RETEST_DIRECTION_MISMATCH"


def test_linked_retest_must_not_use_the_model() -> None:
    r = _retest()
    r["scan"]["usage"]["model_calls"] = 1
    with pytest.raises(demo.DemoGuardError) as exc:
        demo.assert_linked_retest(_discovery(), r)
    assert exc.value.code == "RETEST_USED_MODEL"
    r = _retest()
    r["audit"].append({"id": 9, "event": "CANDIDATE_GENERATION_REQUEST",
                       "created_at": "x", "details": {}})
    with pytest.raises(demo.DemoGuardError):
        demo.assert_linked_retest(_discovery(), r)


def test_linked_retest_uses_fresh_observations() -> None:
    demo.assert_fresh_evidence(_discovery(), _retest())
    r = _retest()
    r["scan"]["evidence"][0]["name"] = "cand-001-01-control-user_a"  # reuse a discovery name
    with pytest.raises(demo.DemoGuardError) as exc:
        demo.assert_fresh_evidence(_discovery(), r)
    assert exc.value.code == "EVIDENCE_STALE"


def test_synthetic_patched_and_vulnerable_routes_distinguished() -> None:
    assert demo.distinguishes_routes(_discovery(), _retest()) is True
    # If the retest hit the vulnerable route, the distinction collapses.
    r = _retest()
    for item in r["scan"]["evidence"]:
        item["path"] = item["path"].replace("/patched", "")
    assert demo.distinguishes_routes(_discovery(), r) is False


def test_response_sequences_are_exact() -> None:
    demo.assert_response_sequence(_discovery(), demo.VULNERABLE_SEQUENCE)
    demo.assert_response_sequence(_retest(), demo.PATCHED_SEQUENCE)
    d = _discovery()
    d["scan"]["evidence"][2]["status_code"] = 403
    with pytest.raises(demo.DemoGuardError) as exc:
        demo.assert_response_sequence(d, demo.VULNERABLE_SEQUENCE)
    assert exc.value.code == "RESPONSE_SEQUENCE_MISMATCH"


def test_scope_enforced_read_only() -> None:
    d = _discovery()
    d["scan"]["evidence"][0]["method"] = "DELETE"
    with pytest.raises(demo.DemoGuardError) as exc:
        demo.assert_read_only_in_scope(d)
    assert exc.value.code == "NON_READ_ONLY_REQUEST"


def test_secrets_and_hidden_reasoning_never_enter_manifest() -> None:
    assert demo.find_secret_markers({"x": "lab-token-user-a"}) == ["lab-token"]
    assert demo.find_secret_markers({"m": "<think>secret plan</think>"})
    d = _retest()  # a report smuggling hidden reasoning into an audit detail
    d["audit"][0]["details"] = {"reasoning_content": "step by step"}
    with pytest.raises(demo.DemoGuardError):
        demo.assert_no_secrets(demo.build_timeline(d) + [d["audit"][0]["details"]])
    # A clean manifest is marker-free.
    manifest = demo.build_manifest("demo-x", "t", HEALTH, _discovery(), _retest(), {})
    assert demo.find_secret_markers(manifest) == []


def test_manifest_and_summary_do_not_overstate_capability() -> None:
    manifest = demo.build_manifest("demo-x", "t", HEALTH, _discovery(), _retest(), {})
    summary = demo.build_summary_markdown(manifest).lower()
    assert "does not prove" in summary
    assert "not production readiness" in summary
    assert "synthetic" in summary
    assert len(manifest["does_not_prove"]) >= 4
    # No absolute/overreaching capability claims.
    banned = ("fully autonomous", "production ready", "complete coverage", "any vulnerability")
    for phrase in banned:
        assert phrase not in summary


def test_controller_actions_are_not_labeled_ai() -> None:
    assert demo.actor_for_event("CANDIDATE_GENERATED") == demo.ACTOR_AI_MODEL
    # Everything the controller/verifier/safety does must NOT be attributed to the model.
    for event in ("EXECUTION_QUEUE", "CANDIDATE_VALIDATION", "OBSERVATION", "REQUEST_STARTED",
                  "RETEST_PLAN", "TERMINAL_REASON", "SCAN_COMPLETED"):
        assert demo.actor_for_event(event) == demo.ACTOR_CONTROLLER
    assert demo.actor_for_event("VERIFIER_RESULT") == demo.ACTOR_VERIFIER
    assert demo.actor_for_event("SAFETY_APPROVED") == demo.ACTOR_SAFETY
    # An unknown event defaults to CONTROLLER, never to the AI.
    assert demo.actor_for_event("SOMETHING_NEW") == demo.ACTOR_CONTROLLER


def test_timeline_events_have_stable_ids_actors_and_links() -> None:
    timeline = demo.build_timeline(_discovery())
    assert timeline[0]["event_id"] == "scan-aaaaaaaaaaaa:1"
    assert all(e["scan_id"] == "scan-aaaaaaaaaaaa" for e in timeline)
    assert all(e["timestamp"] for e in timeline)
    gen = next(e for e in timeline if e["event"] == "CANDIDATE_GENERATED")
    assert gen["actor"] == demo.ACTOR_AI_MODEL
    assert gen["actor_type"] == demo.ACTOR_AI_MODEL
    assert gen["finding_id"] == "finding-scan-aaaaaaaaaaaa-cand-001-01-probe-user_a-B-200"
    obs = next(e for e in timeline if e["event"] == "OBSERVATION")
    assert obs["confirms_finding"] is True
    assert obs["evidence_ref"]["evidence_id"].startswith("scan-aaaaaaaaaaaa:")
    # Redacted evidence reference carries no response body.
    assert "response_excerpt" not in (obs["evidence_ref"] or {})
    assert "error" not in (obs["evidence_ref"] or {})


def test_manifest_has_stable_scan_finding_and_retest_links() -> None:
    manifest = demo.build_manifest("demo-x", "t", HEALTH, _discovery(), _retest(), {})
    assert manifest["manifest_schema_version"] == 1
    assert manifest["links"] == {
        "discovery_scan_id": "scan-aaaaaaaaaaaa",
        "finding_id": "finding-scan-aaaaaaaaaaaa-cand-001-01-probe-user_a-B-200",
        "retest_scan_id": "scan-bbbbbbbbbbbb",
        "retest_of_scan_id": "scan-aaaaaaaaaaaa",
    }
    assert manifest["discovery"]["target_request_ids"] == [
        "scan-aaaaaaaaaaaa:cand-001-01-control-user_a",
        "scan-aaaaaaaaaaaa:cand-001-01-control-user_b",
        "scan-aaaaaaaaaaaa:cand-001-01-probe-user_a-B-200",
    ]
    assert manifest["retest"]["target_request_ids"] == [
        "scan-bbbbbbbbbbbb:rt-01-control-user_a",
        "scan-bbbbbbbbbbbb:rt-01-control-user_b",
        "scan-bbbbbbbbbbbb:rt-01-probe-user_a-B-200",
    ]
    assert all(
        event["linked_retest_scan_id"] == "scan-bbbbbbbbbbbb"
        for event in manifest["discovery"]["timeline"]
    )
    assert all(
        event["retest_of_scan_id"] == "scan-aaaaaaaaaaaa"
        for event in manifest["retest"]["timeline"]
    )
    assert all(
        event["finding_id"]
        == "finding-scan-aaaaaaaaaaaa-cand-001-01-probe-user_a-B-200"
        for event in manifest["retest"]["timeline"]
    )


def test_phase_1_operator_console_is_documented_but_deferred() -> None:
    backlog = " ".join(
        (ROOT / "docs" / "phase-1.0-operator-console.md").read_text().lower().split()
    )
    for phrase in (
        "aegis operator console",
        "live mission control",
        "structured audit explorer",
        "sse",
        "visual evidence replay",
        "safe api evidence cards",
        "playwright",
        "screenshot hashing",
        "redaction",
        "retention",
        "size limits",
        "management-oriented finding summaries",
        "synthetic lab",
        "read-only",
    ):
        assert phrase in backlog
    assert "no frontend redesign or migration is part of phase 0.9" in backlog


def test_manifest_surfaces_executed_candidate_direction() -> None:
    # The model proposes two valid candidates; the controller executes cand-002. The AI-contribution
    # view and the direction guard must both reflect cand-002 (the confirmed one), not cand-001.
    d = _discovery()
    other = {
        "capability": "bola_object_read_v1", "operation_id": "getAccount",
        "owner_principal_ref": "user_a", "alternate_principal_ref": "user_b", "object_ref": "A-100",
        "expected_authorization_invariant": "user_b must not read user_a's account",
        "projected_context_refs": ["getAccount", "A-100", "user_a", "user_b"],
    }
    record = d["scan"]["candidate_records"][0]
    record["validated_candidates"] = [
        {"candidate_id": "cand-001", "candidate": other},
        {"candidate_id": "cand-002", "candidate": record["validated_candidates"][0]["candidate"]},
    ]
    d["scan"]["selected_candidate_id"] = "cand-002"
    d["scan"]["executed_candidate_ids"] = ["cand-002"]
    demo.assert_candidate_matches_finding(d)
    manifest = demo.build_manifest("demo-x", "t", HEALTH, d, _retest(), {})
    assert manifest["ai_contribution"]["object_ref"] == "B-200"
    assert manifest["ai_contribution"]["alternate_principal_ref"] == "user_a"


def test_candidate_finding_direction_mismatch_fails() -> None:
    d = _discovery()
    candidate = d["scan"]["candidate_records"][0]["validated_candidates"][0]["candidate"]
    candidate["object_ref"] = "A-100"
    with pytest.raises(demo.DemoGuardError) as exc:
        demo.assert_candidate_matches_finding(d)
    assert exc.value.code == "CANDIDATE_FINDING_DIRECTION_MISMATCH"


def test_no_model_based_selection_in_flow() -> None:
    demo.assert_no_model_selection(_discovery())
    d = _discovery()
    d["scan"]["candidate_records"][0]["selected_candidate_id"] = "cand-001"
    with pytest.raises(demo.DemoGuardError) as exc:
        demo.assert_no_model_selection(d)
    assert exc.value.code == "MODEL_SELECTION_PRESENT"


def test_runner_refuses_to_overwrite_prior_evidence(tmp_path: Path) -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "demo_runner", ROOT / "scripts" / "demo_runner.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    target = tmp_path / "phase-0.9-demo-x.json"
    module.write_with_checksum(target, "first\n")
    assert target.exists()
    assert target.with_suffix(".json.sha256").exists()
    with pytest.raises(SystemExit) as exc:
        module.write_with_checksum(target, "second\n")
    assert "DEMO_EVIDENCE_EXISTS" in str(exc.value)


def test_cleanup_is_project_scoped() -> None:
    script = (ROOT / "scripts" / "run_management_demo.sh").read_text()
    # Cleanup and teardown always target the named project, never a bare `docker compose down`.
    assert 'PROJECT="aegis-management-demo"' in script
    for line in script.splitlines():
        stripped = line.strip()
        if "down" in stripped and stripped.startswith("docker compose"):
            assert "-p \"$PROJECT\"" in stripped or '-p "$PROJECT"' in stripped
    # No blanket prune/rm of unrelated resources.
    assert "docker system prune" not in script
    assert "docker rm -f $(docker ps" not in script
