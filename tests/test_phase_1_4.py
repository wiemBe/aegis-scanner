"""Phase 1.4 offline controls. Live qwen3:8b acceptance is a separate evidence run."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from fastapi import FastAPI, Header, HTTPException

from aegis.beast.contracts import (
    BEAST_PROFILE_ID,
    BeastRunRequest,
    CommandResult,
    LeaseRequest,
    ResourceEnvelope,
)
from aegis.beast.controller import BeastController, BeastRejected
from aegis.beast.store import BeastStore
from aegis.settings import Settings
from lab_api.main import app as lab_app


class Harness:
    def __init__(self, *, destroy_success: bool = True) -> None:
        self.gateway = FastAPI()
        self.sandbox = FastAPI()
        self.commands: list[dict[str, Any]] = []
        self.destroyed: set[str] = set()
        self.destroy_success = destroy_success
        self._routes()

    def _routes(self) -> None:
        @self.gateway.post("/v1/beast/decide")
        async def decide(body: dict[str, Any]) -> dict[str, Any]:
            observations = body["observations"]
            sequence = body["sequence"]
            if sequence == 1:
                decision = {
                    "decision_type": "command",
                    "hypothesis": "The owner object provides a useful authorization control.",
                    "expected_intent": "Read synthetic user A's own object as a control.",
                    "command_text": (
                        "curl -s -H 'Authorization: Bearer lab-token-user-a' "
                        '"$BEAST_TARGET$BEAST_TARGET_BASE_PATH/accounts/A-100"'
                    ),
                }
            elif sequence == 2:
                decision = {
                    "decision_type": "command",
                    "hypothesis": "A cross-owner object read may lack an ownership check.",
                    "expected_intent": "Read a synthetic user B object as synthetic user A.",
                    "command_text": (
                        'payload="B-200"; curl -s -H \'Authorization: Bearer '
                        "lab-token-user-a' "
                        '"$BEAST_TARGET$BEAST_TARGET_BASE_PATH/accounts/$payload"'
                    ),
                }
            else:
                decision = {
                    "decision_type": "stop",
                    "hypothesis": "The direct response is sufficient for independent verification.",
                    "summary": "Stop after observing the cross-owner response.",
                    "evidence_observation_ids": [observations[-1]["observation_id"]],
                }
            return {
                "model": "qwen3:8b",
                "decision": decision,
                "usage": {"input_tokens": 30, "output_tokens": 12, "total_tokens": 42},
                "metadata": {
                    "provider_type": "ollama",
                    "runtime": "ollama",
                    "runtime_version": "test",
                    "model": "qwen3:8b",
                    "model_digest": "sha256:test",
                    "context_length": 8192,
                    "temperature": 0,
                    "seed": 42,
                    "prompt_eval_count": 30,
                    "eval_count": 12,
                    "total_duration_ms": 10,
                    "stop_reason": "stop",
                },
            }

        def authorized(token: str | None) -> None:
            if token != "test-supervisor-token":  # noqa: S105 - synthetic test token
                raise HTTPException(status_code=403)

        @self.sandbox.post("/v1/sessions")
        async def session(
            body: dict[str, Any], x_beast_supervisor_token: str | None = Header(default=None)
        ) -> dict[str, Any]:
            authorized(x_beast_supervisor_token)
            return {
                "run_id": body["run_id"],
                "sandbox_instance_id": "sandbox-test",
                "workspace_reference": f"workspace:{body['run_id']}",
                "ready": True,
            }

        @self.sandbox.post("/v1/commands")
        async def command(
            body: dict[str, Any], x_beast_supervisor_token: str | None = Header(default=None)
        ) -> dict[str, Any]:
            authorized(x_beast_supervisor_token)
            self.commands.append(copy.deepcopy(body))
            if body["sequence"] == 1:
                output = '{"account_id":"A-100","owner_id":"user-a","balance":1234.5}'
            else:
                output = '{"account_id":"B-200","owner_id":"user-b","balance":9875.5}'
            return CommandResult(
                command_id=body["command_id"],
                exit_code=0,
                timed_out=False,
                terminated=False,
                duration_ms=4,
                stdout=output,
                stderr="",
                output_truncated=False,
                artifact_references=[],
                resource_usage={"target_connections": body["sequence"]},
                network_destinations=["beast-target:8080"],
            ).model_dump(mode="json")

        @self.sandbox.post("/v1/runs/{run_id}/destroy")
        async def destroy(
            run_id: str, x_beast_supervisor_token: str | None = Header(default=None)
        ) -> dict[str, Any]:
            authorized(x_beast_supervisor_token)
            self.destroyed.add(run_id)
            return {"run_id": run_id, "destroyed": self.destroy_success, "artifacts": []}

        @self.sandbox.post("/v1/runs/{run_id}/stop")
        async def stop(
            run_id: str, x_beast_supervisor_token: str | None = Header(default=None)
        ) -> dict[str, Any]:
            authorized(x_beast_supervisor_token)
            return {"run_id": run_id, "process_tree_killed": True}


def controller(tmp_path: Path, harness: Harness, **overrides: Any) -> BeastController:
    values: dict[str, Any] = {
        "database_path": str(tmp_path / "beast.db"),
        "ai_provider": "ollama",
        "ai_model": "qwen3:8b",
        "beast_enabled": True,
        "beast_supervisor_token": "test-supervisor-token",
    }
    values.update(overrides)
    settings = Settings(**values)
    store = BeastStore(settings.database_path)
    store.initialize()
    return BeastController(
        settings,
        store,
        gateway_transport=httpx.ASGITransport(app=harness.gateway),
        sandbox_transport=httpx.ASGITransport(app=harness.sandbox),
        verifier_transport=httpx.ASGITransport(app=lab_app),
    )


def lease_request(**overrides: Any) -> LeaseRequest:
    values = {
        "operator_id": "operator-1",
        "actor_type": "OPERATOR",
        "target_ref": "beast-synthetic-vulnerable",
        "profile_id": BEAST_PROFILE_ID,
        "confirmation": "BEAST Disposable Synthetic Bank Adversary Target",
    }
    values.update(overrides)
    return LeaseRequest(**values)


def test_activation_is_operator_only_exact_and_synthetic(tmp_path: Path) -> None:
    harness = Harness()
    beast = controller(tmp_path, harness)
    preflight = beast.preflight("beast-synthetic-vulnerable")
    assert preflight.target.environment == "SYNTHETIC_LAB"
    assert preflight.technical_subtitle == "Disposable AI Adversary Sandbox"
    assert preflight.automatic_expiry_seconds <= 900
    with pytest.raises(BeastRejected, match="ACTIVATION_PHRASE_MISMATCH"):
        beast.issue_lease(lease_request(confirmation="BEAST wrong"))
    with pytest.raises(BeastRejected, match="TARGET_NOT_IN_CONTROLLER_INVENTORY"):
        beast.preflight("https://public.example")
    with pytest.raises(BeastRejected, match="BEAST_REQUIRES_LOCAL_LLM"):
        controller(tmp_path / "demo", harness, ai_provider="demo").preflight(
            "beast-synthetic-vulnerable"
        )
    with pytest.raises(BeastRejected, match="BEAST_REQUIRES_EXACT_APPROVED_MODEL"):
        controller(tmp_path / "wrong-model", harness, ai_model="qwen3:4b").preflight(
            "beast-synthetic-vulnerable"
        )


def test_resource_expansion_and_lease_reuse_fail_closed(tmp_path: Path) -> None:
    beast = controller(tmp_path, Harness())
    expanded = ResourceEnvelope(max_commands=9)
    with pytest.raises(BeastRejected, match="RESOURCE_ENVELOPE_EXPANSION_REJECTED"):
        beast.issue_lease(lease_request(requested_resources=expanded))
    lease = beast.issue_lease(lease_request())
    beast.create_run(BeastRunRequest(lease_id=lease.lease_id, scenario_id="bola_readonly"))
    with pytest.raises(BeastRejected, match="LEASE_NOT_ACTIVE"):
        beast.create_run(BeastRunRequest(lease_id=lease.lease_id, scenario_id="bola_readonly"))


@pytest.mark.asyncio
async def test_arbitrary_command_is_preserved_and_adaptation_is_audited(tmp_path: Path) -> None:
    harness = Harness()
    beast = controller(tmp_path, harness)
    lease = beast.issue_lease(lease_request())
    run = beast.create_run(BeastRunRequest(lease_id=lease.lease_id, scenario_id="bola_readonly"))
    await beast.run(run.run_id)
    complete = beast.store.get_run(run.run_id)
    assert complete is not None
    assert complete.state == "VERIFIED"
    assert complete.verifier_conclusion is not None
    assert complete.verifier_conclusion["authority"] == "DETERMINISTIC_VERIFIER"
    assert complete.verifier_conclusion["status"] == "CONFIRMED"
    assert complete.workspace_destroyed and complete.cleanup_verified
    assert len(complete.model_calls) == 3 and len(complete.commands) == 2
    # Quotes, variables, semicolons and arbitrary arguments cross the controller unchanged.
    assert harness.commands[1]["command_text"] == complete.commands[1].command_text
    assert 'payload="B-200";' in harness.commands[1]["command_text"]
    assert complete.commands[0].command_text != complete.commands[1].command_text
    events = beast.store.events(run.run_id)
    event_types = [event["event_type"] for event in events]
    assert event_types.count("AI_SHELL_COMMAND_PROPOSED") == 2
    assert event_types.count("AI_SHELL_COMMAND_COMPLETED") == 2
    assert "AI_ADVERSARY_OBSERVATION" in event_types
    assert "AI_ADVERSARY_STOPPED" in event_types
    assert "VERIFICATION_COMPLETED" in event_types
    assert "SANDBOX_DESTROYED" in event_types
    assert all(event["digest"] for event in events)


@pytest.mark.asyncio
async def test_emergency_stop_revokes_lease_and_preserves_audit(tmp_path: Path) -> None:
    harness = Harness()
    beast = controller(tmp_path, harness)
    lease = beast.issue_lease(lease_request())
    run = beast.create_run(BeastRunRequest(lease_id=lease.lease_id, scenario_id="bola_readonly"))
    stopped = await beast.emergency_stop(run.run_id, "operator-1")
    assert stopped.emergency_stopped and stopped.state == "STOPPED"
    saved_lease = beast.store.get_lease(lease.lease_id)
    assert saved_lease is not None and saved_lease.state == "REVOKED"
    events = [event["event_type"] for event in beast.store.events(run.run_id)]
    assert events[-2:] == ["BEAST_EMERGENCY_STOP_REQUESTED", "BEAST_EMERGENCY_STOP_COMPLETED"]
    with pytest.raises(BeastRejected, match="TARGET_REACTIVATION_BLOCKED"):
        beast.preflight("beast-synthetic-vulnerable")
    restored = await beast.restore_target("beast-synthetic-vulnerable", "operator-1")
    assert restored["health"] == "GREEN"
    assert beast.preflight("beast-synthetic-vulnerable").target.target_ref.endswith("vulnerable")


@pytest.mark.asyncio
async def test_failed_cleanup_blocks_target_reactivation(tmp_path: Path) -> None:
    beast = controller(tmp_path, Harness(destroy_success=False))
    lease = beast.issue_lease(lease_request())
    run = beast.create_run(BeastRunRequest(lease_id=lease.lease_id, scenario_id="bola_readonly"))
    await beast.run(run.run_id)
    complete = beast.store.get_run(run.run_id)
    assert complete is not None
    assert complete.state == "REVIEW_REQUIRED" and complete.stop_reason == "CLEANUP_FAILED"
    with pytest.raises(BeastRejected, match="TARGET_REACTIVATION_BLOCKED:CLEANUP_FAILED"):
        beast.issue_lease(lease_request())


def test_negative_inventory_and_single_sandbox_admission(tmp_path: Path) -> None:
    beast = controller(tmp_path, Harness())
    with pytest.raises(BeastRejected, match="PHASE_1_4_SYNTHETIC_LAB_ONLY"):
        beast.preflight("beast-control-production")
    with pytest.raises(BeastRejected, match="RESET_CAPABILITY_REQUIRED"):
        beast.preflight("beast-control-no-reset")
    first = beast.issue_lease(lease_request())
    beast.create_run(BeastRunRequest(lease_id=first.lease_id, scenario_id="endpoint_discovery"))
    second = beast.issue_lease(lease_request())
    with pytest.raises(BeastRejected, match="BEAST_SANDBOX_ALREADY_ACTIVE"):
        beast.create_run(
            BeastRunRequest(lease_id=second.lease_id, scenario_id="endpoint_discovery")
        )


def test_compose_boundary_has_no_host_mount_socket_or_external_network() -> None:
    compose = yaml.safe_load(Path("docker-compose.beast.yml").read_text())
    sandbox = compose["services"]["beast-sandbox"]
    assert sandbox["read_only"] is True
    assert sandbox["security_opt"] == ["no-new-privileges:true"]
    assert sandbox["networks"] == ["beast-adversary"]
    assert sandbox["dns"] == ["127.0.0.1"]
    assert sandbox["extra_hosts"] == ["beast-target:10.214.48.2"]
    assert "SYS_ADMIN" not in sandbox["cap_add"] and "NET_ADMIN" not in sandbox["cap_add"]
    encoded = Path("docker-compose.beast.yml").read_text()
    assert "docker.sock" not in encoded
    assert "privileged:" not in encoded
    assert "network_mode: host" not in encoded
    assert all(
        compose["networks"][name]["internal"] is True
        for name in ("beast-rpc", "beast-adversary", "beast-target-backend")
    )
    assert "beast-adversary" not in compose["services"]["control-plane"]["networks"]
    assert "beast-adversary" not in compose["services"]["lab-api"]["networks"]
    assert compose["services"]["beast-target-gateway"]["networks"]["beast-adversary"][
        "ipv4_address"
    ] == "10.214.48.2"


def test_controller_contains_no_command_allowlist_or_expected_sequence() -> None:
    source = Path("src/aegis/beast/controller.py").read_text()
    assert "command_text.startswith" not in source
    assert "allowed_commands" not in source
    assert "curl " not in source
    assert "sqlmap " not in source
    assert "ffuf " not in source
