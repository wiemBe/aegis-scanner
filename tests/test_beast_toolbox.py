"""Phase 1.4-B — BEAST sandbox toolbox (AKCA + curated HexStrike web-recon tools).

Offline controls only. Live qwen3:8b + real image acceptance is a separate operator evidence run
(see docs/phase-1.4-b-beast-toolbox.md). These tests keep three things in lockstep:

  1. the controller-owned advisory manifest (aegis.beast.toolbox.SANDBOX_TOOLBOX),
  2. the pinned provenance (deploy/beast-sandbox/tools.lock.json), and
  3. what the image actually installs (deploy/beast-sandbox/Dockerfile),

and prove the manifest is transmitted to the model without widening any boundary.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException

from aegis.beast.contracts import (
    BEAST_PROFILE_ID,
    BeastDecisionRequest,
    BeastRunRequest,
    BeastToolDescriptor,
    CommandResult,
    LeaseRequest,
)
from aegis.beast.controller import BeastController
from aegis.beast.observe import render_decision_brief
from aegis.beast.store import BeastStore
from aegis.beast.toolbox import (
    SANDBOX_TOOLBOX,
    SANDBOX_TOOLBOX_BOUNDARY_NOTE,
    sandbox_toolbox,
)
from aegis.settings import Settings
from lab_api.main import app as lab_app

_ROOT = Path(__file__).resolve().parents[1]
_DOCKERFILE = (_ROOT / "deploy/beast-sandbox/Dockerfile").read_text()
_LOCK = json.loads((_ROOT / "deploy/beast-sandbox/tools.lock.json").read_text())

# Raw-socket / exploitation tooling that must never be advertised as "available": the sandbox drops
# all capabilities and the only egress is the GET/HEAD/OPTIONS gateway, so these could not function.
_FORBIDDEN_ADVISORY_TOOLS = frozenset(
    {"nmap", "masscan", "rustscan", "metasploit", "hydra", "msfconsole"}
)


def _apt_packages() -> set[str]:
    match = re.search(
        r"apt-get install -y --no-install-recommends\s*\\?\s*(.*?)&& rm -rf",
        _DOCKERFILE,
        re.DOTALL,
    )
    assert match, "could not locate the apt install block in the beast Dockerfile"
    tokens = re.split(r"[\s\\]+", match.group(1))
    return {token for token in tokens if token and re.fullmatch(r"[a-z0-9][a-z0-9.+-]*", token)}


def _dockerfile_checksums() -> set[str]:
    return set(re.findall(r"--checksum=sha256:([0-9a-f]{64})", _DOCKERFILE))


# --------------------------------------------------------------------------------------------------
# Provenance / consistency
# --------------------------------------------------------------------------------------------------


def test_tools_lock_shas_are_pinned_in_the_dockerfile() -> None:
    dockerfile_shas = _dockerfile_checksums()
    assert dockerfile_shas, "the beast Dockerfile must pin every fetched asset by sha256"
    for name, meta in _LOCK["tools"].items():
        for arch, sha in meta["sha256"].items():
            assert sha in dockerfile_shas, f"{name} {arch} sha {sha} not pinned in the Dockerfile"


def test_new_tools_are_copied_into_the_image() -> None:
    for name in ("akca", "katana", "httpx"):
        assert name in _LOCK["tools"], f"{name} must be pinned in tools.lock.json"
        assert re.search(
            rf"COPY --from=webtools /out/{name} /usr/local/bin/{name}\b", _DOCKERFILE
        ), f"{name} is not COPYed onto PATH in the final image"
    # nuclei stays installed from its own pre-existing stage.
    assert "COPY --from=nuclei /out/nuclei /usr/local/bin/nuclei" in _DOCKERFILE


def test_projectdiscovery_httpx_is_not_shadowed_by_the_python_httpx_cli() -> None:
    pip_install = _DOCKERFILE.index("RUN pip install --no-cache-dir .")
    pinned_copy = _DOCKERFILE.index("COPY --from=webtools /out/httpx /usr/local/bin/httpx")
    assert pinned_copy > pip_install


def test_every_advertised_tool_is_actually_installed() -> None:
    apt = _apt_packages()
    lock = set(_LOCK["tools"])
    for tool in SANDBOX_TOOLBOX:
        assert tool.name in apt or tool.name in lock, (
            f"advisory tool {tool.name!r} is neither an apt package nor a pinned lock entry"
        )


def test_advisory_toolbox_excludes_rawsocket_and_exploit_tools() -> None:
    names = {tool.name for tool in SANDBOX_TOOLBOX}
    assert not (names & _FORBIDDEN_ADVISORY_TOOLS), (
        "advisory toolbox must not list tools the GET/HEAD/OPTIONS gateway makes inert"
    )
    # nmap is in the base image but must not be advertised as usable.
    assert "nmap" in _apt_packages() and "nmap" not in names


def test_third_party_provenance_and_licenses_present() -> None:
    hexstrike_license = (_ROOT / "third_party/hexstrike-ai/LICENSE").read_text()
    akca_license = (_ROOT / "third_party/akca/LICENSE").read_text()
    assert "MIT License" in hexstrike_license
    assert "Apache License" in akca_license
    assert (_ROOT / "third_party/hexstrike-ai/NOTICE.md").exists()
    assert (_ROOT / "third_party/akca/NOTICE.md").exists()
    assert _LOCK["tools"]["akca"]["license"] == "Apache-2.0"


# --------------------------------------------------------------------------------------------------
# What the model sees
# --------------------------------------------------------------------------------------------------


def _request(tools: list[BeastToolDescriptor]) -> BeastDecisionRequest:
    return BeastDecisionRequest(
        run_id="run-test",
        scenario_id="endpoint_discovery",
        objective="Map the authorized surface.",
        target_origin="http://beast-target:8080",
        target_base_path="/lab/beast/vulnerable",
        synthetic_public_accounts=[],
        sequence=1,
        remaining_commands=8,
        remaining_time_seconds=180,
        objective_evidence_sufficient=False,
        decision_requirements=[],
        observations=[],
        available_tools=tools,
    )


def test_render_brief_lists_tools_and_the_boundary_note() -> None:
    brief = render_decision_brief(_request(sandbox_toolbox()))
    assert "Installed sandbox tools" in brief
    assert "advisory" in brief
    for name in ("akca", "katana", "httpx", "nuclei", "ffuf", "gobuster", "sqlmap"):
        assert f"- {name} (" in brief
    assert SANDBOX_TOOLBOX_BOUNDARY_NOTE in brief


def test_render_brief_omits_the_block_when_no_tools_supplied() -> None:
    brief = render_decision_brief(_request([]))
    assert "Installed sandbox tools" not in brief
    # An empty list must not weaken the rest of the brief.
    assert "Objective:" in brief and "Return one JSON object" in brief


def test_sandbox_toolbox_returns_independent_copies() -> None:
    first = sandbox_toolbox()
    first[0].purpose = "mutated"
    assert sandbox_toolbox()[0].purpose != "mutated"


def test_beast_config_projects_the_complete_toolbox(tmp_path: Path) -> None:
    settings = Settings(database_path=str(tmp_path / "config.db"))
    store = BeastStore(settings.database_path)
    store.initialize()
    config = BeastController(settings, store).config()
    assert {tool["name"] for tool in config["tools"]} == {tool.name for tool in SANDBOX_TOOLBOX}


# --------------------------------------------------------------------------------------------------
# The manifest is actually transmitted to the gateway, and no boundary is widened
# --------------------------------------------------------------------------------------------------


class _CapturingTransport(httpx.AsyncBaseTransport):
    """Wraps the gateway transport to record every /v1/beast/decide envelope."""

    def __init__(self, inner: httpx.AsyncBaseTransport) -> None:
        self._inner = inner
        self.decide_envelopes: list[dict[str, Any]] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/beast/decide":
            self.decide_envelopes.append(json.loads(request.content))
        return await self._inner.handle_async_request(request)


def _gateway() -> FastAPI:
    app = FastAPI()

    @app.post("/v1/beast/decide")
    async def decide(body: dict[str, Any]) -> dict[str, Any]:
        sequence = body["sequence"]
        if sequence == 1:
            decision = {
                "decision_type": "command",
                "hypothesis": "The owner object is a useful control.",
                "expected_intent": "Read synthetic user A's own object.",
                "command_text": (
                    "curl -s -H 'Authorization: Bearer lab-token-user-a' "
                    '"$BEAST_TARGET$BEAST_TARGET_BASE_PATH/accounts/A-100"'
                ),
            }
        elif sequence == 2:
            decision = {
                "decision_type": "command",
                "hypothesis": "A cross-owner read may lack an ownership check.",
                "expected_intent": "Read synthetic user B object as user A.",
                "command_text": (
                    "curl -s -H 'Authorization: Bearer lab-token-user-a' "
                    '"$BEAST_TARGET$BEAST_TARGET_BASE_PATH/accounts/B-200"'
                ),
            }
        else:
            decision = {
                "decision_type": "stop",
                "hypothesis": "The direct response is sufficient for verification.",
                "summary": "Stop after the cross-owner response.",
                "evidence_observation_ids": [body["observations"][-1]["observation_id"]],
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
            },
        }

    return app


def _sandbox() -> FastAPI:
    app = FastAPI()

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "tool_checks": {
                tool.name: {
                    "status": "READY",
                    "executable": tool.name,
                    "detail": f"{tool.name} test-version",
                }
                for tool in SANDBOX_TOOLBOX
            },
        }

    def authorized(token: str | None) -> None:
        if token != "test-supervisor-token":  # noqa: S105 - synthetic test token
            raise HTTPException(status_code=403)

    @app.post("/v1/sessions")
    async def session(
        body: dict[str, Any], x_beast_supervisor_token: str | None = Header(default=None)
    ) -> dict[str, Any]:
        authorized(x_beast_supervisor_token)
        # The session boundary the controller forwards must stay read-only + synthetic-scoped.
        assert body["allowed_methods"] == ["GET", "HEAD", "OPTIONS"]
        assert body["allowed_path_prefix"] == "/lab/beast/vulnerable"
        return {
            "run_id": body["run_id"],
            "sandbox_instance_id": "sandbox-test",
            "workspace_reference": f"workspace:{body['run_id']}",
            "ready": True,
        }

    @app.post("/v1/commands")
    async def command(
        body: dict[str, Any], x_beast_supervisor_token: str | None = Header(default=None)
    ) -> dict[str, Any]:
        authorized(x_beast_supervisor_token)
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

    @app.post("/v1/runs/{run_id}/destroy")
    async def destroy(
        run_id: str, x_beast_supervisor_token: str | None = Header(default=None)
    ) -> dict[str, Any]:
        authorized(x_beast_supervisor_token)
        return {"run_id": run_id, "destroyed": True, "artifacts": []}

    return app


async def test_controller_transmits_the_toolbox_without_widening_scope(tmp_path: Path) -> None:
    gateway, sandbox = _gateway(), _sandbox()
    settings = Settings(
        database_path=str(tmp_path / "beast.db"),
        ai_provider="ollama",
        ai_model="qwen3:8b",
        beast_enabled=True,
        beast_supervisor_token="test-supervisor-token",  # noqa: S106 - synthetic test token
    )
    store = BeastStore(settings.database_path)
    store.initialize()
    capturing = _CapturingTransport(httpx.ASGITransport(app=gateway))
    beast = BeastController(
        settings,
        store,
        gateway_transport=capturing,
        sandbox_transport=httpx.ASGITransport(app=sandbox),
        verifier_transport=httpx.ASGITransport(app=lab_app),
    )
    lease = beast.issue_lease(
        LeaseRequest(
            operator_id="operator-1",
            actor_type="OPERATOR",
            target_ref="beast-synthetic-vulnerable",
            profile_id=BEAST_PROFILE_ID,
            confirmation="ASSESS Disposable Synthetic Bank Adversary Target",
        )
    )
    run = beast.create_run(BeastRunRequest(lease_id=lease.lease_id, scenario_id="bola_readonly"))
    await beast.run(run.run_id)

    assert capturing.decide_envelopes, "controller never called the gateway decide route"
    for envelope in capturing.decide_envelopes:
        names = {tool["name"] for tool in envelope["available_tools"]}
        assert {"akca", "katana", "httpx"} <= names
        assert not (names & _FORBIDDEN_ADVISORY_TOOLS)
    # The toolbox does not add authority: the run still completes under the verifier.
    complete = beast.store.get_run(run.run_id)
    assert complete is not None and complete.state == "VERIFIED"


async def test_toolbox_health_requires_successful_runtime_execution_probes(tmp_path: Path) -> None:
    settings = Settings(
        database_path=str(tmp_path / "health.db"),
        ai_provider="ollama",
        ai_model="qwen3:8b",
        beast_enabled=True,
        beast_supervisor_token="test-supervisor-token",  # noqa: S106 - synthetic test token
    )
    store = BeastStore(settings.database_path)
    store.initialize()
    beast = BeastController(
        settings,
        store,
        sandbox_transport=httpx.ASGITransport(app=_sandbox()),
    )

    health = await beast.toolbox_health()

    assert health["state"] == "READY"
    assert health["ready"] == health["total"] == len(SANDBOX_TOOLBOX)
    assert {tool["status"] for tool in health["tools"]} == {"READY"}
