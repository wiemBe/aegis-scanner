"""Production company-private provider path: fail-closed configuration and isolation."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from pydantic import SecretStr

from aegis.deploy.preflight import PreflightError
from aegis.deploy.private_provider_preflight import (
    EXIT_BAD_INPUT,
    PrivateProviderInputs,
    analyze_rendered_config,
    main,
    render_production_config,
    validate_endpoint,
    validate_inputs,
    validate_model,
    validate_token_source,
)
from aegis.providers import InternalOpenAICompatibleProvider
from aegis.settings import Settings

ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / "docker-compose.private-provider.prod.yml"
DIGEST = "sha256:" + "a" * 64
IMAGE = f"registry.example.test/security/aegis@{DIGEST}"
DASHBOARD_IMAGE = f"registry.example.test/security/nginx@sha256:{'b' * 64}"


class _ComposeLoader(yaml.SafeLoader):
    pass


_ComposeLoader.add_constructor("!reset", lambda _loader, _node: None)


def _overlay() -> dict[str, Any]:
    return yaml.load(OVERLAY.read_text(encoding="utf-8"), Loader=_ComposeLoader)  # noqa: S506


def _inputs() -> PrivateProviderInputs:
    return validate_inputs(
        IMAGE,
        DASHBOARD_IMAGE,
        "https://models.internal.corp:8443",
        "security-model-v1",
        "/opt/aegis/secrets/provider-token",
    )


def _rendered(inputs: PrivateProviderInputs) -> dict[str, Any]:
    image = inputs.image.reference
    return {
        "services": {
            "control-plane": {
                "image": image,
                "read_only": True,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "environment": {
                    "AI_PROVIDER": "internal_openai_compatible",
                    "AI_MODEL": inputs.model,
                    "AI_ALLOWED_MODELS": inputs.model,
                    "LLM_GATEWAY_URL": "http://llm-gateway:8080",
                },
                "networks": {"security-lab": None, "planner-rpc": None},
            },
            "lab-api": {
                "image": image,
                "read_only": True,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "networks": {"security-lab": None},
            },
            "llm-gateway": {
                "image": image,
                "read_only": True,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "environment": {
                    "AI_PROVIDER": "internal_openai_compatible",
                    "AI_BASE_URL": inputs.endpoint,
                    "AI_MODEL": inputs.model,
                    "AI_ALLOWED_MODELS": inputs.model,
                    "AI_AUTH_MODE": "bearer",
                    "AI_AUTH_TOKEN_FILE": "/run/secrets/aegis-provider-token",
                    "AI_USE_EGRESS_PROXY": "false",
                },
                "networks": {"planner-rpc": None, "provider-egress": None},
                "volumes": [
                    {
                        "type": "bind",
                        "source": inputs.token_source,
                        "target": "/run/secrets/aegis-provider-token",
                        "read_only": True,
                    }
                ],
            },
            "dashboard": {
                "image": inputs.dashboard_image.reference,
                "read_only": True,
                "cap_drop": ["ALL"],
                "security_opt": ["no-new-privileges:true"],
                "networks": {"dashboard-ingress": None, "security-lab": None},
                "ports": [
                    {
                        "host_ip": "127.0.0.1",
                        "published": "8000",
                        "target": 8080,
                        "protocol": "tcp",
                    }
                ],
            },
        },
        "networks": {
            "security-lab": {"internal": True},
            "planner-rpc": {"internal": True},
            "provider-egress": {"internal": False},
            "dashboard-ingress": {"internal": False},
        },
    }


def test_overlay_is_immutable_hardened_and_credential_file_only() -> None:
    services = _overlay()["services"]
    gateway = services["llm-gateway"]
    assert gateway["build"] is None
    assert gateway["image"].startswith("${AEGIS_IMAGE")
    assert gateway["read_only"] is True
    assert gateway["cap_drop"] == ["ALL"]
    assert gateway["restart"] == "unless-stopped"
    assert gateway["mem_limit"] and gateway["cpus"] and gateway["pids_limit"]
    assert not gateway.get("ports")
    assert "AI_AUTH_TOKEN" not in gateway["environment"]
    assert "AI_AUTH_TOKEN" not in services["control-plane"]["environment"]
    assert gateway["environment"]["AI_AUTH_TOKEN_FILE"] == (
        "/run/secrets/aegis-provider-token"  # noqa: S105 - file path, not a credential
    )
    assert services["control-plane"]["env_file"] is None

    dashboard_prod = yaml.safe_load(
        (ROOT / "docker-compose.dashboard.prod.yml").read_text(encoding="utf-8")
    )
    assert dashboard_prod["services"]["dashboard"]["image"].startswith(
        "${AEGIS_DASHBOARD_IMAGE"
    )
    nginx_config = (ROOT / "deploy/dashboard-nginx.conf").read_text(encoding="utf-8")
    assert "access_log off;" in nginx_config
    assert "$request" not in nginx_config and "$request_uri" not in nginx_config


@pytest.mark.parametrize(
    "bad",
    [
        None,
        "",
        "http://models.internal.corp",
        "https://user:secret@models.internal.corp",
        "https://models.internal.corp/v1",
        "https://models.internal.corp?x=1",
        "https://localhost",
        "https://internal-ai.example",
    ],
)
def test_endpoint_validation_fails_closed(bad: str | None) -> None:
    with pytest.raises(ValueError):
        validate_endpoint(bad)


def test_non_secret_inputs_are_exact_and_bounded() -> None:
    assert validate_endpoint("https://models.internal.corp/") == "https://models.internal.corp"
    assert validate_model("security-model:v1") == "security-model:v1"
    assert validate_token_source("/opt/aegis/secrets/token") == "/opt/aegis/secrets/token"
    for bad in (None, "", " model", "x" * 129, "model\nother"):
        with pytest.raises(ValueError):
            validate_model(bad)
    for bad in (None, "", "relative/token", "/", "/tmp"):  # noqa: S108
        with pytest.raises(ValueError):
            validate_token_source(bad)


def test_analyzer_accepts_exact_private_provider_topology() -> None:
    inputs = _inputs()
    analyze_rendered_config(_rendered(inputs), inputs)


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker compose is unavailable")
def test_real_compose_render_satisfies_private_provider_preflight() -> None:
    inputs = _inputs()
    analyze_rendered_config(render_production_config(inputs), inputs)


@pytest.mark.parametrize(
    ("service", "mutation"),
    [
        ("control-plane", {"ports": ["8000:8000"]}),
        ("llm-gateway", {"build": {"context": "."}}),
        ("llm-gateway", {"image": "registry.example.test/aegis@sha256:" + "b" * 64}),
    ],
)
def test_analyzer_rejects_mutable_or_published_services(
    service: str, mutation: dict[str, Any]
) -> None:
    inputs = _inputs()
    config = _rendered(inputs)
    config["services"][service].update(mutation)
    with pytest.raises(PreflightError):
        analyze_rendered_config(config, inputs)


def test_analyzer_rejects_credential_or_network_boundary_regression() -> None:
    inputs = _inputs()
    config = _rendered(inputs)
    config["services"]["control-plane"]["environment"]["AI_AUTH_TOKEN_FILE"] = "/secret"  # noqa: S105
    with pytest.raises(PreflightError, match="credential"):
        analyze_rendered_config(config, inputs)

    config = _rendered(inputs)
    config["services"]["llm-gateway"]["networks"]["security-lab"] = None
    with pytest.raises(PreflightError, match="network"):
        analyze_rendered_config(config, inputs)

    config = _rendered(inputs)
    config["services"]["lab-api"]["environment"] = {"DEEPSEEK_API_KEY": "present"}
    with pytest.raises(PreflightError, match="credential"):
        analyze_rendered_config(config, inputs)


def test_analyzer_rejects_mutable_or_public_dashboard() -> None:
    inputs = _inputs()
    config = _rendered(inputs)
    config["services"]["dashboard"]["image"] = "nginx:latest"
    with pytest.raises(PreflightError, match="dashboard image"):
        analyze_rendered_config(config, inputs)

    config = _rendered(inputs)
    config["services"]["dashboard"]["ports"][0]["host_ip"] = "0.0.0.0"  # noqa: S104
    with pytest.raises(PreflightError, match="loopback"):
        analyze_rendered_config(config, inputs)


def test_gateway_reads_bounded_token_file(tmp_path: Path) -> None:
    token = tmp_path / "provider-token"
    token.write_text("file-secret-value\n", encoding="utf-8")
    settings = Settings(
        ai_provider="internal_openai_compatible",
        ai_base_url="https://models.internal.corp",
        ai_model="security-model-v1",
        ai_allowed_models="security-model-v1",
        ai_auth_mode="bearer",
        ai_auth_token_file=str(token),
    )
    provider = InternalOpenAICompatibleProvider(
        settings, httpx.MockTransport(lambda _request: httpx.Response(200))
    )
    assert provider._token == "file-secret-value"  # noqa: S105 - test-only sentinel


def test_gateway_rejects_ambiguous_or_invalid_token_source(tmp_path: Path) -> None:
    token = tmp_path / "provider-token"
    token.write_text("file-secret", encoding="utf-8")
    with pytest.raises(ValueError, match="exactly one"):
        InternalOpenAICompatibleProvider(
            Settings(
                ai_provider="internal_openai_compatible",
                ai_base_url="https://models.internal.corp",
                ai_model="security-model-v1",
                ai_allowed_models="security-model-v1",
                ai_auth_mode="bearer",
                ai_auth_token=SecretStr("inline-secret"),
                ai_auth_token_file=str(token),
            ),
            httpx.MockTransport(lambda _request: httpx.Response(200)),
        )
    with pytest.raises(ValueError, match="credential source"):
        InternalOpenAICompatibleProvider(
            Settings(
                ai_provider="internal_openai_compatible",
                ai_base_url="https://models.internal.corp",
                ai_model="security-model-v1",
                ai_allowed_models="security-model-v1",
                ai_auth_mode="bearer",
                ai_auth_token_file=str(tmp_path / "missing"),
            ),
            httpx.MockTransport(lambda _request: httpx.Response(200)),
        )


def test_cli_rejects_secret_shaped_invalid_input_without_echo(
    capsys: pytest.CaptureFixture[str],
) -> None:
    sentinel = "SECRET-MUST-NOT-LEAK"
    code = main(
        [
            "--image",
            IMAGE,
            "--dashboard-image",
            DASHBOARD_IMAGE,
            "--endpoint",
            f"https://user:{sentinel}@models.internal.corp",
            "--model",
            "security-model-v1",
            "--token-source",
            "/opt/aegis/secrets/token",
        ]
    )
    assert code == EXIT_BAD_INPUT
    assert sentinel not in capsys.readouterr().out
