from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest
import yaml

from aegis.deploy.aegis_ai_prod_preflight import (
    analyze_rendered_config,
    render_production_config,
    validate_inputs,
)

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "aegis-ai-prod.yml"
APP_IMAGE = f"registry.example.test/aegis@sha256:{'a' * 64}"
DASHBOARD_IMAGE = f"registry.example.test/nginx@sha256:{'b' * 64}"


def _inputs():  # type: ignore[no-untyped-def]
    return validate_inputs(
        APP_IMAGE,
        DASHBOARD_IMAGE,
        "https://models.internal.corp",
        "security-model-v1",
        "/opt/aegis/provider-token",
        "/opt/aegis/extensions.json",
        "/opt/aegis/nginx.conf",
        "8000",
    )


def test_standalone_prod_file_is_rootless_hardened_and_selinux_aware() -> None:
    document: dict[str, Any] = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    services = document["services"]
    for name in ("control-plane", "lab-api", "llm-gateway"):
        service = services[name]
        assert service["image"].startswith("${AEGIS_IMAGE:?")
        assert service["user"] == "10001:10001"
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert service["security_opt"] == ["no-new-privileges:true"]
        assert not service.get("build") and not service.get("privileged")
    assert services["dashboard"]["ports"] == ["127.0.0.1:${AEGIS_UI_PORT:-8000}:8080"]
    assert services["llm-gateway"]["volumes"][0].endswith(":ro,Z")
    assert services["llm-gateway"]["volumes"][1].endswith(":ro,z")
    assert "AI_AUTH_TOKEN" not in services["llm-gateway"]["environment"]
    assert "AI_AUTH_TOKEN_FILE" not in services["control-plane"]["environment"]
    assert document["networks"]["security-lab"]["internal"] is True
    assert document["networks"]["planner-rpc"]["internal"] is True


@pytest.mark.parametrize("port", ("80", "0", "65536", "not-a-port"))
def test_rootless_ui_port_validation_fails_closed(port: str) -> None:
    with pytest.raises(ValueError, match="UI port"):
        validate_inputs(
            APP_IMAGE,
            DASHBOARD_IMAGE,
            "https://models.internal.corp",
            "security-model-v1",
            "/opt/aegis/provider-token",
            "/opt/aegis/extensions.json",
            "/opt/aegis/nginx.conf",
            port,
        )


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker Compose render unavailable")
def test_real_compose_render_passes_standalone_production_preflight() -> None:
    inputs = _inputs()
    analyze_rendered_config(render_production_config(inputs, "docker"), inputs)
