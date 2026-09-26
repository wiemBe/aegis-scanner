"""Static topology assertions for the opt-in OpenRouter Compose profile."""

from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / "docker-compose.openrouter.yml"
PROD = ROOT / "docker-compose.openrouter.prod.yml"
SQUID = ROOT / "deploy" / "egress-proxy.openrouter.squid.conf"


def compose() -> dict[str, Any]:
    return yaml.safe_load(OVERLAY.read_text(encoding="utf-8"))


def test_gateway_has_exact_model_key_file_and_private_routing() -> None:
    services = compose()["services"]
    control = services["control-plane"]
    gateway = services["llm-gateway"]
    control_env = control["environment"]
    gateway_env = gateway["environment"]

    assert control_env["AI_PROVIDER"] == "openrouter"
    assert control_env["AI_MODEL"] == "qwen/qwen3.8-27b"
    assert "OPENROUTER_API_KEY" not in control_env
    assert "OPENROUTER_API_KEY_FILE" not in control_env
    assert gateway_env["AI_PROVIDER"] == "openrouter"
    assert gateway_env["AI_BASE_URL"] == "https://openrouter.ai"
    assert gateway_env["AI_MODEL"] == "qwen/qwen3.8-27b"
    assert gateway_env["AI_ALLOWED_MODELS"] == "qwen/qwen3.8-27b"
    assert gateway_env["OPENROUTER_API_KEY_FILE"] == "/run/secrets/openrouter-api-key"
    assert gateway_env["AI_USE_EGRESS_PROXY"] == "true"
    assert gateway["networks"] == ["planner-rpc", "gateway-egress"]
    assert "security-lab" not in gateway["networks"]
    assert "provider-egress" not in gateway["networks"]
    assert any("OPENROUTER_API_KEY_SOURCE" in item for item in gateway["volumes"])


def test_only_proxy_joins_public_egress_and_has_no_key() -> None:
    document = compose()
    services = document["services"]
    proxy = services["egress-proxy"]
    assert document["networks"]["planner-rpc"]["internal"] is True
    assert document["networks"]["gateway-egress"]["internal"] is True
    assert document["networks"]["provider-egress"]["internal"] is False
    assert proxy["networks"] == ["gateway-egress", "provider-egress"]
    assert "environment" not in proxy
    assert "ports" not in proxy


def test_squid_is_default_deny_and_openrouter_only() -> None:
    text = SQUID.read_text(encoding="utf-8")
    assert "acl openrouter_host dstdomain openrouter.ai" in text
    assert "http_access allow CONNECT openrouter_host https_port" in text
    assert "http_access deny all" in text
    assert "api.openai.com" not in text
    assert "api.deepseek.com" not in text


def test_production_overlay_requires_immutable_gateway_and_proxy_images() -> None:
    text = PROD.read_text(encoding="utf-8")
    assert "build: !reset null" in text
    assert "AEGIS_IMAGE:?" in text
    assert "AEGIS_EGRESS_PROXY_IMAGE:?" in text
    assert "@sha256" in text
