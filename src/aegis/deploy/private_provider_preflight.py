"""Fail-closed preflight for the company-private provider production topology.

The command validates non-secret operator inputs, renders all three production Compose layers, and
proves the credential/network/image isolation invariants from the merged result. It does not open
the credential file, contact the provider, pull images, or start containers.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess  # noqa: S404 - fixed docker-compose argv, never shell=True
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Any
from urllib.parse import urlsplit

from aegis.deploy.image_reference import (
    ImageReferenceError,
    ImmutableImageReference,
    parse_immutable_image_reference,
)
from aegis.deploy.preflight import PreflightError

IMAGE_ENV_VAR = "AEGIS_IMAGE"
DASHBOARD_IMAGE_ENV_VAR = "AEGIS_DASHBOARD_IMAGE"
ENDPOINT_ENV_VAR = "AEGIS_PROVIDER_BASE_URL"
MODEL_ENV_VAR = "AEGIS_PROVIDER_MODEL"
TOKEN_SOURCE_ENV_VAR = "AEGIS_PROVIDER_TOKEN_SOURCE"  # noqa: S105 - path, not a credential
PRODUCTION_SERVICES = ("control-plane", "lab-api", "llm-gateway")
_MODEL_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_RENDER_TIMEOUT_SECONDS = 60

_REPO_ROOT = Path(__file__).resolve().parents[3]
_COMPOSE_FILES = (
    _REPO_ROOT / "docker-compose.yml",
    _REPO_ROOT / "docker-compose.prod.yml",
    _REPO_ROOT / "docker-compose.private-provider.prod.yml",
    _REPO_ROOT / "docker-compose.dashboard.yml",
    _REPO_ROOT / "docker-compose.dashboard.prod.yml",
)

EXIT_OK = 0
EXIT_BAD_INPUT = 2
EXIT_RENDER_FAILED = 3


@dataclass(frozen=True)
class PrivateProviderInputs:
    image: ImmutableImageReference
    dashboard_image: ImmutableImageReference
    endpoint: str
    model: str
    token_source: str


def validate_endpoint(raw: str | None) -> str:
    """Accept one configured HTTPS origin, with fixed credential-free failures."""

    if raw is None or raw == "" or raw != raw.strip():
        raise ValueError("provider endpoint is missing or invalid")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError:
        raise ValueError("provider endpoint is missing or invalid") from None
    host = parsed.hostname
    if (
        parsed.scheme != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or host == "localhost"
        or host.endswith(".example")
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError("provider endpoint must be a configured HTTPS origin")
    return raw[:-1] if raw.endswith("/") else raw


def validate_model(raw: str | None) -> str:
    if raw is None or _MODEL_RE.fullmatch(raw) is None:
        raise ValueError("provider model identifier is missing or invalid")
    return raw


def validate_token_source(raw: str | None) -> str:
    if raw is None or raw == "" or raw != raw.strip():
        raise ValueError("provider token source path is missing or invalid")
    path = PurePath(raw)
    if not path.is_absolute() or str(path) in {"/", "/tmp", "/var/tmp"}:  # noqa: S108
        raise ValueError("provider token source path must be a specific absolute file path")
    return raw


def validate_inputs(
    image: str | None,
    dashboard_image: str | None,
    endpoint: str | None,
    model: str | None,
    token_source: str | None,
) -> PrivateProviderInputs:
    return PrivateProviderInputs(
        image=parse_immutable_image_reference(image),
        dashboard_image=parse_immutable_image_reference(dashboard_image),
        endpoint=validate_endpoint(endpoint),
        model=validate_model(model),
        token_source=validate_token_source(token_source),
    )


def _mapping(value: object, message: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PreflightError(message)
    return value


def analyze_rendered_config(config: Mapping[str, Any], inputs: PrivateProviderInputs) -> None:
    """Prove immutable images, exact provider binding, and credential/network isolation."""

    services = _mapping(config.get("services"), "rendered configuration has no services section")
    for name in PRODUCTION_SERVICES:
        service = _mapping(services.get(name), f"rendered configuration is missing service {name}")
        if service.get("image") != inputs.image.reference:
            raise PreflightError(f"the {name} image does not match the immutable digest")
        if service.get("build") not in (None, "", {}):
            raise PreflightError(f"the {name} service has an active build fallback")
        if service.get("ports"):
            raise PreflightError(f"the {name} service unexpectedly publishes a host port")
        if service.get("read_only") is not True or "ALL" not in service.get("cap_drop", []):
            raise PreflightError(f"the {name} runtime hardening is incomplete")
        if "no-new-privileges:true" not in service.get("security_opt", []):
            raise PreflightError(f"the {name} runtime hardening is incomplete")

    dashboard = _mapping(services.get("dashboard"), "rendered configuration is missing dashboard")
    if dashboard.get("image") != inputs.dashboard_image.reference:
        raise PreflightError("the dashboard image does not match its immutable digest")
    if dashboard.get("build") not in (None, "", {}):
        raise PreflightError("the dashboard service has an active build fallback")
    if dashboard.get("read_only") is not True or "ALL" not in dashboard.get("cap_drop", []):
        raise PreflightError("the dashboard runtime hardening is incomplete")
    if "no-new-privileges:true" not in dashboard.get("security_opt", []):
        raise PreflightError("the dashboard runtime hardening is incomplete")
    ports = dashboard.get("ports")
    if not isinstance(ports, list) or len(ports) != 1 or not isinstance(ports[0], Mapping):
        raise PreflightError("the dashboard loopback port binding is invalid")
    port = ports[0]
    if (
        port.get("host_ip") != "127.0.0.1"
        or str(port.get("published")) != "8000"
        or port.get("target") != 8080
        or port.get("protocol") != "tcp"
    ):
        raise PreflightError("the dashboard loopback port binding is invalid")

    control = _mapping(services["control-plane"], "control-plane configuration is invalid")
    gateway = _mapping(services["llm-gateway"], "llm-gateway configuration is invalid")
    control_env = _mapping(control.get("environment"), "control-plane environment is invalid")
    gateway_env = _mapping(gateway.get("environment"), "llm-gateway environment is invalid")

    if control_env.get("AI_PROVIDER") != "internal_openai_compatible":
        raise PreflightError("control-plane provider binding is invalid")
    if (
        control_env.get("AI_MODEL") != inputs.model
        or control_env.get("AI_ALLOWED_MODELS") != inputs.model
    ):
        raise PreflightError("control-plane model binding is invalid")
    if control_env.get("LLM_GATEWAY_URL") != "http://llm-gateway:8080":
        raise PreflightError("control-plane gateway binding is invalid")
    credential_fields = {"AI_AUTH_TOKEN", "AI_AUTH_TOKEN_FILE", "DEEPSEEK_API_KEY"}
    for name in ("control-plane", "lab-api"):
        service = _mapping(services[name], f"{name} configuration is invalid")
        environment = service.get("environment", {})
        environment = _mapping(environment, f"{name} environment is invalid")
        if credential_fields.intersection(environment):
            raise PreflightError(f"{name} unexpectedly contains a provider credential source")

    expected_gateway = {
        "AI_PROVIDER": "internal_openai_compatible",
        "AI_BASE_URL": inputs.endpoint,
        "AI_MODEL": inputs.model,
        "AI_ALLOWED_MODELS": inputs.model,
        "AI_AUTH_MODE": "bearer",
        "AI_AUTH_TOKEN_FILE": "/run/secrets/aegis-provider-token",
        "AI_USE_EGRESS_PROXY": "false",
    }
    if any(gateway_env.get(key) != value for key, value in expected_gateway.items()):
        raise PreflightError("llm-gateway provider binding is invalid")
    if "AI_AUTH_TOKEN" in gateway_env or "DEEPSEEK_API_KEY" in gateway_env:
        raise PreflightError("llm-gateway credential must not be present in its environment")

    control_networks = set(_mapping(control.get("networks"), "control-plane networks are invalid"))
    gateway_networks = set(_mapping(gateway.get("networks"), "llm-gateway networks are invalid"))
    dashboard_networks = set(
        _mapping(dashboard.get("networks"), "dashboard networks are invalid")
    )
    if control_networks != {"security-lab", "planner-rpc"}:
        raise PreflightError("control-plane network isolation is invalid")
    if gateway_networks != {"planner-rpc", "provider-egress"}:
        raise PreflightError("llm-gateway network isolation is invalid")
    if dashboard_networks != {"dashboard-ingress", "security-lab"}:
        raise PreflightError("dashboard network isolation is invalid")

    volumes = gateway.get("volumes")
    if not isinstance(volumes, list) or len(volumes) != 1 or not isinstance(volumes[0], Mapping):
        raise PreflightError("llm-gateway credential mount is invalid")
    mount = volumes[0]
    if (
        mount.get("type") != "bind"
        or mount.get("source") != inputs.token_source
        or mount.get("target") != "/run/secrets/aegis-provider-token"
        or mount.get("read_only") is not True
    ):
        raise PreflightError("llm-gateway credential mount is invalid")

    networks = _mapping(config.get("networks"), "rendered configuration has no networks section")
    planner = _mapping(networks.get("planner-rpc"), "planner-rpc network is missing")
    provider = _mapping(networks.get("provider-egress"), "provider-egress network is missing")
    target = _mapping(networks.get("security-lab"), "security-lab network is missing")
    ingress = _mapping(networks.get("dashboard-ingress"), "dashboard-ingress network is missing")
    if (
        planner.get("internal") is not True
        or target.get("internal") is not True
        or provider.get("internal") is True
        or ingress.get("internal") is True
    ):
        raise PreflightError("provider network boundary is invalid")


def render_production_config(inputs: PrivateProviderInputs) -> dict[str, Any]:
    docker_bin = shutil.which("docker")
    if docker_bin is None:
        raise PreflightError("docker is unavailable; cannot prove the private-provider config")
    env = {
        **os.environ,
        IMAGE_ENV_VAR: inputs.image.reference,
        DASHBOARD_IMAGE_ENV_VAR: inputs.dashboard_image.reference,
        ENDPOINT_ENV_VAR: inputs.endpoint,
        MODEL_ENV_VAR: inputs.model,
        TOKEN_SOURCE_ENV_VAR: inputs.token_source,
    }
    argv: list[str] = [docker_bin, "compose"]
    for compose_file in _COMPOSE_FILES:
        argv.extend(("-f", str(compose_file)))
    argv.extend(("config", "--format", "json"))
    try:
        completed = subprocess.run(  # noqa: S603 - fixed executable/flags, no shell
            argv,
            capture_output=True,
            text=True,
            env=env,
            timeout=_RENDER_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise PreflightError("rendering the private-provider config timed out") from exc
    except OSError as exc:
        raise PreflightError("docker could not render the private-provider config") from exc
    if completed.returncode != 0:
        raise PreflightError("docker compose could not render the private-provider config")
    try:
        rendered = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise PreflightError("the rendered private-provider config was not valid JSON") from exc
    if not isinstance(rendered, dict):
        raise PreflightError("the rendered private-provider config was not a mapping")
    return rendered


def run_preflight(inputs: PrivateProviderInputs) -> None:
    analyze_rendered_config(render_production_config(inputs), inputs)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m aegis.deploy.private_provider_preflight",
        description=(
            "Validate and prove the immutable company-private provider production topology."
        ),
    )
    parser.add_argument("--image", default=os.environ.get(IMAGE_ENV_VAR))
    parser.add_argument("--dashboard-image", default=os.environ.get(DASHBOARD_IMAGE_ENV_VAR))
    parser.add_argument("--endpoint", default=os.environ.get(ENDPOINT_ENV_VAR))
    parser.add_argument("--model", default=os.environ.get(MODEL_ENV_VAR))
    parser.add_argument("--token-source", default=os.environ.get(TOKEN_SOURCE_ENV_VAR))
    args = parser.parse_args(argv)
    try:
        inputs = validate_inputs(
            args.image,
            args.dashboard_image,
            args.endpoint,
            args.model,
            args.token_source,
        )
    except (ImageReferenceError, ValueError) as exc:
        print(f"PRIVATE PROVIDER PREFLIGHT FAILED (input): {exc}")
        return EXIT_BAD_INPUT
    try:
        run_preflight(inputs)
    except PreflightError as exc:
        print(f"PRIVATE PROVIDER PREFLIGHT FAILED (rendered config): {exc}")
        return EXIT_RENDER_FAILED
    print("PRIVATE PROVIDER PREFLIGHT OK")
    print(f"  image digest : {inputs.image.digest}")
    print(f"  ingress digest: {inputs.dashboard_image.digest}")
    print("  provider     : configured HTTPS origin with one exact model")
    print(
        "  isolation    : credential file is gateway-only; "
        "target and provider networks are separate"
    )
    print(
        "  note         : image pull, provider reachability and staging soak are not performed here"
    )
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
