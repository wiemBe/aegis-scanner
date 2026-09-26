"""Fail-closed preflight for the standalone Fedora/RHEL production Compose file.

The command renders ``aegis-ai-prod.yml`` through the selected container engine and proves the
immutable-image, credential, extension, ingress and network boundaries. It never reads a secret,
pulls an image, contacts a provider or starts a container.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess  # noqa: S404 - fixed engine/compose argv, never shell=True
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml

from aegis.deploy.image_reference import (
    ImageReferenceError,
    ImmutableImageReference,
    parse_immutable_image_reference,
)
from aegis.deploy.preflight import PreflightError
from aegis.deploy.private_provider_preflight import (
    validate_endpoint,
    validate_model,
    validate_token_source,
)

ContainerEngine = Literal["podman", "docker"]
_ROOT = Path(__file__).resolve().parents[3]
_COMPOSE_FILE = _ROOT / "aegis-ai-prod.yml"
_RENDER_TIMEOUT_SECONDS = 60
_APP_SERVICES = ("control-plane", "lab-api", "llm-gateway")

EXIT_OK = 0
EXIT_BAD_INPUT = 2
EXIT_RENDER_FAILED = 3


@dataclass(frozen=True)
class ProductionInputs:
    image: ImmutableImageReference
    dashboard_image: ImmutableImageReference
    endpoint: str
    model: str
    token_source: str
    extension_source: str
    nginx_source: str
    ui_port: int


def _absolute_file_path(raw: str | None, label: str) -> str:
    if raw is None or raw == "" or raw != raw.strip():
        raise ValueError(f"{label} path is missing or invalid")
    path = Path(raw)
    if not path.is_absolute() or path == Path("/"):
        raise ValueError(f"{label} path must be a specific absolute file path")
    return raw


def _ui_port(raw: str | int | None) -> int:
    try:
        value = int(raw if raw is not None else 8000)
    except (TypeError, ValueError):
        raise ValueError("UI port is invalid") from None
    if not 1024 <= value <= 65535:
        raise ValueError("UI port must be between 1024 and 65535 for rootless Podman")
    return value


def validate_inputs(
    image: str | None,
    dashboard_image: str | None,
    endpoint: str | None,
    model: str | None,
    token_source: str | None,
    extension_source: str | None,
    nginx_source: str | None,
    ui_port: str | int | None,
) -> ProductionInputs:
    return ProductionInputs(
        image=parse_immutable_image_reference(image),
        dashboard_image=parse_immutable_image_reference(dashboard_image),
        endpoint=validate_endpoint(endpoint),
        model=validate_model(model),
        token_source=validate_token_source(token_source),
        extension_source=_absolute_file_path(extension_source, "extension manifest"),
        nginx_source=_absolute_file_path(nginx_source, "Nginx configuration"),
        ui_port=_ui_port(ui_port),
    )


def _mapping(value: object, message: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PreflightError(message)
    return value


def _service_networks(service: Mapping[str, Any], name: str) -> set[str]:
    networks = service.get("networks")
    if isinstance(networks, Mapping):
        return set(networks)
    if isinstance(networks, list) and all(isinstance(item, str) for item in networks):
        return set(networks)
    raise PreflightError(f"the {name} network declaration is invalid")


def _mounts(service: Mapping[str, Any], name: str) -> list[Mapping[str, Any]]:
    volumes = service.get("volumes", [])
    if not isinstance(volumes, list) or not all(isinstance(item, Mapping) for item in volumes):
        raise PreflightError(f"the {name} volume declaration is invalid")
    return list(volumes)


def _require_mount(
    service: Mapping[str, Any], name: str, source: str, target: str
) -> Mapping[str, Any]:
    matches = [
        mount
        for mount in _mounts(service, name)
        if mount.get("source") == source and mount.get("target") == target
    ]
    if len(matches) != 1 or matches[0].get("type") != "bind" or matches[0].get(
        "read_only"
    ) is not True:
        raise PreflightError(f"the {name} {target} mount is not a single read-only bind")
    return matches[0]


def analyze_rendered_config(config: Mapping[str, Any], inputs: ProductionInputs) -> None:
    services = _mapping(config.get("services"), "rendered configuration has no services")
    for name in _APP_SERVICES:
        service = _mapping(services.get(name), f"rendered configuration is missing {name}")
        if service.get("image") != inputs.image.reference or service.get("build") not in (
            None,
            "",
            {},
        ):
            raise PreflightError(f"the {name} image is not immutable or has a build fallback")
        if service.get("user") != "10001:10001":
            raise PreflightError(f"the {name} service does not use the fixed non-root identity")
        if service.get("ports") or service.get("privileged") is True:
            raise PreflightError(f"the {name} service exposes an unsafe runtime surface")
        if service.get("read_only") is not True or "ALL" not in service.get("cap_drop", []):
            raise PreflightError(f"the {name} runtime hardening is incomplete")
        if "no-new-privileges:true" not in service.get("security_opt", []):
            raise PreflightError(f"the {name} runtime hardening is incomplete")

    control = _mapping(services["control-plane"], "control-plane is invalid")
    lab = _mapping(services["lab-api"], "lab-api is invalid")
    gateway = _mapping(services["llm-gateway"], "llm-gateway is invalid")
    dashboard = _mapping(services.get("dashboard"), "rendered configuration is missing dashboard")
    if dashboard.get("image") != inputs.dashboard_image.reference:
        raise PreflightError("the dashboard image is not the requested immutable digest")
    if dashboard.get("user") != "101:101" or dashboard.get("read_only") is not True:
        raise PreflightError("the dashboard runtime hardening is incomplete")
    if "ALL" not in dashboard.get("cap_drop", []) or dashboard.get("privileged") is True:
        raise PreflightError("the dashboard runtime hardening is incomplete")
    if "no-new-privileges:true" not in dashboard.get("security_opt", []):
        raise PreflightError("the dashboard runtime hardening is incomplete")

    ports = dashboard.get("ports")
    if not isinstance(ports, list) or len(ports) != 1 or not isinstance(ports[0], Mapping):
        raise PreflightError("the dashboard loopback publication is invalid")
    port = ports[0]
    if (
        port.get("host_ip") != "127.0.0.1"
        or str(port.get("published")) != str(inputs.ui_port)
        or port.get("target") != 8080
        or port.get("protocol") != "tcp"
    ):
        raise PreflightError("the dashboard loopback publication is invalid")

    control_env = _mapping(control.get("environment"), "control-plane environment is invalid")
    gateway_env = _mapping(gateway.get("environment"), "llm-gateway environment is invalid")
    expected_common = {
        "AI_PROVIDER": "internal_openai_compatible",
        "AI_MODEL": inputs.model,
        "AI_ALLOWED_MODELS": inputs.model,
        "EXTENSION_MANIFEST_PATH": "/etc/aegis/extensions/manifest.json",
    }
    if any(control_env.get(key) != value for key, value in expected_common.items()):
        raise PreflightError("the control-plane model or extension binding is invalid")
    expected_gateway = {
        **expected_common,
        "AI_BASE_URL": inputs.endpoint,
        "AI_AUTH_MODE": "bearer",
        "AI_AUTH_TOKEN_FILE": "/run/secrets/aegis-provider-token",
        "AI_USE_EGRESS_PROXY": "false",
    }
    if any(gateway_env.get(key) != value for key, value in expected_gateway.items()):
        raise PreflightError("the llm-gateway provider binding is invalid")
    credential_names = {"AI_AUTH_TOKEN", "AI_AUTH_TOKEN_FILE", "DEEPSEEK_API_KEY"}
    for name, service in (("control-plane", control), ("lab-api", lab)):
        environment = _mapping(service.get("environment", {}), f"{name} environment is invalid")
        if credential_names.intersection(environment):
            raise PreflightError(f"the {name} unexpectedly receives a provider credential")
    if "AI_AUTH_TOKEN" in gateway_env or "DEEPSEEK_API_KEY" in gateway_env:
        raise PreflightError("the provider credential must not be stored in the environment")

    _require_mount(
        gateway, "llm-gateway", inputs.token_source, "/run/secrets/aegis-provider-token"
    )
    _require_mount(
        gateway,
        "llm-gateway",
        inputs.extension_source,
        "/etc/aegis/extensions/manifest.json",
    )
    _require_mount(
        control,
        "control-plane",
        inputs.extension_source,
        "/etc/aegis/extensions/manifest.json",
    )
    _require_mount(dashboard, "dashboard", inputs.nginx_source, "/etc/nginx/nginx.conf")
    if any(
        mount.get("target") == "/run/secrets/aegis-provider-token"
        for service in (control, lab, dashboard)
        for mount in _mounts(service, "non-gateway service")
    ):
        raise PreflightError("the provider credential is mounted outside the llm-gateway")

    expected_networks = {
        "control-plane": {"security-lab", "planner-rpc"},
        "lab-api": {"security-lab"},
        "llm-gateway": {"planner-rpc", "provider-egress"},
        "dashboard": {"dashboard-ingress", "security-lab"},
    }
    for name, expected in expected_networks.items():
        service = _mapping(services[name], f"{name} is invalid")
        if _service_networks(service, name) != expected:
            raise PreflightError(f"the {name} network isolation is invalid")
    networks = _mapping(config.get("networks"), "rendered configuration has no networks")
    target_network = _mapping(networks.get("security-lab"), "security-lab is missing")
    planner_network = _mapping(networks.get("planner-rpc"), "planner-rpc is missing")
    provider_network = _mapping(networks.get("provider-egress"), "provider-egress is missing")
    if target_network.get("internal") is not True:
        raise PreflightError("the target network must be internal")
    if planner_network.get("internal") is not True:
        raise PreflightError("the planner network must be internal")
    if provider_network.get("internal") is True:
        raise PreflightError("the provider egress network is invalid")


def render_production_config(
    inputs: ProductionInputs, engine: ContainerEngine = "podman"
) -> dict[str, Any]:
    engine_bin = shutil.which(engine)
    if engine_bin is None:
        raise PreflightError(f"{engine} is unavailable; the production config cannot be proven")
    env = {
        **os.environ,
        "AEGIS_IMAGE": inputs.image.reference,
        "AEGIS_DASHBOARD_IMAGE": inputs.dashboard_image.reference,
        "AEGIS_PROVIDER_BASE_URL": inputs.endpoint,
        "AEGIS_PROVIDER_MODEL": inputs.model,
        "AEGIS_PROVIDER_TOKEN_SOURCE": inputs.token_source,
        "AEGIS_EXTENSION_MANIFEST_SOURCE": inputs.extension_source,
        "AEGIS_NGINX_CONFIG_SOURCE": inputs.nginx_source,
        "AEGIS_UI_PORT": str(inputs.ui_port),
    }
    argv = [engine_bin, "compose", "-f", str(_COMPOSE_FILE), "config"]
    try:
        completed = subprocess.run(  # noqa: S603 - fixed executable/arguments; never shell=True
            argv,
            capture_output=True,
            text=True,
            env=env,
            timeout=_RENDER_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise PreflightError("rendering the production config timed out") from exc
    except OSError as exc:
        raise PreflightError(f"{engine} could not render the production config") from exc
    if completed.returncode != 0:
        raise PreflightError(f"{engine} compose could not render the production config")
    try:
        rendered = yaml.safe_load(completed.stdout)
    except yaml.YAMLError as exc:
        raise PreflightError("the rendered production config was not valid YAML") from exc
    if not isinstance(rendered, dict):
        raise PreflightError("the rendered production config was not a mapping")
    return rendered


def run_preflight(inputs: ProductionInputs, engine: ContainerEngine) -> None:
    analyze_rendered_config(render_production_config(inputs, engine), inputs)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m aegis.deploy.aegis_ai_prod_preflight",
        description="Validate the standalone rootless Podman Fedora/RHEL production topology.",
    )
    parser.add_argument("--engine", choices=("podman", "docker"), default="podman")
    parser.add_argument("--image", default=os.environ.get("AEGIS_IMAGE"))
    parser.add_argument("--dashboard-image", default=os.environ.get("AEGIS_DASHBOARD_IMAGE"))
    parser.add_argument("--endpoint", default=os.environ.get("AEGIS_PROVIDER_BASE_URL"))
    parser.add_argument("--model", default=os.environ.get("AEGIS_PROVIDER_MODEL"))
    parser.add_argument("--token-source", default=os.environ.get("AEGIS_PROVIDER_TOKEN_SOURCE"))
    parser.add_argument(
        "--extension-source", default=os.environ.get("AEGIS_EXTENSION_MANIFEST_SOURCE")
    )
    parser.add_argument("--nginx-source", default=os.environ.get("AEGIS_NGINX_CONFIG_SOURCE"))
    parser.add_argument("--ui-port", default=os.environ.get("AEGIS_UI_PORT", "8000"))
    args = parser.parse_args(argv)
    try:
        inputs = validate_inputs(
            args.image,
            args.dashboard_image,
            args.endpoint,
            args.model,
            args.token_source,
            args.extension_source,
            args.nginx_source,
            args.ui_port,
        )
    except (ImageReferenceError, ValueError) as exc:
        print(f"AEGIS AI PROD PREFLIGHT FAILED (input): {exc}")
        return EXIT_BAD_INPUT
    try:
        run_preflight(inputs, args.engine)
    except PreflightError as exc:
        print(f"AEGIS AI PROD PREFLIGHT FAILED (rendered config): {exc}")
        return EXIT_RENDER_FAILED
    print("AEGIS AI PROD PREFLIGHT OK")
    print(f"  application : {inputs.image.digest}")
    print(f"  dashboard   : {inputs.dashboard_image.digest}")
    print(f"  engine      : {args.engine} compose")
    print("  ingress     : loopback only")
    print("  extensions  : declarative, read-only, catalog-authority preserved")
    print("  note        : image pull, provider reachability and live traffic were not performed")
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
