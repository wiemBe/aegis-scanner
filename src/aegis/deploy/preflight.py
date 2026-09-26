"""Fail-closed production deployment preflight (WP2 / G-ROLL-1).

Operator entry point::

    export AEGIS_IMAGE=registry.example.com/aegis@sha256:<64-hex>
    python -m aegis.deploy.preflight

It performs two independent, fail-closed checks and refuses the deployment path if either cannot be
positively confirmed:

1. **Reference validation** — ``AEGIS_IMAGE`` must be an immutable ``sha256`` digest reference
   (:func:`aegis.deploy.image_reference.parse_immutable_image_reference`). A missing, tag-only,
   ``latest``, malformed, or non-``sha256`` reference is rejected before anything else happens.
2. **Rendered-configuration proof** — the merged production Compose configuration
   (``docker-compose.yml`` + ``docker-compose.prod.yml``) must use *exactly* that digest for both
   long-lived services and must contain no active local ``build:`` fallback. This is proven from the
   configuration Compose actually renders, not from parsing YAML by hand.

The preflight never pulls the image (runtime digest pull is out of scope / NOT_EVALUATED here) and
never reads, requires, or emits a registry or provider credential.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess  # noqa: S404 - fixed, trusted docker/compose argv; never shell=True, no user input
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegis.deploy.image_reference import (
    ImageReferenceError,
    ImmutableImageReference,
    parse_immutable_image_reference,
)

IMAGE_ENV_VAR = "AEGIS_IMAGE"
PRODUCTION_SERVICES: tuple[str, ...] = ("control-plane", "lab-api")

_REPO_ROOT = Path(__file__).resolve().parents[3]
BASE_COMPOSE_FILE = _REPO_ROOT / "docker-compose.yml"
PRODUCTION_COMPOSE_FILE = _REPO_ROOT / "docker-compose.prod.yml"


class PreflightError(RuntimeError):
    """A production preflight check failed; the deployment path must not proceed (fail closed)."""


@dataclass(frozen=True)
class RenderProof:
    """The outcome of the rendered-configuration proof."""

    evaluated: bool
    detail: str


def analyze_rendered_config(config: Mapping[str, Any], expected_reference: str) -> None:
    """Raise :class:`PreflightError` unless the rendered config pins the digest with no build.

    Every service in :data:`PRODUCTION_SERVICES` must be present, must set ``image`` to exactly
    ``expected_reference``, and must carry no ``build`` key (a mutable local-build fallback). Any
    deviation fails closed.
    """

    services = config.get("services")
    if not isinstance(services, Mapping):
        raise PreflightError("rendered configuration has no services section")
    for service_name in PRODUCTION_SERVICES:
        service = services.get(service_name)
        if not isinstance(service, Mapping):
            raise PreflightError(f"rendered configuration is missing service {service_name!r}")
        if "build" in service and service["build"] not in (None, "", {}):
            raise PreflightError(
                f"service {service_name!r} still has an active build fallback in production: "
                f"{service['build']!r}"
            )
        image = service.get("image")
        if image != expected_reference:
            raise PreflightError(
                f"service {service_name!r} image {image!r} does not match the required immutable "
                f"reference {expected_reference!r}"
            )


def _compose_available() -> bool:
    return shutil.which("docker") is not None


def render_production_config(reference: str) -> dict[str, Any]:
    """Render the merged production Compose configuration as a dict (requires Docker Compose).

    Runs ``docker compose -f <base> -f <prod> config`` with ``AEGIS_IMAGE`` set to ``reference``.
    The image is never pulled. Raises :class:`PreflightError` if Compose cannot render the config.
    """

    docker_bin = shutil.which("docker")
    if docker_bin is None:
        raise PreflightError("docker is not available to render the production configuration")
    env = {**os.environ, IMAGE_ENV_VAR: reference}
    argv: list[str] = [
        docker_bin,
        "compose",
        "-f",
        str(BASE_COMPOSE_FILE),
        "-f",
        str(PRODUCTION_COMPOSE_FILE),
        "config",
        "--format",
        "json",
    ]
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, no user-controlled tokens
        argv,
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        raise PreflightError(
            "docker compose could not render the production configuration "
            f"(exit {completed.returncode}): {completed.stderr.strip()[:200]}"
        )
    try:
        rendered = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive
        raise PreflightError(f"rendered configuration is not valid JSON: {exc}") from exc
    if not isinstance(rendered, dict):
        raise PreflightError("rendered configuration is not a mapping")
    return rendered


def run_preflight(
    *, raw_reference: str | None, render: bool
) -> tuple[ImmutableImageReference, RenderProof]:
    """Validate the reference and, optionally, prove the rendered config. Fail closed on error."""

    reference = parse_immutable_image_reference(raw_reference)
    if not render:
        return reference, RenderProof(
            evaluated=False,
            detail="rendered-config proof NOT_EVALUATED (docker unavailable or --no-render)",
        )
    config = render_production_config(reference.reference)
    analyze_rendered_config(config, reference.reference)
    return reference, RenderProof(
        evaluated=True,
        detail=(
            f"rendered production config pins {', '.join(PRODUCTION_SERVICES)} to the exact digest "
            "with no active build fallback"
        ),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m aegis.deploy.preflight",
        description=(
            "Fail-closed production deployment preflight: validate the immutable image digest and "
            "prove the rendered production Compose configuration pins it with no build fallback."
        ),
    )
    parser.add_argument(
        "--image",
        default=os.environ.get(IMAGE_ENV_VAR),
        help=f"immutable image reference (default: ${IMAGE_ENV_VAR})",
    )
    parser.add_argument(
        "--no-render",
        action="store_true",
        help="validate the reference only; skip the rendered-config proof",
    )
    args = parser.parse_args(argv)

    render = not args.no_render and _compose_available()
    try:
        reference, proof = run_preflight(raw_reference=args.image, render=render)
    except ImageReferenceError as exc:
        print(f"PREFLIGHT FAILED (image reference): {exc}")
        return 2
    except PreflightError as exc:
        print(f"PREFLIGHT FAILED (rendered config): {exc}")
        return 3

    print("PREFLIGHT OK")
    print(f"  image digest : {reference.digest}")
    print(f"  services     : {', '.join(PRODUCTION_SERVICES)}")
    print(f"  render proof : {proof.detail}")
    if not proof.evaluated:
        print("  note         : runtime digest pull is NOT_EVALUATED (never performed here)")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
