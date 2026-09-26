"""Fail-closed production deployment preflight (WP2 / G-ROLL-1).

Operator entry point::

    export AEGIS_IMAGE=registry.example.com/aegis@sha256:<64-hex>
    python -m aegis.deploy.preflight

It performs two mandatory, fail-closed checks and refuses the deployment path unless **both** pass:

1. **Reference validation** — ``AEGIS_IMAGE`` must be an immutable, fully-qualified ``sha256``
   digest reference (:func:`aegis.deploy.image_reference.parse_immutable_image_reference`). Exit
   ``2`` on any violation.
2. **Rendered-configuration proof** — the merged production Compose configuration
   (``docker-compose.yml`` + ``docker-compose.prod.yml``) is *always* rendered and analyzed: both
   long-lived services must use exactly that digest and carry no active local ``build:`` fallback.
   There is **no bypass**. Missing Docker, missing Compose support, a timeout, a render failure,
   invalid JSON, or ambiguous output all fail closed with exit ``3``.

The preflight only ever renders configuration; it never pulls the image (runtime digest pull is out
of scope / NOT_EVALUATED here) and never reads, requires, or emits a registry or provider secret.
All diagnostics are fixed, credential-free strings — raw Compose stderr and raw exceptions are never
printed.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess  # noqa: S404 - fixed, trusted docker/compose argv; never shell=True, no user input
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from aegis.deploy.image_reference import (
    ImageReferenceError,
    ImmutableImageReference,
    parse_immutable_image_reference,
)

IMAGE_ENV_VAR = "AEGIS_IMAGE"
PRODUCTION_SERVICES: tuple[str, ...] = ("control-plane", "lab-api")
_RENDER_TIMEOUT_SECONDS = 60

_REPO_ROOT = Path(__file__).resolve().parents[3]
BASE_COMPOSE_FILE = _REPO_ROOT / "docker-compose.yml"
PRODUCTION_COMPOSE_FILE = _REPO_ROOT / "docker-compose.prod.yml"

EXIT_OK = 0
EXIT_BAD_REFERENCE = 2
EXIT_RENDER_FAILED = 3


class PreflightError(RuntimeError):
    """A production preflight check failed; the deployment path must not proceed (fail closed)."""


def analyze_rendered_config(config: Mapping[str, Any], expected_reference: str) -> None:
    """Raise :class:`PreflightError` unless the rendered config pins the digest with no build.

    Every service in :data:`PRODUCTION_SERVICES` must be present, must set ``image`` to exactly
    ``expected_reference``, and must carry no ``build`` key (a mutable local-build fallback). Any
    deviation fails closed. Diagnostics name only the fixed service constant, never rendered values.
    """

    services = config.get("services")
    if not isinstance(services, Mapping):
        raise PreflightError("rendered configuration has no services section")
    for service_name in PRODUCTION_SERVICES:
        service = services.get(service_name)
        if not isinstance(service, Mapping):
            raise PreflightError(f"rendered configuration is missing service {service_name}")
        if "build" in service and service["build"] not in (None, "", {}):
            raise PreflightError(
                f"the {service_name} service still has an active build fallback in production"
            )
        if service.get("image") != expected_reference:
            raise PreflightError(
                f"the {service_name} service image does not match the required immutable digest"
            )


def render_production_config(reference: str) -> dict[str, Any]:
    """Render the merged production Compose configuration as a dict.

    Runs ``docker compose -f <base> -f <prod> config`` with ``AEGIS_IMAGE`` set to ``reference``;
    the image is never pulled. Any failure — Docker/Compose unavailable, timeout, non-zero exit,
    invalid JSON, or ambiguous output — raises :class:`PreflightError` with a fixed, credential-free
    message (raw Compose stderr and raw exception text are never surfaced).
    """

    docker_bin = shutil.which("docker")
    if docker_bin is None:
        raise PreflightError("docker is unavailable; cannot render and prove the production config")
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
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, no user-controlled tokens
            argv,
            capture_output=True,
            text=True,
            env=env,
            timeout=_RENDER_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise PreflightError("rendering the production configuration timed out") from exc
    except OSError as exc:  # docker binary vanished / not executable
        raise PreflightError("docker could not be executed to render the config") from exc
    if completed.returncode != 0:
        raise PreflightError(
            "docker compose could not render the production configuration "
            "(Compose support missing or the configuration is invalid)"
        )
    try:
        rendered = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise PreflightError("the rendered production configuration was not valid JSON") from exc
    if not isinstance(rendered, dict):
        raise PreflightError("the rendered production configuration was not a mapping")
    return rendered


def run_preflight(raw_reference: str | None) -> tuple[ImmutableImageReference, str]:
    """Validate the reference and prove the rendered config. Fail closed on any error.

    Returns the validated reference and a fixed proof description. Raises
    :class:`aegis.deploy.image_reference.ImageReferenceError` for a bad reference and
    :class:`PreflightError` for any render/analysis failure. Rendering is unconditional — there is
    no NOT_EVALUATED success path.
    """

    reference = parse_immutable_image_reference(raw_reference)
    config = render_production_config(reference.reference)
    analyze_rendered_config(config, reference.reference)
    proof = (
        f"rendered production config pins {', '.join(PRODUCTION_SERVICES)} to the exact digest "
        "with no active build fallback"
    )
    return reference, proof


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m aegis.deploy.preflight",
        description=(
            "Fail-closed production deployment preflight: validate the immutable image digest and "
            "always prove, from the rendered production Compose configuration, that both "
            "long-lived services use exactly that digest with no build fallback. No render bypass."
        ),
    )
    parser.add_argument(
        "--image",
        default=os.environ.get(IMAGE_ENV_VAR),
        help=f"immutable image reference (default: ${IMAGE_ENV_VAR})",
    )
    args = parser.parse_args(argv)

    try:
        reference, proof = run_preflight(args.image)
    except ImageReferenceError as exc:
        print(f"PREFLIGHT FAILED (image reference): {exc}")
        return EXIT_BAD_REFERENCE
    except PreflightError as exc:
        print(f"PREFLIGHT FAILED (rendered config): {exc}")
        return EXIT_RENDER_FAILED

    print("PREFLIGHT OK")
    print(f"  image digest : {reference.digest}")
    print(f"  services     : {', '.join(PRODUCTION_SERVICES)}")
    print(f"  render proof : {proof}")
    print("  note         : runtime digest pull is NOT_EVALUATED (never performed here)")
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
