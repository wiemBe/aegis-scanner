"""Scanner-network smoke: public origins work; control and canary names do not."""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request

ORIGINS = {
    "aegis-bank": "http://aegis-bank:8101",
    "aegis-shop": "http://aegis-shop:8102",
    "aegis-ops": "http://aegis-ops:8103",
    "aegis-cloud": "http://aegis-cloud:8104",
}


def get_status(url: str) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(url, timeout=3) as response:  # noqa: S310 - fixed inventory
            return response.status, response.read(131_072)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(131_072)


def main() -> None:
    checks = 0
    for application_id, origin in ORIGINS.items():
        health_status, _ = get_status(origin + "/health")
        openapi_status, openapi_body = get_status(origin + "/openapi.json")
        control_status, _ = get_status(origin + "/__control/health")
        if (
            health_status != 200
            or openapi_status != 200
            or b'"openapi":"3.1.0"' not in openapi_body.replace(b" ", b"")
        ):
            raise SystemExit(f"public surface failed: {application_id}")
        if control_status != 404:
            raise SystemExit(f"management path exposed: {application_id}")
        checks += 3
    for forbidden_host in (
        "range-controller",
        "range-canary",
        "aegis-bank-control",
        "aegis-shop-control",
        "aegis-ops-control",
        "aegis-cloud-control",
        "aegis-bank-core",
        "aegis-shop-core",
        "aegis-ops-core",
        "aegis-cloud-core",
        "aegis-shop-view",
        "ops-worker",
        "ops-worker-control",
        "shop-browser",
        "shop-effect-canary",
        "shop-effect-canary-control",
        "cloud-admin",
    ):
        try:
            socket.getaddrinfo(forbidden_host, None)
        except socket.gaierror:
            checks += 1
        else:
            raise SystemExit(f"forbidden scanner-network name resolved: {forbidden_host}")
    print(json.dumps({"status": "PASS", "checks": checks}, sort_keys=True))


if __name__ == "__main__":
    main()
