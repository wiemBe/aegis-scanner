#!/usr/bin/env python3
"""Phase 1.3 reachability probe, executed INSIDE the zap-runner or zap-scope-guard container.

    docker exec -i <container> python3 - <role> < scripts/zap_topology_probe.py

Standard library only (it runs on the Python 3.11 of the pinned ZAP image and the Python 3.12 of
the guard image). For each destination it records whether DNS resolved and whether a TCP connection
succeeded within three seconds, and prints one JSON document. It sends no application data.
"""

from __future__ import annotations

import json
import os
import socket
import sys

DESTINATIONS: dict[str, list[tuple[str, str, int]]] = {
    "zap-runner": [
        ("synthetic_target_direct", "lab-api", 8001),
        ("scope_guard_proxy", "zap-scope-guard", 3128),
        ("scope_guard_control", "zap-scope-guard", 3129),
        ("control_plane_listener_by_name", "control-plane", 8000),
        ("control_plane_listener_by_ip", "10.213.47.10", 8000),
        ("nuclei_runner", "nuclei-runner", 8090),
        ("llm_gateway", "llm-gateway", 8080),
        ("ollama_host", "host.docker.internal", 11434),
        ("dashboard", "dashboard", 8080),
        ("public_ip", "1.1.1.1", 443),
        ("public_dns_name", "example.com", 443),
    ],
    "zap-scope-guard": [
        ("synthetic_target", "lab-api", 8001),
        ("control_plane_listener_by_name", "control-plane", 8000),
        ("control_plane_listener_by_ip", "10.213.47.10", 8000),
        ("nuclei_runner", "nuclei-runner", 8090),
        ("llm_gateway", "llm-gateway", 8080),
        ("ollama_host", "host.docker.internal", 11434),
        ("public_ip", "1.1.1.1", 443),
        ("public_dns_name", "example.com", 443),
    ],
}


def probe(host: str, port: int) -> str:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        return f"BLOCKED:{type(exc).__name__}"
    for family, kind, proto, _, address in infos:
        with socket.socket(family, kind, proto) as sock:
            sock.settimeout(3)
            try:
                sock.connect(address)
            except OSError as exc:
                last = f"BLOCKED:{type(exc).__name__}"
                continue
            return "REACHABLE"
    return last


def main() -> int:
    role = sys.argv[1] if len(sys.argv) > 1 else ""
    if role not in DESTINATIONS:
        raise SystemExit("role must be zap-runner or zap-scope-guard")
    result = {
        "role": role,
        "uid": os.getuid(),
        "docker_socket_present": os.path.exists("/var/run/docker.sock"),
        "shell_present": any(os.path.exists(p) for p in ("/bin/sh", "/bin/bash", "/usr/bin/sh")),
        "root_filesystem_writable": os.access("/", os.W_OK),
        "results": {name: probe(host, port) for name, host, port in DESTINATIONS[role]},
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
