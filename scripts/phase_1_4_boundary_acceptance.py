#!/usr/bin/env python3
"""Destructive-in-sandbox Phase 1.4 boundary controls.

Run inside the control-plane container after the primary matrix is idle. These deterministic
commands are negative boundary controls only; they are never used as primary attack scenarios.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import threading
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4


def post(url: str, payload: dict[str, Any], token: str) -> tuple[int, dict[str, Any]]:
    request = urllib.request.Request(  # noqa: S310 - fixed internal supervisor RPC
        url,
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Beast-Supervisor-Token": token,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:  # noqa: S310
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return exc.code, {"detail": "NON_JSON_ERROR"}


def resources(**overrides: Any) -> dict[str, Any]:
    value = {
        "total_wall_time_seconds": 180,
        "per_command_timeout_seconds": 20,
        "max_commands": 20,
        "max_target_connections": 40,
        "max_request_rate_per_second": 4,
        "max_concurrency": 2,
        "max_transmitted_bytes": 262_144,
        "max_received_bytes": 1_048_576,
        "max_processes": 32,
        "max_open_files": 64,
        "cpu_quota": 1.0,
        "memory_bytes": 268_435_456,
        "writable_disk_bytes": 33_554_432,
        "stdout_stderr_bytes": 65_536,
        "artifact_bytes": 4_194_304,
    }
    value.update(overrides)
    return value


class Session:
    def __init__(self, base: str, token: str, *, output_limit: int = 65_536) -> None:
        self.base = base.rstrip("/")
        self.token = token
        self.run_id = f"boundary-{uuid4().hex[:16]}"
        self.output_limit = output_limit
        self.sequence = 0
        self.results: list[dict[str, Any]] = []
        status, body = post(
            self.base + "/v1/sessions",
            {
                "run_id": self.run_id,
                "target_origin": "http://beast-target:8080",
                "allowed_path_prefix": "/lab/beast/vulnerable",
                "allowed_methods": ["GET", "HEAD", "OPTIONS"],
                "resources": resources(stdout_stderr_bytes=output_limit),
            },
            token,
        )
        assert status == 200 and body["ready"] is True, (status, body)

    def command(self, text: str, *, timeout: int = 10) -> dict[str, Any]:
        self.sequence += 1
        status, body = post(
            self.base + "/v1/commands",
            {
                "command_id": f"cmd-{self.run_id}-{self.sequence:03d}",
                "parent_command_id": (
                    None if self.sequence == 1 else f"cmd-{self.run_id}-{self.sequence - 1:03d}"
                ),
                "run_id": self.run_id,
                "sequence": self.sequence,
                "shell": "/bin/bash",
                "command_text": text,
                "working_directory_reference": f"workspace:{self.run_id}",
                "timeout_seconds": timeout,
                "output_limit_bytes": self.output_limit,
                "artifact_limit_bytes": 4_194_304,
                "expected_intent": "Phase 1.4 deterministic sandbox boundary control",
                "hypothesis_reference": "The immutable sandbox boundary contains this operation",
            },
            self.token,
        )
        assert status == 200, (status, body)
        self.results.append(body)
        return body

    def destroy(self) -> dict[str, Any]:
        status, body = post(self.base + f"/v1/runs/{self.run_id}/destroy", {}, self.token)
        assert status == 200 and body["destroyed"] is True, (status, body)
        return body


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--supervisor-url", default=os.environ.get("BEAST_SUPERVISOR_URL", ""))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    token = os.environ.get("BEAST_SUPERVISOR_TOKEN", "")
    assert args.supervisor_url and token
    results: dict[str, Any] = {}

    session = Session(args.supervisor_url, token, output_limit=4096)
    checks = {
        "unprivileged_identity": "test \"$(id -u)\" = 65532 && test \"$(id -g)\" = 65532",
        "host_filesystem": "test ! -e /host && test ! -e /Users/efe",
        "docker_socket": "test ! -S /var/run/docker.sock && test ! -S /run/docker.sock",
        "supervisor_separation": (
            "! kill -TERM 1 2>/dev/null && ! grep -a BEAST_SUPERVISOR_TOKEN "
            "/proc/1/environ 2>/dev/null && ! touch /opt/aegis/supervisor-write 2>/dev/null"
        ),
        "public_internet": "! curl -fsS --connect-timeout 2 http://example.com/",
        "public_dns": "! getent hosts example.com",
        "control_plane": "! curl -fsS --connect-timeout 2 http://10.213.47.10:8000/health",
        "llm_gateway": "! curl -fsS --connect-timeout 2 http://llm-gateway:8080/health",
        "ollama": "! curl -fsS --connect-timeout 2 http://host.docker.internal:11434/api/tags",
        "alternate_lab": "! curl -fsS --connect-timeout 2 http://lab-api:8001/health",
        "audit_store": "test ! -e /data/aegis.db && ! mkdir /data 2>/dev/null",
        "network_policy": "! ip route add 203.0.113.0/24 via 10.214.48.1 2>/dev/null",
        "workspace_only": (
            "touch workspace-ok && test -f workspace-ok && ! touch /tmp/nope 2>/dev/null"
        ),
        "exact_target": "curl -fsS \"$BEAST_TARGET$BEAST_TARGET_BASE_PATH\" >/dev/null",
        "path_scope": (
            "test \"$(curl -sS -o /dev/null -w '%{http_code}' "
            "\"$BEAST_TARGET/lab/beast/patched\")\" = 403"
        ),
        "method_scope": (
            "test \"$(curl -sS -o /dev/null -w '%{http_code}' -X POST "
            "\"$BEAST_TARGET$BEAST_TARGET_BASE_PATH\")\" = 403"
        ),
        "supervisor_auth": (
            "test \"$(curl -sS -o /dev/null -w '%{http_code}' -X POST "
            "http://127.0.0.1:8094/v1/runs/x/stop)\" = 403"
        ),
    }
    for name, command in checks.items():
        result = session.command(command)
        assert result["exit_code"] == 0 and not result["timed_out"], (name, result)
        results[name] = result

    detached = session.command("setsid sh -c 'sleep 60' >/dev/null 2>&1 & echo $!")
    assert detached["exit_code"] == 0
    no_survivor = session.command("! pgrep -u 65532 -x sleep >/dev/null")
    assert no_survivor["exit_code"] == 0
    results["background_process_killed"] = {"launch": detached, "probe": no_survivor}

    exhausted = session.command(
        "python3 -c \"import subprocess,time; p=[]; "
        "[(p.append(subprocess.Popen(['sleep','2']))) for _ in range(80)]; time.sleep(0.2)\"",
        timeout=8,
    )
    assert exhausted["exit_code"] != 0 or exhausted["terminated"]
    results["process_exhaustion_contained"] = exhausted

    output = session.command("python3 -c \"print('X'*20000)\"")
    assert output["output_truncated"] is True
    assert len(output["stdout"].encode()) + len(output["stderr"].encode()) <= 4096
    results["oversized_output_contained"] = output

    artifacts = session.command(
        "printf safe > good.txt; printf '#!/bin/sh\\nexit 0\\n' > bad.sh; chmod +x bad.sh; "
        "printf '%s' '-----BEGIN PRIVATE KEY-----' > secret.txt"
    )
    assert artifacts["exit_code"] == 0
    destroyed = session.destroy()
    dispositions = {
        item["reference"]: item["disposition"]
        for item in destroyed["artifacts"]
        if "reference" in item
    }
    assert dispositions["artifact:good.txt"] == "ADMITTED"
    assert dispositions["artifact:bad.sh"] == "REJECTED"
    assert dispositions["artifact:secret.txt"] == "REJECTED"
    network = next(
        item["network_boundary"]
        for item in destroyed["artifacts"]
        if "network_boundary" in item
    )
    blocked_reasons = {item["reason"] for item in network["blocked"]}
    assert {"PATH_OUTSIDE_EXACT_TARGET_SCOPE", "METHOD_OUTSIDE_TARGET_SCOPE"} <= blocked_reasons
    results["artifact_admission_and_destroy"] = destroyed

    persistence = Session(args.supervisor_url, token)
    probe = persistence.command("test ! -e workspace-ok && test ! -e good.txt")
    assert probe["exit_code"] == 0
    results["no_persistence"] = {"probe": probe, "destroy": persistence.destroy()}

    emergency = Session(args.supervisor_url, token)
    holder: dict[str, Any] = {}

    def long_command() -> None:
        holder["result"] = emergency.command(
            "setsid sh -c 'sleep 60' >/dev/null 2>&1 & sleep 60", timeout=60
        )

    thread = threading.Thread(target=long_command, daemon=True)
    thread.start()
    time.sleep(1)
    stopped = emergency.destroy()
    thread.join(timeout=15)
    assert not thread.is_alive()
    assert stopped["destroyed"] is True
    assert holder["result"]["terminated"] is True
    final = Session(args.supervisor_url, token)
    survivor = final.command("! pgrep -u 65532 -x sleep >/dev/null")
    assert survivor["exit_code"] == 0
    results["emergency_stop_process_tree"] = {
        "command": holder["result"],
        "destroy": stopped,
        "survivor_probe": survivor,
        "final_destroy": final.destroy(),
    }

    invalid_status, invalid = post(
        args.supervisor_url.rstrip("/") + "/v1/sessions",
        {
            "run_id": f"invalid-{uuid4().hex[:8]}",
            "target_origin": "http://beast-target:8080",
            "allowed_path_prefix": "/lab/beast/vulnerable",
            "allowed_methods": ["GET", "HEAD", "OPTIONS"],
            "resources": resources(max_processes=65),
        },
        token,
    )
    assert invalid_status == 422
    results["budget_expansion_rejected"] = invalid

    artifact = {
        "phase": "1.4",
        "verdict": "GO",
        "generated_at": datetime.now(UTC).isoformat(),
        "profile_id": "BEAST_ADVERSARY_SANDBOX_V1",
        "controls": results,
    }
    rendered = json.dumps(artifact, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered)
        args.output.with_suffix(args.output.suffix + ".sha256").write_text(
            f"{hashlib.sha256(rendered.encode()).hexdigest()}  {args.output.name}\n"
        )
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
