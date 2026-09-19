from __future__ import annotations

import hashlib
from typing import Any

import httpx

from aegis.beast.contracts import BeastTarget


class BeastVerifier:
    """Fresh, deterministic verifier. Model and shell prose never determine the conclusion."""

    def __init__(self, lab_origin: str, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.lab_origin = lab_origin.rstrip("/")
        self.transport = transport

    async def health(self, target: BeastTarget) -> dict[str, Any]:
        """Prove the immutable fixture is reachable before clearing an operator-review block."""
        url = self.lab_origin + target.base_path
        async with httpx.AsyncClient(
            timeout=5, follow_redirects=False, trust_env=False, transport=self.transport
        ) as client:
            response = await client.get(url)
        body = response.content[:65_536]
        healthy = response.status_code == 200 and b"Disposable Synthetic Bank API" in body
        return {
            "authority": "DETERMINISTIC_VERIFIER",
            "healthy": healthy,
            "status_code": response.status_code,
            "evidence_sha256": hashlib.sha256(body).hexdigest(),
        }

    async def verify(self, target: BeastTarget, scenario_id: str) -> dict[str, Any]:
        url = self.lab_origin + target.base_path
        async with httpx.AsyncClient(
            timeout=5, follow_redirects=False, trust_env=False, transport=self.transport
        ) as client:
            if scenario_id == "endpoint_discovery":
                response = await client.get(url + "/openapi.json")
                body = response.content[:131_072]
                document = response.json() if response.status_code == 200 else {}
                paths = sorted((document.get("paths") or {}).keys())
                complete = any("accounts" in p for p in paths) and any("search" in p for p in paths)
                return self._result(
                    "VERIFIED" if complete else "INCOMPLETE",
                    scenario_id,
                    response.status_code,
                    body,
                    {"path_count": len(paths), "surface_complete": complete},
                )
            if scenario_id == "information_exposure":
                response = await client.get(url + "/.git/config")
                body = response.content[:131_072]
                exposed = response.status_code == 200 and b"SYNTHETIC AEGIS LAB FIXTURE" in body
                patched = response.status_code in {403, 404} and not exposed
                return self._result(
                    "CONFIRMED" if exposed else "PASS" if patched else "INCOMPLETE",
                    scenario_id,
                    response.status_code,
                    body,
                    {"synthetic_metadata_exposed": exposed},
                )
            if scenario_id == "bola_readonly":
                headers = {"Authorization": "Bearer lab-token-user-a"}
                owner = await client.get(url + "/accounts/A-100", headers=headers)
                cross = await client.get(url + "/accounts/B-200", headers=headers)
                owner_body, cross_body = owner.content[:65_536], cross.content[:65_536]
                cross_owner = False
                if cross.status_code == 200:
                    try:
                        cross_owner = cross.json().get("owner_id") == "user-b"
                    except (ValueError, AttributeError):
                        cross_owner = False
                confirmed = owner.status_code == 200 and cross_owner
                patched = owner.status_code == 200 and cross.status_code == 403
                return self._result(
                    "CONFIRMED" if confirmed else "PASS" if patched else "INCOMPLETE",
                    scenario_id,
                    cross.status_code,
                    owner_body + b"\n" + cross_body,
                    {
                        "owner_control_status": owner.status_code,
                        "cross_owner_status": cross.status_code,
                        "cross_owner_identity_proved": cross_owner,
                    },
                )
            if scenario_id == "safe_injection":
                baseline = await client.get(url + "/search", params={"q": "synthetic"})
                probe = await client.get(url + "/search", params={"q": "' OR '1'='1"})
                baseline_body, probe_body = baseline.content[:65_536], probe.content[:65_536]
                marker = b"SYNTHETIC_SQL_INJECTION_CONFIRMED"
                confirmed = (
                    baseline.status_code == 200
                    and probe.status_code == 200
                    and marker not in baseline_body
                    and marker in probe_body
                )
                patched = (
                    baseline.status_code == 200
                    and probe.status_code == 200
                    and marker not in baseline_body
                    and marker not in probe_body
                )
                return self._result(
                    "CONFIRMED" if confirmed else "PASS" if patched else "INCOMPLETE",
                    scenario_id,
                    probe.status_code,
                    baseline_body + b"\n" + probe_body,
                    {
                        "baseline_clean": marker not in baseline_body,
                        "probe_marker": marker in probe_body,
                    },
                )
        return {"status": "INCOMPLETE", "reason": "UNSUPPORTED_SCENARIO"}

    def _result(
        self,
        status: str,
        scenario_id: str,
        status_code: int,
        evidence: bytes,
        facts: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "authority": "DETERMINISTIC_VERIFIER",
            "status": status,
            "scenario_id": scenario_id,
            "fresh_probe": True,
            "status_code": status_code,
            "evidence_sha256": hashlib.sha256(evidence).hexdigest(),
            "evidence_bytes": len(evidence),
            "facts": facts,
        }
