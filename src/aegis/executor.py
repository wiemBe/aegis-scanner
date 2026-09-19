import json
import re
import time
from typing import Any

import httpx

from aegis.http import bounded_body
from aegis.models import PlannedRequest, RequestEvidence
from aegis.safety import SafetyController
from aegis.settings import Settings
from aegis.surface import Variant

SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "token",
    "access_token",
    "refresh_token",
    "password",
    "secret",
    "api_key",
    "apikey",
    "client_secret",
}


def redact(value: Any, secrets: tuple[str, ...] = (), depth: int = 0) -> Any:
    if depth > 12:
        return "[DEPTH_LIMIT]"
    if isinstance(value, dict):
        return {
            str(redact(str(key), secrets)): "[REDACTED]"
            if str(key).lower() in SENSITIVE_KEYS
            else redact(item, secrets, depth + 1)
            for key, item in list(value.items())[:40]
        }
    if isinstance(value, list):
        return [redact(item, secrets, depth + 1) for item in value[:20]]
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(secret, "[REDACTED]")
        return re.sub(r"(?i)bearer\s+[^\s\"']+", "Bearer [REDACTED]", value)[:1000]
    return value


class TestExecutor:
    def __init__(
        self,
        settings: Settings,
        safety: SafetyController,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self.safety = safety
        self.transport = transport

    async def execute_one(
        self,
        base_url: str,
        request: PlannedRequest,
        variant: Variant,
    ) -> RequestEvidence:
        url = self.safety.approve_request(base_url, request, variant)
        headers = {"User-Agent": "Aegis-AI-Security-Lab/0.2"}
        if request.credential_profile != "anonymous":
            headers["Authorization"] = (
                f"Bearer {self.settings.credentials[request.credential_profile]}"
            )
        started = time.monotonic()
        status: int | None = None
        body: dict[str, Any] | str | None = None
        error: str | None = None
        try:
            async with (
                httpx.AsyncClient(
                    timeout=self.settings.request_timeout_seconds,
                    follow_redirects=False,
                    trust_env=False,
                    transport=self.transport,
                ) as client,
                client.stream(request.method, url, headers=headers) as response,
            ):
                status = response.status_code
                raw = await bounded_body(response, self.settings.max_response_bytes)
            try:
                parsed = json.loads(raw)
            except ValueError:
                parsed = raw.decode("utf-8", errors="replace")
            cleaned = redact(parsed, tuple(self.settings.credentials.values()))
            body = cleaned if isinstance(cleaned, dict | str) else "[NON_OBJECT_RESPONSE]"
        except (httpx.HTTPError, ValueError) as exc:
            error = type(exc).__name__
        return RequestEvidence(
            name=request.name,
            method=request.method,
            path=request.path,
            credential_profile=request.credential_profile,
            status_code=status,
            duration_ms=round((time.monotonic() - started) * 1000),
            response_excerpt=body,
            error=error,
        )
