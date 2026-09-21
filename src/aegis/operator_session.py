"""Minimal server-side local operator sessions for active-scan control."""

from __future__ import annotations

import hmac
import secrets
import threading
from datetime import UTC, datetime, timedelta


class OperatorSessionStore:
    """Opaque, HttpOnly-cookie sessions; browser input never supplies an operator identity."""

    def __init__(self, bootstrap_secret: str, ttl_seconds: int = 900) -> None:
        if len(bootstrap_secret.encode()) < 32:
            raise ValueError("operator bootstrap secret unavailable")
        self._secret = bootstrap_secret.encode()
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._sessions: dict[str, tuple[str, datetime]] = {}

    def login(self, supplied: str, *, operator_id: str = "local-operator") -> tuple[str, str]:
        if not hmac.compare_digest(supplied.encode(), self._secret):
            raise PermissionError("operator authentication failed")
        session_id, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self._lock:
            self._prune()
            self._sessions[session_id] = (csrf, datetime.now(UTC) + timedelta(seconds=self._ttl))
        return session_id, csrf

    def validate(
        self, session_id: str | None, csrf: str | None = None, *, mutate: bool = False
    ) -> bool:
        if not session_id:
            return False
        with self._lock:
            self._prune()
            entry = self._sessions.get(session_id)
            if entry is None:
                return False
            token, _ = entry
            return not mutate or (csrf is not None and hmac.compare_digest(csrf, token))

    def revoke(self, session_id: str | None) -> None:
        if session_id:
            with self._lock:
                self._sessions.pop(session_id, None)

    def _prune(self) -> None:
        now = datetime.now(UTC)
        self._sessions = {sid: value for sid, value in self._sessions.items() if value[1] > now}
