"""Fail-closed metadata and local storage boundary for future browser screenshots.

Browser capture is intentionally inactive in Phase 1.0.  The store is nevertheless complete enough
to validate and persist an already-redacted artifact from a future approved runner.  It cannot read
arbitrary paths and it never exposes bytes to the planner.
"""

from __future__ import annotations

import hashlib
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, Self
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ALLOWED_MIME = {"image/png": ".png", "image/webp": ".webp"}
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
WEBP_PREFIX = b"RIFF"
WEBP_MARKER = b"WEBP"
ARTIFACT_ID = re.compile(r"^shot-[a-f0-9]{16}$")


class ScreenshotMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    artifact_id: str = Field(pattern=r"^shot-[a-f0-9]{16}$")
    run_id: str = Field(pattern=r"^scan-[a-f0-9]{12}$")
    scan_id: str = Field(pattern=r"^scan-[a-f0-9]{12}$")
    event_id: str = Field(pattern=r"^evt-[0-9]{12}$")
    timestamp: datetime
    approved_target_origin: str
    capture_type: Literal["VIEWPORT", "ELEMENT"]
    redaction_status: Literal["REDACTED"]
    mime_type: Literal["image/png", "image/webp"]
    width: int = Field(ge=1, le=2560)
    height: int = Field(ge=1, le=1600)
    byte_size: int = Field(ge=1, le=5_000_000)
    sha256_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    retention_expiry: datetime
    local_storage_reference: str = Field(pattern=r"^[a-f0-9]{2}/shot-[a-f0-9]{16}\.(png|webp)$")
    fixture: bool = False

    @field_validator("approved_target_origin")
    @classmethod
    def validate_origin(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or parsed.path not in {"", "/"}:
            raise ValueError("approved origin must be an origin without a path")
        if parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise ValueError("approved origin contains forbidden components")
        if parsed.hostname not in {"lab-api", "127.0.0.1", "localhost"}:
            raise ValueError("external screenshot origin is not approved")
        return value.rstrip("/")

    @model_validator(mode="after")
    def validate_relationships(self) -> Self:
        if self.run_id != self.scan_id:
            raise ValueError("screenshot run and scan identifiers must match")
        if self.retention_expiry <= self.timestamp:
            raise ValueError("screenshot retention expiry must follow capture")
        if self.retention_expiry > self.timestamp + timedelta(hours=48):
            raise ValueError("screenshot retention exceeds the maximum policy window")
        return self


class ScreenshotStore:
    def __init__(
        self,
        root: Path,
        *,
        enabled: bool = False,
        max_bytes: int = 25_000_000,
        retention_hours: int = 24,
    ) -> None:
        self.root = root.resolve()
        self.enabled = enabled
        self.max_bytes = max_bytes
        self.retention_hours = retention_hours

    def _target(self, artifact_id: str, mime_type: str) -> Path:
        if not ARTIFACT_ID.fullmatch(artifact_id) or mime_type not in ALLOWED_MIME:
            raise ValueError("invalid screenshot identifier or MIME type")
        relative = Path(artifact_id[5:7]) / f"{artifact_id}{ALLOWED_MIME[mime_type]}"
        target = (self.root / relative).resolve()
        if self.root not in target.parents:
            raise ValueError("screenshot path escapes project storage")
        return target

    @staticmethod
    def _validate_magic(content: bytes, mime_type: str) -> None:
        valid = content.startswith(PNG_MAGIC) if mime_type == "image/png" else (
            len(content) >= 12
            and content.startswith(WEBP_PREFIX)
            and content[8:12] == WEBP_MARKER
        )
        if not valid:
            raise ValueError("screenshot bytes do not match declared MIME type")

    def usage(self) -> int:
        if not self.root.exists():
            return 0
        return sum(path.stat().st_size for path in self.root.rglob("*") if path.is_file())

    def persist(
        self,
        *,
        artifact_id: str,
        scan_id: str,
        event_id: str,
        origin: str,
        capture_type: Literal["VIEWPORT", "ELEMENT"],
        mime_type: Literal["image/png", "image/webp"],
        width: int,
        height: int,
        content: bytes,
        redacted: bool,
    ) -> ScreenshotMetadata:
        if not self.enabled:
            raise PermissionError("browser screenshot capture is disabled")
        if not redacted:
            raise ValueError("screenshot must be redacted before persistence")
        self._validate_magic(content, mime_type)
        if len(content) > 5_000_000:
            raise ValueError("screenshot exceeds byte limit")
        if self.usage() + len(content) > self.max_bytes:
            raise ValueError("screenshot project quota exceeded")
        target = self._target(artifact_id, mime_type)
        now = datetime.now(UTC)
        digest = hashlib.sha256(content).hexdigest()
        relative = target.relative_to(self.root).as_posix()
        metadata = ScreenshotMetadata(
            artifact_id=artifact_id,
            run_id=scan_id,
            scan_id=scan_id,
            event_id=event_id,
            timestamp=now,
            approved_target_origin=origin,
            capture_type=capture_type,
            redaction_status="REDACTED",
            mime_type=mime_type,
            width=width,
            height=height,
            byte_size=len(content),
            sha256_digest=digest,
            retention_expiry=now + timedelta(hours=self.retention_hours),
            local_storage_reference=relative,
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(descriptor, content)
        finally:
            os.close(descriptor)
        return metadata

    def read(self, metadata: ScreenshotMetadata) -> bytes:
        target = self._target(metadata.artifact_id, metadata.mime_type)
        expected = (self.root / metadata.local_storage_reference).resolve()
        if target != expected:
            raise ValueError("screenshot storage reference mismatch")
        content = target.read_bytes()
        self._validate_magic(content, metadata.mime_type)
        if hashlib.sha256(content).hexdigest() != metadata.sha256_digest:
            raise ValueError("screenshot checksum mismatch")
        return content

    def delete_expired(
        self,
        *,
        project_root: Path,
        artifacts: list[ScreenshotMetadata],
        now: datetime,
    ) -> list[str]:
        """Delete only expired files under the explicitly supplied, matching project root.

        Metadata ownership remains external to this byte store.  Callers must select expired
        project records first and pass their artifact IDs through a future audited deletion API.
        The Phase 1.0 console does not call this method automatically.
        """

        if project_root.resolve() != self.root:
            raise ValueError("deletion must be explicitly project-scoped")
        if now.tzinfo is None:
            raise ValueError("retention timestamp must be timezone-aware")
        deleted: list[str] = []
        for metadata in artifacts:
            if metadata.retention_expiry > now:
                continue
            target = self._target(metadata.artifact_id, metadata.mime_type)
            expected = (self.root / metadata.local_storage_reference).resolve()
            if target != expected or self.root not in target.parents:
                raise ValueError("expired screenshot path escapes project storage")
            target.unlink(missing_ok=True)
            deleted.append(metadata.artifact_id)
        return deleted
