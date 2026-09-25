"""Controller-owned operator target inventory (Phase 1.9.5 correction).

Operators onboard authorized company websites, APIs and IP/CIDR ranges through the console. The
controller — never the browser — normalizes, validates, authorizes and persists each target. Browser
input never becomes a raw scanner argument: it is stored as a normalized, bounded scope that the
execution path enforces. Credential *values* are never stored here; only an opaque reference to the
existing controller-owned credential mechanism.

Everything in this module is deterministic and offline. It performs no DNS resolution and no network
egress; hostnames are normalized structurally (IDNA/punycode, scheme, port, path) so the same rules
apply in tests and at runtime.
"""

from __future__ import annotations

import ipaddress
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, TypedDict
from urllib.parse import urlsplit
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class NormalizedScope(TypedDict):
    """The exact, typed shape returned by :func:`validate_and_normalize`.

    Making the shape explicit (rather than ``dict[str, object]``) lets the controller assign the
    normalized fields onto a :class:`TargetRecord` without ``# type: ignore`` escape hatches.
    """

    origins: list[str]
    addresses: list[str]
    wildcard_subdomains: list[str]
    allowed_path_prefixes: list[str]
    excluded_path_prefixes: list[str]
    openapi_url: str | None


TargetType = Literal["WEBSITE", "API", "IP_CIDR", "SYNTHETIC"]
Environment = Literal["PRODUCTION", "STAGING", "DEVELOPMENT", "INTERNAL", "SYNTHETIC"]
# DRAFT -> VALIDATED -> AUTHORIZED -> AVAILABLE_FOR_ASSESSMENT -> DISABLED. For the single-operator
# deployment an explicit attestation + authorization reference advances a created target straight to
# AVAILABLE_FOR_ASSESSMENT; DISABLED preserves the record and its audit history.
LifecycleState = Literal[
    "DRAFT", "VALIDATED", "AUTHORIZED", "AVAILABLE_FOR_ASSESSMENT", "DISABLED"
]

_ENV_DEFAULT_PORTS = {"http": 80, "https": 443}
# Cloud metadata / link-local space stays unavailable to ordinary onboarding; only an authorized
# cloud-boundary profile may target it, which this onboarding flow deliberately does not grant.
_BLOCKED_METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata",
    "fd00:ec2::254",
    "100.100.100.200",
}


class TargetValidationError(ValueError):
    """A bounded, operator-readable reason a target or scope was rejected. Never a stack trace."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ScopeViolation(ValueError):
    """An execution URL fell outside a target's stored, authorized scope. Fails closed."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class TargetCreate(BaseModel):
    """The typed create request. The browser sends this; it never sends scanner arguments."""

    model_config = ConfigDict(extra="forbid")

    target_type: TargetType
    display_name: str = Field(min_length=2, max_length=120)
    environment: Environment
    owner: str | None = Field(default=None, max_length=160)
    authorization_reference: str = Field(min_length=2, max_length=120)
    authorization_attested: bool
    description: str | None = Field(default=None, max_length=1000)
    # WEBSITE / API scope.
    origins: list[str] = Field(default_factory=list)
    allowed_path_prefixes: list[str] = Field(default_factory=list)
    excluded_path_prefixes: list[str] = Field(default_factory=list)
    wildcard_subdomains: list[str] = Field(default_factory=list)
    wildcard_authorized: bool = False
    # API extras. Credential values are NEVER accepted here — only an opaque reference.
    openapi_url: str | None = Field(default=None, max_length=2000)
    credential_reference: str | None = Field(default=None, max_length=120)
    # IP / CIDR scope.
    addresses: list[str] = Field(default_factory=list)
    cidr_authorized: bool = False


class TargetRecord(BaseModel):
    """The persisted, controller-owned inventory record and its safe projection."""

    model_config = ConfigDict(extra="forbid")

    id: str
    target_type: TargetType
    display_name: str
    environment: Environment
    owner: str | None
    authorization_reference: str
    attested_by: str | None
    description: str | None
    origins: list[str]
    addresses: list[str]
    wildcard_subdomains: list[str]
    allowed_path_prefixes: list[str]
    excluded_path_prefixes: list[str]
    openapi_url: str | None
    credential_reference: str | None
    status: LifecycleState
    enabled: bool
    created_at: str
    updated_at: str
    last_assessment_at: str | None = None

    def authorized_scope(self) -> list[str]:
        """A flat, human-readable list of exactly what execution is bounded to."""

        scope = list(self.origins) + list(self.addresses)
        scope += [f"*.{d}" for d in self.wildcard_subdomains]
        return scope

    def projection(self) -> dict[str, object]:
        supported = _SUPPORTED_PROFILES.get(self.target_type, [])
        return {
            "target_ref": self.id,
            "name": self.display_name,
            "type": _TYPE_LABEL[self.target_type],
            "target_type": self.target_type,
            "environment": self.environment,
            "description": self.description or "",
            "origin_source": "OPERATOR_ONBOARDED",
            "synthetic": self.target_type == "SYNTHETIC",
            "status": self.status,
            "enabled": self.enabled,
            "authorization_reference": self.authorization_reference,
            "authorized_scope": self.authorized_scope(),
            "allowed_path_prefixes": self.allowed_path_prefixes,
            "excluded_path_prefixes": self.excluded_path_prefixes,
            "credential_reference": self.credential_reference,
            "last_assessment_at": self.last_assessment_at,
            "supported_profile_ids": supported,
        }


_TYPE_LABEL: dict[TargetType, str] = {
    "WEBSITE": "Website / FQDN",
    "API": "API",
    "IP_CIDR": "IP / CIDR",
    "SYNTHETIC": "Synthetic range",
}

# Which catalog profiles each target type could be assessed by. Whether a profile is *executable*
# in a given deployment is still decided separately by the profile availability logic, so an
# unavailable adapter shows the profile disabled with a reason rather than running anything.
_SUPPORTED_PROFILES: dict[TargetType, list[str]] = {
    "SYNTHETIC": ["aegis-native-bola-synthetic"],
    "WEBSITE": ["ZAP_LAB_PASSIVE_OPENAPI_V1", "NUCLEI_LAB_SAFE_HTTP_V1"],
    "API": ["ZAP_LAB_PASSIVE_OPENAPI_V1", "NUCLEI_LAB_SAFE_HTTP_V1"],
    "IP_CIDR": [],
}


# --- normalization / validation (pure) -----------------------------------------------------------


def normalize_origin(raw: str) -> str:
    """Normalize one website/API origin to ``scheme://host[:port]``. Rejects embedded credentials,
    full arbitrary URLs (a path beyond ``/``), malformed hosts and blocked metadata hosts."""

    candidate = raw.strip()
    if not candidate:
        raise TargetValidationError("EMPTY_ORIGIN")
    if "@" in candidate.split("//")[-1].split("/")[0]:
        # user:password@host — never accepted, even before URL parsing.
        raise TargetValidationError("EMBEDDED_CREDENTIALS_FORBIDDEN")
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    parts = urlsplit(candidate)
    if parts.scheme not in _ENV_DEFAULT_PORTS:
        raise TargetValidationError("UNSUPPORTED_SCHEME")
    if parts.username or parts.password:
        raise TargetValidationError("EMBEDDED_CREDENTIALS_FORBIDDEN")
    if parts.query or parts.fragment:
        raise TargetValidationError("ORIGIN_NOT_A_URL")
    if parts.path not in ("", "/"):
        # An origin is a host, not an arbitrary URL. Paths belong in allowed/excluded prefixes.
        raise TargetValidationError("ORIGIN_NOT_A_URL")
    host = parts.hostname
    if not host:
        raise TargetValidationError("MALFORMED_ORIGIN")
    try:
        host = host.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        raise TargetValidationError("MALFORMED_HOST") from None
    if not re.fullmatch(r"[a-z0-9.-]+", host) or ".." in host or host.startswith("-"):
        raise TargetValidationError("MALFORMED_HOST")
    if host in _BLOCKED_METADATA_HOSTS:
        raise TargetValidationError("METADATA_HOST_NOT_AUTHORIZED")
    port = parts.port
    if port is None:
        port = _ENV_DEFAULT_PORTS[parts.scheme]
    if not 1 <= port <= 65535:
        raise TargetValidationError("INVALID_PORT")
    default = _ENV_DEFAULT_PORTS[parts.scheme]
    return f"{parts.scheme}://{host}" if port == default else f"{parts.scheme}://{host}:{port}"


def normalize_wildcard(raw: str) -> str:
    """Normalize an authorized wildcard subdomain to its bare apex (``*.company.com`` -> host)."""

    candidate = raw.strip().lower()
    candidate = candidate.removeprefix("*.")
    origin = normalize_origin(candidate)
    return urlsplit(origin).hostname or candidate


def normalize_address(raw: str) -> str:
    """Normalize a single IP or a CIDR. Private/internal space is allowed; metadata/link-local is
    not. Returns the canonical string form."""

    candidate = raw.strip()
    if not candidate:
        raise TargetValidationError("EMPTY_ADDRESS")
    try:
        if "/" in candidate:
            network = ipaddress.ip_network(candidate, strict=False)
            if str(network.network_address) in _BLOCKED_METADATA_HOSTS:
                raise TargetValidationError("METADATA_HOST_NOT_AUTHORIZED")
            if network.is_link_local:
                raise TargetValidationError("LINK_LOCAL_NOT_AUTHORIZED")
            return str(network)
        address = ipaddress.ip_address(candidate)
    except ValueError:
        raise TargetValidationError("MALFORMED_ADDRESS") from None
    if str(address) in _BLOCKED_METADATA_HOSTS or address.is_link_local:
        raise TargetValidationError("LINK_LOCAL_NOT_AUTHORIZED")
    return str(address)


def _normalize_prefix(raw: str) -> str:
    prefix = raw.strip()
    if not prefix:
        raise TargetValidationError("EMPTY_PATH_PREFIX")
    if not prefix.startswith("/"):
        prefix = "/" + prefix
    if "://" in prefix or " " in prefix:
        raise TargetValidationError("MALFORMED_PATH_PREFIX")
    return prefix.rstrip("/") or "/"


def _dedupe(values: list[str]) -> list[str]:
    seen: list[str] = []
    for value in values:
        if value in seen:
            raise TargetValidationError("DUPLICATE_ORIGIN")
        seen.append(value)
    return seen


def validate_and_normalize(request: TargetCreate) -> NormalizedScope:
    """Validate a create request and return the normalized, controller-owned scope fields. Raises
    :class:`TargetValidationError` with a bounded code on any violation."""

    if not request.authorization_attested:
        raise TargetValidationError("AUTHORIZATION_ATTESTATION_REQUIRED")
    if not request.authorization_reference.strip():
        raise TargetValidationError("AUTHORIZATION_REFERENCE_REQUIRED")

    origins: list[str] = []
    addresses: list[str] = []
    wildcards: list[str] = []

    if request.target_type in ("WEBSITE", "API", "SYNTHETIC"):
        if not request.origins:
            raise TargetValidationError("AT_LEAST_ONE_ORIGIN_REQUIRED")
        origins = _dedupe([normalize_origin(o) for o in request.origins])
        if request.wildcard_subdomains:
            if not request.wildcard_authorized:
                raise TargetValidationError("WILDCARD_REQUIRES_EXPLICIT_AUTHORIZATION")
            wildcards = _dedupe([normalize_wildcard(w) for w in request.wildcard_subdomains])
    elif request.target_type == "IP_CIDR":
        if not request.addresses:
            raise TargetValidationError("AT_LEAST_ONE_ADDRESS_REQUIRED")
        normalized = [normalize_address(a) for a in request.addresses]
        for original, _norm in zip(request.addresses, normalized, strict=True):
            if "/" in original and not request.cidr_authorized:
                raise TargetValidationError("CIDR_REQUIRES_EXPLICIT_AUTHORIZATION")
        addresses = _dedupe(normalized)

    allowed = [_normalize_prefix(p) for p in request.allowed_path_prefixes]
    excluded = [_normalize_prefix(p) for p in request.excluded_path_prefixes]

    openapi_url: str | None = None
    if request.openapi_url:
        openapi = request.openapi_url.strip()
        parts = urlsplit(openapi if "://" in openapi else f"https://{openapi}")
        if parts.username or parts.password:
            raise TargetValidationError("EMBEDDED_CREDENTIALS_FORBIDDEN")
        openapi_host = normalize_origin(f"{parts.scheme}://{parts.netloc}")
        if openapi_host not in origins:
            raise TargetValidationError("OPENAPI_URL_OUTSIDE_SCOPE")
        openapi_url = openapi

    return {
        "origins": origins,
        "addresses": addresses,
        "wildcard_subdomains": wildcards,
        "allowed_path_prefixes": allowed,
        "excluded_path_prefixes": excluded,
        "openapi_url": openapi_url,
    }


def authorize_url_against_target(record: TargetRecord, url: str) -> str:
    """Fail-closed scope check for an execution/redirect URL. Returns the normalized origin when the
    URL is inside the stored authorized scope; raises :class:`ScopeViolation` otherwise. This is how
    a redirect or discovered host that escapes the approved scope is rejected."""

    # A real execution/redirect URL carries a path (and possibly a query); the origin check must
    # run against the scheme+host+port only, or every path would be rejected as "not an origin".
    # The path is enforced separately below against the allowed/excluded prefixes.
    parts = urlsplit(url if "://" in url else f"https://{url}")
    try:
        origin = normalize_origin(f"{parts.scheme}://{parts.netloc}")
    except TargetValidationError as exc:
        raise ScopeViolation(exc.code) from None
    host = urlsplit(origin).hostname or ""
    if origin in record.origins:
        in_scope = True
    elif any(host == wc or host.endswith(f".{wc}") for wc in record.wildcard_subdomains):
        in_scope = True
    else:
        in_scope = _host_in_addresses(host, record.addresses)
    if not in_scope:
        raise ScopeViolation("TARGET_ESCAPE_OUTSIDE_AUTHORIZED_SCOPE")
    path = urlsplit(url).path or "/"
    if any(path.startswith(prefix) for prefix in record.excluded_path_prefixes):
        raise ScopeViolation("PATH_EXCLUDED_FROM_SCOPE")
    if record.allowed_path_prefixes and not any(
        path.startswith(prefix) for prefix in record.allowed_path_prefixes
    ):
        raise ScopeViolation("PATH_OUTSIDE_ALLOWED_PREFIXES")
    return origin


def _host_in_addresses(host: str, addresses: list[str]) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    for entry in addresses:
        try:
            if "/" in entry:
                if ip in ipaddress.ip_network(entry, strict=False):
                    return True
            elif ip == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue
    return False


# --- persistence ---------------------------------------------------------------------------------


class TargetInventoryStore:
    """SQLite-backed, controller-owned target inventory. Survives process restart; never stored in
    the browser."""

    def __init__(self, database_path: str) -> None:
        self.database_path = database_path

    def initialize(self) -> None:
        path = Path(self.database_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS operator_targets (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def create(self, request: TargetCreate, *, operator_id: str | None = None) -> TargetRecord:
        normalized = validate_and_normalize(request)
        now = datetime.now(UTC).isoformat()
        record = TargetRecord(
            id=f"tgt-{uuid4().hex[:12]}",
            target_type=request.target_type,
            display_name=request.display_name.strip(),
            environment=request.environment,
            owner=(request.owner or None),
            authorization_reference=request.authorization_reference.strip(),
            attested_by=operator_id,
            description=(request.description or None),
            origins=normalized["origins"],
            addresses=normalized["addresses"],
            wildcard_subdomains=normalized["wildcard_subdomains"],
            allowed_path_prefixes=normalized["allowed_path_prefixes"],
            excluded_path_prefixes=normalized["excluded_path_prefixes"],
            openapi_url=normalized["openapi_url"],
            credential_reference=(request.credential_reference or None),
            status="AVAILABLE_FOR_ASSESSMENT",
            enabled=True,
            created_at=now,
            updated_at=now,
        )
        self._reject_duplicate_scope(record)
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO operator_targets (id, created_at, updated_at, payload) "
                "VALUES (?,?,?,?)",
                (record.id, now, now, record.model_dump_json()),
            )
        return record

    def _reject_duplicate_scope(self, record: TargetRecord) -> None:
        new_scope = set(record.origins) | set(record.addresses)
        for existing in self.list():
            if existing.enabled and (
                set(existing.origins) | set(existing.addresses)
            ) & new_scope:
                raise TargetValidationError("DUPLICATE_ORIGIN")

    def list(self) -> list[TargetRecord]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM operator_targets ORDER BY created_at ASC"
            ).fetchall()
        return [TargetRecord.model_validate_json(row["payload"]) for row in rows]

    def get(self, target_id: str) -> TargetRecord | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM operator_targets WHERE id = ?", (target_id,)
            ).fetchone()
        return TargetRecord.model_validate_json(row["payload"]) if row else None

    def _save(self, record: TargetRecord) -> TargetRecord:
        record.updated_at = datetime.now(UTC).isoformat()
        with self._connect() as connection:
            connection.execute(
                "UPDATE operator_targets SET updated_at = ?, payload = ? WHERE id = ?",
                (record.updated_at, record.model_dump_json(), record.id),
            )
        return record

    def set_enabled(self, target_id: str, enabled: bool) -> TargetRecord | None:
        record = self.get(target_id)
        if record is None:
            return None
        record.enabled = enabled
        record.status = "AVAILABLE_FOR_ASSESSMENT" if enabled else "DISABLED"
        return self._save(record)

    def update_scope(self, target_id: str, request: TargetCreate) -> TargetRecord | None:
        record = self.get(target_id)
        if record is None:
            return None
        normalized = validate_and_normalize(request)
        record.origins = normalized["origins"]
        record.addresses = normalized["addresses"]
        record.wildcard_subdomains = normalized["wildcard_subdomains"]
        record.allowed_path_prefixes = normalized["allowed_path_prefixes"]
        record.excluded_path_prefixes = normalized["excluded_path_prefixes"]
        record.openapi_url = normalized["openapi_url"]
        record.display_name = request.display_name.strip()
        record.environment = request.environment
        record.authorization_reference = request.authorization_reference.strip()
        return self._save(record)

    def mark_assessed(self, target_id: str) -> None:
        record = self.get(target_id)
        if record is not None:
            record.last_assessment_at = datetime.now(UTC).isoformat()
            self._save(record)


def scope_preview(request: TargetCreate) -> dict[str, object]:
    """A dry-run normalization used by the console to show the exact scope before saving."""

    normalized = validate_and_normalize(request)
    scope = (
        list(normalized["origins"])
        + list(normalized["addresses"])
        + [f"*.{d}" for d in normalized["wildcard_subdomains"]]
    )
    return {"authorized_scope": scope, **normalized}
