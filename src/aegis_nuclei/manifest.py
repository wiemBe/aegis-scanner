"""The checked-in, controller-owned Nuclei template manifest.

The manifest (``manifest.json`` beside this module) is the ONLY source of admissible templates. It
pins the Nuclei engine release, the upstream nuclei-templates release/commit, and — per admitted
template — its relative path, SHA-256, signature expectation, protocol, methods, request budget,
redirect behaviour, expected severity claim, the Aegis capability it serves, the deterministic
verification policy and the review record.

The manifest digest is the SHA-256 of the manifest file's exact bytes. Controller and runner both
compute it independently; an execution proceeds only when the two agree.
"""

from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

MANIFEST_PATH = Path(__file__).with_name("manifest.json")

_SHA256 = r"^[a-f0-9]{64}$"
# A manifest template path is a relative, normalized POSIX path of plain segments ending in .yaml.
_REL_PATH = r"^[a-z0-9][a-z0-9_-]*(/[a-z0-9][a-z0-9_-]*)*\.yaml$"


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class EngineArtifact(_Frozen):
    asset: str = Field(pattern=r"^nuclei_[0-9.]+_linux_(arm64|amd64)\.zip$")
    asset_sha256: str = Field(pattern=_SHA256)
    binary_sha256: str = Field(pattern=_SHA256)


class EnginePin(_Frozen):
    name: Literal["nuclei"]
    version: str = Field(pattern=r"^v[0-9]+\.[0-9]+\.[0-9]+$")
    upstream_repository: Literal["https://github.com/projectdiscovery/nuclei"]
    upstream_tag_commit: str = Field(pattern=r"^[a-f0-9]{40}$")
    release_published_at: str
    license: str
    release_checksums_asset: str
    artifacts: dict[Literal["linux_arm64", "linux_amd64"], EngineArtifact]


class UpstreamTemplates(_Frozen):
    repository: Literal["https://github.com/projectdiscovery/nuclei-templates"]
    release: str = Field(pattern=r"^v[0-9]+\.[0-9]+\.[0-9]+$")
    commit: str = Field(pattern=r"^[a-f0-9]{40}$")
    license: str
    license_file: str
    license_sha256: str = Field(pattern=_SHA256)


class SignatureExpectation(_Frozen):
    expected_status: Literal["SIGNED_VERIFIED"]
    signer: Literal["projectdiscovery/nuclei-templates"]
    digest_fingerprint: str = Field(pattern=r"^[a-f0-9]{32}$")


class ReviewRecord(_Frozen):
    reviewed_on: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    reviewer: str = Field(min_length=3, max_length=120)
    operator_countersigned: bool
    notes: str = Field(max_length=600)


class TemplateEntry(_Frozen):
    template_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,80}$")
    path: str = Field(pattern=_REL_PATH, max_length=200)
    sha256: str = Field(pattern=_SHA256)
    upstream_path: str = Field(pattern=_REL_PATH, max_length=200)
    name: str = Field(min_length=1, max_length=120)
    license: str
    signature: SignatureExpectation
    protocol: Literal["http"]
    methods: tuple[Literal["GET", "HEAD"], ...] = Field(min_length=1, max_length=2)
    request_paths: tuple[str, ...] = Field(min_length=1, max_length=4)
    max_requests: int = Field(ge=1, le=4)
    redirects: Literal["DISABLED"]
    allowed_matcher_names: tuple[str, ...] = Field(max_length=8)
    expected_severity: Literal["info", "low", "medium", "high", "critical"]
    capability_id: str = Field(pattern=r"^[a-z0-9_]{3,100}$")
    verification_policy: Literal["DETERMINISTIC_AEGIS_VERIFIER", "HUMAN_REVIEW_REQUIRED"]
    verifier: str = Field(min_length=3, max_length=80)
    review: ReviewRecord

    @field_validator("request_paths")
    @classmethod
    def _base_url_relative(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        # Every declared request must be relative to the controller-supplied {{BaseURL}} so a
        # template can never name its own origin.
        for item in value:
            if not item.startswith("{{BaseURL}}/") or ".." in item or "://" in item:
                raise ValueError("request paths must be {{BaseURL}}-relative without traversal")
        return value


class TemplateManifest(_Frozen):
    schema_: Literal["aegis.nuclei.template-manifest/1"] = Field(alias="schema")
    template_set_id: str = Field(pattern=r"^[a-z0-9-]{3,64}$")
    manifest_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    profile_id: Literal["NUCLEI_LAB_SAFE_HTTP_V1"]
    engine: EnginePin
    upstream_templates: UpstreamTemplates
    templates: tuple[TemplateEntry, ...] = Field(min_length=1, max_length=8)

    @field_validator("templates")
    @classmethod
    def _unique(cls, value: tuple[TemplateEntry, ...]) -> tuple[TemplateEntry, ...]:
        ids = [t.template_id for t in value]
        paths = [t.path for t in value]
        if len(ids) != len(set(ids)) or len(paths) != len(set(paths)):
            raise ValueError("template ids and paths must be unique")
        return value

    def by_id(self, template_id: str) -> TemplateEntry | None:
        return next((t for t in self.templates if t.template_id == template_id), None)

    def for_capability(self, capability_id: str) -> tuple[TemplateEntry, ...]:
        return tuple(t for t in self.templates if t.capability_id == capability_id)

    @property
    def total_max_requests(self) -> int:
        return sum(t.max_requests for t in self.templates)


def manifest_digest(path: Path = MANIFEST_PATH) -> str:
    """SHA-256 of the manifest file's exact bytes."""

    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_manifest(raw: bytes) -> TemplateManifest:
    # strict=True rejects JSON-number/strings coercion; the JSON mode keeps tuples/literals exact.
    return TemplateManifest.model_validate_json(raw)


@lru_cache(maxsize=4)
def load_manifest(path: Path = MANIFEST_PATH) -> TemplateManifest:
    return parse_manifest(path.read_bytes())


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()
