"""The checked-in, controller-owned ZAP supply-chain and passive-rule manifest.

``manifest.json`` beside this module is the ONLY source of truth for what the isolated zap-runner
may contain and enable: the exact ZAP release, the pinned multi-architecture OCI image digests, the
ZAP jar digest, the per-architecture JVM digests, the exact add-on files (id, version, SHA-256)
that may exist in the install plugin directory, the add-on ids that must never be present, and the
admitted passive-rule manifest.

The manifest digest is the SHA-256 of the file's exact bytes. The controller and the runner each
compute it independently and an execution proceeds only when both agree.
"""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

MANIFEST_PATH = Path(__file__).with_name("manifest.json")

_SHA256 = r"^[a-f0-9]{64}$"
_OCI_DIGEST = r"^sha256:[a-f0-9]{64}$"
Arch = Literal["linux_arm64", "linux_amd64"]


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ImagePin(_Frozen):
    repository: Literal["docker.io/zaproxy/zap-stable"]
    observed_tag: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    index_digest: str = Field(pattern=_OCI_DIGEST)
    platforms: dict[Arch, str]
    sbom: str = Field(max_length=80)

    @field_validator("platforms")
    @classmethod
    def _digests(cls, value: dict[str, str]) -> dict[str, str]:
        for digest in value.values():
            if not digest.startswith("sha256:") or len(digest) != 71:
                raise ValueError("platform digests must be sha256 OCI digests")
        return value


class JarPin(_Frozen):
    path: str = Field(pattern=r"^zap-[0-9.]+\.jar$")
    sha256: str = Field(pattern=_SHA256)


class JavaPlatformPin(_Frozen):
    home: str = Field(pattern=r"^/usr/lib/jvm/java-17-openjdk-(arm64|amd64)$")
    java_sha256: str = Field(pattern=_SHA256)
    libjvm_sha256: str = Field(pattern=_SHA256)
    release_sha256: str = Field(pattern=_SHA256)


class JavaPin(_Frozen):
    version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    runtime_version: str = Field(max_length=60)
    implementor: str = Field(max_length=40)
    platforms: dict[Arch, JavaPlatformPin]


class EnginePin(_Frozen):
    name: Literal["zap"]
    version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    release_published_at: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    upstream_repository: Literal["https://github.com/zaproxy/zaproxy"]
    license: str = Field(max_length=40)
    image: ImagePin
    jar: JarPin
    java: JavaPin


class AddOnPin(_Frozen):
    id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9]{1,40}$")
    version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    status: Literal["release", "beta", "alpha"]
    file: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9]*-(release|beta|alpha)-[0-9.]+\.zap$")
    sha256: str = Field(pattern=_SHA256)
    role: str = Field(max_length=200)


class ReviewRecord(_Frozen):
    reviewed_on: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    reviewer: str = Field(min_length=3, max_length=120)
    operator_countersigned: bool
    notes: str = Field(max_length=600)


class PassiveRule(_Frozen):
    plugin_id: int = Field(ge=10000, le=99999)
    name: str = Field(min_length=3, max_length=120)
    add_on_id: str = Field(max_length=40)
    add_on_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    implementation: str = Field(pattern=r"^org\.zaproxy\.[A-Za-z0-9_.]+$", max_length=160)
    quality: Literal["release"]
    threshold: Literal["LOW", "MEDIUM", "HIGH"]
    claimed_risk: Literal["info", "low", "medium", "high"]
    claimed_confidence: Literal["falsepositive", "low", "medium", "high", "confirmed"]
    risk_confidence_policy: Literal[
        "UNTRUSTED_TOOL_METADATA_NEVER_SETS_AEGIS_SEVERITY_OR_CONFIDENCE"
    ]
    expected_evidence_fields: tuple[str, ...] = Field(min_length=1, max_length=6)
    expected_param: str = Field(pattern=r"^[a-z0-9-]{1,64}$")
    capability_id: str = Field(pattern=r"^[a-z0-9_]{3,100}$")
    verification_policy: Literal["DETERMINISTIC_AEGIS_VERIFIER", "HUMAN_REVIEW_REQUIRED"]
    verifier: str = Field(min_length=3, max_length=80)
    aegis_verified_severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    justification: str = Field(max_length=600)
    review: ReviewRecord


class ZapManifest(_Frozen):
    schema_: Literal["aegis.zap.manifest/1"] = Field(alias="schema")
    manifest_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    profile_id: Literal["ZAP_LAB_PASSIVE_OPENAPI_V1"]
    engine: EnginePin
    add_ons: tuple[AddOnPin, ...] = Field(min_length=1, max_length=16)
    forbidden_add_on_ids: tuple[str, ...] = Field(max_length=128)
    passive_rules: tuple[PassiveRule, ...] = Field(min_length=1, max_length=8)

    @field_validator("add_ons")
    @classmethod
    def _unique_add_ons(cls, value: tuple[AddOnPin, ...]) -> tuple[AddOnPin, ...]:
        ids = [a.id for a in value]
        files = [a.file for a in value]
        if len(ids) != len(set(ids)) or len(files) != len(set(files)):
            raise ValueError("add-on ids and files must be unique")
        return value

    @field_validator("passive_rules")
    @classmethod
    def _unique_rules(cls, value: tuple[PassiveRule, ...]) -> tuple[PassiveRule, ...]:
        ids = [r.plugin_id for r in value]
        if len(ids) != len(set(ids)):
            raise ValueError("passive rule plugin ids must be unique")
        return value

    def add_on(self, add_on_id: str) -> AddOnPin | None:
        return next((a for a in self.add_ons if a.id == add_on_id), None)

    def rule(self, plugin_id: int) -> PassiveRule | None:
        return next((r for r in self.passive_rules if r.plugin_id == plugin_id), None)

    def rules_for_capability(self, capability_id: str) -> tuple[PassiveRule, ...]:
        return tuple(r for r in self.passive_rules if r.capability_id == capability_id)

    @property
    def add_on_set(self) -> frozenset[tuple[str, str]]:
        return frozenset((a.id, a.version) for a in self.add_ons)


def manifest_digest(path: Path = MANIFEST_PATH) -> str:
    """SHA-256 of the manifest file's exact bytes."""

    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_manifest(raw: bytes) -> ZapManifest:
    return ZapManifest.model_validate_json(raw)


@lru_cache(maxsize=4)
def load_manifest(path: Path = MANIFEST_PATH) -> ZapManifest:
    manifest = parse_manifest(path.read_bytes())
    # A forbidden add-on id can never also be an admitted one; an admitted rule must live in an
    # admitted add-on at the pinned version. Either inconsistency is a broken manifest.
    admitted = {a.id for a in manifest.add_ons}
    if admitted & set(manifest.forbidden_add_on_ids):
        raise ValueError("an add-on is both admitted and forbidden")
    for rule in manifest.passive_rules:
        pin = manifest.add_on(rule.add_on_id)
        if pin is None or pin.version != rule.add_on_version:
            raise ValueError("passive rule references an unpinned add-on")
    return manifest


def add_on_inventory_digest(manifest: ZapManifest) -> str:
    """Stable digest of the admitted add-on inventory (id, version, file SHA-256), sorted."""

    rows = sorted((a.id, a.version, a.sha256) for a in manifest.add_ons)
    return hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()
