"""The checked-in, controller-owned ZAP active-rule manifest (Phase 1.5).

``manifest.json`` beside this module is the ONLY source of truth for the digest-pinned Phase 1.5
runner image: the exact ZAP release and OCI/jar/JVM digests (identical to Phase 1.3, so the base
image is unchanged), the exact add-on files that may exist in the plugin directory, the add-on ids
that must never be present, the neutralised forced-dependency ids, and the single admitted release
active rule (40012, reflected cross-site scripting) with its fixed threshold and strength.

The active manifest is SEPARATE from the passive ``aegis_zap.manifest``. It reuses the same pin
models (image, jar, JVM, add-on, review) but adds active-rule fields and the forced-dependency
accounting that active scanning requires. The Phase 1.3 passive profile and its 8-add-on image are
never modified or widened by this module.
"""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegis_zap.manifest import AddOnPin, EnginePin, ReviewRecord

MANIFEST_PATH = Path(__file__).with_name("manifest.json")


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ActiveRule(_Frozen):
    """One admitted, reviewed release-quality active scan rule. Fixed threshold and strength."""

    plugin_id: int = Field(ge=10000, le=99999)
    name: str = Field(min_length=3, max_length=120)
    add_on_id: str = Field(max_length=40)
    add_on_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    implementation: str = Field(pattern=r"^org\.zaproxy\.[A-Za-z0-9_.]+$", max_length=160)
    cwe_id: int = Field(ge=0, le=1_000)
    quality: Literal["release"]
    threshold: Literal["LOW", "MEDIUM", "HIGH"]
    strength: Literal["LOW", "MEDIUM", "HIGH", "INSANE"]
    claimed_risk: Literal["info", "low", "medium", "high"]
    claimed_confidence: Literal["falsepositive", "low", "medium", "high", "confirmed"]
    risk_confidence_policy: Literal[
        "UNTRUSTED_TOOL_METADATA_NEVER_SETS_AEGIS_SEVERITY_OR_CONFIDENCE"
    ]
    expected_evidence_fields: tuple[str, ...] = Field(min_length=1, max_length=8)
    expected_param: str = Field(pattern=r"^[a-z0-9_-]{1,64}$")
    capability_id: str = Field(pattern=r"^[a-z0-9_]{3,100}$")
    verification_policy: Literal["DETERMINISTIC_AEGIS_VERIFIER", "HUMAN_REVIEW_REQUIRED"]
    verifier: str = Field(min_length=3, max_length=80)
    aegis_verified_severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    attack_field_policy: Literal["REDACTED_CLASSIFICATION_AND_DIGEST_ONLY_NEVER_RAW_ATTACK_TEXT"]
    justification: str = Field(max_length=700)
    review: ReviewRecord


class ZapActiveManifest(_Frozen):
    schema_: Literal["aegis.zap.active-manifest/1"] = Field(alias="schema")
    manifest_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    profile_id: Literal["ZAP_LAB_ACTIVE_REFLECTED_XSS_V1"]
    engine: EnginePin
    add_ons: tuple[AddOnPin, ...] = Field(min_length=1, max_length=16)
    forbidden_add_on_ids: tuple[str, ...] = Field(max_length=128)
    # Present in the image ONLY to satisfy the admitted rule's mandatory dependency chain; disabled
    # and unreachable at runtime. ascanrules -> oast -> database.
    neutralised_dependency_ids: tuple[str, ...] = Field(max_length=8)
    active_rules: tuple[ActiveRule, ...] = Field(min_length=1, max_length=4)
    prohibited_jobs: tuple[str, ...] = Field(max_length=64)
    prohibited_features: tuple[str, ...] = Field(max_length=64)

    @field_validator("add_ons")
    @classmethod
    def _unique_add_ons(cls, value: tuple[AddOnPin, ...]) -> tuple[AddOnPin, ...]:
        ids = [a.id for a in value]
        files = [a.file for a in value]
        if len(ids) != len(set(ids)) or len(files) != len(set(files)):
            raise ValueError("add-on ids and files must be unique")
        return value

    @field_validator("active_rules")
    @classmethod
    def _unique_rules(cls, value: tuple[ActiveRule, ...]) -> tuple[ActiveRule, ...]:
        ids = [r.plugin_id for r in value]
        if len(ids) != len(set(ids)):
            raise ValueError("active rule plugin ids must be unique")
        return value

    @model_validator(mode="after")
    def _consistent(self) -> ZapActiveManifest:
        admitted = {a.id for a in self.add_ons}
        if admitted & set(self.forbidden_add_on_ids):
            raise ValueError("an add-on is both admitted and forbidden")
        if not set(self.neutralised_dependency_ids) <= admitted:
            raise ValueError("a neutralised dependency is not an admitted add-on")
        for rule in self.active_rules:
            pin = self.add_on(rule.add_on_id)
            if pin is None or pin.version != rule.add_on_version:
                raise ValueError("active rule references an unpinned add-on")
            if pin.status != "release" or rule.quality != "release":
                raise ValueError("an admitted active rule must be release quality")
        return self

    def add_on(self, add_on_id: str) -> AddOnPin | None:
        return next((a for a in self.add_ons if a.id == add_on_id), None)

    def rule(self, plugin_id: int) -> ActiveRule | None:
        return next((r for r in self.active_rules if r.plugin_id == plugin_id), None)

    def rules_for_capability(self, capability_id: str) -> tuple[ActiveRule, ...]:
        return tuple(r for r in self.active_rules if r.capability_id == capability_id)

    @property
    def add_on_set(self) -> frozenset[tuple[str, str]]:
        return frozenset((a.id, a.version) for a in self.add_ons)


def manifest_digest(path: Path = MANIFEST_PATH) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_manifest(raw: bytes) -> ZapActiveManifest:
    return ZapActiveManifest.model_validate_json(raw)


@lru_cache(maxsize=4)
def load_manifest(path: Path = MANIFEST_PATH) -> ZapActiveManifest:
    return parse_manifest(path.read_bytes())


def add_on_inventory_digest(manifest: ZapActiveManifest) -> str:
    rows = sorted((a.id, a.version, a.sha256) for a in manifest.add_ons)
    return hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest()
