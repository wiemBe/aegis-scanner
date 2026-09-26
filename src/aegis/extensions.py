"""Fail-closed, declarative production extension packs.

Extension packs may add bounded prompt guidance, named agent profiles over an existing Aegis
role, and aliases for tools that are already present in the immutable engine catalog.  They cannot
load Python, declare commands or URLs, add a capability, change an execution profile, or grant a
permission.  Those boundaries remain compiled into the application and independently verified.
"""

from __future__ import annotations

import hashlib
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aegis.engine.catalog import get_engine_capability, get_engine_profile
from aegis.multi_agent.contracts import AgentRole

_MAX_MANIFEST_BYTES = 65_536
_MAX_PROMPT_CHARS = 4_000
_IDENTIFIER_PATTERN = r"^[a-z][a-z0-9_.-]{2,63}$"
_TASK_PATTERN = r"^[A-Z][A-Z0-9_]{2,79}$"


class _StrictExtensionModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class PromptFragment(_StrictExtensionModel):
    id: str = Field(pattern=_IDENTIFIER_PATTERN)
    text: str = Field(min_length=1, max_length=1_000)

    @model_validator(mode="after")
    def reject_unsafe_material(self) -> PromptFragment:
        lowered = self.text.lower()
        forbidden = ("http://", "https://", "authorization:", "bearer ", "api_key", "api-key")
        if "\x00" in self.text or any(marker in lowered for marker in forbidden):
            raise ValueError("prompt fragment contains a forbidden origin or credential marker")
        return self


class AgentProfile(_StrictExtensionModel):
    """A named specialization of an existing, controller-owned role.

    A profile does not create a new runtime role.  It selects bounded guidance for existing task
    types whose request and response schemas remain server-owned.
    """

    id: str = Field(pattern=_IDENTIFIER_PATTERN)
    display_name: str = Field(min_length=1, max_length=80)
    base_role: AgentRole
    task_types: tuple[str, ...] = Field(min_length=1, max_length=16)
    prompt_fragment_ids: tuple[str, ...] = Field(default=(), max_length=8)

    @model_validator(mode="after")
    def validate_task_types(self) -> AgentProfile:
        import re

        if len(set(self.task_types)) != len(self.task_types):
            raise ValueError("agent profile task types must be unique")
        if any(re.fullmatch(_TASK_PATTERN, item) is None for item in self.task_types):
            raise ValueError("agent profile contains an invalid task type")
        if len(set(self.prompt_fragment_ids)) != len(self.prompt_fragment_ids):
            raise ValueError("agent profile prompt fragment references must be unique")
        return self


class ToolBinding(_StrictExtensionModel):
    """A display alias for one already compiled-in capability/profile pair."""

    id: str = Field(pattern=_IDENTIFIER_PATTERN)
    display_name: str = Field(min_length=1, max_length=80)
    capability_id: str = Field(min_length=3, max_length=100)
    profile_id: str = Field(min_length=3, max_length=100)
    description: str = Field(default="", max_length=240)

    @model_validator(mode="after")
    def validate_catalog_binding(self) -> ToolBinding:
        capability = get_engine_capability(self.capability_id)
        profile = get_engine_profile(self.profile_id)
        if capability is None or profile is None:
            raise ValueError("tool binding must reference an existing capability and profile")
        if (
            capability.engine is not profile.engine
            or self.capability_id not in profile.capability_ids
        ):
            raise ValueError("tool binding capability is not admitted by the referenced profile")
        return self


class ExtensionPack(_StrictExtensionModel):
    schema_version: Literal["aegis-extension-v1"] = "aegis-extension-v1"
    pack_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    pack_version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    prompt_fragments: tuple[PromptFragment, ...] = Field(default=(), max_length=32)
    agent_profiles: tuple[AgentProfile, ...] = Field(default=(), max_length=32)
    tool_bindings: tuple[ToolBinding, ...] = Field(default=(), max_length=64)

    @model_validator(mode="after")
    def validate_references(self) -> ExtensionPack:
        for collection in (self.prompt_fragments, self.agent_profiles, self.tool_bindings):
            identifiers = [item.id for item in collection]
            if len(set(identifiers)) != len(identifiers):
                raise ValueError("extension identifiers must be unique within each section")
        fragments = {item.id for item in self.prompt_fragments}
        for profile in self.agent_profiles:
            if not set(profile.prompt_fragment_ids).issubset(fragments):
                raise ValueError("agent profile references an unknown prompt fragment")
            chars = sum(
                len(fragment.text)
                for fragment in self.prompt_fragments
                if fragment.id in profile.prompt_fragment_ids
            )
            if chars > _MAX_PROMPT_CHARS:
                raise ValueError("agent profile prompt guidance exceeds the bounded limit")
        return self


@dataclass(frozen=True)
class ExtensionRuntime:
    pack: ExtensionPack | None
    source_sha256: str | None

    def prompt_guidance(self, role: AgentRole, task_type: str) -> str | None:
        if self.pack is None:
            return None
        fragment_by_id = {fragment.id: fragment.text for fragment in self.pack.prompt_fragments}
        selected: list[str] = []
        for profile in self.pack.agent_profiles:
            if profile.base_role is role and task_type in profile.task_types:
                selected.extend(fragment_by_id[item] for item in profile.prompt_fragment_ids)
        return " ".join(selected) or None

    def projection(self) -> dict[str, object]:
        if self.pack is None:
            return {
                "enabled": False,
                "schema_version": "aegis-extension-v1",
                "source_sha256": None,
                "prompt_fragments": [],
                "agent_profiles": [],
                "tool_bindings": [],
                "authority": "CATALOG_AND_CONTROLLER_ONLY",
            }
        return {
            "enabled": True,
            "schema_version": self.pack.schema_version,
            "pack_id": self.pack.pack_id,
            "pack_version": self.pack.pack_version,
            "source_sha256": self.source_sha256,
            "prompt_fragments": [fragment.id for fragment in self.pack.prompt_fragments],
            "agent_profiles": [
                {
                    "id": profile.id,
                    "display_name": profile.display_name,
                    "base_role": profile.base_role.value,
                    "task_types": list(profile.task_types),
                }
                for profile in self.pack.agent_profiles
            ],
            "tool_bindings": [
                {
                    **binding.model_dump(mode="json"),
                    "authority": "EXISTING_CATALOG_BINDING_ONLY",
                }
                for binding in self.pack.tool_bindings
            ],
            "authority": "CATALOG_AND_CONTROLLER_ONLY",
        }


EMPTY_EXTENSION_RUNTIME = ExtensionRuntime(pack=None, source_sha256=None)


def load_extension_pack(path_value: str | None) -> ExtensionRuntime:
    """Load one bounded JSON manifest, or return the disabled runtime when no path is set."""

    if path_value is None or path_value == "":
        return EMPTY_EXTENSION_RUNTIME
    try:
        path = Path(path_value)
        if not path.is_absolute() or path.is_symlink() or not path.is_file():
            raise OSError
        file_stat = path.stat()
        if file_stat.st_size > _MAX_MANIFEST_BYTES or file_stat.st_mode & (
            stat.S_IWGRP | stat.S_IWOTH
        ):
            raise OSError
        raw = path.read_bytes()
        if len(raw) > _MAX_MANIFEST_BYTES:
            raise OSError
        pack = ExtensionPack.model_validate_json(raw)
    except (OSError, UnicodeError, ValueError) as exc:
        raise RuntimeError("AEGIS extension manifest is unavailable or invalid") from exc
    return ExtensionRuntime(pack=pack, source_sha256=hashlib.sha256(raw).hexdigest())
