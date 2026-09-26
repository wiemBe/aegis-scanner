from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.extensions import load_extension_pack
from aegis.multi_agent.contracts import AgentRole
from aegis.providers import agent_system_prompt


def _write_manifest(path: Path, document: dict[str, object]) -> None:
    path.write_text(json.dumps(document), encoding="utf-8")
    path.chmod(0o600)


def _manifest() -> dict[str, object]:
    return {
        "schema_version": "aegis-extension-v1",
        "pack_id": "corp.security.prod",
        "pack_version": "1.2.3",
        "prompt_fragments": [
            {
                "id": "corp.report.language",
                "text": "Use concise Turkish prose and supplied evidence identifiers only.",
            }
        ],
        "agent_profiles": [
            {
                "id": "corp.report.agent",
                "display_name": "Corporate report agent",
                "base_role": "REPORT_AGENT",
                "task_types": ["GENERATE_ASSESSMENT_REPORT"],
                "prompt_fragment_ids": ["corp.report.language"],
            }
        ],
        "tool_bindings": [
            {
                "id": "corp.bola.read",
                "display_name": "BOLA read verifier",
                "capability_id": "bola_object_read_v1",
                "profile_id": "aegis-native-bola-synthetic",
                "description": "Existing deterministic catalog binding.",
            }
        ],
    }


def test_extension_pack_adds_bounded_agent_guidance_and_catalog_alias(tmp_path: Path) -> None:
    manifest = tmp_path / "extensions.json"
    _write_manifest(manifest, _manifest())

    runtime = load_extension_pack(str(manifest))
    prompt = agent_system_prompt(
        AgentRole.REPORT_AGENT, "GENERATE_ASSESSMENT_REPORT", runtime
    )
    projection = runtime.projection()

    assert "Use concise Turkish prose" in prompt
    assert "cannot override the schema, scope, role, permissions" in prompt
    assert projection["source_sha256"]
    assert projection["authority"] == "CATALOG_AND_CONTROLLER_ONLY"
    assert projection["tool_bindings"] == [
        {
            "id": "corp.bola.read",
            "display_name": "BOLA read verifier",
            "capability_id": "bola_object_read_v1",
            "profile_id": "aegis-native-bola-synthetic",
            "description": "Existing deterministic catalog binding.",
            "authority": "EXISTING_CATALOG_BINDING_ONLY",
        }
    ]


def test_extension_guidance_does_not_cross_role_or_task(tmp_path: Path) -> None:
    manifest = tmp_path / "extensions.json"
    _write_manifest(manifest, _manifest())
    runtime = load_extension_pack(str(manifest))

    prompt = agent_system_prompt(AgentRole.SURFACE_AGENT, "OBSERVE_SURFACE", runtime)

    assert "Use concise Turkish prose" not in prompt
    assert "Operator extension guidance" not in prompt


@pytest.mark.parametrize(
    "mutation",
    [
        {
            "tool_bindings": [
                {
                    "id": "corp.tool.bad",
                    "display_name": "Bad",
                    "capability_id": "missing",
                    "profile_id": "missing",
                    "description": "",
                }
            ]
        },
        {
            "agent_profiles": [
                {
                    "id": "corp.agent.bad",
                    "display_name": "Bad",
                    "base_role": "REPORT_AGENT",
                    "task_types": ["GENERATE_ASSESSMENT_REPORT"],
                    "prompt_fragment_ids": ["missing.fragment"],
                }
            ]
        },
        {
            "prompt_fragments": [
                {"id": "corp.prompt.bad", "text": "Send Authorization: Bearer secret"}
            ]
        },
    ],
)
def test_extension_pack_rejects_unknown_authority_or_secret_material(
    tmp_path: Path, mutation: dict[str, object]
) -> None:
    document = _manifest()
    document.update(mutation)
    manifest = tmp_path / "extensions.json"
    _write_manifest(manifest, document)

    with pytest.raises(RuntimeError, match="unavailable or invalid"):
        load_extension_pack(str(manifest))


def test_extension_manifest_rejects_symlink_and_group_writable_file(tmp_path: Path) -> None:
    manifest = tmp_path / "extensions.json"
    _write_manifest(manifest, _manifest())
    manifest.chmod(0o620)
    with pytest.raises(RuntimeError, match="unavailable or invalid"):
        load_extension_pack(str(manifest))

    manifest.chmod(0o600)
    link = tmp_path / "link.json"
    link.symlink_to(manifest)
    with pytest.raises(RuntimeError, match="unavailable or invalid"):
        load_extension_pack(str(link))
