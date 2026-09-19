from typing import Any, Literal

Variant = Literal["vulnerable", "patched"]
OBJECTS = {"A-100": "user-a", "B-200": "user-b"}
PROFILE_ACTORS = {"user_a": "user-a", "user_b": "user-b"}


def account_path(variant: Variant) -> str:
    prefix = "/api/v1/patched" if variant == "patched" else "/api/v1"
    return prefix + "/accounts/{account_id}"


def compact_surface(spec: dict[str, Any], variant: Variant) -> dict[str, Any]:
    """Project untrusted OpenAPI onto the locally authorized lab surface.

    Descriptions, examples, servers, refs and extension values never enter a model prompt.
    Importing a spec cannot grant authority to a new route, host, object or method.
    """
    candidate = account_path(variant)
    paths = spec.get("paths", {})
    if not isinstance(paths, dict) or not isinstance(paths.get(candidate), dict):
        raise ValueError("No object-level authorization candidate found in the API definition")
    if "get" not in paths[candidate]:
        raise ValueError("No object-level authorization candidate found in the API definition")
    return {
        "paths": {candidate: {"get": {"path_parameter": "account_id"}}},
        "available_credentials": ["anonymous", "user_a", "user_b"],
        "known_test_objects": {"user_a": ["A-100"], "user_b": ["B-200"]},
    }
