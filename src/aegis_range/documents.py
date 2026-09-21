"""Load immutable checked-in public OpenAPI documents."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def openapi_document(service: str) -> dict[str, Any]:
    path = Path(__file__).with_name("openapi") / f"{service}.json"
    value: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("OpenAPI document root must be an object")
    return value
