"""Deterministic, fail-closed active-scan OpenAPI projection (Phase 1.5).

ZAP never receives the application's original OpenAPI document. For one inventory target the
projection builds a NEW minimal OpenAPI 3.0.3 document that contains only:

- the approved origin, taken from the controller inventory (never from the source's ``servers``);
- exactly one approved GET operation whose path is under ``/lab/zap-active/``;
- exactly one bounded query parameter (the projected parameter ZAP is allowed to mutate), with a
  bounded, non-secret example value and a length-capped string schema;
- a minimal 200 response.

The whole source document is validated first with the same structural guard as the passive
projection (external/file ``$ref``, callbacks, webhooks, links, alternate/templated servers,
credential material, over-size/over-nesting all reject the entire projection). A state-changing or
non-GET operation, an unexpected parameter, or any parameter other than the single projected query
parameter rejects the projection. Output bytes are canonical JSON so the digest is identical on the
controller and inside the isolated runner.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

from aegis_zap.projection import (
    MAX_SOURCE_BYTES,
    ProjectionErrorCode,
    ProjectionRejected,
    _check_servers,
    _no_duplicate_keys,
    _walk,
    canonical_json,
)
from aegis_zap_active.inventory import ZapActiveTarget, source_bytes, source_sha256

PROJECTION_VERSION = "1.5.0"
PROJECTION_ENGINE = f"aegis-zap-active-projection/{PROJECTION_VERSION}"

MAX_QUERY_VALUE = 32
EXAMPLE_QUERY_VALUE = "aegis-probe"
_PATH = re.compile(r"^/lab/zap-active/[a-z][a-z0-9-]{0,30}/[a-z][a-z0-9-]{0,30}$")
_OP_ID = re.compile(r"^[A-Za-z][A-Za-z0-9]{2,80}$")
_PARAM_NAME = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_PATH_ITEM_FIELDS = frozenset({"summary", "description", "parameters", "servers", "$ref"})
STATE_CHANGING_METHODS = frozenset({"post", "put", "patch", "delete"})


@dataclass(frozen=True)
class ActiveProjectionResult:
    projection_version: str
    target_ref: str
    origin: str
    source_name: str
    source_sha256: str
    method: str  # "GET"
    path: str
    operation_id: str
    query_param: str
    document: bytes
    digest: str
    allowlist_digest: str
    removed_operations: int

    @property
    def operation_count(self) -> int:
        return 1

    @property
    def path_count(self) -> int:
        return 1

    @property
    def url(self) -> str:
        return f"{self.origin}{self.path}"

    @property
    def urls(self) -> tuple[str, ...]:
        return (self.url,)

    @property
    def query_params(self) -> tuple[str, ...]:
        return (self.query_param,)

    @property
    def redaction_status(self) -> str:
        return "REDACTED" if self.removed_operations else "NOT_REQUIRED"


def projection_ref(target_ref: str) -> str:
    return f"{target_ref}/{PROJECTION_VERSION}"


def allowlist_digest(method: str, path: str, operation_id: str, query_param: str) -> str:
    rows = [[method, path, operation_id, query_param]]
    return hashlib.sha256(canonical_json(rows)).hexdigest()


def _resolve_parameter(doc: dict[str, object], item: object) -> dict[str, object]:
    if not isinstance(item, dict):
        raise ProjectionRejected(ProjectionErrorCode.SOURCE_MALFORMED, "parameter")
    ref = item.get("$ref")
    if ref is None:
        return item
    prefix = "#/components/parameters/"
    if not isinstance(ref, str) or not ref.startswith(prefix) or len(item) != 1:
        raise ProjectionRejected(ProjectionErrorCode.SOURCE_MALFORMED, "parameter ref")
    components = doc.get("components")
    params = components.get("parameters") if isinstance(components, dict) else None
    target = params.get(ref[len(prefix) :]) if isinstance(params, dict) else None
    if not isinstance(target, dict) or "$ref" in target:
        raise ProjectionRejected(ProjectionErrorCode.SOURCE_MALFORMED, "parameter ref target")
    return target


def project(target: ZapActiveTarget, source: bytes | None = None) -> ActiveProjectionResult:
    """Build the active projection for one inventory target, or raise ``ProjectionRejected``."""

    raw = source if source is not None else source_bytes(target)
    if len(raw) > MAX_SOURCE_BYTES:
        raise ProjectionRejected(ProjectionErrorCode.SOURCE_OVERSIZED)
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise ProjectionRejected(ProjectionErrorCode.SOURCE_MALFORMED) from None
    if not isinstance(doc, dict):
        raise ProjectionRejected(ProjectionErrorCode.SOURCE_MALFORMED)
    version = doc.get("openapi")
    if not isinstance(version, str) or not re.fullmatch(r"3\.(0|1)\.[0-9]+", version):
        raise ProjectionRejected(ProjectionErrorCode.UNSUPPORTED_VERSION)
    if doc.get("webhooks"):
        raise ProjectionRejected(ProjectionErrorCode.WEBHOOKS_PRESENT)
    _walk(doc, 0, [0], None)
    if target.origin.rstrip("/") != target.origin or not re.fullmatch(
        r"http://[a-z0-9.-]+:[0-9]{1,5}", target.origin
    ):
        raise ProjectionRejected(ProjectionErrorCode.ORIGIN_NOT_APPROVED)
    _check_servers(doc, target.origin)

    paths = doc.get("paths")
    if not isinstance(paths, dict) or not paths:
        raise ProjectionRejected(ProjectionErrorCode.SOURCE_MALFORMED, "paths")

    found: tuple[str, str, dict[str, object], dict[str, object]] | None = None
    total_operations = 0
    for template, item in paths.items():
        if not isinstance(item, dict):
            raise ProjectionRejected(ProjectionErrorCode.SOURCE_MALFORMED, "path item")
        if "$ref" in item:
            raise ProjectionRejected(ProjectionErrorCode.PATH_ITEM_REFERENCE)
        for key, operation in item.items():
            if key in _PATH_ITEM_FIELDS or key.startswith("x-"):
                continue
            method = key.lower()
            if key != method or not isinstance(operation, dict):
                raise ProjectionRejected(ProjectionErrorCode.CUSTOM_METHOD)
            total_operations += 1
            op_id = operation.get("operationId")
            if not isinstance(op_id, str) or not _OP_ID.fullmatch(op_id):
                raise ProjectionRejected(ProjectionErrorCode.SOURCE_MALFORMED, "operationId")
            if op_id == target.operation_id:
                found = (template, method, item, operation)

    if found is None:
        raise ProjectionRejected(ProjectionErrorCode.OPERATION_NOT_FOUND, target.operation_id)
    template, method, item, operation = found
    if method in STATE_CHANGING_METHODS:
        raise ProjectionRejected(ProjectionErrorCode.STATE_CHANGING_OPERATION, target.operation_id)
    if method != "get":
        raise ProjectionRejected(ProjectionErrorCode.METHOD_NOT_ALLOWED, target.operation_id)
    if not isinstance(template, str) or not _PATH.fullmatch(template):
        raise ProjectionRejected(ProjectionErrorCode.UNSAFE_PATH, target.operation_id)

    # Exactly the single projected query parameter; a path/header/cookie parameter, a second query
    # parameter, or a different name rejects the projection.
    query_names: list[str] = []
    declared: list[object] = []
    for source_params in (item.get("parameters"), operation.get("parameters")):
        if source_params is None:
            continue
        if not isinstance(source_params, list):
            raise ProjectionRejected(ProjectionErrorCode.SOURCE_MALFORMED, "parameters")
        declared.extend(source_params)
    for raw_param in declared:
        param = _resolve_parameter(doc, raw_param)
        location, name = param.get("in"), param.get("name")
        if not isinstance(name, str) or location not in {"path", "query", "header", "cookie"}:
            raise ProjectionRejected(ProjectionErrorCode.SOURCE_MALFORMED, "parameter")
        if location != "query":
            raise ProjectionRejected(ProjectionErrorCode.UNAPPROVED_PARAMETER, name)
        if not _PARAM_NAME.fullmatch(name):
            raise ProjectionRejected(ProjectionErrorCode.UNAPPROVED_PARAMETER, name)
        query_names.append(name)
    if query_names != [target.query_param]:
        raise ProjectionRejected(ProjectionErrorCode.UNAPPROVED_PARAMETER, target.operation_id)

    document = canonical_json(
        {
            "openapi": "3.0.3",
            "info": {"title": "Aegis projected active surface", "version": PROJECTION_VERSION},
            "servers": [{"url": target.origin}],
            "paths": {
                template: {
                    "get": {
                        "operationId": target.operation_id,
                        "parameters": [
                            {
                                "name": target.query_param,
                                "in": "query",
                                "required": True,
                                "schema": {"type": "string", "maxLength": MAX_QUERY_VALUE},
                                "example": EXAMPLE_QUERY_VALUE,
                            }
                        ],
                        "responses": {"200": {"description": "Synthetic response"}},
                    }
                }
            },
        }
    )
    return ActiveProjectionResult(
        projection_version=PROJECTION_VERSION,
        target_ref=target.target_ref,
        origin=target.origin,
        source_name=target.source,
        source_sha256=(
            hashlib.sha256(raw).hexdigest() if source is not None else source_sha256(target)
        ),
        method="GET",
        path=template,
        operation_id=target.operation_id,
        query_param=target.query_param,
        document=document,
        digest=hashlib.sha256(document).hexdigest(),
        allowlist_digest=allowlist_digest("GET", template, target.operation_id, target.query_param),
        removed_operations=total_operations - 1,
    )
