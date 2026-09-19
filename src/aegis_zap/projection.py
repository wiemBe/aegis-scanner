"""Deterministic, fail-closed projection of a controller-owned OpenAPI source for ZAP.

ZAP never receives an application's original OpenAPI document. For one inventory target the
projection builds a NEW minimal OpenAPI 3.0.3 document that contains only:

- the approved origin, taken from the controller inventory (never from the source's ``servers``);
- the approved GET/HEAD operations named by the inventory allowlist, with their operation ids;
- bounded, non-secret example values for their path parameters, taken from the inventory;
- a minimal response object per operation (no schemas are needed for import).

The source document is validated as a whole first. Anything that could introduce a new request,
destination or credential rejects the entire projection: remote/external/file ``$ref`` or
``externalValue``, callbacks, webhooks, links, alternate or templated servers, custom methods,
path-item references, credential-like material, oversized/over-nested documents. Approving a
state-changing or non-read-only operation is rejected; unapproved operations, descriptions,
examples, security, tags, extensions and schemas are removed.

The output bytes are canonical JSON, so the same inventory entry always yields the same bytes and
the same SHA-256 on the controller and inside the isolated runner.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from aegis_zap.inventory import ZapTarget, source_bytes, source_sha256

PROJECTION_VERSION = "1.3.0"
PROJECTION_ENGINE = f"aegis-zap-openapi-projection/{PROJECTION_VERSION}"

MAX_SOURCE_BYTES = 131_072
MAX_DEPTH = 24
MAX_NODES = 20_000
MAX_SOURCE_PATHS = 64
MAX_SOURCE_OPERATIONS = 128
MAX_PROJECTED_OPERATIONS = 8
MAX_STRING = 4_096

READ_ONLY_METHODS = ("get", "head")
STATE_CHANGING_METHODS = frozenset({"post", "put", "patch", "delete"})
OTHER_OPENAPI_METHODS = frozenset({"options", "trace"})
_PATH_ITEM_FIELDS = frozenset({"summary", "description", "parameters", "servers", "$ref"})
_TEMPLATE = re.compile(r"^/lab/zap/[a-z0-9_-]+(?:/(?:[a-z0-9_-]+|\{[a-z_]{1,32}\}))*$")
_CONCRETE = re.compile(r"^/lab/zap/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*$")
_VALUE = re.compile(r"^[a-z0-9-]{1,64}$")
_PARAM = re.compile(r"\{([a-z_]{1,32})\}")
_CREDENTIAL = re.compile(
    r"(?i)(\bbearer\s+[a-z0-9._~+/=-]{8,}|authorization\s*:|\bcookie\s*:|set-cookie|lab-token-|"
    r"(api[_-]?key|secret|password|passwd|token)\s*[:=]\s*\S{4,}|"
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY)"
)


class ProjectionErrorCode(StrEnum):
    SOURCE_OVERSIZED = "SOURCE_OVERSIZED"
    SOURCE_MALFORMED = "SOURCE_MALFORMED"
    EXCESSIVE_NESTING = "EXCESSIVE_NESTING"
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    EXTERNAL_REFERENCE = "EXTERNAL_REFERENCE"
    WEBHOOKS_PRESENT = "WEBHOOKS_PRESENT"
    CALLBACKS_PRESENT = "CALLBACKS_PRESENT"
    LINKS_PRESENT = "LINKS_PRESENT"
    ALTERNATE_SERVER = "ALTERNATE_SERVER"
    SERVER_VARIABLES = "SERVER_VARIABLES"
    TOO_MANY_PATHS = "TOO_MANY_PATHS"
    TOO_MANY_OPERATIONS = "TOO_MANY_OPERATIONS"
    CUSTOM_METHOD = "CUSTOM_METHOD"
    PATH_ITEM_REFERENCE = "PATH_ITEM_REFERENCE"
    OPERATION_NOT_FOUND = "OPERATION_NOT_FOUND"
    DUPLICATE_OPERATION_ID = "DUPLICATE_OPERATION_ID"
    STATE_CHANGING_OPERATION = "STATE_CHANGING_OPERATION"
    METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
    UNSAFE_PATH = "UNSAFE_PATH"
    UNAPPROVED_PARAMETER = "UNAPPROVED_PARAMETER"
    CREDENTIAL_MATERIAL = "CREDENTIAL_MATERIAL"
    ORIGIN_NOT_APPROVED = "ORIGIN_NOT_APPROVED"


class ProjectionRejected(ValueError):
    """The projection refused the source. Carries a precise, UI-safe code only."""

    def __init__(self, code: ProjectionErrorCode, detail: str = "") -> None:
        super().__init__(code.value)
        self.code = code
        self.detail = detail[:120]


@dataclass(frozen=True)
class ProjectedOperation:
    method: str  # "GET" | "HEAD"
    path_template: str
    path: str
    operation_id: str


@dataclass(frozen=True)
class ProjectionResult:
    projection_version: str
    target_ref: str
    origin: str
    source_name: str
    source_sha256: str
    document: bytes
    digest: str
    operations: tuple[ProjectedOperation, ...]
    allowlist_digest: str
    removed_operations: int
    stripped_categories: tuple[str, ...]

    @property
    def operation_count(self) -> int:
        return len(self.operations)

    @property
    def path_count(self) -> int:
        return len({op.path for op in self.operations})

    @property
    def redaction_status(self) -> str:
        return "REDACTED" if self.stripped_categories or self.removed_operations else "NOT_REQUIRED"

    @property
    def urls(self) -> tuple[str, ...]:
        return tuple(f"{self.origin}{op.path}" for op in self.operations)


def projection_ref(target_ref: str) -> str:
    return f"{target_ref}/{PROJECTION_VERSION}"


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def allowlist_digest(operations: tuple[ProjectedOperation, ...]) -> str:
    rows = sorted([op.method, op.path, op.operation_id] for op in operations)
    return hashlib.sha256(canonical_json(rows)).hexdigest()


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _walk(node: Any, depth: int, counter: list[int], parent: str | None) -> None:
    """Whole-document structural validation (refs, callbacks, links, servers, size, strings)."""

    counter[0] += 1
    if counter[0] > MAX_NODES:
        raise ProjectionRejected(ProjectionErrorCode.SOURCE_OVERSIZED, "nodes")
    if depth > MAX_DEPTH:
        raise ProjectionRejected(ProjectionErrorCode.EXCESSIVE_NESTING)
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref":
                if not isinstance(value, str):
                    raise ProjectionRejected(ProjectionErrorCode.SOURCE_MALFORMED, "$ref")
                if not value.startswith("#/"):
                    raise ProjectionRejected(ProjectionErrorCode.EXTERNAL_REFERENCE)
            if key in {"externalValue", "operationRef"}:
                raise ProjectionRejected(ProjectionErrorCode.EXTERNAL_REFERENCE, key)
            if key == "callbacks":
                raise ProjectionRejected(ProjectionErrorCode.CALLBACKS_PRESENT)
            if key == "links":
                raise ProjectionRejected(ProjectionErrorCode.LINKS_PRESENT)
            if key == "servers" and parent is not None:
                # Path-item or operation-level servers can redirect traffic to a new origin.
                raise ProjectionRejected(ProjectionErrorCode.ALTERNATE_SERVER, "nested servers")
            _walk(value, depth + 1, counter, key)
    elif isinstance(node, list):
        for item in node:
            _walk(item, depth + 1, counter, parent)
    elif isinstance(node, str):
        if len(node) > MAX_STRING:
            raise ProjectionRejected(ProjectionErrorCode.SOURCE_OVERSIZED, "string")
        if _CREDENTIAL.search(node):
            raise ProjectionRejected(ProjectionErrorCode.CREDENTIAL_MATERIAL)


def _check_servers(doc: dict[str, Any], origin: str) -> None:
    servers = doc.get("servers")
    if servers is None:
        return
    if not isinstance(servers, list) or not servers:
        raise ProjectionRejected(ProjectionErrorCode.SOURCE_MALFORMED, "servers")
    for server in servers:
        if not isinstance(server, dict) or not isinstance(server.get("url"), str):
            raise ProjectionRejected(ProjectionErrorCode.SOURCE_MALFORMED, "server")
        if "variables" in server or "{" in server["url"]:
            raise ProjectionRejected(ProjectionErrorCode.SERVER_VARIABLES)
        if server["url"].rstrip("/") != origin.rstrip("/"):
            raise ProjectionRejected(ProjectionErrorCode.ALTERNATE_SERVER)


def _resolve_parameter(doc: dict[str, Any], item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ProjectionRejected(ProjectionErrorCode.SOURCE_MALFORMED, "parameter")
    ref = item.get("$ref")
    if ref is None:
        return item
    prefix = "#/components/parameters/"
    if not isinstance(ref, str) or not ref.startswith(prefix) or len(item) != 1:
        raise ProjectionRejected(ProjectionErrorCode.SOURCE_MALFORMED, "parameter ref")
    target = ((doc.get("components") or {}).get("parameters") or {}).get(ref[len(prefix) :])
    if not isinstance(target, dict) or "$ref" in target:
        raise ProjectionRejected(ProjectionErrorCode.SOURCE_MALFORMED, "parameter ref target")
    return target


def _stripped_categories(doc: dict[str, Any]) -> tuple[str, ...]:
    found: set[str] = set()

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in {"description", "summary"}:
                    found.add("descriptions")
                elif key == "tags":
                    found.add("tags")
                elif key in {"security", "securitySchemes"}:
                    found.add("security")
                elif key in {"example", "examples", "default"}:
                    found.add("examples")
                elif key == "externalDocs":
                    found.add("external_docs")
                elif key == "contact":
                    found.add("contact")
                elif key == "requestBody":
                    found.add("request_bodies")
                elif key == "content":
                    found.add("response_content")
                elif key.startswith("x-"):
                    found.add("extensions")
                visit(value)
        elif isinstance(node, list):
            for item in node:
                visit(item)

    visit(doc)
    if doc.get("components"):
        found.add("components")
    return tuple(sorted(found))


def project(target: ZapTarget, source: bytes | None = None) -> ProjectionResult:
    """Build the projection for one inventory target, or raise :class:`ProjectionRejected`."""

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
    if len(paths) > MAX_SOURCE_PATHS:
        raise ProjectionRejected(ProjectionErrorCode.TOO_MANY_PATHS)

    by_id: dict[str, tuple[str, str, dict[str, Any], dict[str, Any]]] = {}
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
            if key != method or method not in (
                set(READ_ONLY_METHODS) | STATE_CHANGING_METHODS | OTHER_OPENAPI_METHODS
            ):
                raise ProjectionRejected(ProjectionErrorCode.CUSTOM_METHOD)
            if not isinstance(operation, dict):
                raise ProjectionRejected(ProjectionErrorCode.SOURCE_MALFORMED, "operation")
            total_operations += 1
            op_id = operation.get("operationId")
            if not isinstance(op_id, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{2,80}", op_id):
                raise ProjectionRejected(ProjectionErrorCode.SOURCE_MALFORMED, "operationId")
            if op_id in by_id:
                raise ProjectionRejected(ProjectionErrorCode.DUPLICATE_OPERATION_ID)
            by_id[op_id] = (template, method, item, operation)
    if total_operations > MAX_SOURCE_OPERATIONS:
        raise ProjectionRejected(ProjectionErrorCode.TOO_MANY_OPERATIONS)

    wanted = target.operation_ids
    if not wanted or len(wanted) > MAX_PROJECTED_OPERATIONS or len(set(wanted)) != len(wanted):
        raise ProjectionRejected(ProjectionErrorCode.TOO_MANY_OPERATIONS, "allowlist")
    approved_values = dict(target.path_values)
    projected: list[tuple[ProjectedOperation, list[dict[str, Any]]]] = []
    for op_id in wanted:
        found = by_id.get(op_id)
        if found is None:
            raise ProjectionRejected(ProjectionErrorCode.OPERATION_NOT_FOUND, op_id)
        template, method, item, operation = found
        if method in STATE_CHANGING_METHODS:
            raise ProjectionRejected(ProjectionErrorCode.STATE_CHANGING_OPERATION, op_id)
        if method not in READ_ONLY_METHODS:
            raise ProjectionRejected(ProjectionErrorCode.METHOD_NOT_ALLOWED, op_id)
        if not isinstance(template, str) or not _TEMPLATE.fullmatch(template):
            raise ProjectionRejected(ProjectionErrorCode.UNSAFE_PATH, op_id)

        declared: dict[str, dict[str, Any]] = {}
        for raw_param in list(item.get("parameters") or []) + list(
            operation.get("parameters") or []
        ):
            param = _resolve_parameter(doc, raw_param)
            location, name = param.get("in"), param.get("name")
            if not isinstance(name, str) or location not in {"path", "query", "header", "cookie"}:
                raise ProjectionRejected(ProjectionErrorCode.SOURCE_MALFORMED, "parameter")
            if location != "path":
                # Anonymous, parameter-free requests only: an optional query/header/cookie
                # parameter is removed; a required one cannot be satisfied and is refused.
                if param.get("required") is True:
                    raise ProjectionRejected(ProjectionErrorCode.UNAPPROVED_PARAMETER, name)
                continue
            declared[name] = param

        names = _PARAM.findall(template)
        if set(names) != set(declared):
            raise ProjectionRejected(ProjectionErrorCode.UNAPPROVED_PARAMETER, op_id)
        concrete = template
        parameters: list[dict[str, Any]] = []
        for name in names:
            value = approved_values.get(name)
            if value is None or not _VALUE.fullmatch(value):
                raise ProjectionRejected(ProjectionErrorCode.UNAPPROVED_PARAMETER, name)
            concrete = concrete.replace("{" + name + "}", value, 1)
            parameters.append(
                {
                    "name": name,
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string", "enum": [value]},
                    "example": value,
                }
            )
        if not _CONCRETE.fullmatch(concrete):
            raise ProjectionRejected(ProjectionErrorCode.UNSAFE_PATH, op_id)
        projected.append(
            (ProjectedOperation(method.upper(), template, concrete, op_id), parameters)
        )

    if len({(op.method, op.path) for op, _ in projected}) != len(projected):
        raise ProjectionRejected(ProjectionErrorCode.DUPLICATE_OPERATION_ID, "method+path")

    out_paths: dict[str, dict[str, Any]] = {}
    ordered = sorted(projected, key=lambda pair: (pair[0].path_template, pair[0].method))
    for op, parameters in ordered:
        entry: dict[str, Any] = {
            "operationId": op.operation_id,
            "responses": {"200": {"description": "Synthetic response"}},
        }
        if parameters:
            entry["parameters"] = parameters
        out_paths.setdefault(op.path_template, {})[op.method.lower()] = entry
    document = canonical_json(
        {
            "openapi": "3.0.3",
            "info": {"title": "Aegis projected synthetic surface", "version": PROJECTION_VERSION},
            "servers": [{"url": target.origin}],
            "paths": out_paths,
        }
    )
    operations = tuple(sorted((op for op, _ in projected), key=lambda o: (o.path, o.method)))
    return ProjectionResult(
        projection_version=PROJECTION_VERSION,
        target_ref=target.target_ref,
        origin=target.origin,
        source_name=target.source,
        source_sha256=(
            hashlib.sha256(raw).hexdigest() if source is not None else source_sha256(target)
        ),
        document=document,
        digest=hashlib.sha256(document).hexdigest(),
        operations=operations,
        allowlist_digest=allowlist_digest(operations),
        removed_operations=total_operations - len(operations),
        stripped_categories=_stripped_categories(doc),
    )
