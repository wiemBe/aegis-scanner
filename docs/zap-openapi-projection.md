# ZAP OpenAPI projection (Phase 1.3)

ZAP never receives an application's own OpenAPI document or an OpenAPI URL. For one inventory
target, the controller builds a **new** minimal OpenAPI 3.0.3 document
(`src/aegis_zap/projection.py`, projection version `1.3.0`). The isolated runner re-derives the same
document from its own copy of the inventory and refuses to start ZAP unless its digests match the
controller's. ZAP imports it with the Automation Framework `openapi` job using `apiFile` — never
`apiUrl`.

## Inputs (controller-owned only)

`src/aegis_zap/inventory.py` holds each target reference: the approved origin
(`http://lab-api:8001`), a checked-in source document under `src/aegis_zap/sources/`, the exact
operation ids that may be projected, and bounded non-secret values for their path parameters
(`catalog_id = synthetic-catalog-1`). The model, the operator request body and the RPC caller can
only name a target **reference**; they cannot supply a document, URL, operation or value.

## What the projection contains

- `servers`: exactly the inventory origin (the source's `servers` are validated, never copied);
- the approved GET/HEAD operations with their operation ids;
- path parameters as `required`, `schema: {type: string, enum: [value]}` and `example: value`,
  using only inventory values;
- one minimal response per operation (`200: Synthetic response`);
- nothing else: no descriptions, summaries, tags, security requirements or schemes, examples,
  request bodies, response content, schemas, components, extensions or external docs.

Output bytes are canonical JSON (sorted keys, no whitespace), so the same target always yields the
same bytes and SHA-256.

## What rejects the whole projection

| Condition | Code |
| --- | --- |
| Source over 128 KiB, over 20,000 nodes or any string over 4 KiB | `SOURCE_OVERSIZED` |
| Invalid UTF-8/JSON or duplicate keys | `SOURCE_MALFORMED` |
| Nesting deeper than 24 | `EXCESSIVE_NESTING` |
| Not OpenAPI 3.0.x/3.1.x (e.g. Swagger 2.0) | `UNSUPPORTED_VERSION` |
| Any `$ref` not starting with `#/` (remote, relative-file or `file:`), `externalValue`, `operationRef` | `EXTERNAL_REFERENCE` |
| `webhooks` / any `callbacks` / any `links` | `WEBHOOKS_PRESENT` / `CALLBACKS_PRESENT` / `LINKS_PRESENT` |
| Top-level server other than the inventory origin, or path/operation-level `servers` | `ALTERNATE_SERVER` |
| Server variables or templated server URL | `SERVER_VARIABLES` |
| More than 64 paths / 128 operations / 8 approved operations | `TOO_MANY_PATHS` / `TOO_MANY_OPERATIONS` |
| Unknown HTTP method key (e.g. `connect`) | `CUSTOM_METHOD` |
| Path-item `$ref` | `PATH_ITEM_REFERENCE` |
| Approved operation id missing or duplicated | `OPERATION_NOT_FOUND` / `DUPLICATE_OPERATION_ID` |
| Approved operation is POST/PUT/PATCH/DELETE | `STATE_CHANGING_OPERATION` |
| Approved operation is OPTIONS/TRACE | `METHOD_NOT_ALLOWED` |
| Path outside `/lab/zap/...`, traversal, encoded or unsafe characters | `UNSAFE_PATH` |
| Required query/header/cookie parameter, or a path parameter without an inventory value | `UNAPPROVED_PARAMETER` |
| Credential-like material anywhere (Bearer tokens, `Authorization:`/`Cookie:`, `lab-token-`, key/secret/password assignments, JWTs, AWS keys, private keys) | `CREDENTIAL_MATERIAL` |

Optional non-path parameters and unapproved operations are **removed** and counted, not copied.

## Recorded provenance

Each execution records the source inventory reference and source SHA-256, the projection
reference (`<target_ref>/1.3.0`) and version, the projected document SHA-256, the operation-allowlist
SHA-256, the projected operation and path counts, the removed-operation count, the stripped
categories, the approved target reference and the redaction status (`REDACTED`).

## Current inventory

| Target reference | Purpose | Operations | Result |
| --- | --- | --- | --- |
| `synthetic-zap-vulnerable` | acceptance | `GET /lab/zap/vulnerable/status`, `GET /lab/zap/vulnerable/catalog/synthetic-catalog-1` | projected, 2 operations |
| `synthetic-zap-patched` | acceptance | `GET /lab/zap/patched/status`, `GET /lab/zap/patched/catalog/synthetic-catalog-1` | projected, 2 operations |
| `synthetic-zap-negative-state-changing` | negative control | status + `POST /lab/zap/admin/purge` | `STATE_CHANGING_OPERATION` |
| `synthetic-zap-negative-alternate-server` | negative control | status, source adds a production server | `ALTERNATE_SERVER` |
| `synthetic-zap-negative-external-ref` | negative control | status, source schema is a remote `$ref` | `EXTERNAL_REFERENCE` |
| `synthetic-zap-negative-redirect` | runtime negative | route answers 302 | projected; guard/runner fail closed |
| `synthetic-zap-negative-unstable` | runtime negative | route drops the connection | projected; guard/runner fail closed |
| `synthetic-zap-negative-slow` | runtime negative | route answers after 12 s | projected; runner fails closed |

The acceptance projections have SHA-256
`ca9a56e8b29ac37150dbd448b28aa2e535299205981c068dec550d3af13d1389` (vulnerable) and
`8022095f0a29cc71cb50de267562650790e5011298fa199f831bc60f24d5346c` (patched). Projection-time negative
controls are rejected before any runner contact or target traffic.
