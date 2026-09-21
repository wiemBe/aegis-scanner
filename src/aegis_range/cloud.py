"""Aegis Cloud: deterministic integration-check service with a synthetic-only canary."""

from __future__ import annotations

import io
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from xml.sax import SAXException, handler, make_parser

import httpx
from fastapi import Cookie, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from aegis_range.cloud_fixture import credential
from aegis_range.documents import openapi_document
from aegis_range.runtime import Mode, ScenarioRuntime, management_router

SERVICE = "aegis-cloud"
SCENARIO = "cloud-integration-fetch-v1"
XXE_SCENARIO = "cloud-xml-import-v1"
CORS_SCENARIO = "cloud-workspace-sharing-v1"
METADATA_SCENARIO = "cloud-metadata-response-v1"
INTERNAL_SCENARIO = "cloud-service-access-v1"
CANARY_ORIGIN = "http://range-canary:8500"
ADMIN_ORIGIN = "http://cloud-admin:8700"
runtime = ScenarioRuntime(
    SERVICE, (SCENARIO, XXE_SCENARIO, CORS_SCENARIO, METADATA_SCENARIO, INTERNAL_SCENARIO)
)
app = FastAPI(title="Aegis Cloud", version="1.0.0", openapi_url=None, docs_url=None, redoc_url=None)
app.state.canary_transport = None
app.state.admin_transport = None
XML_FIXTURE = Path(__file__).parent / "fixtures" / "cloud" / "resource.txt"


class IntegrationCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=8, max_length=240)


class XmlImport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    document: str = Field(min_length=3, max_length=4000)


class InternalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    access_token: str = Field(min_length=10, max_length=240)


class _NameHandler(handler.ContentHandler):
    def __init__(self) -> None:
        super().__init__()
        self.in_name = False
        self.parts: list[str] = []

    def startElement(self, name: str, attrs: object) -> None:  # noqa: N802 - SAX API
        if name == "name":
            self.in_name = True

    def endElement(self, name: str) -> None:  # noqa: N802 - SAX API
        if name == "name":
            self.in_name = False

    def characters(self, content: str) -> None:
        if self.in_name:
            self.parts.append(content)


class _FixtureResolver(handler.EntityResolver):
    def resolveEntity(self, public_id: str | None, system_id: str) -> str:  # noqa: N802
        if public_id is not None or system_id != "file:///fixtures/cloud/resource.txt":
            raise SAXException("resource unavailable")
        return XML_FIXTURE.resolve().as_uri()


def _canary_path(url: str) -> str | None:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "range-canary"
        or parsed.port != 8500
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/status/")
    ):
        return None
    return parsed.path


@app.get("/health", include_in_schema=False)
def health() -> dict[str, str]:
    return {"status": "ok", "service": SERVICE, "seed": "2026.1"}


@app.get("/openapi.json", include_in_schema=False)
def openapi() -> dict[str, object]:
    return openapi_document(SERVICE)


@app.get("/api/integrations", operation_id="listIntegrations")
def integrations() -> dict[str, object]:
    return {"integrations": [{"name": "Partner Catalog", "status": "configured"}]}


@app.post("/api/integrations/check", operation_id="checkIntegration")
async def check(payload: IntegrationCheck, request: Request) -> dict[str, Any]:
    if payload.url == "https://status.partner.invalid/health":
        return {"reachable": True, "status_code": 200, "service": "Partner Catalog"}
    canary_path = _canary_path(payload.url)
    if canary_path is None or runtime.mode(SCENARIO) is Mode.PATCHED:
        raise HTTPException(status_code=400, detail="Integration destination is not approved")
    transport: httpx.AsyncBaseTransport | None = request.app.state.canary_transport
    async with httpx.AsyncClient(
        timeout=2, follow_redirects=False, trust_env=False, transport=transport
    ) as client:
        response = await client.get(
            CANARY_ORIGIN + canary_path,
            headers={"X-Range-Generation": str(runtime.generation)},
        )
    if response.status_code != 200 or len(response.content) > 4096:
        raise HTTPException(status_code=502, detail="Integration check failed")
    body: object = response.json()
    if not isinstance(body, dict):
        raise HTTPException(status_code=502, detail="Integration check failed")
    result = dict(body)
    if runtime.mode(METADATA_SCENARIO) is Mode.PATCHED:
        result.pop("access_token", None)
        result.pop("token_type", None)
    return {"reachable": True, "status_code": response.status_code, "result": result}


@app.get("/api/regions", operation_id="listRegions")
def regions() -> dict[str, object]:
    return {"regions": ["eu-central", "eu-west"]}


@app.post("/api/imports/xml", operation_id="importIntegrationXml")
def import_xml(payload: XmlImport) -> dict[str, str]:
    document = payload.document
    entity = re.search(
        r'<!ENTITY\s+resource\s+SYSTEM\s+"file:///fixtures/cloud/resource.txt"\s*>', document
    )
    if "<!DOCTYPE" in document:
        if (
            runtime.mode(XXE_SCENARIO) is Mode.PATCHED
            or entity is None
            or document.count("<!ENTITY") != 1
        ):
            raise HTTPException(status_code=400, detail="Import document could not be processed")
    # The vulnerable half intentionally demonstrates external-entity handling. The
    # resolver below admits one exact synthetic fixture and rejects every other ID.
    parser = make_parser()  # noqa: S317 - bounded vulnerable-range parser
    parser.setFeature(handler.feature_external_ges, runtime.mode(XXE_SCENARIO) is Mode.VULNERABLE)
    parser.setFeature(handler.feature_external_pes, False)
    result = _NameHandler()
    parser.setContentHandler(result)
    parser.setEntityResolver(_FixtureResolver())
    try:
        parser.parse(io.StringIO(document))
    except (SAXException, ValueError) as exc:
        raise HTTPException(
            status_code=400, detail="Import document could not be processed"
        ) from exc
    name = "".join(result.parts).strip()
    if not name or len(name) > 200:
        raise HTTPException(status_code=400, detail="Import document could not be processed")
    return {"name": name, "status": "imported"}


def _cors_headers(origin: str | None) -> dict[str, str]:
    if runtime.mode(CORS_SCENARIO) is Mode.VULNERABLE and origin:
        return {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"}
    if origin == "https://portal.aegis.invalid":
        return {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
            "Vary": "Origin",
        }
    return {}


@app.options("/api/workspaces/current", operation_id="preflightCurrentWorkspace")
def workspace_preflight(request: Request) -> Response:
    headers = _cors_headers(request.headers.get("origin"))
    headers["Access-Control-Allow-Methods"] = "GET"
    headers["Access-Control-Allow-Headers"] = "Authorization"
    return Response(status_code=204, headers=headers)


@app.get("/api/workspaces/current", operation_id="getCurrentWorkspace")
def workspace(
    request: Request,
    cloud_session: str | None = Cookie(default=None),
) -> Response:
    import json

    if cloud_session != "synthetic-cloud-session":
        raise HTTPException(status_code=401, detail="Session unavailable")
    return Response(
        json.dumps({"workspace_id": "WS-100", "name": "Synthetic Workspace"}),
        media_type="application/json",
        headers=_cors_headers(request.headers.get("origin")),
    )


async def _admin(request: Request, access_token: str, mode: str) -> httpx.Response:
    transport: httpx.AsyncBaseTransport | None = request.app.state.admin_transport
    async with httpx.AsyncClient(
        base_url=ADMIN_ORIGIN,
        timeout=2,
        follow_redirects=False,
        trust_env=False,
        transport=transport,
    ) as client:
        return await client.get(
            "/v1/summary",
            headers={
                "Authorization": f"Bearer {access_token}",
                "X-Range-Generation": str(runtime.generation),
                "X-Validation-Mode": mode,
            },
        )


@app.get("/api/operations/summary", operation_id="getOperationsSummary")
async def operations_summary(request: Request) -> dict[str, str]:
    response = await _admin(request, credential(runtime.generation, "admin-service"), "strict")
    if response.status_code != 200:
        raise HTTPException(status_code=502, detail="Operation unavailable")
    return {"status": "ready"}


@app.post("/api/integrations/execute", operation_id="executeIntegrationOperation")
async def execute(payload: InternalRequest, request: Request) -> dict[str, str]:
    mode = "compatibility" if runtime.mode(INTERNAL_SCENARIO) is Mode.VULNERABLE else "strict"
    response = await _admin(request, payload.access_token, mode)
    if response.status_code != 200:
        raise HTTPException(status_code=403, detail="Operation unavailable")
    body = response.json()
    return {"status": "completed", "effect": str(body["effect"])}


app.include_router(management_router(runtime))
