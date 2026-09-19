import asyncio
import json
import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic
from uuid import uuid4

import httpx
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from aegis.engine.catalog import catalog_projection
from aegis.engine.contracts import ENGINE_KERNEL_VERSION, SecurityEngine
from aegis.models import EXECUTION_POLICY_VERSION, PLANNER_CONTRACT_VERSION, ScanCreate, ScanResult
from aegis.operator import (
    ActorType,
    AuditEnvelope,
    Engine,
    engine_readiness,
    evidence_cards,
    execution_policy_projection,
    finding_lifecycle_projection,
    finding_projection,
    project_event,
    scan_projection,
)
from aegis.planner import build_planner
from aegis.safety import SafetyController
from aegis.screenshots import ScreenshotStore
from aegis.service import ScanService
from aegis.settings import get_settings
from aegis.storage import ScanStore
from aegis.verifier import DeterministicVerifier

PACKAGE_DIR = Path(__file__).parent
settings = get_settings()
# Structural enforcement: the control plane must never receive a provider credential. It reaches
# the model only via the isolated llm-gateway. A credential mounted here is a misconfiguration.
if settings.ai_auth_token is not None:
    raise RuntimeError(
        "Control plane must not be given AI_AUTH_TOKEN; mount it only on the llm-gateway service"
    )
store = ScanStore(settings.database_path)
safety = SafetyController(settings)
planner = build_planner(settings)
service = ScanService(settings, store, planner, safety)
templates = Jinja2Templates(directory=PACKAGE_DIR / "templates")
screenshot_store = ScreenshotStore(Path(settings.database_path).parent / "screenshots")


class StreamConnections:
    def __init__(self, maximum: int = 8) -> None:
        self.maximum = maximum
        self.active = 0
        self._lock = asyncio.Lock()

    async def acquire(self) -> bool:
        async with self._lock:
            if self.active >= self.maximum:
                return False
            self.active += 1
            return True

    async def release(self) -> None:
        async with self._lock:
            self.active = max(0, self.active - 1)


streams = StreamConnections()


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    store.initialize()
    yield


app = FastAPI(title=settings.app_name, version="0.2.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=PACKAGE_DIR / "static"), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next: object) -> object:
    request_id = request.headers.get("x-request-id", "")
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", request_id):
        request_id = f"req-{uuid4().hex[:16]}"
    request.state.request_id = request_id
    response = await call_next(request)  # type: ignore[operator]
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; "
        "frame-ancestors 'none'; form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Request-ID"] = request_id
    return response


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    # Only LOCAL_LLM deployments carry an acceptance verdict badge; other modes show nothing.
    validation_status = (
        settings.local_llm_validation_status if planner.name == "LOCAL_LLM" else ""
    )
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "planner_mode": planner.name,
            "model_name": settings.ai_model if planner.name != "DEMO_HEURISTIC" else "",
            "validation_status": validation_status,
            "contract_version": PLANNER_CONTRACT_VERSION,
        },
    )


@app.get("/demo", response_class=HTMLResponse)
async def management_demo(request: Request) -> HTMLResponse:
    # Phase 0.9 focused management-demo view. It is additive and read-only: it renders the two demo
    # scans (discovery + linked retest) named by ?discovery=&retest= entirely from the existing
    # read-only scan API, and never alters the engineering dashboard at "/".
    return templates.TemplateResponse(
        request=request,
        name="demo.html",
        context={
            "planner_mode": planner.name,
            "model_name": settings.ai_model if planner.name != "DEMO_HEURISTIC" else "",
            "contract_version": PLANNER_CONTRACT_VERSION,
        },
    )


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "planner": planner.name}


@app.post("/api/scans", response_model=ScanResult, status_code=202)
async def create_scan(request: ScanCreate, background_tasks: BackgroundTasks) -> ScanResult:
    try:
        result = service.create(request)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    background_tasks.add_task(service.run, result.id)
    return result


@app.get("/api/scans", response_model=list[ScanResult])
async def list_scans() -> list[ScanResult]:
    return store.list_recent()


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str) -> dict[str, object]:
    result = store.get(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"scan": result.model_dump(mode="json"), "audit": store.audit(scan_id)}


def _linked_retests(scans: list[ScanResult], scan_id: str) -> list[ScanResult]:
    return [item for item in scans if item.retest_of == scan_id]


def _scan_projection(scan: ScanResult, linked_retests: list[str]) -> dict[str, object]:
    return scan_projection(
        scan,
        linked_retests,
        target_request_budget=settings.max_requests_per_scan,
        model_call_budget=settings.max_model_calls,
        token_budget=settings.max_tokens_per_scan,
    )


def _console_events(
    *, after_sequence: int = 0, limit: int = 100, scan_id: str | None = None
) -> list[AuditEnvelope]:
    scans = store.list_all()
    scan_map = {item.id: item for item in scans}
    rows = store.raw_audit_events(
        after_sequence=after_sequence,
        limit=limit,
        scan_id=scan_id,
    )
    projected: list[AuditEnvelope] = []
    for row in rows:
        current_scan = scan_map.get(str(row["scan_id"]))
        linked = _linked_retests(scans, str(row["scan_id"]))
        row["linked_retest_scan_id"] = linked[0].id if linked else None
        envelope = project_event(
            row,
            current_scan,
            parent_event_id=(
                f"evt-{int(row['parent_id']):012d}"
                if row.get("parent_id") is not None
                else None
            ),
        )
        projected.append(envelope)
    return projected


@app.get("/api/console/config")
async def console_config() -> dict[str, object]:
    return {
        "console_version": "1.0.0",
        "planner_contract_version": PLANNER_CONTRACT_VERSION,
        "execution_policy_version": EXECUTION_POLICY_VERSION,
        "scope_badges": ["SYNTHETIC LAB", "LOCAL LLM", "READ-ONLY", "AUTHORIZED TARGET"],
        "screenshots_enabled": screenshot_store.enabled,
        "operational_engines": [Engine.AEGIS_NATIVE],
        "engine_contract": [item.value for item in Engine],
        "actor_contract": [item.value for item in ActorType],
        "engine_kernel_version": ENGINE_KERNEL_VERSION,
        "engine_catalog": catalog_projection(),
    }


@app.get("/api/console/runs")
async def console_runs(limit: int = Query(default=50, ge=1, le=100)) -> dict[str, object]:
    scans = store.list_all(limit)
    return {
        "items": [
            _scan_projection(scan, [item.id for item in _linked_retests(scans, scan.id)])
            for scan in scans
        ],
        "count": len(scans),
    }


@app.get("/api/console/runs/{scan_id}")
async def console_run(scan_id: str) -> dict[str, object]:
    scan = store.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Run not found")
    scans = store.list_all()
    retests = _linked_retests(scans, scan.id)
    events = _console_events(scan_id=scan.id, limit=200)
    return {
        "run": _scan_projection(scan, [item.id for item in retests]),
        "events": [item.model_dump(mode="json") for item in events],
        "evidence": evidence_cards(scan),
        "screenshot_artifacts": [],
        "lifecycle": finding_lifecycle_projection(scan),
        "execution_policy": execution_policy_projection(scan),
    }


@app.get("/api/console/audit")
async def console_audit(
    request: Request,
    cursor: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
    scan_id: str | None = Query(default=None, max_length=64),
    finding_id: str | None = Query(default=None, max_length=128),
    actor: ActorType | None = None,
    stage: str | None = Query(default=None, max_length=40),
    status: str | None = Query(default=None, max_length=32),
    engine: Engine | None = None,
    event_type: str | None = Query(default=None, max_length=64),
    model: str | None = Query(default=None, max_length=100),
    operation: str | None = Query(default=None, max_length=120),
    principal_relationship: str | None = Query(default=None, max_length=32),
    safety_decision: str | None = Query(default=None, max_length=32),
    time_from: datetime | None = None,
    time_to: datetime | None = None,
) -> dict[str, object]:
    # Pull a bounded window and apply presentation-level filters after strict redaction.
    events = _console_events(after_sequence=cursor, limit=200, scan_id=scan_id)
    scans = {item.id: item for item in store.list_all()}

    def matches(item: AuditEnvelope) -> bool:
        scan = scans.get(item.scan_id)
        if finding_id and item.finding_id != finding_id:
            return False
        if actor and item.actor_type != actor:
            return False
        if stage and item.stage != stage:
            return False
        if status and item.status != status:
            return False
        if engine and item.engine != engine:
            return False
        if event_type and item.event_type != event_type:
            return False
        if model and (scan is None or scan.model != model):
            return False
        encoded = json.dumps(item.metadata, sort_keys=True)
        if operation and operation not in encoded:
            return False
        if principal_relationship and principal_relationship not in encoded:
            return False
        if safety_decision and safety_decision not in item.event_type:
            return False
        if time_from and item.timestamp < time_from:
            return False
        if time_to and item.timestamp > time_to:
            return False
        return True

    filtered = [item for item in events if matches(item)]
    page = filtered[:limit]
    next_cursor = page[-1].sequence if len(page) == limit else None
    store.audit_access(request.state.request_id, "/api/console/audit", "OK")
    return {
        "items": [item.model_dump(mode="json") for item in page],
        "next_cursor": next_cursor,
        "stable_order": "sequence ASC",
        "redacted": True,
    }


def _parse_event_cursor(value: str | None) -> int:
    if not value:
        return 0
    if value.isdigit():
        return int(value)
    match = re.fullmatch(r"evt-([0-9]{12})", value)
    if not match:
        raise HTTPException(status_code=400, detail="Invalid event cursor")
    return int(match.group(1))


@app.get("/api/console/events")
async def console_event_stream(
    request: Request,
    last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
    cursor: str | None = Query(default=None, max_length=32),
) -> StreamingResponse:
    start = _parse_event_cursor(last_event_id or cursor)
    if not await streams.acquire():
        raise HTTPException(status_code=429, detail="Event stream connection limit reached")
    store.audit_access(request.state.request_id, "/api/console/events", "OPEN")

    async def generate() -> AsyncIterator[str]:
        sequence = start
        last_heartbeat = monotonic()
        try:
            while True:
                if await request.is_disconnected():
                    break
                events = _console_events(after_sequence=sequence, limit=100)
                if events and events[0].sequence > sequence + 1 and sequence > 0:
                    gap = {"expected": sequence + 1, "received": events[0].sequence}
                    yield f"event: gap\ndata: {json.dumps(gap, separators=(',', ':'))}\n\n"
                for item in events:
                    if item.sequence <= sequence:
                        continue
                    payload = item.model_dump_json()
                    yield f"id: {item.event_id}\nevent: audit\ndata: {payload}\n\n"
                    sequence = item.sequence
                now = monotonic()
                if now - last_heartbeat >= 15:
                    yield f": heartbeat {datetime.now(UTC).isoformat()}\n\n"
                    last_heartbeat = now
                await asyncio.sleep(1)
        finally:
            await streams.release()
            store.audit_access(request.state.request_id, "/api/console/events", "CLOSED")

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"},
    )


def _verified_findings() -> list[tuple[ScanResult, int, list[ScanResult]]]:
    scans = store.list_all()
    verifier = DeterministicVerifier()
    output: list[tuple[ScanResult, int, list[ScanResult]]] = []
    for scan in scans:
        verified_ids = {
            item.id
            for item in verifier.verify(
                scan.hypotheses, scan.evidence, scan.variant, scan_id=scan.id
            )
        }
        for index, finding in enumerate(scan.findings):
            if finding.id in verified_ids:
                output.append((scan, index, _linked_retests(scans, scan.id)))
    return output


@app.get("/api/console/findings")
async def console_findings(limit: int = Query(default=50, ge=1, le=100)) -> dict[str, object]:
    findings = _verified_findings()[:limit]
    return {
        "items": [finding_projection(scan, index, retests) for scan, index, retests in findings],
        "provenance_policy": "Only deterministic verifier-generated records are displayed.",
    }


@app.get("/api/console/findings/{finding_id}")
async def console_finding(finding_id: str) -> dict[str, object]:
    for scan, index, retests in _verified_findings():
        if scan.findings[index].id == finding_id:
            return {
                "finding": finding_projection(scan, index, retests),
                "evidence": evidence_cards(scan),
                "retest": _scan_projection(retests[0], []) if retests else None,
            }
    raise HTTPException(status_code=404, detail="Verified finding not found")


async def _check_json(url: str) -> tuple[str, dict[str, object] | None]:
    try:
        async with httpx.AsyncClient(timeout=1.5, trust_env=False) as client:
            response = await client.get(url)
            response.raise_for_status()
            body = response.json()
        return "HEALTHY", body if isinstance(body, dict) else None
    except (httpx.HTTPError, ValueError):
        return "UNAVAILABLE", None


@app.get("/api/console/integrations")
async def console_integrations() -> dict[str, object]:
    gateway_status, gateway = await _check_json(f"{settings.llm_gateway_url}/health")
    local_connected = planner.name == "LOCAL_LLM" and gateway_status == "HEALTHY"
    model = gateway.get("model") if gateway else settings.ai_model
    return {
        "items": [
            {"name": "Aegis Native", "engine": "AEGIS_NATIVE", "state": "CONNECTED"},
            {
                "name": "Local LLM",
                "engine": "LOCAL_LLM",
                "state": "CONNECTED" if local_connected else "NOT_CONNECTED",
                "model": model,
                "digest": gateway.get("model_digest") if gateway else None,
                "provider": gateway.get("provider") if gateway else None,
            },
            {"name": "Nuclei", "engine": "NUCLEI", "state": "PLANNED_NOT_CONNECTED"},
            {"name": "ZAP", "engine": "ZAP", "state": "PLANNED_NOT_CONNECTED"},
            {"name": "Burp DAST", "engine": "BURP_DAST", "state": "PLANNED_NOT_CONNECTED"},
        ]
    }


@app.get("/api/console/engines")
async def console_engines() -> dict[str, object]:
    # Honest, four-state engine readiness. Only AEGIS_NATIVE is enabled; the three planned engines
    # are DISABLED and fail closed. The native engine's `reachable` reflects the real lab health.
    lab_status, _ = await _check_json(f"{settings.lab_base_url}/health")
    healths = []
    for health in service.dispatcher.health():
        if health.engine is SecurityEngine.AEGIS_NATIVE:
            health = health.model_copy(update={"reachable": lab_status == "HEALTHY"})
        healths.append(health)
    return {
        "items": engine_readiness(healths),
        "kernel_version": ENGINE_KERNEL_VERSION,
        "operational_engines": [SecurityEngine.AEGIS_NATIVE.value],
    }


@app.get("/api/console/health")
async def console_health() -> dict[str, object]:
    lab_status, _ = await _check_json(f"{settings.lab_base_url}/health")
    gateway_status, gateway = await _check_json(f"{settings.llm_gateway_url}/health")
    db_status = "HEALTHY"
    try:
        store.list_recent(1)
    except OSError:
        db_status = "UNAVAILABLE"
    database = Path(settings.database_path)
    return {
        "checked_at": datetime.now(UTC).isoformat(),
        "control_plane": "HEALTHY",
        "gateway": gateway_status,
        "ollama": gateway_status if planner.name == "LOCAL_LLM" else "NOT_CONFIGURED",
        "model": gateway.get("model") if gateway else settings.ai_model,
        "model_digest": gateway.get("model_digest") if gateway else None,
        "lab": lab_status,
        "dashboard_api": "HEALTHY",
        "database": db_status,
        "network_isolation": "CONFIGURED_NOT_RUNTIME_ATTESTED",
        "last_topology_test": "NOT_AVAILABLE_IN_RUNTIME",
        "last_secret_scan": "NOT_AVAILABLE_IN_RUNTIME",
        "event_stream": {"state": "AVAILABLE", "active": streams.active, "limit": streams.maximum},
        "evidence_storage": {
            "database_bytes": database.stat().st_size if database.exists() else 0,
            "screenshot_bytes": screenshot_store.usage(),
            "screenshot_quota_bytes": screenshot_store.max_bytes,
        },
    }


@app.get("/api/console/screenshots")
async def console_screenshots() -> dict[str, object]:
    return {
        "enabled": False,
        "capture_runner": "INACTIVE",
        "items": [],
        "fixture_notice": (
            "No browser capture runner is connected. Any future UI fixture is labeled "
            "BROWSER_SCREENSHOT / FIXTURE / NOT SCAN EVIDENCE."
        ),
        "policy": {
            "allowed_origins": ["lab-api", "127.0.0.1", "localhost"],
            "mime_types": sorted(["image/png", "image/webp"]),
            "max_bytes": 5_000_000,
            "max_dimensions": [2560, 1600],
            "retention_hours": screenshot_store.retention_hours,
            "sent_to_llm": False,
        },
    }


CONSOLE_DIR = PACKAGE_DIR / "console"
if CONSOLE_DIR.exists():
    app.mount("/console", StaticFiles(directory=CONSOLE_DIR, html=True), name="console")


if __name__ == "__main__":
    asyncio.run(service.run(service.create().id))
