import asyncio
import json
import re
import sqlite3
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic

import httpx
from fastapi import FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict, Field

from aegis import run_ledger, scm_verifier, zap_verifier
from aegis.beast.contracts import (
    TOOLBOX_PROFILE_SCENARIOS,
    BeastRun,
    BeastRunRequest,
    LeaseRequest,
)
from aegis.beast.controller import BeastController, BeastRejected
from aegis.beast.inventory import target as beast_target
from aegis.beast.store import BeastStore
from aegis.console_catalog import (
    ProfileAvailability,
    profile_directory,
    target_directory,
)
from aegis.engine.catalog import catalog_projection
from aegis.engine.contracts import ENGINE_KERNEL_VERSION, SecurityEngine
from aegis.extensions import load_extension_pack
from aegis.models import EXECUTION_POLICY_VERSION, PLANNER_CONTRACT_VERSION, ScanCreate, ScanResult
from aegis.multi_agent.benchmark import BenchmarkResultStore
from aegis.multi_agent.lifecycle import LifecycleLedger
from aegis.multi_agent.report_agent import (
    ReportAgentQueue,
    content_disposition,
    export_media_type,
    render_report_html,
    render_report_markdown,
    report_json,
)
from aegis.multi_agent.runtime import console_projection as multi_agent_projection
from aegis.multi_agent.staging import (
    EnvironmentTier,
    StagingLedger,
    deployment_disabled,
    staging_capability_state,
    tier_is_executable,
)
from aegis.multi_agent.store import MultiAgentStore
from aegis.observability import logger as obs_logger
from aegis.observability import metrics as obs_metrics
from aegis.operator import (
    ActorType,
    AuditEnvelope,
    Engine,
    engine_readiness,
    evidence_cards,
    execution_policy_projection,
    finding_lifecycle_projection,
    finding_projection,
    nuclei_summary,
    project_event,
    scan_projection,
    zap_summary,
)
from aegis.operator_session import OperatorSessionStore
from aegis.planner import GatewayPlanner, build_planner
from aegis.process_lifecycle import ProcessLifecycle, ProcessState, ServiceDraining
from aegis.readiness import ReadinessReport, evaluate_readiness
from aegis.safety import SafetyController
from aegis.screenshots import ScreenshotStore
from aegis.service import ScanService
from aegis.settings import get_settings
from aegis.storage import ScanStore
from aegis.target_inventory import (
    TargetCreate,
    TargetInventoryStore,
    TargetValidationError,
    scope_preview,
)
from aegis.verifier import DeterministicVerifier
from aegis.zap_active_controller import ZapActiveActivation, ZapActiveController
from aegis.zap_active_lease import LeaseError
from aegis_nuclei.manifest import load_manifest, manifest_digest
from aegis_obs.middleware import disable_uvicorn_access_log, observe_request
from aegis_zap.manifest import add_on_inventory_digest
from aegis_zap.manifest import load_manifest as load_zap_manifest
from aegis_zap.manifest import manifest_digest as zap_manifest_digest

PACKAGE_DIR = Path(__file__).parent
settings = get_settings()
extension_runtime = load_extension_pack(settings.extension_manifest_path)
# Structural enforcement: the control plane must never receive a provider credential. It reaches
# the model only via the isolated llm-gateway. A credential mounted here is a misconfiguration.
if (
    settings.ai_auth_token is not None
    or settings.ai_auth_token_file is not None
    or settings.openrouter_api_key is not None
    or settings.openrouter_api_key_file is not None
):
    raise RuntimeError(
        "Control plane must not be given a provider credential; mount it only on the "
        "llm-gateway service"
    )
store = ScanStore(settings.database_path)
safety = SafetyController(settings)
planner = build_planner(settings)
service = ScanService(settings, store, planner, safety)
process_lifecycle = ProcessLifecycle(
    grace_seconds=settings.shutdown_grace_seconds,
    logger=obs_logger,
    metrics=obs_metrics,
)
# Direct ASGI transports used by offline tests do not run lifespan. Production lifespan resets this
# to STARTING before initialization and then explicitly returns to SERVING.
process_lifecycle.mark_serving()
templates = Jinja2Templates(directory=PACKAGE_DIR / "templates")
screenshot_store = ScreenshotStore(Path(settings.database_path).parent / "screenshots")
# Persisted run ledger (one CSV/JSONL row per completed assessment), next to the SQLite database so
# it shares the same durability. Written fail-soft; served by GET /api/console/runs.csv.
run_ledger_dir = Path(settings.database_path).parent
beast_store = BeastStore(settings.database_path)
multi_agent_store = MultiAgentStore(settings.database_path)
# Phase 2.4 controller-owned single-agent vs multi-agent benchmark result store (read-only surface).
benchmark_store = BenchmarkResultStore(settings.database_path)
# Phase 2.5 controller-owned authenticated staging-progression ledger (read-only surface).
staging_ledger = StagingLedger(settings.database_path)
# Phase 2.6 controller-authoritative REPORT_AGENT job queue + report store (read-only surface).
report_agent_queue = ReportAgentQueue(settings.database_path)
# Phase 2.7 controller-governed assessment-lifecycle ledger (read-only surface).
lifecycle_ledger = LifecycleLedger(settings.database_path)
# Controller-owned operator target inventory (Phase 1.9.5). Persists onboarded company targets;
# the browser never holds authority over scope.
target_store = TargetInventoryStore(settings.database_path)
beast = BeastController(settings, beast_store)
# Phase 1.5. Constructing the controller is inert: it holds no lease and contacts nothing until an
# operator completes the activation ceremony. When ZAP Active is enabled the lease-signing secret
# must be real, so a misconfigured deployment fails here rather than scanning unauthenticated.
zap_active = ZapActiveController(settings, safety)
if settings.zap_active_enabled:
    settings.require_zap_active_lease_secret()
    settings.require_zap_active_runner_client_secret()
    settings.require_zap_active_operator_bootstrap_secret()
operator_sessions = OperatorSessionStore(
    settings.require_zap_active_operator_bootstrap_secret()
    if settings.zap_active_enabled
    else "disabled-operator-session-secret-000000000000"
)


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


def _debug_step(code: str) -> None:
    """Emit one bounded, secret-free controller checkpoint when diagnostic tracing is enabled."""

    if settings.debug_logging:
        obs_logger.log(
            service="control-plane",
            event="debug_step",
            level="DEBUG",
            request_id="-",
            code=code,
        )


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    # Replace Uvicorn's raw access log (which can expose paths/query strings) with our bounded,
    # secret-free structured request log. Defence in depth alongside `--no-access-log` in Compose.
    disable_uvicorn_access_log()
    _debug_step("startup.lifecycle.begin")
    process_lifecycle.start()
    _debug_step("startup.persistence.scan_store")
    store.initialize()
    _debug_step("startup.persistence.toolbox_store")
    beast_store.initialize()
    _debug_step("startup.persistence.multi_agent_store")
    multi_agent_store.initialize()
    _debug_step("startup.persistence.benchmark_store")
    benchmark_store.initialize()
    _debug_step("startup.persistence.staging_ledger")
    staging_ledger.initialize()
    _debug_step("startup.persistence.report_queue")
    report_agent_queue.initialize()
    _debug_step("startup.persistence.lifecycle_ledger")
    lifecycle_ledger.initialize()
    _debug_step("startup.persistence.target_inventory")
    target_store.initialize()
    process_lifecycle.mark_serving()
    _debug_step("startup.lifecycle.serving")
    obs_logger.log(service="control-plane", event="startup", level="INFO", request_id="-")
    try:
        yield
    finally:
        _debug_step("shutdown.lifecycle.drain_begin")
        await process_lifecycle.drain()
        _debug_step("shutdown.lifecycle.drain_complete")


app = FastAPI(title=settings.app_name, version="0.2.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=PACKAGE_DIR / "static"), name="static")


@app.middleware("http")
async def security_headers(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    # Observability wraps the request: it validates/normalizes the request id (into
    # request.state.request_id), records bounded metrics, and emits at most one structured log line.
    # It re-raises any downstream error unchanged, so the security headers below are intact.
    async def admitted_call_next(inner_request: Request) -> Response:
        drain_safe = inner_request.url.path in {
            "/api/zap-active/stop",
            "/api/zap-active/operator/logout",
        } or (
            inner_request.url.path.startswith("/api/beast/runs/")
            and inner_request.url.path.endswith("/stop")
        )
        if (
            inner_request.method in {"POST", "PUT", "PATCH", "DELETE"}
            and process_lifecycle.state is not ProcessState.SERVING
            and not drain_safe
        ):
            return JSONResponse(status_code=503, content={"detail": ServiceDraining.code})
        return await call_next(inner_request)

    response = await observe_request(
        request,
        admitted_call_next,
        service="control-plane",
        registry=obs_metrics,
        logger=obs_logger,
    )
    request_id = request.state.request_id
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
    validation_status = settings.local_llm_validation_status if planner.name == "LOCAL_LLM" else ""
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


@app.get("/multi-agent", response_class=HTMLResponse)
async def multi_agent_console(request: Request) -> HTMLResponse:
    """Read-only Phase 1.7 console projection; execution remains controller/API owned."""

    return templates.TemplateResponse(
        request=request,
        name="multi_agent.html",
        context={},
    )


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "planner": planner.name}


@app.get("/api/console/extensions")
async def extension_catalog() -> dict[str, object]:
    """Expose a non-secret inventory; execution authority remains in the compiled catalog."""

    return extension_runtime.projection()


@app.get("/ready", response_model=ReadinessReport)
async def ready(response: Response) -> ReadinessReport:
    # Readiness is distinct from the liveness stub above: it fails closed (503) whenever the
    # control plane is not in a safe-to-serve state (persistence lost, schema absent, or a
    # forbidden provider credential present). Orchestrators gate on this signal, not on /health.
    report = evaluate_readiness(settings, store, process_state=process_lifecycle.state.value)
    # Mirror the verdict into the readiness gauges. This observation never changes the verdict: a
    # metrics/logging failure cannot convert a failed check to PASS (the report is returned as-is).
    obs_metrics.set_readiness(
        ready=report.ready,
        checks={check.name: check.status.value == "PASS" for check in report.checks},
    )
    if not report.ready:
        response.status_code = 503
    return report


@app.get("/metrics", include_in_schema=False)
async def metrics_endpoint() -> PlainTextResponse:
    # Internal-only operational metrics (bounded cardinality, no secrets). Exposed only inside the
    # `security-lab` network by the Compose topology: no host port, no public ingress. A render
    # failure returns a fixed 503 body and never leaks raw internal state.
    body = obs_metrics.render()
    if body.startswith("# metrics_unavailable"):
        return PlainTextResponse(body, status_code=503, media_type="text/plain; version=0.0.4")
    return PlainTextResponse(body, media_type="text/plain; version=0.0.4")


@app.post("/api/scans", response_model=ScanResult, status_code=202)
async def create_scan(request: ScanCreate) -> ScanResult:
    try:
        result = process_lifecycle.create_and_submit(
            create=lambda: service.create(request),
            work_id=lambda scan: scan.id,
            work_factory=lambda scan: service.run(scan.id),
            on_timeout=lambda scan: service.mark_shutdown_timeout(scan.id),
        )
    except ServiceDraining:
        raise HTTPException(status_code=503, detail=ServiceDraining.code) from None
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
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
                f"evt-{int(row['parent_id']):012d}" if row.get("parent_id") is not None else None
            ),
        )
        projected.append(envelope)
    return projected


@app.get("/api/console/config")
async def console_config() -> dict[str, object]:
    if settings.ai_model.lower().startswith("deepseek"):
        planner_badge = "DEEPSEEK"
    elif settings.ai_provider == "ollama":
        planner_badge = "LOCAL LLM"
    else:
        planner_badge = settings.mode_label.replace("_", " ")
    return {
        "console_version": "1.0.0",
        "planner_contract_version": PLANNER_CONTRACT_VERSION,
        "execution_policy_version": EXECUTION_POLICY_VERSION,
        "scope_badges": ["SYNTHETIC LAB", planner_badge, "READ-ONLY", "AUTHORIZED TARGET"],
        "screenshots_enabled": screenshot_store.enabled,
        "operational_engines": [Engine.AEGIS_NATIVE]
        + ([Engine.NUCLEI] if service.nuclei.enabled else [])
        + ([Engine.ZAP] if service.zap.enabled else [])
        + (["TOOLBOX"] if settings.beast_enabled else []),
        "engine_contract": [item.value for item in Engine],
        "actor_contract": [item.value for item in ActorType],
        "engine_kernel_version": ENGINE_KERNEL_VERSION,
        "engine_catalog": catalog_projection(),
        # Active-scan configuration is operator-session protected; this public summary deliberately
        # carries only availability and never the activation ceremony or target details.
        "zap_active": {"enabled": zap_active.enabled},
    }


@app.get("/api/console/multi-agent/runs")
async def console_multi_agent_runs(
    limit: int = Query(default=25, ge=1, le=100),
) -> dict[str, object]:
    return {
        "items": [multi_agent_projection(item) for item in multi_agent_store.list_recent(limit)],
        "zap_active_agent_capability": "DISABLED",
    }


@app.get("/api/console/multi-agent/runs/{run_id}")
async def console_multi_agent_run(run_id: str) -> dict[str, object]:
    if not re.fullmatch(r"marun-[a-f0-9]{16}", run_id):
        raise HTTPException(status_code=404, detail="Agent run not found")
    item = multi_agent_store.get(run_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Agent run not found")
    return multi_agent_projection(item)


@app.get("/api/console/benchmarks")
async def console_benchmarks(
    limit: int = Query(default=25, ge=1, le=100),
) -> dict[str, object]:
    """Read-only projection of controller-owned single-agent vs multi-agent benchmark pairs.

    Offline sprint: the live single-vs-multi comparison is NOT_EVALUATED, so no architecture is
    declared superior here. Only raw, controller-owned run-pair references are surfaced.
    """

    return {
        "items": [pair.model_dump(mode="json") for pair in benchmark_store.list_pairs(limit)],
        "live_single_vs_multi_benchmark_status": "NOT_EVALUATED",
        "superiority_declared": False,
    }


@app.get("/api/console/benchmarks/{pair_id}")
async def console_benchmark(pair_id: str) -> dict[str, object]:
    if not re.fullmatch(r"rpair-[a-f0-9]{16}", pair_id):
        raise HTTPException(status_code=404, detail="Benchmark pair not found")
    pair = benchmark_store.get_pair(pair_id)
    if pair is None:
        raise HTTPException(status_code=404, detail="Benchmark pair not found")
    comparison = benchmark_store.get_comparison(pair_id)
    return {
        "pair": pair.model_dump(mode="json"),
        "comparison": comparison.model_dump(mode="json") if comparison else None,
        "superiority_declared": (
            bool(comparison.superiority_claim_supported) if comparison else False
        ),
    }


@app.get("/api/console/staging/tiers")
async def console_staging_tiers() -> dict[str, object]:
    """Read-only projection of the controller-owned environment tier ladder and its honest state.

    No gate is assumed satisfied here (this is a public summary), so every tier reports its
    fail-closed default: real AUTHORIZED_STAGING is DEPLOYMENT_DISABLED this sprint and the live
    authenticated-staging status is NOT_EVALUATED. The browser never holds authority over the tier.
    """

    tiers = [
        {
            "tier": tier.value,
            "executable": tier_is_executable(tier),
            "deployment_disabled": deployment_disabled(tier),
            "activation_state": staging_capability_state(tier, gates_satisfied=False).value,
        }
        for tier in EnvironmentTier
    ]
    return {
        "tiers": tiers,
        "live_authenticated_staging_status": "NOT_EVALUATED",
        "authenticated_progression_framework_status": "OFFLINE_PASS",
    }


@app.get("/api/console/staging/{campaign_id}/events")
async def console_staging_events(campaign_id: str) -> dict[str, object]:
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,120}", campaign_id):
        raise HTTPException(status_code=404, detail="Staging campaign not found")
    events = staging_ledger.events(campaign_id)
    return {"items": [event.model_dump(mode="json") for event in events]}


@app.get("/api/console/reports")
async def console_reports(
    limit: int = Query(default=25, ge=1, le=100),
) -> dict[str, object]:
    """Read-only projection of controller-authoritative assessment reports (Phase 2.6)."""

    reports = report_agent_queue.list_reports(limit)
    return {
        "items": [
            {
                "report_id": report.report_id,
                "version": report.version,
                "campaign_id": report.campaign_id,
                "status": report.status,
                "report_uri": report.report_uri,
                "content_sha256": report.content_sha256,
                "live_report_agent_status": report.live_report_agent_status,
            }
            for report in reports
        ],
        "live_report_agent_status": "NOT_EVALUATED",
    }


@app.get("/api/console/reports/{report_id}/v/{version}")
async def console_report(report_id: str, version: int) -> dict[str, object]:
    if not re.fullmatch(r"rpt-[a-f0-9]{16}", report_id) or version < 1:
        raise HTTPException(status_code=404, detail="Report not found")
    report = report_agent_queue.get_report(report_id, version)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return report.model_dump(mode="json")


@app.get("/api/console/reports/{report_id}/v/{version}/download.{extension}")
async def console_report_download(report_id: str, version: int, extension: str) -> Response:
    """Download a controller-authoritative report export (json/md/html) as a safe attachment.

    The report content is controller-owned and deterministic; the filename is sanitized and the
    Content-Disposition is always ``attachment`` so a hostile campaign id cannot traverse paths or
    inject headers. PDF is intentionally unsupported (NOT_EVALUATED) and fails closed as 404.
    """

    if not re.fullmatch(r"rpt-[a-f0-9]{16}", report_id) or version < 1:
        raise HTTPException(status_code=404, detail="Report not found")
    try:
        media_type = export_media_type(extension)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Unsupported export format") from exc
    report = report_agent_queue.get_report(report_id, version)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    renderers = {
        "json": report_json,
        "md": render_report_markdown,
        "html": render_report_html,
    }
    body = renderers[extension.lower().lstrip(".")](report)
    return Response(
        content=body,
        media_type=media_type,
        headers={"Content-Disposition": content_disposition(report, extension)},
    )


@app.get("/api/console/assessments/{assessment_id}/lifecycle")
async def console_assessment_lifecycle(assessment_id: str) -> dict[str, object]:
    """Read-only projection of a controller-governed assessment lifecycle (Phase 2.7).

    Surfaces the overall state, per-stage records, the cleanup ledger and the immutable audit
    trail — the controller owns every transition; the browser never advances state. Live
    full-lifecycle execution is NOT_EVALUATED this sprint.
    """

    if not re.fullmatch(r"asmt-[a-f0-9]{16}", assessment_id):
        raise HTTPException(status_code=404, detail="Assessment not found")
    spec = lifecycle_ledger.get_spec(assessment_id)
    if spec is None:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return {
        "assessment_id": assessment_id,
        "campaign_id": spec.campaign_id,
        "state": lifecycle_ledger.get_state(assessment_id).value,
        "cancel_requested": lifecycle_ledger.cancel_requested(assessment_id),
        "stages": [
            record.model_dump(mode="json") for record in lifecycle_ledger.all_stages(assessment_id)
        ],
        "cleanup": [
            entry.model_dump(mode="json")
            for entry in lifecycle_ledger.cleanup_entries(assessment_id)
        ],
        "audit_trail": lifecycle_ledger.audit_trail(assessment_id),
        "live_full_lifecycle_status": "NOT_EVALUATED",
    }


class EmergencyStopRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operator_id: str = Field(pattern=r"^[A-Za-z0-9._@-]{3,80}$")


class OperatorLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    bootstrap_secret: str = Field(min_length=32, max_length=256)


def _operator(request: Request, *, mutate: bool = False) -> str:
    if not operator_sessions.validate(
        request.cookies.get("aegis_operator_session"),
        request.headers.get("X-CSRF-Token"),
        mutate=mutate,
    ):
        raise HTTPException(
            status_code=401 if not request.cookies.get("aegis_operator_session") else 403,
            detail="OPERATOR_AUTH_REQUIRED",
        )
    return "local-operator"


@app.post("/api/zap-active/operator/login")
async def zap_active_login(request: OperatorLoginRequest, response: Response) -> dict[str, str]:
    try:
        session_id, csrf = operator_sessions.login(request.bootstrap_secret)
    except PermissionError:
        raise HTTPException(status_code=401, detail="OPERATOR_AUTH_REQUIRED") from None
    response.set_cookie(
        "aegis_operator_session",
        session_id,
        httponly=True,
        samesite="strict",
        secure=True,
        max_age=900,
    )
    return {"csrf_token": csrf}


@app.post("/api/zap-active/operator/logout")
async def zap_active_logout(request: Request, response: Response) -> dict[str, str]:
    _operator(request, mutate=True)
    operator_sessions.revoke(request.cookies.get("aegis_operator_session"))
    response.delete_cookie("aegis_operator_session")
    return {"status": "REVOKED"}


@app.get("/api/zap-active/config")
async def zap_active_config(request: Request) -> dict[str, object]:
    _operator(request)
    return zap_active.config()


@app.get("/api/zap-active/preflight")
async def zap_active_preflight(request: Request) -> dict[str, object]:
    _operator(request)
    return await zap_active.preflight()


@app.post("/api/zap-active/activate", status_code=201)
async def zap_active_activate(
    request: ZapActiveActivation, http_request: Request
) -> dict[str, object]:
    """The activation ceremony: the exact confirmation phrase; nothing else widens it."""

    try:
        await zap_active.activate(
            request.model_copy(update={"operator_id": _operator(http_request, mutate=True)})
        )
    except LeaseError as exc:
        # A bounded refusal label. Never a token, a claim value or a cryptographic detail.
        raise HTTPException(status_code=422, detail=exc.code) from None
    return zap_active.view()


@app.post("/api/zap-active/run", status_code=202)
async def zap_active_run(request: Request) -> dict[str, object]:
    _operator(request, mutate=True)
    if zap_active.session.state != "ARMED":
        raise HTTPException(status_code=409, detail="NO_ARMED_SESSION")
    try:
        process_lifecycle.submit(work_id="zap-active-session", work_factory=_zap_active_execute)
    except ServiceDraining:
        raise HTTPException(status_code=503, detail=ServiceDraining.code) from None
    return zap_active.view()


async def _zap_active_execute() -> None:
    try:
        await zap_active.execute()
    except LeaseError:  # pragma: no cover - the session already records the terminal reason
        pass


@app.get("/api/zap-active/session")
async def zap_active_session(request: Request) -> dict[str, object]:
    _operator(request)
    status = await zap_active.adapter.lease_status() if settings.zap_active_enabled else None
    return zap_active.view(status)


@app.post("/api/zap-active/stop")
async def zap_active_stop(
    request: EmergencyStopRequest, http_request: Request
) -> dict[str, object]:
    await zap_active.stop(_operator(http_request, mutate=True))
    return zap_active.view()


@app.get("/api/beast/config")
async def beast_config() -> dict[str, object]:
    return beast.config()


@app.get("/api/beast/preflight/{target_ref}")
async def beast_preflight(target_ref: str) -> dict[str, object]:
    try:
        return beast.preflight(target_ref).model_dump(mode="json")
    except (BeastRejected, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


@app.post("/api/beast/leases", status_code=201)
async def beast_issue_lease(request: LeaseRequest) -> dict[str, object]:
    try:
        return beast.issue_lease(request).model_dump(mode="json")
    except BeastRejected as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


@app.post("/api/beast/runs", status_code=202)
async def beast_create_run(
    request: BeastRunRequest,
) -> dict[str, object]:
    try:
        run = process_lifecycle.create_and_submit(
            create=lambda: beast.create_run(request),
            work_id=lambda created: created.run_id,
            work_factory=lambda created: beast.run(created.run_id),
        )
    except ServiceDraining:
        raise HTTPException(status_code=503, detail=ServiceDraining.code) from None
    except BeastRejected as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from None
    return run.model_dump(mode="json")


@app.get("/api/beast/runs")
async def beast_runs(limit: int = Query(default=50, ge=1, le=100)) -> dict[str, object]:
    items = beast_store.list_runs(limit)
    return {"items": [item.model_dump(mode="json") for item in items], "count": len(items)}


@app.get("/api/beast/runs/{run_id}")
async def beast_run_detail(run_id: str) -> dict[str, object]:
    run = beast_store.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Beast run not found")
    return {
        "run": run.model_dump(mode="json"),
        "events": beast_store.events(run_id),
    }


@app.post("/api/beast/runs/{run_id}/stop")
async def beast_emergency_stop(run_id: str, request: EmergencyStopRequest) -> dict[str, object]:
    try:
        run = await beast.emergency_stop(run_id, request.operator_id)
    except BeastRejected as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None
    return run.model_dump(mode="json")


@app.post("/api/beast/targets/{target_ref}/restore")
async def beast_restore_target(target_ref: str, request: EmergencyStopRequest) -> dict[str, object]:
    try:
        return await beast.restore_target(target_ref, request.operator_id)
    except (BeastRejected, ValueError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


# --- Disposable-toolbox run projection into the normal console surfaces --------------------------
#
# A toolbox run lives in its own store with its own transcript; these read-only projections surface
# it in the same Runs list/detail the operator uses for every other assessment, without inventing
# scan-store findings: the toolbox verifier conclusion stays in the run record and transcript.

_TOOLBOX_STATE_TO_CONSOLE: dict[str, str] = {
    "QUEUED": "QUEUED",
    "RUNNING": "RUNNING",
    "VERIFIED": "FAIL",
    "PASS": "PASS",
    "REVIEW_REQUIRED": "REVIEW",
    "INCOMPLETE": "INCOMPLETE",
    "STOPPED": "REVIEW",
}


def _toolbox_target_name(target_ref: str) -> str:
    try:
        return beast_target(target_ref).name
    except ValueError:
        return target_ref


def _toolbox_run_projection(run: BeastRun) -> dict[str, object]:
    confirmed = run.state.value == "VERIFIED"
    verifier_status = None
    if isinstance(run.verifier_conclusion, dict):
        verifier_status = run.verifier_conclusion.get("status")
    reported_tokens = 0
    for call in run.model_calls:
        usage = call.get("usage") if isinstance(call, dict) else None
        if isinstance(usage, dict):
            total = usage.get(
                "total_tokens",
                int(usage.get("input_tokens", 0)) + int(usage.get("output_tokens", 0)),
            )
            reported_tokens += int(total)
    return {
        "id": run.run_id,
        "status": _TOOLBOX_STATE_TO_CONSOLE.get(run.state.value, "REVIEW"),
        "target_name": _toolbox_target_name(run.target_ref),
        "scope": "Disposable toolbox lab / authorized base path (read-only)",
        "planner": "AI adversary (disposable toolbox)",
        "mode": "TOOLBOX",
        "model": run.model,
        "variant": run.operator_profile_id or f"TOOLBOX/{run.scenario_id}",
        "scenario": run.scenario_id,
        "created_at": run.created_at.isoformat(),
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "planner_contract_version": PLANNER_CONTRACT_VERSION,
        "execution_policy_version": EXECUTION_POLICY_VERSION,
        "usage": {
            "requests": len(run.commands),
            "model_calls": len(run.model_calls),
            "reserved_tokens": 0,
            "reported_tokens": reported_tokens,
        },
        "budgets": {
            "target_requests": run.resources.max_target_connections,
            "model_calls": run.resources.max_commands,
            "token_reservations": 0,
        },
        "candidate_counts": {"generated": 0, "validated": 0, "rejected": 0},
        "safety_rejections": 0,
        "finding_count": 1 if confirmed else 0,
        "finding_ids": [],
        "retest_of": None,
        "linked_retests": [],
        "verification": verifier_status,
        "terminal_reason": run.stop_reason,
        "engine": "TOOLBOX",
        "adapter_version": None,
        "tool_reported_count": 0,
        "verifier_confirmed_count": 1 if confirmed else 0,
        "toolbox": True,
    }


def _toolbox_runs(limit: int) -> list[BeastRun]:
    """Read toolbox runs fail-soft: an uninitialized store projects as no runs, never a 5xx."""

    try:
        return beast_store.list_runs(limit)
    except sqlite3.OperationalError:
        return []


def _toolbox_run(run_id: str) -> BeastRun | None:
    try:
        return beast_store.get_run(run_id)
    except sqlite3.OperationalError:
        return None


@app.get("/api/console/runs")
async def console_runs(limit: int = Query(default=50, ge=1, le=100)) -> dict[str, object]:
    scans = store.list_all(limit)
    items: list[dict[str, object]] = [
        _scan_projection(scan, [item.id for item in _linked_retests(scans, scan.id)])
        for scan in scans
    ]
    # Disposable-toolbox assessments surface in the same list; their transcript stays in the
    # toolbox store and opens through the run-detail toolbox branch.
    toolbox_items = [_toolbox_run_projection(run) for run in _toolbox_runs(limit)]
    merged = sorted(
        items + toolbox_items,
        key=lambda item: str(item.get("created_at", "")),
        reverse=True,
    )[:limit]
    return {"items": merged, "count": len(merged)}


@app.get("/api/console/runs.csv")
async def console_runs_csv() -> Response:
    """Download the persisted run ledger as CSV (one row per completed assessment, keyed by
    date + target FQDN/API/IP). Redacted: only projected run/target fields, never bodies."""

    return Response(
        content=run_ledger.read_csv(run_ledger_dir),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{run_ledger.download_filename()}"',
            "Cache-Control": "no-store",
        },
    )


@app.get("/api/console/runs/{scan_id}")
async def console_run(scan_id: str) -> dict[str, object]:
    scan = store.get(scan_id)
    if scan is None:
        toolbox = _toolbox_run(scan_id)
        if toolbox is not None:
            # A disposable-toolbox assessment: the normal run projection plus the raw toolbox
            # record + audit events the transcript panel renders. No scan-store records are
            # fabricated — the verifier conclusion stays in the run record itself.
            return {
                "run": _toolbox_run_projection(toolbox),
                "events": [],
                "evidence": [],
                "screenshot_artifacts": [],
                "lifecycle": [],
                "execution_policy": {},
                "toolbox": {
                    "run": toolbox.model_dump(mode="json"),
                    "events": beast_store.events(scan_id),
                },
            }
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


def _nuclei_finding_verified(scan: ScanResult) -> bool:
    """Re-evaluate a Nuclei scan's persisted, body-free verifier facts. Only a verifier CONFIRMED
    conclusion backed by a VERIFIED lifecycle record is ever displayed as a finding."""

    try:
        facts = [scm_verifier.ScmProbeFacts.model_validate(f) for f in scan.verifier_evidence]
    except ValueError:
        return False
    return scm_verifier.evaluate(facts).status == "CONFIRMED" and any(
        n.get("lifecycle_state") == "VERIFIED" for n in scan.normalized_findings
    )


def _zap_finding_verified(scan: ScanResult) -> bool:
    """Re-evaluate a ZAP scan's persisted, body-free verifier facts. Only a verifier CONFIRMED
    conclusion backed by a VERIFIED lifecycle record is ever displayed as a finding."""

    try:
        facts = [zap_verifier.ZapProbeFacts.model_validate(f) for f in scan.verifier_evidence]
    except ValueError:
        return False
    return zap_verifier.evaluate(facts).status == "CONFIRMED" and any(
        n.get("lifecycle_state") == "VERIFIED" for n in scan.normalized_findings
    )


def _verified_findings() -> list[tuple[ScanResult, int, list[ScanResult]]]:
    scans = store.list_all()
    verifier = DeterministicVerifier()
    output: list[tuple[ScanResult, int, list[ScanResult]]] = []
    for scan in scans:
        if scan.engine == SecurityEngine.NUCLEI.value:
            if scan.findings and _nuclei_finding_verified(scan):
                output.append((scan, 0, _linked_retests(scans, scan.id)))
            continue
        if scan.engine == SecurityEngine.ZAP.value:
            if scan.findings and _zap_finding_verified(scan):
                output.append((scan, 0, _linked_retests(scans, scan.id)))
            continue
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
        "provenance_policy": (
            "Only deterministic verifier-generated records are displayed. Nuclei results and ZAP "
            "alerts are tool-reported until the independent Aegis verifier confirms them."
        ),
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


async def _nuclei_integration_state() -> str:
    if not service.nuclei.enabled:
        return "DISABLED"
    await service.nuclei.attest()
    health = service.nuclei.health()
    return "CONNECTED" if health.authorized else health.state


def _nuclei_readiness_extras() -> dict[str, object]:
    """Pinned provenance + the latest execution for the Nuclei readiness card. No URL, no output."""

    manifest = load_manifest()
    attestation = service.nuclei.last_attestation
    latest = next(
        (
            scan
            for scan in store.list_all(100)
            if scan.engine == SecurityEngine.NUCLEI.value and scan.nuclei_provenance
        ),
        None,
    )
    summary = nuclei_summary(latest) if latest else None
    return {
        "pinned_engine_version": manifest.engine.version,
        "pinned_binary_sha256": {
            arch: artifact.binary_sha256 for arch, artifact in manifest.engine.artifacts.items()
        },
        "attested_engine_version": attestation.engine.nuclei_version if attestation else None,
        "attested_binary_sha256": attestation.engine.binary_sha256 if attestation else None,
        "template_set_id": manifest.template_set_id,
        "manifest_version": manifest.manifest_version,
        "manifest_digest": manifest_digest(),
        "attested_manifest_digest": attestation.manifest_digest if attestation else None,
        "admitted_template_count": len(manifest.templates),
        "upstream_templates": f"{manifest.upstream_templates.release} "
        f"({manifest.upstream_templates.commit[:12]})",
        "signature_probe": attestation.signature_probe if attestation else None,
        "last_health_check": (
            service.nuclei.last_checked_at.isoformat() if service.nuclei.last_checked_at else None
        ),
        "latest_execution": (
            {
                "scan_id": latest.id,
                "status": latest.status.value,
                "terminal_reason": latest.terminal_reason,
                "http_connections": summary.get("http_connections") if summary else None,
                "request_budget": summary.get("request_budget") if summary else None,
                "matched": summary.get("matched") if summary else None,
                "records": summary.get("records") if summary else None,
                "lifecycle_states": [
                    str(n.get("lifecycle_state")) for n in latest.normalized_findings
                ],
                "tool_reported": len(latest.normalized_findings),
                "verifier_confirmed": sum(
                    n.get("lifecycle_state") == "VERIFIED" for n in latest.normalized_findings
                ),
                "completed_at": latest.completed_at.isoformat() if latest.completed_at else None,
            }
            if latest
            else None
        ),
        "responsibility": (
            "Nuclei is an Aegis-controlled detection engine. Its results are independently "
            "correlated and verified; Nuclei does not directly confirm Aegis findings."
        ),
    }


async def _zap_integration_state() -> str:
    if not service.zap.enabled:
        return "DISABLED"
    await service.zap.attest()
    health = service.zap.health()
    return "CONNECTED" if health.authorized else health.state


def _zap_readiness_extras() -> dict[str, object]:
    """Pinned provenance, coverage and the latest execution for the ZAP readiness card. No URL, no
    HTTP body, no alert prose, no raw ZAP output."""

    manifest = load_zap_manifest()
    attestation = service.zap.last_attestation
    latest = next(
        (
            scan
            for scan in store.list_all(100)
            if scan.engine == SecurityEngine.ZAP.value and scan.zap_provenance
        ),
        None,
    )
    summary = zap_summary(latest) if latest else None
    return {
        "pinned_engine_version": manifest.engine.version,
        "pinned_image_index_digest": manifest.engine.image.index_digest,
        "pinned_image_platform_digests": dict(manifest.engine.image.platforms),
        "pinned_jar_sha256": manifest.engine.jar.sha256,
        "pinned_java_runtime": manifest.engine.java.runtime_version,
        "attested_engine_version": attestation.engine.zap_version if attestation else None,
        "attested_arch": attestation.engine.arch if attestation else None,
        "add_on_inventory_digest": add_on_inventory_digest(manifest),
        "attested_add_on_inventory_digest": (
            attestation.engine.add_on_inventory_digest if attestation else None
        ),
        "add_ons": [
            {"id": a.id, "version": a.version, "status": a.status} for a in manifest.add_ons
        ],
        "manifest_version": manifest.manifest_version,
        "manifest_digest": zap_manifest_digest(),
        "profile_id": manifest.profile_id,
        "profile_version": attestation.profile_version if attestation else None,
        "approved_rule_count": len(manifest.passive_rules),
        "approved_rules": [
            {"plugin_id": r.plugin_id, "name": r.name} for r in manifest.passive_rules
        ],
        "guard_version": attestation.guard.guard_version if attestation else None,
        "guard_reachable": bool(attestation and attestation.guard.reachable),
        "last_health_check": (
            service.zap.last_checked_at.isoformat() if service.zap.last_checked_at else None
        ),
        "latest_execution": (
            {
                "scan_id": latest.id,
                "status": latest.status.value,
                "terminal_reason": latest.terminal_reason,
                "projection_digest": summary.get("projection_digest") if summary else None,
                "operation_count": summary.get("operation_count") if summary else None,
                "imported_urls": summary.get("imported_urls") if summary else None,
                "expected_requests": summary.get("expected_requests") if summary else None,
                "observed_requests": summary.get("observed_requests") if summary else None,
                "passive_queue_drained": (
                    summary.get("passive_queue_drained") if summary else None
                ),
                "tool_reported": summary.get("tool_reported_alerts") if summary else 0,
                "correlated": summary.get("correlated_alerts") if summary else 0,
                "verifier_confirmed": summary.get("verifier_confirmed") if summary else 0,
                "coverage_state": summary.get("coverage_state") if summary else "INCOMPLETE",
                "completed_at": latest.completed_at.isoformat() if latest.completed_at else None,
            }
            if latest
            else None
        ),
        "responsibility": (
            "ZAP passively analyzes responses from controller-approved read-only API operations. "
            "ZAP alerts are independently correlated and verified by Aegis."
        ),
    }


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
            {"name": "Nuclei", "engine": "NUCLEI", "state": await _nuclei_integration_state()},
            {"name": "ZAP", "engine": "ZAP", "state": await _zap_integration_state()},
            {"name": "Burp DAST", "engine": "BURP_DAST", "state": "PLANNED_NOT_CONNECTED"},
        ]
    }


@app.get("/api/console/engines")
async def console_engines() -> dict[str, object]:
    # Honest, four-state engine readiness. Nuclei and ZAP are operational only when their fresh
    # runner attestations are authorized; Burp stays disabled. Native reachability reflects the lab.
    lab_status, _ = await _check_json(f"{settings.lab_base_url}/health")
    if service.nuclei.enabled:
        await service.nuclei.attest()
    if service.zap.enabled:
        await service.zap.attest()
    healths = []
    for health in service.dispatcher.health():
        if health.engine is SecurityEngine.AEGIS_NATIVE:
            health = health.model_copy(update={"reachable": lab_status == "HEALTHY"})
        healths.append(health)
    operational = [SecurityEngine.AEGIS_NATIVE.value]
    if service.nuclei.enabled and service.nuclei.health().authorized:
        operational.append(SecurityEngine.NUCLEI.value)
    if service.zap.enabled and service.zap.health().authorized:
        operational.append(SecurityEngine.ZAP.value)
    extras = {
        SecurityEngine.NUCLEI: _nuclei_readiness_extras(),
        SecurityEngine.ZAP: _zap_readiness_extras(),
    }
    return {
        "items": engine_readiness(healths, extras),
        "kernel_version": ENGINE_KERNEL_VERSION,
        "operational_engines": operational,
    }


def _merged_target_directory() -> list[dict[str, object]]:
    """Controller-seeded synthetic targets plus operator-onboarded company targets."""

    return target_directory() + [record.projection() for record in target_store.list()]


def _resolve_target(target_id: str) -> dict[str, object] | None:
    return next(
        (item for item in _merged_target_directory() if item["target_ref"] == target_id), None
    )


async def _profile_availability() -> dict[str, ProfileAvailability]:
    """The single source of truth for whether each catalog profile can execute right now."""

    _debug_step("profiles.preflight.begin")
    if service.nuclei.enabled:
        await service.nuclei.attest()
        _debug_step("profiles.preflight.nuclei_attested")
    if service.zap.enabled:
        await service.zap.attest()
        _debug_step("profiles.preflight.zap_attested")
    nuclei_ok = service.nuclei.enabled and service.nuclei.health().authorized
    zap_ok = service.zap.enabled and service.zap.health().authorized
    toolbox = await beast.toolbox_health()
    _debug_step("profiles.preflight.toolbox_checked")
    toolbox_tools = {
        str(item.get("name")): str(item.get("status"))
        for item in toolbox.get("tools", [])
        if isinstance(item, dict)
    }
    toolbox_eligibility_reason = ""
    if not settings.beast_enabled:
        toolbox_eligibility_reason = "The disposable toolbox is not enabled in this deployment."
    elif settings.ai_provider not in {
        "ollama",
        "internal_openai_compatible",
        "deepseek",
        "openrouter",
    }:
        toolbox_eligibility_reason = (
            "Toolbox assessments require a supported local or hosted provider."
        )
    # No fixed-model gate: the toolbox runs on the model the operator selected in the console. The
    # gateway's reviewed allowlist governs what can be selected, and every BEAST decision is
    # identity-checked against that live selection at run time.

    def toolbox_profile(*required: str) -> ProfileAvailability:
        if toolbox_eligibility_reason:
            return {"available": False, "reason": toolbox_eligibility_reason}
        missing = [name for name in required if toolbox_tools.get(name) != "READY"]
        if missing:
            return {
                "available": False,
                "reason": f"Tool self-check failed: {', '.join(missing)}.",
            }
        return {"available": True, "reason": ""}

    def engine_reason(enabled: bool, authorized: bool, enable_flag: str) -> ProfileAvailability:
        if not enabled:
            return {
                "available": False,
                "reason": f"The {enable_flag} adapter is not enabled in this deployment.",
            }
        if not authorized:
            return {
                "available": False,
                "reason": (f"The {enable_flag} runner has not returned an authorized attestation."),
            }
        return {"available": True, "reason": ""}

    result: dict[str, ProfileAvailability] = {
        "aegis-native-bola-synthetic": {"available": True, "reason": ""},
        "NUCLEI_LAB_SAFE_HTTP_V1": engine_reason(service.nuclei.enabled, nuclei_ok, "Nuclei"),
        "ZAP_LAB_PASSIVE_OPENAPI_V1": engine_reason(service.zap.enabled, zap_ok, "ZAP"),
        "ZAP_LAB_ACTIVE_REFLECTED_XSS_V1": (
            {"available": True, "reason": ""}
            if zap_active.enabled
            else {
                "available": False,
                "reason": (
                    "Requires the operator ZAP Active activation lease, which is not enabled in "
                    "this deployment."
                ),
            }
        ),
        "OUTSIDE_IN_WEB_DISCOVERY_V1": toolbox_profile("ffuf", "gobuster"),
        "TOOLBOX_INFORMATION_EXPOSURE_V1": toolbox_profile("curl", "nuclei"),
        "TOOLBOX_BOLA_READONLY_V1": toolbox_profile("curl", "httpie"),
        "SQLMAP_AUTHORIZED_WEB_V1": toolbox_profile("sqlmap"),
        "IP_NETWORK_ASSESSMENT_V1": {
            "available": False,
            "reason": (
                "The signed-lease network runner is not enabled in this deployment. The profile "
                "is visible so authorized IP/CIDR targets no longer appear to have no assessment."
            ),
        },
    }
    _debug_step("profiles.preflight.complete")
    return result


@app.get("/api/console/targets")
async def console_targets() -> dict[str, object]:
    """Authorized target inventory for the New Assessment flow. Controller-owned; never built from
    planner input. Credentials, management origins and answer keys are never projected. Operators
    add company targets through POST /api/console/targets, not by editing files."""

    return {
        "items": _merged_target_directory(),
        "environment": "SYNTHETIC_LAB / SYNTHETIC_RANGE / OPERATOR_ONBOARDED",
        # Custom entry now happens through the typed onboarding endpoint, not free-text scan input.
        "custom_target_entry": True,
    }


@app.get("/api/console/toolbox/health")
async def console_toolbox_health() -> dict[str, object]:
    """Live fixed-command probes for tools available to normal assessment profiles."""

    return await beast.toolbox_health()


@app.post("/api/console/targets/preview")
async def console_target_preview(request: TargetCreate) -> dict[str, object]:
    """Dry-run normalization so the console can show the exact authorized scope before saving."""

    try:
        return scope_preview(request)
    except TargetValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.code) from None


@app.post("/api/console/targets", status_code=201)
async def console_create_target(request: TargetCreate) -> dict[str, object]:
    """Persist a real controller-owned inventory record for an authorized operator target."""

    try:
        record = target_store.create(request, operator_id="local-operator")
    except TargetValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.code) from None
    return record.projection()


@app.get("/api/console/targets/{target_id}")
async def console_get_target(target_id: str) -> dict[str, object]:
    resolved = _resolve_target(target_id)
    if resolved is None:
        raise HTTPException(status_code=404, detail="Target not found")
    return resolved


@app.put("/api/console/targets/{target_id}")
async def console_update_target(target_id: str, request: TargetCreate) -> dict[str, object]:
    if target_store.get(target_id) is None:
        raise HTTPException(status_code=404, detail="Target not found")
    try:
        record = target_store.update_scope(target_id, request, operator_id="local-operator")
    except TargetValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.code) from None
    assert record is not None
    return record.projection()


@app.delete("/api/console/targets/{target_id}", status_code=204)
async def console_delete_target(target_id: str) -> Response:
    """Delete an operator-onboarded target; seeded catalog targets are immutable."""

    record = target_store.delete(target_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Target not found")
    return Response(status_code=204)


@app.post("/api/console/targets/{target_id}/disable")
async def console_disable_target(target_id: str) -> dict[str, object]:
    record = target_store.set_enabled(target_id, False)
    if record is None:
        raise HTTPException(status_code=404, detail="Target not found")
    return record.projection()


@app.post("/api/console/targets/{target_id}/enable")
async def console_enable_target(target_id: str) -> dict[str, object]:
    record = target_store.set_enabled(target_id, True)
    if record is None:
        raise HTTPException(status_code=404, detail="Target not found")
    return record.projection()


class AssessmentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_id: str = Field(min_length=3, max_length=80)
    profile_id: str = Field(min_length=3, max_length=100)
    request_budget: int | None = Field(default=None, ge=1, le=100_000, strict=True)
    max_duration_minutes: float | None = Field(
        default=None,
        gt=0,
        le=1_440,
        allow_inf_nan=False,
        strict=True,
    )


def _profiles_with_effective_limits(
    availability: dict[str, ProfileAvailability],
) -> list[dict[str, object]]:
    """Project deploy-time ceilings so the browser never advertises a limit we would reject."""

    items = profile_directory(availability)
    for profile in items:
        if profile.get("engine") == "TOOLBOX":
            continue
        capabilities = profile.get("capabilities")
        if not isinstance(capabilities, list):
            continue
        for capability in capabilities:
            if not isinstance(capability, dict):
                continue
            capability["request_budget"] = min(
                int(capability.get("request_budget", 0)), settings.max_requests_per_scan
            )
            capability["time_budget_ms"] = min(
                int(capability.get("time_budget_ms", 0)),
                round(settings.scan_timeout_seconds * 1000),
            )
    return items


class AiModelSelection(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    model: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9._:/-]+$")


def _ai_change_blocker() -> str | None:
    """Do not change model identity underneath work that already reserved provider budgets."""

    if process_lifecycle.in_flight:
        return "ASSESSMENT_IN_PROGRESS"
    if beast_store.active_runs():
        return "TOOLBOX_ASSESSMENT_IN_PROGRESS"
    if zap_active.session.state in {"ARMED", "RUNNING"}:
        return "ZAP_ACTIVE_SESSION_IN_PROGRESS"
    return None


async def _gateway_control_request(
    method: str,
    path: str,
    *,
    payload: dict[str, object] | None = None,
    timeout_seconds: float = 5.0,
) -> dict[str, object]:
    """Call a fixed internal gateway control route and return a bounded JSON object."""

    url = settings.llm_gateway_url.rstrip("/") + path
    try:
        async with httpx.AsyncClient(
            timeout=timeout_seconds, follow_redirects=False, trust_env=False
        ) as client:
            response = await client.request(method, url, json=payload)
        if response.status_code != 200 or len(response.content) > 65_536:
            raise HTTPException(status_code=409, detail="GATEWAY_CONTROL_REJECTED")
        body = response.json()
        if not isinstance(body, dict):
            raise ValueError("gateway response is not an object")
        return body
    except HTTPException:
        raise
    except (httpx.HTTPError, ValueError):
        raise HTTPException(status_code=503, detail="AI_GATEWAY_UNAVAILABLE") from None


@app.get("/api/console/ai/models")
async def console_ai_models() -> dict[str, object]:
    if not isinstance(planner, GatewayPlanner):
        return {
            "provider": "demo",
            "current_model": "demo-heuristic",
            "models": ["demo-heuristic"],
            "runtime_switching": False,
        }
    return await _gateway_control_request("GET", "/v1/models")


@app.get("/api/console/ai/balance")
async def console_ai_balance() -> dict[str, object]:
    if not isinstance(planner, GatewayPlanner):
        return {
            "provider": "demo",
            "state": "UNSUPPORTED",
            "available": None,
            "balances": [],
            "checked_at": datetime.now(UTC).isoformat(),
        }
    return await _gateway_control_request("GET", "/v1/billing/balance")


@app.post("/api/console/ai/select")
async def console_ai_select(request: AiModelSelection) -> dict[str, object]:
    if not isinstance(planner, GatewayPlanner):
        raise HTTPException(status_code=409, detail="LIVE_AI_GATEWAY_NOT_CONFIGURED")
    blocker = _ai_change_blocker()
    if blocker is not None:
        raise HTTPException(status_code=409, detail=blocker)
    body = await _gateway_control_request(
        "POST", "/v1/models/select", payload=request.model_dump(mode="json")
    )
    current = body.get("current_model")
    models = body.get("models")
    if current != request.model or not isinstance(models, list) or current not in models:
        raise HTTPException(status_code=502, detail="GATEWAY_MODEL_SELECTION_MISMATCH")
    # The planner performs its own exact response-model check. Update it only after the gateway
    # acknowledged the same allowlisted id; credentials and provider URLs never enter this process.
    planner.model = request.model
    settings.ai_model = request.model
    obs_logger.log(
        service="control-plane",
        event="security_check",
        level="INFO",
        request_id="-",
        code="AI_MODEL_SELECTION_APPLIED",
    )
    return body


@app.post("/api/console/ai/test")
async def console_ai_test() -> dict[str, object]:
    if not isinstance(planner, GatewayPlanner):
        raise HTTPException(status_code=409, detail="LIVE_AI_GATEWAY_NOT_CONFIGURED")
    blocker = _ai_change_blocker()
    if blocker is not None:
        raise HTTPException(status_code=409, detail=blocker)
    body = await _gateway_control_request(
        "POST",
        "/v1/synthetic-test",
        payload={},
        timeout_seconds=settings.model_timeout_seconds + 10,
    )
    if body.get("model") != planner.model or body.get("cleanup_verified") is not True:
        raise HTTPException(status_code=502, detail="SYNTHETIC_AI_TEST_INVALID_RESULT")
    obs_logger.log(
        service="control-plane",
        event="security_check",
        level="INFO" if body.get("status") == "PASS" else "ERROR",
        request_id="-",
        code=(
            "SYNTHETIC_AI_TEST_PASSED"
            if body.get("status") == "PASS"
            else "SYNTHETIC_AI_TEST_FAILED"
        ),
    )
    return body


def _record_run_ledger(scan_id: str, target: dict[str, object], profile_id: str) -> None:
    """Append one completed run to the persisted ledger. Fail-soft: never affects the run."""

    try:
        scan = store.get(scan_id)
        if scan is None:
            return
        projection = _scan_projection(scan, [])
        run_ledger.append(run_ledger_dir, run_ledger.build_row(projection, target, profile_id))
    except Exception:  # noqa: BLE001 - a ledger write must never break or fail a run
        obs_logger.log(
            service="control-plane",
            event="operation_error",
            level="ERROR",
            request_id="-",
            code="RUN_LEDGER_WRITE_FAILED",
        )


async def _run_and_record(scan_id: str, target: dict[str, object], profile_id: str) -> None:
    """Execute the assessment, then record it to the run ledger regardless of outcome."""

    try:
        await service.run(scan_id)
    finally:
        _record_run_ledger(scan_id, target, profile_id)


@app.post("/api/console/assessments", status_code=202)
async def console_create_assessment(request: AssessmentCreate) -> dict[str, object]:
    """Typed assessment creation that references a stable inventory target id and enforces its
    stored scope. Execution stays controller-side; a request for a disabled target, an unknown
    target, or a profile the backend cannot execute for that target fails closed with an auditable
    reason and never reaches an engine."""

    target = _resolve_target(request.target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="TARGET_NOT_FOUND")
    if not target.get("enabled", False) or target.get("status") == "DISABLED":
        raise HTTPException(status_code=409, detail="TARGET_DISABLED")
    supported_profiles = target.get("supported_profile_ids", [])
    if not isinstance(supported_profiles, list) or request.profile_id not in supported_profiles:
        raise HTTPException(status_code=409, detail="PROFILE_INCOMPATIBLE_WITH_TARGET")
    if request.profile_id in TOOLBOX_PROFILE_SCENARIOS:
        # Operator-facing TOOLBOX profiles start from the assessment wizard's toolbox step: the
        # disposable-sandbox ceremony (server preflight, typed confirmation phrase, single-use
        # lease) is the operator authorization this endpoint cannot replace or bypass. Fail
        # closed with the exact reason instead of the generic executor error, regardless of
        # whether the toolbox happens to be healthy right now.
        raise HTTPException(
            status_code=409, detail="TOOLBOX_PROFILE_STARTS_FROM_TOOLBOX_STEP"
        )
    availability = await _profile_availability()
    state = availability.get(request.profile_id, {"available": False, "reason": "UNKNOWN_PROFILE"})
    if not state["available"]:
        # The only executable path in this deployment is the synthetic-native combination; a company
        # target's engine profiles are unavailable, so no real company scan is ever started here.
        raise HTTPException(status_code=409, detail="PROFILE_UNAVAILABLE_FOR_DEPLOYMENT")

    profile = next(
        (
            item
            for item in _profiles_with_effective_limits(availability)
            if item.get("profile_id") == request.profile_id
        ),
        None,
    )
    capabilities = profile.get("capabilities", []) if isinstance(profile, dict) else []
    primary = capabilities[0] if isinstance(capabilities, list) and capabilities else None
    if not isinstance(primary, dict):
        raise HTTPException(status_code=409, detail="PROFILE_LIMITS_UNAVAILABLE")
    policy_requests = min(int(primary["request_budget"]), settings.max_requests_per_scan)
    policy_time_ms = min(
        int(primary["time_budget_ms"]), round(settings.scan_timeout_seconds * 1000)
    )
    requested_time_ms = (
        round(request.max_duration_minutes * 60_000)
        if request.max_duration_minutes is not None
        else policy_time_ms
    )
    requested_requests = request.request_budget or policy_requests
    if requested_requests > policy_requests:
        raise HTTPException(status_code=422, detail="REQUEST_BUDGET_EXCEEDS_POLICY")
    if requested_time_ms > policy_time_ms:
        raise HTTPException(status_code=422, detail="DURATION_EXCEEDS_POLICY")

    if (
        request.target_id == "synthetic-bank-api"
        and request.profile_id == "aegis-native-bola-synthetic"
    ):
        try:
            result = process_lifecycle.create_and_submit(
                create=lambda: service.create(
                    ScanCreate(
                        request_budget=requested_requests,
                        time_budget_ms=requested_time_ms,
                    )
                ),
                work_id=lambda scan: scan.id,
                work_factory=lambda scan: _run_and_record(scan.id, target, request.profile_id),
                on_timeout=lambda scan: service.mark_shutdown_timeout(scan.id),
            )
        except ServiceDraining:
            raise HTTPException(status_code=503, detail=ServiceDraining.code) from None
        return {
            "run_id": result.id,
            "target_id": request.target_id,
            "profile_id": request.profile_id,
            "status": result.status.value,
            "request_budget": requested_requests,
            "time_budget_ms": requested_time_ms,
        }
    # A supported, available, but non-native combination (e.g. a range target with an enabled engine
    # adapter). Not reachable in the default deployment; fail closed rather than guess an executor.
    raise HTTPException(status_code=409, detail="NO_EXECUTOR_FOR_TARGET_PROFILE")


@app.get("/api/console/profiles")
async def console_profiles() -> dict[str, object]:
    """Plain-language assessment profiles backed by the real enabled catalog profiles. A profile is
    only advertised as available when the backing adapter can actually execute it; otherwise it is
    returned unavailable with a precise operator-readable reason (never a clickable fake option)."""

    return {
        "items": _profiles_with_effective_limits(await _profile_availability()),
        "provenance_policy": (
            "Profiles are backed by the controller-owned engine capability catalog. Engine and "
            "tool results are unconfirmed until the independent Aegis verifier promotes them."
        ),
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
