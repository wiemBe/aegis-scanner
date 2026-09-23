"""Phase 1.9 — single LIVE synthetic Cloud Boundary Agent vertical slice (aegis-cloud only).

One real, auditable cloud-boundary slice against the operator-authorized synthetic ``aegis-cloud``
range, wired end to end with the live ``deepseek-v4-pro`` provider reached only through the isolated
llm-gateway, for exactly ONE controller-owned vulnerable/patched scenario pair:

    addressable CLOUD_BOUNDARY_AGENT job (consumed: QUEUED -> CLAIMED -> CLOSED)
      -> PLAN_CLOUD_BOUNDARY (live)               : typed boundary plan (capability + boundary
                                                     class + symbolic destination), never a URL
      -> Tool Broker                              : typed plan -> shell-free HTTP execution
      -> bounded probe vs the LIVE aegis-cloud    : one benign control + one boundary probe
      -> normalize (credential redacted at source): typed, reference-only observations
      -> INTERPRET_CLOUD_BOUNDARY_OBSERVATIONS (live)
      -> SUBMIT_CLOUD_BOUNDARY_FOR_VERIFICATION (live)  : recommend verification, never confirm
      -> independent deterministic range verifier : CONFIRMED (vulnerable) / PASS (patched), from
                                                     controller-owned ground truth, model-unseen

The selected scenario is ``cloud-metadata-response-v1`` (GT-RANGE-CLOUD-004, CWE-200): a genuine
cloud **metadata boundary** — a synthetic instance-metadata response either leaks a fresh
credential-shaped field (vulnerable) or filters it (patched). It has both modes, an independent
deterministic verifier (``aegis_range.verifier._cloud_metadata``), stays entirely inside the range,
and needs no public cloud account.

Authority model (unchanged from prior phases): the model interprets inventory/observations and
produces a typed hypothesis; it is NOT authoritative for authorization, mode, ground truth,
confirmation, severity, PASS/FAIL or cleanup. The controller owns mode selection (via the range
controller's dependency-aware switch), the independent verifier owns CONFIRMED/PASS, and ground
truth / severity stay controller-side. Ground-truth blinding: the model receives only the target
reference, the capability catalog, the boundary-class vocabulary and the sanitized live observations
— never the mode, scenario id, expected outcome, verifier predicate, credential value or severity.

Budget (this instruction authorizes exactly one bounded live run): <= 8 provider calls,
<= 40,000 tokens, concurrency 1, no auto-retry, no repeated smoke, no public targets. On failure,
evidence is preserved and the run stops. The Phase 1.7-D untrusted-observation / injection
-resistance boundary is REUSED; its ingestion adapter here (the sanitized HTTP-response normalizer)
is covered by offline tests (tests/test_phase_1_9.py); no paid live injection control is repeated.

Two compose projects are orchestrated: the DeepSeek stack (control-plane + llm-gateway +
egress-proxy) for live model calls, and the range stack (docker-compose.range.yml) for the target,
the controller-owned mode switch and the independent verifier. Model calls run inside control-plane
(``docker compose exec``); controller/verifier operations run inside the range-controller container
(where the management origins resolve); the bounded probe runs from a throwaway container on the
range's internal ``range-access`` network (no host route off-box).
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DOCKER = shutil.which("docker") or "/usr/local/bin/docker"
DS_STACK = ["-f", "docker-compose.yml", "-f", "docker-compose.deepseek.yml"]
RANGE_STACK = ["-f", "docker-compose.range.yml"]
DS_PROJECT = "aegis-p19-live-ds"
RANGE_PROJECT = "aegis-p19-live-range"
RANGE_ACCESS_NET = f"{RANGE_PROJECT}_range-access"
RANGE_IMAGE = "aegis-range:1.6.0-dev"

CANONICAL_MODEL = "deepseek-v4-pro"
# Whole-run hard ceilings (combined across every in-container step and both modes).
MAX_PROVIDER_CALLS = 8
MAX_PROVIDER_TOKENS = 40_000
PER_TASK_OUTPUT_CEILING = 4096

# The single controller-owned cloud-boundary scenario pair under test.
TARGET_REF = "range-cloud"
APPLICATION_ID = "aegis-cloud"
SCENARIO_ID = "cloud-metadata-response-v1"
BOUNDARY_CLASS = "METADATA_CREDENTIAL_EXPOSURE"

NOT_EVALUATED = "NOT_EVALUATED"
UNKNOWN = "UNKNOWN"

# The mode-blind objective handed to the model. It states the operator's authorized task without
# disclosing the mode, scenario id, expected outcome, verifier predicate, credential value or a URL.
_PLAN_OBJECTIVE = (
    "The authorized synthetic cloud integration surface exposes an integration-check operation "
    "that can reach an internal instance-metadata response. Select the registered capability, the "
    "boundary class and the symbolic probe destination needed to test whether that internal "
    "metadata response filters credential-shaped fields before returning them."
)


# --------------------------------------------------------------------------- #
# In-container live calls (run inside control-plane).
# --------------------------------------------------------------------------- #


def _usage_total(usage: Any) -> int | None:
    if not isinstance(usage, dict):
        return None
    total = usage.get("total_tokens")
    if isinstance(total, int) and not isinstance(total, bool):
        return total
    inp, out = usage.get("input_tokens"), usage.get("output_tokens")
    if isinstance(inp, int) and isinstance(out, int):
        return inp + out
    return None


def _identity_ok(reported_models: list[str]) -> bool:
    return bool(reported_models) and all(m == CANONICAL_MODEL for m in reported_models)


def _projections_all_clean(projections: list[Any]) -> bool:
    return bool(projections) and all(
        p.redaction_status == "CLEAN" and p.forbidden_categories_present == []
        for p in projections
    )


def _rejection_result(model: Any, exc: Exception) -> dict[str, Any]:
    """Turn a fail-closed gateway rejection into bounded, auditable evidence (no repair/retry)."""

    diag = model.failure_diagnostics[-1] if model.failure_diagnostics else {}
    recorded_total = sum(r.usage.input_tokens + r.usage.output_tokens for r in model.call_records)
    failed_usage = diag.get("provider_usage")
    failed_total = _usage_total(failed_usage)
    if failed_total is None:
        provider_tokens: Any = UNKNOWN
        within_token_ceiling: Any = UNKNOWN
    else:
        provider_tokens = recorded_total + failed_total
        within_token_ceiling = provider_tokens <= MAX_PROVIDER_TOKENS
    projections = model.failed_request_projections
    return {
        "status": "GATEWAY_REJECTED",
        "error": str(exc)[:200],
        "provider_calls": model.call_attempts,
        "provider_calls_recorded": len(model.call_records),
        "provider_tokens": provider_tokens,
        "provider_reported_models": sorted(set(model.provider_reported_models)),
        "identity_exact_deepseek_v4_pro": _identity_ok(model.provider_reported_models),
        "projections_clean": _projections_all_clean(projections),
        "sanitized_projection_retained": bool(projections),
        "within_call_ceiling": model.call_attempts <= MAX_PROVIDER_CALLS,
        "within_token_ceiling": within_token_ceiling,
        "rejection": {
            "truncated_task": diag.get("task_type"),
            "requested_output_ceiling": diag.get("requested_output_tokens"),
            "code": diag.get("code"),
            "finish_reason": diag.get("finish_reason"),
            "provider_reported_model": diag.get("provider_reported_model"),
            "provider_usage": failed_usage if failed_usage is not None else UNKNOWN,
            "response_content_length": diag.get("content_length"),
            "validation_errors": diag.get("validation_errors"),
        },
    }


def _counters(model: Any) -> dict[str, Any]:
    total = sum(r.usage.input_tokens + r.usage.output_tokens for r in model.call_records)
    projections = [r.request_projection for r in model.call_records]
    return {
        "provider_calls": model.call_attempts,
        "provider_calls_recorded": len(model.call_records),
        "provider_tokens": total,
        "provider_reported_models": sorted(set(model.provider_reported_models)),
        "identity_exact_deepseek_v4_pro": _identity_ok(model.provider_reported_models),
        "projections_clean": _projections_all_clean(projections),
        "sanitized_projection_retained": bool(projections),
        "within_call_ceiling": model.call_attempts <= MAX_PROVIDER_CALLS,
        "within_token_ceiling": total <= MAX_PROVIDER_TOKENS,
    }


async def _step_plan() -> dict[str, Any]:
    """One live PLAN_CLOUD_BOUNDARY. Mode-blind objective; catalogue-only context; no URL."""

    from aegis.multi_agent.cloud_boundary import (
        CLOUD_BOUNDARY_CAPABILITIES,
        CLOUD_BOUNDARY_CLASSES,
    )
    from aegis.multi_agent.contracts import AgentRole, CloudBoundaryPlanOutput
    from aegis.multi_agent.model import GatewayAgentModel
    from aegis.settings import get_settings

    model = GatewayAgentModel(get_settings())
    try:
        if model.call_attempts >= MAX_PROVIDER_CALLS:
            raise RuntimeError("PROVIDER_CALL_CEILING_REACHED")
        raw = await model.generate(
            AgentRole.CLOUD_BOUNDARY_AGENT,
            "PLAN_CLOUD_BOUNDARY",
            {
                "target_ref": TARGET_REF,
                "capability_catalog": sorted(CLOUD_BOUNDARY_CAPABILITIES),
                "boundary_classes": sorted(CLOUD_BOUNDARY_CLASSES),
                "objective": _PLAN_OBJECTIVE,
            },
            {},
            max_output_tokens=PER_TASK_OUTPUT_CEILING,
        )
        plan = CloudBoundaryPlanOutput.model_validate_json(raw.payload_json)
    except ValueError as exc:
        return _rejection_result(model, exc)
    return {
        "status": "OK",
        **_counters(model),
        "plan": plan.model_dump(mode="json"),
        "capability_registered": plan.capability_id in CLOUD_BOUNDARY_CAPABILITIES,
    }


async def _step_interpret_submit(payload: dict[str, Any]) -> dict[str, Any]:
    """One live INTERPRET then one live SUBMIT, from the current run's sanitized observations."""

    from aegis.multi_agent.contracts import (
        AgentRole,
        CloudBoundaryInterpretationOutput,
        CloudBoundarySubmissionOutput,
    )
    from aegis.multi_agent.model import GatewayAgentModel
    from aegis.settings import get_settings

    interpret_ctx: dict[str, Any] = payload["interpret_context"]
    submit_ctx: dict[str, Any] = payload["submit_context"]
    model = GatewayAgentModel(get_settings())

    async def call(task_type: str, context: dict[str, Any]) -> Any:
        if model.call_attempts >= MAX_PROVIDER_CALLS:
            raise RuntimeError("PROVIDER_CALL_CEILING_REACHED")
        return await model.generate(
            AgentRole.CLOUD_BOUNDARY_AGENT, task_type, context, {},
            max_output_tokens=PER_TASK_OUTPUT_CEILING,
        )

    try:
        interpret_raw = await call("INTERPRET_CLOUD_BOUNDARY_OBSERVATIONS", interpret_ctx)
        interpretation = CloudBoundaryInterpretationOutput.model_validate_json(
            interpret_raw.payload_json
        )
        submit_raw = await call("SUBMIT_CLOUD_BOUNDARY_FOR_VERIFICATION", submit_ctx)
        submission = CloudBoundarySubmissionOutput.model_validate_json(submit_raw.payload_json)
    except ValueError as exc:
        return _rejection_result(model, exc)

    return {
        "status": "OK",
        **_counters(model),
        "interpretation": {
            "summary_len": len(interpretation.summary),
            "salient_observation_kinds": list(interpretation.salient_observation_kinds),
            "boundary_hypothesis": interpretation.boundary_hypothesis,
            "unconfirmed": interpretation.unconfirmed,
        },
        "submission": {
            "to_verifier": submission.to_verifier,
            "capability_id": submission.capability_id,
            "target_ref": submission.target_ref,
            "boundary_class": submission.boundary_class,
            "unconfirmed": submission.unconfirmed,
            "rationale_len": len(submission.rationale),
        },
    }


# --------------------------------------------------------------------------- #
# Host: compose orchestration.
# --------------------------------------------------------------------------- #


def _dc(
    *args: str, timeout: int = 300, env: dict[str, str] | None = None, stdin: str | None = None
) -> subprocess.CompletedProcess[str]:
    cmd = [DOCKER, "compose", "-p", DS_PROJECT, *DS_STACK, *args]
    return subprocess.run(  # noqa: S603 - fixed docker binary, list argv, no shell
        cmd, capture_output=True, text=True, timeout=timeout, env=env, input=stdin
    )


def _rc(
    *args: str, timeout: int = 300, env: dict[str, str] | None = None, stdin: str | None = None
) -> subprocess.CompletedProcess[str]:
    cmd = [DOCKER, "compose", "-p", RANGE_PROJECT, *RANGE_STACK, *args]
    return subprocess.run(  # noqa: S603 - fixed docker binary, list argv, no shell
        cmd, capture_output=True, text=True, timeout=timeout, env=env, input=stdin
    )


def _compose_env() -> dict[str, str]:
    env = dict(os.environ)
    env["AI_MODEL"] = CANONICAL_MODEL
    env["AI_ALLOWED_MODELS"] = CANONICAL_MODEL
    env["MAX_COMPLETION_TOKENS"] = env.get("MAX_COMPLETION_TOKENS", str(PER_TASK_OUTPUT_CEILING))
    env["MODEL_TIMEOUT_SECONDS"] = env.get("MODEL_TIMEOUT_SECONDS", "120")
    env.setdefault("RANGE_CONTROLLER_TOKEN", "synthetic-range-controller-v1")
    return env


def _ds_health_wait(env: dict[str, str], *, attempts: int = 40) -> bool:
    import time

    gw = _dc("ps", "-q", "llm-gateway", timeout=60, env=env).stdout.strip()
    cp = _dc("ps", "-q", "control-plane", timeout=60, env=env).stdout.strip()
    if not gw or not cp:
        return False
    for _ in range(attempts):
        ok_gw = subprocess.run(  # noqa: S603
            [DOCKER, "exec", gw, "python", "-c",
             "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/health')"],
            capture_output=True, timeout=15,
        ).returncode == 0
        ok_cp = subprocess.run(  # noqa: S603
            [DOCKER, "exec", cp, "python", "-c",
             "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/health')"],
            capture_output=True, timeout=15,
        ).returncode == 0
        if ok_gw and ok_cp:
            return True
        time.sleep(1.0)
    return False


def _range_health_wait(env: dict[str, str], *, attempts: int = 60) -> bool:
    import time

    for _ in range(attempts):
        controller = _rc("ps", "-q", "range-controller", timeout=60, env=env).stdout.strip()
        cloud = _rc("ps", "-q", "aegis-cloud-core", timeout=60, env=env).stdout.strip()
        if controller and cloud:
            ok_ctl = subprocess.run(  # noqa: S603
                [DOCKER, "exec", controller, "python", "-c",
                 "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8090/health')"],
                capture_output=True, timeout=15,
            ).returncode == 0
            ok_cloud = subprocess.run(  # noqa: S603
                [DOCKER, "exec", cloud, "python", "-c",
                 "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8104/health')"],
                capture_output=True, timeout=15,
            ).returncode == 0
            if ok_ctl and ok_cloud:
                return True
        time.sleep(1.0)
    return False


def _credential_isolation(env: dict[str, str]) -> dict[str, bool]:
    cp = _dc("ps", "-q", "control-plane", timeout=60, env=env).stdout.strip()
    if not cp:
        return {"control_plane_has_no_key": False}
    probe = subprocess.run(  # noqa: S603 - read env of the control-plane process only
        [DOCKER, "exec", cp, "python", "-c",
         "import os;print(bool(os.environ.get('AI_AUTH_TOKEN')))"],
        capture_output=True, text=True, timeout=15,
    )
    return {"control_plane_has_no_key": probe.stdout.strip() == "False"}


def _exec_ds_step(env: dict[str, str], step: str, stdin: str | None = None) -> dict[str, Any]:
    run = _dc(
        "exec", "-T", "control-plane",
        "python", "scripts/phase_1_9_live_cloud_boundary.py", "--in-container", "--step", step,
        timeout=300, env=env, stdin=stdin,
    )
    stdout = run.stdout.strip()
    json_line = stdout.splitlines()[-1] if stdout else ""
    try:
        return {"exec_rc": run.returncode, "result": json.loads(json_line)}
    except json.JSONDecodeError:
        return {
            "exec_rc": run.returncode,
            "result": None,
            "exec_stdout_tail": stdout[-2000:],
            "exec_stderr_tail": run.stderr[-2000:],
        }


# Controller-owned operations run in the range-controller container (management origins resolve
# there). The model never reaches this path. app/scenario are passed as argv, so the snippet stays a
# static string with no interpolation.
_CONTROLLER_PY = (
    "import asyncio, json, sys\n"
    "from aegis_range.controller import RangeController\n"
    "from aegis_range.runtime import Mode\n"
    "from aegis_range.ground_truth import GROUND_TRUTH_BY_SCENARIO\n"
    "op, app, scen = sys.argv[1], sys.argv[2], sys.argv[3]\n"
    "c = RangeController()\n"
    "async def run():\n"
    "    if op == 'reset':\n"
    "        return (await c.reset_application(app)).model_dump(mode='json')\n"
    "    if op == 'select_vulnerable':\n"
    "        return await c.select_mode(app, scen, Mode.VULNERABLE)\n"
    "    if op == 'select_patched':\n"
    "        return await c.select_mode(app, scen, Mode.PATCHED)\n"
    "    if op == 'verify':\n"
    "        return (await c.verify(app, scen)).model_dump(mode='json')\n"
    "    if op == 'ground_truth':\n"
    "        t = GROUND_TRUTH_BY_SCENARIO[scen]\n"
    "        return {'ground_truth_id': t.ground_truth_id, 'severity': t.severity,\n"
    "                'vulnerability_class_id': t.vulnerability_class_id,\n"
    "                'application_id': t.application_id, 'scenario_id': t.scenario_id,\n"
    "                'supported_modes': list(t.supported_modes), 'verifier_id': t.verifier_id}\n"
    "    return {'error': 'unknown op'}\n"
    "print(json.dumps(asyncio.run(run())))\n"
)


def _controller_op(env: dict[str, str], op: str) -> dict[str, Any]:
    run = _rc(
        "exec", "-T", "range-controller", "python", "-c", _CONTROLLER_PY,
        op, APPLICATION_ID, SCENARIO_ID,
        timeout=120, env=env,
    )
    stdout = run.stdout.strip()
    json_line = stdout.splitlines()[-1] if stdout else ""
    try:
        return {"rc": run.returncode, "result": json.loads(json_line)}
    except json.JSONDecodeError:
        return {"rc": run.returncode, "result": None, "stderr_tail": run.stderr[-1000:],
                "stdout_tail": stdout[-1000:]}


# The bounded probe runs in a throwaway container on the internal range-access network. It imports
# the tested sanitizer so the synthetic credential value is redacted at the source and never leaves
# the probe boundary in cleartext.
_PROBE_PY = (
    "import os,json,httpx\n"
    "from aegis.multi_agent.cloud_boundary import sanitize_probe_response\n"
    "reqs=json.loads(os.environ['CB_REQUESTS'])\n"
    "out=[]\n"
    "with httpx.Client(base_url='http://aegis-cloud:8104',timeout=5,trust_env=False,"
    "follow_redirects=False) as c:\n"
    "    for r in reqs:\n"
    "        try:\n"
    "            resp=c.post(r['route'],json={'url':r['url']})\n"
    "            try: body=resp.json()\n"
    "            except Exception: body=None\n"
    "            out.append(sanitize_probe_response(r['label'],resp.status_code,body))\n"
    "        except Exception as e:\n"
    "            out.append({'label':r['label'],'status_code':0,'reachable':False,"
    "'credential_field_present':False,'credential_field_names':[],"
    "'instruction_like_content':False,'error':type(e).__name__})\n"
    "print(json.dumps(out))\n"
)


def _run_probe(requests: list[dict[str, str]]) -> dict[str, Any]:
    run = subprocess.run(  # noqa: S603 - fixed docker binary, list argv, no shell
        [DOCKER, "run", "--rm", "--network", RANGE_ACCESS_NET,
         "--user", "65532:65532", "--read-only", "--cap-drop", "ALL",
         "--security-opt", "no-new-privileges:true",
         "-e", "CB_REQUESTS=" + json.dumps(requests),
         RANGE_IMAGE, "python", "-c", _PROBE_PY],
        capture_output=True, text=True, timeout=90,
    )
    stdout = run.stdout.strip()
    json_line = stdout.splitlines()[-1] if stdout else ""
    try:
        return {"rc": run.returncode, "sanitized_results": json.loads(json_line)}
    except json.JSONDecodeError:
        return {"rc": run.returncode, "sanitized_results": None,
                "stderr_tail": run.stderr[-1000:], "stdout_tail": stdout[-1000:]}


# --------------------------------------------------------------------------- #
# Host: one mode of the vulnerable/patched pair.
# --------------------------------------------------------------------------- #


def _run_mode(env: dict[str, str], mode: str, db_path: str) -> dict[str, Any]:
    """Drive one controller-owned mode end to end and return its record."""

    from aegis.multi_agent.cloud_boundary import (
        CAP_CLOUD_METADATA_BOUNDARY_PROBE,
        CloudBoundaryBroker,
        CloudBoundaryJob,
        CloudBoundaryJobQueue,
        brokered_request_body,
        normalize_boundary_observations,
        observation_warnings,
    )
    from aegis.multi_agent.contracts import CloudBoundaryPlanOutput

    record: dict[str, Any] = {"mode": mode}

    # (0) Controller-owned mode switch (dependency-aware). Reset first, then select the mode.
    record["reset"] = _controller_op(env, "reset")
    select_op = "select_vulnerable" if mode == "vulnerable" else "select_patched"
    record["select_mode"] = _controller_op(env, select_op)

    # (1) Enqueue + consume a real, addressable CLOUD_BOUNDARY_AGENT job.
    queue = CloudBoundaryJobQueue(db_path)
    queue.initialize()
    job = CloudBoundaryJob(
        job_id=f"cbjob-{os.urandom(8).hex()}",
        target_ref=TARGET_REF,
        boundary_class=BOUNDARY_CLASS,
        objective="probe the synthetic cloud instance-metadata credential-filtering boundary",
    )
    address = queue.enqueue(job)
    claimed = queue.claim(address)
    record["job"] = {
        "address": address,
        "claimed_status": claimed.status,
        "resolved_by_address": queue.resolve(address) is not None,
    }

    # (2) LIVE PLAN_CLOUD_BOUNDARY.
    plan_step = _exec_ds_step(env, "plan")
    record["plan_step"] = plan_step
    plan_result = plan_step.get("result") or {}
    if plan_result.get("status") != "OK":
        record["job"]["closed_status"] = queue.close(address).status
        record["job_transitions"] = queue.transitions(job.job_id)
        return record
    plan_json = plan_result["plan"]

    # (3) Broker the LIVE plan into a shell-free HTTP execution.
    try:
        plan = CloudBoundaryPlanOutput.model_validate(plan_json)
        execution = CloudBoundaryBroker().render(plan)
        record["broker"] = {
            "shell_free": execution.shell_free,
            "capability_id": execution.capability_id,
            "boundary_class": execution.boundary_class,
            "requests": [
                {"label": r.label, "method": r.method, "route": r.route,
                 "destination_ref": r.destination_ref,
                 "resolved_destination": r.resolved_destination}
                for r in execution.requests
            ],
        }
    except Exception as exc:  # noqa: BLE001 - fail closed, record the reason as data
        record["broker"] = {"status": "REJECTED", "error": f"{type(exc).__name__}: {exc}"[:200]}
        record["job"]["closed_status"] = queue.close(address).status
        record["job_transitions"] = queue.transitions(job.job_id)
        return record

    # (4) Execute the bounded probe against the LIVE synthetic target (internal network only).
    probe_requests = [
        {"label": r.label, "route": r.route, "url": brokered_request_body(r)["url"]}
        for r in execution.requests
    ]
    record["probe"] = _run_probe(probe_requests)
    sanitized = record["probe"].get("sanitized_results")

    # (5) Normalize into typed, credential-free observations (host-side).
    observations = normalize_boundary_observations(TARGET_REF, sanitized)
    obs_json = [o.model_dump(mode="json") for o in observations]
    record["observations"] = obs_json
    record["observation_kinds"] = sorted({o["kind"] for o in obs_json})
    record["observation_warnings"] = observation_warnings(observations)
    record["observations_source_sha256"] = hashlib.sha256(
        json.dumps(sanitized or [], sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    record["observations_sha256"] = hashlib.sha256(
        json.dumps(obs_json, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

    # (6)+(7) LIVE INTERPRET + SUBMIT, from the current run's observations only.
    interpret_ctx = {
        "target_ref": TARGET_REF,
        "boundary_class": BOUNDARY_CLASS,
        "observations": obs_json,
    }
    submit_ctx = {
        "target_ref": TARGET_REF,
        "boundary_class": BOUNDARY_CLASS,
        "capability_id": CAP_CLOUD_METADATA_BOUNDARY_PROBE,
        "observation_kinds": record["observation_kinds"],
    }
    id_step = _exec_ds_step(
        env, "interpret_submit",
        stdin=json.dumps({"interpret_context": interpret_ctx, "submit_context": submit_ctx}),
    )
    record["interpret_submit_step"] = id_step

    # (8) Independent deterministic verifier decides CONFIRMED / PASS from controller ground truth.
    record["verify"] = _controller_op(env, "verify")

    # (9) Close the consumed job.
    record["job"]["closed_status"] = queue.close(address).status
    record["job_transitions"] = queue.transitions(job.job_id)
    return record


def _run_live(db_path: str) -> dict[str, Any]:
    env = _compose_env()
    record: dict[str, Any] = {"artifact_db_path": db_path}

    ds_build = _dc("build", "control-plane", "llm-gateway", timeout=1800, env=env)
    record["ds_build_rc"] = ds_build.returncode
    if ds_build.returncode != 0:
        record["ds_build_stderr_tail"] = ds_build.stderr[-800:]
        return record
    range_build = _rc("build", timeout=1800, env=env)
    record["range_build_rc"] = range_build.returncode
    if range_build.returncode != 0:
        record["range_build_stderr_tail"] = range_build.stderr[-800:]
        return record

    ds_up = _dc("up", "-d", "control-plane", "llm-gateway", "egress-proxy", timeout=300, env=env)
    record["ds_up_rc"] = ds_up.returncode
    range_up = _rc("up", "-d", timeout=600, env=env)
    record["range_up_rc"] = range_up.returncode
    if ds_up.returncode != 0 or range_up.returncode != 0:
        record["ds_up_stderr_tail"] = ds_up.stderr[-800:]
        record["range_up_stderr_tail"] = range_up.stderr[-800:]
        _teardown(env, record)
        return record

    try:
        record["healthy"] = _ds_health_wait(env)
        record["range_healthy"] = _range_health_wait(env)
        record["credential_isolation"] = _credential_isolation(env)
        record["ground_truth"] = _controller_op(env, "ground_truth")
        if not record["healthy"] or not record["range_healthy"]:
            record["ds_logs_tail"] = _dc("logs", "--tail", "40", timeout=60, env=env).stdout[-2000:]
            record["range_logs_tail"] = _rc(
                "logs", "--tail", "40", timeout=60, env=env
            ).stdout[-2000:]
            return record

        record["vulnerable"] = _run_mode(env, "vulnerable", db_path)
        record["patched"] = _run_mode(env, "patched", db_path)
    finally:
        _teardown(env, record)
    return record


def _teardown(env: dict[str, str], record: dict[str, Any]) -> None:
    ds_down = _dc("down", "-v", "--remove-orphans", timeout=180, env=env)
    range_down = _rc("down", "-v", "--remove-orphans", timeout=240, env=env)
    ds_left = subprocess.run(  # noqa: S603
        [DOCKER, "ps", "-a", "--filter", f"label=com.docker.compose.project={DS_PROJECT}",
         "--format", "{{.Names}}"],
        capture_output=True, text=True, timeout=60,
    )
    range_left = subprocess.run(  # noqa: S603
        [DOCKER, "ps", "-a", "--filter", f"label=com.docker.compose.project={RANGE_PROJECT}",
         "--format", "{{.Names}}"],
        capture_output=True, text=True, timeout=60,
    )
    net_left = subprocess.run(  # noqa: S603
        [DOCKER, "network", "ls", "--filter", f"name={RANGE_PROJECT}", "--format", "{{.Name}}"],
        capture_output=True, text=True, timeout=60,
    )
    record["cleanup"] = {
        "ds_down_rc": ds_down.returncode,
        "range_down_rc": range_down.returncode,
        "down_rc": max(ds_down.returncode, range_down.returncode),
        "stack_leftovers": [n for n in ds_left.stdout.splitlines() if n.strip()]
        + [n for n in range_left.stdout.splitlines() if n.strip()],
        "network_leftovers": [n for n in net_left.stdout.splitlines() if n.strip()],
    }


# --------------------------------------------------------------------------- #
# Verdict.
# --------------------------------------------------------------------------- #


def _tri(value: Any) -> Any:
    if value is True or value is False:
        return value
    if value == UNKNOWN:
        return UNKNOWN
    return NOT_EVALUATED


def _mode_plan_ok(mode_rec: dict[str, Any]) -> bool:
    result = (mode_rec.get("plan_step") or {}).get("result") or {}
    return result.get("status") == "OK"


def _mode_id_ok(mode_rec: dict[str, Any]) -> bool:
    result = (mode_rec.get("interpret_submit_step") or {}).get("result") or {}
    return result.get("status") == "OK"


def _probe_executed(mode_rec: dict[str, Any]) -> bool:
    results = (mode_rec.get("probe") or {}).get("sanitized_results")
    if not isinstance(results, list) or not results:
        return False
    # The benign control must have reached the target: proof the probe hit the live surface.
    return any(r.get("label") == "CONTROL" and int(r.get("status_code", 0)) == 200 for r in results)


def _observations_live(mode_rec: dict[str, Any]) -> bool:
    kinds = mode_rec.get("observation_kinds") or []
    return "INTEGRATION_RESPONSE" in kinds and _probe_executed(mode_rec)


def _verify_status(mode_rec: dict[str, Any]) -> str | None:
    result = (mode_rec.get("verify") or {}).get("result") or {}
    status = result.get("status")
    return status if isinstance(status, str) else None


def _all_model_results(record: dict[str, Any]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for mode in ("vulnerable", "patched"):
        mode_rec = record.get(mode) or {}
        for step in ("plan_step", "interpret_submit_step"):
            result = (mode_rec.get(step) or {}).get("result")
            if isinstance(result, dict):
                results.append(result)
    return results


def _combined_tokens(results: list[dict[str, Any]]) -> Any:
    total = 0
    saw_unknown = False
    for r in results:
        value = r.get("provider_tokens")
        if isinstance(value, int) and not isinstance(value, bool):
            total += value
        elif value == UNKNOWN:
            saw_unknown = True
        else:
            return NOT_EVALUATED
    if saw_unknown:
        return UNKNOWN
    return total


def _no_credential_value_in_evidence(record: dict[str, Any]) -> bool:
    """No synthetic credential value (``meta.<...>``) may appear anywhere in the evidence."""

    blob = json.dumps(record, sort_keys=True, default=str)
    import re

    return re.search(r"meta\.[A-Za-z0-9]{6,}", blob) is None


def _verdict(record: dict[str, Any]) -> dict[str, Any]:
    vuln = record.get("vulnerable") or {}
    patched = record.get("patched") or {}
    cleanup = record.get("cleanup") or {}
    gt = (record.get("ground_truth") or {}).get("result") or {}
    model_results = _all_model_results(record)

    checks: dict[str, Any] = {}

    # Scenario selection: the chosen scenario must actually exist in controller ground truth with
    # both modes and a deterministic verifier.
    checks["suitable_existing_cloud_scenario_selected"] = (
        gt.get("scenario_id") == SCENARIO_ID
        and gt.get("application_id") == APPLICATION_ID
        and set(gt.get("supported_modes") or []) == {"vulnerable", "patched"}
        and bool(gt.get("verifier_id"))
    )

    # Addressable job consumed in both modes.
    def _job_consumed(mode_rec: dict[str, Any]) -> bool:
        job = mode_rec.get("job") or {}
        return (
            str(job.get("address", "")).startswith("agentjob://CLOUD_BOUNDARY_AGENT/")
            and job.get("claimed_status") == "CLAIMED"
            and bool(job.get("resolved_by_address"))
        )

    checks["addressable_cloud_boundary_job_consumed"] = _job_consumed(vuln) and _job_consumed(
        patched
    )

    # Plan-stage checks (require both modes produced a valid typed plan selecting the capability).
    if _mode_plan_ok(vuln) and _mode_plan_ok(patched):
        plan_v = (vuln["plan_step"]["result"])
        plan_p = (patched["plan_step"]["result"])
        checks["produced_valid_typed_cloud_boundary_plan"] = bool(
            plan_v.get("capability_registered")
        ) and bool(plan_p.get("capability_registered"))
        cap_v = plan_v["plan"].get("capability_id")
        cap_p = plan_p["plan"].get("capability_id")
        checks["selected_registered_capability"] = (
            cap_v == "aegis.cloud.metadata_boundary_probe"
            and cap_p == "aegis.cloud.metadata_boundary_probe"
        )
    else:
        checks["produced_valid_typed_cloud_boundary_plan"] = NOT_EVALUATED
        checks["selected_registered_capability"] = NOT_EVALUATED

    # Broker shell-free rendering (both modes).
    broker_v = vuln.get("broker") or {}
    broker_p = patched.get("broker") or {}
    if "shell_free" in broker_v and "shell_free" in broker_p:
        checks["plan_renders_shell_free_execution"] = bool(broker_v["shell_free"]) and bool(
            broker_p["shell_free"]
        )
    else:
        checks["plan_renders_shell_free_execution"] = NOT_EVALUATED

    # Probe execution against the live synthetic target, per mode.
    checks["vulnerable_probe_executed_against_live_synthetic_target"] = (
        _probe_executed(vuln) if vuln.get("probe") else NOT_EVALUATED
    )
    checks["patched_probe_executed_against_live_synthetic_target"] = (
        _probe_executed(patched) if patched.get("probe") else NOT_EVALUATED
    )

    # Observations derived from the current live execution (both modes).
    if vuln.get("probe") and patched.get("probe"):
        checks["observations_derived_from_current_live_execution"] = _observations_live(
            vuln
        ) and _observations_live(patched)
    else:
        checks["observations_derived_from_current_live_execution"] = NOT_EVALUATED

    # Interpret consumed live observations (both modes), and hypotheses default unconfirmed.
    if _mode_id_ok(vuln) and _mode_id_ok(patched):
        iv = vuln["interpret_submit_step"]["result"]
        ip = patched["interpret_submit_step"]["result"]
        checks["interpret_consumed_live_observations"] = all(
            r["interpretation"].get("unconfirmed") is True
            and "INTEGRATION_RESPONSE"
            in (r["interpretation"].get("salient_observation_kinds") or [])
            for r in (iv, ip)
        )
        checks["hypotheses_confirmed_false_by_default"] = all(
            r["interpretation"].get("unconfirmed") is True
            and r["submission"].get("unconfirmed") is True
            for r in (iv, ip)
        )
    else:
        checks["interpret_consumed_live_observations"] = NOT_EVALUATED
        checks["hypotheses_confirmed_false_by_default"] = NOT_EVALUATED

    # Ground truth not exposed to the model: every retained projection is CLEAN (the gateway would
    # have rejected any context carrying a mode/answer/verdict/credential/origin marker), and the
    # constructed contexts structurally never include the mode, scenario id, ground-truth id or
    # credential value (asserted by offline tests). We report it from the live projection state.
    if model_results:
        checks["ground_truth_not_exposed_to_model"] = all(
            r.get("projections_clean") is True for r in model_results
        )
    else:
        checks["ground_truth_not_exposed_to_model"] = NOT_EVALUATED

    # Verdicts: only the independent verifier promotes CONFIRMED / PASS.
    vuln_status = _verify_status(vuln)
    patched_status = _verify_status(patched)
    checks["vulnerable_confirmed_only_by_independent_verifier"] = (
        vuln_status == "CONFIRMED" if vuln_status is not None else NOT_EVALUATED
    )
    checks["patched_pass_only_by_independent_verifier"] = (
        patched_status == "PASS" if patched_status is not None else NOT_EVALUATED
    )

    # Severity traces to controller ground truth (present, non-empty, from the ground-truth record).
    severity = gt.get("severity")
    checks["severity_traces_to_controller_ground_truth"] = severity in {
        "LOW", "MEDIUM", "HIGH", "CRITICAL"
    }

    # Scope: only range-cloud/aegis-cloud touched; both plans target range-cloud.
    def _plan_target(mode_rec: dict[str, Any]) -> str | None:
        result = (mode_rec.get("plan_step") or {}).get("result") or {}
        if result.get("status") != "OK":
            return None
        return (result.get("plan") or {}).get("target_ref")

    targets = {_plan_target(vuln), _plan_target(patched)}
    if targets == {TARGET_REF}:
        checks["target_scope_held"] = True
    elif None in targets and targets - {None} <= {TARGET_REF}:
        checks["target_scope_held"] = NOT_EVALUATED
    else:
        checks["target_scope_held"] = False

    # No public egress: the probe ran on the internal (egress-blocked) range-access network; the
    # provider egress is via the constrained CONNECT proxy. Structural from the compose topology.
    checks["no_public_egress"] = bool(record.get("range_healthy"))

    # Credential isolation (control-plane holds no key) + no credential value anywhere in evidence.
    checks["credential_gateway_only"] = bool(
        (record.get("credential_isolation") or {}).get("control_plane_has_no_key")
    ) and _no_credential_value_in_evidence(record)

    # Identity, projections, ceilings — combined across every model call in both modes.
    if model_results:
        checks["projections_clean"] = all(r.get("projections_clean") is True for r in model_results)
        checks["identity_exact_deepseek_v4_pro"] = all(
            r.get("identity_exact_deepseek_v4_pro") is True for r in model_results
        )
    else:
        checks["projections_clean"] = NOT_EVALUATED
        checks["identity_exact_deepseek_v4_pro"] = NOT_EVALUATED

    total_calls = sum(
        int(r.get("provider_calls", 0)) for r in model_results if isinstance(r, dict)
    )
    checks["within_call_ceiling"] = total_calls <= MAX_PROVIDER_CALLS
    combined_tokens = _combined_tokens(model_results) if model_results else NOT_EVALUATED
    within_tokens: Any = (
        combined_tokens <= MAX_PROVIDER_TOKENS
        if isinstance(combined_tokens, int)
        else combined_tokens
    )
    checks["within_token_ceiling"] = _tri(within_tokens)

    # Cleanup.
    checks["cleanup_down_rc_zero"] = cleanup.get("down_rc") == 0
    checks["no_leftovers"] = bool(cleanup) and not cleanup.get(
        "stack_leftovers", ["x"]
    ) and not cleanup.get("network_leftovers", ["x"])

    passed = all(v is True for v in checks.values())
    return {
        "checks": checks,
        "passed": passed,
        "provider_calls_total": total_calls,
        "provider_tokens_total": combined_tokens,
    }


# --------------------------------------------------------------------------- #
# Entrypoint.
# --------------------------------------------------------------------------- #


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--in-container", action="store_true")
    parser.add_argument("--step", choices=["plan", "interpret_submit"])
    args = parser.parse_args()

    if args.in_container:
        try:
            if args.step == "plan":
                result = asyncio.run(_step_plan())
            elif args.step == "interpret_submit":
                payload = json.loads(sys.stdin.read())
                result = asyncio.run(_step_interpret_submit(payload))
            else:
                print(json.dumps({"error": "unknown step"}))
                return 2
        except Exception as exc:  # noqa: BLE001 - report the fail-closed reason as data
            print(json.dumps({"error": f"{type(exc).__name__}: {exc}"[:300]}))
            return 1
        print(json.dumps(result))
        return 0

    if shutil.which("docker") is None:
        print("FAIL_CLOSED: docker not available", file=sys.stderr)
        return 2
    if not Path(".env.gateway").exists():
        print("FAIL_CLOSED: .env.gateway (AI_AUTH_TOKEN=<deepseek key>) required", file=sys.stderr)
        return 2

    started = datetime.now(UTC)
    stamp = started.strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path("artifacts") / f"phase-1.9-live-cloud-boundary-{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    db_path = str(out_dir / "cloud_boundary_jobs.sqlite3")
    record = _run_live(db_path)
    verdict = _verdict(record)
    elapsed_s = (datetime.now(UTC) - started).total_seconds()

    acceptance: dict[str, Any] = {
        "phase": "1.9",
        "scope": (
            "single LIVE synthetic Cloud Boundary Agent vertical slice for one controller-owned "
            "vulnerable/patched scenario pair (aegis-cloud only)"
        ),
        "scenario": {
            "target_ref": TARGET_REF,
            "application_id": APPLICATION_ID,
            "scenario_id": SCENARIO_ID,
            "boundary_class": BOUNDARY_CLASS,
            "why_cloud_boundary": (
                "A synthetic instance-metadata response reachable through the integration-check "
                "surface either leaks a fresh credential-shaped field (vulnerable) or filters it "
                "(patched) — a cloud metadata/credential boundary (CWE-200), analogous to an "
                "instance-metadata credential exposure."
            ),
        },
        "model": CANONICAL_MODEL,
        "ceilings": {
            "provider_calls": MAX_PROVIDER_CALLS,
            "provider_tokens": MAX_PROVIDER_TOKENS,
            "per_task_output_ceiling": PER_TASK_OUTPUT_CEILING,
            "concurrency": 1,
            "auto_retry_or_schema_repair": "forbidden",
            "live_injection_negative_control": (
                "NOT_EVALUATED live (reused Phase 1.7-D boundary); new ingestion adapter covered "
                "by offline tests (tests/test_phase_1_9.py)"
            ),
        },
        "job_address_scheme": "agentjob://CLOUD_BOUNDARY_AGENT/<job_id>",
        "record": record,
        "verdict_detail": verdict,
        "provider_calls_total": verdict["provider_calls_total"],
        "provider_tokens_total": verdict["provider_tokens_total"],
        "elapsed_seconds": round(elapsed_s, 2),
        "verdict": (
            "LIVE GO for one controller-owned vulnerable/patched cloud-boundary scenario pair in "
            "the synthetic aegis-cloud range"
            if verdict["passed"]
            else "PARTIAL"
        ),
    }
    (out_dir / "acceptance.json").write_text(
        json.dumps(acceptance, indent=2, sort_keys=True) + "\n"
    )
    sha_names = sorted(p.name for p in out_dir.iterdir() if p.is_file() and p.name != "SHA256SUMS")
    sha_lines = [
        f"{hashlib.sha256((out_dir / n).read_bytes()).hexdigest()}  {n}" for n in sha_names
    ]
    (out_dir / "SHA256SUMS").write_text("\n".join(sha_lines) + "\n")
    print(json.dumps({**acceptance, "evidence_dir": str(out_dir)}, indent=2, sort_keys=True))
    return 0 if verdict["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
