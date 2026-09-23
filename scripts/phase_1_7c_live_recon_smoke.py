"""Phase 1.7-C Gate 3 — bounded live DeepSeek recon smoke against Bank and Shop references.

Only after Gates 0-2 pass. This drives the real ``deepseek-v4-pro`` provider through the isolated
llm-gateway (control-plane -> planner-rpc -> llm-gateway -> gateway-egress -> egress-proxy ->
api.deepseek.com) for the three RECON_AGENT task types added in Gate 2: PLAN_RECON,
INTERPRET_RECON_OBSERVATIONS and DELEGATE_RECON_HYPOTHESIS. It proves the live model can:

  1. select an appropriate registered Recon capability;
  2. produce a valid typed plan (an NmapScanPlan the controller accepts and renders shell-free);
  3. interpret bounded normalized observations;
  4. delegate an appropriate reference-only hypothesis;
  5. avoid confirming a finding.

Hard ceilings: <= 8 provider calls, <= 40 000 provider tokens, concurrency 1, no offline fallback
or schema repair (a schema violation fails closed), no ZAP Active, no Beast Mode, no public target.
The controller never discloses expected ports, candidate/clean status, answer keys or verifier
expectations to the model — the observations fed to INTERPRET are genuine, neutral facts (real
service records from the preserved containerized run), never labelled vulnerable/patched. Exact
deepseek-v4-pro identity validation and the sanitized pre-dispatch projection are preserved and
asserted; a model-selected candidate remains unconfirmed.

Two modes: ``--in-container`` performs the live calls inside the control-plane container and prints
one JSON object; the default host mode brings up the minimal deepseek stack, runs the in-container
pass, tears it down, and writes fresh timestamped evidence under ``artifacts/``.
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
STACK = ["-f", "docker-compose.yml", "-f", "docker-compose.deepseek.yml"]
PROJECT = "aegis-p17c-gate3-live"
CANONICAL_MODEL = "deepseek-v4-pro"
MAX_PROVIDER_CALLS = 8
MAX_PROVIDER_TOKENS = 40_000
# Explicit bounded per-task output ceiling. 1024 truncated DeepSeek structured output (its
# reasoning_content consumed the completion allowance before the JSON object closed, yielding
# finish_reason=length). 4096 gives sufficient headroom for these small reference-only schemas
# while staying well under the combined 40 000-token / 8-call budget. Raise it only with a measured
# reason, never silently to an unbounded value; the gateway request contract caps it at 8192.
PER_TASK_OUTPUT_CEILING: dict[str, int] = {
    "PLAN_RECON": 4096,
    "INTERPRET_RECON_OBSERVATIONS": 4096,
    "DELEGATE_RECON_HYPOTHESIS": 4096,
}
# Tri-state markers for evidence semantics: a check that could not run is NOT_EVALUATED (never
# false), and a value that depends on usage the provider did not return is UNKNOWN (never a breach).
NOT_EVALUATED = "NOT_EVALUATED"
UNKNOWN = "UNKNOWN"

# Genuine, neutral service records sourced from the preserved REAL containerized run
# (artifacts/phase-1.7c-containerized-*). They are input observations, not an answer key: no
# vulnerable/patched label, no verdict, no expected outcome is disclosed to the model.
_REAL_OBSERVATIONS = {
    "range-bank": {
        "target_ref": "range-bank",
        "discovered_services": [
            {"protocol": "tcp", "port": 8101, "state": "open", "service": "http",
             "product": "Uvicorn"}
        ],
        "documented_operations": [
            {"method": "GET", "route": "/accounts/{account_id}"},
            {"method": "GET", "route": "/accounts/{account_id}/transactions"},
        ],
    },
    "range-shop": {
        "target_ref": "range-shop",
        "discovered_services": [
            {"protocol": "tcp", "port": 8102, "state": "open", "service": "http",
             "product": "Uvicorn"}
        ],
        "documented_operations": [
            {"method": "GET", "route": "/products", "parameters": ["q"]},
        ],
    },
}


# --------------------------------------------------------------------------- #
# In-container live calls.
# --------------------------------------------------------------------------- #


def _usage_total(usage: Any) -> int | None:
    """Total tokens for a reported usage block, or None when it cannot be determined."""
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
    """Turn a fail-closed gateway rejection into bounded, auditable evidence.

    No JSON is repaired, coerced or extracted, and no retry is attempted; the rejected call's
    bounded diagnostics (finish reason, usage, content/reasoning *lengths*) are recorded so the
    operator can distinguish a truncation from a refusal. Raw output and reasoning_content text are
    never present here — only counts and the model identity that was reported before validation.
    """
    diag = model.failure_diagnostics[-1] if model.failure_diagnostics else {}
    recorded_total = sum(r.usage.input_tokens + r.usage.output_tokens for r in model.call_records)
    failed_usage = diag.get("provider_usage")
    failed_total = _usage_total(failed_usage)
    if failed_total is None:
        # Missing usage is UNKNOWN, never interpreted as a budget breach.
        provider_tokens: Any = UNKNOWN
        within_token_ceiling: Any = UNKNOWN
    else:
        provider_tokens = recorded_total + failed_total
        within_token_ceiling = provider_tokens <= MAX_PROVIDER_TOKENS
    reasoning_present = diag.get("reasoning_present")
    finish_reason = diag.get("finish_reason")
    if reasoning_present is None:
        reasoning_consumed: Any = UNKNOWN
    else:
        reasoning_consumed = bool(reasoning_present) and finish_reason == "length"
    projections = model.failed_request_projections
    return {
        "status": "GATEWAY_REJECTED",
        "error": str(exc)[:200],
        "provider_calls": model.call_attempts,  # counts the rejected call
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
            "finish_reason": finish_reason,
            "provider_reported_model": diag.get("provider_reported_model"),
            "provider_usage": failed_usage if failed_usage is not None else UNKNOWN,
            "response_content_length": diag.get("content_length"),
            "reasoning_present": reasoning_present,
            "reasoning_length": diag.get("reasoning_length"),
            "reasoning_consumed_allowance": reasoning_consumed,
            # Bounded, value-free schema-violation summary when a *complete* response failed the
            # strict contract (AGENT_OUTPUT_REJECTED). None on a truncation/other rejection path.
            "validation_errors": diag.get("validation_errors"),
        },
    }


async def _live_smoke() -> dict[str, Any]:
    from aegis.multi_agent.contracts import (
        AgentRole,
        ReconDelegationOutput,
        ReconInterpretationOutput,
        ReconPlanOutput,
    )
    from aegis.multi_agent.model import GatewayAgentModel
    from aegis.multi_agent.recon import RECON_CAPABILITIES, NmapScanPlan, build_nmap_bundle
    from aegis.settings import get_settings

    settings = get_settings()
    model = GatewayAgentModel(settings)

    async def call(role: AgentRole, task_type: str, context: dict[str, Any]) -> Any:
        if model.call_attempts >= MAX_PROVIDER_CALLS:
            raise RuntimeError("PROVIDER_CALL_CEILING_REACHED")
        # Explicit bounded per-task output ceiling; the gateway/provider clamp it further.
        return await model.generate(
            role, task_type, context, {}, max_output_tokens=PER_TASK_OUTPUT_CEILING[task_type]
        )

    try:
        return await _run_recon_tasks(
            model,
            call,
            AgentRole,
            ReconDelegationOutput,
            ReconInterpretationOutput,
            ReconPlanOutput,
            RECON_CAPABILITIES,
            NmapScanPlan,
            build_nmap_bundle,
        )
    except ValueError as exc:
        # A gateway rejection (schema violation or finish_reason=length truncation) fails closed.
        # We do not repair, coerce or extract JSON, and we do not retry inside this run.
        return _rejection_result(model, exc)


async def _run_recon_tasks(  # noqa: PLR0913 - explicit lazily-imported deps keep the module import-light
    model: Any,
    call: Any,
    AgentRole: Any,
    ReconDelegationOutput: Any,
    ReconInterpretationOutput: Any,
    ReconPlanOutput: Any,
    RECON_CAPABILITIES: Any,
    NmapScanPlan: Any,
    build_nmap_bundle: Any,
) -> dict[str, Any]:
    # (1) + (2) PLAN_RECON for the Bank and Shop references. No port/answer-key disclosure.
    plans: dict[str, dict[str, Any]] = {}
    for target in ("range-bank", "range-shop"):
        raw = await call(
            AgentRole.RECON_AGENT,
            "PLAN_RECON",
            {
                "target_ref": target,
                "objective": "Enumerate the reachable service and documented API surface.",
            },
        )
        plan = ReconPlanOutput.model_validate_json(raw.payload_json)
        record: dict[str, Any] = {
            "capability_id": plan.capability_id,
            "capability_registered": plan.capability_id in RECON_CAPABILITIES,
            "has_typed_nmap_plan": plan.nmap_plan is not None,
        }
        # (2) If the model chose network discovery, prove its typed plan is controller-executable:
        # the controller renders shell-free argv and rejects anything out of profile.
        if plan.capability_id == "aegis.recon.network_service_discovery" and plan.nmap_plan:
            nmap_plan = NmapScanPlan(
                target_ref=plan.target_ref,
                profile_id=plan.profile_id or "RANGE_FULL_RECON",
                transports=plan.nmap_plan.transports,
                tcp_port_spec=plan.nmap_plan.tcp_port_spec,
                udp_port_spec=plan.nmap_plan.udp_port_spec,
                discovery_strategy=plan.nmap_plan.discovery_strategy,
                version_detection=plan.nmap_plan.version_detection,
                version_intensity=plan.nmap_plan.version_intensity,
                os_detection=plan.nmap_plan.os_detection,
                traceroute=plan.nmap_plan.traceroute,
                timing_profile=plan.nmap_plan.timing_profile,
                nse_categories=list(plan.nmap_plan.nse_categories),
                nse_script_ids=list(plan.nmap_plan.nse_script_ids),
            )
            bundle = build_nmap_bundle(nmap_plan)
            argvs = [list(j.argv) for j in bundle.jobs]
            record["plan_renders_shell_free_argv"] = all(
                a and a[0] == "nmap" and not ({"sh", "bash", "-c", ";", "|"} & set(a))
                for a in argvs
            )
            record["job_count"] = len(bundle.jobs)
        plans[target] = record

    # (3) INTERPRET_RECON_OBSERVATIONS on genuine, neutral observations for each target.
    interpretations: dict[str, dict[str, Any]] = {}
    for target in ("range-bank", "range-shop"):
        raw = await call(
            AgentRole.RECON_AGENT, "INTERPRET_RECON_OBSERVATIONS", _REAL_OBSERVATIONS[target]
        )
        interp = ReconInterpretationOutput.model_validate_json(raw.payload_json)
        interpretations[target] = {
            "unconfirmed": interp.unconfirmed,
            "salient_kinds": list(interp.salient_observation_kinds),
            "recommended_followups": list(interp.recommended_followups),
            "followups_all_registered": all(
                f in RECON_CAPABILITIES for f in interp.recommended_followups
            ),
        }

    # (4) DELEGATE_RECON_HYPOTHESIS from a documented parameter reference (reference-only).
    raw = await call(
        AgentRole.RECON_AGENT,
        "DELEGATE_RECON_HYPOTHESIS",
        {
            "target_ref": "range-shop",
            "route": "/products",
            "parameter": "q",
            "observation_kind": "PARAMETER_CANDIDATE",
        },
    )
    delegation = ReconDelegationOutput.model_validate_json(raw.payload_json)
    delegation_record = {
        "to_agent": delegation.to_agent,
        "capability_id": delegation.capability_id,
        "target_ref": delegation.target_ref,
        "route": delegation.route,
        "reference_only": delegation.capability_id.startswith("aegis."),
    }

    total_tokens = sum(r.usage.input_tokens + r.usage.output_tokens for r in model.call_records)
    projections = [r.request_projection for r in model.call_records]
    return {
        "status": "OK",
        "provider_calls": model.call_attempts,
        "provider_calls_recorded": len(model.call_records),
        "provider_tokens": total_tokens,
        "provider_reported_models": sorted(set(model.provider_reported_models)),
        "identity_exact_deepseek_v4_pro": _identity_ok(model.provider_reported_models),
        "projections_clean": _projections_all_clean(projections),
        "sanitized_projection_retained": bool(projections),
        "plans": plans,
        "interpretations": interpretations,
        "delegation": delegation_record,
        "within_call_ceiling": model.call_attempts <= MAX_PROVIDER_CALLS,
        "within_token_ceiling": total_tokens <= MAX_PROVIDER_TOKENS,
    }


# --------------------------------------------------------------------------- #
# Host orchestration.
# --------------------------------------------------------------------------- #


def _dc(
    *args: str, timeout: int = 300, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    cmd = [DOCKER, "compose", "-p", PROJECT, *STACK, *args]
    return subprocess.run(  # noqa: S603 - fixed docker binary, list argv, no shell
        cmd, capture_output=True, text=True, timeout=timeout, env=env
    )


def _compose_env() -> dict[str, str]:
    env = dict(os.environ)
    # Force the operator-authorized model and tight ceilings into Compose interpolation.
    env["AI_MODEL"] = CANONICAL_MODEL
    env["AI_ALLOWED_MODELS"] = CANONICAL_MODEL
    # The provider clamps each request to min(requested, MAX_COMPLETION_TOKENS), so the configured
    # cap must be at least the per-task ceiling for the headroom to take effect. Keep it exactly at
    # the ceiling so it remains a hard, bounded limit rather than an unbounded value.
    env["MAX_COMPLETION_TOKENS"] = env.get(
        "MAX_COMPLETION_TOKENS", str(max(PER_TASK_OUTPUT_CEILING.values()))
    )
    # A DeepSeek reasoning model emits reasoning_content before the JSON object; a 30s read timeout
    # was too tight for a 4096-token completion (finish never arrived -> ReadTimeout). 120s is a
    # measured, bounded raise, still far under the settings cap (le=600); never an unbounded value.
    env["MODEL_TIMEOUT_SECONDS"] = env.get("MODEL_TIMEOUT_SECONDS", "120")
    return env


def _health_wait(env: dict[str, str], *, attempts: int = 40) -> bool:
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


def _credential_isolation(env: dict[str, str]) -> dict[str, bool]:
    """The DeepSeek key must be present in the gateway only, never in the control plane."""
    cp = _dc("ps", "-q", "control-plane", timeout=60, env=env).stdout.strip()
    if not cp:
        return {"control_plane_has_no_key": False}
    probe = subprocess.run(  # noqa: S603 - read env of the control-plane process only
        [DOCKER, "exec", cp, "python", "-c",
         "import os;print(bool(os.environ.get('AI_AUTH_TOKEN')))"],
        capture_output=True, text=True, timeout=15,
    )
    return {"control_plane_has_no_key": probe.stdout.strip() == "False"}


def _run_live() -> dict[str, Any]:
    env = _compose_env()
    record: dict[str, Any] = {}
    build = _dc("build", "control-plane", "llm-gateway", timeout=1200, env=env)
    record["build_rc"] = build.returncode
    if build.returncode != 0:
        record["build_stderr_tail"] = build.stderr[-800:]
        return record
    up = _dc("up", "-d", "control-plane", "llm-gateway", "egress-proxy", timeout=300, env=env)
    record["up_rc"] = up.returncode
    if up.returncode != 0:
        record["up_stderr_tail"] = up.stderr[-800:]
        _dc("down", "-v", "--remove-orphans", timeout=180, env=env)
        return record
    try:
        record["healthy"] = _health_wait(env)
        record["credential_isolation"] = _credential_isolation(env)
        if not record["healthy"]:
            record["logs_tail"] = _dc("logs", "--tail", "40", timeout=60, env=env).stdout[-2000:]
            return record
        run = _dc(
            "exec", "-T", "control-plane",
            "python", "scripts/phase_1_7c_live_recon_smoke.py", "--in-container",
            timeout=300, env=env,
        )
        record["exec_rc"] = run.returncode
        stdout = run.stdout.strip()
        json_line = stdout.splitlines()[-1] if stdout else ""
        try:
            record["smoke"] = json.loads(json_line)
        except json.JSONDecodeError:
            record["smoke"] = None
            record["exec_stdout_tail"] = stdout[-2000:]
            record["exec_stderr_tail"] = run.stderr[-2000:]
    finally:
        down = _dc("down", "-v", "--remove-orphans", timeout=180, env=env)
        leftovers = subprocess.run(  # noqa: S603
            [DOCKER, "ps", "-a", "--filter", f"label=com.docker.compose.project={PROJECT}",
             "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=60,
        )
        record["cleanup"] = {
            "down_rc": down.returncode,
            "leftovers": [n for n in leftovers.stdout.splitlines() if n.strip()],
        }
    return record


def _tri(value: Any) -> Any:
    """Keep a real True/False or the literal UNKNOWN; anything else is NOT_EVALUATED."""
    if value is True or value is False:
        return value
    if value == UNKNOWN:
        return UNKNOWN
    return NOT_EVALUATED


def _eval_bool(smoke: dict[str, Any], key: str) -> Any:
    """A recorded check keeps its real boolean; a check that never ran is NOT_EVALUATED."""
    if key in smoke:
        return bool(smoke[key])
    return NOT_EVALUATED


def _verdict(record: dict[str, Any]) -> dict[str, Any]:
    smoke = record.get("smoke") or {}
    status = smoke.get("status")
    # Stack/credential/cleanup checks run before any provider call, so they are always evaluable.
    checks: dict[str, Any] = {
        "stack_healthy": bool(record.get("healthy")),
        "credential_in_gateway_only": bool(
            (record.get("credential_isolation") or {}).get("control_plane_has_no_key")
        ),
        "cleanup_ok": not (record.get("cleanup") or {}).get("leftovers", ["x"]),
    }

    if status == "OK":
        plans = smoke.get("plans") or {}
        interps = smoke.get("interpretations") or {}
        delegation = smoke.get("delegation") or {}
        checks.update(
            {
                "selected_registered_capability": bool(plans)
                and all(p.get("capability_registered") for p in plans.values()),
                # A non-nmap capability is a valid typed plan; an nmap plan must render shell-free.
                "produced_valid_typed_plan": bool(plans)
                and all(p.get("plan_renders_shell_free_argv", True) for p in plans.values()),
                "interpreted_observations_unconfirmed": bool(interps)
                and all(i.get("unconfirmed") is True for i in interps.values()),
                "delegated_reference_only": bool(delegation)
                and delegation.get("reference_only") is True
                and delegation.get("to_agent") in {"AUTHORIZATION_AGENT", "INJECTION_AGENT"},
                "avoided_confirming": bool(interps)
                and all(i.get("unconfirmed") is True for i in interps.values()),
                "identity_exact_deepseek_v4_pro": bool(
                    smoke.get("identity_exact_deepseek_v4_pro")
                ),
                "projections_clean": bool(smoke.get("projections_clean")),
                "sanitized_projection_retained": bool(smoke.get("sanitized_projection_retained")),
                "within_call_ceiling": bool(smoke.get("within_call_ceiling")),
                "within_token_ceiling": _tri(smoke.get("within_token_ceiling")),
            }
        )
    else:
        # A gateway rejection (or absent smoke): downstream capability/plan/interpret/delegate
        # checks could not execute and are NOT_EVALUATED, never false. Checks the rejected call
        # still produced (identity, projection retention, call/token counters) keep their real
        # result so a truncation stays auditable.
        checks.update(
            {
                "selected_registered_capability": NOT_EVALUATED,
                "produced_valid_typed_plan": NOT_EVALUATED,
                "interpreted_observations_unconfirmed": NOT_EVALUATED,
                "delegated_reference_only": NOT_EVALUATED,
                "avoided_confirming": NOT_EVALUATED,
                "identity_exact_deepseek_v4_pro": _eval_bool(
                    smoke, "identity_exact_deepseek_v4_pro"
                ),
                "projections_clean": _eval_bool(smoke, "projections_clean"),
                "sanitized_projection_retained": _eval_bool(smoke, "sanitized_projection_retained"),
                "within_call_ceiling": _eval_bool(smoke, "within_call_ceiling"),
                "within_token_ceiling": _tri(smoke.get("within_token_ceiling")),
            }
        )

    # PARTIAL/NO-GO whenever any required check is not strictly True (NOT_EVALUATED and UNKNOWN
    # never count as a pass).
    passed = all(v is True for v in checks.values())
    return {"checks": checks, "passed": passed, "status": status or "NO_SMOKE"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--in-container", action="store_true")
    args = parser.parse_args()

    if args.in_container:
        try:
            result = asyncio.run(_live_smoke())
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
    record = _run_live()
    verdict = _verdict(record)
    elapsed_s = (datetime.now(UTC) - started).total_seconds()

    stamp = started.strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path("artifacts") / f"phase-1.7c-live-recon-smoke-{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)
    acceptance: dict[str, Any] = {
        "phase": "1.7-C",
        "gate": "gate3_live_deepseek_recon_smoke",
        "model": CANONICAL_MODEL,
        "ceilings": {
            "provider_calls": MAX_PROVIDER_CALLS,
            "provider_tokens": MAX_PROVIDER_TOKENS,
            "concurrency": 1,
            "nmap_full_port_executions": 0,
            "nuclei_executions": 0,
            "zap_passive_executions": 0,
            "zap_active": "forbidden",
            "beast_mode": "forbidden",
            "offline_fallback_or_schema_repair": "forbidden",
        },
        "record": record,
        "verdict_detail": verdict,
        "elapsed_seconds": round(elapsed_s, 2),
        "verdict": (
            "LIVE PASS for the bounded DeepSeek recon smoke" if verdict["passed"] else "PARTIAL"
        ),
    }
    files = {"acceptance.json": acceptance}
    for name, payload in files.items():
        (out_dir / name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    sha_lines = [
        f"{hashlib.sha256((out_dir / n).read_bytes()).hexdigest()}  {n}" for n in sorted(files)
    ]
    (out_dir / "SHA256SUMS").write_text("\n".join(sha_lines) + "\n")
    print(json.dumps({**acceptance, "evidence_dir": str(out_dir)}, indent=2, sort_keys=True))
    return 0 if verdict["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
