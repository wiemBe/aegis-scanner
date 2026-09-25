"""Phase 2.3 — single LIVE bounded synthetic Adaptive-Retest / Remediation loop (aegis-ops only).

One real, auditable remediation/retest loop over the operator-authorized synthetic ``aegis-ops``
range, wired end to end with the live ``deepseek-v4-pro`` provider reached only via the isolated
llm-gateway, for exactly ONE controller-owned verifier-confirmed detection-control finding that is
remediated and then re-tested to PASS:

    fresh reset + select vulnerable
      -> addressable LEAD_ORCHESTRATOR job (QUEUED->CLAIMED->CLOSED)
      -> DELEGATE_ADVERSARY_SIMULATION (live, call 1)         : typed delegation (capability+class)
      -> persisted typed delegation (agentqueue://RECON_AGENT/<id>)
      -> addressable RECON_AGENT job (QUEUED->CLAIMED->CLOSED)
      -> PLAN_ADVERSARY_SIMULATION (live, call 2)             : registered capability + profile id
      -> Tool Broker -> disposable worker (baseline + alternate) vs the LIVE aegis-ops protected op
      -> independent deterministic verifier ADJUDICATES the worker evidence -> CONFIRMED
      -> persist finding (INITIAL_CONFIRMED)
      -> RECOMMEND_ADVERSARY_REMEDIATION (live, call 3)       : NON-AUTHORITATIVE registered id
      -> controller authorizes + applies the REGISTERED remediation (vulnerable->patched + sentinel
         rotation); immutable patch receipt persisted; state PATCH_APPLIED -> RETEST_QUEUED
      -> fresh RETEST RECON_AGENT job (receipt consumed exactly once) -> RETEST_RUNNING
      -> PLAN_ADVERSARY_SIMULATION retest (live, call 4)      : fresh plan from the sanitized
         retest projection
      -> Tool Broker -> disposable worker (baseline + alternate) again vs the now-patched op
      -> independent deterministic verifier ADJUDICATES the FRESH retest evidence -> PASS
      -> conclude retest (RETEST_PASS) with the causal-remediation-break proof
      -> reset + invalidate receipt + rotate/remove sentinel + teardown.

Narrow claim (only after a successful live run): "LIVE GO for one controller-authorized synthetic
remediation and fresh agent-directed retest loop that changed one verifier-confirmed detection-
control finding from CONFIRMED to PASS." It explicitly EXCLUDES autonomous code repair, general
remediation, production targets and broad regression assurance.

Authority model (unchanged from 2.2 + the 2.3 remediation authority): the model interprets the
authorized surface, produces typed hypotheses and *recommends* a registered remediation id; it isn't
authoritative for target authorization, routes, headers, payloads, the probe sequence, the mode, the
remediation decision, the state machine, the patch, the sentinel, confirmation, PASS/FAIL, severity,
retest eligibility or cleanup. The non-AI controller owns the remediation; the independent verifier
owns CONFIRMED/PASS and adjudicates the worker's own evidence, generating no substitute traffic.

Budget (this file is OFFLINE-READY; ``main`` fails closed without docker and ``.env.gateway`` so no
paid call is made until a run is explicitly authorized): <= 4 provider calls, <= 12,000 tokens,
concurrency 1, no auto-retry / schema repair / second campaign.
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
DS_PROJECT = "aegis-p23-live-ds"
RANGE_PROJECT = "aegis-p23-live-range"
RANGE_ACCESS_NET = f"{RANGE_PROJECT}_range-access"
RANGE_IMAGE = "aegis-range:1.6.0-dev"

CANONICAL_MODEL = "deepseek-v4-pro"
# Whole-run hard ceilings (combined across every in-container step of the single loop).
MAX_PROVIDER_CALLS = 4
MAX_PROVIDER_TOKENS = 12_000
PER_TASK_OUTPUT_CEILING = 4096

TARGET_REF = "range-ops"
APPLICATION_ID = "aegis-ops"
SCENARIO_ID = "ops-detection-control-bypass-v1"
TECHNIQUE_CLASS = "HTTP_DETECTION_CONTROL_BYPASS"
FINDING_TYPE = "HTTP_DETECTION_CONTROL_BYPASS"
REMEDIATION_PROFILE_ID = "enforce_uniform_detection_control_v1"

NOT_EVALUATED = "NOT_EVALUATED"
UNKNOWN = "UNKNOWN"

# Mode-blind objectives (no mode, scenario id, expected outcome, verifier predicate, marker or URL).
_DELEGATE_OBJECTIVE = (
    "The authorized synthetic operations surface protects one internal operation behind an HTTP "
    "detection control. Delegate to the recon agent the bounded adversary simulation that "
    "determines whether a controller-approved alternate request variant can bypass that detection "
    "control. Select the registered adversary-simulation capability and a typed technique class."
)
_PLAN_OBJECTIVE = (
    "Select the registered adversary-simulation capability, a typed technique class and the "
    "registered probe profile for a bounded test of whether a controller-approved alternate "
    "variant bypasses the authorized synthetic detection control. The selected probe profile — not "
    "this plan — determines the complete deterministic probe sequence, route, headers, pacing, "
    "maximum requests and stop conditions; any variant count you state is only a non-authoritative "
    "hint that the controller renders from the profile."
)
_RECOMMEND_OBJECTIVE = (
    "An independent verifier confirmed the detection-control finding described by the sanitized "
    "projection. Interpret it and recommend one registered remediation-profile id. Your "
    "recommendation is non-authoritative: the controller re-selects and applies the registered "
    "remediation. Do not author any command, patch or request, and do not change the target or "
    "scope."
)
_RETEST_PLAN_OBJECTIVE = (
    "The controller has applied a registered remediation to the previously confirmed finding "
    "referenced in the sanitized projection. Plan a fresh bounded retest of the same finding by "
    "selecting the registered adversary-simulation capability, technique class and probe profile. "
    "The controller-owned profile still owns the complete deterministic probe sequence."
)


# --------------------------------------------------------------------------- #
# Fail-closed cumulative campaign budget (calls + tokens), enforced BEFORE each call.
# --------------------------------------------------------------------------- #


class _CampaignBudget:
    """Host-side, cross-step, fail-closed campaign budget for the whole single-loop run.

    Each in-container step spawns its own model process, so per-process counters cannot enforce a
    campaign-cumulative ceiling. Before a provider call is started, :meth:`can_start` refuses it if
    starting it *could* exceed either the remaining call budget or the remaining token budget (the
    latter reserves the per-task output ceiling against the remaining tokens). A refused call yields
    ``BUDGET_STOP`` and stops the loop; no call is started that could breach the ceiling.
    """

    def __init__(self, max_calls: int, max_tokens: int, per_call_output_ceiling: int) -> None:
        self.max_calls = max_calls
        self.max_tokens = max_tokens
        self.per_call_output_ceiling = per_call_output_ceiling
        self.calls = 0
        self.tokens = 0

    def can_start(self) -> tuple[bool, str]:
        if self.calls + 1 > self.max_calls:
            return False, (f"CALL_CEILING: {self.calls} consumed + 1 > {self.max_calls} permitted")
        if self.tokens + self.per_call_output_ceiling > self.max_tokens:
            return False, (
                f"TOKEN_CEILING: {self.tokens} consumed + {self.per_call_output_ceiling} permitted "
                f"maximum > {self.max_tokens} campaign ceiling"
            )
        return True, "OK"

    def record(self, calls: Any, tokens: Any) -> None:
        if isinstance(calls, int) and not isinstance(calls, bool):
            self.calls += calls
        if isinstance(tokens, int) and not isinstance(tokens, bool):
            self.tokens += tokens

    def snapshot(self) -> dict[str, int]:
        return {
            "calls_consumed": self.calls,
            "tokens_consumed": self.tokens,
            "calls_remaining": self.max_calls - self.calls,
            "tokens_remaining": self.max_tokens - self.tokens,
        }


def _budget_stop_result(reason: str, budget: _CampaignBudget) -> dict[str, Any]:
    return {
        "exec_rc": 0,
        "result": {
            "status": "BUDGET_STOP",
            "reason": reason,
            "budget": budget.snapshot(),
            "provider_calls": 0,
            "provider_tokens": 0,
        },
    }


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
        p.redaction_status == "CLEAN" and p.forbidden_categories_present == [] for p in projections
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


async def _step_delegate() -> dict[str, Any]:
    """One live DELEGATE_ADVERSARY_SIMULATION (LEAD_ORCHESTRATOR). Mode-blind; catalogue-only."""

    from aegis.multi_agent.adversary_simulation import ADV_CAPABILITIES, ADV_TECHNIQUE_CLASSES
    from aegis.multi_agent.contracts import AdversarySimulationDelegationOutput, AgentRole
    from aegis.multi_agent.model import GatewayAgentModel
    from aegis.settings import get_settings

    model = GatewayAgentModel(get_settings())
    try:
        if model.call_attempts >= MAX_PROVIDER_CALLS:
            raise RuntimeError("PROVIDER_CALL_CEILING_REACHED")
        raw = await model.generate(
            AgentRole.LEAD_ORCHESTRATOR,
            "DELEGATE_ADVERSARY_SIMULATION",
            {
                "target_ref": TARGET_REF,
                "capability_catalog": sorted(ADV_CAPABILITIES),
                "technique_classes": sorted(ADV_TECHNIQUE_CLASSES),
                "downstream_agent": "RECON_AGENT",
                "objective": _DELEGATE_OBJECTIVE,
            },
            {},
            max_output_tokens=PER_TASK_OUTPUT_CEILING,
        )
        delegation = AdversarySimulationDelegationOutput.model_validate_json(raw.payload_json)
    except ValueError as exc:
        return _rejection_result(model, exc)
    return {
        "status": "OK",
        **_counters(model),
        "delegation": delegation.model_dump(mode="json"),
        "capability_registered": delegation.capability_id in ADV_CAPABILITIES,
    }


async def _step_plan(objective: str, projection: dict[str, Any] | None) -> dict[str, Any]:
    """One live PLAN_ADVERSARY_SIMULATION (RECON_AGENT). Catalogue-only; an optional sanitized
    projection (for the retest plan) is added as reference context only."""

    from aegis.multi_agent.adversary_simulation import (
        ADV_CAPABILITIES,
        ADV_PROBE_PROFILE_IDS,
        ADV_TECHNIQUE_CLASSES,
    )
    from aegis.multi_agent.contracts import AdversarySimulationPlanOutput, AgentRole
    from aegis.multi_agent.model import GatewayAgentModel
    from aegis.settings import get_settings

    context: dict[str, Any] = {
        "target_ref": TARGET_REF,
        "capability_catalog": sorted(ADV_CAPABILITIES),
        "technique_classes": sorted(ADV_TECHNIQUE_CLASSES),
        "probe_profile_ids": sorted(ADV_PROBE_PROFILE_IDS),
        "objective": objective,
    }
    if projection is not None:
        context["verified_finding_projection"] = projection

    model = GatewayAgentModel(get_settings())
    try:
        if model.call_attempts >= MAX_PROVIDER_CALLS:
            raise RuntimeError("PROVIDER_CALL_CEILING_REACHED")
        raw = await model.generate(
            AgentRole.RECON_AGENT,
            "PLAN_ADVERSARY_SIMULATION",
            context,
            {},
            max_output_tokens=PER_TASK_OUTPUT_CEILING,
        )
        plan = AdversarySimulationPlanOutput.model_validate_json(raw.payload_json)
    except ValueError as exc:
        return _rejection_result(model, exc)
    return {
        "status": "OK",
        **_counters(model),
        "plan": plan.model_dump(mode="json"),
        "capability_registered": plan.capability_id in ADV_CAPABILITIES,
    }


async def _step_recommend(projection: dict[str, Any]) -> dict[str, Any]:
    """One live RECOMMEND_ADVERSARY_REMEDIATION (RECON_AGENT) from the sanitized projection."""

    from aegis.multi_agent.contracts import AdversaryRemediationRecommendationOutput, AgentRole
    from aegis.multi_agent.model import GatewayAgentModel
    from aegis.multi_agent.remediation import REMEDIATION_PROFILE_IDS
    from aegis.settings import get_settings

    model = GatewayAgentModel(get_settings())
    try:
        if model.call_attempts >= MAX_PROVIDER_CALLS:
            raise RuntimeError("PROVIDER_CALL_CEILING_REACHED")
        raw = await model.generate(
            AgentRole.RECON_AGENT,
            "RECOMMEND_ADVERSARY_REMEDIATION",
            {
                "verified_finding_projection": projection,
                "registered_remediation_profile_ids": sorted(REMEDIATION_PROFILE_IDS),
                "objective": _RECOMMEND_OBJECTIVE,
            },
            {},
            max_output_tokens=PER_TASK_OUTPUT_CEILING,
        )
        recommendation = AdversaryRemediationRecommendationOutput.model_validate_json(
            raw.payload_json
        )
    except ValueError as exc:
        return _rejection_result(model, exc)
    return {
        "status": "OK",
        **_counters(model),
        "recommendation": {
            "recommended_remediation_profile_id": recommendation.recommended_remediation_profile_id,
            "remediation_authoritative": recommendation.remediation_authoritative,
            "technique_hypothesis": recommendation.technique_hypothesis,
            "finding_domain": recommendation.finding_domain,
            "salient_observation_kinds": list(recommendation.salient_observation_kinds),
            "unconfirmed": recommendation.unconfirmed,
            "summary_len": len(recommendation.summary),
        },
        "recommended_id_registered": (
            recommendation.recommended_remediation_profile_id in REMEDIATION_PROFILE_IDS
        ),
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


def _health_exec(container: str, url: str) -> bool:
    return (
        subprocess.run(  # noqa: S603
            [DOCKER, "exec", container, "python", "-c",
             f"import urllib.request;urllib.request.urlopen('{url}')"],
            capture_output=True,
            timeout=15,
        ).returncode
        == 0
    )


def _ds_health_wait(env: dict[str, str], *, attempts: int = 40) -> bool:
    import time

    gw = _dc("ps", "-q", "llm-gateway", timeout=60, env=env).stdout.strip()
    cp = _dc("ps", "-q", "control-plane", timeout=60, env=env).stdout.strip()
    if not gw or not cp:
        return False
    for _ in range(attempts):
        if _health_exec(gw, "http://127.0.0.1:8080/health") and _health_exec(
            cp, "http://127.0.0.1:8000/health"
        ):
            return True
        time.sleep(1.0)
    return False


def _range_health_wait(env: dict[str, str], *, attempts: int = 60) -> bool:
    import time

    for _ in range(attempts):
        controller = _rc("ps", "-q", "range-controller", timeout=60, env=env).stdout.strip()
        ops = _rc("ps", "-q", "aegis-ops-core", timeout=60, env=env).stdout.strip()
        if controller and ops and _health_exec(
            controller, "http://127.0.0.1:8090/health"
        ) and _health_exec(ops, "http://127.0.0.1:8103/health"):
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
        capture_output=True,
        text=True,
        timeout=15,
    )
    return {"control_plane_has_no_key": probe.stdout.strip() == "False"}


def _exec_ds_step(env: dict[str, str], step: str, stdin: str | None = None) -> dict[str, Any]:
    run = _dc(
        "exec",
        "-T",
        "control-plane",
        "python",
        "scripts/phase_2_3_live_adaptive_retest.py",
        "--in-container",
        "--step",
        step,
        timeout=300,
        env=env,
        stdin=stdin,
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
# there). The model never reaches this path. app/scenario are argv; the worker evidence for
# adjudication crosses via STDIN as canonical bytes with a SHA-256 digest argv (never a host env;
# `docker compose exec` does not forward host env, which silently arrives empty). The receiver fails
# closed via load_worker_evidence; there is no env fallback.
_CONTROLLER_PY = (
    "import asyncio, json, sys\n"
    "from aegis_range.controller import RangeController\n"
    "from aegis_range.runtime import Mode\n"
    "from aegis_range.ground_truth import GROUND_TRUTH_BY_SCENARIO\n"
    "from aegis.multi_agent.adversary_simulation import load_worker_evidence\n"
    "op, app, scen = sys.argv[1], sys.argv[2], sys.argv[3]\n"
    "expected_digest = sys.argv[4] if len(sys.argv) > 4 else None\n"
    "c = RangeController()\n"
    "async def run():\n"
    "    if op == 'reset':\n"
    "        return (await c.reset_application(app)).model_dump(mode='json')\n"
    "    if op == 'sentinel_reset':\n"
    "        return await c.reset_detection_sentinel(app)\n"
    "    if op == 'select_vulnerable':\n"
    "        return await c.select_mode(app, scen, Mode.VULNERABLE)\n"
    "    if op == 'state':\n"
    "        mode, gen, sent = await c._ops_synthetic_state(app, scen)\n"
    "        return {'mode': mode, 'generation': gen, 'sentinel_digest': sent}\n"
    "    if op == 'remediate':\n"
    "        return await c.apply_detection_control_remediation(app, scen)\n"
    "    if op == 'adjudicate':\n"
    "        raw = sys.stdin.buffer.read()\n"
    "        evidence = load_worker_evidence(raw, expected_digest=expected_digest)\n"
    "        result = await c.adjudicate_detection_control_bypass(app, evidence)\n"
    "        return result.model_dump(mode='json')\n"
    "    if op == 'ground_truth':\n"
    "        t = GROUND_TRUTH_BY_SCENARIO[scen]\n"
    "        return {'ground_truth_id': t.ground_truth_id, 'severity': t.severity,\n"
    "                'vulnerability_class_id': t.vulnerability_class_id,\n"
    "                'application_id': t.application_id, 'scenario_id': t.scenario_id,\n"
    "                'supported_modes': list(t.supported_modes), 'verifier_id': t.verifier_id}\n"
    "    return {'error': 'unknown op'}\n"
    "print(json.dumps(asyncio.run(run())))\n"
)


def _controller_op(
    env: dict[str, str], op: str, worker_evidence: dict[str, Any] | None = None
) -> dict[str, Any]:
    from aegis.multi_agent.adversary_simulation import (
        serialize_worker_evidence,
        worker_evidence_digest,
    )

    argv = ["exec", "-T", "range-controller", "python", "-c", _CONTROLLER_PY, op,
            APPLICATION_ID, SCENARIO_ID]
    stdin_bytes: bytes | None = None
    if worker_evidence is not None:
        raw = serialize_worker_evidence(worker_evidence)
        stdin_bytes = raw
        argv.append(worker_evidence_digest(raw))
    run = _rc(
        *argv,
        timeout=120,
        env=env,
        stdin=stdin_bytes.decode() if stdin_bytes is not None else None,
    )
    stdout = run.stdout.strip()
    json_line = stdout.splitlines()[-1] if stdout else ""
    try:
        return {"rc": run.returncode, "result": json.loads(json_line)}
    except json.JSONDecodeError:
        return {
            "rc": run.returncode,
            "result": None,
            "stderr_tail": run.stderr[-1000:],
            "stdout_tail": stdout[-1000:],
        }


# The bounded probe worker runs in a throwaway container on the internal range-access network. It
# imports the tested sanitizer/worker so the raw sentinel marker is redacted to a digest at the
# source. The controller-owned signature markers reach it ONLY via ADV_PROBE_SPECS (broker secret
# path); they are never persisted into the run record.
_WORKER_PY = (
    "import os,json\n"
    "from aegis.multi_agent.adversary_simulation import run_bounded_detection_probes\n"
    "specs=json.loads(os.environ['ADV_PROBE_SPECS'])\n"
    "print(json.dumps(run_bounded_detection_probes("
    "specs, base_url='http://aegis-ops:8103', target_ref='range-ops')))\n"
)


def _run_worker(request_specs: list[dict[str, object]]) -> dict[str, Any]:
    run = subprocess.run(  # noqa: S603 - fixed docker binary, list argv, no shell
        [
            DOCKER, "run", "--rm", "--network", RANGE_ACCESS_NET,
            "--user", "65532:65532", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "-e", "ADV_PROBE_SPECS=" + json.dumps(request_specs),
            RANGE_IMAGE, "python", "-c", _WORKER_PY,
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    stdout = run.stdout.strip()
    json_line = stdout.splitlines()[-1] if stdout else ""
    try:
        parsed = json.loads(json_line)
        return {"rc": run.returncode, "worker": parsed, "network": RANGE_ACCESS_NET}
    except json.JSONDecodeError:
        return {
            "rc": run.returncode,
            "worker": None,
            "network": RANGE_ACCESS_NET,
            "stderr_tail": run.stderr[-1000:],
            "stdout_tail": stdout[-1000:],
        }


def _broker_and_run(env: dict[str, str], plan_json: dict[str, Any]) -> dict[str, Any]:
    """Broker a live plan into a shell-free bounded probe execution and run the disposable worker.

    Returns {broker, worker, observations, adjudication_input, evidence_at} or {broker: REJECTED}.
    """

    from aegis.multi_agent.adversary_simulation import (
        AdversaryBroker,
        adversary_probe_requests,
        detection_adjudication_input,
        normalize_adv_observations,
        observation_warnings,
    )
    from aegis.multi_agent.contracts import AdversarySimulationPlanOutput

    out: dict[str, Any] = {}
    try:
        plan = AdversarySimulationPlanOutput.model_validate(plan_json)
        execution = AdversaryBroker().render(plan)
        out["broker"] = {
            "shell_free": execution.shell_free,
            "capability_id": execution.capability_id,
            "technique_class": execution.technique_class,
            "target_ref": execution.target_ref,
            "model_requested_profile_id": execution.model_requested_profile_id,
            "model_requested_probe_variants": execution.model_requested_probe_variants,
            "controller_effective_profile_id": execution.controller_effective_profile_id,
            "controller_effective_probe_variants": execution.controller_effective_probe_variants,
            "controller_adjustment_reason": execution.controller_adjustment_reason,
            "total_requests": execution.total_requests,
            "concurrency": execution.concurrency,
            "redirect_policy": execution.redirect_policy,
            "probes": [
                {"label": p.label, "method": p.method, "route": p.route, "variant": p.variant}
                for p in execution.probes
            ],
        }
    except Exception as exc:  # noqa: BLE001 - fail closed, record the reason as data
        return {"broker": {"status": "REJECTED", "error": f"{type(exc).__name__}: {exc}"[:200]}}

    request_specs = adversary_probe_requests(execution)
    out["worker"] = _run_worker(request_specs)
    out["evidence_at"] = datetime.now(UTC).isoformat()
    worker_out = (out["worker"] or {}).get("worker") or {}
    sanitized = worker_out.get("sanitized")
    observations = normalize_adv_observations(TARGET_REF, sanitized)
    obs_json = [o.model_dump(mode="json") for o in observations]
    out["observations"] = obs_json
    out["observation_kinds"] = sorted({o["kind"] for o in obs_json})
    out["observation_warnings"] = observation_warnings(observations)
    out["adjudication_input"] = detection_adjudication_input(sanitized)
    out["sanitized"] = sanitized if isinstance(sanitized, list) else []
    return out


# --------------------------------------------------------------------------- #
# Host: the single bounded remediation/retest loop.
# --------------------------------------------------------------------------- #


def _run_loop(  # noqa: PLR0915, PLR0912, C901
    env: dict[str, str], queue_db: str, ledger_db: str, budget: _CampaignBudget
) -> dict[str, Any]:
    from aegis.multi_agent.adversary_simulation import (
        CAP_DETECTION_CONTROL_PROBE,
        AdvAgentJob,
        AdvSimTaskQueue,
        PersistedAdvDelegation,
        evidence_sha256_of,
    )
    from aegis.multi_agent.remediation import (
        ENFORCE_UNIFORM_DETECTION_CONTROL_V1,
        PersistedFinding,
        RemediationController,
        RemediationLedger,
        RemediationLedgerError,
        RemediationState,
        build_recommendation_projection,
        build_retest_projection,
    )

    campaign_id = f"phase-2.3-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    loop: dict[str, Any] = {"campaign_id": campaign_id}

    # (0) Fresh reset + select vulnerable (a known reset vulnerable starting state).
    loop["reset"] = _controller_op(env, "reset")
    loop["select_vulnerable"] = _controller_op(env, "select_vulnerable")

    queue = AdvSimTaskQueue(queue_db)
    queue.initialize()
    ledger = RemediationLedger(ledger_db)
    ledger.initialize()
    controller = RemediationController(ledger)

    loop_id = f"rloop-{os.urandom(8).hex()}"
    ledger.open_loop(loop_id, campaign_id, TARGET_REF, SCENARIO_ID)
    loop["loop_id"] = loop_id

    # ------------------------ fresh initial hand-off + execution ------------------------ #
    lead_job = AdvAgentJob(
        job_id=f"agjob-{os.urandom(8).hex()}",
        to_agent="LEAD_ORCHESTRATOR",
        target_ref=TARGET_REF,
        technique_class=TECHNIQUE_CLASS,
        task_type="DELEGATE_ADVERSARY_SIMULATION",
        objective="delegate the bounded synthetic detection-control-bypass simulation",
    )
    lead_address = queue.enqueue_job(lead_job)
    lead_claimed = queue.claim_job(lead_address)
    loop["lead_job"] = {
        "address": lead_address,
        "claimed_status": lead_claimed.status,
        "resolved_by_address": queue.resolve_job(lead_address) is not None,
    }

    allowed, reason = budget.can_start()
    if not allowed:
        loop["delegate_step"] = _budget_stop_result(reason, budget)
        loop["budget_stop"] = True
        return loop
    delegate_step = _exec_ds_step(env, "delegate")
    loop["delegate_step"] = delegate_step
    delegate_result = delegate_step.get("result") or {}
    budget.record(delegate_result.get("provider_calls"), delegate_result.get("provider_tokens"))
    if delegate_result.get("status") != "OK":
        return loop

    source_digest = evidence_sha256_of(
        {
            "target_ref": TARGET_REF,
            "technique_class": TECHNIQUE_CLASS,
            "objective": _DELEGATE_OBJECTIVE,
        }
    )
    delegation = PersistedAdvDelegation(
        delegation_id=f"adelg-{os.urandom(8).hex()}",
        producer_job_id=lead_job.job_id,
        capability_id=CAP_DETECTION_CONTROL_PROBE,
        target_ref=TARGET_REF,
        technique_class=TECHNIQUE_CLASS,
        source_evidence_sha256=source_digest,
    )
    delegation_address = queue.persist_delegation(delegation)
    loop["delegation"] = {
        "address": delegation_address,
        "delegation_id": delegation.delegation_id,
        "producer_job_id": delegation.producer_job_id,
        "task_type": delegation.task_type,
        "resolved_by_address": queue.resolve_delegation(delegation_address) is not None,
    }

    recon_job = AdvAgentJob(
        job_id=f"agjob-{os.urandom(8).hex()}",
        to_agent="RECON_AGENT",
        target_ref=TARGET_REF,
        technique_class=TECHNIQUE_CLASS,
        task_type="PLAN_ADVERSARY_SIMULATION",
        objective="run the bounded synthetic detection-control-bypass simulation",
        from_delegation_id=delegation.delegation_id,
        producer_job_id=lead_job.job_id,
    )
    recon_address = queue.enqueue_job(recon_job)
    recon_claimed = queue.claim_job(recon_address)
    loop["recon_job"] = {
        "address": recon_address,
        "claimed_status": recon_claimed.status,
        "resolved_by_address": queue.resolve_job(recon_address) is not None,
        "from_delegation_id": recon_job.from_delegation_id,
        "producer_job_id": recon_job.producer_job_id,
    }
    loop["handoff_linked"] = queue.handoff_linked(delegation.delegation_id)

    allowed, reason = budget.can_start()
    if not allowed:
        loop["plan_step"] = _budget_stop_result(reason, budget)
        loop["budget_stop"] = True
        return loop
    plan_step = _exec_ds_step(env, "plan_initial")
    loop["plan_step"] = plan_step
    plan_result = plan_step.get("result") or {}
    budget.record(plan_result.get("provider_calls"), plan_result.get("provider_tokens"))
    if plan_result.get("status") != "OK":
        return loop

    # Capture the controller state that is live when the worker probes (finding provenance).
    loop["initial_state"] = _controller_op(env, "state")
    initial = _broker_and_run(env, plan_result["plan"])
    loop["initial_execution"] = initial
    if initial.get("broker", {}).get("status") == "REJECTED":
        return loop

    # Independent verifier adjudicates the WORKER evidence (no substitute traffic) -> CONFIRMED.
    loop["initial_verify"] = _controller_op(
        env, "adjudicate", worker_evidence=initial["adjudication_input"]
    )
    initial_status = ((loop["initial_verify"].get("result") or {}).get("status"))
    initial_facts = ((loop["initial_verify"].get("result") or {}).get("facts") or {})
    queue.close_job(recon_address)
    queue.close_job(lead_address)
    loop["lead_job"]["closed_status"] = "CLOSED"
    loop["recon_job"]["closed_status"] = "CLOSED"

    if initial_status != "CONFIRMED":
        loop["state"] = ledger.transition(
            loop_id, RemediationState.INCOMPLETE, "initial finding not CONFIRMED"
        ).value
        return loop

    # ------------------------ persist finding (INITIAL_CONFIRMED) ------------------------ #
    state_res = (loop["initial_state"].get("result") or {})
    from aegis.multi_agent.remediation import controller_state_digest

    finding = PersistedFinding(
        finding_id=f"find-{os.urandom(8).hex()}",
        loop_id=loop_id,
        campaign_id=campaign_id,
        target_ref=TARGET_REF,
        scenario_id=SCENARIO_ID,
        finding_type=FINDING_TYPE,  # type: ignore[arg-type]
        verified_status="CONFIRMED",
        verifier_evidence_sha256=str(
            (loop["initial_verify"].get("result") or {}).get("evidence_sha256", "0" * 64)
        ),
        controller_state_digest=controller_state_digest(
            str(state_res.get("mode", "")),
            int(state_res.get("generation", 0)),
            str(state_res.get("sentinel_digest", "")),
        ),
        controller_sentinel_epoch=int(state_res.get("generation", 0)),
        initial_evidence_at=datetime.fromisoformat(initial["evidence_at"]),
    )
    controller.confirm_initial_finding(finding)
    loop["finding"] = {
        "finding_id": finding.finding_id,
        "finding_uri": finding.finding_uri,
        "verified_status": finding.verified_status,
        "initial_evidence_at": finding.initial_evidence_at.isoformat(),
        "state_after": ledger.state(loop_id).value,
    }

    # ------------------------ RECOMMEND (call 3) ------------------------ #
    recommendation_projection = build_recommendation_projection(finding, initial.get("sanitized"))
    loop["recommendation_projection"] = recommendation_projection
    allowed, reason = budget.can_start()
    if not allowed:
        loop["recommend_step"] = _budget_stop_result(reason, budget)
        loop["budget_stop"] = True
        return loop
    recommend_step = _exec_ds_step(
        env, "recommend", stdin=json.dumps({"projection": recommendation_projection})
    )
    loop["recommend_step"] = recommend_step
    recommend_result = recommend_step.get("result") or {}
    budget.record(recommend_result.get("provider_calls"), recommend_result.get("provider_tokens"))
    if recommend_result.get("status") != "OK":
        loop["state"] = ledger.transition(
            loop_id, RemediationState.INCOMPLETE, "recommendation step failed"
        ).value
        return loop
    recommended_id = recommend_result["recommendation"]["recommended_remediation_profile_id"]
    controller.record_recommendation(finding, recommended_id)
    loop["recommendation"] = {
        "recommended_id": recommended_id,
        "remediation_authoritative": recommend_result["recommendation"][
            "remediation_authoritative"
        ],
        "state_after": ledger.state(loop_id).value,
    }

    # --------------------- controller authorizes + applies remediation --------------------- #
    now = datetime.now(UTC)
    # The controller SELECTS the registered remediation itself (the model recommendation is a hint).
    controller_selected_id = ENFORCE_UNIFORM_DETECTION_CONTROL_V1
    authorization = controller.authorize_remediation(
        finding,
        controller_selected_id,
        now=now,
        authorization_id=f"rauth-{os.urandom(8).hex()}",
        lease_id=f"rlease-{os.urandom(8).hex()}",
    )
    loop["authorization"] = {
        "authorization_id": authorization.authorization_id,
        "lease_id": authorization.lease_id,
        "controller_selected_remediation_id": controller_selected_id,
        "valid_at_issue": authorization.valid_at(now),
        "state_after": ledger.state(loop_id).value,
    }

    mutation = _controller_op(env, "remediate")
    loop["remediation_mutation"] = mutation
    mutation_result = mutation.get("result") or {}
    try:
        receipt = controller.apply_remediation(
            finding,
            authorization,
            mutation_result,
            now=datetime.now(UTC),
            receipt_id=f"rcpt-{os.urandom(8).hex()}",
            campaign_id=campaign_id,
        )
    except Exception as exc:  # noqa: BLE001 - fail closed, record as data
        loop["patch"] = {"status": "REJECTED", "error": f"{type(exc).__name__}: {exc}"[:200]}
        loop["state"] = ledger.transition(
            loop_id, RemediationState.INCOMPLETE, "patch application rejected"
        ).value
        return loop
    loop["patch"] = {
        "receipt_id": receipt.receipt_id,
        "receipt_uri": receipt.receipt_uri,
        "previous_mode": receipt.previous_mode,
        "resulting_mode": receipt.resulting_mode,
        "pre_state_digest": receipt.pre_state_digest,
        "post_state_digest": receipt.post_state_digest,
        "state_changed": receipt.pre_state_digest != receipt.post_state_digest,
        "old_sentinel_epoch": receipt.old_sentinel_epoch,
        "new_sentinel_epoch": receipt.new_sentinel_epoch,
        "sentinel_rotated": receipt.old_sentinel_digest != receipt.new_sentinel_digest,
        "applied_at": receipt.applied_at.isoformat(),
        "cleanup_obligations": list(receipt.cleanup_obligations),
        "state_after": ledger.state(loop_id).value,
    }

    # ------------------------ fresh retest job + consume receipt ------------------------ #
    retest_job = AdvAgentJob(
        job_id=f"agjob-{os.urandom(8).hex()}",
        to_agent="RECON_AGENT",
        target_ref=TARGET_REF,
        technique_class=TECHNIQUE_CLASS,
        task_type="RETEST_ADVERSARY_SIMULATION",
        objective="fresh agent-directed retest of the remediated detection-control finding",
    )
    retest_address = queue.enqueue_job(retest_job)
    retest_claimed = queue.claim_job(retest_address)
    stored_receipt = ledger.get_receipt(receipt.receipt_id)
    assert stored_receipt is not None
    controller.begin_retest(finding, stored_receipt, retest_job.job_id)
    binding = ledger.retest_binding(retest_job.job_id)
    loop["retest_job"] = {
        "address": retest_address,
        "claimed_status": retest_claimed.status,
        "resolved_by_address": queue.resolve_job(retest_address) is not None,
        "binding": binding,
        "receipt_consumed": ledger.receipt_consumed(receipt.receipt_id),
        "state_after": ledger.state(loop_id).value,
    }

    # Replay: a second consume of the same receipt must fail closed.
    try:
        ledger.consume_receipt(receipt.receipt_id)
        loop["retest_job"]["replay_blocked"] = False
    except RemediationLedgerError:
        loop["retest_job"]["replay_blocked"] = True

    # ------------------------ RETEST PLAN (call 4) + fresh execution ------------------------ #
    consumed_receipt = ledger.get_receipt(receipt.receipt_id)
    assert consumed_receipt is not None
    retest_projection = build_retest_projection(finding, consumed_receipt, initial.get("sanitized"))
    loop["retest_projection"] = retest_projection
    allowed, reason = budget.can_start()
    if not allowed:
        loop["retest_plan_step"] = _budget_stop_result(reason, budget)
        loop["budget_stop"] = True
        return loop
    retest_plan_step = _exec_ds_step(
        env, "plan_retest", stdin=json.dumps({"projection": retest_projection})
    )
    loop["retest_plan_step"] = retest_plan_step
    retest_plan_result = retest_plan_step.get("result") or {}
    budget.record(
        retest_plan_result.get("provider_calls"), retest_plan_result.get("provider_tokens")
    )
    if retest_plan_result.get("status") != "OK":
        loop["state"] = ledger.transition(
            loop_id, RemediationState.RETEST_FAIL, "retest plan step failed"
        ).value
        return loop

    retest = _broker_and_run(env, retest_plan_result["plan"])
    loop["retest_execution"] = retest
    if retest.get("broker", {}).get("status") == "REJECTED":
        loop["state"] = ledger.transition(
            loop_id, RemediationState.RETEST_FAIL, "retest broker rejected"
        ).value
        return loop

    # Independent verifier adjudicates the FRESH retest evidence (no substitute traffic) -> PASS.
    loop["retest_verify"] = _controller_op(
        env, "adjudicate", worker_evidence=retest["adjudication_input"]
    )
    retest_status = ((loop["retest_verify"].get("result") or {}).get("status"))
    retest_facts = ((loop["retest_verify"].get("result") or {}).get("facts") or {})

    # Stale-evidence reuse: the INITIAL vulnerable evidence must NOT satisfy the post-patch retest.
    stale = _controller_op(env, "adjudicate", worker_evidence=initial["adjudication_input"])
    stale_status = ((stale.get("result") or {}).get("status"))
    loop["stale_evidence_retest"] = {"status": stale_status, "blocked": stale_status != "PASS"}

    # Conclude the retest with the causal-remediation-break proof (over persisted immutable inputs).
    final_state, proof = controller.conclude_retest(
        finding,
        consumed_receipt,
        retest_verifier_status=str(retest_status),
        initial_evidence_at=finding.initial_evidence_at,
        retest_evidence_at=datetime.fromisoformat(retest["evidence_at"]),
        retest_target_ref=TARGET_REF,
        retest_scenario_id=SCENARIO_ID,
    )
    queue.close_job(retest_address)
    loop["retest_job"]["closed_status"] = "CLOSED"
    loop["causal_proof"] = proof
    loop["retest_verify_facts"] = retest_facts
    loop["initial_verify_facts"] = initial_facts
    loop["final_state"] = final_state.value
    loop["loop_transitions"] = ledger.loop_transitions(loop_id)
    return loop


def _run_live(queue_db: str, ledger_db: str) -> dict[str, Any]:
    env = _compose_env()
    record: dict[str, Any] = {"queue_db_path": queue_db, "ledger_db_path": ledger_db}

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
            record["range_logs_tail"] = _rc("logs", "--tail", "40", timeout=60, env=env).stdout[
                -2000:
            ]
            return record

        budget = _CampaignBudget(MAX_PROVIDER_CALLS, MAX_PROVIDER_TOKENS, PER_TASK_OUTPUT_CEILING)
        record["loop"] = _run_loop(env, queue_db, ledger_db, budget)
        record["budget_final"] = budget.snapshot()
    finally:
        _final_reset_and_cleanup(env, record)
    return record


def _final_reset_and_cleanup(env: dict[str, str], record: dict[str, Any]) -> None:
    # Restore the synthetic target to its documented baseline and rotate/remove the sentinel.
    record["final_reset"] = _controller_op(env, "reset")
    record["final_sentinel_reset"] = _controller_op(env, "sentinel_reset")
    _teardown(env, record)


def _teardown(env: dict[str, str], record: dict[str, Any]) -> None:
    ds_down = _dc("down", "-v", "--remove-orphans", timeout=180, env=env)
    range_down = _rc("down", "-v", "--remove-orphans", timeout=240, env=env)
    ds_left = subprocess.run(  # noqa: S603
        [DOCKER, "ps", "-a", "--filter",
         f"label=com.docker.compose.project={DS_PROJECT}", "--format", "{{.Names}}"],
        capture_output=True, text=True, timeout=60,
    )
    range_left = subprocess.run(  # noqa: S603
        [DOCKER, "ps", "-a", "--filter",
         f"label=com.docker.compose.project={RANGE_PROJECT}", "--format", "{{.Names}}"],
        capture_output=True, text=True, timeout=60,
    )
    net_left = subprocess.run(  # noqa: S603
        [DOCKER, "network", "ls", "--filter", f"name={RANGE_PROJECT}", "--format", "{{.Name}}"],
        capture_output=True, text=True, timeout=60,
    )
    ds_net_left = subprocess.run(  # noqa: S603
        [DOCKER, "network", "ls", "--filter", f"name={DS_PROJECT}", "--format", "{{.Name}}"],
        capture_output=True, text=True, timeout=60,
    )
    record["cleanup"] = {
        "ds_down_rc": ds_down.returncode,
        "range_down_rc": range_down.returncode,
        "down_rc": max(ds_down.returncode, range_down.returncode),
        "stack_leftovers": [n for n in ds_left.stdout.splitlines() if n.strip()]
        + [n for n in range_left.stdout.splitlines() if n.strip()],
        "network_leftovers": [n for n in net_left.stdout.splitlines() if n.strip()]
        + [n for n in ds_net_left.stdout.splitlines() if n.strip()],
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


def _step_ok(container: dict[str, Any], step: str) -> bool:
    result = (container.get(step) or {}).get("result") or {}
    return result.get("status") == "OK"


def _worker_probes(execution: dict[str, Any]) -> list[dict[str, Any]]:
    sanitized = execution.get("sanitized")
    return sanitized if isinstance(sanitized, list) else []


def _probe(execution: dict[str, Any], label: str) -> dict[str, Any] | None:
    for probe in _worker_probes(execution):
        if probe.get("label") == label:
            return probe
    return None


def _both_probes_executed(execution: dict[str, Any]) -> bool:
    baseline = _probe(execution, "BASELINE_PROBE")
    alternate = _probe(execution, "ALTERNATE_PROBE")
    return (
        baseline is not None
        and alternate is not None
        and int(baseline.get("status_code", 0)) > 0
        and int(alternate.get("status_code", 0)) > 0
    )


def _all_model_results(loop: dict[str, Any]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for step in ("delegate_step", "plan_step", "recommend_step", "retest_plan_step"):
        result = (loop.get(step) or {}).get("result")
        if isinstance(result, dict) and result.get("status") == "OK":
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


def _no_marker_leak(record: dict[str, Any]) -> bool:
    blob = json.dumps(record, sort_keys=True, default=str)
    forbidden = ("ops-scan-baseline-v1", "ops-scan-alternate-v1")
    return not any(token in blob for token in forbidden)


def _verdict(record: dict[str, Any]) -> dict[str, Any]:  # noqa: C901, PLR0912, PLR0915
    loop = record.get("loop") or {}
    cleanup = record.get("cleanup") or {}
    model_results = _all_model_results(loop)
    initial = loop.get("initial_execution") or {}
    retest = loop.get("retest_execution") or {}
    patch = loop.get("patch") or {}
    proof = loop.get("causal_proof") or {}

    checks: dict[str, Any] = {}

    def na_group(keys: tuple[str, ...]) -> None:
        for key in keys:
            checks[key] = NOT_EVALUATED

    # --- fresh initial jobs + hand-off --- #
    lead = loop.get("lead_job") or {}
    recon = loop.get("recon_job") or {}
    if lead and recon:
        checks["fresh_initial_lead_job_persisted"] = (
            str(lead.get("address", "")).startswith("agentjob://LEAD_ORCHESTRATOR/")
            and lead.get("claimed_status") == "CLAIMED"
            and bool(lead.get("resolved_by_address"))
        )
        checks["fresh_initial_recon_job_persisted"] = (
            str(recon.get("address", "")).startswith("agentjob://RECON_AGENT/")
            and recon.get("claimed_status") == "CLAIMED"
            and bool(recon.get("resolved_by_address"))
            and recon.get("from_delegation_id")
            == (loop.get("delegation") or {}).get("delegation_id")
        )
    else:
        na_group(("fresh_initial_lead_job_persisted", "fresh_initial_recon_job_persisted"))

    # --- fresh initial worker execution + verifier CONFIRMED --- #
    if initial.get("broker") and initial.get("sanitized") is not None:
        checks["initial_worker_execution_fresh"] = _both_probes_executed(initial)
    else:
        checks["initial_worker_execution_fresh"] = NOT_EVALUATED
    initial_status = ((loop.get("initial_verify") or {}).get("result") or {}).get("status")
    checks["initial_verifier_confirmed"] = (
        initial_status == "CONFIRMED" if initial_status is not None else NOT_EVALUATED
    )

    # --- recommendation (model-generated, non-authoritative) --- #
    if _step_ok(loop, "recommend_step"):
        rec = loop["recommend_step"]["result"]["recommendation"]
        checks["remediation_recommendation_model_generated"] = bool(
            rec.get("recommended_remediation_profile_id")
        )
        checks["remediation_recommendation_non_authoritative"] = (
            rec.get("remediation_authoritative") is False
        )
    else:
        na_group(
            (
                "remediation_recommendation_model_generated",
                "remediation_recommendation_non_authoritative",
            )
        )

    # --- controller selection + authorization --- #
    authorization = loop.get("authorization") or {}
    if authorization:
        checks["registered_remediation_selected_by_controller"] = (
            authorization.get("controller_selected_remediation_id") == REMEDIATION_PROFILE_ID
            and authorization.get("state_after") == "PATCH_AUTHORIZED"
        )
        checks["patch_authorization_valid"] = authorization.get("valid_at_issue") is True
    else:
        na_group(("registered_remediation_selected_by_controller", "patch_authorization_valid"))

    # --- patch receipt + state change + sentinel rotation --- #
    if patch and patch.get("receipt_id"):
        checks["patch_receipt_persisted"] = bool(patch.get("receipt_uri")) and (
            patch.get("state_after") == "RETEST_QUEUED"
        )
        checks["patch_changed_controller_state"] = patch.get("state_changed") is True
        checks["sentinel_epoch_rotated"] = patch.get("sentinel_rotated") is True
    else:
        na_group(
            ("patch_receipt_persisted", "patch_changed_controller_state", "sentinel_epoch_rotated")
        )

    # --- fresh retest job, binding, receipt single-use + replay --- #
    retest_job = loop.get("retest_job") or {}
    if retest_job and retest_job.get("address"):
        binding = retest_job.get("binding") or {}
        checks["fresh_retest_job_persisted"] = (
            str(retest_job.get("address", "")).startswith("agentjob://RECON_AGENT/")
            and retest_job.get("claimed_status") == "CLAIMED"
            and bool(retest_job.get("resolved_by_address"))
        )
        checks["retest_bound_to_original_finding"] = binding.get("finding_id") == (
            loop.get("finding") or {}
        ).get("finding_id")
        checks["retest_used_valid_patch_receipt"] = (
            retest_job.get("receipt_consumed") is True
            and binding.get("receipt_id") == patch.get("receipt_id")
        )
        checks["patch_receipt_replay_blocked"] = retest_job.get("replay_blocked") is True
    else:
        na_group(
            (
                "fresh_retest_job_persisted",
                "retest_bound_to_original_finding",
                "retest_used_valid_patch_receipt",
                "patch_receipt_replay_blocked",
            )
        )

    # --- retest ordering + fresh evidence + stale rejection --- #
    stale = loop.get("stale_evidence_retest") or {}
    checks["retest_started_after_patch"] = (
        bool(proof.get("retest_evidence_follows_patch")) if proof else NOT_EVALUATED
    )
    checks["stale_evidence_reuse_blocked"] = (
        stale.get("blocked") is True if stale else NOT_EVALUATED
    )
    if retest.get("broker") and retest.get("sanitized") is not None:
        checks["retest_worker_reexecuted_sequence"] = _both_probes_executed(retest)
    else:
        checks["retest_worker_reexecuted_sequence"] = NOT_EVALUATED

    # --- retest verifier adjudication + non-substitution + PASS --- #
    retest_status = ((loop.get("retest_verify") or {}).get("result") or {}).get("status")
    retest_facts = loop.get("retest_verify_facts") or {}
    if retest_status is not None:
        checks["retest_verifier_adjudicated_fresh_evidence"] = (
            retest_status in {"PASS", "CONFIRMED"} and retest_facts.get("baseline_denied") is True
        )
        checks["verifier_did_not_substitute"] = (
            retest_facts.get("verifier_generated_bypass_traffic") is False
            and int(retest_facts.get("verifier_probe_requests", 1)) == 0
        )
        checks["patched_retest_pass"] = retest_status == "PASS"
    else:
        na_group(
            (
                "retest_verifier_adjudicated_fresh_evidence",
                "verifier_did_not_substitute",
                "patched_retest_pass",
            )
        )

    # --- causal remediation break proven --- #
    checks["causal_remediation_break_proven"] = (
        all(bool(v) for v in proof.values()) if proof else NOT_EVALUATED
    )

    # --- scope + egress --- #
    brokers = [b for b in (initial.get("broker"), retest.get("broker")) if isinstance(b, dict)]
    if brokers and all("probes" in b for b in brokers):
        checks["inventory_scope_enforced"] = all(b.get("target_ref") == TARGET_REF for b in brokers)
        egress_ok = True
        for execution in (initial, retest):
            worker = execution.get("worker") or {}
            probes = (execution.get("broker") or {}).get("probes") or []
            relative = all(
                str(p.get("route", "")).startswith("/") and "://" not in str(p.get("route", ""))
                for p in probes
            )
            egress_ok = egress_ok and relative and str(worker.get("network", "")).endswith(
                "range-access"
            )
        checks["no_public_egress"] = egress_ok
    else:
        na_group(("inventory_scope_enforced", "no_public_egress"))

    # --- reset + cleanup + no leftovers --- #
    final_reset = (record.get("final_reset") or {}).get("result") or {}
    final_sentinel = (record.get("final_sentinel_reset") or {}).get("result") or {}
    if record.get("final_reset") is not None:
        checks["reset_complete"] = bool(final_reset.get("healthy")) and (
            final_sentinel.get("status") == "reset" or final_sentinel.get("status_code") == 200
        )
    else:
        checks["reset_complete"] = NOT_EVALUATED
    checks["cleanup_complete"] = cleanup.get("down_rc") == 0 if cleanup else NOT_EVALUATED
    checks["no_leftovers"] = (
        (
            bool(cleanup)
            and not cleanup.get("stack_leftovers", ["x"])
            and not cleanup.get("network_leftovers", ["x"])
        )
        if cleanup
        else NOT_EVALUATED
    )
    checks["no_marker_leak"] = _no_marker_leak(record)

    # --- identity + ceilings --- #
    if model_results:
        checks["identity_exact_deepseek_v4_pro"] = all(
            r.get("identity_exact_deepseek_v4_pro") is True for r in model_results
        )
    else:
        checks["identity_exact_deepseek_v4_pro"] = NOT_EVALUATED
    total_calls = sum(int(r.get("provider_calls", 0)) for r in model_results)
    checks["provider_call_ceiling_enforced"] = (
        total_calls <= MAX_PROVIDER_CALLS if model_results else NOT_EVALUATED
    )
    combined_tokens = _combined_tokens(model_results) if model_results else NOT_EVALUATED
    within_tokens: Any = (
        combined_tokens <= MAX_PROVIDER_TOKENS
        if isinstance(combined_tokens, int)
        else combined_tokens
    )
    checks["campaign_token_ceiling_enforced"] = _tri(within_tokens)

    passed = all(v is True for v in checks.values())
    return {
        "checks": checks,
        "passed": passed,
        "provider_calls_total": total_calls,
        "provider_tokens_total": combined_tokens,
        "final_state": loop.get("final_state", NOT_EVALUATED),
    }


# --------------------------------------------------------------------------- #
# Entrypoint.
# --------------------------------------------------------------------------- #


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--in-container", action="store_true")
    parser.add_argument(
        "--step", choices=["delegate", "plan_initial", "recommend", "plan_retest"]
    )
    args = parser.parse_args()

    if args.in_container:
        try:
            if args.step == "delegate":
                result = asyncio.run(_step_delegate())
            elif args.step == "plan_initial":
                result = asyncio.run(_step_plan(_PLAN_OBJECTIVE, None))
            elif args.step == "recommend":
                projection = json.loads(sys.stdin.read())["projection"]
                result = asyncio.run(_step_recommend(projection))
            elif args.step == "plan_retest":
                projection = json.loads(sys.stdin.read())["projection"]
                result = asyncio.run(_step_plan(_RETEST_PLAN_OBJECTIVE, projection))
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
    out_dir = Path("artifacts") / f"phase-2.3-live-adaptive-retest-{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    queue_db = str(out_dir / "adversary_simulation_jobs.sqlite3")
    ledger_db = str(out_dir / "remediation_ledger.sqlite3")
    record = _run_live(queue_db, ledger_db)
    verdict = _verdict(record)
    elapsed_s = (datetime.now(UTC) - started).total_seconds()

    acceptance: dict[str, Any] = {
        "phase": "2.3",
        "scope": (
            "single LIVE bounded synthetic adaptive-retest / remediation loop for one controller-"
            "owned verifier-confirmed HTTP detection-control finding (aegis-ops): fresh vulnerable "
            "execution -> verifier CONFIRMED -> AI remediation recommendation (non-authoritative) "
            "controller-authorized registered remediation + immutable patch receipt -> fresh agent-"
            "directed retest -> verifier PASS, with the causal-remediation-break proven"
        ),
        "scenario": {
            "target_ref": TARGET_REF,
            "application_id": APPLICATION_ID,
            "scenario_id": SCENARIO_ID,
            "technique_class": TECHNIQUE_CLASS,
            "remediation_profile_id": REMEDIATION_PROFILE_ID,
        },
        "model": CANONICAL_MODEL,
        "ceilings": {
            "provider_calls": MAX_PROVIDER_CALLS,
            "provider_tokens": MAX_PROVIDER_TOKENS,
            "per_task_output_ceiling": PER_TASK_OUTPUT_CEILING,
            "concurrency": 1,
            "auto_retry_or_schema_repair": "forbidden",
        },
        "lead_job_address_scheme": "agentjob://LEAD_ORCHESTRATOR/<job_id>",
        "recon_agent_job_address_scheme": "agentjob://RECON_AGENT/<job_id>",
        "delegation_address_scheme": "agentqueue://RECON_AGENT/<delegation_id>",
        "patch_receipt_uri_scheme": "patchreceipt://range-ops/<receipt_id>",
        "record": record,
        "verdict_detail": verdict,
        "provider_calls_total": verdict["provider_calls_total"],
        "provider_tokens_total": verdict["provider_tokens_total"],
        "elapsed_seconds": round(elapsed_s, 2),
        "verdict": (
            "LIVE GO for one controller-authorized synthetic remediation and fresh agent-directed "
            "retest loop that changed one verifier-confirmed detection-control finding from "
            "CONFIRMED to PASS"
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
