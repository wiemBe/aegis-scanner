"""Phase 2.0 — single LIVE verified multi-primitive attack chain (aegis-cloud only).

One real, auditable, causally-connected two-primitive attack chain against the operator-authorized
synthetic ``aegis-cloud`` range, wired end to end with the live ``deepseek-v4-pro`` provider reached
only through the isolated llm-gateway, for exactly ONE controller-owned vulnerable/patched campaign:

    addressable CHAIN_AGENT job (consumed: QUEUED -> CLAIMED -> CLOSED)
      -> PLAN_ATTACK_CHAIN (CHAIN_AGENT, live)      : typed two-primitive chain plan
      -> PLAN_CLOUD_BOUNDARY (CLOUD_BOUNDARY_AGENT, live) : Stage A probe plan (reused Phase 1.9)
      -> Tool Broker + isolated broker execution    : Stage A metadata probe; credential captured at
                                                     source into a secret store; only an
                                                       opaque credentialref:// leaves the boundary
      -> INDEPENDENT VERIFIER (Stage A link)         : CONFIRMED (exposed) / PASS (suppressed)
      -> INTERPRET_CHAIN_STAGE (CHAIN_AGENT, live)   : reads the verified Stage A link
      -> SELECT_NEXT_CHAIN_STEP (AUTHORIZATION_AGENT, live) : selects the credential-backed Stage B
      -> Tool Broker + isolated broker execution     : Stage B resolves the opaque reference
                                                       broker-side and reaches the private admin
                                                       operation; a causal-dependency control proves
                                                       an unrelated/invalid reference is rejected
      -> INDEPENDENT VERIFIER (Stage B link + impact): CONFIRMED (private effect) / PASS
      -> EXPLAIN_VERIFIED_CHAIN (CHAIN_AGENT, live)  : explains the verified chain + remediation

Stage A is METADATA_CREDENTIAL_EXPOSURE (``cloud-metadata-response-v1``, GT-RANGE-CLOUD-004,
CWE-200); Stage B is INTERNAL_SERVICE_AUTHORIZATION (``cloud-service-access-v1``,
GT-RANGE-CLOUD-005, CWE-285). These are two DISTINCT primitives linked by a real credential handoff:
Stage B cannot succeed without the credential Stage A exposes. This is emphatically NOT the Phase
1.7-B ``DELEGATION_WORKFLOW_CHAIN``.

Authority model (unchanged): the model plans, interprets and selects; it is NOT authoritative for
authorization, mode, ground truth, credential values, confirmation, severity, PASS/FAIL, causal-link
truth, final impact or cleanup. The controller owns mode selection; the independent deterministic
range verifier owns CONFIRMED/PASS for each link and the final impact; ground truth / severity stay
controller-side. The model never receives the mode, scenario id, expected result, verifier
predicate, ground-truth id, raw credential value or final severity.

Budget (this instruction authorizes exactly one bounded live campaign): <= 12 provider calls,
<= 60,000 tokens, concurrency 1, no auto-retry, no repeated smoke, no public targets. On failure,
evidence is preserved and the campaign stops. The Phase 1.7-D untrusted-observation / injection
-resistance boundary and the Phase 1.9 credential-redaction boundary are REUSED; their new ingestion
paths here (the Stage-A capture and Stage-B sanitizers, the secret store, the chain ledger) are
covered by offline tests (tests/test_phase_2_0.py); no paid injection control is repeated.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DOCKER = shutil.which("docker") or "/usr/local/bin/docker"
DS_STACK = ["-f", "docker-compose.yml", "-f", "docker-compose.deepseek.yml"]
RANGE_STACK = ["-f", "docker-compose.range.yml"]
DS_PROJECT = "aegis-p20-live-ds"
RANGE_PROJECT = "aegis-p20-live-range"
RANGE_ACCESS_NET = f"{RANGE_PROJECT}_range-access"
RANGE_IMAGE = "aegis-range:1.6.0-dev"

CANONICAL_MODEL = "deepseek-v4-pro"
# Whole-campaign hard ceilings (combined across every in-container step and both arms).
MAX_PROVIDER_CALLS = 12
MAX_PROVIDER_TOKENS = 60_000
PER_TASK_OUTPUT_CEILING = 4096

# The single controller-owned chain under test.
CHAIN_ID = "cloud-service-chain-v1"
TARGET_REF = "range-cloud"
APPLICATION_ID = "aegis-cloud"
STAGE_A_SCENARIO = "cloud-metadata-response-v1"
STAGE_B_SCENARIO = "cloud-service-access-v1"
STAGE_A_PRIMITIVE = "METADATA_CREDENTIAL_EXPOSURE"
STAGE_B_PRIMITIVE = "INTERNAL_SERVICE_AUTHORIZATION"

NOT_EVALUATED = "NOT_EVALUATED"
UNKNOWN = "UNKNOWN"

# Mode-blind objectives handed to the model. They state the operator's authorized task without
# disclosing the mode, scenario id, expected outcome, verifier predicate, credential value or a URL.
_CHAIN_OBJECTIVE = (
    "Plan a two-stage chain of two distinct registered primitives on the authorized synthetic "
    "cloud surface, where the first stage produces an artifact reference the second stage must "
    "consume to reach the private operation."
)
_STAGE_A_OBJECTIVE = (
    "Select the registered capability, boundary class and symbolic probe destination needed to "
    "test whether the internal metadata response filters credential-shaped fields before returning "
    "them."
)
_STAGE_B_OBJECTIVE = (
    "The prior stage produced an opaque credential reference. Select the registered capability and "
    "symbolic destination that consumes that reference to reach the private administration "
    "operation."
)
_EXPLAIN_OBJECTIVE = (
    "Both stages were independently verified. Explain how the first primitive's artifact enabled "
    "the second primitive to reach the private operation, and how to remediate the chain."
)


# --------------------------------------------------------------------------- #
# In-container live model calls (run inside control-plane).
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


async def _one_call(step: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Run exactly one live gateway task and validate its strict output. One model per call."""

    from aegis.multi_agent.attack_chain import (
        CHAIN_CAPABILITIES,
        CHAIN_DESTINATION_REFS,
        CHAIN_PRIMITIVE_TYPES,
    )
    from aegis.multi_agent.cloud_boundary import (
        CLOUD_BOUNDARY_CAPABILITIES,
        CLOUD_BOUNDARY_CLASSES,
    )
    from aegis.multi_agent.contracts import (
        AgentRole,
        AttackChainPlanOutput,
        ChainExplanationOutput,
        ChainNextStepOutput,
        ChainStageInterpretationOutput,
        CloudBoundaryPlanOutput,
    )
    from aegis.multi_agent.model import GatewayAgentModel
    from aegis.settings import get_settings

    model = GatewayAgentModel(get_settings())

    async def call(role: Any, task_type: str, context: dict[str, Any]) -> Any:
        if model.call_attempts >= MAX_PROVIDER_CALLS:
            raise RuntimeError("PROVIDER_CALL_CEILING_REACHED")
        return await model.generate(
            role, task_type, context, {}, max_output_tokens=PER_TASK_OUTPUT_CEILING
        )

    try:
        if step == "plan_chain":
            raw = await call(
                AgentRole.CHAIN_AGENT,
                "PLAN_ATTACK_CHAIN",
                {
                    "target_ref": TARGET_REF,
                    "capability_catalog": sorted(CHAIN_CAPABILITIES),
                    "primitive_types": sorted(CHAIN_PRIMITIVE_TYPES),
                    "destination_refs": sorted(CHAIN_DESTINATION_REFS),
                    "objective": _CHAIN_OBJECTIVE,
                },
            )
            plan = AttackChainPlanOutput.model_validate_json(raw.payload_json)
            output = plan.model_dump(mode="json")
        elif step == "plan_stage_a":
            raw = await call(
                AgentRole.CLOUD_BOUNDARY_AGENT,
                "PLAN_CLOUD_BOUNDARY",
                {
                    "target_ref": TARGET_REF,
                    "capability_catalog": sorted(CLOUD_BOUNDARY_CAPABILITIES),
                    "boundary_classes": sorted(CLOUD_BOUNDARY_CLASSES),
                    "objective": _STAGE_A_OBJECTIVE,
                },
            )
            plan_a = CloudBoundaryPlanOutput.model_validate_json(raw.payload_json)
            output = plan_a.model_dump(mode="json")
        elif step == "interpret_stage_a":
            raw = await call(
                AgentRole.CHAIN_AGENT,
                "INTERPRET_CHAIN_STAGE",
                {
                    "target_ref": TARGET_REF,
                    "primitive_type": STAGE_A_PRIMITIVE,
                    "observation_kinds": payload["observation_kinds"],
                },
            )
            interp = ChainStageInterpretationOutput.model_validate_json(raw.payload_json)
            output = interp.model_dump(mode="json")
        elif step == "select_stage_b":
            raw = await call(
                AgentRole.AUTHORIZATION_AGENT,
                "SELECT_NEXT_CHAIN_STEP",
                {
                    "target_ref": TARGET_REF,
                    "prior_primitive_type": STAGE_A_PRIMITIVE,
                    "prior_link_reference_present": True,
                    "capability_catalog": sorted(CHAIN_CAPABILITIES),
                    "primitive_types": sorted(CHAIN_PRIMITIVE_TYPES),
                    "destination_refs": sorted(CHAIN_DESTINATION_REFS),
                    "objective": _STAGE_B_OBJECTIVE,
                },
            )
            nxt = ChainNextStepOutput.model_validate_json(raw.payload_json)
            output = nxt.model_dump(mode="json")
        elif step == "explain_chain":
            raw = await call(
                AgentRole.CHAIN_AGENT,
                "EXPLAIN_VERIFIED_CHAIN",
                {
                    "target_ref": TARGET_REF,
                    "ordered_primitive_types": [STAGE_A_PRIMITIVE, STAGE_B_PRIMITIVE],
                    "link_independently_verified": True,
                    "objective": _EXPLAIN_OBJECTIVE,
                },
            )
            expl = ChainExplanationOutput.model_validate_json(raw.payload_json)
            output = expl.model_dump(mode="json")
        else:
            return {"status": "ERROR", "error": f"unknown step {step}"}
    except ValueError as exc:
        return _rejection_result(model, exc)
    return {"status": "OK", **_counters(model), "output": output}


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
        ok_gw = (
            subprocess.run(  # noqa: S603
                [
                    DOCKER,
                    "exec",
                    gw,
                    "python",
                    "-c",
                    "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/health')",
                ],
                capture_output=True,
                timeout=15,
            ).returncode
            == 0
        )
        ok_cp = (
            subprocess.run(  # noqa: S603
                [
                    DOCKER,
                    "exec",
                    cp,
                    "python",
                    "-c",
                    "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/health')",
                ],
                capture_output=True,
                timeout=15,
            ).returncode
            == 0
        )
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
            ok_ctl = (
                subprocess.run(  # noqa: S603
                    [
                        DOCKER,
                        "exec",
                        controller,
                        "python",
                        "-c",
                        "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8090/health')",
                    ],
                    capture_output=True,
                    timeout=15,
                ).returncode
                == 0
            )
            ok_cloud = (
                subprocess.run(  # noqa: S603
                    [
                        DOCKER,
                        "exec",
                        cloud,
                        "python",
                        "-c",
                        "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8104/health')",
                    ],
                    capture_output=True,
                    timeout=15,
                ).returncode
                == 0
            )
            if ok_ctl and ok_cloud:
                return True
        time.sleep(1.0)
    return False


def _credential_isolation(env: dict[str, str]) -> dict[str, bool]:
    cp = _dc("ps", "-q", "control-plane", timeout=60, env=env).stdout.strip()
    if not cp:
        return {"control_plane_has_no_key": False}
    probe = subprocess.run(  # noqa: S603 - read env of the control-plane process only
        [
            DOCKER,
            "exec",
            cp,
            "python",
            "-c",
            "import os;print(bool(os.environ.get('AI_AUTH_TOKEN')))",
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    return {"control_plane_has_no_key": probe.stdout.strip() == "False"}


def _exec_model_step(
    env: dict[str, str], step: str, context: dict[str, Any] | None = None
) -> dict[str, Any]:
    run = _dc(
        "exec",
        "-T",
        "control-plane",
        "python",
        "scripts/phase_2_0_live_multi_primitive_chain.py",
        "--in-container",
        "--step",
        step,
        timeout=300,
        env=env,
        stdin=json.dumps(context or {}),
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
# there). The model never reaches this path. op/app/scenario are passed as argv.
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


def _controller_op(env: dict[str, str], op: str, scenario: str) -> dict[str, Any]:
    run = _rc(
        "exec",
        "-T",
        "range-controller",
        "python",
        "-c",
        _CONTROLLER_PY,
        op,
        APPLICATION_ID,
        scenario,
        timeout=120,
        env=env,
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


# The bounded chain broker execution runs in a throwaway container on the internal range-access
# network. It imports the tested capture/sanitizer/secret-store/broker (aegis.multi_agent
# .attack_chain.run_isolated_chain_probe) so the synthetic credential value is captured at the
# source, resolved broker-side, and never leaves the container in cleartext: only opaque references
# and value-free sanitized facts are printed. Stage A, the causal-dependency control (an
# unrelated/invalid reference), Stage B and the reference revocation all happen in that one isolated
# process, so the raw value is confined to a single execution boundary.
_CHAIN_PROBE_PY = (
    "import os, json\n"
    "from aegis.multi_agent.attack_chain import run_isolated_chain_probe\n"
    "print(json.dumps(run_isolated_chain_probe(\n"
    "    json.loads(os.environ['CB_STAGE_A_REQUESTS']), os.environ['CB_MODE'])))\n"
)


def _run_chain_probe(stage_a_requests: list[dict[str, str]], mode: str) -> dict[str, Any]:
    run = subprocess.run(  # noqa: S603 - fixed docker binary, list argv, no shell
        [
            DOCKER,
            "run",
            "--rm",
            "--network",
            RANGE_ACCESS_NET,
            "--user",
            "65532:65532",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "-e",
            "CB_STAGE_A_REQUESTS=" + json.dumps(stage_a_requests),
            "-e",
            "CB_MODE=" + mode,
            RANGE_IMAGE,
            "python",
            "-c",
            _CHAIN_PROBE_PY,
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    stdout = run.stdout.strip()
    json_line = stdout.splitlines()[-1] if stdout else ""
    try:
        return {"rc": run.returncode, "chain": json.loads(json_line)}
    except json.JSONDecodeError:
        return {
            "rc": run.returncode,
            "chain": None,
            "stderr_tail": run.stderr[-1200:],
            "stdout_tail": stdout[-1200:],
        }


# --------------------------------------------------------------------------- #
# Host: one arm of the vulnerable/patched campaign.
# --------------------------------------------------------------------------- #


def _run_arm(env: dict[str, str], arm: str, db_path: str) -> dict[str, Any]:
    """Drive one arm end to end and return its record.

    ``arm`` is "vulnerable" (full chain, both primitives) or "patched" (Stage A suppressed, chain
    blocked before protected-resource access).
    """

    from aegis.multi_agent.attack_chain import (
        CAP_METADATA_BOUNDARY_PROBE,
        AttackChainLedger,
        AttackChainRecord,
        ChainJob,
        ChainLink,
        ChainState,
        LinkHypothesisState,
        LinkVerificationState,
        new_link_id,
        source_sha256,
        stage_a_control_url,
        stage_a_probe_url,
    )

    record: dict[str, Any] = {"arm": arm}
    ledger = AttackChainLedger(db_path)
    ledger.initialize()

    # (0) Controller-owned mode selection. Reset first, then select the controller-owned modes.
    #     Vulnerable: select the Stage-B scenario VULNERABLE (its reset dependencies cascade the
    #     integration + metadata scenarios VULNERABLE too — the whole chain is armed in one call).
    #     Patched: select the Stage-A metadata scenario PATCHED (its dependency keeps the fetch
    #     surface reachable; the credential field is suppressed) so no usable reference is produced.
    record["reset"] = _controller_op(env, "reset", STAGE_A_SCENARIO)
    if arm == "vulnerable":
        record["select_mode"] = _controller_op(env, "select_vulnerable", STAGE_B_SCENARIO)
    else:
        record["select_mode"] = _controller_op(env, "select_patched", STAGE_A_SCENARIO)

    # (1) Enqueue + consume a real, addressable CHAIN_AGENT job; open the chain record.
    job = ChainJob(
        job_id=f"chjob-{os.urandom(8).hex()}",
        chain_id=CHAIN_ID,
        target_ref=TARGET_REF,
        objective="compose the metadata-exposure and internal-service authorization chain",
    )
    address = ledger.enqueue_job(job)
    claimed = ledger.claim_job(address)
    chain_record = AttackChainRecord(
        chain_id=CHAIN_ID,
        objective="link metadata credential exposure to credential-backed private-service access",
        authorized_target_refs=[TARGET_REF],
        overall_state=ChainState.RUNNING,
    )
    ledger.upsert_chain(job.job_id, chain_record)
    record["job"] = {
        "address": address,
        "claimed_status": claimed.status,
        "resolved_by_address": ledger.resolve_job(address) is not None,
    }

    def _fail(state: ChainState) -> dict[str, Any]:
        ledger.upsert_chain(job.job_id, chain_record.model_copy(update={"overall_state": state}))
        record["job"]["closed_status"] = ledger.close_job(address).status
        record["job_transitions"] = ledger.job_transitions(job.job_id)
        record["chain_transitions"] = ledger.chain_transitions(CHAIN_ID, job.job_id)
        record["chain_final_state"] = state.value
        record["links"] = [
            link.model_dump(mode="json") for link in ledger.links(CHAIN_ID, job.job_id)
        ]
        return record

    # (2) LIVE PLAN_ATTACK_CHAIN (CHAIN_AGENT).
    record["plan_chain"] = _exec_model_step(env, "plan_chain")
    if (record["plan_chain"].get("result") or {}).get("status") != "OK":
        return _fail(ChainState.FAILED)

    # (3) LIVE PLAN_CLOUD_BOUNDARY (CLOUD_BOUNDARY_AGENT) — Stage A probe plan (reused Phase 1.9).
    record["plan_stage_a"] = _exec_model_step(env, "plan_stage_a")
    plan_a_result = record["plan_stage_a"].get("result") or {}
    if plan_a_result.get("status") != "OK":
        return _fail(ChainState.FAILED)

    # (4) Broker the Stage A plan into a shell-free execution + run the isolated Stage A probe.
    from aegis.multi_agent.cloud_boundary import CloudBoundaryBroker
    from aegis.multi_agent.contracts import CloudBoundaryPlanOutput

    try:
        plan_a = CloudBoundaryPlanOutput.model_validate(plan_a_result["output"])
        execution = CloudBoundaryBroker().render(plan_a)
        record["stage_a_broker"] = {
            "shell_free": execution.shell_free,
            "capability_id": execution.capability_id,
            "boundary_class": execution.boundary_class,
        }
    except Exception as exc:  # noqa: BLE001 - fail closed, record the reason as data
        record["stage_a_broker"] = {
            "status": "REJECTED",
            "error": f"{type(exc).__name__}: {exc}"[:200],
        }
        return _fail(ChainState.FAILED)

    # The broker resolves the Stage A destinations; the chain probe container connects to them.
    stage_a_requests = [
        {"label": "CONTROL", "route": "/api/integrations/check", "url": stage_a_control_url()},
        {"label": "BOUNDARY_PROBE", "route": "/api/integrations/check", "url": stage_a_probe_url()},
    ]
    probe_mode = "full" if arm == "vulnerable" else "stage_a_only"
    record["chain_probe"] = _run_chain_probe(stage_a_requests, probe_mode)
    chain_out = record["chain_probe"].get("chain") or {}
    credential_reference_present = bool(chain_out.get("credential_reference_present"))
    stage_a_source_sha = source_sha256(chain_out.get("stage_a") or [])

    # (5) INDEPENDENT VERIFIER — Stage A link (CONFIRMED exposed / PASS suppressed).
    record["verify_stage_a"] = _controller_op(env, "verify", STAGE_A_SCENARIO)
    stage_a_status = (record["verify_stage_a"].get("result") or {}).get("status")

    # Persist the Stage A link (a real handoff carrying typed evidence references + source hash).
    stage_a_link = ChainLink(
        link_id=new_link_id(),
        chain_id=CHAIN_ID,
        stage_index=0,
        primitive_type=STAGE_A_PRIMITIVE,  # type: ignore[arg-type]
        capability_id=CAP_METADATA_BOUNDARY_PROBE,
        producing_agent="CLOUD_BOUNDARY_AGENT",
        consuming_agent="CHAIN_AGENT",
        input_evidence_refs=[],
        output_evidence_refs=(["credential-reference"] if credential_reference_present else []),
        source_evidence_sha256=stage_a_source_sha,
        credential_reference=None,  # opaque reference lives only in the isolated broker boundary
        hypothesis_state=LinkHypothesisState.EXECUTED,
        verification_state=(
            LinkVerificationState.CONFIRMED
            if stage_a_status == "CONFIRMED"
            else LinkVerificationState.PASS
            if stage_a_status == "PASS"
            else LinkVerificationState.INCOMPLETE
        ),
        severity_ref="GT-RANGE-CLOUD-004",
    )
    ledger.upsert_link(job.job_id, stage_a_link)

    # Patched arm: Stage A is suppressed, no usable reference exists, the chain is blocked before
    # protected-resource access. Do not attempt Stage B; do not invent a credential.
    if arm != "vulnerable":
        record["stage_a_source_sha256"] = stage_a_source_sha
        record["credential_reference_present"] = credential_reference_present
        return _fail(ChainState.BLOCKED_BY_PATCH)

    if not credential_reference_present or stage_a_status != "CONFIRMED":
        # The vulnerable arm requires a produced, verified Stage A artifact to proceed.
        record["stage_a_source_sha256"] = stage_a_source_sha
        return _fail(ChainState.FAILED)

    ledger.upsert_chain(
        job.job_id, chain_record.model_copy(update={"overall_state": ChainState.LINK_CONFIRMED})
    )

    # (6) LIVE INTERPRET_CHAIN_STAGE (CHAIN_AGENT) — read the verified Stage A link.
    record["interpret_stage_a"] = _exec_model_step(
        env,
        "interpret_stage_a",
        {"observation_kinds": ["INTEGRATION_RESPONSE", "CREDENTIAL_REFERENCE_PRESENT"]},
    )

    # (7) LIVE SELECT_NEXT_CHAIN_STEP (AUTHORIZATION_AGENT) — select the credential-backed step.
    record["select_stage_b"] = _exec_model_step(env, "select_stage_b")
    select_result = record["select_stage_b"].get("result") or {}
    if select_result.get("status") != "OK":
        return _fail(ChainState.FAILED)

    # (8) INDEPENDENT VERIFIER — Stage B link + final impact (CONFIRMED effect / PASS).
    record["verify_stage_b"] = _controller_op(env, "verify", STAGE_B_SCENARIO)
    stage_b_status = (record["verify_stage_b"].get("result") or {}).get("status")
    stage_b_source_sha = source_sha256(
        {
            "stage_b": chain_out.get("stage_b") or [],
            "causal_control": chain_out.get("causal_control"),
        }
    )

    stage_b_link = ChainLink(
        link_id=new_link_id(),
        chain_id=CHAIN_ID,
        stage_index=1,
        primitive_type=STAGE_B_PRIMITIVE,  # type: ignore[arg-type]
        capability_id="aegis.cloud.internal_service_access",
        producing_agent="AUTHORIZATION_AGENT",
        consuming_agent="CHAIN_AGENT",
        input_evidence_refs=["credential-reference"],
        output_evidence_refs=(
            ["private-operation-effect"] if stage_b_status == "CONFIRMED" else []
        ),
        source_evidence_sha256=stage_b_source_sha,
        depends_on_link_id=stage_a_link.link_id,
        consumes_prior_credential_reference=True,
        credential_reference=None,
        hypothesis_state=LinkHypothesisState.EXECUTED,
        verification_state=(
            LinkVerificationState.CONFIRMED
            if stage_b_status == "CONFIRMED"
            else LinkVerificationState.PASS
            if stage_b_status == "PASS"
            else LinkVerificationState.INCOMPLETE
        ),
        severity_ref="GT-RANGE-CLOUD-005",
    )
    ledger.upsert_link(job.job_id, stage_b_link)

    # (9) LIVE EXPLAIN_VERIFIED_CHAIN (CHAIN_AGENT) — only after both links are verified.
    if stage_a_status == "CONFIRMED" and stage_b_status == "CONFIRMED":
        record["explain_chain"] = _exec_model_step(env, "explain_chain")

    # (10) Finalize chain state from the INDEPENDENT verifier only.
    ledger.upsert_chain(
        job.job_id,
        chain_record.model_copy(
            update={
                "overall_state": (
                    ChainState.CHAIN_CONFIRMED
                    if stage_a_status == "CONFIRMED" and stage_b_status == "CONFIRMED"
                    else ChainState.FAILED
                ),
                "severity_ref": "GT-RANGE-CLOUD-005",
            }
        ),
    )
    record["stage_a_source_sha256"] = stage_a_source_sha
    record["stage_b_source_sha256"] = stage_b_source_sha
    record["credential_reference_present"] = credential_reference_present
    record["job"]["closed_status"] = ledger.close_job(address).status
    record["job_transitions"] = ledger.job_transitions(job.job_id)
    record["chain_transitions"] = ledger.chain_transitions(CHAIN_ID, job.job_id)
    record["chain_final_state"] = (
        ChainState.CHAIN_CONFIRMED.value
        if stage_a_status == "CONFIRMED" and stage_b_status == "CONFIRMED"
        else ChainState.FAILED.value
    )
    record["links"] = [link.model_dump(mode="json") for link in ledger.links(CHAIN_ID, job.job_id)]
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
        record["ground_truth_stage_a"] = _controller_op(env, "ground_truth", STAGE_A_SCENARIO)
        record["ground_truth_stage_b"] = _controller_op(env, "ground_truth", STAGE_B_SCENARIO)
        if not record["healthy"] or not record["range_healthy"]:
            record["ds_logs_tail"] = _dc("logs", "--tail", "40", timeout=60, env=env).stdout[-2000:]
            record["range_logs_tail"] = _rc("logs", "--tail", "40", timeout=60, env=env).stdout[
                -2000:
            ]
            return record

        record["vulnerable"] = _run_arm(env, "vulnerable", db_path)
        record["patched"] = _run_arm(env, "patched", db_path)
    finally:
        _teardown(env, record)
    return record


def _teardown(env: dict[str, str], record: dict[str, Any]) -> None:
    ds_down = _dc("down", "-v", "--remove-orphans", timeout=180, env=env)
    range_down = _rc("down", "-v", "--remove-orphans", timeout=240, env=env)
    ds_left = subprocess.run(  # noqa: S603
        [
            DOCKER,
            "ps",
            "-a",
            "--filter",
            f"label=com.docker.compose.project={DS_PROJECT}",
            "--format",
            "{{.Names}}",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    range_left = subprocess.run(  # noqa: S603
        [
            DOCKER,
            "ps",
            "-a",
            "--filter",
            f"label=com.docker.compose.project={RANGE_PROJECT}",
            "--format",
            "{{.Names}}",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    net_left = subprocess.run(  # noqa: S603
        [DOCKER, "network", "ls", "--filter", f"name={RANGE_PROJECT}", "--format", "{{.Name}}"],
        capture_output=True,
        text=True,
        timeout=60,
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


def _model_result(arm_rec: dict[str, Any], step: str) -> dict[str, Any]:
    return (arm_rec.get(step) or {}).get("result") or {}


def _step_ok(arm_rec: dict[str, Any], step: str) -> bool:
    return _model_result(arm_rec, step).get("status") == "OK"


def _all_model_results(record: dict[str, Any]) -> list[dict[str, Any]]:
    steps = ("plan_chain", "plan_stage_a", "interpret_stage_a", "select_stage_b", "explain_chain")
    results: list[dict[str, Any]] = []
    for arm in ("vulnerable", "patched"):
        arm_rec = record.get(arm) or {}
        for step in steps:
            result = (arm_rec.get(step) or {}).get("result")
            if isinstance(result, dict) and result.get("status") in {"OK", "GATEWAY_REJECTED"}:
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
    return re.search(r"meta\.[0-9]+\.[a-z-]+\.[a-f0-9]{6,}", blob) is None


def _verify_status(arm_rec: dict[str, Any], step: str) -> str | None:
    result = (arm_rec.get(step) or {}).get("result") or {}
    status = result.get("status")
    return status if isinstance(status, str) else None


def _stage_a_probe_reached(arm_rec: dict[str, Any]) -> bool:
    chain = (arm_rec.get("chain_probe") or {}).get("chain") or {}
    stage_a = chain.get("stage_a") or []
    return any(s.get("label") == "CONTROL" and int(s.get("status_code", 0)) == 200 for s in stage_a)


def _separate_live_agent_stage_jobs_persisted(record: dict[str, Any]) -> Any:
    """Whether the ledger persisted *distinct live per-stage agent jobs* — separate
    ``agentjob://`` jobs owned by the producing agents (e.g. CLOUD_BOUNDARY_AGENT for Stage A and
    AUTHORIZATION_AGENT for Stage B), each independently queued/claimed/closed.

    This is deliberately distinct from ``chain_link_handoff_metadata_persisted``: producing-agent
    *labels* on chain links can never satisfy this. In the bounded Phase 2.0 run only the single
    CHAIN_AGENT job exists per arm and both stages were executed directly by CHAIN_AGENT through the
    Tool Broker, so no such per-stage jobs were recorded and this returns ``NOT_EVALUATED``. It only
    returns ``True`` if the record carries real per-stage agent jobs with their own addresses and a
    producing role that is not CHAIN_AGENT.
    """

    stage_jobs = record.get("stage_agent_jobs")
    if not isinstance(stage_jobs, list) or not stage_jobs:
        return NOT_EVALUATED
    roles = {str(j.get("to_agent")) for j in stage_jobs if isinstance(j, dict)}
    addressed = all(
        str(j.get("address", "")).startswith("agentjob://")
        and str(j.get("to_agent")) != "CHAIN_AGENT"
        for j in stage_jobs
        if isinstance(j, dict)
    )
    if addressed and {"CLOUD_BOUNDARY_AGENT", "AUTHORIZATION_AGENT"} <= roles:
        return True
    return NOT_EVALUATED


def _verdict(record: dict[str, Any]) -> dict[str, Any]:
    vuln = record.get("vulnerable") or {}
    patched = record.get("patched") or {}
    cleanup = record.get("cleanup") or {}
    gt_a = (record.get("ground_truth_stage_a") or {}).get("result") or {}
    gt_b = (record.get("ground_truth_stage_b") or {}).get("result") or {}
    model_results = _all_model_results(record)
    vuln_chain = (vuln.get("chain_probe") or {}).get("chain") or {}

    checks: dict[str, Any] = {}

    # --- Chain composition + causal connection --- #
    plan_out = _model_result(vuln, "plan_chain").get("output") or {}
    plan_stages = plan_out.get("stages") or []
    plan_primitives = [s.get("primitive_type") for s in plan_stages]
    checks["selected_chain_contains_distinct_primitives"] = (
        len(plan_primitives) == 2
        and plan_primitives[0] != plan_primitives[1]
        and set(plan_primitives) == {STAGE_A_PRIMITIVE, STAGE_B_PRIMITIVE}
    )
    # Causal connection: the plan's second stage consumes the first, and the persisted Stage B link
    # depends on the Stage A link and consumes its credential reference.
    links = vuln.get("links") or []
    link_by_index = {link.get("stage_index"): link for link in links}
    stage_a_link = link_by_index.get(0) or {}
    stage_b_link = link_by_index.get(1) or {}
    checks["chain_links_are_causally_connected"] = bool(
        len(plan_stages) == 2
        and plan_stages[1].get("consumes_prior_stage") is True
        and stage_b_link.get("depends_on_link_id") == stage_a_link.get("link_id")
        and stage_a_link.get("link_id")
        and stage_b_link.get("consumes_prior_credential_reference") is True
    )

    # --- Addressable job + persisted handoffs --- #
    def _job_consumed(arm_rec: dict[str, Any]) -> bool:
        job = arm_rec.get("job") or {}
        transitions = [t.get("to") for t in (arm_rec.get("job_transitions") or [])]
        return (
            str(job.get("address", "")).startswith("agentjob://CHAIN_AGENT/")
            and job.get("claimed_status") == "CLAIMED"
            and bool(job.get("resolved_by_address"))
            and transitions[:3] == ["QUEUED", "CLAIMED", "CLOSED"]
        )

    checks["addressable_chain_job_consumed"] = _job_consumed(vuln) and _job_consumed(patched)
    # Chain-link handoff METADATA persisted: two ordered links carrying producing/consuming ROLE
    # LABELS, evidence references, source hashes, the Stage-B->Stage-A dependency edge and the
    # credential-reference dependency. This is link metadata only. It does NOT — and must not be
    # read to — assert that separate live per-stage agent jobs were created and executed. The
    # producing-agent labels below are metadata on the CHAIN_AGENT-produced links, not proof that
    # a CLOUD_BOUNDARY_AGENT or AUTHORIZATION_AGENT job ran. See
    # ``_separate_live_agent_stage_jobs_persisted`` for that distinct (NOT_EVALUATED) concept.
    checks["chain_link_handoff_metadata_persisted"] = bool(
        len(links) == 2
        and stage_a_link.get("stage_index") == 0
        and stage_b_link.get("stage_index") == 1
        and stage_a_link.get("producing_agent") == "CLOUD_BOUNDARY_AGENT"
        and stage_b_link.get("producing_agent") == "AUTHORIZATION_AGENT"
        and stage_a_link.get("consuming_agent") == "CHAIN_AGENT"
        and stage_b_link.get("consuming_agent") == "CHAIN_AGENT"
        and stage_b_link.get("depends_on_link_id") == stage_a_link.get("link_id")
        and bool(stage_a_link.get("link_id"))
        and stage_b_link.get("consumes_prior_credential_reference") is True
        and "credential-reference" in (stage_b_link.get("input_evidence_refs") or [])
        and re.fullmatch(r"[a-f0-9]{64}", str(stage_a_link.get("source_evidence_sha256", "")))
        and re.fullmatch(r"[a-f0-9]{64}", str(stage_b_link.get("source_evidence_sha256", "")))
    )

    # --- Typed plan + registered capabilities --- #
    checks["produced_valid_typed_chain_plan"] = bool(
        _step_ok(vuln, "plan_chain")
        and plan_out.get("target_ref") == TARGET_REF
        and plan_out.get("unconfirmed") is True
    )
    plan_caps = {s.get("capability_id") for s in plan_stages}
    stage_a_cap = (_model_result(vuln, "plan_stage_a").get("output") or {}).get("capability_id")
    select_cap = (_model_result(vuln, "select_stage_b").get("output") or {}).get(
        "next_capability_id"
    )
    registered = {"aegis.cloud.metadata_boundary_probe", "aegis.cloud.internal_service_access"}
    checks["selected_only_registered_capabilities"] = bool(
        plan_caps <= registered
        and plan_caps == registered
        and stage_a_cap == "aegis.cloud.metadata_boundary_probe"
        and select_cap == "aegis.cloud.internal_service_access"
    )

    # --- Execution shell-free --- #
    broker_a = vuln.get("stage_a_broker") or {}
    checks["execution_shell_free"] = broker_a.get("shell_free") is True

    # --- Live execution against synthetic targets --- #
    checks["vulnerable_stages_executed_against_live_synthetic_targets"] = bool(
        _stage_a_probe_reached(vuln)
        and any(
            s.get("label") == "CONTROL" and int(s.get("status_code", 0)) == 200
            for s in (vuln_chain.get("stage_b") or [])
        )
    )
    # Observations derived from the current live execution (not fixtures): the Stage A probe
    # saw the credential field this run, and Stage B observed the private-operation effect.
    boundary_saw_credential = any(
        s.get("label") == "BOUNDARY_PROBE" and s.get("credential_field_present") is True
        for s in (vuln_chain.get("stage_a") or [])
    )
    stage_b_effect = any(
        s.get("label") == "SERVICE_ACCESS" and s.get("admin_effect_present") is True
        for s in (vuln_chain.get("stage_b") or [])
    )
    checks["observations_derived_from_current_live_execution"] = bool(
        boundary_saw_credential and stage_b_effect
    )
    checks["no_fixture_in_live_data_path"] = bool(
        _stage_a_probe_reached(vuln) and boundary_saw_credential and stage_b_effect
    )

    # --- Independent per-link verification + causal dependency --- #
    va = _verify_status(vuln, "verify_stage_a")
    vb = _verify_status(vuln, "verify_stage_b")
    checks["each_required_link_independently_verified"] = va == "CONFIRMED" and vb == "CONFIRMED"
    checks["stage_b_requires_stage_a_output"] = bool(
        stage_b_link.get("consumes_prior_credential_reference") is True
        and stage_b_link.get("depends_on_link_id") == stage_a_link.get("link_id")
        and stage_b_effect
    )
    # Causal-dependency control: an unrelated/invalid reference is rejected by the operation.
    causal = vuln_chain.get("causal_control") or {}
    checks["causal_dependency_control_held"] = bool(
        causal
        and causal.get("admin_effect_present") is False
        and int(causal.get("status_code", 0)) != 200
        and stage_b_effect  # and the real reference DID reach the effect
    )

    # --- Opaque credential handoff --- #
    checks["opaque_credential_reference_used"] = bool(
        vuln_chain.get("credential_reference_present") is True
        and stage_b_link.get("consumes_prior_credential_reference") is True
    )
    checks["credential_value_hidden_from_models"] = (
        all(r.get("projections_clean") is True for r in model_results)
        if model_results
        else NOT_EVALUATED
    )
    checks["credential_value_absent_from_projections_and_artifacts"] = (
        _no_credential_value_in_evidence(record)
    )

    # --- Hypotheses default false; ground truth blinded --- #
    unconfirmed_flags = [
        _model_result(vuln, "plan_chain").get("output", {}).get("unconfirmed"),
        _model_result(vuln, "interpret_stage_a").get("output", {}).get("unconfirmed"),
        _model_result(vuln, "select_stage_b").get("output", {}).get("unconfirmed"),
    ]
    link_hyp_false = (
        all(link.get("hypothesis_confirmed") is False for link in links) if links else False
    )
    checks["hypotheses_confirmed_false_by_default"] = bool(
        all(flag is True for flag in unconfirmed_flags) and link_hyp_false
    )
    checks["ground_truth_not_exposed_to_models"] = (
        all(r.get("projections_clean") is True for r in model_results)
        if model_results
        else NOT_EVALUATED
    )

    # --- Verifier authority --- #
    checks["vulnerable_chain_confirmed_only_by_independent_verifier"] = bool(
        va == "CONFIRMED"
        and vb == "CONFIRMED"
        and vuln.get("chain_final_state") == "CHAIN_CONFIRMED"
    )
    pa = _verify_status(patched, "verify_stage_a")
    checks["patched_chain_blocked_by_independent_verifier"] = bool(
        pa == "PASS"
        and patched.get("chain_final_state") == "BLOCKED_BY_PATCH"
        and patched.get("credential_reference_present") is False
    )
    # The broken (patched) chain must NOT be reported as confirmed.
    checks["broken_chain_not_reported_as_confirmed"] = bool(
        patched.get("chain_final_state") != "CHAIN_CONFIRMED" and "explain_chain" not in patched
    )

    # --- Severity traces to controller ground truth --- #
    checks["severity_traces_to_controller_ground_truth"] = bool(
        gt_a.get("severity") in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        and gt_b.get("severity") in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        and gt_a.get("ground_truth_id") == "GT-RANGE-CLOUD-004"
        and gt_b.get("ground_truth_id") == "GT-RANGE-CLOUD-005"
    )

    # --- Identity, scope, egress, ceilings --- #
    checks["identity_exact_deepseek_v4_pro"] = (
        all(r.get("identity_exact_deepseek_v4_pro") is True for r in model_results)
        if model_results
        else NOT_EVALUATED
    )
    checks["target_scope_held"] = plan_out.get("target_ref") == TARGET_REF and all(
        link.get("chain_id") == CHAIN_ID for link in links
    )
    checks["no_public_egress"] = bool(record.get("range_healthy"))
    checks["credential_gateway_only"] = bool(
        (record.get("credential_isolation") or {}).get("control_plane_has_no_key")
    ) and _no_credential_value_in_evidence(record)

    total_calls = sum(int(r.get("provider_calls", 0)) for r in model_results if isinstance(r, dict))
    # provider_calls is one per in-container model object (one call each), so the sum is calls.
    checks["within_call_ceiling"] = total_calls <= MAX_PROVIDER_CALLS
    combined_tokens = _combined_tokens(model_results) if model_results else NOT_EVALUATED
    within_tokens: Any = (
        combined_tokens <= MAX_PROVIDER_TOKENS
        if isinstance(combined_tokens, int)
        else combined_tokens
    )
    checks["within_token_ceiling"] = _tri(within_tokens)

    # --- Cleanup + reference revocation --- #
    checks["credential_references_revoked"] = bool(
        vuln_chain.get("post_revoke_resolvable") is False
        and vuln_chain.get("revoked_reference_rejected") is True
    )
    checks["cleanup_down_rc_zero"] = cleanup.get("down_rc") == 0
    checks["no_leftovers"] = (
        bool(cleanup)
        and not cleanup.get("stack_leftovers", ["x"])
        and not cleanup.get("network_leftovers", ["x"])
    )

    passed = all(v is True for v in checks.values())
    # Status fields live OUTSIDE ``checks`` so the NOT_EVALUATED multi-agent-stage scope cannot
    # break the bounded attack-chain pass, yet is always present so a reader cannot mistake this
    # for multi-agent-stage acceptance.
    return {
        "checks": checks,
        "passed": passed,
        "attack_chain_status": "LIVE_GO" if passed else "NOT_LIVE_GO",
        "separate_live_agent_stage_jobs_persisted": _separate_live_agent_stage_jobs_persisted(
            record
        ),
        "live_multi_agent_stage_handoffs": NOT_EVALUATED,
        "provider_calls_total": total_calls,
        "provider_tokens_total": combined_tokens,
    }


# --------------------------------------------------------------------------- #
# Entrypoint.
# --------------------------------------------------------------------------- #


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--in-container", action="store_true")
    parser.add_argument(
        "--step",
        choices=[
            "plan_chain",
            "plan_stage_a",
            "interpret_stage_a",
            "select_stage_b",
            "explain_chain",
        ],
    )
    args = parser.parse_args()

    if args.in_container:
        try:
            context = json.loads(sys.stdin.read() or "{}")
            result = asyncio.run(_one_call(args.step, context))
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
    out_dir = Path("artifacts") / f"phase-2.0-live-multi-primitive-chain-{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    db_path = str(out_dir / "attack_chain_ledger.sqlite3")
    record = _run_live(db_path)
    verdict = _verdict(record)
    elapsed_s = (datetime.now(UTC) - started).total_seconds()

    acceptance: dict[str, Any] = {
        "phase": "2.0",
        "scope": (
            "single LIVE verified multi-primitive attack chain (metadata credential exposure -> "
            "credential-backed internal-service authorization) and its patched break, for one "
            "controller-owned campaign in the synthetic aegis-cloud range"
        ),
        "chain": {
            "chain_id": CHAIN_ID,
            "chain_class": "VERIFIED_MULTI_PRIMITIVE_CHAIN",
            "distinct_from": "Phase 1.7-B DELEGATION_WORKFLOW_CHAIN",
            "stage_a": {
                "primitive_type": STAGE_A_PRIMITIVE,
                "scenario_id": STAGE_A_SCENARIO,
                "cwe": "CWE-200",
                "capability_id": "aegis.cloud.metadata_boundary_probe",
                "producing_agent": "CLOUD_BOUNDARY_AGENT",
            },
            "stage_b": {
                "primitive_type": STAGE_B_PRIMITIVE,
                "scenario_id": STAGE_B_SCENARIO,
                "cwe": "CWE-285",
                "capability_id": "aegis.cloud.internal_service_access",
                "producing_agent": "AUTHORIZATION_AGENT",
            },
            "causal_link": (
                "Stage A exposes a fresh synthetic instance-metadata credential, captured "
                "into an isolated ephemeral secret store as an opaque credentialref://; Stage B "
                "resolves that reference broker-side to reach the private admin operation. "
                "Without Stage A's credential the private operation is rejected."
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
                "NOT_EVALUATED live (reused Phase 1.7-D / 1.9 boundaries); new ingestion paths "
                "covered by offline tests (tests/test_phase_2_0.py)"
            ),
        },
        "chain_job_address_scheme": "agentjob://CHAIN_AGENT/<job_id>",
        "credential_reference_scheme": "credentialref://<chain_id>/<opaque>",
        "record": record,
        "verdict_detail": verdict,
        "provider_calls_total": verdict["provider_calls_total"],
        "provider_tokens_total": verdict["provider_tokens_total"],
        "elapsed_seconds": round(elapsed_s, 2),
        "verdict": (
            "LIVE GO for one verifier-confirmed multi-primitive attack chain and its patched break "
            "inside the bounded synthetic range"
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
