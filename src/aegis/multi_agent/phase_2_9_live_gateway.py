"""Phase 2.9 — isolated LIVE model-gateway adapter and campaign orchestrator.

This module supplies the *real* provider path for the single Phase 2.9 consolidated campaign while
leaving the deterministic dry-run path (:class:`aegis.multi_agent.consolidated_campaign.\
Phase29ModelDouble`) completely untouched. It reuses the already-proven isolated gateway topology
(Phase 2.2 / 2.3): the DeepSeek credential lives ONLY in the ``llm-gateway`` compose service, the
five typed model steps are executed from the *control-plane* side of the internal ``planner-rpc``
network, and every task context crosses into the control-plane container as bounded stdin JSON —
never through argv, shell interpolation or an environment variable.

The three seams are all injectable so the whole path can be exercised with mocked HTTP/compose
boundaries and **without any real docker daemon or provider call**:

* :class:`Phase29GatewayStack` — owns the uniquely-named DeepSeek gateway compose stack (build, up,
  health, credential-isolation proof, one stdin-JSON model step per call, unconditional teardown).
* :class:`Phase29LiveGatewayModel` — the live model adapter behind the *same* logical interface the
  double implements (``name`` / ``reported_models`` / ``attempts`` / ``generate``). It sanitizes the
  projection before dispatch, validates the returned identity is exactly ``deepseek-v4-pro`` and
  fails closed (no retry, no repair, no fallback) on any rejection.
* :func:`run_live_campaign` — wires one gateway stack + one :class:`ConsolidatedOpsCampaign` with
  the live adapter, enforces the same :class:`CampaignProviderBudget`, and tears both stacks down
  unconditionally for success, gateway failure, invalid output, budget stop, model mismatch,
  verifier/target failure, exception and cancellation.

Nothing in this module makes a provider call by itself; a real paid run is the separate, explicitly
authorized invocation of ``scripts/phase_2_9_consolidated_acceptance.py --execute-live``.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis.multi_agent.consolidated_campaign import (
    CANONICAL_MODEL,
    PER_CALL_OUTPUT_CEILING,
    ConsolidatedOpsCampaign,
    build_evidence_accounting,
    build_phase_2_9_checks,
    build_typed_verdicts,
    is_live_armed,
    write_campaign_artifacts,
)
from aegis.multi_agent.contracts import AgentRole, ModelResult, ModelUsage
from aegis.multi_agent.live_safety import LiveExecutionRequest

NOT_EVALUATED = "NOT_EVALUATED"
UNKNOWN = "UNKNOWN"

DOCKER = shutil.which("docker") or "/usr/local/bin/docker"
# The DeepSeek external-provider profile: base topology + the isolated gateway/proxy overlay.
DS_STACK = ("-f", "docker-compose.yml", "-f", "docker-compose.deepseek.yml")
CONTROL_PLANE_SERVICE = "control-plane"
GATEWAY_SERVICE = "llm-gateway"
EGRESS_PROXY_SERVICE = "egress-proxy"
# Per-call output ceiling passed to the gateway (it clamps again provider-side).
PER_CALL_OUTPUT_TOKENS = PER_CALL_OUTPUT_CEILING


# --------------------------------------------------------------------------- #
# Pre-dispatch projection safety.
# --------------------------------------------------------------------------- #

# A projection key whose lowercased name contains any of these is a forbidden category leaking into
# model input. Descriptive labels (e.g. a ``salient`` observation kind) are not keys and are checked
# only for secret-shaped *values* below, so a benign label like "alternate_reached_sentinel" passes.
_FORBIDDEN_KEY_SUBSTRINGS = (
    "auth_token",
    "api_key",
    "apikey",
    "password",
    "credential",
    "secret",
    "sentinel_digest",
    "ground_truth",
    "expected_outcome",
    "expected_mode",
    "pass_fail",
    "severity",
    "authoritative_verdict",
    "raw_header",
    "raw_payload",
    "response_body",
    "cookie",
    "bearer",
)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SECRETISH_VALUE = re.compile(r"(?i)(sk-[a-z0-9]{8,}|bearer\s+\S|api[_-]?key\s*[=:])")


class Phase29ProjectionError(ValueError):
    """A model projection carried a forbidden category; fail closed before any dispatch."""

    code = "PHASE_2_9_PROJECTION_FORBIDDEN"

    def __init__(self, categories: list[str]) -> None:
        self.categories = categories
        super().__init__(f"{self.code}:{','.join(categories)}")


def scan_projection_categories(context: Mapping[str, Any]) -> list[str]:
    """Return the sorted forbidden categories present in ``context`` (empty when clean)."""

    found: set[str] = set()

    def _walk(node: Any, key_path: str) -> None:
        if isinstance(node, Mapping):
            for k, v in node.items():
                lowered = str(k).lower()
                for sub in _FORBIDDEN_KEY_SUBSTRINGS:
                    if sub in lowered:
                        found.add(f"FORBIDDEN_KEY:{sub}")
                _walk(v, lowered)
        elif isinstance(node, list | tuple):
            for item in node:
                _walk(item, key_path)
        elif isinstance(node, str):
            if _HEX64.match(node.strip()):
                found.add("SECRET_OR_DIGEST_VALUE")
            if _SECRETISH_VALUE.search(node):
                found.add("SECRET_OR_DIGEST_VALUE")

    _walk(context, "")
    return sorted(found)


def assert_phase29_projection_clean(context: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a projection carries no forbidden category; return a JSON-safe sanitized copy."""

    categories = scan_projection_categories(context)
    if categories:
        raise Phase29ProjectionError(categories)
    # A round-trip through JSON guarantees the persisted/dispatched projection is exactly what was
    # validated (no non-serializable objects, no hidden attributes).
    sanitized: dict[str, Any] = json.loads(json.dumps(context, sort_keys=True))
    return sanitized


# --------------------------------------------------------------------------- #
# The isolated DeepSeek gateway compose stack.
# --------------------------------------------------------------------------- #


@dataclass
class ComposeResult:
    """A minimal, structural stand-in for ``subprocess.CompletedProcess`` (test-injectable)."""

    returncode: int
    stdout: str = ""
    stderr: str = ""


# A compose runner: (argv, stdin, timeout) -> ComposeResult; the default uses shell=False docker.
# Tests inject a fake to exercise the whole path with no docker daemon and no provider call.
ComposeRunner = Callable[[list[str], str | None, int], ComposeResult]


def _default_compose_runner(argv: list[str], stdin: str | None, timeout: int) -> ComposeResult:
    completed = subprocess.run(  # noqa: S603 - fixed docker binary, list argv, shell=False
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        input=stdin,
        shell=False,
    )
    return ComposeResult(
        returncode=completed.returncode, stdout=completed.stdout, stderr=completed.stderr
    )


# Executed inside the control-plane container via ``python -c``. It reads ONE bounded stdin-JSON
# request, runs exactly one GatewayAgentModel.generate, and prints exactly one JSON line. The
# provider credential never reaches this process — the control-plane service holds no key; only the
# gateway does. No raw provider text is returned: on success only the gateway-validated structured
# output + provider-reported usage/identity; on rejection only bounded, value-free diagnostics.
_STEP_PY = (
    "import asyncio, json, sys\n"
    "from aegis.multi_agent.contracts import AgentRole\n"
    "from aegis.multi_agent.model import GatewayAgentModel\n"
    "from aegis.settings import get_settings\n"
    "req = json.loads(sys.stdin.buffer.read().decode())\n"
    "role = AgentRole(req['role'])\n"
    "task = req['task_type']\n"
    "ctx = req['context']\n"
    "mot = req.get('max_output_tokens')\n"
    "model = GatewayAgentModel(get_settings())\n"
    "async def run():\n"
    "    try:\n"
    "        res = await model.generate(role, task, ctx, {}, max_output_tokens=mot)\n"
    "    except Exception as exc:\n"
    "        diag = model.failure_diagnostics[-1] if model.failure_diagnostics else {}\n"
    "        keep = ('task_type','call_index','finish_reason','provider_reported_model',\n"
    "                'content_length','validation_errors','requested_output_tokens','code')\n"
    "        return {'status':'REJECTED',\n"
    "                'error': type(exc).__name__ + ':' + str(exc)[:200],\n"
    "                'code': diag.get('code') or (str(exc)[:100]),\n"
    "                'provider_reported_models': list(model.provider_reported_models),\n"
    "                'provider_usage': diag.get('provider_usage'),\n"
    "                'diagnostic': {k: diag.get(k) for k in keep}}\n"
    "    rec = model.call_records[-1]\n"
    "    return {'status':'OK',\n"
    "            'payload_json': res.payload_json,\n"
    "            'usage': {'input_tokens': res.usage.input_tokens,\n"
    "                      'output_tokens': res.usage.output_tokens},\n"
    "            'provider_reported_models': list(model.provider_reported_models),\n"
    "            'request_projection': rec.request_projection.model_dump(mode='json')}\n"
    "print(json.dumps(asyncio.run(run())))\n"
)

# Zero-cost identity/health preflight: the gateway /health endpoint reports the configured model
# without any provider call. Run from the control-plane side of planner-rpc.
_HEALTH_PY = (
    "import json, urllib.request\n"
    "print(urllib.request.urlopen('http://llm-gateway:8080/health', timeout=5).read().decode())\n"
)
# The control-plane process must never hold the provider credential.
_KEY_PROBE_PY = "import os; print(bool(os.environ.get('AI_AUTH_TOKEN')))\n"


@dataclass
class Phase29GatewayStack:
    """One uniquely-named DeepSeek gateway stack for a single Phase 2.9 live campaign."""

    campaign_id: str
    runner: ComposeRunner = _default_compose_runner
    env: dict[str, str] = field(default_factory=dict)
    up_done: bool = False

    @property
    def project(self) -> str:
        # Compose project names are lowercased and constrained; the campaign id already is.
        return f"aegis-p29-live-ds-{self.campaign_id}".lower()

    def _dc(
        self, *args: str, stdin: str | None = None, timeout: int = 300
    ) -> ComposeResult:
        argv = [DOCKER, "compose", "-p", self.project, *DS_STACK, *args]
        return self.runner(argv, stdin, timeout)

    # ------------------------------ lifecycle ------------------------------ #

    def build(self, *, timeout: int = 1800) -> ComposeResult:
        return self._dc("build", CONTROL_PLANE_SERVICE, GATEWAY_SERVICE, timeout=timeout)

    def up(self, *, timeout: int = 300) -> ComposeResult:
        result = self._dc(
            "up", "-d", CONTROL_PLANE_SERVICE, GATEWAY_SERVICE, EGRESS_PROXY_SERVICE,
            timeout=timeout,
        )
        self.up_done = result.returncode == 0
        return result

    def health(self, *, timeout: int = 30) -> bool:
        """True iff both the gateway and the control plane answer their in-network health checks."""

        gw = self._dc(
            "exec", "-T", GATEWAY_SERVICE, "python", "-c",
            "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/health')",
            timeout=timeout,
        )
        cp = self._dc(
            "exec", "-T", CONTROL_PLANE_SERVICE, "python", "-c",
            "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/health')",
            timeout=timeout,
        )
        return gw.returncode == 0 and cp.returncode == 0

    def control_plane_has_no_key(self, *, timeout: int = 30) -> bool:
        """Prove the control-plane process environment does not contain the provider credential."""

        probe = self._dc(
            "exec", "-T", CONTROL_PLANE_SERVICE, "python", "-c", _KEY_PROBE_PY, timeout=timeout
        )
        return probe.returncode == 0 and probe.stdout.strip() == "False"

    def gateway_reported_model(self, *, timeout: int = 30) -> str | None:
        """Zero-cost model identity from the gateway /health endpoint (no provider call)."""

        probe = self._dc(
            "exec", "-T", CONTROL_PLANE_SERVICE, "python", "-c", _HEALTH_PY, timeout=timeout
        )
        if probe.returncode != 0:
            return None
        line = probe.stdout.strip().splitlines()[-1] if probe.stdout.strip() else ""
        try:
            model = json.loads(line).get("model")
        except (ValueError, AttributeError):
            return None
        return model if isinstance(model, str) else None

    def exec_step(self, stdin_json: str, *, timeout: int = 300) -> dict[str, Any]:
        """Execute one model step in the control-plane container; return its parsed JSON result."""

        run = self._dc(
            "exec", "-T", CONTROL_PLANE_SERVICE, "python", "-c", _STEP_PY,
            stdin=stdin_json, timeout=timeout,
        )
        stdout = run.stdout.strip()
        last = stdout.splitlines()[-1] if stdout else ""
        try:
            return {"exec_rc": run.returncode, "result": json.loads(last)}
        except json.JSONDecodeError:
            return {
                "exec_rc": run.returncode,
                "result": None,
                "exec_stdout_tail": stdout[-2000:],
                "exec_stderr_tail": run.stderr[-2000:],
            }

    def teardown(self, *, timeout: int = 180) -> dict[str, Any]:
        """Unconditionally stop the stack (-v --remove-orphans) and prove zero leftovers."""

        down = self._dc("down", "-v", "--remove-orphans", timeout=timeout)
        # Any container still labelled with this compose project is a leftover.
        left = self.runner(
            [DOCKER, "ps", "-a", "--filter", f"label=com.docker.compose.project={self.project}",
             "--format", "{{.Names}}"],
            None,
            60,
        )
        nets = self.runner(
            [DOCKER, "network", "ls", "--filter",
             f"label=com.docker.compose.project={self.project}", "--format", "{{.Name}}"],
            None,
            60,
        )
        vols = self.runner(
            [DOCKER, "volume", "ls", "--filter",
             f"label=com.docker.compose.project={self.project}", "--format", "{{.Name}}"],
            None,
            60,
        )
        container_leftovers = [n for n in left.stdout.splitlines() if n.strip()]
        network_leftovers = [n for n in nets.stdout.splitlines() if n.strip()]
        volume_leftovers = [n for n in vols.stdout.splitlines() if n.strip()]
        return {
            "down_rc": down.returncode,
            "container_leftovers": container_leftovers,
            "network_leftovers": network_leftovers,
            "volume_leftovers": volume_leftovers,
            "no_leftovers": down.returncode == 0
            and not container_leftovers
            and not network_leftovers
            and not volume_leftovers,
        }


# --------------------------------------------------------------------------- #
# The live model adapter (same logical interface as Phase29ModelDouble).
# --------------------------------------------------------------------------- #


class Phase29LiveModelError(RuntimeError):
    """A fail-closed live model call: rejection, invalid output or identity mismatch.

    Carries the provider-reported usage when the gateway supplied it for a rejected call; ``None``
    means the usage is UNKNOWN and the campaign budget must not assume zero.
    """

    def __init__(
        self,
        code: str,
        provider_input: int | None = None,
        provider_output: int | None = None,
    ) -> None:
        self.code = code
        self.provider_input = provider_input
        self.provider_output = provider_output
        self.usage_known = provider_input is not None and provider_output is not None
        super().__init__(code)


def _split_usage(usage: Any) -> tuple[int | None, int | None]:
    if not isinstance(usage, dict):
        return None, None
    inp, out = usage.get("input_tokens"), usage.get("output_tokens")
    ok = isinstance(inp, int) and not isinstance(inp, bool)
    ok = ok and isinstance(out, int) and not isinstance(out, bool)
    return (inp, out) if ok else (None, None)


class Phase29LiveGatewayModel:
    """Live model adapter to the isolated gateway, drop-in for :class:`Phase29ModelDouble`.

    It exposes the same synchronous ``generate`` surface the campaign drives, plus the ``name`` /
    ``reported_models`` / ``attempts`` attributes the campaign record reads, plus live-only
    evidence (sanitized projections + failure diagnostics). Each call is one isolated stdin-JSON
    round-trip into the control-plane container; there is no retry, no schema-repair call and no
    fallback provider.
    """

    name = "ISOLATED_LIVE_GATEWAY"

    def __init__(self, stack: Phase29GatewayStack) -> None:
        self._stack = stack
        self.reported_models: list[str] = []
        self.attempts: list[dict[str, Any]] = []
        self.failure_diagnostics: list[dict[str, Any]] = []
        self.sanitized_projections: list[dict[str, Any]] = []
        self.gateway_request_projections: list[dict[str, Any]] = []

    def generate(
        self,
        role: AgentRole,
        task_type: str,
        context: dict[str, Any],
        *,
        max_output_tokens: int | None = None,
    ) -> ModelResult:
        sanitized = assert_phase29_projection_clean(context)
        self.sanitized_projections.append(
            {"role": role.value, "task_type": task_type, "projection": sanitized}
        )
        request = json.dumps(
            {
                "role": role.value,
                "task_type": task_type,
                "context": sanitized,
                "max_output_tokens": max_output_tokens or PER_CALL_OUTPUT_TOKENS,
            },
            sort_keys=True,
        )
        step = self._stack.exec_step(request)
        result = step.get("result")
        if step.get("exec_rc") != 0 or not isinstance(result, dict):
            self.failure_diagnostics.append(
                {
                    "code": "GATEWAY_EXEC_FAILED",
                    "task_type": task_type,
                    "exec_rc": step.get("exec_rc"),
                    "exec_stdout_tail": step.get("exec_stdout_tail"),
                    "exec_stderr_tail": step.get("exec_stderr_tail"),
                }
            )
            raise Phase29LiveModelError("GATEWAY_EXEC_FAILED")

        for model_id in result.get("provider_reported_models") or []:
            if isinstance(model_id, str):
                self.reported_models.append(model_id)

        if result.get("status") != "OK":
            diagnostic = result.get("diagnostic") or {}
            diagnostic.setdefault("code", result.get("code"))
            diagnostic["task_type"] = task_type
            self.failure_diagnostics.append(diagnostic)
            inp, out = _split_usage(result.get("provider_usage"))
            raise Phase29LiveModelError(str(result.get("code") or "GATEWAY_REJECTED"), inp, out)

        identity = self.reported_models[-1] if self.reported_models else None
        if identity != CANONICAL_MODEL:
            self.failure_diagnostics.append(
                {"code": "PROVIDER_MODEL_MISMATCH", "task_type": task_type, "identity": identity}
            )
            raise Phase29LiveModelError("PROVIDER_MODEL_MISMATCH")

        usage = result.get("usage") or {}
        input_tokens = int(usage.get("input_tokens", 0))
        output_tokens = int(usage.get("output_tokens", 0))
        projection = result.get("request_projection")
        if isinstance(projection, dict):
            self.gateway_request_projections.append(projection)
        self.attempts.append(
            {
                "role": role.value,
                "task_type": task_type,
                "reported_model": identity,
                "provenance": self.name,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": input_tokens + output_tokens,
            }
        )
        return ModelResult(
            payload_json=result["payload_json"],
            usage=ModelUsage(input_tokens=input_tokens, output_tokens=output_tokens),
        )

    # ------------------------------ evidence ------------------------------- #

    def identity_exact(self) -> bool:
        return bool(self.reported_models) and all(
            m == CANONICAL_MODEL for m in self.reported_models
        )


# --------------------------------------------------------------------------- #
# The live campaign orchestrator.
# --------------------------------------------------------------------------- #


StackFactory = Callable[[str], Phase29GatewayStack]
CampaignFactory = Callable[[Path, Phase29LiveGatewayModel], ConsolidatedOpsCampaign]


class LiveCampaignError(RuntimeError):
    """A typed, fail-closed live-campaign abort. The stacks are still torn down unconditionally."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _default_stack_factory(campaign_id: str) -> Phase29GatewayStack:
    return Phase29GatewayStack(campaign_id=campaign_id)


def _default_campaign_factory(
    base_dir: Path, model: Phase29LiveGatewayModel
) -> ConsolidatedOpsCampaign:
    # A real live run stands up the real synthetic range container; the model boundary is the live
    # isolated gateway adapter (never the deterministic double).
    return ConsolidatedOpsCampaign(base_dir=base_dir, containerized=True, model=model)


def run_live_campaign(
    *,
    authorization_ref: str,
    out_root: Path,
    stack_factory: StackFactory = _default_stack_factory,
    campaign_factory: CampaignFactory = _default_campaign_factory,
    build: bool = True,
) -> dict[str, Any]:
    """Run ONE live Phase 2.9 campaign against the isolated gateway; tear both stacks down always.

    The caller must have already armed the live guard (exact intent + non-secret authorization + the
    exact 5-call / 15,000-token caps). This function stands up the gateway stack, proves credential
    isolation and the zero-cost model identity, then drives the SAME consolidated campaign with the
    live adapter in place of the deterministic double. On any failure it aborts without retry or
    repair, records fail-closed diagnostics and always tears the stacks down.
    """

    started = datetime.now(UTC)
    art_dir = out_root / "evidence"

    # Build the campaign first so its canonical campaign_id names the gateway project too. A never-
    # called placeholder model is passed in, then replaced with the stack-bound live model.
    campaign = campaign_factory(out_root / "work", _PlaceholderModel())  # type: ignore[arg-type]
    stack = stack_factory(campaign.campaign_id)
    live_model = Phase29LiveGatewayModel(stack)
    campaign.model = live_model

    stack_teardown: dict[str, Any] = {"down_rc": None, "no_leftovers": None}
    preflight: dict[str, Any] = {
        "gateway_up": False,
        "gateway_healthy": False,
        "control_plane_has_no_key": False,
        "gateway_reported_model": None,
        "model_identity_preflight_ok": False,
    }
    abort_code: str | None = None
    record: dict[str, Any] | None = None

    try:
        if build:
            stack.build()
        up = stack.up()
        preflight["gateway_up"] = up.returncode == 0
        if up.returncode != 0:
            raise LiveCampaignError("GATEWAY_STACK_UP_FAILED")
        preflight["gateway_healthy"] = stack.health()
        if not preflight["gateway_healthy"]:
            raise LiveCampaignError("GATEWAY_UNHEALTHY")
        preflight["control_plane_has_no_key"] = stack.control_plane_has_no_key()
        if not preflight["control_plane_has_no_key"]:
            raise LiveCampaignError("CONTROL_PLANE_HOLDS_CREDENTIAL")
        reported = stack.gateway_reported_model()
        preflight["gateway_reported_model"] = reported
        preflight["model_identity_preflight_ok"] = reported == CANONICAL_MODEL
        if not preflight["model_identity_preflight_ok"]:
            raise LiveCampaignError("MODEL_IDENTITY_PREFLIGHT_MISMATCH")

        record = campaign.run()
    except (LiveCampaignError, Phase29LiveModelError, Phase29ProjectionError) as exc:
        abort_code = getattr(exc, "code", type(exc).__name__)
    except Exception as exc:  # noqa: BLE001 - fail closed on ANY error; stacks torn down in finally
        abort_code = f"UNEXPECTED:{type(exc).__name__}"
    finally:
        stack_teardown = stack.teardown()

    acceptance = _assemble_live_acceptance(
        started=started,
        campaign_id=stack.campaign_id,
        authorization_ref=authorization_ref,
        preflight=preflight,
        record=record,
        live_model=live_model,
        stack_teardown=stack_teardown,
        abort_code=abort_code,
        art_dir=art_dir,
        campaign=campaign if abort_code is None else None,
    )
    return acceptance


class _PlaceholderModel:
    """A never-called stand-in used only to build the campaign before its stack id exists."""

    name = "UNBOUND_PLACEHOLDER"
    reported_models: list[str] = []
    attempts: list[dict[str, Any]] = []

    def generate(self, *args: Any, **kwargs: Any) -> ModelResult:  # pragma: no cover - never called
        raise RuntimeError("PLACEHOLDER_MODEL_MUST_BE_REPLACED_BEFORE_USE")


def _assemble_live_acceptance(
    *,
    started: datetime,
    campaign_id: str,
    authorization_ref: str,
    preflight: dict[str, Any],
    record: dict[str, Any] | None,
    live_model: Phase29LiveGatewayModel | None,
    stack_teardown: dict[str, Any],
    abort_code: str | None,
    art_dir: Path,
    campaign: ConsolidatedOpsCampaign | None,
) -> dict[str, Any]:
    """Build (and, on a completed run, persist) the fail-closed live acceptance record.

    The live-provider *status* is never LIVE GO here: this build observes and records the evidence
    but leaves the GO/NO-GO adjudication to an explicitly authorized human review.
    """

    secret_isolation = {
        "provider_key_only_in_gateway": bool(preflight["control_plane_has_no_key"]),
        "host_output_key_free": True,  # this process never reads .env.gateway; compose mounts it
        "control_plane_key_free": bool(preflight["control_plane_has_no_key"]),
    }
    reported = sorted(set(live_model.reported_models)) if live_model else []

    if abort_code is not None or record is None:
        diagnostics = list(live_model.failure_diagnostics) if live_model else []
        return {
            "phase": "2.9",
            "mode": "LIVE",
            "status": "LIVE_ABORTED_FAIL_CLOSED",
            "abort_code": abort_code or "NO_RECORD",
            "campaign_id": campaign_id,
            "authorization_ref": authorization_ref,
            "preflight": preflight,
            "secret_isolation": secret_isolation,
            "provider_reported_models": reported,
            "failure_diagnostics": diagnostics,
            "phase_2_9_live_provider_status": NOT_EVALUATED,
            "cleanup": stack_teardown,
            "elapsed_seconds": round((datetime.now(UTC) - started).total_seconds(), 2),
        }

    assert campaign is not None
    accounting = build_evidence_accounting(record, live=True)
    artifact_result = write_campaign_artifacts(art_dir, campaign, record)
    checks = build_phase_2_9_checks(
        record,
        guard_enforced=True,
        artifact_manifest_verified=artifact_result["manifest_verified"],
        report_outputs_persisted=artifact_result["report_outputs_persisted"],
        live=True,
    )
    verdicts = build_typed_verdicts(record, checks)
    true_checks = sorted(k for k, v in checks.items() if v is True)
    ne_checks = sorted(k for k, v in checks.items() if v == NOT_EVALUATED)
    false_checks = sorted(k for k, v in checks.items() if v is False)
    return {
        "phase": "2.9",
        "mode": "LIVE",
        "status": "LIVE_OBSERVED_PENDING_HUMAN_ADJUDICATION",
        "campaign_id": campaign_id,
        "authorization_ref": authorization_ref,
        "preflight": preflight,
        "secret_isolation": secret_isolation,
        "evidence_accounting": accounting,
        "provider_reported_models": reported,
        "sanitized_projections": live_model.sanitized_projections if live_model else [],
        "checks": checks,
        "check_counts": {
            "true": len(true_checks),
            "not_evaluated": len(ne_checks),
            "false": len(false_checks),
            "total": len(checks),
        },
        "not_evaluated_checks": ne_checks,
        "false_checks": false_checks,
        "typed_verdicts": verdicts,
        "canonical_job_addresses": {
            "lead": record["jobs"]["lead_job_address"],
            "initial_recon": record["jobs"]["recon_job_address"],
            "retest_recon": record["jobs"]["retest_recon_job_address"],
            "report": record["jobs"]["report_job_address"],
        },
        # This task never claims LIVE GO; the top-line provider status stays NOT_EVALUATED.
        "phase_2_9_live_provider_status": NOT_EVALUATED,
        "cleanup": stack_teardown,
        "evidence_dir": str(art_dir),
        "elapsed_seconds": round((datetime.now(UTC) - started).total_seconds(), 2),
    }


def guard_is_armed_for_live(request: LiveExecutionRequest) -> bool:
    """Re-export the campaign's pure guard probe for the live runner (no side effects)."""

    return is_live_armed(request)
