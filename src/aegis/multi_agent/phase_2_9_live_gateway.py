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

import hashlib
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
    MAX_PROVIDER_CALLS,
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
COMPOSE_PROJECT_MAX_LENGTH = 63


def _compose_project_name(campaign_id: str) -> str:
    """Return a deterministic, collision-resistant Docker Compose project name.

    Compose accepts only lowercase ASCII letters/digits, hyphens and underscores. The canonical
    Phase 2.9 campaign id contains a dot (``phase-2.9``), so passing it through verbatim makes every
    real live build fail before a stack can start. Normal-size ids retain their random campaign
    suffix; unusually long ids retain uniqueness through a digest of the full, unsanitized id.
    """

    raw = f"aegis-p29-live-ds-{campaign_id}".lower()
    normalized = re.sub(r"[^a-z0-9_-]+", "-", raw).strip("-_")
    if len(normalized) <= COMPOSE_PROJECT_MAX_LENGTH:
        return normalized
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    prefix = normalized[: COMPOSE_PROJECT_MAX_LENGTH - len(digest) - 1].rstrip("-_")
    return f"{prefix}-{digest}"


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


# The exact allowlisted top-level projection shapes for the five planned campaign calls. A task's
# dispatched context must match one of its registered key sets EXACTLY — an unexpected (extra),
# missing or unknown-task shape fails closed BEFORE any dispatch. This complements the
# forbidden-category scan: the scan rejects known-bad content, this rejects anything not explicitly
# expected for the specific call.
_ALLOWED_PROJECTION_SHAPES: dict[str, tuple[frozenset[str], ...]] = {
    "DELEGATE_ADVERSARY_SIMULATION": (frozenset({"target_ref", "capability_catalog"}),),
    # PLAN is issued twice with distinct, individually-allowlisted shapes (initial / retest).
    "PLAN_ADVERSARY_SIMULATION": (
        frozenset({"target_ref", "capability_id"}),
        frozenset({"target_ref", "finding_ref"}),
    ),
    "RECOMMEND_ADVERSARY_REMEDIATION": (frozenset({"finding_ref", "salient"}),),
    "GENERATE_ASSESSMENT_REPORT": (frozenset({"finding_id", "campaign_id"}),),
}


class Phase29ProjectionShapeError(ValueError):
    """A model projection had an unexpected shape for its task; fail closed before any dispatch."""

    code = "PHASE_2_9_PROJECTION_SHAPE_UNEXPECTED"

    def __init__(self, task_type: str, keys: list[str]) -> None:
        self.task_type = task_type
        self.keys = keys
        super().__init__(f"{self.code}:{task_type}:{','.join(sorted(keys))}")


def assert_phase29_projection_shape(task_type: str, sanitized: Mapping[str, Any]) -> None:
    """Fail closed unless the sanitized projection matches an allowlisted shape for the task."""

    allowed = _ALLOWED_PROJECTION_SHAPES.get(task_type)
    keys = set(sanitized)
    if allowed is None or keys not in allowed:
        raise Phase29ProjectionShapeError(task_type, sorted(keys))


def gateway_projection_corresponds(
    projection: Mapping[str, Any], sanitized: Mapping[str, Any]
) -> bool:
    """True iff the gateway-retained request projection corresponds to the sanitized dispatched ctx.

    The retained projection must record a CLEAN redaction with no forbidden categories, and — when
    it carries the context field names the gateway retained — those names must be exactly the
    sanitized context's keys (no field crossed that was not in the sanitized projection).
    """

    if projection.get("redaction_status") != "CLEAN":
        return False
    if list(projection.get("forbidden_categories_present") or []):
        return False
    field_names = projection.get("context_field_names")
    if field_names is not None and set(field_names) != set(sanitized):
        return False
    return True


# --------------------------------------------------------------------------- #
# The isolated DeepSeek gateway compose stack.
# --------------------------------------------------------------------------- #


@dataclass
class ComposeResult:
    """A minimal, structural stand-in for ``subprocess.CompletedProcess`` (test-injectable)."""

    returncode: int
    stdout: str = ""
    stderr: str = ""


def _compose_failure_diagnostic(code: str, result: ComposeResult) -> dict[str, Any]:
    """Build a bounded, value-free diagnostic without transporting compose output.

    Compose stdout/stderr is intentionally not persisted: build tools may echo environment-derived
    values. Instead, recognize a small allowlist of useful error classes and record only booleans,
    the return code and a fixed diagnostic code.
    """

    combined = f"{result.stderr}\n{result.stdout}".lower()
    if "invalid project name" in combined:
        category = "COMPOSE_INVALID_PROJECT_NAME"
    elif "no such file or directory" in combined:
        category = "COMPOSE_BUILD_INPUT_MISSING"
    elif "failed to solve" in combined:
        category = "COMPOSE_BUILD_SOLVE_FAILED"
    elif "timeout" in combined or "timed out" in combined:
        category = "COMPOSE_BUILD_TIMEOUT"
    else:
        category = "COMPOSE_COMMAND_FAILED"
    return {
        "code": code,
        "diagnostic_code": category,
        "returncode": result.returncode,
        "stdout_present": bool(result.stdout),
        "stderr_present": bool(result.stderr),
    }


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
        return _compose_project_name(self.campaign_id)

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
        # Any container/network/volume still labelled with this compose project is a leftover. Each
        # listing probe's return code is recorded: a non-zero probe means the leftover state could
        # NOT be established, so cleanup is treated as unproven (fail closed) rather than clean.
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
        probe_rcs = {
            "down_rc": down.returncode,
            "container_probe_rc": left.returncode,
            "network_probe_rc": nets.returncode,
            "volume_probe_rc": vols.returncode,
        }
        all_probes_ok = all(rc == 0 for rc in probe_rcs.values())
        return {
            **probe_rcs,
            "container_leftovers": container_leftovers,
            "network_leftovers": network_leftovers,
            "volume_leftovers": volume_leftovers,
            # no_leftovers is True ONLY when every probe returned rc 0 AND every leftover list is
            # empty. A failed down or any failed listing probe makes cleanup unproven -> False.
            "no_leftovers": all_probes_ok
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
    """Strictly validate a provider usage record.

    Both ``input_tokens`` and ``output_tokens`` must be present, strict (non-bool) integers and
    non-negative. Any absent, partial, boolean, negative, malformed or non-integer field makes the
    usage UNKNOWN (``None, None``) — it is NEVER coerced to zero as a substitute.
    """

    if not isinstance(usage, dict):
        return None, None
    inp, out = usage.get("input_tokens"), usage.get("output_tokens")
    ok = isinstance(inp, int) and not isinstance(inp, bool) and inp >= 0
    ok = ok and isinstance(out, int) and not isinstance(out, bool) and out >= 0
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
        # Every DISPATCHED attempt (success, rejection, mismatch, unknown-usage, exec failure) with
        # its known or UNKNOWN usage, so an aborted run still persists the full attempt history.
        self.dispatched_attempts: list[dict[str, Any]] = []
        self.failure_diagnostics: list[dict[str, Any]] = []
        self.sanitized_projections: list[dict[str, Any]] = []
        self.gateway_request_projections: list[dict[str, Any]] = []
        self.projection_correspondence: list[bool] = []

    def _record_dispatch(
        self,
        role: AgentRole,
        task_type: str,
        status: str,
        reported_model: str | None,
        input_tokens: int | None,
        output_tokens: int | None,
    ) -> None:
        self.dispatched_attempts.append(
            {
                "role": role.value,
                "task_type": task_type,
                "status": status,
                "reported_model": reported_model,
                "provenance": self.name,
                "input_tokens": input_tokens if input_tokens is not None else UNKNOWN,
                "output_tokens": output_tokens if output_tokens is not None else UNKNOWN,
                "usage_known": input_tokens is not None and output_tokens is not None,
            }
        )

    def generate(
        self,
        role: AgentRole,
        task_type: str,
        context: dict[str, Any],
        *,
        max_output_tokens: int | None = None,
    ) -> ModelResult:
        sanitized = assert_phase29_projection_clean(context)
        # Fail closed before dispatch on any unexpected projection shape for this specific task.
        assert_phase29_projection_shape(task_type, sanitized)
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
            self._record_dispatch(role, task_type, "GATEWAY_EXEC_FAILED", None, None, None)
            raise Phase29LiveModelError("GATEWAY_EXEC_FAILED")

        for model_id in result.get("provider_reported_models") or []:
            if isinstance(model_id, str):
                self.reported_models.append(model_id)
        identity = self.reported_models[-1] if self.reported_models else None

        if result.get("status") != "OK":
            diagnostic = result.get("diagnostic") or {}
            diagnostic.setdefault("code", result.get("code"))
            diagnostic["task_type"] = task_type
            self.failure_diagnostics.append(diagnostic)
            # Preserve the provider-reported usage the gateway supplied for the rejected call.
            inp, out = _split_usage(result.get("provider_usage"))
            self._record_dispatch(role, task_type, "REJECTED", identity, inp, out)
            raise Phase29LiveModelError(str(result.get("code") or "GATEWAY_REJECTED"), inp, out)

        # A success response. Parse and preserve the reported usage FIRST so a later identity- or
        # host-validation rejection still settles the budget with the usage the response supplied.
        input_tokens, output_tokens = _split_usage(result.get("usage"))

        if identity != CANONICAL_MODEL:
            self.failure_diagnostics.append(
                {"code": "PROVIDER_MODEL_MISMATCH", "task_type": task_type, "identity": identity}
            )
            self._record_dispatch(
                role, task_type, "MODEL_MISMATCH", identity, input_tokens, output_tokens
            )
            raise Phase29LiveModelError("PROVIDER_MODEL_MISMATCH", input_tokens, output_tokens)

        # Strict usage: a success with absent/partial/boolean/negative/non-integer usage is UNKNOWN,
        # never zero. Settle the reserved attempt with UNKNOWN so the budget stops before the next
        # call rather than assuming zero tokens were spent.
        if input_tokens is None or output_tokens is None:
            self.failure_diagnostics.append(
                {"code": "PROVIDER_USAGE_UNKNOWN", "task_type": task_type, "identity": identity}
            )
            self._record_dispatch(role, task_type, "USAGE_UNKNOWN", identity, None, None)
            raise Phase29LiveModelError("PROVIDER_USAGE_UNKNOWN", None, None)

        # A valid retained request projection is REQUIRED for every successful provider response: it
        # is the proof the gateway retained exactly the sanitized dispatched context. A missing or
        # malformed projection fails closed (usage preserved, attempt settled, no next call).
        projection = result.get("request_projection")
        if not isinstance(projection, dict):
            self.failure_diagnostics.append(
                {"code": "GATEWAY_PROJECTION_MISSING", "task_type": task_type}
            )
            self._record_dispatch(
                role, task_type, "PROJECTION_MISSING", identity, input_tokens, output_tokens
            )
            raise Phase29LiveModelError("GATEWAY_PROJECTION_MISSING", input_tokens, output_tokens)
        self.gateway_request_projections.append(projection)
        corresponds = gateway_projection_corresponds(projection, sanitized)
        if not corresponds:
            self.failure_diagnostics.append(
                {"code": "GATEWAY_PROJECTION_MISMATCH", "task_type": task_type}
            )
            self._record_dispatch(
                role, task_type, "PROJECTION_MISMATCH", identity, input_tokens, output_tokens
            )
            raise Phase29LiveModelError("GATEWAY_PROJECTION_MISMATCH", input_tokens, output_tokens)
        # Only a corresponding projection records a successful correspondence result.
        self.projection_correspondence.append(True)

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
        self._record_dispatch(role, task_type, "OK", identity, input_tokens, output_tokens)
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
# (base_dir, model, authorization_reference) -> campaign. The authorization reference is threaded
# into the controller-owned AssessmentSpec so the live binding can be proven for exact equality.
CampaignFactory = Callable[[Path, Phase29LiveGatewayModel, str], ConsolidatedOpsCampaign]


class LiveCampaignError(RuntimeError):
    """A typed, fail-closed live-campaign abort. The stacks are still torn down unconditionally."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _default_stack_factory(campaign_id: str) -> Phase29GatewayStack:
    return Phase29GatewayStack(campaign_id=campaign_id)


def _default_campaign_factory(
    base_dir: Path, model: Phase29LiveGatewayModel, authorization_reference: str
) -> ConsolidatedOpsCampaign:
    # A real live run stands up the real synthetic range container; the model boundary is the live
    # isolated gateway adapter (never the deterministic double). The validated non-secret operator
    # authorization reference is threaded into the controller-owned AssessmentSpec.
    return ConsolidatedOpsCampaign(
        base_dir=base_dir,
        containerized=True,
        model=model,
        authorization_reference=authorization_reference,
    )


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

    # Build the campaign first so its canonical campaign_id names the gateway project too. A never-
    # called placeholder model is passed in, then replaced with the stack-bound live model. The
    # validated non-secret authorization reference is threaded into the controller-owned spec here.
    campaign = campaign_factory(
        out_root / "work",
        _PlaceholderModel(),  # type: ignore[arg-type]
        authorization_ref,
    )
    stack = stack_factory(campaign.campaign_id)
    live_model = Phase29LiveGatewayModel(stack)
    campaign.model = live_model
    # Collision-resistant, per-run evidence directory (refuses an existing path — never exist_ok).
    art_dir = out_root / f"evidence-{campaign.campaign_id}"
    controller_authorization_reference = campaign.asm.spec.authorization_reference

    stack_teardown: dict[str, Any] = {"down_rc": None, "no_leftovers": None}
    preflight: dict[str, Any] = {
        "gateway_build_rc": None,
        "gateway_up": False,
        "gateway_healthy": False,
        "control_plane_has_no_key": None,
        "gateway_reported_model": None,
        "model_identity_preflight_ok": False,
        "authorization_binding_ok": False,
    }
    abort_code: str | None = None
    record: dict[str, Any] | None = None

    try:
        # Authorization binding: the controller-recorded spec reference MUST equal the armed
        # operator reference. A mismatch/missing binding aborts BEFORE any stack starts or dispatch.
        preflight["authorization_binding_ok"] = (
            controller_authorization_reference == authorization_ref
        )
        if not preflight["authorization_binding_ok"]:
            raise LiveCampaignError("AUTHORIZATION_BINDING_MISMATCH")
        if build:
            built = stack.build()
            preflight["gateway_build_rc"] = built.returncode
            # A non-zero build must abort before `up` or any provider dispatch.
            if built.returncode != 0:
                live_model.failure_diagnostics.append(
                    _compose_failure_diagnostic("GATEWAY_BUILD_FAILED", built)
                )
                raise LiveCampaignError("GATEWAY_BUILD_FAILED")
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
    except (
        LiveCampaignError,
        Phase29LiveModelError,
        Phase29ProjectionError,
        Phase29ProjectionShapeError,
    ) as exc:
        abort_code = getattr(exc, "code", type(exc).__name__)
    except Exception as exc:  # noqa: BLE001 - fail closed on ANY error; stacks torn down in finally
        abort_code = f"UNEXPECTED:{type(exc).__name__}"
    finally:
        stack_teardown = stack.teardown()

    acceptance = _assemble_live_acceptance(
        started=started,
        campaign_id=campaign.campaign_id,
        authorization_ref=authorization_ref,
        controller_authorization_reference=controller_authorization_reference,
        preflight=preflight,
        record=record,
        live_model=live_model,
        stack_teardown=stack_teardown,
        abort_code=abort_code,
        art_dir=art_dir,
        campaign=campaign,
    )
    return acceptance


class _PlaceholderModel:
    """A never-called stand-in used only to build the campaign before its stack id exists."""

    name = "UNBOUND_PLACEHOLDER"
    reported_models: list[str] = []
    attempts: list[dict[str, Any]] = []

    def generate(self, *args: Any, **kwargs: Any) -> ModelResult:  # pragma: no cover - never called
        raise RuntimeError("PLACEHOLDER_MODEL_MUST_BE_REPLACED_BEFORE_USE")


def _secret_isolation_evidence(
    preflight: dict[str, Any], transported_evidence: Any
) -> dict[str, Any]:
    """Report ONLY runtime-established secret-isolation facts; unproven ones are NOT_EVALUATED.

    * ``control_plane_key_free`` — the value-free boolean probe result (the control-plane process
      env does not carry the provider credential), or NOT_EVALUATED when the probe never ran.
    * ``provider_key_only_in_gateway`` — NOT_EVALUATED: the single control-plane probe cannot, on
      its own, establish the credential lives ONLY in the gateway (that needs a per-service probe).
    * ``recorded_evidence_credential_free`` — evidence-derived: no credential-shaped value (an
      ``sk-*`` key, a bearer token, an ``api_key=`` marker) appears in the recorded evidence.
    """

    cp = preflight.get("control_plane_has_no_key")
    control_plane_key_free: bool | str = bool(cp) if isinstance(cp, bool) else NOT_EVALUATED
    blob = json.dumps(transported_evidence, sort_keys=True, default=str)
    return {
        "control_plane_key_free": control_plane_key_free,
        "provider_key_only_in_gateway": NOT_EVALUATED,
        "recorded_evidence_credential_free": not bool(_SECRETISH_VALUE.search(blob)),
    }


def _budget_evidence(campaign: ConsolidatedOpsCampaign) -> dict[str, Any]:
    """Budget reservations + snapshot with known/UNKNOWN usage (available even on an abort)."""

    return {
        "snapshot": campaign.budget.snapshot(),
        "reservations": campaign.budget.attempts_export(),
    }


def _persist_live_evidence(
    art_dir: Path,
    *,
    acceptance: dict[str, Any],
    extra_files: dict[str, Any],
) -> bool:
    """Write the outer verdict + extra evidence and an integrity manifest over everything present.

    The caller has already created ``art_dir`` fresh (``exist_ok=False``) and, on a completed run,
    written the campaign evidence bundle into it. Here the decisive outer live acceptance verdict
    and every extra evidence file (gateway/range cleanup, dispatched attempts, budget) are written
    and the integrity manifest is computed over ALL files — including ``live_acceptance.json`` —
    then re-verified. Returns the verification result.
    """

    for name, payload in extra_files.items():
        (art_dir / name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    # The decisive outer live acceptance verdict is written as a normal evidence file so it is
    # covered by the integrity manifest — never left only on stdout.
    (art_dir / "live_acceptance.json").write_text(
        json.dumps(acceptance, indent=2, sort_keys=True) + "\n"
    )
    manifest_names = sorted(
        str(p.relative_to(art_dir))
        for p in art_dir.rglob("*")
        if p.is_file() and p.name != "LIVE_SHA256SUMS"
    )
    lines = [
        f"{hashlib.sha256((art_dir / n).read_bytes()).hexdigest()}  {n}" for n in manifest_names
    ]
    (art_dir / "LIVE_SHA256SUMS").write_text("\n".join(lines) + "\n")
    # Re-read and verify every manifested file.
    verified = True
    for line in (art_dir / "LIVE_SHA256SUMS").read_text().splitlines():
        if not line.strip():
            continue
        digest, name = line.split("  ", 1)
        if hashlib.sha256((art_dir / name).read_bytes()).hexdigest() != digest:
            verified = False
    return verified


def _assemble_live_acceptance(
    *,
    started: datetime,
    campaign_id: str,
    authorization_ref: str,
    controller_authorization_reference: str,
    preflight: dict[str, Any],
    record: dict[str, Any] | None,
    live_model: Phase29LiveGatewayModel | None,
    stack_teardown: dict[str, Any],
    abort_code: str | None,
    art_dir: Path,
    campaign: ConsolidatedOpsCampaign,
) -> dict[str, Any]:
    """Build and ALWAYS persist the fail-closed live acceptance record (aborts included).

    The live-provider *status* is never LIVE GO here: this build observes and records the evidence
    but leaves the GO/NO-GO adjudication to an explicitly authorized human review. Every armed
    attempt — success or fail-closed abort — produces a fresh, non-overwriting artifact whose
    integrity manifest covers the live acceptance verdict and the post-run cleanup evidence.
    """

    reported = sorted(set(live_model.reported_models)) if live_model else []
    dispatched = list(live_model.dispatched_attempts) if live_model else []
    diagnostics = list(live_model.failure_diagnostics) if live_model else []
    sanitized_projections = list(live_model.sanitized_projections) if live_model else []
    budget_evidence = _budget_evidence(campaign)
    secret_isolation = _secret_isolation_evidence(
        preflight,
        {
            "sanitized_projections": sanitized_projections,
            "dispatched_attempts": dispatched,
            "failure_diagnostics": diagnostics,
        },
    )
    lineage = {
        "campaign_id": campaign_id,
        "assessment_id": campaign.asm.assessment_id,
        "run_epoch": campaign.run_epoch,
        "loop_id": campaign.asm.loop_id,
        "finding_id": campaign.asm.finding_id,
    }
    # Durable range-cleanup snapshot (captured in run()'s finally; survives an abort). Its default
    # is NOT_STARTED when range creation never began.
    range_cleanup = dict(campaign.range_cleanup)

    if abort_code is not None or record is None:
        # Fresh directory only: refuse an existing path so a live abort never overwrites evidence.
        art_dir.mkdir(parents=True, exist_ok=False)
        acceptance: dict[str, Any] = {
            "phase": "2.9",
            "mode": "LIVE",
            "status": "LIVE_ABORTED_FAIL_CLOSED",
            "abort_code": abort_code or "NO_RECORD",
            "campaign_id": campaign_id,
            "armed_authorization_reference": authorization_ref,
            "controller_authorization_reference": controller_authorization_reference,
            "campaign_lineage": lineage,
            "preflight": preflight,
            "secret_isolation": secret_isolation,
            "provider_reported_models": reported,
            "dispatched_attempts": dispatched,
            "budget": budget_evidence,
            "sanitized_projections": sanitized_projections,
            "failure_diagnostics": diagnostics,
            "phase_2_9_live_provider_status": NOT_EVALUATED,
            "cleanup": stack_teardown,
            "range_cleanup": range_cleanup,
            "elapsed_seconds": round((datetime.now(UTC) - started).total_seconds(), 2),
        }
        integrity = _persist_live_evidence(
            art_dir,
            acceptance=acceptance,
            extra_files={
                "gateway_cleanup.json": stack_teardown,
                "range_cleanup.json": range_cleanup,
                "dispatched_attempts.json": dispatched,
                "budget_reservations_and_usage.json": budget_evidence,
                "failure_diagnostics.json": diagnostics,
            },
        )
        acceptance["evidence_dir"] = str(art_dir)
        acceptance["integrity_manifest_verified"] = integrity
        return acceptance

    accounting = build_evidence_accounting(record, live=True)
    # The campaign bundle is written into the fresh artifact dir by _persist_live_evidence below,
    # but its manifest verification is needed for the checks — so write it here into the (not-yet-
    # existing) dir first, then _persist_live_evidence adds the outer verdict + manifest over all.
    art_dir.mkdir(parents=True, exist_ok=False)
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

    # Cleanup CONTROLS the verdict. Observed-success is permitted ONLY when every controller, range,
    # gateway, artifact, budget and typed check required for observation is strictly true.
    usage_complete = record["lifecycle"]["usage_complete"] is True
    gateway_cleanup_clean = stack_teardown.get("no_leftovers") is True
    # Range cleanup is MANDATORY for a live campaign: the controller ledger succeeded (incl. reset),
    # teardown ran AND actually succeeded (or strictly proved prior absence), the leftover query
    # itself succeeded, and zero range resources remain. A None / missing / UNKNOWN / failed-query /
    # failed-teardown / non-PASS snapshot is NOT clean.
    range_cleanup_complete = (
        record["cleanup"]["cleanup_ok"] is True
        and range_cleanup.get("status") == "PASS"
        and range_cleanup.get("teardown_ran") is True
        and range_cleanup.get("teardown_ok") is True
        and range_cleanup.get("leftover_query_ok") is True
        and range_cleanup.get("no_leftovers") is True
    )
    # Every successful provider call must have exactly one True correspondence record (five for a
    # complete campaign): the gateway retained precisely the sanitized dispatched context each time.
    correspondence = list(live_model.projection_correspondence) if live_model else []
    projection_correspondence_complete = (
        len(correspondence) == MAX_PROVIDER_CALLS and all(correspondence)
    )
    gates = {
        "typed_verdict_satisfied": verdicts["phase_2_9"]["satisfied"] is True,
        "no_false_checks": not false_checks,
        "artifact_manifest_verified": bool(artifact_result["manifest_verified"]),
        "budget_usage_complete": usage_complete,
        "gateway_cleanup_no_leftovers": gateway_cleanup_clean,
        "range_cleanup_complete": range_cleanup_complete,
        "projection_correspondence_complete": projection_correspondence_complete,
    }
    observed_ok = all(gates.values())
    status = (
        "LIVE_OBSERVED_PENDING_HUMAN_ADJUDICATION"
        if observed_ok
        else "LIVE_OBSERVED_FAILED_CLOSED"
    )

    acceptance = {
        "phase": "2.9",
        "mode": "LIVE",
        "status": status,
        "campaign_id": campaign_id,
        "armed_authorization_reference": authorization_ref,
        "controller_authorization_reference": controller_authorization_reference,
        "campaign_lineage": lineage,
        "preflight": preflight,
        "secret_isolation": secret_isolation,
        "evidence_accounting": accounting,
        "provider_reported_models": reported,
        "dispatched_attempts": dispatched,
        "budget": budget_evidence,
        "sanitized_projections": sanitized_projections,
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
        "live_acceptance_gates": gates,
        "projection_correspondence": correspondence,
        "canonical_job_addresses": {
            "lead": record["jobs"]["lead_job_address"],
            "initial_recon": record["jobs"]["recon_job_address"],
            "retest_recon": record["jobs"]["retest_recon_job_address"],
            "report": record["jobs"]["report_job_address"],
        },
        # This task never claims LIVE GO; the top-line provider status stays NOT_EVALUATED.
        "phase_2_9_live_provider_status": NOT_EVALUATED,
        "cleanup": stack_teardown,
        "range_cleanup": range_cleanup,
        "elapsed_seconds": round((datetime.now(UTC) - started).total_seconds(), 2),
    }
    integrity = _persist_live_evidence(
        art_dir,
        acceptance=acceptance,
        extra_files={
            "gateway_cleanup.json": stack_teardown,
            "range_cleanup.json": range_cleanup,
            "dispatched_attempts.json": dispatched,
            "live_budget_reservations.json": budget_evidence,
        },
    )
    acceptance["evidence_dir"] = str(art_dir)
    acceptance["integrity_manifest_verified"] = integrity
    return acceptance


def guard_is_armed_for_live(request: LiveExecutionRequest) -> bool:
    """Re-export the campaign's pure guard probe for the live runner (no side effects)."""

    return is_live_armed(request)
