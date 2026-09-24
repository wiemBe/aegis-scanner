"""Phase 2.1 controlled Authentication-testing slice: capability registry, Tool Broker, response
sanitization/normalization, a bounded disposable login worker, and a real persisted, addressable
LEAD_ORCHESTRATOR -> AUTHORIZATION_AGENT job/delegation queue.

This is the control-plane half of the single synthetic authentication rate-limit/lockout vertical
slice. It mirrors the Phase 1.9 cloud-boundary design point-for-point, adapted to an authentication
control (missing credential-attempt rate limiting / account lockout) on the synthetic ``aegis-bank``
login surface:

* the model *selects* a registered authentication capability, a typed authentication control class,
  opaque account / invalid-candidate-set / positive-control references and a bounded invalid-attempt
  count (see :class:`aegis.multi_agent.contracts.AuthenticationPlanOutput`); it never authors a URL,
  username, passcode, credential value, header or request body;
* the :class:`AuthenticationBroker` deterministically renders that typed plan into a **shell-free**
  bounded HTTP login-attempt set — a fixed method, a fixed route, concurrency 1, and a controller
  -clamped attempt budget — and fails closed on anything outside the registered capability's scope.
  The model may request *fewer* invalid attempts than the controller ceiling but never more;
* :func:`sanitize_login_response` runs at the source (inside the disposable worker) so any token /
  ``Set-Cookie`` / ``Authorization`` value is redacted before it leaves the attempt boundary — only
  a response's status, a boolean "a token-shaped field was present", and whether it was a lockout
  signal are ever carried forward. The positive-control session token is captured into an isolated
  in-worker ephemeral store as an opaque ``credentialref://`` reference and revoked in place;
* target-controlled login error content is untrusted DATA: instruction-like content is flagged
  (reusing the Phase 1.7-D marker set), never obeyed;
* the agent **never confirms**: observations, hypotheses and the submission all carry
  ``unconfirmed=True`` at the type level. Only the independent deterministic range verifier promotes
  the vulnerable case to CONFIRMED or the patched case to PASS, from controller-owned ground truth
  this module never sees.

The :class:`AuthTaskQueue` is the real inter-agent boundary: a real ``LEAD_ORCHESTRATOR`` job is
persisted and consumed, it produces a persisted typed delegation, and a separate real
``AUTHORIZATION_AGENT`` job (carrying that delegation id and the producer job id) is persisted and
consumed. Every record links the producer job, the consumer job, the delegation, the task type and
the source-evidence digest, so the audit trail proves a real hand-off — not just role labels.
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Literal

import httpx
from pydantic import Field

from aegis.multi_agent.attack_chain import EphemeralSecretStore, is_credential_reference
from aegis.multi_agent.contracts import AuthenticationPlanOutput, StrictModel, now_utc
from aegis.multi_agent.injection import HOSTILE_INSTRUCTION_MARKERS

# --------------------------------------------------------------------------- #
# Capability registry (kept in lockstep with aegis.multi_agent.registry / .contracts).
# --------------------------------------------------------------------------- #

CAP_AUTH_RATE_LIMIT_PROBE = "aegis.bank.auth_rate_limit_probe"
AUTH_CAPABILITIES: frozenset[str] = frozenset({CAP_AUTH_RATE_LIMIT_PROBE})

# The bounded authentication control classes the model may hypothesize. Kept identical to the
# gateway contract's ``_GwAuthControlClass`` literal by the drift-guard test.
AUTH_CONTROL_CLASSES: frozenset[str] = frozenset(
    {"CREDENTIAL_RATE_LIMIT", "ACCOUNT_LOCKOUT", "LOGIN_COOLDOWN"}
)

# Opaque, symbolic references (kept identical to the gateway contract's alias literals). None is a
# username, passcode or candidate value: the broker resolves each to a controller-owned synthetic
# value controller-side, never to the model.
AUTH_ACCOUNT_REFS: frozenset[str] = frozenset({"PRIMARY_SYNTHETIC_ACCOUNT"})
AUTH_CANDIDATE_SET_REFS: frozenset[str] = frozenset({"INVALID_CANDIDATE_SET_A"})
AUTH_POSITIVE_CONTROL_REFS: frozenset[str] = frozenset({"POSITIVE_CONTROL_CREDENTIAL"})

_FINDING_DOMAIN = "AUTHENTICATION"
_PHASE_ID = "auth-rate-limit-v1"

# The single registered login route/method for this capability. The model never selects these; the
# broker fixes them, so no route or verb is model-controllable.
_LOGIN_ROUTE = "/api/sessions"
_LOGIN_METHOD: Literal["POST"] = "POST"

# Hard controller limits (mirrors the Phase 2.1 instruction). The model may request less, not more.
ATTEMPT_CEILING = 12
CONCURRENCY = 1
# One positive control + K invalid attempts + one post-burst control, so K <= ATTEMPT_CEILING - 2.
_MAX_INVALID_ATTEMPTS = ATTEMPT_CEILING - 2


# --------------------------------------------------------------------------- #
# Controller-owned probe-profile registry (the root correction).
# --------------------------------------------------------------------------- #
# The model selects or recommends a registered probe-profile id; the controller resolves it into the
# bounded effective test sequence. The profile — never the model — owns whether the invalid burst is
# sufficient to cross the synthetic policy threshold, the pre/post positive controls, concurrency,
# pacing, the maximum attempts, the stop conditions and the account reset requirement. None of these
# values (least of all ``sufficient_invalid_attempts``, which is threshold-derived controller state)
# is ever placed in a model prompt, projection, observation, queue payload or report. A model-
# requested invalid count below the profile minimum must not silently become an insufficient test:
# the controller deterministically renders the profile's sufficient sequence and records the
# adjustment reason. The value is chosen controller-side to exceed the synthetic lockout threshold
# by one attempt while staying within ``ATTEMPT_CEILING`` (one pre + K invalid + one post <= 12).


class CredentialRateLimitProbeProfile(StrictModel):
    """A controller-owned, typed probe profile. Fully resolved controller-side; model-blind."""

    profile_id: Literal["credential_rate_limit_threshold_probe_v1"]
    pre_burst_positive_controls: Literal[1] = 1
    # Controller-owned invalid-burst length, sufficient to cross the synthetic policy threshold. It
    # is threshold-derived state; it is never disclosed to the model (which only names the profile).
    sufficient_invalid_attempts: int = Field(ge=1, le=_MAX_INVALID_ATTEMPTS)
    post_burst_positive_controls: Literal[1] = 1
    concurrency: Literal[1] = 1
    pacing_seconds: float = Field(ge=0.0, le=5.0)
    max_attempts: int = Field(ge=3, le=ATTEMPT_CEILING)
    stop_conditions: tuple[str, ...] = Field(min_length=1)
    reset_required: bool = True


CRED_RATE_LIMIT_THRESHOLD_PROBE_V1: Literal["credential_rate_limit_threshold_probe_v1"] = (
    "credential_rate_limit_threshold_probe_v1"
)

# The single registered profile. ``sufficient_invalid_attempts=6`` crosses the synthetic lockout
# threshold (controller-owned, threshold+1) and, with the two controls, totals 8 attempts <= 12.
AUTH_PROBE_PROFILES: dict[str, CredentialRateLimitProbeProfile] = {
    CRED_RATE_LIMIT_THRESHOLD_PROBE_V1: CredentialRateLimitProbeProfile(
        profile_id=CRED_RATE_LIMIT_THRESHOLD_PROBE_V1,
        sufficient_invalid_attempts=6,
        pacing_seconds=0.0,
        max_attempts=ATTEMPT_CEILING,
        stop_conditions=(
            "INVALID_CREDENTIAL_AUTHENTICATED",
            "MAX_ATTEMPTS_REACHED",
        ),
        reset_required=True,
    )
}
AUTH_PROBE_PROFILE_IDS: frozenset[str] = frozenset(AUTH_PROBE_PROFILES)

# ------------------------- Controller / broker secret path ------------------------- #
# These concrete synthetic credential values live ONLY here (and in the rendered attempt bodies the
# broker hands to the disposable worker). They are never placed in a model prompt, projection,
# observation, queue payload or report. The invalid candidate set is controller-owned synthetic.
_ACCOUNT_RESOLUTION: dict[str, str] = {"PRIMARY_SYNTHETIC_ACCOUNT": "alex@example.test"}
_POSITIVE_CONTROL_RESOLUTION: dict[str, str] = {
    "POSITIVE_CONTROL_CREDENTIAL": "synthetic-alex-pass"  # noqa: S105 - synthetic controller secret
}
_INVALID_CANDIDATE_SETS: dict[str, tuple[str, ...]] = {
    "INVALID_CANDIDATE_SET_A": tuple(
        f"invalid-candidate-{index}" for index in range(_MAX_INVALID_ATTEMPTS)
    )
}

# Defence-in-depth: a rendered route must carry no shell metacharacter or whitespace.
_SHELL_METACHARACTERS = frozenset({";", "|", "&", "$", "`", "\n", "\r", " ", "\t", ">", "<"})
_SAFE_ROUTE_RE = re.compile(r"^/[A-Za-z0-9/_.-]+$")

# The token-shaped / credential-bearing fields and headers redacted at the ingestion boundary.
_TOKEN_FIELDS = ("access_token", "token", "session", "refresh_token")
_SENSITIVE_HEADERS = frozenset(
    {"set-cookie", "authorization", "www-authenticate", "proxy-authenticate"}
)


class AuthenticationRejection(ValueError):
    """Raised when an authentication selection escapes the controller allowlist or scope."""


# --------------------------------------------------------------------------- #
# Tool Broker: typed plan -> shell-free bounded login-attempt execution.
# --------------------------------------------------------------------------- #

_AttemptLabel = Literal["POSITIVE_CONTROL", "INVALID_ATTEMPT", "POST_CONTROL"]
_CredentialKind = Literal["POSITIVE_CONTROL", "INVALID_CANDIDATE", "POST_CONTROL"]


class BrokeredAuthAttempt(StrictModel):
    """One controller-rendered, shell-free login attempt. No username, passcode, body or shell text.

    ``credential_kind`` says which controller-owned value the broker injects at send time; the value
    itself is never represented here. ``candidate_index`` selects a member of the invalid candidate
    set for an INVALID_CANDIDATE attempt (``-1`` for the two control attempts).
    """

    label: _AttemptLabel
    method: Literal["POST"]
    route: str = Field(min_length=1, max_length=200)
    credential_kind: _CredentialKind
    candidate_index: int = Field(default=-1, ge=-1, le=ATTEMPT_CEILING)


class BrokeredAuthExecution(StrictModel):
    """The full shell-free bounded login-attempt execution the broker renders from a typed plan."""

    capability_id: Literal["aegis.bank.auth_rate_limit_probe"]
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    finding_domain: Literal["AUTHENTICATION"] = "AUTHENTICATION"
    control_class: str = Field(min_length=3, max_length=64)
    account_ref: str = Field(min_length=3, max_length=64)
    candidate_set_ref: str = Field(min_length=3, max_length=64)
    attempt_ceiling: int = Field(ge=1, le=ATTEMPT_CEILING)
    # Model-requested vs controller-effective fields, kept strictly separate (the root correction).
    # The profile id and hint are what the model asked for; the effective fields are what the
    # controller deterministically rendered. A hint never lowers the effective sequence below the
    # profile minimum.
    model_requested_profile_id: str = Field(min_length=3, max_length=80)
    model_requested_invalid_attempts: int = Field(ge=1, le=ATTEMPT_CEILING)
    controller_effective_profile_id: str = Field(min_length=3, max_length=80)
    controller_effective_invalid_attempts: int = Field(ge=1, le=ATTEMPT_CEILING)
    controller_adjustment_reason: str = Field(min_length=3, max_length=120)
    # Retained for backwards-compatible auditing; equal to the model hint / controller-effective
    # counts respectively.
    requested_invalid_attempts: int = Field(ge=1, le=ATTEMPT_CEILING)
    rendered_invalid_attempts: int = Field(ge=1, le=ATTEMPT_CEILING)
    total_attempts: int = Field(ge=3, le=ATTEMPT_CEILING)
    concurrency: Literal[1]
    attempts: list[BrokeredAuthAttempt] = Field(min_length=3, max_length=ATTEMPT_CEILING)
    shell_free: bool


class AuthenticationBroker:
    """Convert a typed :class:`AuthenticationPlanOutput` to a shell-free bounded login-attempt set.

    It re-validates every model selection against the controller allowlist (capability id, control
    class, account/candidate/positive-control references, method, concurrency), *clamps* the
    requested invalid-attempt count to the controller ceiling and the candidate-set size, and
    renders one positive-control login, the bounded invalid-attempt sequence and a post-burst
    control. It
    proves the rendering is shell-free and never emits a username, passcode, body or shell string.
    """

    def render(self, plan: AuthenticationPlanOutput) -> BrokeredAuthExecution:
        if plan.capability_id not in AUTH_CAPABILITIES:
            raise AuthenticationRejection("AUTH_CAPABILITY_NOT_REGISTERED")
        if plan.control_class not in AUTH_CONTROL_CLASSES:
            raise AuthenticationRejection("AUTH_CONTROL_CLASS_NOT_REGISTERED")
        attempt = plan.attempt
        if attempt.method != _LOGIN_METHOD:
            raise AuthenticationRejection("AUTH_METHOD_NOT_ALLOWED")
        if attempt.concurrency != CONCURRENCY:
            raise AuthenticationRejection("AUTH_CONCURRENCY_NOT_ALLOWED")
        if attempt.account_ref not in AUTH_ACCOUNT_REFS:
            raise AuthenticationRejection("AUTH_ACCOUNT_REF_NOT_REGISTERED")
        if attempt.candidate_set_ref not in AUTH_CANDIDATE_SET_REFS:
            raise AuthenticationRejection("AUTH_CANDIDATE_SET_NOT_REGISTERED")
        if (
            attempt.positive_control_ref is not None
            and attempt.positive_control_ref not in AUTH_POSITIVE_CONTROL_REFS
        ):
            raise AuthenticationRejection("AUTH_POSITIVE_CONTROL_REF_NOT_REGISTERED")
        # Resolve the controller-owned probe profile. The model only *names* it; the profile — not
        # the model — decides whether the invalid burst is sufficient to cross the synthetic policy
        # threshold. An unregistered profile fails closed.
        profile = AUTH_PROBE_PROFILES.get(attempt.probe_profile_id)
        if profile is None:
            raise AuthenticationRejection("AUTH_PROBE_PROFILE_NOT_REGISTERED")
        candidates = _INVALID_CANDIDATE_SETS.get(attempt.candidate_set_ref)
        if not candidates:
            raise AuthenticationRejection("AUTH_CANDIDATE_SET_UNRESOLVABLE")
        # Deterministic controller rendering: the effective invalid-attempt count is the profile's
        # sufficient sequence, clamped only by the hard controller ceiling and the candidate-set
        # size — NEVER lowered by the model's hint. A hint below the profile minimum is recorded but
        # cannot produce an insufficient test; a hint at or above it changes nothing.
        model_hint = attempt.requested_invalid_attempts
        rendered_invalid = min(
            profile.sufficient_invalid_attempts, _MAX_INVALID_ATTEMPTS, len(candidates)
        )
        if rendered_invalid < 1:
            raise AuthenticationRejection("AUTH_PROFILE_SEQUENCE_UNRENDERABLE")
        if model_hint < rendered_invalid:
            adjustment_reason = (
                f"MODEL_HINT_{model_hint}_BELOW_PROFILE_SUFFICIENT_"
                f"{rendered_invalid}_RENDERED_PROFILE_SEQUENCE"
            )
        elif model_hint > rendered_invalid:
            adjustment_reason = (
                f"MODEL_HINT_{model_hint}_ABOVE_PROFILE_SUFFICIENT_"
                f"{rendered_invalid}_RENDERED_PROFILE_SEQUENCE"
            )
        else:
            adjustment_reason = f"MODEL_HINT_MATCHED_PROFILE_SUFFICIENT_{rendered_invalid}"
        attempts: list[BrokeredAuthAttempt] = [
            BrokeredAuthAttempt(
                label="POSITIVE_CONTROL",
                method=_LOGIN_METHOD,
                route=_LOGIN_ROUTE,
                credential_kind="POSITIVE_CONTROL",
            )
        ]
        attempts += [
            BrokeredAuthAttempt(
                label="INVALID_ATTEMPT",
                method=_LOGIN_METHOD,
                route=_LOGIN_ROUTE,
                credential_kind="INVALID_CANDIDATE",
                candidate_index=index,
            )
            for index in range(rendered_invalid)
        ]
        attempts.append(
            BrokeredAuthAttempt(
                label="POST_CONTROL",
                method=_LOGIN_METHOD,
                route=_LOGIN_ROUTE,
                credential_kind="POST_CONTROL",
            )
        )
        shell_free = all(self._is_shell_free(item) for item in attempts)
        if not shell_free:
            raise AuthenticationRejection("AUTH_EXECUTION_NOT_SHELL_FREE")
        total = len(attempts)
        if total > ATTEMPT_CEILING or total > profile.max_attempts:
            raise AuthenticationRejection("AUTH_ATTEMPT_CEILING_EXCEEDED")
        return BrokeredAuthExecution(
            capability_id=plan.capability_id,
            target_ref=plan.target_ref,
            control_class=plan.control_class,
            account_ref=attempt.account_ref,
            candidate_set_ref=attempt.candidate_set_ref,
            attempt_ceiling=ATTEMPT_CEILING,
            model_requested_profile_id=attempt.probe_profile_id,
            model_requested_invalid_attempts=model_hint,
            controller_effective_profile_id=profile.profile_id,
            controller_effective_invalid_attempts=rendered_invalid,
            controller_adjustment_reason=adjustment_reason,
            requested_invalid_attempts=model_hint,
            rendered_invalid_attempts=rendered_invalid,
            total_attempts=total,
            concurrency=CONCURRENCY,
            attempts=attempts,
            shell_free=shell_free,
        )

    @staticmethod
    def _is_shell_free(attempt: BrokeredAuthAttempt) -> bool:
        if attempt.method != _LOGIN_METHOD:
            return False
        if not _SAFE_ROUTE_RE.match(attempt.route):
            return False
        return not any(ch in attempt.route for ch in _SHELL_METACHARACTERS)


def authentication_attempt_bodies(execution: BrokeredAuthExecution) -> list[dict[str, object]]:
    """Resolve a rendered execution into concrete request bodies. Broker secret path only.

    The username, valid passcode and invalid candidate values are resolved controller-side here and
    handed only to the disposable worker. This output must never be persisted into an artifact,
    projection or queue payload.
    """

    username = _ACCOUNT_RESOLUTION[execution.account_ref]
    valid_passcode = _POSITIVE_CONTROL_RESOLUTION["POSITIVE_CONTROL_CREDENTIAL"]
    candidates = _INVALID_CANDIDATE_SETS[execution.candidate_set_ref]
    bodies: list[dict[str, object]] = []
    for attempt in execution.attempts:
        if attempt.credential_kind == "INVALID_CANDIDATE":
            passcode = candidates[attempt.candidate_index]
        else:
            passcode = valid_passcode
        bodies.append(
            {
                "label": attempt.label,
                "kind": attempt.credential_kind,
                "route": attempt.route,
                "body": {"username": username, "passcode": passcode},
            }
        )
    return bodies


# --------------------------------------------------------------------------- #
# Source-side sanitization of the untrusted login response (redaction boundary).
# --------------------------------------------------------------------------- #


def sanitize_login_response(
    label: str,
    status_code: int,
    body: object,
    headers: dict[str, str] | None = None,
) -> dict[str, object]:
    """Reduce one raw login response to sanitized, credential-free facts.

    Runs at the source (inside the disposable worker). It records only the response status, whether
    a token-shaped field was present (as a boolean, never the value), whether the response is a
    rate-limit / lockout signal (HTTP 429), whether a sensitive header (``Set-Cookie`` /
    ``Authorization``) was present (as a boolean), and whether target-controlled instruction-like
    content was observed (flagged as DATA, never obeyed). No token, cookie or header value leaves.
    """

    headers = headers or {}
    token_field_present = False
    if isinstance(body, dict):
        for field in _TOKEN_FIELDS:
            value = body.get(field)
            if isinstance(value, str) and value:
                token_field_present = True
                break
    authenticated = int(status_code) == 200 and token_field_present
    locked_out = int(status_code) == 429
    sensitive_headers_present = any(name.lower() in _SENSITIVE_HEADERS for name in headers)
    lowered = _stringify(body).lower()
    instruction_like = any(marker in lowered for marker in HOSTILE_INSTRUCTION_MARKERS)
    return {
        "label": label,
        "status_code": int(status_code),
        "authenticated": authenticated,
        "token_field_present": token_field_present,
        "locked_out": locked_out,
        "sensitive_headers_present": sensitive_headers_present,
        "instruction_like_content": instruction_like,
    }


def _stringify(body: object) -> str:
    try:
        return json.dumps(body, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(body)


# --------------------------------------------------------------------------- #
# Bounded disposable login worker (runs in the throwaway container / offline test).
# --------------------------------------------------------------------------- #


def run_bounded_login_attempts(
    attempt_bodies: list[dict[str, object]],
    *,
    base_url: str,
    target_ref: str = "range-bank",
    transport: httpx.BaseTransport | None = None,
) -> dict[str, object]:
    """Execute the controller-rendered bounded login-attempt set and return sanitized facts only.

    The positive-control session token, if issued, is captured into an isolated in-process ephemeral
    secret store as an opaque ``credentialref://`` reference, proven resolvable, then revoked and
    the store zeroized — the raw token value never leaves this worker. The returned facts carry the
    sanitized per-attempt observations and the (value-free) positive-control reference lifecycle.
    """

    store = EphemeralSecretStore()
    sanitized: list[dict[str, object]] = []
    positive: dict[str, object] = {
        "captured": False,
        "reference": None,
        "reference_is_opaque": None,
        "resolvable_before_revoke": None,
        "resolvable_after_revoke": None,
    }
    with httpx.Client(
        base_url=base_url, timeout=5, trust_env=False, follow_redirects=False, transport=transport
    ) as client:
        for attempt in attempt_bodies:
            label = str(attempt.get("label", ""))
            kind = str(attempt.get("kind", ""))
            route = str(attempt.get("route", _LOGIN_ROUTE))
            body = attempt.get("body")
            try:
                response = client.post(route, json=body)
                try:
                    parsed: object = response.json()
                except ValueError:
                    parsed = None
                fact = sanitize_login_response(
                    label, response.status_code, parsed, dict(response.headers)
                )
                if (
                    kind == "POSITIVE_CONTROL"
                    and response.status_code == 200
                    and isinstance(parsed, dict)
                ):
                    token = parsed.get("access_token")
                    if isinstance(token, str) and token:
                        binding = store.capture(
                            chain_id=_PHASE_ID,
                            target_ref=target_ref,
                            capability_id=CAP_AUTH_RATE_LIMIT_PROBE,
                            value=token,
                        )
                        positive = {
                            "captured": True,
                            "reference": binding.reference,
                            "reference_is_opaque": is_credential_reference(binding.reference),
                            "resolvable_before_revoke": store.is_resolvable(binding.reference),
                            "resolvable_after_revoke": None,
                        }
                        store.revoke(binding.reference)
                        positive["resolvable_after_revoke"] = store.is_resolvable(binding.reference)
                sanitized.append(fact)
            except httpx.HTTPError as exc:
                sanitized.append(
                    {
                        "label": label,
                        "status_code": 0,
                        "authenticated": False,
                        "token_field_present": False,
                        "locked_out": False,
                        "sensitive_headers_present": False,
                        "instruction_like_content": False,
                        "error": type(exc).__name__,
                    }
                )
    zeroized = store.zeroize()
    return {
        "sanitized": sanitized,
        "positive_control": positive,
        "store_zeroized_count": zeroized,
    }


# --------------------------------------------------------------------------- #
# Typed, credential-free, reference-only observations.
# --------------------------------------------------------------------------- #


class LoginAttemptObservation(StrictModel):
    kind: Literal["LOGIN_ATTEMPT_RESPONSE"] = "LOGIN_ATTEMPT_RESPONSE"
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    label: _AttemptLabel
    status_code: int = Field(ge=0, le=599)
    authenticated: bool = False
    locked_out: bool = False
    instruction_like_content: bool = False


class RateLimitSignalObservation(StrictModel):
    kind: Literal["RATE_LIMIT_SIGNAL_PRESENT", "RATE_LIMIT_SIGNAL_ABSENT"]
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")


class PositiveControlObservation(StrictModel):
    kind: Literal["POSITIVE_CONTROL_USABLE"] = "POSITIVE_CONTROL_USABLE"
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    usable: bool


class AuthNoFinding(StrictModel):
    kind: Literal["NO_FINDING"] = "NO_FINDING"
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    capability_id: str = Field(min_length=3, max_length=80)
    detail: str = Field(default="", max_length=120)


class AuthIncompleteObservation(StrictModel):
    kind: Literal["INCOMPLETE_TOOL_ERROR"] = "INCOMPLETE_TOOL_ERROR"
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    capability_id: str = Field(min_length=3, max_length=80)
    reason: str = Field(min_length=1, max_length=120)


AuthObservationModel = (
    LoginAttemptObservation
    | RateLimitSignalObservation
    | PositiveControlObservation
    | AuthNoFinding
    | AuthIncompleteObservation
)

_VALID_LABELS = ("POSITIVE_CONTROL", "INVALID_ATTEMPT", "POST_CONTROL")


def normalize_auth_observations(
    target_ref: str, sanitized_results: list[dict[str, object]] | None
) -> list[AuthObservationModel]:
    """Turn sanitized login-attempt facts into typed, credential-free, reference-only observations.

    A ``None`` or empty result set (a tool error) yields a single INCOMPLETE observation, never a
    clean NO_FINDING — an absent observation is never silently a pass.
    """

    if not sanitized_results:
        return [
            AuthIncompleteObservation(
                target_ref=target_ref,
                capability_id=CAP_AUTH_RATE_LIMIT_PROBE,
                reason="login worker produced no result",
            )
        ]
    observations: list[AuthObservationModel] = []
    any_invalid = False
    lockout_present = False
    positive_usable = False
    for item in sanitized_results:
        label = str(item.get("label", ""))
        if label not in _VALID_LABELS:
            observations.append(
                AuthIncompleteObservation(
                    target_ref=target_ref,
                    capability_id=CAP_AUTH_RATE_LIMIT_PROBE,
                    reason="login attempt missing request label",
                )
            )
            continue
        raw_status = str(item.get("status_code", ""))
        status = int(raw_status) if raw_status.isdigit() else 0
        typed_label: _AttemptLabel = label  # type: ignore[assignment]
        locked = bool(item.get("locked_out"))
        authenticated = bool(item.get("authenticated"))
        observations.append(
            LoginAttemptObservation(
                target_ref=target_ref,
                label=typed_label,
                status_code=status,
                authenticated=authenticated,
                locked_out=locked,
                instruction_like_content=bool(item.get("instruction_like_content")),
            )
        )
        if label == "INVALID_ATTEMPT":
            any_invalid = True
            lockout_present = lockout_present or locked
        if label == "POSITIVE_CONTROL" and authenticated:
            positive_usable = True
    if any_invalid:
        signal_kind: Literal["RATE_LIMIT_SIGNAL_PRESENT", "RATE_LIMIT_SIGNAL_ABSENT"] = (
            "RATE_LIMIT_SIGNAL_PRESENT" if lockout_present else "RATE_LIMIT_SIGNAL_ABSENT"
        )
        observations.append(RateLimitSignalObservation(kind=signal_kind, target_ref=target_ref))
    observations.append(PositiveControlObservation(target_ref=target_ref, usable=positive_usable))
    return observations


def observation_warnings(observations: list[AuthObservationModel]) -> list[str]:
    """Instruction-resistance warnings: target-controlled instruction-like content, as data."""

    if any(
        isinstance(obs, LoginAttemptObservation) and obs.instruction_like_content
        for obs in observations
    ):
        return ["target-controlled instruction-like content observed; treated as data"]
    return []


# --------------------------------------------------------------------------- #
# Real, persisted, addressable LEAD_ORCHESTRATOR / AUTHORIZATION_AGENT job + delegation queue.
# --------------------------------------------------------------------------- #

_JOB_ADDRESS_SCHEME = "agentjob"
_DELEGATION_ADDRESS_SCHEME = "agentqueue"
_JOB_AGENTS = ("LEAD_ORCHESTRATOR", "AUTHORIZATION_AGENT")


class AuthTaskQueueError(RuntimeError):
    """A queue-level failure (duplicate id, malformed address, illegal transition). Fails closed."""


class AuthAgentJob(StrictModel):
    """A real, persisted, addressable inbound job for one Phase 2.1 agent.

    A LEAD_ORCHESTRATOR job carries no producer link; an AUTHORIZATION_AGENT job carries the
    persisted delegation id it was created from and the producer (lead) job id. Neither carries a
    mode, ground-truth id, verdict, severity, credential or origin.
    """

    job_id: str = Field(pattern=r"^agjob-[a-f0-9]{16}$")
    to_agent: Literal["LEAD_ORCHESTRATOR", "AUTHORIZATION_AGENT"]
    finding_domain: Literal["AUTHENTICATION"] = "AUTHENTICATION"
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    control_class: str = Field(min_length=3, max_length=64)
    task_type: str = Field(pattern=r"^[A-Z_]+$", max_length=80)
    objective: str = Field(min_length=3, max_length=300)
    from_delegation_id: str = Field(default="", max_length=40)
    producer_job_id: str = Field(default="", max_length=40)
    status: Literal["QUEUED", "CLAIMED", "CLOSED"] = "QUEUED"
    enqueued_at: datetime = Field(default_factory=now_utc)

    @property
    def address(self) -> str:
        return f"{_JOB_ADDRESS_SCHEME}://{self.to_agent}/{self.job_id}"


class PersistedAuthDelegation(StrictModel):
    """A real, persisted, addressable LEAD_ORCHESTRATOR -> AUTHORIZATION_AGENT delegation.

    It carries only references and links: the producer (lead) job id, a registered capability, a
    target reference, the authentication control class and the source-evidence digest. No payload,
    mode, verdict or credential is representable. ``reference_only=False`` distinguishes it from a
    non-persisted stub; ``confirmed``/``unconfirmed`` restate that a delegation never confirms.
    """

    delegation_id: str = Field(pattern=r"^adelg-[a-f0-9]{16}$")
    from_agent: Literal["LEAD_ORCHESTRATOR"] = "LEAD_ORCHESTRATOR"
    to_agent: Literal["AUTHORIZATION_AGENT"] = "AUTHORIZATION_AGENT"
    finding_domain: Literal["AUTHENTICATION"] = "AUTHENTICATION"
    producer_job_id: str = Field(pattern=r"^agjob-[a-f0-9]{16}$")
    capability_id: str = Field(pattern=r"^aegis\.[a-z0-9_.]+$")
    target_ref: str = Field(pattern=r"^range-[a-z0-9-]+$")
    control_class: str = Field(min_length=3, max_length=64)
    task_type: Literal["PLAN_AUTHENTICATION_TEST"] = "PLAN_AUTHENTICATION_TEST"
    source_evidence_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    reference_only: Literal[False] = False
    confirmed: Literal[False] = False
    unconfirmed: Literal[True] = True
    status: Literal["QUEUED", "CLAIMED", "CLOSED"] = "QUEUED"
    enqueued_at: datetime = Field(default_factory=now_utc)

    @property
    def delegation_address(self) -> str:
        return f"{_DELEGATION_ADDRESS_SCHEME}://{self.to_agent}/{self.delegation_id}"


def parse_auth_job_address(address: str) -> tuple[str, str]:
    prefix = f"{_JOB_ADDRESS_SCHEME}://"
    if not address.startswith(prefix):
        raise AuthTaskQueueError("JOB_ADDRESS_SCHEME_INVALID")
    rest = address[len(prefix) :]
    to_agent, sep, job_id = rest.partition("/")
    if not sep or to_agent not in _JOB_AGENTS or not job_id:
        raise AuthTaskQueueError("JOB_ADDRESS_MALFORMED")
    return to_agent, job_id


def parse_auth_delegation_address(address: str) -> tuple[str, str]:
    prefix = f"{_DELEGATION_ADDRESS_SCHEME}://"
    if not address.startswith(prefix):
        raise AuthTaskQueueError("DELEGATION_ADDRESS_SCHEME_INVALID")
    rest = address[len(prefix) :]
    to_agent, sep, delegation_id = rest.partition("/")
    if not sep or to_agent != "AUTHORIZATION_AGENT" or not delegation_id:
        raise AuthTaskQueueError("DELEGATION_ADDRESS_MALFORMED")
    return to_agent, delegation_id


class AuthTaskQueue:
    """A durable, addressable inbound job + delegation queue for the Phase 2.1 hand-off, on SQLite.

    It persists two addressable agent jobs (LEAD_ORCHESTRATOR and AUTHORIZATION_AGENT) and the typed
    delegation that links them, records every job state transition, and resolves each record by its
    durable address. There is no field through which a payload, mode, verdict, severity or secret
    could be persisted.
    """

    def __init__(self, database_path: str) -> None:
        self.database_path = database_path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> None:
        Path(self.database_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS auth_agent_jobs (
                    job_id TEXT PRIMARY KEY,
                    to_agent TEXT NOT NULL,
                    status TEXT NOT NULL,
                    address TEXT NOT NULL UNIQUE,
                    task_type TEXT NOT NULL,
                    from_delegation_id TEXT NOT NULL,
                    producer_job_id TEXT NOT NULL,
                    enqueued_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS auth_agent_job_transitions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL,
                    from_status TEXT NOT NULL,
                    to_status TEXT NOT NULL,
                    at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS auth_delegations (
                    delegation_id TEXT PRIMARY KEY,
                    from_agent TEXT NOT NULL,
                    to_agent TEXT NOT NULL,
                    producer_job_id TEXT NOT NULL,
                    task_type TEXT NOT NULL,
                    capability_id TEXT NOT NULL,
                    address TEXT NOT NULL UNIQUE,
                    source_evidence_sha256 TEXT NOT NULL,
                    enqueued_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_auth_agent_jobs_agent_status
                    ON auth_agent_jobs(to_agent, status);
                """
            )

    # --------------------------- jobs --------------------------- #

    def enqueue_job(self, job: AuthAgentJob) -> str:
        with self._connect() as connection:
            try:
                connection.execute(
                    """INSERT INTO auth_agent_jobs(
                        job_id, to_agent, status, address, task_type,
                        from_delegation_id, producer_job_id, enqueued_at, payload
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        job.job_id,
                        job.to_agent,
                        job.status,
                        job.address,
                        job.task_type,
                        job.from_delegation_id,
                        job.producer_job_id,
                        job.enqueued_at.isoformat(),
                        job.model_dump_json(),
                    ),
                )
                self._record_transition(connection, job.job_id, "NONE", job.status)
            except sqlite3.IntegrityError as exc:
                raise AuthTaskQueueError("JOB_ID_ALREADY_ENQUEUED") from exc
        return job.address

    def get_job(self, job_id: str) -> AuthAgentJob | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM auth_agent_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
        return AuthAgentJob.model_validate_json(row["payload"]) if row else None

    def resolve_job(self, address: str) -> AuthAgentJob | None:
        to_agent, job_id = parse_auth_job_address(address)
        job = self.get_job(job_id)
        if job is not None and job.to_agent != to_agent:
            raise AuthTaskQueueError("JOB_ADDRESS_ROUTING_MISMATCH")
        return job

    def claim_job(self, address: str) -> AuthAgentJob:
        return self._transition(address, expected="QUEUED", new="CLAIMED")

    def close_job(self, address: str) -> AuthAgentJob:
        return self._transition(address, expected="CLAIMED", new="CLOSED")

    def _transition(self, address: str, *, expected: str, new: str) -> AuthAgentJob:
        to_agent, job_id = parse_auth_job_address(address)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload, status FROM auth_agent_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
            if row is None:
                raise AuthTaskQueueError("JOB_NOT_FOUND")
            job = AuthAgentJob.model_validate_json(row["payload"])
            if job.to_agent != to_agent:
                raise AuthTaskQueueError("JOB_ADDRESS_ROUTING_MISMATCH")
            if row["status"] != expected:
                raise AuthTaskQueueError(f"JOB_ILLEGAL_TRANSITION_{row['status']}_TO_{new}")
            updated = job.model_copy(update={"status": new})
            connection.execute(
                "UPDATE auth_agent_jobs SET status = ?, payload = ? WHERE job_id = ?",
                (new, updated.model_dump_json(), job_id),
            )
            self._record_transition(connection, job_id, expected, new)
        return updated

    def job_transitions(self, job_id: str) -> list[dict[str, str]]:
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT from_status, to_status, at FROM auth_agent_job_transitions
                WHERE job_id = ? ORDER BY id""",
                (job_id,),
            ).fetchall()
        return [{"from": r["from_status"], "to": r["to_status"], "at": r["at"]} for r in rows]

    def count_jobs(self) -> int:
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS n FROM auth_agent_jobs").fetchone()
        return int(row["n"])

    # ------------------------ delegations ------------------------ #

    def persist_delegation(self, delegation: PersistedAuthDelegation) -> str:
        with self._connect() as connection:
            # The producer job must already exist and be a LEAD_ORCHESTRATOR job — a delegation
            # cannot be fabricated without its producer.
            producer = connection.execute(
                "SELECT to_agent FROM auth_agent_jobs WHERE job_id = ?",
                (delegation.producer_job_id,),
            ).fetchone()
            if producer is None or producer["to_agent"] != "LEAD_ORCHESTRATOR":
                raise AuthTaskQueueError("DELEGATION_PRODUCER_JOB_INVALID")
            try:
                connection.execute(
                    """INSERT INTO auth_delegations(
                        delegation_id, from_agent, to_agent, producer_job_id, task_type,
                        capability_id, address, source_evidence_sha256, enqueued_at, payload
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        delegation.delegation_id,
                        delegation.from_agent,
                        delegation.to_agent,
                        delegation.producer_job_id,
                        delegation.task_type,
                        delegation.capability_id,
                        delegation.delegation_address,
                        delegation.source_evidence_sha256,
                        delegation.enqueued_at.isoformat(),
                        delegation.model_dump_json(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise AuthTaskQueueError("DELEGATION_ID_ALREADY_PERSISTED") from exc
        return delegation.delegation_address

    def get_delegation(self, delegation_id: str) -> PersistedAuthDelegation | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM auth_delegations WHERE delegation_id = ?", (delegation_id,)
            ).fetchone()
        return PersistedAuthDelegation.model_validate_json(row["payload"]) if row else None

    def resolve_delegation(self, address: str) -> PersistedAuthDelegation | None:
        to_agent, delegation_id = parse_auth_delegation_address(address)
        delegation = self.get_delegation(delegation_id)
        if delegation is not None and delegation.to_agent != to_agent:
            raise AuthTaskQueueError("DELEGATION_ADDRESS_ROUTING_MISMATCH")
        return delegation

    def handoff_linked(self, delegation_id: str) -> bool:
        """True iff the delegation, its producer lead job and a consumer AUTHORIZATION_AGENT job
        carrying that delegation id are all persisted and mutually linked."""

        delegation = self.get_delegation(delegation_id)
        if delegation is None:
            return False
        producer = self.get_job(delegation.producer_job_id)
        if producer is None or producer.to_agent != "LEAD_ORCHESTRATOR":
            return False
        with self._connect() as connection:
            consumer = connection.execute(
                """SELECT to_agent FROM auth_agent_jobs
                WHERE from_delegation_id = ? AND producer_job_id = ? AND to_agent = ?""",
                (delegation_id, delegation.producer_job_id, "AUTHORIZATION_AGENT"),
            ).fetchone()
        return consumer is not None

    @staticmethod
    def _record_transition(
        connection: sqlite3.Connection, job_id: str, from_status: str, to_status: str
    ) -> None:
        connection.execute(
            """INSERT INTO auth_agent_job_transitions(job_id, from_status, to_status, at)
            VALUES (?, ?, ?, ?)""",
            (job_id, from_status, to_status, now_utc().isoformat()),
        )


def evidence_sha256_of(payload: object) -> str:
    """Deterministic digest of a mode-blind context, for delegation provenance linking."""

    import hashlib

    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()
