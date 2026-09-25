"""Reusable live-execution safety prerequisites.

Two small, provider-agnostic controls that any bounded live campaign entry point can reuse to stay
fail-closed. They are deliberately dependency-light (no gateway, no docker, no range imports) so the
guard decision and the budget arithmetic can be unit-tested in isolation and reused by later phases.

* :class:`LiveExecutionGuard` — the live path is **inert by default**. It arms only when an operator
  supplies an explicit intent flag, a **non-secret** authorization reference, and the EXACT declared
  budget caps. A missing intent or authorization returns the typed ``LIVE_AUTHORIZATION_REQUIRED``;
  a wrong/absent call or token cap returns the typed ``INVALID_LIVE_BUDGET``. The decision is a pure
  function of the parsed request — it reads no environment variable, no filesystem and no secret, so
  the mere presence of a gateway credential file (``.env.gateway``) can never arm execution.

* :class:`CampaignProviderBudget` — a fail-closed, **reserve-before-dispatch** cumulative provider
  budget. Before every provider call the caller reserves the worst case (the sanitized input
  projection estimate plus the maximum output allowance) and one call slot; a reservation that would
  breach the campaign call ceiling or token ceiling is refused with ``BUDGET_STOP`` and no call is
  started. A rejected/failed call never counts as zero tokens, and an UNKNOWN provider usage fails
  closed — the remaining hard ceiling can no longer be enforced, so further reservations are refused
  rather than silently assuming the unknown usage was zero.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# A non-secret authorization reference: a short opaque slug an operator can safely paste into a
# command line and an audit log. A value that looks like a bearer token / api key (too long, or
# carrying a secret-ish prefix) is refused so a credential is never accepted here by mistake.
_AUTHORIZATION_REF_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{2,119}$")
_SECRETISH = re.compile(r"(?i)(sk-|bearer\s|api[_-]?key|token=|secret)")


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class LiveSafetyError(ValueError):
    """Base class for the typed, fail-closed live-safety refusals."""

    code = "LIVE_SAFETY_ERROR"

    def __init__(self, detail: str = "") -> None:
        super().__init__(f"{self.code}:{detail}" if detail else self.code)
        self.detail = detail


class LiveAuthorizationRequired(LiveSafetyError):
    """Live path invoked without the explicit intent + non-secret authorization reference."""

    code = "LIVE_AUTHORIZATION_REQUIRED"


class InvalidLiveBudget(LiveSafetyError):
    """The live path was invoked with an absent or non-matching call/token budget cap."""

    code = "INVALID_LIVE_BUDGET"


class BudgetStop(RuntimeError):
    """A provider-call reservation would breach the campaign ceiling (or usage is unenforceable)."""

    code = "BUDGET_STOP"

    def __init__(self, reason: str, snapshot: dict[str, Any] | None = None) -> None:
        super().__init__(f"BUDGET_STOP:{reason}")
        self.reason = reason
        self.snapshot = snapshot or {}


# --------------------------------------------------------------------------- #
# Live authorization guard (pure, fail-closed).
# --------------------------------------------------------------------------- #


class LiveExecutionRequest(_Frozen):
    """The parsed operator intent for a live run. Every field defaults to the inert value."""

    execute_live: bool = False
    authorization_ref: str | None = None
    max_provider_calls: int | None = None
    max_total_tokens: int | None = None


class LiveBudgetPolicy(_Frozen):
    """The exact caps a live run must declare to arm, plus the per-call output allowance."""

    required_max_provider_calls: int = Field(ge=1, le=100)
    required_max_total_tokens: int = Field(ge=1, le=1_000_000)
    per_call_output_ceiling: int = Field(ge=1, le=8192)


class ArmedLiveExecution(_Frozen):
    """The result of a satisfied guard: the validated authorization + caps and an explicit flag."""

    authorization_ref: str
    max_provider_calls: int
    max_total_tokens: int
    armed: Literal[True] = True


@dataclass(frozen=True)
class LiveExecutionGuard:
    """Arms a live run only from an explicit intent + non-secret authorization + exact budget caps.

    The evaluation is a pure function of the parsed :class:`LiveExecutionRequest`; it touches no
    environment variable, secret store or filesystem, so a present ``.env.gateway`` alone can never
    arm execution.
    """

    policy: LiveBudgetPolicy

    def evaluate(self, request: LiveExecutionRequest) -> ArmedLiveExecution:
        """Return an :class:`ArmedLiveExecution`, or raise the typed fail-closed refusal."""

        if not request.execute_live:
            raise LiveAuthorizationRequired("explicit --execute-live intent is required")
        ref = (request.authorization_ref or "").strip()
        if not ref:
            raise LiveAuthorizationRequired("a non-secret --authorization-ref is required")
        if _SECRETISH.search(ref) or not _AUTHORIZATION_REF_PATTERN.match(ref):
            raise LiveAuthorizationRequired(
                "authorization reference must be a short non-secret slug"
            )
        if request.max_provider_calls is None or request.max_total_tokens is None:
            raise InvalidLiveBudget("both --max-provider-calls and --max-total-tokens are required")
        if request.max_provider_calls != self.policy.required_max_provider_calls:
            raise InvalidLiveBudget(
                f"--max-provider-calls must be exactly {self.policy.required_max_provider_calls}"
            )
        if request.max_total_tokens != self.policy.required_max_total_tokens:
            raise InvalidLiveBudget(
                f"--max-total-tokens must be exactly {self.policy.required_max_total_tokens}"
            )
        return ArmedLiveExecution(
            authorization_ref=ref,
            max_provider_calls=request.max_provider_calls,
            max_total_tokens=request.max_total_tokens,
        )

    def is_armed(self, request: LiveExecutionRequest) -> bool:
        """A non-raising probe: True iff :meth:`evaluate` would arm the request."""

        try:
            self.evaluate(request)
        except LiveSafetyError:
            return False
        return True


# --------------------------------------------------------------------------- #
# Fail-closed, reserve-before-dispatch cumulative provider budget.
# --------------------------------------------------------------------------- #


def estimate_input_tokens(projection: Any) -> int:
    """A conservative token estimate of a sanitized input projection (>= 1).

    Uses a deterministic 4-chars-per-token approximation over the canonical JSON of the projection.
    It is intentionally an over-estimate-friendly floor: a real live adapter reserves against this
    before it knows the provider-reported input count.
    """

    try:
        material = json.dumps(projection, sort_keys=True, default=str)
    except (TypeError, ValueError):
        material = str(projection)
    return max(1, len(material) // 4)


@dataclass
class ProviderReservation:
    """One outstanding reservation: worst-case tokens reserved for a single provider call."""

    index: int
    operation: str
    estimated_input: int
    max_output: int
    reserved_tokens: int
    settled: bool = False


@dataclass
class ProviderAttemptUsage:
    """The settled record of one provider call: reserved worst case vs. recorded actual usage."""

    index: int
    operation: str
    reserved_tokens: int
    input_tokens: int | None
    output_tokens: int | None
    total_tokens: int | None
    known: bool


@dataclass
class CampaignProviderBudget:
    """A cumulative, controller-owned, reserve-before-dispatch provider budget for one campaign.

    ``concurrency`` is fixed at 1 (one outstanding reservation at a time). The budget cannot be
    modified after construction other than through :meth:`reserve` / :meth:`record_actual`; a model
    (or any untrusted party) can never widen it.
    """

    max_provider_calls: int
    max_total_tokens: int
    per_call_output_ceiling: int
    calls_reserved: int = 0
    calls_recorded: int = 0
    tokens_recorded: int = 0
    usage_complete: bool = True
    _outstanding: ProviderReservation | None = field(default=None, repr=False)
    attempts: list[ProviderAttemptUsage] = field(default_factory=list)

    def reserve(
        self, operation: str, estimated_input: int, max_output: int | None = None
    ) -> ProviderReservation:
        """Reserve one call slot + the worst-case token cost, or raise :class:`BudgetStop`.

        Refuses (before any call is started) when: a prior call's usage is UNKNOWN (the remaining
        hard ceiling can no longer be enforced without assuming zero); the call ceiling would be
        breached; or the worst-case (already-recorded tokens + this call's estimated input + maximum
        output allowance) would breach the token ceiling.
        """

        if self._outstanding is not None:
            raise BudgetStop("CONCURRENCY_VIOLATION", self.snapshot())
        if not self.usage_complete:
            raise BudgetStop("PRIOR_USAGE_UNKNOWN_CEILING_UNENFORCEABLE", self.snapshot())
        out = self.per_call_output_ceiling if max_output is None else max_output
        if out > self.per_call_output_ceiling:
            raise BudgetStop("PER_CALL_OUTPUT_CEILING_EXCEEDED", self.snapshot())
        if self.calls_reserved + 1 > self.max_provider_calls:
            raise BudgetStop(
                f"CALL_CEILING:{self.calls_reserved}+1>{self.max_provider_calls}", self.snapshot()
            )
        worst_case = self.tokens_recorded + max(0, estimated_input) + max(0, out)
        if worst_case > self.max_total_tokens:
            raise BudgetStop(
                f"TOKEN_CEILING:worst_case={worst_case}>{self.max_total_tokens}", self.snapshot()
            )
        self.calls_reserved += 1
        reservation = ProviderReservation(
            index=self.calls_reserved,
            operation=operation,
            estimated_input=max(0, estimated_input),
            max_output=max(0, out),
            reserved_tokens=max(0, estimated_input) + max(0, out),
        )
        self._outstanding = reservation
        return reservation

    def record_actual(
        self,
        reservation: ProviderReservation,
        input_tokens: int | None,
        output_tokens: int | None,
    ) -> ProviderAttemptUsage:
        """Settle a reservation with the provider-reported usage (or UNKNOWN if unavailable).

        A rejected/failed call still consumes its call slot and MUST be settled — passing ``None``
        for either token count marks the campaign usage incomplete (``usage_complete=False``) so a
        subsequent :meth:`reserve` fails closed rather than assuming the missing usage was zero.
        """

        if self._outstanding is None or self._outstanding.index != reservation.index:
            raise BudgetStop("RESERVATION_MISMATCH", self.snapshot())
        reservation.settled = True
        self._outstanding = None
        self.calls_recorded += 1
        known = input_tokens is not None and output_tokens is not None
        total: int | None
        if known:
            assert input_tokens is not None and output_tokens is not None
            total = max(0, input_tokens) + max(0, output_tokens)
            self.tokens_recorded += total
        else:
            total = None
            self.usage_complete = False
        attempt = ProviderAttemptUsage(
            index=reservation.index,
            operation=reservation.operation,
            reserved_tokens=reservation.reserved_tokens,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total,
            known=known,
        )
        self.attempts.append(attempt)
        return attempt

    def within_ceilings(self) -> bool:
        """True iff every recorded call stayed within the call and (known) token ceilings."""

        return (
            self.calls_recorded <= self.max_provider_calls
            and self.tokens_recorded <= self.max_total_tokens
        )

    def snapshot(self) -> dict[str, Any]:
        return {
            "max_provider_calls": self.max_provider_calls,
            "max_total_tokens": self.max_total_tokens,
            "per_call_output_ceiling": self.per_call_output_ceiling,
            "calls_reserved": self.calls_reserved,
            "calls_recorded": self.calls_recorded,
            "tokens_recorded": self.tokens_recorded,
            "tokens_remaining": self.max_total_tokens - self.tokens_recorded,
            "calls_remaining": self.max_provider_calls - self.calls_reserved,
            "usage_complete": self.usage_complete,
            "within_ceilings": self.within_ceilings(),
            "outstanding_reservation": (
                self._outstanding.index if self._outstanding is not None else None
            ),
        }

    def attempts_export(self) -> list[dict[str, Any]]:
        return [
            {
                "index": a.index,
                "operation": a.operation,
                "reserved_tokens": a.reserved_tokens,
                "input_tokens": a.input_tokens if a.input_tokens is not None else "UNKNOWN",
                "output_tokens": a.output_tokens if a.output_tokens is not None else "UNKNOWN",
                "total_tokens": a.total_tokens if a.total_tokens is not None else "UNKNOWN",
                "usage_known": a.known,
            }
            for a in self.attempts
        ]
