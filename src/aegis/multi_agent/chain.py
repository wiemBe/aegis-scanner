"""Phase 1.7-B chain contract and validation.

A chain composes *already-registered* bounded capabilities within a single authorized target
scope. It never acquires a new capability, never self-recurses, and a failed step never becomes
permission to broaden scope. Terminal verification is an independent controller action, not a
model-selectable capability, so it never appears in a chain step.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from aegis.multi_agent.contracts import StrictModel

MAX_CHAIN_STEPS = 5

# Honest capability label: this composes recon -> injection -> independent verification as a
# delegation workflow. It is NOT a multi-primitive attack chain (which would combine two or more
# independently verified vulnerability primitives into a distinct controller-verified effect) and
# it does NOT complete any Phase 1.6 range attack chain.
CHAIN_CLASS = "DELEGATION_WORKFLOW_CHAIN"

# Registered capabilities a chain step may reference. Terminal verification is intentionally absent.
_RECON_CAPABILITY = "aegis.surface.openapi"
_INJECTION_CAPABILITIES: frozenset[str] = frozenset(
    {"aegis.injection.xss_reflected", "aegis.injection.sql_boolean"}
)
_CHAIN_CAPABILITIES: frozenset[str] = frozenset({_RECON_CAPABILITY}) | _INJECTION_CAPABILITIES


class ChainValidationError(ValueError):
    """Raised when a chain plan escapes depth, transition, or scope bounds."""


class ChainStep(StrictModel):
    capability: Literal[
        "aegis.surface.openapi",
        "aegis.injection.xss_reflected",
        "aegis.injection.sql_boolean",
    ]
    input_from: str | None = Field(default=None, pattern=r"^step-[0-9]$")


class ChainPlanOutput(StrictModel):
    """Model-authored chain. Bounded to registered capabilities and a small step budget."""

    steps: list[ChainStep] = Field(min_length=1, max_length=MAX_CHAIN_STEPS)


def validate_chain(plan: ChainPlanOutput) -> None:
    """Enforce depth, the recon->injection transition, single scope, and no recursion."""

    if len(plan.steps) > MAX_CHAIN_STEPS:
        raise ChainValidationError("CHAIN_MAX_DEPTH_EXCEEDED")
    for index, step in enumerate(plan.steps):
        position = index + 1
        if step.capability not in _CHAIN_CAPABILITIES:
            raise ChainValidationError("CHAIN_CAPABILITY_NOT_REGISTERED")
        if index == 0:
            if step.capability != _RECON_CAPABILITY:
                raise ChainValidationError("CHAIN_MUST_START_WITH_RECON")
            if step.input_from is not None:
                raise ChainValidationError("CHAIN_FIRST_STEP_HAS_NO_INPUT")
            continue
        # After recon, only injection probes are a legal transition.
        if step.capability == _RECON_CAPABILITY:
            raise ChainValidationError("CHAIN_ILLEGAL_TRANSITION")
        if step.capability not in _INJECTION_CAPABILITIES:
            raise ChainValidationError("CHAIN_ILLEGAL_TRANSITION")
        if step.input_from is None:
            raise ChainValidationError("CHAIN_STEP_MISSING_INPUT")
        source = int(step.input_from.split("-", 1)[1])
        if source < 1 or source >= position:
            # A step may only consume the output of an earlier step; self/forward references and
            # any recursive dependency are rejected.
            raise ChainValidationError("CHAIN_INPUT_NOT_EARLIER_STEP")
