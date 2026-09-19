"""Registered deterministic verifier / tool capabilities (Contract V3, Part B.7).

A capability is a read-only test type that the DETERMINISTIC verifier can actually evaluate. The
registry is the single source of truth for which candidate ``test_type`` + ``capability`` pairs are
legal, and it is projected to the model so it can only name real capabilities. The projection never
selects a capability on the model's behalf; the model must choose one, and deterministic validation
rejects any candidate whose capability is unregistered or state-changing.

Only capabilities the verifier can confirm are registered. The deterministic verifier currently
confirms object-level authorization (BOLA) via a read-only object read comparison, so that is the
only registered capability. AUTHN/EXPOSURE have no registered deterministic verifier capability yet,
so a candidate naming them is rejected rather than silently accepted — an honest, fail-closed stance
that keeps generation within what the verifier can actually prove.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Capability:
    """A registered read-only test capability backed by the deterministic verifier."""

    id: str
    test_type: str
    title: str
    # Read-only HTTP methods this capability may use. Every registered capability is read-only.
    methods: tuple[str, ...] = ("GET", "HEAD", "OPTIONS")
    read_only: bool = True
    verifier: str = "deterministic"

    def projection(self) -> dict[str, object]:
        """Non-sensitive projection handed to the model. No behaviour, no attack sequence."""
        return {
            "id": self.id,
            "test_type": self.test_type,
            "title": self.title,
            "methods": list(self.methods),
            "read_only": self.read_only,
        }


# The one capability the deterministic verifier can confirm today. Adding a capability here requires
# a matching deterministic verifier path; nothing else in the control plane branches on it.
CAPABILITY_REGISTRY: tuple[Capability, ...] = (
    Capability(
        id="bola_object_read_v1",
        test_type="BOLA",
        title="Object-level authorization read comparison",
    ),
)

_BY_ID: dict[str, Capability] = {c.id: c for c in CAPABILITY_REGISTRY}


def get_capability(capability_id: str) -> Capability | None:
    return _BY_ID.get(capability_id)


def registered_ids() -> frozenset[str]:
    return frozenset(_BY_ID)


def registered_test_types() -> frozenset[str]:
    return frozenset(c.test_type for c in CAPABILITY_REGISTRY)


def registered_methods() -> frozenset[str]:
    methods: set[str] = set()
    for capability in CAPABILITY_REGISTRY:
        methods.update(capability.methods)
    return frozenset(methods)


def projection() -> list[dict[str, object]]:
    return [c.projection() for c in CAPABILITY_REGISTRY]


@dataclass(frozen=True)
class Operation:
    """An approved operation on the projected surface. ``read_only`` False means state-changing;
    such an operation is never a legal candidate target (fail-closed at validation)."""

    operation_id: str
    method: str
    path_template: str
    read_only: bool
    object_parameter: str | None = None
    objects: tuple[str, ...] = field(default_factory=tuple)

    def projection(self) -> dict[str, object]:
        return {
            "operation_id": self.operation_id,
            "method": self.method,
            "read_only": self.read_only,
            "object_parameter": self.object_parameter,
            "objects": list(self.objects),
        }
