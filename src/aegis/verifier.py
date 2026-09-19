from aegis.models import Finding, Hypothesis, RequestEvidence, Verification
from aegis.surface import OBJECTS, PROFILE_ACTORS, Variant, account_path


class DeterministicVerifier:
    """Only local fixture ownership and bound executor evidence can prove lab BOLA."""

    def _bound(
        self,
        hypotheses: list[Hypothesis],
        evidence: list[RequestEvidence],
        variant: Variant,
    ) -> list[RequestEvidence]:
        planned = {r.name: r for h in hypotheses if h.category == "BOLA" for r in h.requests}
        if len({e.name for e in evidence}) != len(evidence):
            return []
        matched = []
        for item in evidence:
            request = planned.get(item.name)
            if (
                request is not None
                and item.method == request.method == "GET"
                and item.path == request.path
                and item.credential_profile == request.credential_profile
                and item.path
                in {account_path(variant).replace("{account_id}", obj) for obj in OBJECTS}
                and not item.error
            ):
                matched.append(item)
        return matched

    def _identity(self, item: RequestEvidence) -> bool:
        body = item.response_excerpt
        obj = item.path.rsplit("/", 1)[-1]
        return (
            item.status_code == 200
            and isinstance(body, dict)
            and body.get("account_id") == obj
            and body.get("owner_id") == OBJECTS.get(obj)
        )

    def verify(
        self,
        hypotheses: list[Hypothesis],
        evidence: list[RequestEvidence],
        variant: Variant = "vulnerable",
        scan_id: str | None = None,
    ) -> list[Finding]:
        findings = []
        for item in self._bound(hypotheses, evidence, variant):
            actor = PROFILE_ACTORS.get(item.credential_profile)
            obj = item.path.rsplit("/", 1)[-1]
            if actor and self._identity(item) and actor != OBJECTS[obj]:
                findings.append(
                    Finding(
                        # Namespacing by the controller-assigned scan id makes this stable within
                        # a scan and fresh across demo runs. Direct verifier use may omit scan_id
                        # and retains the historical evidence-derived shape.
                        id=(
                            f"finding-{scan_id}-{item.name}"
                            if scan_id is not None
                            else f"finding-{item.name}"
                        ),
                        title="Broken Object Level Authorization in account lookup",
                        severity="HIGH",
                        category="API1:2023 BOLA",
                        confidence="CONFIRMED",
                        description=(
                            f"Synthetic principal {actor} read {obj}, owned by {OBJECTS[obj]}."
                        ),
                        remediation="Enforce authenticated object ownership before serialization.",
                        evidence_names=[item.name],
                    )
                )
        return findings

    def evaluate(
        self,
        hypotheses: list[Hypothesis],
        evidence: list[RequestEvidence],
        variant: Variant,
    ) -> Verification:
        findings = self.verify(hypotheses, evidence, variant)
        if findings:
            return Verification(
                status="CONFIRMED",
                summary="Cross-owner synthetic read confirmed.",
                evidence_names=[n for f in findings for n in f.evidence_names],
            )
        matched = self._bound(hypotheses, evidence, variant)
        # A denial alone, 404, timeout, empty plan or unsupported category never establishes PASS.
        controls = {
            e.credential_profile: e
            for e in matched
            if self._identity(e)
            and PROFILE_ACTORS.get(e.credential_profile) == OBJECTS[e.path.rsplit("/", 1)[-1]]
        }
        for probe in matched:
            obj = probe.path.rsplit("/", 1)[-1]
            actor = PROFILE_ACTORS.get(probe.credential_profile)
            owner_profile = next((p for p, a in PROFILE_ACTORS.items() if a == OBJECTS[obj]), None)
            body = probe.response_excerpt
            if (
                probe.status_code == 403
                and actor
                and actor != OBJECTS[obj]
                and isinstance(body, dict)
                and body == {"detail": "Forbidden"}
                and probe.credential_profile in controls
                and owner_profile in controls
                and controls[owner_profile].path == probe.path
                and len(matched) == len(evidence)
                and all(
                    (
                        e.status_code == 200
                        and self._identity(e)
                        and e.credential_profile in controls
                    )
                    or (e.status_code == 403 and e.response_excerpt == {"detail": "Forbidden"})
                    for e in matched
                )
            ):
                return Verification(
                    status="PASS",
                    summary="Scoped PASS: owner controls succeed; cross-owner read denied.",
                    evidence_names=[
                        controls[probe.credential_profile].name,
                        controls[owner_profile].name,
                        probe.name,
                    ],
                )
        return Verification(
            status="INSUFFICIENT",
            summary="Fresh owner controls and a conclusive cross-owner probe are required.",
        )
