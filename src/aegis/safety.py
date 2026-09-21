from urllib.parse import urljoin, urlsplit

from aegis.models import Hypothesis, PlannedRequest
from aegis.settings import Settings
from aegis.surface import OBJECTS, Variant, account_path
from aegis_nuclei.targets import NUCLEI_TARGETS
from aegis_zap.inventory import ZAP_TARGETS
from aegis_zap.projection import project
from aegis_zap_active.inventory import ZAP_ACTIVE_TARGETS


class SafetyViolation(ValueError):
    pass


class SafetyController:
    """The only component allowed to approve target network actions."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def validate_absolute_url(self, url: str) -> None:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"}:
            raise SafetyViolation("Only HTTP(S) targets are supported")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise SafetyViolation("Credentials, query and fragment in URLs are forbidden")
        if (parsed.hostname or "").lower() not in self.settings.allowed_hosts:
            raise SafetyViolation("Host is outside the exact allowlist")
        base = urlsplit(self.settings.lab_base_url)
        if (parsed.scheme, parsed.hostname, parsed.port) != (base.scheme, base.hostname, base.port):
            raise SafetyViolation("Request escaped the approved target origin")

    def approve_import(self) -> str:
        url = self.settings.lab_openapi_url
        self.validate_absolute_url(url)
        if urlsplit(url).path != "/openapi.json":
            raise SafetyViolation("Only the lab OpenAPI document can be imported")
        return url

    def approve_plan(
        self,
        base_url: str,
        hypotheses: list[Hypothesis],
        *,
        variant: Variant = "vulnerable",
        used_requests: int = 0,
        used_names: frozenset[str] = frozenset(),
        imported_paths: frozenset[str] | None = None,
    ) -> list[str]:
        self.validate_absolute_url(base_url)
        requests = [r for h in hypotheses for r in h.requests]
        if len(requests) + used_requests > self.settings.max_requests_per_scan:
            raise SafetyViolation("Planner exceeded the per-scan request budget")
        names = [r.name for r in requests]
        if len(names) != len(set(names)) or used_names.intersection(names):
            raise SafetyViolation("Request names must be unique across the scan")
        if imported_paths is not None and account_path(variant) not in imported_paths:
            raise SafetyViolation("Request is not present in the imported surface")
        events: list[str] = []
        for request in requests:
            self.approve_request(base_url, request, variant)
            events.append(
                f"APPROVED {request.method} {request.path} as {request.credential_profile}"
            )
        return events

    def approve_request(
        self,
        base_url: str,
        request: PlannedRequest,
        variant: Variant = "vulnerable",
    ) -> str:
        # Revalidate even typed objects: callers can construct or copy unchecked Pydantic models.
        request = PlannedRequest.model_validate(request.model_dump())
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            raise SafetyViolation("State-changing HTTP methods are forbidden")
        permitted = {account_path(variant).replace("{account_id}", obj) for obj in OBJECTS}
        if request.path not in permitted:
            raise SafetyViolation("Request is outside the authorized synthetic object surface")
        absolute_url = urljoin(base_url.rstrip("/") + "/", request.path.lstrip("/"))
        self.validate_absolute_url(absolute_url)
        return absolute_url

    def approve_scm_verification(self, base_url: str, path: str) -> str:
        """Approve ONE of the fixed Phase 1.2 verifier requests (a synthetic route base or its
        ``/.git/config``). Anything else — another path, host or scheme — is a SafetyViolation."""

        permitted = {
            candidate
            for target in NUCLEI_TARGETS.values()
            if target.origin.rstrip("/") == base_url.rstrip("/")
            for candidate in (target.base_path, f"{target.base_path}/.git/config")
        }
        if path not in permitted:
            raise SafetyViolation("Verifier request is outside the fixed synthetic SCM surface")
        absolute_url = base_url.rstrip("/") + path
        self.validate_absolute_url(absolute_url)
        return absolute_url

    def approve_zap_verification(self, base_url: str, path: str) -> str:
        """Approve ONE of the fixed Phase 1.3 verifier requests: the control or scenario operation
        of an ACCEPTANCE inventory target. Negative-control routes, any other path, host or scheme
        is a SafetyViolation."""

        permitted = {
            op.path
            for target in ZAP_TARGETS.values()
            if target.purpose == "ACCEPTANCE"
            and target.origin.rstrip("/") == base_url.rstrip("/")
            for op in project(target).operations
            if op.method == "GET"
            and op.operation_id in {target.control_operation_id, target.scenario_operation_id}
        }
        if path not in permitted:
            raise SafetyViolation("Verifier request is outside the fixed synthetic ZAP surface")
        absolute_url = base_url.rstrip("/") + path
        self.validate_absolute_url(absolute_url)
        return absolute_url

    def approve_zap_active_verification(self, base_url: str, path: str) -> str:
        """Approve the fixed Phase 1.5 verifier request: the projected search path of an ACCEPTANCE
        active target. The verifier supplies the ``q`` marker as a query parameter separately; any
        other path, host or scheme is a SafetyViolation."""

        permitted = {
            target.search_path
            for target in ZAP_ACTIVE_TARGETS.values()
            if target.purpose == "ACCEPTANCE"
            and target.origin.rstrip("/") == base_url.rstrip("/")
        }
        if path not in permitted:
            raise SafetyViolation("Verifier request is outside the fixed synthetic active surface")
        absolute_url = base_url.rstrip("/") + path
        self.validate_absolute_url(absolute_url)
        return absolute_url
