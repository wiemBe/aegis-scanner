"""Containerized SQLMap injection worker for Phase 2.8-C.

Runs the *controller-rendered* SQLMap argv (from the preserved Phase 2.8-B ``build_sqlmap_job``,
with a controller seed + traffic capture) in a bounded, pinned container against the internal range,
returns evidence derived from **SQLMap's own captured request/response traffic** — never from a
helper probe.

The worker also issues the OR-style control/TRUE/FALSE probes, but these are returned ONLY as a
separate scenario control (proving the fixture itself is genuinely vulnerable/patched); they are not
the SQLMap functional evidence and are never fed to the functional verifier. SQLMap's textual
"injectable" statement is parsed for audit only.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from aegis.container_acceptance.contracts import (
    ContainerAcceptanceError,
    ContainerRunResult,
    SqlmapBudgetOutcome,
    SqlmapTrafficEvidence,
)
from aegis.container_acceptance.network import InternalRange
from aegis.container_acceptance.sqlmap_budget import run_sqlmap_with_budget
from aegis.container_acceptance.sqlmap_traffic import normalize_sqlmap_traffic
from aegis.multi_agent.sqlmap_capability import SqlmapInjectionJob, sanitize_sqlmap_output

# The canonical OR-style boolean differential — issued ONLY as a separate scenario control.
CONTROL_QUERY = "Notebook"
BOOLEAN_TRUE_PAYLOAD = "%' OR 1=1 --"
BOOLEAN_FALSE_PAYLOAD = "%' AND 1=2 --"

# The controller baseline seed the SQLMap job is composed with (a value returning a stable non-empty
# baseline so the pinned SQLMap can honestly exhibit a boolean differential).
SQLMAP_SEED_VALUE = "Notebook"

_NOT_INJECTABLE = re.compile(
    r"do(es)? not (seem|appear) to be injectable|all tested parameters do not appear", re.I
)
_INJECTABLE = re.compile(r"identified the following injection point", re.I)
_TOTAL_REQUESTS = re.compile(r"total of (\d+) HTTP", re.I)


def parse_injectable_claim(text: str) -> tuple[bool, int]:
    """Parse SQLMap's OWN audit-only claim + printed request total. Never a verifier input."""

    injectable = bool(_INJECTABLE.search(text)) and not _NOT_INJECTABLE.search(text)
    total_match = _TOTAL_REQUESTS.search(text)
    return injectable, int(total_match.group(1)) if total_match else 0


@dataclass(frozen=True)
class SqlmapWorkerOutput:
    traffic_evidence: SqlmapTrafficEvidence
    run_result: ContainerRunResult
    tool_reported_injectable: bool
    control_counts: dict[str, tuple[int, int]]  # name -> (status, row_count)
    budget: SqlmapBudgetOutcome


class SqlmapContainerWorker:
    """Runs the controller-rendered SQLMap job in a container and normalizes its own traffic.

    Execution is under the controller-owned hard request/duration budget: the SQLMap process is
    killed deterministically if it reaches ``max_http_requests`` or ``max_duration_seconds``."""

    def __init__(
        self,
        job: SqlmapInjectionJob,
        range_: InternalRange,
        *,
        max_http_requests: int,
        max_duration_seconds: int,
    ) -> None:
        self._job = job
        self._range = range_
        self._max_http_requests = max_http_requests
        self._max_duration_seconds = max_duration_seconds

    def run(self) -> SqlmapWorkerOutput:
        exec_id = f"sqlx-{uuid4().hex[:16]}"
        started_at = datetime.now(UTC).isoformat()
        budgeted = run_sqlmap_with_budget(
            self._range,
            image_ref=self._job.image_ref,
            argv=self._job.argv,
            exec_id=exec_id,
            max_http_requests=self._max_http_requests,
            max_duration_seconds=self._max_duration_seconds,
        )
        finished_at = datetime.now(UTC).isoformat()
        # Route SQLMap's real stdout through the preserved production sanitizer (bound + redact).
        sanitize_sqlmap_output(
            budgeted.stdout.encode("utf-8", "replace"), max_bytes=self._job.max_output_bytes
        )
        injectable, _printed = parse_injectable_claim(budgeted.stdout)

        combined = budgeted.stdout.encode("utf-8", "replace")
        run_result = ContainerRunResult(
            image_reference=self._job.image_ref,
            argv_sha256=hashlib.sha256("\x00".join(self._job.argv).encode()).hexdigest(),
            exit_code=budgeted.exit_code,
            timed_out=budgeted.outcome.stop_reason.value == "DURATION_CEILING",
            duration_ms=round(budgeted.outcome.elapsed_seconds * 1000),
            stdout_digest=hashlib.sha256(combined).hexdigest(),
            output_bytes=len(combined),
            output_truncated=len(combined) > self._job.max_output_bytes,
        )

        traffic_text = budgeted.traffic_text
        if not traffic_text.strip():
            raise ContainerAcceptanceError("SQLMAP_TRAFFIC_NOT_CAPTURED")
        evidence = normalize_sqlmap_traffic(
            traffic_text,
            job_id=self._job.job_id,
            process_exec_id=exec_id,
            tool_version=self._job.tool_version,
            image_id=self._job.image_digest,
            target_operation=self._job.target_url.split("?", 1)[0],
            parameter=self._job.parameter,
            seed_value=SQLMAP_SEED_VALUE,
            started_at=started_at,
            finished_at=finished_at,
        )

        # Separate scenario control (NOT a SQLMap functional input): OR-style boolean probes.
        control_counts = {
            "control": self._range.probe_count(CONTROL_QUERY),
            "boolean_true": self._range.probe_count(BOOLEAN_TRUE_PAYLOAD),
            "boolean_false": self._range.probe_count(BOOLEAN_FALSE_PAYLOAD),
        }
        return SqlmapWorkerOutput(
            traffic_evidence=evidence,
            run_result=run_result,
            tool_reported_injectable=injectable,
            control_counts=control_counts,
            budget=budgeted.outcome,
        )
