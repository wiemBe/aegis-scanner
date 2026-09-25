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

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from aegis.container_acceptance.contracts import (
    ContainerAcceptanceError,
    ContainerRunResult,
    SqlmapTrafficEvidence,
)
from aegis.container_acceptance.network import InternalRange
from aegis.container_acceptance.runner import run_tool
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


class SqlmapContainerWorker:
    """Runs the controller-rendered SQLMap job in a container and normalizes its own traffic."""

    def __init__(self, job: SqlmapInjectionJob, range_: InternalRange) -> None:
        self._job = job
        self._range = range_

    def run(self) -> SqlmapWorkerOutput:
        exec_id = f"sqlx-{uuid4().hex[:16]}"
        volume = self._range.create_output_volume(exec_id)
        started_at = datetime.now(UTC).isoformat()
        raw = run_tool(
            image_reference=self._job.image_ref,
            argv=self._job.argv,
            network=self._range.network,
            label=self._range.label,
            output_limit_bytes=self._job.max_output_bytes,
            timeout_seconds=max(60, self._job.per_request_timeout_ms // 1000 * 12),
            volumes=((volume, "/out"),),
        )
        finished_at = datetime.now(UTC).isoformat()
        # Route SQLMap's real stdout through the preserved production sanitizer (bound + redact).
        sanitize_sqlmap_output(
            raw.stdout.encode("utf-8", "replace"), max_bytes=self._job.max_output_bytes
        )
        injectable, _printed = parse_injectable_claim(raw.stdout)

        traffic_text = self._range.read_volume_file(volume, "/out/traffic.txt")
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
            run_result=raw.result,
            tool_reported_injectable=injectable,
            control_counts=control_counts,
        )
