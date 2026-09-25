"""Containerized SQLMap injection worker for Phase 2.8.

The worker runs the *controller-rendered* SQLMap argv (from the preserved Phase 2.8-B
``build_sqlmap_job``) in a bounded, pinned container against the internal range, and produces the
normalized boolean-differential :class:`SqlmapWorkerEvidence` the independent verifier adjudicates.

Two kinds of real worker traffic, both on the internal no-egress network:

* the real SQLMap binary run — its actual stdout/stderr and HTTP request observations, routed
  through the preserved production normalizer (``sanitize_sqlmap_output``). SQLMap's own
  "injectable" statement is parsed and recorded for audit ONLY; it is never a verifier input.
* the boolean-based differential the technique rests on — one benign control query, one boolean-TRUE
  and one boolean-FALSE probe — issued from a helper on the internal network and normalized into the
  evidence's result-count slots.
"""

from __future__ import annotations

import re

from aegis.container_acceptance.contracts import ContainerAcceptanceError, ContainerRunResult
from aegis.container_acceptance.network import InternalRange
from aegis.container_acceptance.runner import run_tool
from aegis.multi_agent.sqlmap_capability import (
    SqlmapInjectionJob,
    SqlmapResultSlot,
    SqlmapWorkerEvidence,
    sanitize_sqlmap_output,
)

# The canonical boolean-based differential probes. Identical to the preserved 2.8-B offline worker
# double, but issued as REAL HTTP over the internal network by the containerized worker.
CONTROL_QUERY = "Notebook"
BOOLEAN_TRUE_PAYLOAD = "%' OR 1=1 --"
BOOLEAN_FALSE_PAYLOAD = "%' AND 1=2 --"

_NOT_INJECTABLE = re.compile(
    r"do(es)? not (seem|appear) to be injectable|all tested parameters do not appear", re.I
)
_INJECTABLE = re.compile(r"identified the following injection point", re.I)
_TOTAL_REQUESTS = re.compile(r"total of (\d+) HTTP", re.I)
_TYPE_LINE = re.compile(r"^\s*Type:\s*(.+?)\s*$", re.M)


def parse_sqlmap_stdout(text: str) -> tuple[bool, int, list[str]]:
    """Parse SQLMap stdout for its audit-only claim, total request count, and reported types.

    ``tool_reported_injectable`` is SQLMap's OWN conclusion; it is recorded for audit and is never a
    verifier input."""

    injectable = bool(_INJECTABLE.search(text)) and not _NOT_INJECTABLE.search(text)
    total_match = _TOTAL_REQUESTS.search(text)
    total = int(total_match.group(1)) if total_match else 0
    types = [m.strip()[:60] for m in _TYPE_LINE.findall(text)][:8]
    return injectable, total, types


class SqlmapContainerWorker:
    """Runs the controller-rendered SQLMap job in a container and normalizes its evidence."""

    def __init__(self, job: SqlmapInjectionJob, range_: InternalRange) -> None:
        self._job = job
        self._range = range_

    def run(self) -> tuple[SqlmapWorkerEvidence, ContainerRunResult, list[str]]:
        # 1) Real SQLMap binary run (controller-rendered argv, pinned image, bounded).
        raw = run_tool(
            image_reference=self._job.image_ref,
            argv=self._job.argv,
            network=self._range.network,
            label=self._range.label,
            output_limit_bytes=self._job.max_output_bytes,
            timeout_seconds=max(30, self._job.per_request_timeout_ms // 1000 * 8),
        )
        # Route SQLMap's real stdout through the preserved production normalizer (bound + redact).
        _safe_text, _truncated = sanitize_sqlmap_output(
            raw.stdout.encode("utf-8", "replace"), max_bytes=self._job.max_output_bytes
        )
        injectable, total_requests, reported_types = parse_sqlmap_stdout(raw.stdout)

        # 2) The boolean-based differential (real worker traffic on the internal network).
        control_status, control_count = self._range.probe_count(CONTROL_QUERY)
        true_status, true_count = self._range.probe_count(BOOLEAN_TRUE_PAYLOAD)
        false_status, false_count = self._range.probe_count(BOOLEAN_FALSE_PAYLOAD)
        if control_count < 0 or true_count < 0 or false_count < 0:
            raise ContainerAcceptanceError("WORKER_PROBE_NON_JSON_RESPONSE")

        evidence = SqlmapWorkerEvidence(
            job_id=self._job.job_id,
            parameter=self._job.parameter,
            control=SqlmapResultSlot(status_code=control_status, result_count=control_count),
            boolean_true=SqlmapResultSlot(status_code=true_status, result_count=true_count),
            boolean_false=SqlmapResultSlot(status_code=false_status, result_count=false_count),
            # SQLMap's own inference — recorded for audit, NEVER a verdict input.
            tool_reported_injectable=injectable,
            sanitized_note=(
                f"containerized SQLMap run + boolean differential; requests={total_requests}; "
                f"types={','.join(reported_types) or 'none'}"
            )[:300],
        )
        return evidence, raw.result, reported_types
