"""Production normalizer for SQLMap-originated traffic (Phase 2.8-C correction).

Parses the request/response log SQLMap itself writes (``-t traffic.txt``) and derives the candidate
result-set differential from **SQLMap's own** requests — never from a separate helper probe. Each
record is reduced to bounded, redacted facts (a ``modified`` flag, the response row count, and
request/response sha256 digests); the raw injected payloads and response bodies are never retained.
The differential (unmodified baseline vs the max/min rows across SQLMap's injected requests) is what
the independent verifier adjudicates. SQLMap's textual "injectable" claim is parsed elsewhere and is
audit-only.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

from aegis.container_acceptance.contracts import (
    SqlmapTrafficEvidence,
    SqlmapTrafficObservation,
)

_REQUEST_SPLIT = re.compile(r"HTTP request \[#\d+\]:")
_GET_LINE = re.compile(r"GET (/\S*) HTTP/")
_STATUS_LINE = re.compile(r"HTTP/\d(?:\.\d)? (\d{3})")
_PRODUCTS_BODY = re.compile(r"\{\"products\":\[.*?\]\}", re.S)


@dataclass(frozen=True)
class _Record:
    modified: bool
    status_code: int
    row_count: int
    request_digest: str
    response_digest: str


def _row_count(body: str) -> int:
    try:
        parsed = json.loads(body)
    except ValueError:
        return body.count("product_id")
    products = parsed.get("products") if isinstance(parsed, dict) else None
    return len(products) if isinstance(products, list) else 0


def _parse_records(traffic: str, *, parameter: str, seed_value: str) -> list[_Record]:
    records: list[_Record] = []
    for block in _REQUEST_SPLIT.split(traffic):
        get = _GET_LINE.search(block)
        if not get:
            continue
        request_line = get.group(1)
        query = parse_qs(urlsplit(request_line).query)
        values = query.get(parameter)
        if not values:
            continue
        q_value = values[0]
        status_match = _STATUS_LINE.search(block)
        status = int(status_match.group(1)) if status_match else 0
        if not (100 <= status <= 599):
            status = 0
        body_match = _PRODUCTS_BODY.search(block)
        body = body_match.group(0) if body_match else ""
        records.append(
            _Record(
                modified=(q_value != seed_value),
                status_code=status or 200,
                row_count=_row_count(body),
                request_digest=hashlib.sha256(request_line.encode()).hexdigest(),
                response_digest=hashlib.sha256(body.encode()).hexdigest(),
            )
        )
    return records


def normalize_sqlmap_traffic(
    traffic_text: str,
    *,
    job_id: str,
    process_exec_id: str,
    tool_version: str,
    image_id: str,
    target_operation: str,
    parameter: str,
    seed_value: str,
    started_at: str,
    finished_at: str,
) -> SqlmapTrafficEvidence:
    """Normalize SQLMap's captured traffic into correlated, redacted differential evidence."""

    records = _parse_records(traffic_text, parameter=parameter, seed_value=seed_value)
    baseline = [r.row_count for r in records if not r.modified]
    injected = [r.row_count for r in records if r.modified]
    control_row_count = max(baseline) if baseline else -1
    injected_max = max(injected) if injected else -1
    injected_min = min(injected) if injected else -1

    observations = [
        SqlmapTrafficObservation(
            sequence=i,
            modified=r.modified,
            status_code=r.status_code,
            row_count=r.row_count,
            request_digest=r.request_digest,
            response_digest=r.response_digest,
        )
        for i, r in enumerate(records[:32])
    ]
    digest_material = json.dumps(
        [
            {
                "seq": o.sequence, "modified": o.modified, "status": o.status_code,
                "rows": o.row_count, "req": o.request_digest, "resp": o.response_digest,
            }
            for o in observations
        ],
        sort_keys=True,
    ).encode()
    return SqlmapTrafficEvidence(
        job_id=job_id,
        process_exec_id=process_exec_id,
        tool_version=tool_version,
        image_id=image_id,
        target_operation=target_operation,
        parameter=parameter,
        started_at=started_at,
        finished_at=finished_at,
        request_count=len(records),
        control_row_count=control_row_count,
        injected_request_count=len(injected),
        injected_max_row_count=injected_max,
        injected_min_row_count=injected_min,
        evidence_digest=hashlib.sha256(digest_material).hexdigest(),
        observations=observations,
    )
