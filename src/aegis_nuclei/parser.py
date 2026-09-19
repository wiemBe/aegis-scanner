"""Strict, versioned parser for Nuclei v3.11.1 JSONL output.

Nuclei output is UNTRUSTED. This parser accepts only a small allowlisted field set, cross-checks
every record against the admitted template set and the inventory-resolved target, strips fields
that could carry sensitive material, and REFUSES output carrying raw request/response data.

Fail-closed outcomes (never PASS, never a confirmed finding):

- ``OVERSIZED``  total bytes, line count or a single line exceeds its bound;
- ``TRUNCATED``  non-empty output that does not end on a line boundary;
- ``MALFORMED``  invalid UTF-8/JSON, duplicate JSON keys, unknown or refused fields, unexpected
  template id/path/origin/URL/matcher, conflicting records for one identity;
- ``EMPTY``      no records at all (with ``-matcher-status`` a completed check always emits one).

Record digests are computed over the normalized record WITHOUT timestamps, so identical tool
observations always yield identical, stable evidence ids.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis_nuclei.contracts import (
    ErrorClass,
    NucleiResultRecord,
    ParseStatus,
    ParseSummary,
    RunnerErrorCode,
)
from aegis_nuclei.manifest import TemplateEntry
from aegis_nuclei.targets import NucleiTarget, origin_parts

PARSER_VERSION = "nuclei-jsonl-parser/1.2.0"
MAX_LINE_BYTES = 16_384

# Every key Nuclei may legitimately emit for an http template under the fixed profile.
_ALLOWED_KEYS = frozenset(
    {
        "template-id",
        "template-path",
        "template-url",
        "info",
        "type",
        "host",
        "port",
        "scheme",
        "url",
        "path",
        "matched-at",
        "ip",
        "timestamp",
        "curl-command",
        "matcher-status",
        "matcher-name",
        "error",
        "extracted-results",
    }
)
# Keys whose presence means raw request/response or out-of-band data leaked through the profile.
_REFUSED_KEYS = frozenset(
    {"request", "response", "template-encoded", "interaction", "meta", "lines", "extractor-name"}
)
# Accepted but never propagated: they can carry headers, addresses or extracted values.
_STRIPPED_KEYS = frozenset({"curl-command", "ip", "template-url", "extracted-results"})
_TIMESTAMP = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$")
_UNREACHABLE = ("port closed", "connection refused", "no address", "no such host", "unreachable")
_TIMEOUTS = ("timeout", "deadline exceeded", "i/o timeout")


class _Reject(Exception):
    def __init__(self, status: ParseStatus, code: RunnerErrorCode) -> None:
        super().__init__(code.value)
        self.status = status
        self.code = code


@dataclass(frozen=True)
class ParseOutcome:
    summary: ParseSummary
    results: tuple[NucleiResultRecord, ...]
    coverage_complete: bool


@dataclass(frozen=True)
class AdmittedTemplate:
    entry: TemplateEntry
    absolute_path: Path


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise _Reject("MALFORMED", RunnerErrorCode.OUTPUT_MALFORMED)
    match = _TIMESTAMP.match(value)
    if not match:
        raise _Reject("MALFORMED", RunnerErrorCode.OUTPUT_MALFORMED)
    base, fraction, zone = match.groups()
    micro = (fraction or ".0")[1:7].ljust(6, "0")
    zone = "+00:00" if zone == "Z" else zone
    return datetime.fromisoformat(f"{base}.{micro}{zone}").astimezone(UTC)


def _classify_error(value: Any) -> ErrorClass:
    if value is None:
        return "NONE"
    if not isinstance(value, str) or len(value) > 1000:
        raise _Reject("MALFORMED", RunnerErrorCode.OUTPUT_MALFORMED)
    lowered = value.lower()
    if any(marker in lowered for marker in _UNREACHABLE):
        return "TARGET_UNREACHABLE"
    if any(marker in lowered for marker in _TIMEOUTS):
        return "TIMEOUT"
    return "OTHER"


def expected_request_urls(entry: TemplateEntry, target: NucleiTarget) -> frozenset[str]:
    return frozenset(p.replace("{{BaseURL}}", target.target_url, 1) for p in entry.request_paths)


def _normalize(
    raw: dict[str, Any],
    admitted: dict[str, AdmittedTemplate],
    target: NucleiTarget,
    stripped: set[str],
) -> NucleiResultRecord:
    keys = set(raw)
    if keys & _REFUSED_KEYS:
        raise _Reject("MALFORMED", RunnerErrorCode.OUTPUT_MALFORMED)
    if keys - _ALLOWED_KEYS:
        raise _Reject("MALFORMED", RunnerErrorCode.OUTPUT_MALFORMED)
    stripped.update(keys & _STRIPPED_KEYS)

    template_id = raw.get("template-id")
    if not isinstance(template_id, str) or template_id not in admitted:
        raise _Reject("MALFORMED", RunnerErrorCode.OUTPUT_MALFORMED)
    item = admitted[template_id]
    entry = item.entry
    if raw.get("template-path") != str(item.absolute_path):
        raise _Reject("MALFORMED", RunnerErrorCode.OUTPUT_MALFORMED)
    if raw.get("type") != entry.protocol:
        raise _Reject("MALFORMED", RunnerErrorCode.OUTPUT_MALFORMED)

    scheme, host, port = origin_parts(target.origin)
    if (
        raw.get("scheme") != scheme
        or str(raw.get("host", "")).lower() != host
        or str(raw.get("port", "")) != str(port)
        or raw.get("url") != target.target_url
        or raw.get("path") != target.base_path
    ):
        raise _Reject("MALFORMED", RunnerErrorCode.OUTPUT_MALFORMED)

    info = raw.get("info")
    if not isinstance(info, dict):
        raise _Reject("MALFORMED", RunnerErrorCode.OUTPUT_MALFORMED)
    severity = str(info.get("severity", "")).lower()
    if info.get("name") != entry.name or severity != entry.expected_severity:
        raise _Reject("MALFORMED", RunnerErrorCode.OUTPUT_MALFORMED)

    matcher_status = raw.get("matcher-status")
    if not isinstance(matcher_status, bool):
        raise _Reject("MALFORMED", RunnerErrorCode.OUTPUT_MALFORMED)
    matcher_name = raw.get("matcher-name")
    if matcher_name is not None and matcher_name not in entry.allowed_matcher_names:
        raise _Reject("MALFORMED", RunnerErrorCode.OUTPUT_MALFORMED)

    matched_at = raw.get("matched-at")
    expected = expected_request_urls(entry, target)
    if matched_at is not None and matched_at not in expected:
        # A match reported against any URL other than the pinned request is an origin/scope
        # escape (redirect or rewritten path) and fails the whole output closed.
        raise _Reject("MALFORMED", RunnerErrorCode.OUTPUT_MALFORMED)
    if matcher_status and matched_at is None:
        raise _Reject("MALFORMED", RunnerErrorCode.OUTPUT_MALFORMED)
    checked_url = matched_at if isinstance(matched_at, str) else target.target_url
    checked_path = checked_url[len(target.origin) :]

    extracted = raw.get("extracted-results")
    if extracted is not None and (not isinstance(extracted, list) or len(extracted) > 64):
        raise _Reject("MALFORMED", RunnerErrorCode.OUTPUT_MALFORMED)
    error_class = _classify_error(raw.get("error"))
    if matcher_status and error_class != "NONE":
        raise _Reject("MALFORMED", RunnerErrorCode.OUTPUT_MALFORMED)

    normalized = {
        "template_id": template_id,
        "target_ref": target.target_ref,
        "matcher_status": matcher_status,
        "checked_path": checked_path,
        "error_class": error_class,
        "claimed_severity": severity,
        "extracted_count": len(extracted or []),
    }
    digest = hashlib.sha256(
        json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return NucleiResultRecord.model_validate(
        {
            **normalized,
            "record_digest": digest,
            "observed_at": _parse_timestamp(raw.get("timestamp")),
        },
        strict=False,
    )


def _summary(
    status: ParseStatus,
    *,
    code: RunnerErrorCode | None = None,
    lines: int = 0,
    records: tuple[NucleiResultRecord, ...] = (),
    duplicates: int = 0,
    stripped: set[str] | None = None,
) -> ParseSummary:
    return ParseSummary(
        parser_version=PARSER_VERSION,
        status=status,
        failure_code=code,
        lines=lines,
        records=len(records),
        matched=sum(1 for r in records if r.matcher_status),
        unmatched=sum(1 for r in records if not r.matcher_status and r.error_class == "NONE"),
        errored=sum(1 for r in records if r.error_class != "NONE"),
        duplicates_collapsed=duplicates,
        stripped_fields=tuple(sorted(stripped or ())),
    )


def parse_jsonl(
    data: bytes,
    *,
    admitted: dict[str, AdmittedTemplate],
    target: NucleiTarget,
    max_results: int,
    max_output_bytes: int,
) -> ParseOutcome:
    """Parse bounded Nuclei JSONL. Never raises; failures are typed, fail-closed outcomes."""

    failed = ParseOutcome(_summary("NOT_PARSED"), (), False)
    if len(data) > max_output_bytes:
        return ParseOutcome(_summary("OVERSIZED", code=RunnerErrorCode.OUTPUT_OVERSIZED), (), False)
    if not data:
        return ParseOutcome(_summary("EMPTY", code=RunnerErrorCode.COVERAGE_INCOMPLETE), (), False)
    if not data.endswith(b"\n"):
        return ParseOutcome(_summary("TRUNCATED", code=RunnerErrorCode.OUTPUT_TRUNCATED), (), False)
    raw_lines = data.split(b"\n")[:-1]
    if len(raw_lines) > max_results:
        return ParseOutcome(
            _summary("OVERSIZED", code=RunnerErrorCode.OUTPUT_OVERSIZED, lines=len(raw_lines)),
            (),
            False,
        )
    stripped: set[str] = set()
    by_identity: dict[tuple[str, str], NucleiResultRecord] = {}
    duplicates = 0
    try:
        for raw_line in raw_lines:
            if len(raw_line) > MAX_LINE_BYTES:
                raise _Reject("OVERSIZED", RunnerErrorCode.OUTPUT_OVERSIZED)
            try:
                text = raw_line.decode("utf-8")
                value = json.loads(text, object_pairs_hook=_no_duplicate_keys)
            except (UnicodeDecodeError, ValueError):
                raise _Reject("MALFORMED", RunnerErrorCode.OUTPUT_MALFORMED) from None
            if not isinstance(value, dict):
                raise _Reject("MALFORMED", RunnerErrorCode.OUTPUT_MALFORMED)
            record = _normalize(value, admitted, target, stripped)
            identity = (record.template_id, record.target_ref)
            existing = by_identity.get(identity)
            if existing is None:
                by_identity[identity] = record
            elif existing.record_digest == record.record_digest:
                duplicates += 1  # identical observation: collapse deterministically
            else:
                # Same template + target with different content (e.g. match AND no-match).
                raise _Reject("MALFORMED", RunnerErrorCode.OUTPUT_MALFORMED)
    except _Reject as reject:
        return ParseOutcome(
            _summary(reject.status, code=reject.code, lines=len(raw_lines), stripped=stripped),
            (),
            False,
        )
    except Exception:  # any unexpected parser fault fails closed, without exception prose
        return failed

    records = tuple(by_identity[key] for key in sorted(by_identity))
    coverage = all(
        any(r.template_id == template_id and r.error_class == "NONE" for r in records)
        for template_id in admitted
    )
    return ParseOutcome(
        _summary(
            "PARSED",
            code=None if coverage else RunnerErrorCode.COVERAGE_INCOMPLETE,
            lines=len(raw_lines),
            records=records,
            duplicates=duplicates,
            stripped=stripped,
        ),
        records,
        coverage,
    )
