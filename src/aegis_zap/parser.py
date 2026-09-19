"""Strict, versioned parser for the ZAP 2.17.0 ``traditional-json`` report.

The report is UNTRUSTED. The profile selects ``traditional-json`` because it carries alert and
instance metadata but no request/response bodies or headers. This parser additionally:

- bounds total bytes, sites, alerts, instances per alert and every string;
- requires strict UTF-8/JSON with duplicate-key rejection and a complete, un-truncated document;
- requires the pinned ZAP version and exactly the approved origin as the only site;
- accepts only alerts from the admitted passive-rule manifest, with the manifest's rule name;
- accepts only instances whose URI is an approved projected URL and whose method matches it;
- rejects any ``attack`` value (a passive alert never carries one);
- NEVER propagates ``desc``, ``solution``, ``otherinfo``, ``reference`` or any HTML/prose field —
  they are counted as stripped; evidence is reduced to a length and a SHA-256;
- collapses identical instances deterministically and derives stable, timestamp-free digests.

ZAP risk and confidence are recorded only as UNTRUSTED ``claimed_*`` labels; they never set Aegis
severity or confidence. Any failure yields a typed fail-closed outcome with no records.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from aegis_zap.contracts import ParseStatus, ZapAlertRecord, ZapParseSummary, ZapRunnerErrorCode
from aegis_zap.manifest import PassiveRule
from aegis_zap.projection import ProjectionResult

PARSER_VERSION = "zap-traditional-json-parser/1.3.0"
MAX_SITES = 4
MAX_STRING = 8_192
MAX_EVIDENCE = 1_024
_TOP_KEYS = frozenset({"@programName", "@version", "@generated", "created", "site", "insights"})
_SITE_KEYS = frozenset({"@name", "@host", "@port", "@ssl", "alerts"})
_ALERT_KEYS = frozenset(
    {
        "pluginid",
        "alertRef",
        "alert",
        "name",
        "riskcode",
        "confidence",
        "riskdesc",
        "desc",
        "instances",
        "count",
        "systemic",
        "solution",
        "otherinfo",
        "reference",
        "cweid",
        "wascid",
        "sourceid",
        "tags",
    }
)
_INSTANCE_KEYS = frozenset(
    {"id", "uri", "nodeName", "method", "param", "attack", "evidence", "otherinfo"}
)
_PROSE_KEYS = ("desc", "solution", "otherinfo", "reference", "riskdesc", "tags")
_RISK = {"0": "info", "1": "low", "2": "medium", "3": "high"}
_CONFIDENCE = {"0": "falsepositive", "1": "low", "2": "medium", "3": "high", "4": "confirmed"}
_PARAM = re.compile(r"^[A-Za-z0-9_.-]{0,100}$")


class _Reject(Exception):
    def __init__(self, status: ParseStatus, code: ZapRunnerErrorCode) -> None:
        super().__init__(code.value)
        self.status = status
        self.code = code


@dataclass(frozen=True)
class ParseOutcome:
    summary: ZapParseSummary
    records: tuple[ZapAlertRecord, ...]


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _bounded_strings(node: Any) -> None:
    if isinstance(node, str):
        if len(node) > MAX_STRING:
            raise _Reject("OVERSIZED", ZapRunnerErrorCode.REPORT_OVERSIZED)
    elif isinstance(node, dict):
        for value in node.values():
            _bounded_strings(value)
    elif isinstance(node, list):
        for item in node:
            _bounded_strings(item)


def _malformed() -> _Reject:
    return _Reject("MALFORMED", ZapRunnerErrorCode.REPORT_MALFORMED)


def _summary(
    status: ParseStatus,
    *,
    code: ZapRunnerErrorCode | None = None,
    sites: int = 0,
    alerts: int = 0,
    instances: int = 0,
    records: tuple[ZapAlertRecord, ...] = (),
    duplicates: int = 0,
    stripped: set[str] | None = None,
) -> ZapParseSummary:
    return ZapParseSummary(
        parser_version=PARSER_VERSION,
        status=status,
        failure_code=code,
        sites=sites,
        alerts=alerts,
        instances=instances,
        records=len(records),
        duplicates_collapsed=duplicates,
        stripped_fields=tuple(sorted(stripped or ())),
    )


def parse_report(
    data: bytes | None,
    *,
    engine_version: str,
    projection: ProjectionResult,
    rules: tuple[PassiveRule, ...],
    max_report_bytes: int,
    max_alerts: int,
    max_instances: int = 8,
) -> ParseOutcome:
    """Parse one bounded report. Never raises; failures are typed, fail-closed outcomes."""

    if data is None:
        return ParseOutcome(_summary("MISSING", code=ZapRunnerErrorCode.REPORT_MISSING), ())
    if len(data) > max_report_bytes:
        return ParseOutcome(_summary("OVERSIZED", code=ZapRunnerErrorCode.REPORT_OVERSIZED), ())
    if not data.strip():
        return ParseOutcome(_summary("EMPTY", code=ZapRunnerErrorCode.REPORT_MISSING), ())
    if not data.rstrip().endswith(b"}"):
        return ParseOutcome(_summary("TRUNCATED", code=ZapRunnerErrorCode.REPORT_TRUNCATED), ())
    stripped: set[str] = set()
    admitted = {rule.plugin_id: rule for rule in rules}
    approved = {(op.method, f"{projection.origin}{op.path}") for op in projection.operations}
    sites_seen = alerts_seen = instances_seen = 0
    try:
        try:
            report = json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
        except (UnicodeDecodeError, ValueError, RecursionError):
            raise _malformed() from None
        if not isinstance(report, dict) or set(report) - _TOP_KEYS:
            raise _malformed()
        _bounded_strings(report)
        if report.get("@programName") != "ZAP":
            raise _malformed()
        if report.get("@version") != engine_version:
            raise _Reject("MALFORMED", ZapRunnerErrorCode.ENGINE_INTEGRITY_FAILURE)
        sites = report.get("site")
        if not isinstance(sites, list) or len(sites) > MAX_SITES:
            raise _Reject("OVERSIZED", ZapRunnerErrorCode.REPORT_OVERSIZED)
        by_identity: dict[tuple[int, str, str, str], ZapAlertRecord] = {}
        duplicates = 0
        for site in sites:
            sites_seen += 1
            if not isinstance(site, dict) or set(site) - _SITE_KEYS:
                raise _malformed()
            if site.get("@name") != projection.origin or site.get("@ssl") != "false":
                raise _Reject("MALFORMED", ZapRunnerErrorCode.SCOPE_ESCAPE_BLOCKED)
            alerts = site.get("alerts")
            if not isinstance(alerts, list):
                raise _malformed()
            for alert in alerts:
                alerts_seen += 1
                if alerts_seen > max_alerts:
                    raise _Reject("OVERSIZED", ZapRunnerErrorCode.REPORT_OVERSIZED)
                if not isinstance(alert, dict) or set(alert) - _ALERT_KEYS:
                    raise _malformed()
                stripped.update(key for key in _PROSE_KEYS if key in alert)
                plugin = alert.get("pluginid")
                if not isinstance(plugin, str) or not plugin.isdigit() or len(plugin) > 6:
                    raise _malformed()
                rule = admitted.get(int(plugin))
                if rule is None:
                    raise _Reject("MALFORMED", ZapRunnerErrorCode.UNADMITTED_RULE)
                if alert.get("name") != rule.name or alert.get("alert") != rule.name:
                    raise _Reject("MALFORMED", ZapRunnerErrorCode.UNADMITTED_RULE)
                if alert.get("alertRef") not in {plugin, f"{plugin}-1"}:
                    raise _Reject("MALFORMED", ZapRunnerErrorCode.UNADMITTED_RULE)
                risk = _RISK.get(str(alert.get("riskcode")))
                confidence = _CONFIDENCE.get(str(alert.get("confidence")))
                instances = alert.get("instances")
                if risk is None or confidence is None or not isinstance(instances, list):
                    raise _malformed()
                if not instances or len(instances) > max_instances:
                    raise _Reject("OVERSIZED", ZapRunnerErrorCode.REPORT_OVERSIZED)
                if str(alert.get("count")) != str(len(instances)):
                    raise _malformed()
                for instance in instances:
                    instances_seen += 1
                    if not isinstance(instance, dict) or set(instance) - _INSTANCE_KEYS:
                        raise _malformed()
                    if "otherinfo" in instance:
                        stripped.add("instance.otherinfo")
                    uri, method = instance.get("uri"), instance.get("method")
                    if (method, uri) not in approved:
                        raise _Reject("MALFORMED", ZapRunnerErrorCode.SCOPE_ESCAPE_BLOCKED)
                    if instance.get("attack") not in (None, ""):
                        raise _malformed()
                    param = instance.get("param", "")
                    evidence = instance.get("evidence", "")
                    if not isinstance(param, str) or not _PARAM.fullmatch(param):
                        raise _malformed()
                    if not isinstance(evidence, str) or len(evidence) > MAX_EVIDENCE:
                        raise _Reject("OVERSIZED", ZapRunnerErrorCode.REPORT_OVERSIZED)
                    if evidence:
                        stripped.add("instance.evidence")
                    assert isinstance(uri, str) and isinstance(method, str)
                    path = uri[len(projection.origin) :]
                    normalized = {
                        "plugin_id": rule.plugin_id,
                        "method": method,
                        "path": path,
                        "param": param.lower(),
                        "claimed_risk": risk,
                        "claimed_confidence": confidence,
                        "evidence_sha256": hashlib.sha256(evidence.encode()).hexdigest(),
                        "evidence_length": len(evidence),
                    }
                    digest = hashlib.sha256(
                        json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest()
                    record = ZapAlertRecord.model_validate(
                        {**normalized, "rule_name": rule.name, "record_digest": digest},
                        strict=False,
                    )
                    identity = (rule.plugin_id, method, path, param.lower())
                    existing = by_identity.get(identity)
                    if existing is None:
                        by_identity[identity] = record
                    elif existing.record_digest == record.record_digest:
                        duplicates += 1
                    else:
                        raise _malformed()
    except _Reject as reject:
        return ParseOutcome(
            _summary(
                reject.status,
                code=reject.code,
                sites=sites_seen,
                alerts=alerts_seen,
                instances=instances_seen,
                stripped=stripped,
            ),
            (),
        )
    except Exception:  # any unexpected parser fault fails closed without exception prose
        return ParseOutcome(_summary("NOT_PARSED", code=ZapRunnerErrorCode.REPORT_MALFORMED), ())
    records = tuple(by_identity[key] for key in sorted(by_identity))
    return ParseOutcome(
        _summary(
            "PARSED",
            sites=sites_seen,
            alerts=alerts_seen,
            instances=instances_seen,
            records=records,
            duplicates=duplicates,
            stripped=stripped,
        ),
        records,
    )
