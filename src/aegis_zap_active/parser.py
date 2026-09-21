"""Strict, versioned parser for the ZAP 2.17.0 ``traditional-json`` report (active reflected XSS).

The report is UNTRUSTED. Unlike the passive parser, an active reflected-XSS alert DOES carry an
``attack`` field (the payload ZAP sent) and an ``evidence`` field (what it saw reflected). This
parser:

- bounds total bytes, sites, alerts, instances per alert and every string; requires strict
  UTF-8/JSON with duplicate-key rejection and a complete document;
- requires the pinned ZAP version and exactly the approved origin as the only site;
- accepts only the single admitted active rule (40012) with the manifest's rule name;
- accepts only instances whose URI path is the approved projected path, whose method is GET and
  whose parameter is the single projected query parameter; any other host, path, method or
  parameter fails closed;
- REDACTS both ``attack`` and ``evidence``: it never stores or propagates the raw strings, only a
  coarse structural attack CLASS, a length and a SHA-256 for correlation. Any HTML/prose field
  (``desc``/``solution``/``otherinfo``/``reference``) is counted as stripped, never propagated.

ZAP risk and confidence are recorded only as UNTRUSTED ``claimed_*`` labels; they never set Aegis
severity or confidence. Any failure yields a typed fail-closed outcome with no records.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlsplit

from aegis_zap.contracts import ParseStatus
from aegis_zap_active.contracts import (
    AttackClass,
    ZapActiveAlertRecord,
    ZapActiveErrorCode,
    ZapActiveParseSummary,
)
from aegis_zap_active.manifest import ActiveRule
from aegis_zap_active.projection import ActiveProjectionResult

PARSER_VERSION = "zap-active-traditional-json-parser/1.5.0"
MAX_SITES = 4
MAX_STRING = 8_192
MAX_EVIDENCE = 4_096
MAX_ATTACK = 8_192
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
_EVENT_HANDLER = re.compile(r"on[a-z]{3,20}\s*=", re.IGNORECASE)


class _Reject(Exception):
    def __init__(self, status: ParseStatus, code: ZapActiveErrorCode) -> None:
        super().__init__(code.value)
        self.status = status
        self.code = code


@dataclass(frozen=True)
class ActiveParseOutcome:
    summary: ZapActiveParseSummary
    records: tuple[ZapActiveAlertRecord, ...]


def classify_attack(attack: str) -> AttackClass:
    """Coarse structural class of a payload. Computed from the raw string but only the CLASS (never
    the raw text) is ever stored or returned to the controller."""

    if not attack:
        return "NONE"
    lowered = attack.lower()
    if "<script" in lowered:
        return "SCRIPT_ELEMENT"
    if "javascript:" in lowered:
        return "JS_URI"
    if _EVENT_HANDLER.search(attack):
        return "EVENT_HANDLER"
    if re.search(r"[\"'][^\"']*>", attack) or attack.startswith(('">', "'>")):
        return "ATTRIBUTE_BREAKOUT"
    if "<" in attack and ">" in attack:
        return "MARKUP_INJECTION"
    return "OTHER"


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
            raise _Reject("OVERSIZED", ZapActiveErrorCode.REPORT_OVERSIZED)
    elif isinstance(node, dict):
        for value in node.values():
            _bounded_strings(value)
    elif isinstance(node, list):
        for item in node:
            _bounded_strings(item)


def _summary(
    status: ParseStatus,
    *,
    code: ZapActiveErrorCode | None = None,
    sites: int = 0,
    alerts: int = 0,
    instances: int = 0,
    records: tuple[ZapActiveAlertRecord, ...] = (),
    duplicates: int = 0,
    stripped: set[str] | None = None,
) -> ZapActiveParseSummary:
    return ZapActiveParseSummary(
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


def _instance_path(uri: str, projection: ActiveProjectionResult, query_param: str) -> str:
    """Validate one instance URI belongs to the exact projected endpoint and only mutates the
    projected query parameter, returning the bare path. Raises ``_Reject`` on any escape."""

    split = urlsplit(uri)
    origin = f"{split.scheme}://{split.hostname}" + (f":{split.port}" if split.port else "")
    if origin != projection.origin or split.path != projection.path:
        raise _Reject("MALFORMED", ZapActiveErrorCode.SCOPE_ESCAPE_BLOCKED)
    if split.query:
        keys = set(parse_qs(split.query, keep_blank_values=True))
        if not keys <= {query_param}:
            raise _Reject("MALFORMED", ZapActiveErrorCode.UNEXPECTED_QUERY_PARAM)
    return split.path


def parse_report(
    data: bytes | None,
    *,
    engine_version: str,
    projection: ActiveProjectionResult,
    rule: ActiveRule,
    max_report_bytes: int,
    max_alerts: int,
    max_instances: int = 16,
) -> ActiveParseOutcome:
    """Parse one bounded active report. Never raises; failures are typed fail-closed outcomes."""

    if data is None:
        return ActiveParseOutcome(_summary("MISSING", code=ZapActiveErrorCode.REPORT_MISSING), ())
    if len(data) > max_report_bytes:
        return ActiveParseOutcome(
            _summary("OVERSIZED", code=ZapActiveErrorCode.REPORT_OVERSIZED), ()
        )
    if not data.strip():
        return ActiveParseOutcome(_summary("EMPTY", code=ZapActiveErrorCode.REPORT_MISSING), ())
    if not data.rstrip().endswith(b"}"):
        return ActiveParseOutcome(
            _summary("TRUNCATED", code=ZapActiveErrorCode.REPORT_TRUNCATED), ()
        )
    stripped: set[str] = set()
    query_param = projection.query_param
    sites_seen = alerts_seen = instances_seen = 0
    try:
        try:
            report = json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicate_keys)
        except (UnicodeDecodeError, ValueError, RecursionError):
            raise _Reject("MALFORMED", ZapActiveErrorCode.REPORT_MALFORMED) from None
        if not isinstance(report, dict) or set(report) - _TOP_KEYS:
            raise _Reject("MALFORMED", ZapActiveErrorCode.REPORT_MALFORMED)
        _bounded_strings(report)
        if report.get("@programName") != "ZAP":
            raise _Reject("MALFORMED", ZapActiveErrorCode.REPORT_MALFORMED)
        if report.get("@version") != engine_version:
            raise _Reject("MALFORMED", ZapActiveErrorCode.ENGINE_INTEGRITY_FAILURE)
        sites = report.get("site")
        if not isinstance(sites, list) or len(sites) > MAX_SITES:
            raise _Reject("OVERSIZED", ZapActiveErrorCode.REPORT_OVERSIZED)
        by_identity: dict[tuple[Any, ...], ZapActiveAlertRecord] = {}
        duplicates = 0
        for site in sites:
            sites_seen += 1
            if not isinstance(site, dict) or set(site) - _SITE_KEYS:
                raise _Reject("MALFORMED", ZapActiveErrorCode.REPORT_MALFORMED)
            if site.get("@name") != projection.origin or site.get("@ssl") != "false":
                raise _Reject("MALFORMED", ZapActiveErrorCode.SCOPE_ESCAPE_BLOCKED)
            alerts = site.get("alerts")
            if not isinstance(alerts, list):
                raise _Reject("MALFORMED", ZapActiveErrorCode.REPORT_MALFORMED)
            for alert in alerts:
                alerts_seen += 1
                if alerts_seen > max_alerts:
                    raise _Reject("OVERSIZED", ZapActiveErrorCode.REPORT_OVERSIZED)
                if not isinstance(alert, dict) or set(alert) - _ALERT_KEYS:
                    raise _Reject("MALFORMED", ZapActiveErrorCode.REPORT_MALFORMED)
                stripped.update(key for key in _PROSE_KEYS if key in alert)
                plugin = alert.get("pluginid")
                if not isinstance(plugin, str) or not plugin.isdigit() or len(plugin) > 6:
                    raise _Reject("MALFORMED", ZapActiveErrorCode.REPORT_MALFORMED)
                if int(plugin) != rule.plugin_id:
                    raise _Reject("MALFORMED", ZapActiveErrorCode.UNADMITTED_RULE)
                if alert.get("name") != rule.name or alert.get("alert") != rule.name:
                    raise _Reject("MALFORMED", ZapActiveErrorCode.UNADMITTED_RULE)
                ref = alert.get("alertRef")
                if not isinstance(ref, str) or not ref.split("-")[0] == plugin:
                    raise _Reject("MALFORMED", ZapActiveErrorCode.UNADMITTED_RULE)
                risk = _RISK.get(str(alert.get("riskcode")))
                confidence = _CONFIDENCE.get(str(alert.get("confidence")))
                instances = alert.get("instances")
                if risk is None or confidence is None or not isinstance(instances, list):
                    raise _Reject("MALFORMED", ZapActiveErrorCode.REPORT_MALFORMED)
                if not instances or len(instances) > max_instances:
                    raise _Reject("OVERSIZED", ZapActiveErrorCode.REPORT_OVERSIZED)
                if str(alert.get("count")) != str(len(instances)):
                    raise _Reject("MALFORMED", ZapActiveErrorCode.REPORT_MALFORMED)
                for instance in instances:
                    instances_seen += 1
                    if not isinstance(instance, dict) or set(instance) - _INSTANCE_KEYS:
                        raise _Reject("MALFORMED", ZapActiveErrorCode.REPORT_MALFORMED)
                    if "otherinfo" in instance:
                        stripped.add("instance.otherinfo")
                    uri, method = instance.get("uri"), instance.get("method")
                    if not isinstance(uri, str) or method != "GET":
                        raise _Reject("MALFORMED", ZapActiveErrorCode.SCOPE_ESCAPE_BLOCKED)
                    path = _instance_path(uri, projection, query_param)
                    param = instance.get("param", "")
                    if not isinstance(param, str) or not _PARAM.fullmatch(param):
                        raise _Reject("MALFORMED", ZapActiveErrorCode.REPORT_MALFORMED)
                    if param != query_param:
                        raise _Reject("MALFORMED", ZapActiveErrorCode.UNEXPECTED_QUERY_PARAM)
                    evidence = instance.get("evidence", "")
                    attack = instance.get("attack", "")
                    if not isinstance(evidence, str) or len(evidence) > MAX_EVIDENCE:
                        raise _Reject("OVERSIZED", ZapActiveErrorCode.REPORT_OVERSIZED)
                    if not isinstance(attack, str) or len(attack) > MAX_ATTACK:
                        raise _Reject("OVERSIZED", ZapActiveErrorCode.REPORT_OVERSIZED)
                    if evidence:
                        stripped.add("instance.evidence")
                    if attack:
                        stripped.add("instance.attack")
                    attack_class = classify_attack(attack)
                    normalized = {
                        "plugin_id": rule.plugin_id,
                        "method": "GET",
                        "path": path,
                        "param": param.lower(),
                        "claimed_risk": risk,
                        "claimed_confidence": confidence,
                        "evidence_sha256": hashlib.sha256(evidence.encode()).hexdigest(),
                        "evidence_length": len(evidence),
                        "attack_class": attack_class,
                        "attack_sha256": hashlib.sha256(attack.encode()).hexdigest(),
                        "attack_length": len(attack),
                    }
                    digest = hashlib.sha256(
                        json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
                    ).hexdigest()
                    record = ZapActiveAlertRecord.model_validate(
                        {**normalized, "rule_name": rule.name, "record_digest": digest},
                        strict=False,
                    )
                    identity = (rule.plugin_id, "GET", path, param.lower(), digest)
                    existing = by_identity.get(identity)
                    if existing is None:
                        by_identity[identity] = record
                    elif existing.record_digest == record.record_digest:
                        duplicates += 1
                    else:
                        raise _Reject("MALFORMED", ZapActiveErrorCode.REPORT_MALFORMED)
    except _Reject as reject:
        return ActiveParseOutcome(
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
        return ActiveParseOutcome(
            _summary("NOT_PARSED", code=ZapActiveErrorCode.REPORT_MALFORMED), ()
        )
    ordered = sorted(by_identity, key=lambda k: tuple(map(str, k)))
    records = tuple(by_identity[key] for key in ordered)
    return ActiveParseOutcome(
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
