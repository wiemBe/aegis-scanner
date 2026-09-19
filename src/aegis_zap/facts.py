"""Bounded, typed facts derived from ZAP's own stdout and ``zap.log``.

ZAP text output is UNTRUSTED and is never returned, persisted or displayed. The runner reads a
bounded prefix of each stream and extracts only the fixed facts below, each matched against the
exact line formats of the pinned ZAP 2.17.0 / Automation Framework 0.60.0 / pscan 0.6.0 add-ons.
A fact that cannot be positively established stays at its fail-closed default.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

MAX_SCAN_BYTES = 262_144

_JOB_STARTED = re.compile(r"^Job (\S+) started$", re.M)
_JOB_FINISHED = re.compile(r"^Job (\S+) finished, time taken: ", re.M)
_URLS_ADDED = re.compile(r"^Job openapi added (\d+) URLs$", re.M)
_URLS_TEST_PASSED = re.compile(
    r"^Job openapi test of type stats passed: projected-operations-imported \[(\d+) == (\d+)\]$",
    re.M,
)
_RULE_SET = re.compile(r"^Job passiveScan-config set rule (\d+) threshold to ([A-Z]+)$", re.M)
_UNKNOWN_RULE = re.compile(r"Unrecognised passive scan rule ID", re.M)
_REPORT = re.compile(r"^Job report generated report (\S+)$", re.M)
_OPENAPI_ERROR = re.compile(r"^Job openapi target: .* error: ", re.M)
_TIMEOUT = re.compile(r"(Read timed out|SocketTimeoutException|timed out)", re.I)
_UNREACHABLE = re.compile(r"(NoHttpResponseException|Connection refused|failed to respond)", re.I)
_INSTALLED = re.compile(r"ExtensionFactory - Installed add-ons: \[(.*)\]\s*$", re.M)
_ADDON = re.compile(r"\[id=([A-Za-z0-9]+), version=([0-9.]+)\]")
_SILENT = "Shh! Silent mode or telemetry turned off"
_ACTIVE_RULE = re.compile(r"Loaded active scan rule", re.I)
_ADDONLIST_ROW = re.compile(r"^[^\t\n]+\t([A-Za-z0-9]+)\tv([0-9.]+)\t(release|beta|alpha)\t", re.M)
_JAVA_VERSION = re.compile(r'^openjdk version "([0-9.]+)"', re.M)
_JAVA_RUNTIME = re.compile(r"OpenJDK Runtime Environment \(build ([^)]+)\)", re.M)


@dataclass(frozen=True)
class AutomationFacts:
    plan_succeeded: bool = False
    plan_failures_reported: bool = False
    jobs_started: tuple[str, ...] = ()
    jobs_finished: tuple[str, ...] = ()
    urls_added: int | None = None
    urls_test_passed: bool = False
    rules_set: tuple[tuple[int, str], ...] = ()
    unknown_rule: bool = False
    pscan_wait_started: bool = False
    pscan_wait_finished: bool = False
    report_paths: tuple[str, ...] = ()
    openapi_errors: int = 0
    target_timeouts: int = 0
    target_unreachable: int = 0


@dataclass(frozen=True)
class ZapLogFacts:
    installed_add_ons: tuple[tuple[str, str], ...] = ()
    silent_mode: bool = False
    active_rules_loaded: int = 0
    installed_line_seen: bool = False


@dataclass(frozen=True)
class AddOnListFacts:
    add_ons: tuple[tuple[str, str, str], ...] = field(default_factory=tuple)


def _text(data: bytes) -> str:
    return data[:MAX_SCAN_BYTES].decode("utf-8", errors="replace").replace("\r\n", "\n")


def automation_facts(stdout: bytes) -> AutomationFacts:
    text = _text(stdout)
    started = tuple(_JOB_STARTED.findall(text))
    finished = tuple(_JOB_FINISHED.findall(text))
    added = _URLS_ADDED.findall(text)
    passed = [(int(a), int(b)) for a, b in _URLS_TEST_PASSED.findall(text)]
    openapi_errors = _OPENAPI_ERROR.findall(text)
    error_lines = [line for line in text.splitlines() if _OPENAPI_ERROR.match(line)]
    return AutomationFacts(
        plan_succeeded="\nAutomation plan succeeded!" in f"\n{text}"
        and "Automation plan failures:" not in text
        and "Automation plan warnings:" not in text,
        plan_failures_reported="Automation plan failures:" in text
        or "Automation plan warnings:" in text,
        jobs_started=started,
        jobs_finished=finished,
        urls_added=int(added[-1]) if len(added) == 1 else None,
        urls_test_passed=len(passed) == 1 and passed[0][0] == passed[0][1],
        rules_set=tuple(sorted((int(i), level) for i, level in _RULE_SET.findall(text))),
        unknown_rule=bool(_UNKNOWN_RULE.search(text)),
        pscan_wait_started="passiveScan-wait" in started,
        pscan_wait_finished="passiveScan-wait" in finished,
        report_paths=tuple(_REPORT.findall(text)),
        openapi_errors=len(openapi_errors),
        target_timeouts=sum(1 for line in error_lines if _TIMEOUT.search(line)),
        target_unreachable=sum(1 for line in error_lines if _UNREACHABLE.search(line)),
    )


def zap_log_facts(log: bytes) -> ZapLogFacts:
    text = _text(log)
    installed = _INSTALLED.findall(text)
    add_ons: tuple[tuple[str, str], ...] = ()
    if len(installed) == 1:
        add_ons = tuple(sorted(_ADDON.findall(installed[0])))
    return ZapLogFacts(
        installed_add_ons=add_ons,
        silent_mode=_SILENT in text,
        active_rules_loaded=len(_ACTIVE_RULE.findall(text)),
        installed_line_seen=len(installed) == 1,
    )


def add_on_list_facts(stdout: bytes) -> AddOnListFacts:
    """Parse ``zap -cmd -addonlist``: one tab-separated row per loaded add-on."""

    rows = _ADDONLIST_ROW.findall(_text(stdout))
    return AddOnListFacts(add_ons=tuple(sorted((i, v, s) for i, v, s in rows)))


def java_version_facts(stderr: bytes) -> tuple[str | None, str | None]:
    text = _text(stderr)
    version = _JAVA_VERSION.search(text)
    runtime = _JAVA_RUNTIME.search(text)
    return (version.group(1) if version else None, runtime.group(1) if runtime else None)


def normalize_add_on_version(version: str) -> str:
    """ZAP prints ``57.0.0`` for an add-on whose file is ``openapi-beta-57.zap``."""

    parts = version.split(".")
    while len(parts) < 3:
        parts.append("0")
    return ".".join(parts[:3])
