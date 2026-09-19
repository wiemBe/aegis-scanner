"""The single fixed ZAP profile: ``ZAP_LAB_PASSIVE_OPENAPI_V1``.

Trusted adapter code generates the Automation Framework plan here, from constants plus
runner-validated values (the projection's approved URLs, the local projected file path, the report
directory and the admitted passive rules). No plan, job, rule setting, ZAP option or header is ever
accepted from the model, the UI or an RPC caller.

The only job sequence is::

    env (one context: the approved URLs only)
    passiveScan-config   disableAllRules, then enable exactly the admitted rule manifest
    openapi              apiFile (the local projected document), never apiUrl; a stats test
                         requires exactly the projected operation count to be imported
    passiveScan-wait     maxDuration 0 = wait until the passive queue is empty
    report               local traditional-json only

Every other job type, and every key that could add a request source, script, credential or remote
destination, is rejected by :func:`validate_plan`, which also requires the plan to be byte-equal to
a freshly generated one. ZAP is invoked with a fixed argv (no shell) that routes all traffic
through the scope guard and disables update checks, telemetry and add-on installation.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from aegis_zap.manifest import PassiveRule
from aegis_zap.projection import ProjectionResult, canonical_json

PROFILE_ID = "ZAP_LAB_PASSIVE_OPENAPI_V1"
PROFILE_VERSION = "1.3.0"
CONTEXT_NAME = "aegis-synthetic"
REPORT_TEMPLATE = "traditional-json"
REPORT_FILE = "aegis-zap-report"
JOB_SEQUENCE = ("passiveScan-config", "openapi", "passiveScan-wait", "report")
PER_REQUEST_TIMEOUT_SECONDS = 4
MAX_HEAP = "-Xmx768m"
USER_AGENT = "Aegis-ZAP-Passive-Lab/1.3.0"
MAX_ALERTS_PER_RULE = 10
MAX_BODY_BYTES_TO_SCAN = 65_536

# Named so a rejection is precise. ANY job type outside JOB_SEQUENCE is rejected regardless.
FORBIDDEN_JOB_TYPES = frozenset(
    {
        "activeScan",
        "activeScan-config",
        "activeScan-policy",
        "spider",
        "spiderAjax",
        "spiderClient",
        "requestor",
        "replacer",
        "script",
        "sequence-import",
        "sequence-activeScan",
        "import",
        "graphql",
        "soap",
        "postman",
        "addOns",
        "alertFilter",
        "delay",
        "exitStatus",
        "outputSummary",
        "llm",
        "mcp",
        "oast",
    }
)
# Keys that must never appear anywhere in a plan (remote sources, scripts, auth, variables).
FORBIDDEN_PLAN_KEYS = frozenset(
    {
        "apiUrl",
        "url",
        "script",
        "scripts",
        "scriptInline",
        "engine",
        "users",
        "authentication",
        "sessionManagement",
        "verification",
        "vars",
        "headers",
        "proxy",
        "policy",
        "policyDefinition",
        "addOns",
        "install",
        "update",
    }
)
FORBIDDEN_ZAP_FLAGS = frozenset(
    {
        "-daemon",
        "-host",
        "-port",
        "-addoninstall",
        "-addoninstallall",
        "-addonuninstall",
        "-addonupdate",
        "-addonlist",
        "-script",
        "-quickurl",
        "-quickout",
        "-quickprogress",
        "-openapifile",
        "-openapiurl",
        "-openapitargeturl",
        "-graphqlfile",
        "-graphqlurl",
        "-soapfile",
        "-soapurl",
        "-postmanfile",
        "-postmanurl",
        "-session",
        "-newsession",
        "-configfile",
        "-installdir",
        "-certload",
        "-certpubdump",
        "-certfulldump",
        "-hud",
        "-lowmem",
        "-experimentaldb",
        "-dev",
    }
)
_ZAP_FLAGS = ("-cmd", "-silent", "-notel", "-dir", "-config", "-autorun")
FIXED_CONFIG = (
    "callhome.tel.enabled=false",
    "start.checkForUpdates=false",
    "start.checkAddonUpdates=false",
    "start.installAddonUpdates=false",
    "start.installScannerRules=false",
    "start.reportReleaseAddons=false",
    "start.reportBetaAddons=false",
    "start.reportAlphaAddons=false",
    "database.recoverylog=false",
    "network.connection.httpProxy.enabled=true",
    f"network.connection.timeoutInSecs={PER_REQUEST_TIMEOUT_SECONDS}",
    f"network.connection.defaultUserAgent={USER_AGENT}",
)
_GUARD_HOST = re.compile(r"^[a-z0-9][a-z0-9.-]{0,62}$")
_SAFE_PATH = re.compile(r"^/[A-Za-z0-9/_.-]+$")
_SHELL_META = ("\n", "\r", "\x00", ";", "|", "&", "`", "$(", ">", "<")

# Environment variables whose presence in the runner process makes it refuse to become ready.
DANGEROUS_ENV_NAMES = frozenset(
    {
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "JAVA_OPTS",
        "CLASSPATH",
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    }
)
DANGEROUS_ENV_PREFIXES = (
    "AI_AUTH",
    "OPENAI",
    "ANTHROPIC",
    "PDCP_",
    "NUCLEI_",
    "ZAP_API",
    "ZAP_JVM",
)


class PlanViolation(ValueError):
    def __init__(self, violations: list[str]) -> None:
        super().__init__(",".join(violations)[:200])
        self.violations = violations


def _include_regex(url: str) -> str:
    # \Q...\E is a literal in Java regex: the context matches exactly the approved URL, nothing
    # under or beside it.
    return f"\\Q{url}\\E"


def build_plan(
    *,
    projection: ProjectionResult,
    api_file: Path,
    report_dir: Path,
    rules: tuple[PassiveRule, ...],
) -> dict[str, Any]:
    """Generate the fixed plan for one validated projection. Pure and deterministic."""

    if not rules:
        raise ValueError("at least one admitted passive rule is required")
    urls = list(projection.urls)
    return {
        "env": {
            "contexts": [
                {
                    "name": CONTEXT_NAME,
                    "urls": urls,
                    "includePaths": [_include_regex(url) for url in urls],
                    "excludePaths": [],
                }
            ],
            "parameters": {
                "failOnError": True,
                "failOnWarning": True,
                "continueOnFailure": False,
                "progressToStdout": True,
            },
        },
        "jobs": [
            {
                "type": "passiveScan-config",
                "parameters": {
                    "maxAlertsPerRule": MAX_ALERTS_PER_RULE,
                    "scanOnlyInScope": True,
                    "maxBodySizeInBytesToScan": MAX_BODY_BYTES_TO_SCAN,
                    "enableTags": False,
                    "disableAllRules": True,
                },
                "rules": [
                    {"id": rule.plugin_id, "name": rule.name, "threshold": rule.threshold.lower()}
                    for rule in sorted(rules, key=lambda r: r.plugin_id)
                ],
            },
            {
                "type": "openapi",
                "parameters": {
                    "apiFile": str(api_file),
                    "targetUrl": projection.origin,
                    "context": CONTEXT_NAME,
                },
                "tests": [
                    {
                        "name": "projected-operations-imported",
                        "type": "stats",
                        "statistic": "openapi.urls.added",
                        "operator": "==",
                        "value": projection.operation_count,
                        "onFail": "error",
                    }
                ],
            },
            {"type": "passiveScan-wait", "parameters": {"maxDuration": 0}},
            {
                "type": "report",
                "parameters": {
                    "template": REPORT_TEMPLATE,
                    "reportDir": str(report_dir),
                    "reportFile": REPORT_FILE,
                    "reportTitle": "Aegis synthetic passive scan",
                    "displayReport": False,
                },
                "risks": ["info", "low", "medium", "high"],
                "confidences": ["falsepositive", "low", "medium", "high", "confirmed"],
            },
        ],
    }


def plan_bytes(plan: dict[str, Any]) -> bytes:
    """Canonical JSON (valid YAML) bytes of a plan; the plan digest is their SHA-256."""

    return canonical_json(plan)


def plan_digest(plan: dict[str, Any]) -> str:
    return hashlib.sha256(plan_bytes(plan)).hexdigest()


def _forbidden_keys(node: Any, found: list[str]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key in FORBIDDEN_PLAN_KEYS:
                found.append(f"FORBIDDEN_KEY:{key}")
            _forbidden_keys(value, found)
    elif isinstance(node, list):
        for item in node:
            _forbidden_keys(item, found)


def validate_plan(plan: Any, expected: dict[str, Any]) -> list[str]:
    """Return every violation of the fixed profile (empty list = valid).

    Structural allowlisting runs first so an injected job/key yields a precise code; the final
    check requires byte-equality with the plan trusted code generated for this projection."""

    violations: list[str] = []
    if not isinstance(plan, dict) or set(plan) != {"env", "jobs"}:
        return ["PLAN_SHAPE"]
    _forbidden_keys(plan, violations)
    jobs = plan.get("jobs")
    if not isinstance(jobs, list):
        return [*violations, "JOBS_SHAPE"]
    types: list[str] = []
    for job in jobs:
        job_type = job.get("type") if isinstance(job, dict) else None
        if not isinstance(job_type, str):
            violations.append("JOB_SHAPE")
            continue
        types.append(job_type)
        if job_type in FORBIDDEN_JOB_TYPES:
            violations.append(f"FORBIDDEN_JOB:{job_type}")
        elif job_type not in JOB_SEQUENCE:
            violations.append(f"UNKNOWN_JOB:{job_type}")
        if job_type == "openapi" and isinstance(job, dict):
            params = job.get("parameters")
            if not isinstance(params, dict) or set(params) != {"apiFile", "targetUrl", "context"}:
                violations.append("OPENAPI_PARAMETERS")
        if job_type == "report" and isinstance(job, dict):
            params = job.get("parameters")
            if not isinstance(params, dict) or params.get("template") != REPORT_TEMPLATE:
                violations.append("REPORT_TEMPLATE")
    if tuple(types) != JOB_SEQUENCE:
        violations.append("JOB_SEQUENCE")
    if not violations and plan_bytes(plan) != plan_bytes(expected):
        violations.append("PLAN_MISMATCH")
    return violations


def build_argv(
    *,
    java: Path,
    jar: Path,
    zap_home: Path,
    tmp_dir: Path,
    plan_file: Path,
    guard_host: str,
    guard_port: int,
) -> list[str]:
    """The fixed argv. Inputs are runner-owned paths and the fixed guard address, never caller
    text. ZAP runs headless in -cmd mode: no API listener, no UI, no local proxy."""

    if not _GUARD_HOST.fullmatch(guard_host) or not 1 <= guard_port <= 65535:
        raise ValueError("guard address outside the profile bounds")
    argv = [
        str(java),
        MAX_HEAP,
        "-XX:-UsePerfData",
        "-XX:+ExitOnOutOfMemoryError",
        "-Djava.awt.headless=true",
        f"-Djava.io.tmpdir={tmp_dir}",
        f"-Duser.home={zap_home}",
        "-jar",
        str(jar),
        "-cmd",
        "-silent",  # no unsolicited requests: no update checks, news or marketplace calls
        "-notel",  # telemetry off (callhome is a mandatory core add-on)
        "-dir",
        str(zap_home),
    ]
    for item in FIXED_CONFIG:
        argv += ["-config", item]
    argv += [
        "-config",
        f"network.connection.httpProxy.host={guard_host}",
        "-config",
        f"network.connection.httpProxy.port={guard_port}",
        "-autorun",
        str(plan_file),
    ]
    assert_argv_safe(argv)
    return argv


_JVM_FLAGS = frozenset(
    {MAX_HEAP, "-XX:-UsePerfData", "-XX:+ExitOnOutOfMemoryError", "-Djava.awt.headless=true"}
)


def assert_argv_safe(argv: list[str]) -> None:
    """Defense in depth over the constructed argv: only the fixed JVM and ZAP flags, only the
    allowlisted -config values, no shell metacharacters and never a forbidden ZAP option."""

    if len(argv) < 4 or "-jar" not in argv:
        raise ValueError("argv shape")
    for token in argv[1:]:
        if any(meta in token for meta in _SHELL_META):
            raise ValueError("control or shell metacharacter in argv")
        if token in FORBIDDEN_ZAP_FLAGS:
            raise ValueError(f"forbidden zap flag in argv: {token}")
    jar_index = argv.index("-jar")
    for token in argv[1:jar_index]:
        if token in _JVM_FLAGS:
            continue
        if token.startswith(("-Djava.io.tmpdir=", "-Duser.home=")) and _SAFE_PATH.fullmatch(
            token.split("=", 1)[1]
        ):
            continue
        raise ValueError(f"jvm flag not in profile: {token}")
    index = jar_index + 2
    while index < len(argv):
        flag = argv[index]
        if flag not in _ZAP_FLAGS:
            raise ValueError(f"zap flag not in profile: {flag}")
        if flag in {"-dir", "-autorun", "-config"}:
            if index + 1 >= len(argv):
                raise ValueError("flag without value")
            value = argv[index + 1]
            if flag == "-config":
                dynamic = value.startswith(
                    ("network.connection.httpProxy.host=", "network.connection.httpProxy.port=")
                )
                if value not in FIXED_CONFIG and not dynamic:
                    raise ValueError(f"config not in profile: {value}")
            elif not _SAFE_PATH.fullmatch(value):
                raise ValueError("unsafe path value")
            index += 2
            continue
        index += 1


def child_environment(zap_home: Path) -> dict[str, str]:
    """The ZAP child environment is constructed from scratch, never inherited."""

    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": str(zap_home),
    }
