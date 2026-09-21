"""The single fixed active profile: ``ZAP_LAB_ACTIVE_REFLECTED_XSS_V1`` (Phase 1.5).

Trusted adapter code generates the Automation Framework plan here from constants plus
runner-validated values (the projection's one approved URL, the local projected file path, the
report directory and the single admitted active rule with its fixed threshold and strength). No
plan, job, rule setting, ZAP option, payload or header is ever accepted from the model, the UI or
an RPC caller.

The only job sequence is::

    env (one context: the approved URL only)
    passiveScan-config    disableAllRules (passive rules add nothing to this scenario)
    openapi               apiFile (the local projected document), never apiUrl
    passiveScan-wait      drain the passive queue before active scanning
    activeScan            an inline policy with defaultStrength/defaultThreshold = OFF and EXACTLY
                          the one admitted rule enabled at its fixed strength/threshold; one thread;
                          a fixed inter-request delay; no new parameters, no header scanning
    passiveScan-wait      drain the passive queue produced by the active requests
    report                local traditional-json only

Every other job type and every key that could add a request source, script, credential, payload or
remote destination is rejected by :func:`validate_plan`, which also requires the plan to be
byte-equal to a freshly generated one. The fixed argv, constructed environment and guard-only egress
are reused unchanged from the passive profile.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from aegis_zap.profile import (  # reused unchanged: fixed argv, safety, clean environment
    assert_argv_safe,
    build_argv,
    child_environment,
)
from aegis_zap.projection import canonical_json
from aegis_zap_active.manifest import ActiveRule
from aegis_zap_active.projection import ActiveProjectionResult

__all__ = [
    "PROFILE_ID",
    "PROFILE_VERSION",
    "CONTEXT_NAME",
    "JOB_SEQUENCE",
    "REPORT_FILE",
    "build_plan",
    "plan_bytes",
    "plan_digest",
    "validate_plan",
    "PlanViolation",
    "build_argv",
    "child_environment",
    "assert_argv_safe",
    "DEFAULT_DELAY_MS",
    "DEFAULT_MAX_SCAN_MINS",
    "THREAD_PER_HOST",
]

PROFILE_ID = "ZAP_LAB_ACTIVE_REFLECTED_XSS_V1"
PROFILE_VERSION = "1.5.0"
CONTEXT_NAME = "aegis-active-synthetic"
REPORT_TEMPLATE = "traditional-json"
REPORT_FILE = "aegis-zap-active-report"
JOB_SEQUENCE = (
    "passiveScan-config",
    "openapi",
    "passiveScan-wait",
    "activeScan",
    "passiveScan-wait",
    "report",
)
THREAD_PER_HOST = 1
DEFAULT_DELAY_MS = 250  # ~<=4 req/s for the synthetic smoke; the test-env profile lowers the rate
DEFAULT_MAX_SCAN_MINS = 5
MAX_ALERTS_PER_RULE = 10
MAX_BODY_BYTES_TO_SCAN = 65_536

# activeScan is now the ONE admitted extra job. Everything else that could add a request source,
# spider, script, or a second active job stays forbidden.
FORBIDDEN_JOB_TYPES = frozenset(
    {
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
# Keys that must never appear anywhere in a plan. ``policyDefinition`` is REQUIRED by the activeScan
# job and is therefore allowed and validated explicitly; a named/file ``policy`` reference is not.
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
        "addOns",
        "install",
        "update",
    }
)


class PlanViolation(ValueError):
    def __init__(self, violations: list[str]) -> None:
        super().__init__(",".join(violations)[:200])
        self.violations = violations


def _include_regex(url: str) -> str:
    return f"\\Q{url}\\E"


def build_plan(
    *,
    projection: ActiveProjectionResult,
    rule: ActiveRule,
    api_file: Path,
    report_dir: Path,
    delay_ms: int = DEFAULT_DELAY_MS,
    max_scan_mins: int = DEFAULT_MAX_SCAN_MINS,
) -> dict[str, Any]:
    """Generate the fixed active plan for one validated projection. Pure and deterministic."""

    url = projection.url
    return {
        "env": {
            "contexts": [
                {
                    "name": CONTEXT_NAME,
                    "urls": [url],
                    "includePaths": [_include_regex(url)],
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
                "rules": [],
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
                "type": "activeScan",
                "parameters": {
                    "context": CONTEXT_NAME,
                    "policy": "",
                    "maxRuleDurationInMins": 0,
                    "maxScanDurationInMins": max_scan_mins,
                    "addQueryParam": False,
                    "delayInMs": delay_ms,
                    "handleAntiCSRFTokens": False,
                    "injectPluginIdInHeader": False,
                    "scanHeadersAllRequests": False,
                    "threadPerHost": THREAD_PER_HOST,
                },
                "policyDefinition": {
                    # defaultThreshold OFF disables every rule by default; only the admitted rule is
                    # re-enabled below. defaultStrength must be a valid attack-strength token (there
                    # is no OFF strength) and is irrelevant while every default rule is thresholded
                    # OFF.
                    "defaultStrength": "medium",
                    "defaultThreshold": "off",
                    "rules": [
                        {
                            "id": rule.plugin_id,
                            "name": rule.name,
                            "strength": rule.strength.lower(),
                            "threshold": rule.threshold.lower(),
                        }
                    ],
                },
            },
            {"type": "passiveScan-wait", "parameters": {"maxDuration": 0}},
            {
                "type": "report",
                "parameters": {
                    "template": REPORT_TEMPLATE,
                    "reportDir": str(report_dir),
                    "reportFile": REPORT_FILE,
                    "reportTitle": "Aegis synthetic active reflected-XSS scan",
                    "displayReport": False,
                },
                "risks": ["info", "low", "medium", "high"],
                "confidences": ["falsepositive", "low", "medium", "high", "confirmed"],
            },
        ],
    }


def plan_bytes(plan: dict[str, Any]) -> bytes:
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


def _validate_active_scan(job: dict[str, Any], rule: ActiveRule, violations: list[str]) -> None:
    params = job.get("parameters")
    if not isinstance(params, dict):
        violations.append("ACTIVESCAN_PARAMETERS")
        return
    delay = params.get("delayInMs")
    if (
        params.get("threadPerHost") != THREAD_PER_HOST
        or params.get("addQueryParam") is not False
        or params.get("scanHeadersAllRequests") is not False
        or params.get("context") != CONTEXT_NAME
        or params.get("policy") != ""
        or not isinstance(delay, int)
        or isinstance(delay, bool)
        or delay < 0
    ):
        violations.append("ACTIVESCAN_PARAMETERS")
    definition = job.get("policyDefinition")
    if not isinstance(definition, dict):
        violations.append("ACTIVESCAN_POLICY")
        return
    if definition.get("defaultStrength") != "medium" or definition.get("defaultThreshold") != "off":
        violations.append("ACTIVESCAN_DEFAULT_NOT_OFF")
    rules = definition.get("rules")
    if not isinstance(rules, list) or len(rules) != 1:
        violations.append("ACTIVESCAN_RULE_SET")
        return
    only = rules[0]
    if not isinstance(only, dict) or only.get("id") != rule.plugin_id:
        violations.append("ACTIVESCAN_UNADMITTED_RULE")
    elif (
        only.get("strength") != rule.strength.lower()
        or only.get("threshold") != rule.threshold.lower()
    ):
        violations.append("ACTIVESCAN_STRENGTH_OR_THRESHOLD")


def validate_plan(plan: Any, expected: dict[str, Any], *, rule: ActiveRule) -> list[str]:
    """Return every violation of the fixed active profile (empty list = valid).

    Structural allowlisting runs first so an injected job/key yields a precise code; the final check
    requires byte-equality with the plan trusted code generated for this projection."""

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
        if job_type == "activeScan" and isinstance(job, dict):
            _validate_active_scan(job, rule, violations)
        if job_type == "report" and isinstance(job, dict):
            params = job.get("parameters")
            if not isinstance(params, dict) or params.get("template") != REPORT_TEMPLATE:
                violations.append("REPORT_TEMPLATE")
    if tuple(types) != JOB_SEQUENCE:
        violations.append("JOB_SEQUENCE")
    if not violations and plan_bytes(plan) != plan_bytes(expected):
        violations.append("PLAN_MISMATCH")
    return violations
