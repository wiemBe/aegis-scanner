"""The single fixed Nuclei execution profile: ``NUCLEI_LAB_SAFE_HTTP_V1``.

The runner builds the Nuclei command line here, as an argv list, from trusted constants plus three
runner-validated values (the admitted template paths, the inventory-resolved target URL and the
per-execution output path). There is no shell, no string concatenation of caller text and no
pass-through of any flag, header, variable, environment value or template selector.

Every flag below was checked against the pinned binary's own ``nuclei -h`` (v3.11.1, captured in
``docs/nuclei-runner-isolation.md``). Features that are OFF by default in v3.11.1 and are enabled
only by a flag (``-code``, ``-file``, ``-headless``, ``-dast``, ``-esc``, ``-egm``, ``-lfa``,
``-ev``, ``-fr``, ``-ai``, ``-dashboard``, ``-cloud-upload``, ``-sf``, ``-H``, ``-V``, ``-p``,
``-turl``, ``-wurl``, ``-w``, ``-as``, ``-uncover``, ``-hae``, ``-project``, ``-sresp``,
``-debug``, ``-stats``, ``-mp``, ``-ep``, ``-hpd``, ``-rdb``, ``-rc``, ``-config``, ``-tp``) are
simply never passed — :data:`FORBIDDEN_FLAGS` makes that a tested invariant.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

PROFILE_ID = "NUCLEI_LAB_SAFE_HTTP_V1"
PROFILE_VERSION = "1.2.0"

# Fixed profile knobs. They are constants, not configuration: changing one is a reviewed code change
# that also changes PROFILE_VERSION.
RATE_LIMIT_PER_SECOND = 2
CONCURRENCY = 1
BULK_SIZE = 1
PER_REQUEST_TIMEOUT_SECONDS = 5
RETRIES = 0
MAX_RESPONSE_READ_BYTES = 65536
MAX_HOST_ERRORS = 1

# Flags that must never appear in a constructed argv. Checked by build_argv() and by tests.
FORBIDDEN_FLAGS = frozenset(
    {
        "-code",
        "-file",
        "-headless",
        "-dast",
        "-fuzz",
        "-dts",
        "-dast-server",
        "-esc",
        "-enable-self-contained",
        "-egm",
        "-enable-global-matchers",
        "-lfa",
        "-allow-local-file-access",
        "-ev",
        "-env-vars",
        "-fr",
        "-follow-redirects",
        "-fhr",
        "-follow-host-redirects",
        "-ai",
        "-prompt",
        "-pd",
        "-dashboard",
        "-pdu",
        "-dashboard-upload",
        "-cup",
        "-cloud-upload",
        "-auth",
        "-tid",
        "-team-id",
        "-sf",
        "-secret-file",
        "-H",
        "-header",
        "-V",
        "-var",
        "-p",
        "-proxy",
        "-turl",
        "-template-url",
        "-w",
        "-workflows",
        "-wurl",
        "-workflow-url",
        "-as",
        "-automatic-scan",
        "-uc",
        "-uncover",
        "-hae",
        "-http-api-endpoint",
        "-project",
        "-sresp",
        "-store-resp",
        "-debug",
        "-dreq",
        "-dresp",
        "-stats",
        "-mp",
        "-metrics-port",
        "-ep",
        "-enable-pprof",
        "-rdb",
        "-rc",
        "-config",
        "-tp",
        "-profile",
        "-up",
        "-update",
        "-ut",
        "-update-templates",
        "-ud",
        "-nss",
        "-no-strict-syntax",
        "-l",
        "-list",
        "-im",
        "-input-mode",
        "-resume",
        "-iserver",
        "-itoken",
        "-cc",
        "-ck",
        "-ca",
        "-irr",
        "-include-rr",
    }
)

# Environment the Nuclei child process receives. It is constructed from scratch (never inherited),
# so NUCLEI_ARGS, NUCLEI_SIGNATURE_PUBLIC_KEY, NUCLEI_TEMPLATES_DIR, NUCLEI_CONFIG_DIR,
# PDCP_API_KEY, proxies and every other ambient variable are structurally absent.
_FIXED_ENV = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD": "true",
    "DISABLE_NUCLEI_TEMPLATES_GITHUB_DOWNLOAD": "true",
    "DISABLE_NUCLEI_TEMPLATES_GITLAB_DOWNLOAD": "true",
    "DISABLE_NUCLEI_TEMPLATES_AWS_DOWNLOAD": "true",
    "DISABLE_NUCLEI_TEMPLATES_AZURE_DOWNLOAD": "true",
    "DISABLE_CLOUD_UPLOAD": "true",
    "DISABLE_CLOUD_UPLOAD_WRN": "true",
}

# Process-environment variables whose mere presence in the runner makes it refuse to start.
DANGEROUS_ENV_PREFIXES = ("NUCLEI_", "PDCP_", "AI_AUTH", "OPENAI", "ANTHROPIC")
DANGEROUS_ENV_NAMES = frozenset(
    {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"}
)


@dataclass(frozen=True)
class ExecutionPaths:
    """Per-execution filesystem locations, all inside the runner's bounded tmpfs."""

    workdir: Path
    home: Path
    output_file: Path


def child_environment(home: Path) -> dict[str, str]:
    env = dict(_FIXED_ENV)
    env["HOME"] = str(home)
    # Nuclei creates dialer/scratch files under the temp dir. Point it into the per-execution
    # directory on the bounded tmpfs; the root filesystem (including /tmp) stays read-only.
    env["TMPDIR"] = str(home)
    return env


def build_argv(
    *,
    binary: Path,
    template_paths: list[Path],
    target_url: str,
    output_file: Path,
    max_time_seconds: int,
) -> list[str]:
    """Construct the fixed profile argv. Inputs are runner-validated, never caller-supplied text."""

    if not template_paths:
        raise ValueError("at least one admitted template path is required")
    if not 5 <= max_time_seconds <= 120:
        raise ValueError("max time outside the profile bounds")
    argv: list[str] = [str(binary)]
    for template in template_paths:
        # Explicit admitted file paths only: never a directory, tag, id filter or URL.
        argv += ["-t", str(template)]
    argv += [
        "-u",
        target_url,
        "-o",
        str(output_file),
        "-jsonl",  # JSONL output
        "-omit-raw",  # raw request/response omitted from findings
        "-omit-template",  # encoded template omitted
        "-matcher-status",  # emit a record for non-matches too (positive coverage evidence)
        "-no-color",
        "-no-stdin",
        "-disable-update-check",  # no engine/template update checks (also no auto-install)
        "-no-interactsh",  # Interactsh/OAST disabled; OAST templates excluded
        "-disable-redirects",
        "-type",
        "http",  # HTTP protocol only
        "-disable-unsigned-templates",  # unsigned or signature-mismatched templates never run
        "-disable-clustering",
        "-rate-limit",
        str(RATE_LIMIT_PER_SECOND),
        "-concurrency",
        str(CONCURRENCY),
        "-bulk-size",
        str(BULK_SIZE),
        "-payload-concurrency",
        "1",
        "-timeout",
        str(PER_REQUEST_TIMEOUT_SECONDS),
        "-retries",
        str(RETRIES),
        "-max-host-error",
        str(MAX_HOST_ERRORS),
        "-response-size-read",
        str(MAX_RESPONSE_READ_BYTES),
        "-max-time",
        f"{max_time_seconds}s",
    ]
    assert_argv_safe(argv)
    return argv


def assert_argv_safe(argv: list[str]) -> None:
    """Defense in depth: refuse an argv carrying any forbidden flag or shell metacharacter."""

    for token in argv[1:]:
        if token in FORBIDDEN_FLAGS:
            raise ValueError(f"forbidden nuclei flag in argv: {token}")
        if any(ch in token for ch in ("\n", "\r", "\x00", ";", "|", "&", "`", "$(")):
            raise ValueError("control or shell metacharacter in argv")
