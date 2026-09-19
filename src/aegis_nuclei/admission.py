"""Static, fail-closed admission of pinned Nuclei templates.

A template may execute only if EVERY rule below holds. Anything the rules cannot positively
establish is a violation: admission is an allowlist over the template's structure, never a
blocklist, so an unknown key, protocol, matcher type or request option rejects the template.

Checks (per template):

- explicitly present in the manifest, a regular non-symlink file under the template root, bounded
  in size, and byte-identical to the manifest SHA-256;
- carries an upstream signature line whose signer fingerprint matches the manifest (the
  cryptographic signature itself is verified by the pinned Nuclei binary with
  ``-disable-unsigned-templates``; see :mod:`nuclei_runner.attestation`);
- only the ``http`` protocol (no code, javascript, headless, file, network/tcp, dns, ssl,
  websocket, whois, workflow, flow, fuzzing/DAST or self-contained templates);
- only GET/HEAD, no request body, no raw requests, no payloads/attack modes, no redirects,
  no header/cookie manipulation, no pipelining/race/unsafe mode;
- request paths exactly equal to the manifest's ``{{BaseURL}}``-relative paths (so the template
  cannot change origin), within the declared request budget;
- no Interactsh/OAST marker, environment-variable access, local file or external payload, or
  remote template reference anywhere in executable sections;
- template id, name and severity equal to the manifest's reviewed values.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from aegis_nuclei.manifest import TemplateEntry, TemplateManifest, file_sha256

MAX_TEMPLATE_BYTES = 32 * 1024

_ALLOWED_TOP_LEVEL = frozenset({"id", "info", "http"})
# Named so the rejection code is precise; any OTHER unknown key is rejected too.
_FORBIDDEN_TOP_LEVEL = frozenset(
    {
        "code",
        "javascript",
        "headless",
        "file",
        "network",
        "tcp",
        "dns",
        "ssl",
        "websocket",
        "whois",
        "workflows",
        "flow",
        "requests",  # legacy alias of http that bypasses newer validation
        "self-contained",
        "variables",
        "signature",
        "multi-protocol",
    }
)
_ALLOWED_REQUEST_KEYS = frozenset(
    {"method", "path", "matchers", "matchers-condition", "extractors", "stop-at-first-match"}
)
_FORBIDDEN_REQUEST_KEYS = frozenset(
    {
        "raw",
        "body",
        "payloads",
        "attack",
        "fuzzing",
        "redirects",
        "host-redirects",
        "max-redirects",
        "unsafe",
        "pipeline",
        "race",
        "race_count",
        "threads",
        "headers",
        "cookie-reuse",
        "req-condition",
        "iterate-all",
        "digest-username",
        "digest-password",
        "self-contained",
        "skip-variables-check",
    }
)
_ALLOWED_MATCHER_TYPES = frozenset({"word", "status", "dsl", "regex", "size"})
_ALLOWED_MATCHER_KEYS = frozenset(
    {
        "type",
        "part",
        "words",
        "status",
        "dsl",
        "regex",
        "size",
        "condition",
        "negative",
        "name",
        "case-insensitive",
    }
)
_ALLOWED_PARTS = frozenset({"body", "header", "all", "response", "status_code"})
_ALLOWED_EXTRACTOR_TYPES = frozenset({"regex"})
_ALLOWED_EXTRACTOR_KEYS = frozenset({"type", "part", "group", "regex", "name"})
_SIGNATURE_LINE = re.compile(r"^# digest: [a-f0-9]{40,400}:([a-f0-9]{32})$")
# Markers that indicate out-of-band interaction, environment/file access or remote content.
_FORBIDDEN_MARKERS = (
    "interactsh",
    "oast",
    "{{env",
    "env(",
    "file://",
    "{{file",
    "helpers/payloads",
    "wordlist",
)


@dataclass(frozen=True)
class TemplateAdmission:
    template_id: str
    path: str
    sha256: str | None
    admitted: bool
    signature_line_fingerprint: str | None
    violations: tuple[str, ...] = field(default_factory=tuple)


def _violation(bucket: list[str], code: str) -> None:
    if code not in bucket:
        bucket.append(code)


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in (_strings(k) + _strings(v))]
    if isinstance(value, list):
        return [s for item in value for s in _strings(item)]
    return []


def _check_matchers(matchers: Any, entry: TemplateEntry, bucket: list[str]) -> None:
    if not isinstance(matchers, list) or not matchers:
        _violation(bucket, "MATCHERS_MISSING")
        return
    for matcher in matchers:
        if not isinstance(matcher, dict):
            _violation(bucket, "MATCHER_MALFORMED")
            continue
        if set(matcher) - _ALLOWED_MATCHER_KEYS:
            _violation(bucket, "MATCHER_UNKNOWN_KEY")
        if matcher.get("type") not in _ALLOWED_MATCHER_TYPES:
            _violation(bucket, "MATCHER_TYPE_NOT_ALLOWED")
        part = matcher.get("part")
        if part is not None and part not in _ALLOWED_PARTS:
            _violation(bucket, "MATCHER_PART_NOT_ALLOWED")
        name = matcher.get("name")
        if name is not None and name not in entry.allowed_matcher_names:
            _violation(bucket, "MATCHER_NAME_NOT_APPROVED")
        if any("{{" in s for s in _strings(matcher)):
            _violation(bucket, "MATCHER_TEMPLATING_NOT_ALLOWED")


def _check_extractors(extractors: Any, bucket: list[str]) -> None:
    if extractors is None:
        return
    if not isinstance(extractors, list):
        _violation(bucket, "EXTRACTOR_MALFORMED")
        return
    for extractor in extractors:
        if not isinstance(extractor, dict):
            _violation(bucket, "EXTRACTOR_MALFORMED")
            continue
        if set(extractor) - _ALLOWED_EXTRACTOR_KEYS:
            # Includes `internal: true`, which would feed extracted values into later requests.
            _violation(bucket, "EXTRACTOR_UNKNOWN_KEY")
        if extractor.get("type") not in _ALLOWED_EXTRACTOR_TYPES:
            _violation(bucket, "EXTRACTOR_TYPE_NOT_ALLOWED")
        if any("{{" in s for s in _strings(extractor)):
            _violation(bucket, "EXTRACTOR_TEMPLATING_NOT_ALLOWED")


def _check_structure(doc: Any, entry: TemplateEntry, bucket: list[str]) -> None:
    if not isinstance(doc, dict):
        _violation(bucket, "TEMPLATE_NOT_A_MAPPING")
        return
    keys = set(doc)
    for key in sorted(keys & _FORBIDDEN_TOP_LEVEL):
        _violation(bucket, f"FORBIDDEN_PROTOCOL_OR_FEATURE:{key}")
    if keys - _ALLOWED_TOP_LEVEL - _FORBIDDEN_TOP_LEVEL:
        _violation(bucket, "UNKNOWN_TOP_LEVEL_KEY")
    if not {"id", "info", "http"} <= keys:
        _violation(bucket, "REQUIRED_KEY_MISSING")
        return

    if doc.get("id") != entry.template_id:
        _violation(bucket, "TEMPLATE_ID_MISMATCH")
    info = doc.get("info")
    if not isinstance(info, dict):
        _violation(bucket, "INFO_MALFORMED")
    else:
        if info.get("name") != entry.name:
            _violation(bucket, "TEMPLATE_NAME_MISMATCH")
        if str(info.get("severity", "")).lower() != entry.expected_severity:
            _violation(bucket, "SEVERITY_MISMATCH")
        metadata = info.get("metadata")
        declared = metadata.get("max-request") if isinstance(metadata, dict) else None
        if not isinstance(declared, int) or declared > entry.max_requests:
            _violation(bucket, "DECLARED_REQUEST_BUDGET_EXCEEDED")

    requests = doc.get("http")
    if not isinstance(requests, list) or not requests:
        _violation(bucket, "HTTP_REQUESTS_MALFORMED")
        return
    paths_seen: list[str] = []
    for request in requests:
        if not isinstance(request, dict):
            _violation(bucket, "HTTP_REQUEST_MALFORMED")
            continue
        for key in sorted(set(request) & _FORBIDDEN_REQUEST_KEYS):
            _violation(bucket, f"FORBIDDEN_REQUEST_FEATURE:{key}")
        if set(request) - _ALLOWED_REQUEST_KEYS - _FORBIDDEN_REQUEST_KEYS:
            _violation(bucket, "UNKNOWN_REQUEST_KEY")
        method = request.get("method")
        if method not in entry.methods:
            _violation(bucket, "METHOD_NOT_ALLOWED")
        paths = request.get("path")
        if not isinstance(paths, list) or not paths or not all(isinstance(p, str) for p in paths):
            _violation(bucket, "PATHS_MALFORMED")
        else:
            paths_seen.extend(paths)
        _check_matchers(request.get("matchers"), entry, bucket)
        _check_extractors(request.get("extractors"), bucket)
        executable = {k: v for k, v in request.items() if k != "extractors"}
        lowered = " ".join(_strings(executable)).lower()
        for marker in _FORBIDDEN_MARKERS:
            if marker in lowered:
                _violation(bucket, "FORBIDDEN_MARKER")
    if paths_seen and (
        sorted(paths_seen) != sorted(entry.request_paths) or len(paths_seen) != len(set(paths_seen))
    ):
        # Any path the manifest did not pin — including an absolute URL or {{RootURL}} variant —
        # could change origin or scope.
        _violation(bucket, "PATH_NOT_PINNED")
    if len(paths_seen) > entry.max_requests:
        _violation(bucket, "REQUEST_BUDGET_EXCEEDED")


def admit_template(root: Path, entry: TemplateEntry) -> TemplateAdmission:
    """Admit one manifest entry from the template root, or explain precisely why not."""

    violations: list[str] = []
    candidate = root / entry.path
    try:
        resolved_root = root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return TemplateAdmission(entry.template_id, entry.path, None, False, None, ("MISSING",))
    if candidate.is_symlink() or not resolved.is_file() or resolved_root not in resolved.parents:
        return TemplateAdmission(
            entry.template_id, entry.path, None, False, None, ("NOT_A_REGULAR_FILE",)
        )
    size = resolved.stat().st_size
    if size > MAX_TEMPLATE_BYTES:
        return TemplateAdmission(entry.template_id, entry.path, None, False, None, ("OVERSIZED",))

    digest = file_sha256(resolved)
    if digest != entry.sha256:
        _violation(violations, "CHECKSUM_MISMATCH")
    raw = resolved.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return TemplateAdmission(entry.template_id, entry.path, digest, False, None, ("NOT_UTF8",))

    lines = [line for line in text.splitlines() if line.strip()]
    fingerprint: str | None = None
    signature = _SIGNATURE_LINE.match(lines[-1]) if lines else None
    if signature is None:
        _violation(violations, "UNSIGNED")
    else:
        fingerprint = signature.group(1)
        if fingerprint != entry.signature.digest_fingerprint:
            _violation(violations, "SIGNER_FINGERPRINT_MISMATCH")
    if sum(1 for line in lines if line.startswith("# digest:")) > 1:
        _violation(violations, "MULTIPLE_SIGNATURE_LINES")

    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        _violation(violations, "YAML_INVALID")
        doc = None
    if doc is not None:
        _check_structure(doc, entry, violations)

    return TemplateAdmission(
        template_id=entry.template_id,
        path=entry.path,
        sha256=digest,
        admitted=not violations,
        signature_line_fingerprint=fingerprint,
        violations=tuple(violations),
    )


def admit_manifest(root: Path, manifest: TemplateManifest) -> list[TemplateAdmission]:
    """Admit every manifest entry. The caller must reject the whole set if ANY entry fails."""

    return [admit_template(root, entry) for entry in manifest.templates]


def unexpected_template_files(root: Path, manifest: TemplateManifest) -> list[str]:
    """Template files present under ``root`` that the manifest does not list.

    They are never passed to Nuclei (the argv names explicit admitted paths only), but their
    presence means the mounted template tree is not the reviewed one, so the runner refuses to
    become ready."""

    listed = {entry.path for entry in manifest.templates}
    extra: list[str] = []
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            continue
        relative = path.relative_to(root).as_posix()
        if relative == manifest.upstream_templates.license_file:
            continue
        if relative not in listed:
            extra.append(relative)
    return extra
