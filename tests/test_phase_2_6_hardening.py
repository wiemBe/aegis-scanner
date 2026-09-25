"""WS8 — Phase 2.6 reporting export hardening (deterministic, offline).

Covers the export-sink defenses added on top of the accepted Phase 2.6 report agent: large-field
truncation, safe download filenames / Content-Disposition, and bundle integrity verification.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from test_phase_2_6 import _source  # reuse the accepted ReportSource builder

from aegis.multi_agent.report_agent import (
    MAX_RENDERED_CHARS,
    ReportProjectionError,
    assemble_report,
    content_disposition,
    export_media_type,
    render_report_html,
    render_report_markdown,
    safe_report_filename,
    verify_report_bundle,
    write_report_bundle,
)


def _report(**overrides: object):
    source = _source(**overrides)
    return assemble_report(
        source=source, model_output=None, report_id="rpt-000000000000abcd", version=1
    )


def test_oversized_prose_is_truncated_at_the_render_sink() -> None:
    # All model-facing report fields are already length-bounded at the contract layer (defense in
    # depth); the render-sink cap additionally protects against a report object that somehow carries
    # an oversized field. Inject one via model_copy (which skips field-length validation).
    huge = "A" * (MAX_RENDERED_CHARS + 500)
    report = _report().model_copy(update={"executive_summary": huge})
    markdown = render_report_markdown(report)
    html_out = render_report_html(report)
    for rendered in (markdown, html_out):
        assert "…[truncated 500 chars]" in rendered
        # The full oversized blob never appears verbatim.
        assert huge not in rendered


def test_truncation_is_deterministic() -> None:
    report = _report().model_copy(
        update={"executive_summary": "B" * (MAX_RENDERED_CHARS + 10)}
    )
    assert render_report_markdown(report) == render_report_markdown(report)
    assert render_report_html(report) == render_report_html(report)


def test_safe_filename_neutralizes_traversal_and_header_injection() -> None:
    report = _report(campaign_id="../../etc/passwd\r\nSet-Cookie: x=y ../..")
    name = safe_report_filename(report, "json")
    assert "/" not in name and "\\" not in name
    assert "\r" not in name and "\n" not in name
    assert ".." not in name
    assert not name.startswith(".")
    assert name.endswith(".json")


def test_content_disposition_is_attachment_with_safe_name() -> None:
    report = _report(campaign_id="camp normal")
    header = content_disposition(report, "html")
    assert header.startswith("attachment; filename=")
    assert "\r" not in header and "\n" not in header
    assert header.endswith('.html"')


def test_unsupported_extension_fails_closed() -> None:
    report = _report()
    with pytest.raises(ReportProjectionError):
        safe_report_filename(report, "exe")
    with pytest.raises(ReportProjectionError):
        export_media_type("pdf")  # PDF export stays NOT_EVALUATED / unsupported


def test_media_types_are_stable() -> None:
    assert export_media_type("json") == "application/json"
    assert export_media_type("md") == "text/markdown"
    assert export_media_type(".html") == "text/html"


def test_verify_bundle_detects_tampering(tmp_path: Path) -> None:
    report = _report()
    out = tmp_path / "bundle"
    write_report_bundle(out, report)
    assert verify_report_bundle(out) is True
    # Tamper with one export; verification must fail closed.
    (out / "report.md").write_text("tampered\n", encoding="utf-8")
    with pytest.raises(ReportProjectionError, match="checksum mismatch"):
        verify_report_bundle(out)


def test_verify_bundle_requires_manifest(tmp_path: Path) -> None:
    with pytest.raises(ReportProjectionError, match="SHA256SUMS"):
        verify_report_bundle(tmp_path)
