"""WS7 — operator-console report download endpoints (JSON / Markdown / HTML).

Exercises the download surface the Reports view uses: controller-authoritative content, correct
media type, safe attachment filename, and fail-closed handling of unknown reports and unsupported
formats (PDF stays NOT_EVALUATED).
"""

from __future__ import annotations

import httpx
import pytest
from test_phase_2_6 import _source

from aegis import main as main_module
from aegis.multi_agent.report_agent import assemble_report


def _report():
    return assemble_report(
        source=_source(), model_output=None, report_id="rpt-00000000000000ab", version=1
    )


async def _download(monkeypatch: pytest.MonkeyPatch, path: str) -> httpx.Response:
    report = _report()
    monkeypatch.setattr(
        main_module.report_agent_queue,
        "get_report",
        lambda report_id, version: (
            report if report_id == report.report_id and version == 1 else None
        ),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=main_module.app), base_url="http://test"
    ) as client:
        return await client.get(path)


@pytest.mark.parametrize(
    ("extension", "media_type"),
    [("json", "application/json"), ("md", "text/markdown"), ("html", "text/html")],
)
async def test_download_returns_export_with_safe_attachment(
    monkeypatch: pytest.MonkeyPatch, extension: str, media_type: str
) -> None:
    response = await _download(
        monkeypatch, f"/api/console/reports/rpt-00000000000000ab/v/1/download.{extension}"
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith(media_type)
    disposition = response.headers["content-disposition"]
    assert disposition.startswith("attachment; filename=")
    assert disposition.endswith(f'.{extension}"')
    assert response.content  # non-empty rendered export


async def test_download_unsupported_format_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    # PDF is NOT_EVALUATED / unsupported and must 404, never 200 with an empty body.
    response = await _download(
        monkeypatch, "/api/console/reports/rpt-00000000000000ab/v/1/download.pdf"
    )
    assert response.status_code == 404


async def test_download_unknown_report_is_404(monkeypatch: pytest.MonkeyPatch) -> None:
    response = await _download(
        monkeypatch, "/api/console/reports/rpt-ffffffffffffffff/v/1/download.json"
    )
    assert response.status_code == 404


async def test_download_malformed_report_id_is_404(monkeypatch: pytest.MonkeyPatch) -> None:
    response = await _download(
        monkeypatch, "/api/console/reports/not-a-real-id/v/1/download.json"
    )
    assert response.status_code == 404
