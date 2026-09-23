#!/usr/bin/env python3
"""Render the Phase 1.8 report from existing evidence without scans or model calls."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from aegis.reporting import build_report, write_report_bundle

DEFAULT_LIVE_DIR = "artifacts/phase-1.7d-live-e2e-recon-20260923T153518Z"
DEFAULT_VERIFIER_DIR = "artifacts/phase-1.7b-offline-20260923T085928Z"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--verifier-results",
        type=Path,
        default=Path(DEFAULT_VERIFIER_DIR) / "verifier-results.json",
    )
    parser.add_argument(
        "--live-acceptance",
        type=Path,
        default=Path(DEFAULT_LIVE_DIR) / "acceptance.json",
    )
    parser.add_argument(
        "--delegation-queue",
        type=Path,
        default=Path(DEFAULT_LIVE_DIR) / "delegation_queue.sqlite3",
    )
    parser.add_argument("--output-root", type=Path, default=Path("artifacts"))
    return parser


def _under(root: Path, path: Path) -> Path:
    return path if path.is_absolute() else root / path


def main() -> int:
    args = _parser().parse_args()
    repo_root = args.repo_root.resolve()
    generated_at = datetime.now(UTC)
    output_dir = _under(repo_root, args.output_root) / (
        f"phase-1.8-report-agent-{generated_at.strftime('%Y%m%dT%H%M%SZ')}"
    )
    report = build_report(
        repo_root=repo_root,
        verifier_results_path=_under(repo_root, args.verifier_results),
        live_acceptance_path=_under(repo_root, args.live_acceptance),
        delegation_queue_path=_under(repo_root, args.delegation_queue),
        generated_at=generated_at,
    )
    write_report_bundle(output_dir, report)
    print(
        json.dumps(
            {
                "artifact_path": output_dir.relative_to(repo_root).as_posix(),
                "verdict": report.verdict.model_dump(mode="json"),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if report.verdict.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
