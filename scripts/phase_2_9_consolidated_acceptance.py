"""Phase 2.9 — consolidated end-to-end synthetic acceptance runner.

Composes the accepted Phase 2.3 (remediation/retest), Phase 2.6 (REPORT_AGENT) and Phase 2.7
(assessment lifecycle) capabilities into ONE bounded, controller-governed synthetic assessment
lifecycle over ``aegis-ops`` and emits the typed per-contract acceptance verdicts + artifact
manifest. See :mod:`aegis.multi_agent.consolidated_campaign`.

Three modes:

* **default (inert)** — prints the PROPOSED campaign and exits. It loads no secret, starts no
  container, creates no job, changes no target state and makes no network/provider call.
* ``--dry-run`` — a PROVIDER-FREE run. Deterministic gateway doubles at the model boundary; real
  controller/queue/verifier/remediation/report/cleanup. ``--containerized`` (default for dry-run)
  stands up a real ``aegis_range.ops`` container on an internal no-egress network; ``--in-process``
  uses the network double. This never loads ``.env.gateway`` and never calls a provider. It may
  establish ``CONTAINERIZED_SYNTHETIC_PASS`` / ``OFFLINE_INTEGRATION_PASS``; provider/model status
  stays ``NOT_EVALUATED``.
* ``--execute-live`` — the LIVE path. It arms ONLY with an explicit ``--authorization-ref`` and the
  EXACT ``--max-provider-calls 5`` / ``--max-total-tokens 15000`` caps; otherwise it returns the
  typed ``LIVE_AUTHORIZATION_REQUIRED`` / ``INVALID_LIVE_BUDGET`` BEFORE any side effect. Once armed
  it verifies (existence only) that ``.env.gateway`` is present, then runs ONE isolated campaign
  via :func:`aegis.multi_agent.phase_2_9_live_gateway.run_live_campaign`: a uniquely-named DeepSeek
  gateway stack (key confined to ``llm-gateway``), the five typed model calls executed from the
  control-plane side over bounded stdin JSON, the same fail-closed :class:`CampaignProviderBudget`,
  and unconditional teardown of both stacks. It observes and records the live evidence but never
  claims LIVE GO — the top-line provider status stays ``NOT_EVALUATED`` pending human adjudication.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aegis.multi_agent.live_safety import LiveExecutionRequest, LiveSafetyError

CANONICAL_MODEL = "deepseek-v4-pro"
NOT_EVALUATED = "NOT_EVALUATED"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute-live", action="store_true", help="arm the live provider path")
    parser.add_argument("--authorization-ref", default=None, help="non-secret authorization ref")
    parser.add_argument("--max-provider-calls", type=int, default=None)
    parser.add_argument("--max-total-tokens", type=int, default=None)
    parser.add_argument(
        "--dry-run", action="store_true", help="run the provider-free acceptance campaign"
    )
    parser.add_argument(
        "--in-process", action="store_true",
        help="dry-run only: use the in-process network double instead of a real container",
    )
    parser.add_argument("--json", action="store_true", help="emit the full record as JSON")
    return parser


def _print(obj: Any) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True))


def _containerized_status(containerized: bool, containerized_pass: bool, offline_pass: bool) -> str:
    """Honest containerized status: only a passing REAL container dry run earns the container pass.

    An in-process dry run never touches a container, so the containerized dimension stays
    NOT_EVALUATED there (the offline dimension is carried by the implementation status instead);
    it is never conveniently reported as a container pass.
    """

    del offline_pass  # the offline dimension is reported via phase_2_9_implementation_status
    if not containerized:
        return NOT_EVALUATED
    return "CONTAINERIZED_SYNTHETIC_PASS" if containerized_pass else "PARTIAL"


def _run_dry_run(*, containerized: bool, emit_json: bool) -> int:
    # Imported lazily so the inert default path constructs no ledgers and touches no docker module.
    from aegis.multi_agent.consolidated_campaign import (
        ConsolidatedOpsCampaign,
        build_evidence_accounting,
        build_phase_2_9_checks,
        build_typed_verdicts,
        is_live_armed,
        write_campaign_artifacts,
    )

    started = datetime.now(UTC)
    stamp = started.strftime("%Y%m%dT%H%M%SZ")
    out_root = Path("artifacts") / f"phase-2.9-consolidated-{stamp}"
    work_dir = out_root / "work"
    art_dir = out_root / "evidence"

    # Guard self-check: the default request is inert; only the exact flags arm (recorded below).
    guard_enforced = (
        not is_live_armed(LiveExecutionRequest())
        and not is_live_armed(LiveExecutionRequest(execute_live=True))
        and not is_live_armed(
            LiveExecutionRequest(
                execute_live=True, authorization_ref="ops", max_provider_calls=4,
                max_total_tokens=15000,
            )
        )
        and is_live_armed(
            LiveExecutionRequest(
                execute_live=True, authorization_ref="ops-2-9-dry-run-selfcheck",
                max_provider_calls=5, max_total_tokens=15000,
            )
        )
    )

    campaign = ConsolidatedOpsCampaign(base_dir=work_dir, containerized=containerized)
    record = campaign.run()
    artifact_result = write_campaign_artifacts(art_dir, campaign, record)
    checks = build_phase_2_9_checks(
        record,
        guard_enforced=guard_enforced,
        artifact_manifest_verified=artifact_result["manifest_verified"],
        report_outputs_persisted=artifact_result["report_outputs_persisted"],
    )
    verdicts = build_typed_verdicts(record, checks)

    manifest_ok = bool(artifact_result["manifest_verified"])
    p29_ok = bool(verdicts["phase_2_9"]["satisfied"])
    containerized_pass = containerized and p29_ok and manifest_ok
    offline_pass = p29_ok and manifest_ok
    accounting = build_evidence_accounting(record)
    true_checks = sorted(k for k, v in checks.items() if v is True)
    not_evaluated_checks = sorted(k for k, v in checks.items() if v == NOT_EVALUATED)
    false_checks = sorted(k for k, v in checks.items() if v is False)
    acceptance = {
        "phase": "2.9",
        "evidence_type": (
            "CONTAINERIZED_SYNTHETIC" if containerized else "OFFLINE_INTEGRATION"
        ),
        "range_backend": record["range_backend"],
        "canonical_model_name": CANONICAL_MODEL,
        # Deterministic-gateway (simulated) vs provider accounting, kept strictly separate.
        "evidence_accounting": accounting,
        "checks": checks,
        # Honest counts: some checks are intentionally live-only and stay NOT_EVALUATED even in a
        # passing containerized run, so a blanket "all checks True" is never reported.
        "check_counts": {
            "true": len(true_checks),
            "not_evaluated": len(not_evaluated_checks),
            "false": len(false_checks),
            "total": len(checks),
        },
        "not_evaluated_checks": not_evaluated_checks,
        "typed_verdicts": verdicts,
        "phase_2_9_implementation_status": "OFFLINE_PASS" if offline_pass else "PARTIAL",
        "phase_2_9_containerized_status": _containerized_status(
            containerized, containerized_pass, offline_pass
        ),
        "phase_2_9_live_provider_status": NOT_EVALUATED,
        "phase_2_3_live_status": NOT_EVALUATED,
        "phase_2_6_live_status": NOT_EVALUATED,
        "phase_2_7_live_status": NOT_EVALUATED,
        "canonical_job_addresses": {
            "lead": record["jobs"]["lead_job_address"],
            "initial_recon": record["jobs"]["recon_job_address"],
            "retest_recon": record["jobs"]["retest_recon_job_address"],
            "report": record["jobs"]["report_job_address"],
        },
        "elapsed_seconds": round((datetime.now(UTC) - started).total_seconds(), 2),
        "record": record,
    }
    (art_dir / "acceptance_verdict.json").write_text(
        json.dumps(acceptance, indent=2, sort_keys=True) + "\n"
    )
    # Append the verdict file's digest to the manifest (the evidence set was verified before it).
    verdict_digest = hashlib.sha256((art_dir / "acceptance_verdict.json").read_bytes()).hexdigest()
    with (art_dir / "SHA256SUMS").open("a") as fh:
        fh.write(f"{verdict_digest}  acceptance_verdict.json\n")

    summary = {
        "phase": "2.9",
        "evidence_dir": str(art_dir),
        "range_backend": record["range_backend"],
        "final_state": record["lifecycle"]["final_state"],
        "gateway_mode": accounting["gateway_mode"],
        "simulated_model_calls": accounting["simulated_model_calls"],
        "simulated_usage_tokens": accounting["simulated_usage_tokens"],
        "provider_calls": accounting["provider_calls"],
        "provider_usage_tokens": accounting["provider_usage_tokens"],
        "exact_model_identity": accounting["exact_model_identity"],
        "live_provider_budget_enforced": accounting["live_provider_budget_enforced"],
        "check_counts": acceptance["check_counts"],
        "false_checks": false_checks,
        "not_evaluated_checks": not_evaluated_checks,
        "canonical_job_addresses": acceptance["canonical_job_addresses"],
        "phase_2_9_implementation_status": acceptance["phase_2_9_implementation_status"],
        "phase_2_9_containerized_status": acceptance["phase_2_9_containerized_status"],
        "phase_2_9_live_provider_status": NOT_EVALUATED,
        "typed_verdicts_satisfied": {
            k: verdicts[k]["satisfied"]
            for k in ("phase_2_3", "phase_2_6", "phase_2_7", "phase_2_9")
        },
    }
    _print(acceptance if emit_json else summary)
    return 0 if verdicts["phase_2_9"]["satisfied"] and artifact_result["manifest_verified"] else 1


def _run_live(args: argparse.Namespace) -> int:
    """The live path: arm from the exact flags BEFORE any side effect, then run the campaign.

    Ordering is strict and fail-closed:

    1. The pure guard validates explicit intent + a non-secret authorization ref + the EXACT
       5-call / 15,000-token caps. A missing/secret-shaped/different value returns the typed refusal
       here, BEFORE ``.env.gateway`` is loaded, any Docker stack starts, any job is created, any
       target state changes or any provider call begins.
    2. Only once armed do we check (existence only) that the gateway configuration is present. If it
       is missing we fail closed with a typed blocker and still start nothing.
    3. The isolated live campaign then runs against the uniquely-named DeepSeek gateway stack, with
       the provider key confined to ``llm-gateway`` and both stacks torn down unconditionally.
    """

    from aegis.multi_agent.consolidated_campaign import live_guard

    request = LiveExecutionRequest(
        execute_live=True,
        authorization_ref=args.authorization_ref,
        max_provider_calls=args.max_provider_calls,
        max_total_tokens=args.max_total_tokens,
    )
    try:
        armed = live_guard().evaluate(request)
    except LiveSafetyError as exc:
        _print({"phase": "2.9", "armed": False, "error_code": exc.code, "detail": exc.detail})
        return 2

    # Existence-only gateway configuration gate (the value is never read here; compose mounts it
    # into the llm-gateway service alone). This runs only AFTER a successful arm.
    if not Path(".env.gateway").exists():
        _print(
            {
                "phase": "2.9",
                "armed": True,
                "status": "LIVE_BLOCKED_MISSING_GATEWAY_CONFIGURATION",
                "detail": (
                    "Armed, but .env.gateway is absent in this working tree; no stack was started "
                    "and no provider was called."
                ),
            }
        )
        return 4

    # Lazy import so the inert default / dry-run paths never touch the live module or docker.
    from aegis.multi_agent.phase_2_9_live_gateway import run_live_campaign

    started = datetime.now(UTC)
    stamp = started.strftime("%Y%m%dT%H%M%SZ")
    out_root = Path("artifacts") / f"phase-2.9-live-{stamp}"
    acceptance = run_live_campaign(
        authorization_ref=armed.authorization_ref,
        out_root=out_root,
    )
    _print(acceptance)
    return 0 if acceptance.get("status") == "LIVE_OBSERVED_PENDING_HUMAN_ADJUDICATION" else 5


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.execute_live:
        return _run_live(args)

    if args.dry_run:
        # Default the dry run to the real-container backend unless --in-process is requested.
        return _run_dry_run(containerized=not args.in_process, emit_json=args.json)

    # Inert default: print the proposed campaign, no side effect of any kind.
    from aegis.multi_agent.consolidated_campaign import proposed_campaign

    _print(proposed_campaign())
    return 0


if __name__ == "__main__":
    sys.exit(main())
