#!/usr/bin/env python3
"""Phase 2.0 — OFFLINE verdict-semantics reconciliation.

Regenerates the *corrected* Phase 2.0 acceptance verdict and a small reconciliation artifact
from the already-persisted live evidence. It runs **no** provider calls, containers, scanners,
capabilities or verifiers, and it never modifies or overwrites the original live evidence under
``artifacts/phase-2.0-live-multi-primitive-chain-*``.

What it corrects (semantics only — the proven chain behavior is untouched):

* the misnamed ``real_agent_handoffs_persisted`` check is regenerated as
  ``chain_link_handoff_metadata_persisted`` (link metadata only), and
* two explicit scope fields are surfaced —
  ``separate_live_agent_stage_jobs_persisted`` and ``live_multi_agent_stage_handoffs`` — both
  ``NOT_EVALUATED`` for the bounded run, so ``passed=true`` can never be read as multi-agent-stage
  acceptance.

Usage counting distinguishes the authoritative attempt from the cumulative phase, and unavailable
(rejected-call) token usage is reported as an explicit unknown — never coerced to zero.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sqlite3
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
FAILED_ATTEMPT_DIR = "artifacts/phase-2.0-live-multi-primitive-chain-20260923T194011Z"
AUTHORITATIVE_ATTEMPT_DIR = "artifacts/phase-2.0-live-multi-primitive-chain-20260923T194626Z"
OUTPUT_DIR = "artifacts/phase-2.0-closure-reconciliation"

MAX_PROVIDER_CALLS = 12
MAX_PROVIDER_TOKENS = 60_000
UNKNOWN = "UNKNOWN"
NOT_EVALUATED = "NOT_EVALUATED"

FINAL_CLAIM = (
    "LIVE GO for one verifier-confirmed multi-primitive attack chain and its patched break "
    "inside the bounded synthetic range. Live multi-agent stage handoffs: NOT_EVALUATED."
)


# --------------------------------------------------------------------------- #
# Pure helpers (unit-tested).
# --------------------------------------------------------------------------- #
def aggregate_usage(attempts: list[dict[str, Any]]) -> dict[str, int]:
    """Cumulative phase usage across attempts.

    ``provider_tokens_total`` that is not a plain int (e.g. ``"UNKNOWN"`` for calls rejected before
    usage was recorded) is *never* treated as zero: those calls are counted under
    ``phase_cumulative_unknown_token_calls`` instead of being folded into the known-token sum.
    """

    cumulative_calls = 0
    known_tokens = 0
    unknown_token_calls = 0
    for attempt in attempts:
        calls = int(attempt["provider_calls_total"])
        cumulative_calls += calls
        tokens = attempt["provider_tokens_total"]
        if isinstance(tokens, int) and not isinstance(tokens, bool):
            known_tokens += tokens
        else:
            unknown_token_calls += calls
    return {
        "phase_cumulative_provider_calls": cumulative_calls,
        "phase_cumulative_known_provider_tokens": known_tokens,
        "phase_cumulative_unknown_token_calls": unknown_token_calls,
    }


def build_usage_block(
    authoritative: dict[str, Any],
    attempts: list[dict[str, Any]],
    *,
    max_calls: int = MAX_PROVIDER_CALLS,
    max_tokens: int = MAX_PROVIDER_TOKENS,
    auditable_cumulative_token_upper_bound: int | None = None,
) -> dict[str, Any]:
    """Report authoritative-attempt usage and cumulative phase usage *separately*.

    ``within_phase_token_ceiling`` stays ``"UNKNOWN"`` whenever any call has unavailable usage. It
    may only become ``True`` if an explicit, auditable cumulative upper bound (request-side input
    tokens + output-token ceiling) is supplied and proves the total stayed below ``max_tokens``. It
    is never inferred from likely prompt size.
    """

    agg = aggregate_usage(attempts)
    auth_calls = int(authoritative["provider_calls_total"])
    auth_tokens = authoritative["provider_tokens_total"]

    within_phase_token: Any = UNKNOWN
    if agg["phase_cumulative_unknown_token_calls"] == 0:
        within_phase_token = agg["phase_cumulative_known_provider_tokens"] <= max_tokens
    elif auditable_cumulative_token_upper_bound is not None:
        within_phase_token = auditable_cumulative_token_upper_bound <= max_tokens

    return {
        "authoritative_attempt_provider_calls": auth_calls,
        "authoritative_attempt_provider_tokens": auth_tokens,
        "phase_cumulative_provider_calls": agg["phase_cumulative_provider_calls"],
        "phase_cumulative_known_provider_tokens": agg["phase_cumulative_known_provider_tokens"],
        "phase_cumulative_unknown_token_calls": agg["phase_cumulative_unknown_token_calls"],
        "within_authoritative_attempt_call_ceiling": auth_calls <= max_calls,
        "within_authoritative_attempt_token_ceiling": (
            isinstance(auth_tokens, int)
            and not isinstance(auth_tokens, bool)
            and auth_tokens <= max_tokens
        ),
        "within_phase_call_ceiling": agg["phase_cumulative_provider_calls"] <= max_calls,
        "within_phase_token_ceiling": within_phase_token,
    }


def build_reconciliation(
    *,
    failed_acceptance: dict[str, Any],
    authoritative_acceptance: dict[str, Any],
    corrected_verdict: dict[str, Any],
    ledger_rows: dict[str, Any],
    provenance: dict[str, Any],
) -> dict[str, Any]:
    """Assemble the offline reconciliation object from existing evidence only."""

    usage = build_usage_block(
        authoritative_acceptance,
        [authoritative_acceptance, failed_acceptance],
    )
    return {
        "phase": "2.0",
        "kind": "offline-verdict-semantics-reconciliation",
        "generated_offline": True,
        "note": (
            "Regenerated from persisted artifacts. No provider calls, containers, scanners, "
            "capabilities or verifiers were executed. Original live evidence is unmodified."
        ),
        "source_artifacts": {
            "failed_attempt": FAILED_ATTEMPT_DIR,
            "authoritative_attempt": AUTHORITATIVE_ATTEMPT_DIR,
        },
        "provenance": provenance,
        "attempt_accounting": [
            {
                "attempt": 1,
                "artifact": FAILED_ATTEMPT_DIR,
                "outcome": failed_acceptance.get("verdict"),
                "provider_calls": failed_acceptance.get("provider_calls_total"),
                "provider_tokens": failed_acceptance.get("provider_tokens_total"),
                "rejection": "PLAN_ATTACK_CHAIN.objective string_too_long (cap 300 < 320)",
                "authoritative": False,
            },
            {
                "attempt": 2,
                "artifact": AUTHORITATIVE_ATTEMPT_DIR,
                "outcome": "LIVE_GO",
                "provider_calls": authoritative_acceptance.get("provider_calls_total"),
                "provider_tokens": authoritative_acceptance.get("provider_tokens_total"),
                "rejection": None,
                "authoritative": True,
            },
        ],
        "usage": usage,
        "semantic_corrections": {
            "renamed_check": {
                "from": "real_agent_handoffs_persisted",
                "to": "chain_link_handoff_metadata_persisted",
                "reason": (
                    "No separate CLOUD_BOUNDARY_AGENT or AUTHORIZATION_AGENT jobs were created; "
                    "the check validates ordered chain-link metadata (role labels, evidence refs, "
                    "source hashes, depends_on_link_id, credential-reference dependency) only."
                ),
            },
            "added_fields": [
                "separate_live_agent_stage_jobs_persisted",
                "live_multi_agent_stage_handoffs",
            ],
            "principle": (
                "Producing-agent role labels on chain links are never proof of live agent "
                "execution. Link metadata and separate live agent jobs are distinct concepts."
            ),
        },
        "corrected_verdict": corrected_verdict,
        "attack_chain_status": corrected_verdict.get("attack_chain_status"),
        "separate_live_agent_stage_jobs_persisted": corrected_verdict.get(
            "separate_live_agent_stage_jobs_persisted"
        ),
        "live_multi_agent_stage_handoffs": corrected_verdict.get("live_multi_agent_stage_handoffs"),
        "final_claim": FINAL_CLAIM,
        "chain_ledger_rows": ledger_rows,
        "objective_rejection_and_correction": {
            "rejection": (
                "PLAN_ATTACK_CHAIN.objective capped at 300 chars; handed-in objective 320."
            ),
            "correction": (
                "Contract prose fields widened to 600 with headroom; objective shortened."
            ),
            "re_run": "One re-run only, transparently, with explicit operator authorization.",
        },
    }


# --------------------------------------------------------------------------- #
# I/O (main only).
# --------------------------------------------------------------------------- #
def _load_orchestrator() -> Any:
    path = REPO_ROOT / "scripts" / "phase_2_0_live_multi_primitive_chain.py"
    spec = importlib.util.spec_from_file_location("phase_2_0_live_multi_primitive_chain", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _read_json(path: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(path.read_text())
    return data


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _ledger_rows(db_path: Path) -> dict[str, Any]:
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        jobs = [
            {k: row[k] for k in ("job_id", "to_agent", "status", "address")}
            for row in con.execute(
                "SELECT job_id, to_agent, status, address FROM chain_jobs ORDER BY enqueued_at"
            )
        ]
        # chain_links stores the typed link in a JSON ``payload`` column.
        links = []
        for row in con.execute(
            "SELECT link_id, chain_id, stage_index, payload FROM chain_links "
            "ORDER BY stage_index, updated_at"
        ):
            payload = json.loads(row["payload"]) if row["payload"] else {}
            links.append(
                {
                    "link_id": row["link_id"],
                    "chain_id": row["chain_id"],
                    "stage_index": row["stage_index"],
                    "primitive_type": payload.get("primitive_type"),
                    "producing_agent": payload.get("producing_agent"),
                    "consuming_agent": payload.get("consuming_agent"),
                    "depends_on_link_id": payload.get("depends_on_link_id"),
                    "consumes_prior_credential_reference": payload.get(
                        "consumes_prior_credential_reference"
                    ),
                    "source_evidence_sha256": payload.get("source_evidence_sha256"),
                    "verification_state": payload.get("verification_state"),
                }
            )
    finally:
        con.close()
    return {
        "chain_jobs": jobs,
        "chain_links": links,
        "distinct_job_roles": sorted({j["to_agent"] for j in jobs}),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", default=OUTPUT_DIR)
    args = parser.parse_args()

    failed = _read_json(REPO_ROOT / FAILED_ATTEMPT_DIR / "acceptance.json")
    authoritative = _read_json(REPO_ROOT / AUTHORITATIVE_ATTEMPT_DIR / "acceptance.json")

    module = _load_orchestrator()
    corrected_verdict = module._verdict(authoritative["record"])

    ledger_rows = _ledger_rows(
        REPO_ROOT / AUTHORITATIVE_ATTEMPT_DIR / "attack_chain_ledger.sqlite3"
    )

    provenance = {
        "failed_acceptance_sha256": _sha256(
            REPO_ROOT / FAILED_ATTEMPT_DIR / "acceptance.json"
        ),
        "authoritative_acceptance_sha256": _sha256(
            REPO_ROOT / AUTHORITATIVE_ATTEMPT_DIR / "acceptance.json"
        ),
        "authoritative_ledger_sha256": _sha256(
            REPO_ROOT / AUTHORITATIVE_ATTEMPT_DIR / "attack_chain_ledger.sqlite3"
        ),
    }

    reconciliation = build_reconciliation(
        failed_acceptance=failed,
        authoritative_acceptance=authoritative,
        corrected_verdict=corrected_verdict,
        ledger_rows=ledger_rows,
        provenance=provenance,
    )

    out_dir = REPO_ROOT / args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "reconciliation.json"
    payload = json.dumps(reconciliation, indent=2, sort_keys=True) + "\n"
    out_path.write_text(payload)
    (out_dir / "SHA256SUMS").write_text(
        f"{hashlib.sha256(payload.encode()).hexdigest()}  reconciliation.json\n"
    )
    print(f"wrote {out_path}")
    print(f"attack_chain_status={reconciliation['attack_chain_status']}")
    print(f"live_multi_agent_stage_handoffs={reconciliation['live_multi_agent_stage_handoffs']}")
    print(f"within_phase_token_ceiling={reconciliation['usage']['within_phase_token_ceiling']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
