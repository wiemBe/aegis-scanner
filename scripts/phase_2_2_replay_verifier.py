"""Phase 2.2 — delayed deterministic verifier adjudication over the PERSISTED live campaign.

The single authorized Phase 2.2 live campaign
(``artifacts/phase-2.2-live-adversary-simulation-20260925T052051Z``) executed the real Lead→Recon
hand-off, the disposable worker's baseline+alternate probes and the vulnerable/patched arms within
budget, but the independent verifier returned INCOMPLETE for both arms: the worker evidence was
transported to the range-controller container through a host environment variable, which
``docker compose exec`` does not forward, so the verifier adjudicated empty evidence.

This script does NOT run a new campaign. It makes **zero** provider calls, issues **zero** worker
probe requests, and starts **no** container. It:

1. verifies the original artifact and its SHA256SUMS are intact;
2. loads the persisted, immutable worker evidence and the controller-owned ground truth captured
   during the original run (the sentinel digest that was live when the worker probed, recorded as
   ``sentinel_reset.previous_sentinel_digest``, and ``detection_active`` from the original verify
   facts) — nothing is regenerated, reconstructed, or substituted from current mutable range state;
3. runs the exact deterministic independent verifier
   (:meth:`RangeVerifier.adjudicate_detection_control_bypass_offline`) over those persisted inputs,
   transported through the fixed bounded, digest-checked path
   (:func:`aegis.multi_agent.adversary_simulation.load_worker_evidence`);
4. recomputes the corrected typed verdict by substituting the delayed verdicts into the original
   record and re-running the campaign verdict; and
5. writes a SEPARATE supplemental artifact (the original is never rewritten).

Eligibility is fail-closed: if the original artifact/SHA256SUMS do not verify, if any required
persisted input is missing/incomplete, or if the decision would need live/mutable range state, the
script stops with ``REPLAY_NOT_ELIGIBLE_NEW_CAMPAIGN_REQUIRED`` and writes nothing.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ORIGINAL_DIR = Path("artifacts/phase-2.2-live-adversary-simulation-20260925T052051Z")
APPLICATION_ID = "aegis-ops"
SCENARIO_ID = "ops-detection-control-bypass-v1"
ELIGIBLE = "LIVE_GO_WITH_DELAYED_VERIFIER_ADJUDICATION"
NOT_ELIGIBLE = "REPLAY_NOT_ELIGIBLE_NEW_CAMPAIGN_REQUIRED"


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _verify_sha256sums(directory: Path) -> tuple[bool, list[str]]:
    """Verify every file listed in the artifact's SHA256SUMS against its recorded digest."""

    sums = directory / "SHA256SUMS"
    if not sums.is_file():
        return False, ["SHA256SUMS missing"]
    problems: list[str] = []
    for line in sums.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        digest, _, name = line.partition("  ")
        target = directory / name
        if not target.is_file():
            problems.append(f"{name}: missing")
        elif _sha256_file(target) != digest:
            problems.append(f"{name}: digest mismatch")
    return (not problems), problems


def _load_live_module() -> Any:
    path = Path(__file__).resolve().parent / "phase_2_2_live_adversary_simulation.py"
    spec = importlib.util.spec_from_file_location("phase_2_2_live_adversary_simulation", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _arm_inputs(arm_rec: dict[str, Any]) -> dict[str, Any] | None:
    """Extract the persisted worker evidence + controller ground truth for one arm, or None."""

    adjudication_input = arm_rec.get("adjudication_input")
    sentinel_reset = (arm_rec.get("sentinel_reset") or {}).get("result") or {}
    original_verify_facts = (arm_rec.get("verify") or {}).get("result", {}).get("facts", {})
    controller_digest = sentinel_reset.get("previous_sentinel_digest")
    detection_active = original_verify_facts.get("detection_active")
    if not isinstance(adjudication_input, dict):
        return None
    if not isinstance(controller_digest, str) or not controller_digest:
        return None
    if detection_active is not True:
        return None
    return {
        "adjudication_input": adjudication_input,
        "controller_sentinel_digest": controller_digest,
        "detection_active": True,
    }


def main() -> int:  # noqa: PLR0915
    started = datetime.now(UTC)

    # (1) Original artifact + SHA256SUMS must be intact.
    if not ORIGINAL_DIR.is_dir():
        print(json.dumps({"result": NOT_ELIGIBLE, "reason": "ORIGINAL_ARTIFACT_MISSING"}))
        return 2
    sums_ok, sums_problems = _verify_sha256sums(ORIGINAL_DIR)
    acceptance_path = ORIGINAL_DIR / "acceptance.json"
    if not sums_ok or not acceptance_path.is_file():
        print(
            json.dumps(
                {
                    "result": NOT_ELIGIBLE,
                    "reason": "ORIGINAL_SHA256SUMS_INVALID",
                    "problems": sums_problems,
                }
            )
        )
        return 2
    original_acceptance_sha256 = _sha256_file(acceptance_path)
    acceptance = json.loads(acceptance_path.read_text())
    record = acceptance["record"]

    from aegis.multi_agent.adversary_simulation import (
        load_worker_evidence,
        serialize_worker_evidence,
        worker_evidence_digest,
    )
    from aegis_range.controller import RangeController

    controller = RangeController()

    # (2)+(3) Load persisted inputs and run the deterministic verifier offline, per arm.
    arms: dict[str, Any] = {}
    for arm in ("vulnerable", "patched"):
        arm_rec = record.get(arm) or {}
        inputs = _arm_inputs(arm_rec)
        if inputs is None:
            print(
                json.dumps(
                    {"result": NOT_ELIGIBLE, "reason": "PERSISTED_INPUTS_INCOMPLETE", "arm": arm}
                )
            )
            return 2
        # Transport the persisted evidence through the FIXED bounded, digest-checked path (the same
        # code the live container path now uses) so the verifier gets exactly the persisted bytes.
        raw = serialize_worker_evidence(inputs["adjudication_input"])
        digest = worker_evidence_digest(raw)
        try:
            evidence = load_worker_evidence(raw, expected_digest=digest)
        except Exception as exc:  # noqa: BLE001 - fail closed
            print(json.dumps({"result": NOT_ELIGIBLE, "reason": f"EVIDENCE_TRANSPORT_{exc}"[:120]}))
            return 2
        verdict = controller.adjudicate_detection_control_bypass_offline(
            APPLICATION_ID,
            evidence,
            detection_active=inputs["detection_active"],
            controller_sentinel_digest=inputs["controller_sentinel_digest"],
        )
        arms[arm] = {
            "worker_evidence": evidence,
            "worker_evidence_digest": digest,
            "controller_sentinel_digest": inputs["controller_sentinel_digest"],
            "detection_active": inputs["detection_active"],
            "verdict": verdict.model_dump(mode="json"),
        }

    # (4) Recompute the corrected campaign verdict: substitute the delayed verdicts into a COPY of
    # the original record and re-run the existing verdict logic. The original is never mutated.
    live = _load_live_module()
    corrected_record = json.loads(json.dumps(record))  # deep copy
    for arm in ("vulnerable", "patched"):
        corrected_record[arm]["verify"] = {"rc": 0, "result": arms[arm]["verdict"]}
    corrected_verdict = live._verdict(corrected_record)

    vuln_status = arms["vulnerable"]["verdict"]["status"]
    patched_status = arms["patched"]["verdict"]["status"]
    decision = (
        ELIGIBLE
        if (corrected_verdict["passed"] and vuln_status == "CONFIRMED" and patched_status == "PASS")
        else NOT_ELIGIBLE
    )

    # (6) Supplemental artifact (separate; original never touched).
    stamp = started.strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path("artifacts") / f"phase-2.2-delayed-verifier-adjudication-{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    verifier_src = Path("src/aegis_range/verifier.py")
    adv_src = Path("src/aegis/multi_agent/adversary_simulation.py")
    supplemental: dict[str, Any] = {
        "phase": "2.2",
        "kind": "DELAYED_DETERMINISTIC_VERIFIER_ADJUDICATION",
        "result": decision,
        "combines": (
            "the original live worker campaign (real Lead→Recon hand-off + disposable worker "
            "baseline/alternate probes, both arms) with a delayed deterministic independent "
            "verifier adjudication over the persisted immutable inputs — no new provider calls, no "
            "new worker probes, no live range state"
        ),
        "original": {
            "run_id": acceptance.get("scenario", {}),
            "artifact_dir": str(ORIGINAL_DIR),
            "artifact_acceptance_sha256": original_acceptance_sha256,
            "artifact_sha256sums_verified": True,
            "original_live_verdict": acceptance.get("verdict"),
            "original_provider_calls_total": acceptance.get("provider_calls_total"),
            "original_provider_tokens_total": acceptance.get("provider_tokens_total"),
        },
        "replay_provenance": {
            "provider_calls": 0,
            "worker_probe_requests": 0,
            "verifier_probe_requests": 0,
            "containers_started": 0,
            "live_range_state_used": False,
            "reconstructed_evidence": False,
            "git_head_commit": _git_head(),
            "verifier_code_working_tree_uncommitted": True,
            "verifier_py_sha256": _sha256_file(verifier_src) if verifier_src.is_file() else None,
            "adversary_simulation_py_sha256": _sha256_file(adv_src) if adv_src.is_file() else None,
        },
        "arms": arms,
        "corrected_verdict_detail": corrected_verdict,
        "corrected_verdict": (
            "LIVE GO for one controller-bounded synthetic HTTP detection-control bypass scenario "
            "pair with a real Lead-to-Recon-Agent handoff"
            if decision == ELIGIBLE
            else "REPLAY_NOT_ELIGIBLE"
        ),
        "elapsed_seconds": round((datetime.now(UTC) - started).total_seconds(), 3),
    }
    (out_dir / "supplemental_adjudication.json").write_text(
        json.dumps(supplemental, indent=2, sort_keys=True) + "\n"
    )
    sha_names = sorted(p.name for p in out_dir.iterdir() if p.is_file() and p.name != "SHA256SUMS")
    (out_dir / "SHA256SUMS").write_text(
        "\n".join(f"{_sha256_file(out_dir / n)}  {n}" for n in sha_names) + "\n"
    )

    print(
        json.dumps(
            {
                "result": decision,
                "vulnerable_status": vuln_status,
                "patched_status": patched_status,
                "corrected_verdict_passed": corrected_verdict["passed"],
                "evidence_dir": str(out_dir),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if decision == ELIGIBLE else 1


def _git_head() -> str | None:
    import subprocess

    try:
        out = subprocess.run(  # noqa: S603
            ["git", "rev-parse", "HEAD"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=10,
        )
        return out.stdout.strip() or None
    except Exception:  # noqa: BLE001
        return None


if __name__ == "__main__":
    raise SystemExit(main())
