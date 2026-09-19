"""Aggregate Phase 0.8 evidence into a model comparison, a candidate-rejection distribution and an
execution-policy audit (docs/phase-0.8, Part K). Reads only the recorded evidence artifacts; it
never calls a model or target and never mutates a scan result."""

import json
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
MODELS = ["qwen3:8b", "foundation-sec:8b-q4"]
WINNER = "qwen3:8b"


def load(name: str) -> dict[str, Any] | None:
    path = ARTIFACTS / name
    if not path.exists():
        return None
    return json.loads(path.read_text())


def slug(model: str) -> str:
    return model.replace(":", "-")


def iter_scans(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    scans: list[dict[str, Any]] = []
    for trial in evidence.get("trials", []):
        scans.append(trial["discovery"])
        if trial.get("retest"):
            scans.append(trial["retest"])
    for trials in evidence.get("matrix", {}).values():
        for trial in trials:
            scans.append(trial["scan"])
    return scans


def main() -> None:
    comparison: dict[str, Any] = {
        "contract_version": 3, "execution_policy_version": 1, "models": {}
    }
    rejections: Counter[str] = Counter()
    admitted = 0
    not_admitted = 0
    executed = 0
    policy_versions: Counter[str] = Counter()

    for model in MODELS:
        narrow = load(f"phase-0.8-narrow-{slug(model)}.json")
        controls = load(f"phase-0.8-controls-{slug(model)}.json")
        entry: dict[str, Any] = {
            "narrow_positive": (narrow or {}).get("summary"),
            "narrow_verdict": (narrow or {}).get("verdict", "NOT_RUN"),
            "controls_verdict": (controls or {}).get("verdict", "NOT_RUN"),
            "controls": (controls or {}).get("summaries"),
        }
        entry["overall_verdict"] = (
            "GO"
            if entry["narrow_verdict"] == "GO" and entry["controls_verdict"] == "GO"
            else "NO-GO"
        )
        comparison["models"][model] = entry
        for evidence in (narrow, controls):
            if not evidence:
                continue
            for scan in iter_scans(evidence):
                if scan.get("execution_policy_version") is not None:
                    policy_versions[str(scan["execution_policy_version"])] += 1
                for record in scan.get("candidate_records", []):
                    for rej in record.get("rejections", []):
                        rejections[rej["code"]] += 1
                    for q in record.get("queue", []):
                        if q["admitted"]:
                            admitted += 1
                        else:
                            not_admitted += 1
                executed += len(scan.get("executed_candidate_ids", []))

    extension = load(f"phase-0.8-extension-{slug(WINNER)}.json")
    comparison["winning_model"] = WINNER
    comparison["extension_verdict"] = (extension or {}).get("verdict", "NOT_RUN")
    comparison["extension_summary"] = (extension or {}).get("summary")
    comparison["overall_verdict"] = (
        "GO"
        if all(m["overall_verdict"] == "GO" for m in comparison["models"].values())
        and comparison["extension_verdict"] == "GO"
        else "NO-GO"
    )

    write("phase-0.8-model-comparison.json", comparison)
    write(
        "phase-0.8-candidate-rejection-distribution.json",
        {
            "note": "Deterministic rejection codes across narrow+controls trials for both models.",
            "rejections": dict(sorted(rejections.items())),
        },
    )
    write(
        "phase-0.8-execution-policy-audit.json",
        {
            "execution_policy_version": 1,
            "policy_version_occurrences": dict(sorted(policy_versions.items())),
            "queue_admitted_entries": admitted,
            "queue_not_admitted_entries": not_admitted,
            "executed_candidates_total": executed,
            "model_based_selection_calls": 0,
        },
    )
    print(json.dumps(comparison, indent=2))


def write(name: str, value: dict[str, Any]) -> None:
    (ARTIFACTS / name).write_text(json.dumps(value, indent=2) + "\n")
    print(f"wrote artifacts/{name}")


if __name__ == "__main__":
    main()
