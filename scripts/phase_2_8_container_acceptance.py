"""Phase 2.8 — CONTAINERIZED synthetic capability acceptance runner.

Runs the real, bounded, digest-pinned container acceptance against an internal no-egress synthetic
range: the SQLMap vulnerable/patched pair through the production normalizer + independent verifier,
and one controller-rendered smoke per recon capability that has a suitable fixture and an acquirable
pinned image. Every other recon capability stays NOT_EVALUATED; LIVE_PROVIDER stays NOT_EVALUATED.

No AI provider is called, no gateway secret is loaded, and the offline authority model is unchanged:
a tool's own claim is audit-only; only the independent verifier promotes a finding.
"""

from __future__ import annotations

import argparse
import json

from aegis.container_acceptance.contracts import ContainerAcceptanceError
from aegis.container_acceptance.controller import Phase28Controller


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-build", action="store_true", help="fail if images are not prebuilt")
    parser.add_argument("--json", action="store_true", help="emit the full report as JSON")
    args = parser.parse_args()

    controller = Phase28Controller(build_missing=not args.no_build)
    try:
        report = controller.run()
    except ContainerAcceptanceError as exc:
        print(json.dumps({"phase": "2.8", "error": str(exc), "passed": False}, indent=2))
        return 2

    sqlmap = report["sqlmap"]
    functional = sqlmap["sqlmap_functional_detection_proven"]
    passed = bool(functional and report["cleanup_clean"])
    report["passed"] = passed
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(json.dumps(
            {
                "phase": report["phase"],
                "sqlmap_status": sqlmap["status"],
                "synthetic_sqli_scenario_confirmed": sqlmap["synthetic_sqli_scenario_confirmed"],
                "sqlmap_functional_detection_proven": functional,
                "sqlmap_checks": sqlmap["checks"],
                "cleanup_clean": report["cleanup_clean"],
                "tools": {t["capability_id"]: t["status"] for t in report["tools"]},
                "not_evaluated": report["not_evaluated"],
                "live_provider_status": report["live_provider_status"],
                "passed": passed,
            },
            indent=2,
            sort_keys=True,
        ))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
