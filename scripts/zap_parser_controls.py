#!/usr/bin/env python3
"""Phase 1.3 report-parser fail-closed controls, executed INSIDE the pinned zap-runner image.

    docker run --rm --network none --read-only \
      -v "$PWD/tests/fixtures:/fixtures:ro" -v "$PWD/scripts:/scripts:ro" \
      --entrypoint python3 aegis-zap-runner:1.3.0 \
      /scripts/zap_parser_controls.py /fixtures/zap-2.17.0-traditional-json-vulnerable.json

A real ZAP run cannot be made to emit a malformed or oversized report on demand, so these controls
feed the runner image's own pinned parser a GENUINE report captured from the pinned ZAP 2.17.0
(the exact profile plan against the synthetic lab) plus deterministic mutations of it. The genuine
report must parse; every mutation must fail closed with no records. Prints one JSON document.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from aegis_zap.inventory import ZAP_TARGETS
from aegis_zap.manifest import load_manifest
from aegis_zap.parser import PARSER_VERSION, parse_report
from aegis_zap.projection import project


def main() -> int:
    genuine = Path(sys.argv[1]).read_bytes()
    manifest = load_manifest()
    projection = project(ZAP_TARGETS["synthetic-zap-vulnerable"])
    report = json.loads(genuine)

    def mutated(change: object) -> bytes:
        copy = json.loads(genuine)
        change(copy)  # type: ignore[operator]
        return json.dumps(copy).encode()

    def first_instance(doc: dict[str, object]) -> dict[str, object]:
        return doc["site"][0]["alerts"][0]["instances"][0]  # type: ignore[index,no-any-return]

    cases: dict[str, bytes | None] = {
        "genuine": genuine,
        "missing": None,
        "empty": b"",
        "truncated": genuine[: len(genuine) // 2],
        "malformed_json": genuine.replace(b'"alerts"', b"alerts", 1),
        "duplicate_keys": genuine.replace(b'"@version"', b'"@version": "2.17.0", "@version"', 1),
        "oversized": genuine.rstrip()[:-1] + b', "insights": "' + b"x" * 200_000 + b'"}',
        "version_drift": mutated(lambda d: d.update({"@version": "2.18.0"})),
        "unadmitted_rule": mutated(
            lambda d: d["site"][0]["alerts"][0].update(pluginid="40012", alertRef="40012")
        ),
        "scope_escape_uri": mutated(
            lambda d: first_instance(d).update(uri="http://lab-api:8001/lab/zap/admin/purge")
        ),
        "foreign_site": mutated(
            lambda d: d["site"].append(
                {"@name": "https://prod.example", "@host": "prod.example", "@port": "443",
                 "@ssl": "true", "alerts": []}
            )
        ),
        "attack_present": mutated(lambda d: first_instance(d).update(attack="<script>")),
        "unexpected_field": mutated(lambda d: first_instance(d).update(requestHeader="Cookie: x")),
    }
    results = {}
    for name, data in cases.items():
        outcome = parse_report(
            data,
            engine_version=manifest.engine.version,
            projection=projection,
            rules=manifest.passive_rules,
            max_report_bytes=131_072,
            max_alerts=8,
        )
        results[name] = {
            "status": outcome.summary.status,
            "failure_code": outcome.summary.failure_code,
            "records": len(outcome.records),
            "stripped_fields": list(outcome.summary.stripped_fields),
        }
    genuine_ok = results["genuine"]["status"] == "PARSED" and results["genuine"]["records"] == 1
    closed = all(
        r["status"] != "PARSED" and r["records"] == 0 for n, r in results.items() if n != "genuine"
    )
    print(
        json.dumps(
            {
                "parser_version": PARSER_VERSION,
                "genuine_report_zap_version": report.get("@version"),
                "genuine_parses": genuine_ok,
                "all_mutations_fail_closed": closed,
                "results": results,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if genuine_ok and closed else 1


if __name__ == "__main__":
    raise SystemExit(main())
