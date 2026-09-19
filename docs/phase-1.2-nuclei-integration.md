# Phase 1.2 — Controlled Nuclei integration

Status: **GO for the bounded synthetic lab only.** This is not production readiness and is not a
broad vulnerability scanner.

Phase 1.2 makes one Nuclei capability operational without moving finding authority into Nuclei.
An operator requests `nuclei_scm_metadata_exposure_v1`; the controller selects
`NUCLEI_LAB_SAFE_HTTP_V1`, resolves one fixed inventory target, constructs a typed job and contacts
the isolated runner. The model cannot select Nuclei, a target, template, flag, header, credential,
environment variable or network destination.

## Frozen operational profile

- Nuclei `v3.11.1`, upstream tag commit `a8c88feb4a1c8e961b7902534ce3af97e9d524a4`.
- Official Linux arm64 binary SHA-256
  `f27098e0be0cc370af52274611608ad61896d7f0a024e35b136327d39e725477`.
- Official Linux amd64 binary SHA-256
  `c49588140f357cbdddd5436dec11201953a4c5390faeec90777f9ee2cfd70251`.
- nuclei-templates `v10.4.8`, commit `e5f19e6144135e107962bb943231413796fd7fe7`.
- One admitted official signed template: `git-config`, SHA-256
  `bd8bdfa0b5ed5bf4d3712edb793adfd0987d9282e51c6f7d673bf14b9e4dd524`.
- Manifest version `1.2.0`; manifest SHA-256
  `8c69c056d9d11990bf11cbc688252d30426654a7ccb16996d3559c84fa472845`.
- Adapter `nuclei-adapter/1.2.0`; runner `nuclei-runner/1.2.0`; parser
  `nuclei-jsonl-parser/1.2.0`; verifier `aegis-scm-metadata-verifier/1.2.0`.

The profile sends one anonymous GET to an inventory-resolved synthetic route. It uses explicit
template paths, JSONL, matcher-status coverage records, no raw output, no stdin, no redirects, no
Interactsh, no update checks, signature enforcement, concurrency/bulk size one, rate two per second,
five-second request timeout, zero retries, a 65,536-byte response-read bound and a 30-second job
budget. The exact argv is built inside the runner without a shell.

## Finding authority

Nuclei output is parsed and stored as `TOOL_REPORTED`, then correlated to the authorized target,
template and capability. A separate Aegis verifier constructs fresh GET probes and evaluates the
synthetic property without trusting Nuclei prose, severity, matcher names, extractors or
classification. Only that verifier can produce `VERIFIED`/`CONFIRMED`. A complete no-match run can
be PASS only when Nuclei coverage is complete and the independent verifier confirms the patched
property. No output, partial output or an execution error is never PASS.

## Acceptance

The real pinned arm64 binary and signed template passed vulnerable 5/5 and patched-negative 5/5.
Out-of-scope controls passed 3/3, denied state-changing/non-HTTP capabilities passed 3/3 and strict
template/RPC admission controls passed 3/3. Exactly ten authorized runner executions occurred;
unauthorized executions and unauthorized target traffic were both zero. The offline suite adds
malformed, oversized, truncated, timeout, non-zero, duplicate, redirect/origin escape, unsigned,
modified, unknown and hostile-response coverage. See `artifacts/phase-1.2-live-acceptance.json` and
`artifacts/quality-gates-phase-1.2.txt`.

## Explicit exclusions

No community scan, template discovery/update, remote template URL, AI template generation,
ProjectDiscovery cloud/dashboard, DAST/fuzz, OAST, headless, code, JavaScript, file/network/DNS/TCP
template, authentication, production target, ZAP, Burp DAST or OWASP coverage claim is enabled.
