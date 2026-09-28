# Phase 1.4-B — BEAST sandbox toolbox (AKCA + curated HexStrike web-recon)

Phase 1.4-B extends the [Phase 1.4 Disposable AI Adversary Sandbox](phase-1.4-beast-mode.md) with
additional web-recon tooling. It changes **what is installed in the disposable sandbox image** and
adds an **advisory tool note** to the model brief. It changes **no boundary**: the target gateway,
lease, verifier authority, network isolation, cleanup and audit are exactly as in Phase 1.4.

Requested integration: [HexStrike-AI](https://github.com/0x4m4/hexstrike-ai) and
[AKCA](https://github.com/akha-security/akca). Provenance and licensing live in
[`third_party/`](../third_party/README.md).

## What was integrated, and what was not

- **AKCA** (`v0.2.4`, Apache-2.0) — a single Go CLI DAST crawler/scanner — is installed as a
  first-class sandbox tool (`akca`). It speaks HTTP GET, which is exactly what the sandbox gateway
  forwards, so it does useful work against the synthetic target.
- **HexStrike-AI** (`master@d689933`, MIT) — an MCP server that lets an AI agent *autonomously*
  drive 150+ tools — is integrated as a **capability surface only**, not as a runtime. Its
  autonomous MCP engine is **deliberately not wired in**:
  - the sandbox has **no model route** by design; the decider is the lab's controller + `qwen3:8b`
    outside the sandbox, so HexStrike's engine (which needs its own LLM egress/credentials from
    inside the adversary network) cannot run without breaking the isolation invariant;
  - the **GET/HEAD/OPTIONS gateway** with byte/rate budgets and dropped capabilities makes most of
    HexStrike's 150 tools (raw-socket scanners, brute-forcers, exploit frameworks) inert regardless.

  The curated, gateway-compatible subset actually added from HexStrike's web-recon category is
  `katana` (crawler) and `httpx` (prober), both ProjectDiscovery Go binaries, alongside the
  `nuclei`, `ffuf` and `sqlmap` already in the image.

If the goal were instead to run HexStrike's autonomous engine, that is a separate, much larger
effort (re-homing its decisions behind the `llm-gateway` and re-validating every tool invocation
under the controller) and is explicitly out of scope here.

## Boundary (unchanged from Phase 1.4)

Every added tool reaches the target only through `beast-target-gateway`, which independently enforces
the exact path prefix, `GET`/`HEAD`/`OPTIONS` methods, request total, rate, concurrency and byte
budgets. The command process has only the internal `beast-adversary` network, no host mount, no
Docker socket, no public route, no model route and no credential environment. The deterministic
`BeastVerifier` alone returns `CONFIRMED`/`PASS`/`VERIFIED`. None of this changed; only the set of
installed binaries did.

## Advisory tool note (not an allow-list)

The controller now includes a `available_tools` note in `BeastDecisionRequest`
(`aegis.beast.toolbox.SANDBOX_TOOLBOX`), rendered into the model brief as *advisory environment
context*. The Phase 1.4 contract already grants the model "any installed tool or shell syntax" with
no command allow-list; this note only tells the model which tools are present and restates the
gateway constraint. Raw-socket/exploit tools (`nmap` et al.) are **not** listed, because the gateway
makes them inert and advertising them would misdescribe the boundary.

## Provenance and supply chain

Every externally fetched binary is pinned by version + SHA-256 in
[`deploy/beast-sandbox/tools.lock.json`](../deploy/beast-sandbox/tools.lock.json) and installed by
the checksum-verified stages of [`deploy/beast-sandbox/Dockerfile`](../deploy/beast-sandbox/Dockerfile)
(build-time network only; runtime networks are internal). Upstream release checksums verified
2026-09-28:

| Tool | Version | License | Source |
| --- | --- | --- | --- |
| akca | 0.2.4 | Apache-2.0 | github:akha-security/akca |
| katana | 1.7.0 | MIT | github:projectdiscovery/katana |
| httpx | 1.12.0 | MIT | github:projectdiscovery/httpx |
| nuclei | 3.11.1 | MIT | github:projectdiscovery/nuclei (pre-existing) |

`tests/test_beast_toolbox.py` fails closed if the manifest, the lock file and the Dockerfile drift
apart, if an advertised tool is not actually installed, if a raw-socket/exploit tool is advertised,
or if the controller stops transmitting the toolbox.

## Acceptance

- **Offline (done):** `tests/test_beast_toolbox.py` (9 controls) + the unchanged
  `tests/test_phase_1_4.py` suite pass; `ruff` and `mypy` clean.
- **Live (operator-run, NOT_EVALUATED):** as with Phase 1.4, a real GO requires building the image
  (`docker compose -f docker-compose.yml -f docker-compose.beast.yml build beast-sandbox`) and
  running the Phase 1.4 live matrix with the real `qwen3:8b` via Ollama, confirming the new tools
  run inside the sandbox, stay within the gateway budget, and that findings remain verifier-owned.
  No paid/live call was made for this increment.

## Operator build note

The `akca`/`katana`/`httpx` binaries are fetched at image-build time from GitHub releases, so the
`beast-sandbox` build needs outbound network the first time (the base range image is otherwise
egress-free). The pinned checksums make the fetch reproducible; a hash mismatch fails the build.
