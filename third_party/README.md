# Third-party provenance

Upstream projects the Aegis lab draws on. This directory holds **provenance and license text only**
— it does **not** vendor upstream source into the build. Each tool is installed from a pinned,
checksum-verified upstream release (see `deploy/beast-sandbox/tools.lock.json` and
`deploy/beast-sandbox/Dockerfile`).

| Project | Pinned at | License | How it is used | What is deliberately **not** used |
| --- | --- | --- | --- | --- |
| [HexStrike-AI](https://github.com/0x4m4/hexstrike-ai) | `master` @ `d689933ff579d839c676c82b231f8e98326c5f04` | MIT | We adopt its **tool surface** — a curated subset of the web-recon CLIs it orchestrates — inside the Phase 1.4 disposable sandbox. | Its autonomous MCP engine, its `hexstrike_server.py` / `hexstrike_mcp.py` runtime, and its self-directed tool selection. See rationale below. |
| [AKCA](https://github.com/akha-security/akca) | `v0.2.4` @ `8ac554e6faf2b8b1f8d49e63037b1e2c57b23dc0` | Apache-2.0 | Installed as a first-class CLI (`akca`) the sandbox model may invoke against the synthetic target. | — |

## Why HexStrike's engine is not wired in

HexStrike-AI is an MCP server whose purpose is to let an AI agent *autonomously* drive 150+ security
tools against a target. That is the direct inverse of this lab's invariant (the model proposes; a
deterministic controller authorizes; an independent verifier confirms) and it is structurally
incompatible with the BEAST sandbox in two concrete ways:

1. **No model route exists inside the sandbox.** The decision-maker is the lab's own controller +
   `qwen3:8b`, running *outside* the sandbox over an isolated route. HexStrike's engine would need
   its own LLM egress and credentials from inside the adversary network — exactly what the
   architecture forbids.
2. **The GET/HEAD/OPTIONS gateway neuters most of the toolset.** The sandbox drops all Linux
   capabilities and the only route out is the HTTP gateway forwarding GET/HEAD/OPTIONS to one
   synthetic origin under byte/rate budgets. Raw-socket, brute-force, exploitation and callback
   tools cannot function regardless.

So the integration adopts HexStrike's **capability surface** — the kind of web-recon tooling it
curates — driven by the lab's controlled decider, not HexStrike's autonomous brain. The curated,
gateway-compatible subset actually installed is `katana` and `httpx` (ProjectDiscovery), alongside
the `nuclei`, `ffuf` and `sqlmap` already present. See `docs/phase-1.4-b-beast-toolbox.md`.

Upstream license texts: [`hexstrike-ai/LICENSE`](hexstrike-ai/LICENSE),
[`akca/LICENSE`](akca/LICENSE).
