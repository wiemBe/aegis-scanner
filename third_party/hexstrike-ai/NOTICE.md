# HexStrike-AI — provenance

- Upstream: https://github.com/0x4m4/hexstrike-ai
- Pinned: branch `master`, commit `d689933ff579d839c676c82b231f8e98326c5f04`
- License: MIT (see [`LICENSE`](LICENSE))
- Verified: 2026-09-28

## What Aegis uses

The **capability surface** only — a curated, gateway-compatible subset of the web-recon CLIs
HexStrike orchestrates — installed into the Phase 1.4 disposable sandbox and driven by the lab's own
controller + `qwen3:8b`. No upstream source is vendored or executed.

## What Aegis deliberately does not use

- `hexstrike_server.py` / `hexstrike_mcp.py` (the MCP server and protocol handler)
- HexStrike's autonomous decision engine and self-directed tool selection
- Any HexStrike component that would require LLM egress/credentials from inside the sandbox

Rationale: [`../README.md`](../README.md) and `docs/phase-1.4-b-beast-toolbox.md`.
