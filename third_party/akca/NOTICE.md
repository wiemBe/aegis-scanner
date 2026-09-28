# AKCA — provenance

- Upstream: https://github.com/akha-security/akca
- Pinned: tag `v0.2.4`, commit `8ac554e6faf2b8b1f8d49e63037b1e2c57b23dc0`
- License: Apache-2.0 (see [`LICENSE`](LICENSE))
- Verified: 2026-09-28

## What Aegis uses

The released `akca` CLI binary (a single Go executable — a contextual DAST crawler/scanner) is
installed into the Phase 1.4 disposable sandbox and may be invoked by the sandbox model against the
synthetic target. Installed from the pinned upstream release, verified by SHA-256
(`deploy/beast-sandbox/tools.lock.json`):

- `akca-linux-amd64` — `265b1cb00a8ed7b8d5cfd4adcccd2e6929afb64f5f2bd2503310d6a53f230017`
- `akca-linux-arm64` — `401f4561bbaf7a7a88c3e5e1543cbab049a40ee1358e873dc4dd9f451626446a`

Like every tool in the sandbox, it reaches the target only through the GET/HEAD/OPTIONS gateway
under strict byte/rate/connection budgets, against the synthetic range only.
