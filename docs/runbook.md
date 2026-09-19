# Operator Runbook — Aegis AI Security Lab (Phase 1.0)

Authorized synthetic lab only. No external or production targets. All commands run through Docker
Compose (the supported Python 3.12 runtime).

## 0. Phase 1.0 Operator Console

Start the same localhost-only stack used by the management demo, then open:

```text
http://127.0.0.1:8000/console/   Operator Console
http://127.0.0.1:8000/           engineering dashboard
```

The console hydrates persisted events before following `/api/console/events` through SSE. A `STALE`
or `GAP` badge means live state is not current; do not present it as live until automatic hydration
returns the badge to `LIVE`. System Health uses actual checks or explicit unknown/unavailable
labels—never reinterpret an unavailable topology/secret result as green.

Presentation mode is available in the console sidebar. Follow the
[management guide](management-demo-phase-1.0.md) and leave the honest limitations visible. Nuclei,
ZAP, and Burp DAST must remain `PLANNED NOT CONNECTED`.

For frontend development and verification (Node is not required in the runtime image):

```bash
cd console
npm ci
npm run typecheck
npm run lint
npm test
npm run build
```

The production build is emitted to `src/aegis/console/` and bundled into the Python package. See
[troubleshooting](operator-console-troubleshooting.md), the
[event reference](audit-event-envelope.md), and the
[screenshot policy](screenshot-privacy-retention.md).

## 0.1 Phase 1.1 security-tool integration kernel

The kernel (`src/aegis/engine/`) is provider-independent. Only `AEGIS_NATIVE` is enabled; Nuclei,
ZAP and Burp DAST are disabled, fail-closed skeletons and must stay `DISABLED` in the console.

- Do not install, connect, credential, or enable Nuclei/ZAP/Burp DAST. Enabling any of them requires
  the [Phase 1.2 prerequisites](phase-1.2-nuclei-prerequisites.md) — flipping the catalog flag alone
  is a scope/safety regression.
- Engine readiness is at `GET /api/console/engines`; the console Integrations view shows honest,
  independent `configured` / `reachable` / `enabled` / `authorized` states.
- The console Run Replay shows the finding lifecycle (tool-reported vs verifier-confirmed) and the
  execution-policy decision panel (jobs constructed vs jobs rejected). No engine observation becomes
  a verified finding without the deterministic verifier or explicit human review.

Backend + frontend gates for Phase 1.1 (network disabled where applicable):

```bash
docker build --build-arg INSTALL_DEV=true -t aegis-check .
docker run --rm --network none -v "$PWD:/workspace" -w /workspace \
  -e PYTHONPATH=/workspace/src -e MYPYPATH=/workspace/src aegis-check \
  sh -c 'ruff check src tests scripts && \
         mypy --explicit-package-bases -p aegis -p lab_api && pytest -q'

# Frontend (Node not required in the runtime image; console/node_modules already present)
docker run --rm --network none -v "$PWD:/workspace" -w /workspace/console node:22-alpine \
  sh -c 'npm run typecheck && npm run lint && npm test && npm run build'
```

The Vite build re-emits `src/aegis/console/`. See [Phase 1.1](phase-1.1-security-tool-kernel.md).

## Phase 1.2 — controlled Nuclei profile

Build and start the isolated profile:

```bash
docker compose -f docker-compose.yml -f docker-compose.nuclei.yml up -d --build
docker compose -f docker-compose.yml -f docker-compose.nuclei.yml ps
docker compose -f docker-compose.yml -f docker-compose.nuclei.yml logs nuclei-runner
```

The runner must report `ready=True failures=none signature_probe=SIGNED_VERIFIED`. It has no host
port. The control plane exposes the profile through the existing scan API only when
`NUCLEI_ENABLED=true` and a fresh attestation matches all pins.

Live acceptance is `scripts/phase_1_2_acceptance.py`; execute it inside the control-plane container
with the internal control-plane and runner URLs. Expected result: vulnerable 5/5, patched-negative
5/5, three out-of-scope, three denied-capability and three template/RPC controls, with zero
unauthorized executions/traffic. See [operations](nuclei-operations.md) for failure codes and
[isolation](nuclei-runner-isolation.md) for topology checks.

The backend gate now includes all four source packages:

```bash
docker build --build-arg INSTALL_DEV=true -t aegis-check .
docker run --rm --network none -v "$PWD:/workspace" -w /workspace \
  -e PYTHONPATH=/workspace/src -e MYPYPATH=/workspace/src aegis-check \
  sh -c 'ruff check src tests scripts && \
         mypy --explicit-package-bases -p aegis -p lab_api -p aegis_nuclei -p nuclei_runner && \
         pytest -q'
```

Never enable runtime updates, mount a template directory, add a credential/proxy variable or expose
the runner port. Any engine/template/signature mismatch is a stop condition, not an upgrade prompt.

## 1. Phase 0.9 one-command management demo

Prerequisites: Docker/Compose is running and the already-approved local `qwen3:8b` model is present
in Ollama on `127.0.0.1:11434`. The command performs its own fail-closed preflight, topology checks,
live discovery, linked patched retest, evidence packaging, and checksum generation:

```bash
scripts/run_management_demo.sh
```

Wait for `MANAGEMENT DEMO READY`, then open the printed `/demo?discovery=...&retest=...` URL. The
stack remains running for presentation. Cleanup affects only the `aegis-management-demo` project:

```bash
scripts/run_management_demo.sh --cleanup
```

Do not hand-edit or overwrite a failed run. Keep its artifacts as evidence, diagnose the failed
guard, and create a new run ID. See [Phase 0.9](phase-0.9.md). Phase 0.9 did not redesign or migrate
the engineering dashboard; the subsequently completed console is covered by the
[Phase 1.0 runbook section](#0-phase-10-operator-console) and
[Phase 1.0 design contract](phase-1.0-operator-console.md).

## 2. Choose a provider

| Goal | `AI_PROVIDER` | Notes |
| --- | --- | --- |
| Offline demo, no model | `demo` | default; no Ollama, no egress |
| Local/private model (dev) | `ollama` | `qwen3:4b` on this host, or `qwen3:8b` on a GPU host |
| Company private endpoint | `internal_openai_compatible` | disabled until real details supplied |
| Public OpenAI (deprecated) | `openai_responses` | disabled; not the deployment model |

## 3. Local Ollama (LOCAL_LLM)

Prerequisite (operator): install Ollama, then pull only the authorized model:

```bash
ollama --version          # confirm Ollama is installed
ollama pull qwen3:4b      # only this model is authorized without further approval
```

If Ollama is **not** installed, install it from the official source and re-run — do not proceed
without it. The macOS install step is: download and run the official installer from
<https://ollama.com/download> (or `brew install ollama` if you use Homebrew), then `ollama serve`.

Bring up the stack (native macOS Ollama reached via Docker `host-gateway`; no host rebinding):

```bash
docker compose -f docker-compose.yml -f docker-compose.ollama.yml \
               -f docker-compose.dashboard.yml up --build -d
```

Verify:

```bash
# control plane reports LOCAL_LLM
docker compose -f docker-compose.yml -f docker-compose.ollama.yml exec -T control-plane \
  python -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8000/health').read())"
# gateway reports ollama + the model
docker compose -f docker-compose.yml -f docker-compose.ollama.yml exec -T control-plane \
  python -c "import urllib.request;print(urllib.request.urlopen('http://llm-gateway:8080/health').read())"
```

Dashboard: <http://127.0.0.1:8000>.

### Switch models (configuration only)

```bash
AI_MODEL=qwen3:8b docker compose -f docker-compose.yml -f docker-compose.ollama.yml up -d
# remote Ollama host (keep it private; do not bind Ollama to 0.0.0.0 without operator approval):
AI_BASE_URL=http://<gpu-host>:11434 AI_MODEL=qwen3:8b \
  docker compose -f docker-compose.yml -f docker-compose.ollama.yml up -d
```

## 4. Phase 0.8 staged acceptance (deterministic execution queue)

Build the dev image, then run each stage per model. Recreate the stack with the model under test
(`AI_MODEL=<model> docker compose -f docker-compose.yml -f docker-compose.ollama.yml up -d`) before
its run. Narrow, control and extended evidence are written to separate files and must never be
overwritten or combined.

```bash
docker build --build-arg INSTALL_DEV=true -t aegis-ai-security-lab-dev .

# Narrow 5/5 positive regression (run for BOTH models first — Part G).
docker run --rm --network ai-security-lab_security-lab -v "$PWD":/work -w /work \
  -e AEGIS_BASE_URL=http://control-plane:8000 -e EXPECTED_MODEL=qwen3:8b \
  -e PHASE_0_8_MODE=narrow aegis-ai-security-lab-dev python scripts/phase_0_8_acceptance.py

# Controls — ONLY after a model passes narrow 5/5 (Part H): patched(5)+auth(3)+scope(3)+state(3).
docker run --rm --network ai-security-lab_security-lab -v "$PWD":/work -w /work \
  -e AEGIS_BASE_URL=http://control-plane:8000 -e EXPECTED_MODEL=qwen3:8b \
  -e PHASE_0_8_MODE=controls aegis-ai-security-lab-dev python scripts/phase_0_8_acceptance.py

# Twenty-trial stability extension — ONLY for a model that passed narrow + controls.
docker run --rm --network ai-security-lab_security-lab -v "$PWD":/work -w /work \
  -e AEGIS_BASE_URL=http://control-plane:8000 -e EXPECTED_MODEL=qwen3:8b \
  -e PHASE_0_8_MODE=extension aegis-ai-security-lab-dev python scripts/phase_0_8_acceptance.py

# Aggregate model comparison + candidate-rejection distribution + execution-policy audit.
docker run --rm --network none -v "$PWD":/work -w /work \
  aegis-ai-security-lab-dev python scripts/compare_phase_0_8.py
```

If neither model passes the narrow 5/5 positive regression, stop after evidence and diagnosis — do
not run controls or the extension and do not loosen a threshold. A NO-GO is a legitimate outcome; do
not retry a generation, coerce a response, or inject a replacement candidate. Phase 0.8 result: both
approved models GO (see [Phase 0.8](phase-0.8.md)). The superseded Phase 0.7 harness
(`scripts/phase_0_7_acceptance.py`, model-based selection) and its NO-GO evidence are retained
immutably.

## 5. Network isolation checks

```bash
# control plane must NOT reach the model endpoint or the internet (deny-all egress)
docker compose -f docker-compose.yml -f docker-compose.ollama.yml exec -T control-plane python -c "
import urllib.request
for u in ('http://host.docker.internal:11434/api/version','http://1.1.1.1'):
    try: urllib.request.urlopen(u,timeout=4); print('REACHABLE (BAD)',u)
    except Exception as e: print('blocked (good)',u,type(e).__name__)"
# gateway MUST reach the pinned Ollama endpoint
docker compose -f docker-compose.yml -f docker-compose.ollama.yml exec -T llm-gateway python -c "
import urllib.request;print(urllib.request.urlopen('http://host.docker.internal:11434/api/version',timeout=6).read())"
```

## 6. Production (company private AI endpoint)

Supply the real institutional details (endpoint, model, auth) — the provider is disabled until then:

```dotenv
# .env
AI_PROVIDER=internal_openai_compatible
AI_BASE_URL=https://<company-endpoint>
AI_MODEL=<company-approved-model>
AI_ALLOWED_MODELS=<company-approved-model>
AI_AUTH_MODE=none|bearer
```

If `AI_AUTH_MODE=bearer`, put the credential only in an untracked `.env.gateway`:

```dotenv
# .env.gateway  (mounted only into llm-gateway; never in .env, chat or a commit)
AI_AUTH_TOKEN=<company-issued token>
```

The control plane refuses to start if `AI_AUTH_TOKEN` is present in its own environment.

## 7. Quality gates

```bash
docker build --build-arg INSTALL_DEV=true -t aegis-check .
docker run --rm --network none -v "$PWD:/workspace" -w /workspace \
  -e PYTHONPATH=/workspace/src -e MYPYPATH=/workspace/src aegis-check \
  sh -c 'ruff check src tests scripts && \
         mypy --explicit-package-bases -p aegis -p lab_api && pytest -q'
```

## 8. Tear down (keep evidence)

```bash
docker compose -f docker-compose.yml -f docker-compose.ollama.yml -f docker-compose.dashboard.yml down
```

`artifacts/` is git-ignored and holds generated evidence; it never contains model secrets or raw
sensitive values.

## 9. Phase 0.5 — Contract V2 benchmark (reproduce)

Only the planner contract changed from Phase 0.4; all other variables are frozen. Bring the stack up
per §2, then run five isolated trials per model into **separate** evidence files (never overwrite the
immutable V1 baselines):

```bash
# qwen3:4b (no repair)
AI_MODEL=qwen3:4b docker compose -f docker-compose.yml -f docker-compose.ollama.yml \
  run --rm -v "$PWD":/work -w /work \
  -e AEGIS_BASE_URL=http://control-plane:8000 -e EXPECTED_MODEL=qwen3:4b \
  -e LOCAL_EVIDENCE_PATH=artifacts/contract-v2-qwen3-4b-no-repair.json \
  -e PYTHONPATH=/work/src --entrypoint python control-plane scripts/local_llm_acceptance.py

# foundation-sec:8b-q4 (recreate the stack with the model first, then run)
AI_MODEL=foundation-sec:8b-q4 docker compose -f docker-compose.yml -f docker-compose.ollama.yml up -d
AI_MODEL=foundation-sec:8b-q4 docker compose -f docker-compose.yml -f docker-compose.ollama.yml \
  run --rm -v "$PWD":/work -w /work \
  -e AEGIS_BASE_URL=http://control-plane:8000 -e EXPECTED_MODEL=foundation-sec:8b-q4 \
  -e LOCAL_EVIDENCE_PATH=artifacts/contract-v2-foundation-sec-no-repair.json \
  -e PYTHONPATH=/work/src --entrypoint python control-plane scripts/local_llm_acceptance.py
```

Read-only post-processing (never re-runs a scan, never touches the V1 baselines):

```bash
export PYTHONPATH="$PWD/src:$PWD/scripts"
python scripts/build_failure_matrix.py                 # Part A: artifacts/contract-v1-failure-matrix.json
python scripts/compare_contracts.py \
  --v1 qwen3:4b=artifacts/local-llm-acceptance.json \
       foundation-sec:8b-q4=artifacts/foundation-sec-acceptance.json \
  --v2-no-repair qwen3:4b=artifacts/contract-v2-qwen3-4b-no-repair.json \
                 foundation-sec:8b-q4=artifacts/contract-v2-foundation-sec-no-repair.json
```

Result: NO-GO for both models under Contract V2 (no repair) — V2 removes the structural/evidence-
reference rejections (0/0) but both small models under-act at discovery (terminal `review`/`stop`).
Part D (bounded repair) precondition is not met (zero validation failures) and is not implemented.
See [Phase 0.5](phase-0.5.md).

## 10. Phase 0.6 — qwen3:8b under the unchanged Contract V2 harness (reproduce)

Only the **model** changed from Phase 0.5; every other variable is frozen. `qwen3:8b` is already in
`AI_ALLOWED_MODELS`, so no allowlist change is needed. Select the model **inline per run** and write
to a **separate** evidence file so no baseline is overwritten. Optionally set the dashboard status to
`LOCAL_LLM_QWEN8B_TESTING` while evaluating (configuration only, in `.env`).

```bash
# Bring the stack up on qwen3:8b (per §2, model selected inline)
AI_MODEL=qwen3:8b docker compose -f docker-compose.yml -f docker-compose.ollama.yml \
  -f docker-compose.dashboard.yml up --build -d

# Five isolated trials -> new evidence file
AI_MODEL=qwen3:8b docker compose -f docker-compose.yml -f docker-compose.ollama.yml \
  run --rm -v "$PWD":/work -w /work \
  -e AEGIS_BASE_URL=http://control-plane:8000 -e EXPECTED_MODEL=qwen3:8b \
  -e LOCAL_EVIDENCE_PATH=artifacts/qwen3-8b-acceptance.json \
  -e PYTHONPATH=/work/src --entrypoint python control-plane scripts/local_llm_acceptance.py
```

Read-only post-processing (three-model Contract V2 comparison + terminal-decision distribution; never
re-runs a scan, never touches any baseline):

```bash
PYTHONPATH="$PWD/src:$PWD/scripts" python scripts/compare_phase_0_6.py
# -> artifacts/phase-0.6-three-model-comparison.json
# -> artifacts/phase-0.6-terminal-decision-distribution.json
```

Topology + secret scan under the evaluated model, and offline quality gates:

```bash
AI_MODEL=qwen3:8b bash scripts/ollama_topology_tests.sh > artifacts/ollama-topology-qwen3-8b.txt
docker build --build-arg INSTALL_DEV=true -t aegis-check .
docker run --rm --network none -v "$PWD:/workspace" -w /workspace \
  -e PYTHONPATH=/workspace/src -e MYPYPATH=/workspace/src aegis-check \
  sh -c 'ruff check src tests scripts && \
         mypy --explicit-package-bases -p aegis -p lab_api && pytest -q'
```

Result: **NO-GO for `qwen3:8b`** — 5/5 valid terminal `review` at the generative discovery step
(identical to `qwen3:4b`), 0/5 hypothesis. Because more than one of five trials terminated instead of
hypothesizing, the Part E path applied: the benchmark stopped after evidence + diagnosis, the Part D
twenty-trial run was NOT started, and no schema repair / forced hypothesis / hard-coded sequence /
prompt edit / silent retry was performed. A proposal-only Phase 0.7 design is in
[Phase 0.6 §7](phase-0.6.md). Keep `.env` `AI_MODEL` at the committed `qwen3:4b` default after the run
so the model-agnostic offline suite stays deterministic (the Phase 0.5 `.env` was backed up to
`.env.phase-0.5.bak`).
