#!/usr/bin/env bash
# =============================================================================================
# Combined Phase 1.7 live acceptance runner.
#
#   Gate 0  Provider identity probe            LIVE   (one provider call, zero target requests)
#   Gate A  Phase 1.7-A BOLA matrix            LIVE   (single/multi x vulnerable/patched)
#   Gate B  Phase 1.7-B recon/injection/chain  OFFLINE cross-check (see note below)
#
# HONEST SCOPE NOTE (do not overstate):
#   * Recon here is HTTP_API_SURFACE_RECON (documented HTTP/API surface only) — NOT network,
#     Nmap, Nuclei or ZAP recon.
#   * The 1.7-B "chain" is a DELEGATION_WORKFLOW_CHAIN (recon -> injection -> independent verify
#     delegation). It is NOT a multi-primitive attack chain and completes no Phase 1.6 range chain.
#   * Gate B has NO live-provider path yet: the llm-gateway serves only the 1.7-A task types, so
#     the 1.7-B matrix is proven in-process (offline structured fixture). It is explicitly NOT a
#     live pass and never counts toward a live GO.
#
# SAFETY:
#   * The provider API key is read from .env.gateway ONLY for absence assertions. It is never
#     printed, echoed, logged, hashed or inspected. (Requirement 12.)
#   * Cleanup (a trap) removes ONLY the containers/networks created under this run's unique Compose
#     project name; unrelated containers, networks, volumes and evidence are preserved.
#   * Only the minimal gateway, egress-proxy, control-plane and bank services are started. ZAP
#     Active, Beast Mode, Nuclei and unrelated scanners are excluded (they are not even in the
#     merged Compose file set below).
# =============================================================================================
set -uo pipefail

# --- 1. Locate the repository root safely ----------------------------------------------------
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || { echo "FATAL: cannot resolve script dir" >&2; exit 2; }
cd "$ROOT" || { echo "FATAL: cannot cd to repo root ($ROOT)" >&2; exit 2; }

# --- 2. Confirm Docker is reachable ----------------------------------------------------------
command -v docker >/dev/null 2>&1 || { echo "FATAL: docker CLI not found" >&2; exit 2; }
docker info >/dev/null 2>&1 || { echo "FATAL: docker daemon is not reachable" >&2; exit 2; }
docker compose version >/dev/null 2>&1 || { echo "FATAL: 'docker compose' plugin not available" >&2; exit 2; }

# The minimal, self-contained combined stack. Every network is Compose-managed by THIS project;
# there is no dependency on a pre-existing aegis-range project or fixed external network. It
# contains NO scanner/beast/zap/nuclei services.
STACK=(-f docker-compose.yml -f docker-compose.deepseek.yml -f docker-compose.phase-1-7-combined.yml)

# --- 3. Validate the exact merged Compose configuration --------------------------------------
if ! docker compose "${STACK[@]}" config --quiet; then
  echo "FATAL: merged Compose configuration is invalid" >&2
  exit 3
fi

# --- 8. Prove there are NO unresolved external networks before any `up` ----------------------
# A stale external reference (e.g. aegis-range_bank-backend) renders as `external: true` under the
# resolved `networks:` block. Fail closed here rather than mid-`up`.
CONFIG_OUT="$(docker compose "${STACK[@]}" config 2>/dev/null)"
if printf '%s\n' "$CONFIG_OUT" \
    | awk '/^networks:/{innet=1; next} /^[A-Za-z]/{innet=0} innet' \
    | grep -qE 'external:[[:space:]]*true'; then
  echo "FATAL: merged config still declares an external network; the combined run must be self-contained." >&2
  printf '%s\n' "$CONFIG_OUT" | awk '/^networks:/{innet=1} /^[A-Za-z]/{if(innet && !/^networks:/)innet=0} innet' >&2
  exit 3
fi
echo "  merged config validated: no external networks (bank-runtime is project-managed, internal)"

# The live gates require the operator-held provider credential in .env.gateway. Read the value ONLY
# to later assert its ABSENCE outside the gateway. It is never emitted.
if [ ! -f "$ROOT/.env.gateway" ]; then
  echo "FATAL: .env.gateway (AI_AUTH_TOKEN=<deepseek key>) is required for the live gates." >&2
  exit 2
fi
KEY_VALUE="$(grep -E '^AI_AUTH_TOKEN=' "$ROOT/.env.gateway" | head -1 | cut -d= -f2-)"
if [ -z "$KEY_VALUE" ]; then
  echo "FATAL: AI_AUTH_TOKEN is empty in .env.gateway." >&2
  exit 2
fi

# Force the operator-authorized model into Compose ${AI_MODEL} interpolation (a shell export beats
# any stale value in the project .env). Exact binding; no aliasing, no fallback.
export AI_MODEL="${DEEPSEEK_MODEL:-deepseek-v4-pro}"
export AI_ALLOWED_MODELS="${DEEPSEEK_ALLOWED_MODELS:-deepseek-v4-pro}"
EXPECTED_MODEL="$AI_MODEL"

# --- 4. Unique Compose project name (isolation + idempotency) --------------------------------
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
PROJECT="aegis-p17c-$(date +%s)-$$"
EVID_REL="artifacts/phase-1.7-combined-live-$STAMP"
EVID="$ROOT/$EVID_REL"
mkdir -p "$EVID"

PASS=0
FAIL=0
GATE0_VERDICT="NOT_RUN"
GATEA_VERDICT="NOT_RUN"
GATEB_VERDICT="NOT_RUN"
pass() { echo "  PASS  $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }

# --- 8/9/10/11. Cleanup trap: remove ONLY this project's resources ---------------------------
cleanup() {
  echo "== Teardown (Compose project '$PROJECT' only) =="
  # -v removes only volumes created for THIS project; --remove-orphans is scoped to this project.
  docker compose "${STACK[@]}" -p "$PROJECT" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

# --- 5. Build + start ONLY the minimal infra services (NOT the runner, NOT any scanner) -------
echo "== Ensure range image present (aegis-bank-live uses the prebuilt aegis-range image) =="
if ! docker image inspect aegis-range:1.6.0-dev >/dev/null 2>&1; then
  echo "   building aegis-range:1.6.0-dev from docker-compose.range.yml ..."
  if ! docker compose -f docker-compose.range.yml build >/tmp/p17c-rangebuild.log 2>&1; then
    echo "FATAL: range image build failed"; tail -20 /tmp/p17c-rangebuild.log; exit 3
  fi
fi
echo "== Build control-plane + gateway + runner (only services with a build context) =="
if ! docker compose "${STACK[@]}" -p "$PROJECT" build control-plane llm-gateway phase-1-7a-runner >/tmp/p17c-build.log 2>&1; then
  echo "FATAL: build failed"; tail -20 /tmp/p17c-build.log; exit 3
fi
echo "== Start minimal services (control-plane, llm-gateway, egress-proxy, aegis-bank-live) =="
if ! docker compose "${STACK[@]}" -p "$PROJECT" up -d control-plane llm-gateway egress-proxy aegis-bank-live >/tmp/p17c-up.log 2>&1; then
  echo "FATAL: bring-up failed"; tail -30 /tmp/p17c-up.log; exit 3
fi

CP="$(docker compose "${STACK[@]}" -p "$PROJECT" ps -q control-plane)"
GW="$(docker compose "${STACK[@]}" -p "$PROJECT" ps -q llm-gateway)"
LAB="$(docker compose "${STACK[@]}" -p "$PROJECT" ps -q lab-api 2>/dev/null || true)"
PX="$(docker compose "${STACK[@]}" -p "$PROJECT" ps -q egress-proxy)"
BK="$(docker compose "${STACK[@]}" -p "$PROJECT" ps -q aegis-bank-live)"

# --- 6. Bounded health checks ----------------------------------------------------------------
echo "== Bounded health wait (gateway + control-plane + bank) =="
ready=0
for _ in $(seq 1 40); do
  if docker exec "$GW" python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')" >/dev/null 2>&1 \
     && docker exec "$CP" python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" >/dev/null 2>&1 \
     && docker exec "$BK" python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8101/health')" >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 1
done
if [ "$ready" = "1" ]; then
  pass "minimal stack healthy within bounded wait"
else
  fail "stack did not become healthy in time"
  docker compose "${STACK[@]}" -p "$PROJECT" logs --tail 40 || true
  exit 3
fi

# --- 12. Credential isolation (value never printed) ------------------------------------------
echo "== Credential isolation (key value never printed) =="
key_absent_in() {
  local cid="$1" label="$2"
  [ -z "$cid" ] && { pass "$label not present in stack (nothing to scan)"; return 0; }
  if docker inspect "$cid" 2>/dev/null | grep -qF "$KEY_VALUE"; then
    fail "credential FOUND in $label"; return 1
  fi
  pass "credential absent in $label"; return 0
}
key_absent_in "$CP" "control-plane"
key_absent_in "$LAB" "lab-api"
key_absent_in "$PX" "egress-proxy"
key_absent_in "$BK" "aegis-bank-live"
if docker inspect "$GW" 2>/dev/null | grep -qF "$KEY_VALUE"; then
  pass "credential present in llm-gateway (only)"
else
  fail "credential NOT present in llm-gateway (expected here)"
fi

# Common bind mount + Python path for one-off script runs in the control-plane image.
RUN_COMMON=(run --rm --no-deps -T -v "$ROOT":/work -w /work -e PYTHONPATH=/work/src)

# --- 7 / Gate 0. Provider identity probe (LIVE, zero target requests) ------------------------
echo "== Gate 0 — provider identity probe (zero target requests) =="
LAB_BEFORE=0
[ -n "$LAB" ] && LAB_BEFORE="$(docker logs "$LAB" 2>&1 | grep -cE '"(GET|POST) /api/v1' || true)"
if docker compose "${STACK[@]}" -p "$PROJECT" "${RUN_COMMON[@]}" \
    -e AI_PROVIDER=internal_openai_compatible \
    -e AI_MODEL="$EXPECTED_MODEL" \
    -e AI_ALLOWED_MODELS="$EXPECTED_MODEL" \
    -e AI_AUTH_MODE=none \
    -e LLM_GATEWAY_URL=http://llm-gateway:8080 \
    -e MODEL_TIMEOUT_SECONDS="${MODEL_TIMEOUT_SECONDS:-90}" \
    -e EVIDENCE_DIR="/work/$EVID_REL" \
    --entrypoint python control-plane scripts/phase_1_7a_identity_probe.py >/tmp/p17c-gate0.out 2>&1; then
  GATE0_RC=0
else
  GATE0_RC=$?
fi
LAB_AFTER=0
[ -n "$LAB" ] && LAB_AFTER="$(docker logs "$LAB" 2>&1 | grep -cE '"(GET|POST) /api/v1' || true)"
if [ "$LAB_BEFORE" = "$LAB_AFTER" ]; then
  pass "no target /api/v1 requests during identity probe ($LAB_BEFORE == $LAB_AFTER)"
else
  fail "target requests observed during identity probe ($LAB_BEFORE -> $LAB_AFTER)"
fi
if [ "$GATE0_RC" = "0" ] && grep -q '"exact_canonical_identity": true' "$EVID/identity-probe.json" 2>/dev/null; then
  GATE0_VERDICT="GO"
  pass "Gate 0 exact provider identity = $EXPECTED_MODEL"
else
  GATE0_VERDICT="NO-GO"
  fail "Gate 0 identity not proven as $EXPECTED_MODEL"
  echo "  identity probe output:"; tail -5 /tmp/p17c-gate0.out 2>/dev/null
  echo "NO-GO: provider identity gate failed; the range is not touched. Stopping before Gate A."
  # Fall through to secret scan + verdict; the trap performs cleanup.
fi

# --- Gate A. Phase 1.7-A live BOLA matrix (only if Gate 0 is GO) -----------------------------
if [ "$GATE0_VERDICT" = "GO" ]; then
  echo "== Gate A — Phase 1.7-A live BOLA matrix (single/multi x vulnerable/patched) =="
  if docker compose "${STACK[@]}" -p "$PROJECT" run --rm phase-1-7a-runner >/tmp/p17c-gateA.out 2>&1; then
    GATEA_RC=0
  else
    GATEA_RC=$?
  fi
  # The 1.7-A harness writes its own artifacts/phase-1.7a-live-<ts>/ dir and prints ARTIFACT_DIR=.
  # Its own final_verdict is PENDING_EXTERNAL_GATES: THIS runner is that external-gate layer
  # (identity, secret scan, teardown, quality gates), so a preliminary_verdict of GO is the signal.
  GATEA_DIR="$(grep -oE 'ARTIFACT_DIR=[^ ]+' /tmp/p17c-gateA.out 2>/dev/null | head -1 | cut -d= -f2-)"
  [ -z "$GATEA_DIR" ] && GATEA_DIR="$(find "$ROOT"/artifacts -maxdepth 1 -type d -name 'phase-1.7a-live-*' | sort | tail -1)"
  if [ "$GATEA_RC" = "0" ] && grep -q '"preliminary_verdict": *"GO"' "$GATEA_DIR/acceptance.json" 2>/dev/null; then
    GATEA_VERDICT="GO"; pass "Gate A live BOLA preliminary_verdict GO ($GATEA_DIR)"
  else
    GATEA_VERDICT="NO-GO"; fail "Gate A live BOLA did not reach GO"
    echo "  Gate A output:"; tail -8 /tmp/p17c-gateA.out 2>/dev/null
  fi
  [ -n "$GATEA_DIR" ] && echo "$GATEA_DIR" > "$EVID/gate-a-evidence-dir.txt"
else
  echo "== Gate A skipped (Gate 0 was NO-GO) =="
fi

# --- Gate B. Phase 1.7-B OFFLINE cross-check (in-process; NOT a live pass) --------------------
echo "== Gate B — Phase 1.7-B recon/injection/chain OFFLINE cross-check (NOT live) =="
if docker compose "${STACK[@]}" -p "$PROJECT" "${RUN_COMMON[@]}" \
    --entrypoint python control-plane scripts/phase_1_7b_acceptance.py >/tmp/p17c-gateB.out 2>&1; then
  GATEB_RC=0
else
  GATEB_RC=$?
fi
GATEB_DIR="$(ls -dt "$ROOT"/artifacts/phase-1.7b-offline-* 2>/dev/null | head -1 || true)"
if [ "$GATEB_RC" = "0" ] && grep -q '"offline_acceptance_passed": true' "$GATEB_DIR/acceptance.json" 2>/dev/null; then
  GATEB_VERDICT="OFFLINE-PASS"; pass "Gate B offline cross-check PASS ($GATEB_DIR)"
else
  GATEB_VERDICT="OFFLINE-FAIL"; fail "Gate B offline cross-check did not pass"
  echo "  Gate B output:"; tail -8 /tmp/p17c-gateB.out 2>/dev/null
fi
[ -n "$GATEB_DIR" ] && echo "$GATEB_DIR" > "$EVID/gate-b-evidence-dir.txt"

# --- Secret scan (key value must appear NOWHERE it is scanned) -------------------------------
echo "== Secret scan (key value never printed) =="
scan_absent() {
  local label="$1"; shift
  if "$@" 2>/dev/null | grep -qF "$KEY_VALUE"; then
    fail "credential FOUND in $label"
  else
    pass "credential absent in $label"
  fi
}
scan_absent "combined evidence dir" grep -rF "" "$EVID"
scan_absent "control-plane logs" docker logs "$CP"
scan_absent "gateway logs" docker logs "$GW"
[ -n "$LAB" ] && scan_absent "lab-api logs" docker logs "$LAB"
scan_absent "egress-proxy logs" docker logs "$PX"
scan_absent "bank logs" docker logs "$BK"

# --- Explicit teardown, then post-cleanup host quality gates (task "Final gates") ------------
echo "== Teardown before host quality gates =="
cleanup
trap - EXIT INT TERM

echo "== Host quality gates (after cleanup; best effort) =="
if [ -x "$ROOT/.venv/bin/python" ]; then
  run_gate() {
    local label="$1"; shift
    if "$@" >/tmp/p17c-qg.log 2>&1; then pass "$label"; else fail "$label"; tail -5 /tmp/p17c-qg.log; fi
  }
  run_gate "1.7-A tests" "$ROOT/.venv/bin/python" -m pytest tests/test_phase_1_7.py tests/test_phase_1_7a_provider_binding.py -q
  run_gate "1.7-B tests" "$ROOT/.venv/bin/python" -m pytest tests/test_phase_1_7b.py -q
  run_gate "ruff" "$ROOT/.venv/bin/ruff" check .
  run_gate "mypy --strict" "$ROOT/.venv/bin/mypy" --strict
  run_gate "full offline pytest" "$ROOT/.venv/bin/python" -m pytest -q
else
  echo "  SKIP  host quality gates (.venv absent; run ruff / mypy --strict / pytest manually)"
fi
if git -C "$ROOT" diff --check >/dev/null 2>&1; then
  pass "git diff --check clean"
else
  fail "git diff --check reported whitespace errors"
fi

# --- Combined evidence manifest + checksums --------------------------------------------------
echo "== Combined evidence manifest =="
cat > "$EVID/combined-summary.json" <<JSON
{
  "phase": "1.7-combined-live",
  "created_at_utc": "$STAMP",
  "compose_project": "$PROJECT",
  "compose_files": ["docker-compose.yml", "docker-compose.deepseek.yml", "docker-compose.phase-1-7-combined.yml"],
  "authorized_model": "$EXPECTED_MODEL",
  "gate0_provider_identity": "$GATE0_VERDICT",
  "gateA_phase_1_7a_live_bola": "$GATEA_VERDICT",
  "gateB_phase_1_7b_offline_crosscheck": "$GATEB_VERDICT",
  "gateB_is_live": false,
  "recon_class": "HTTP_API_SURFACE_RECON",
  "chain_class": "DELEGATION_WORKFLOW_CHAIN"
}
JSON
( cd "$EVID" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 shasum -a 256 > SHA256SUMS ) || true
if ( cd "$EVID" && shasum -a 256 -c SHA256SUMS >/dev/null 2>&1 ); then
  pass "combined evidence checksums verify"
else
  fail "combined evidence checksum mismatch"
fi

# --- Separate verdicts -----------------------------------------------------------------------
echo
echo "================ COMBINED PHASE 1.7 VERDICTS ================"
echo "  1. Phase 1.7-A live BOLA smoke          : $GATEA_VERDICT (identity gate: $GATE0_VERDICT)"
echo "  2. Phase 1.7-B HTTP/API recon+injection : $GATEB_VERDICT (OFFLINE cross-check, NOT live)"
if [ "$GATE0_VERDICT" = "GO" ] && [ "$GATEA_VERDICT" = "GO" ] && [ "$FAIL" -eq 0 ]; then
  echo "  3. Overall combined                     : GO for Phase 1.7-A live BOLA smoke only"
  echo "     (Phase 1.7-B remains an offline cross-check; no live 1.7-B GO is claimed.)"
else
  echo "  3. Overall combined                     : NO-GO (see failing checks above)"
fi
echo "  Evidence: $EVID_REL"
echo "  Checks: PASS=$PASS FAIL=$FAIL"
echo "============================================================"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
