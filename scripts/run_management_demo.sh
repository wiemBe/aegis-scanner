#!/usr/bin/env bash
# Phase 0.9 — one-command reproducible management demo (synthetic lab only, docs/phase-0.9).
#
#   scripts/run_management_demo.sh            # run the demo; leave the stack up for presentation
#   scripts/run_management_demo.sh --cleanup  # remove ONLY the aegis-management-demo project
#
# It packages the already-validated Phase 0.8 capability into a repeatable, auditable demo:
#   1. validates preconditions (Docker/Compose, localhost Ollama, approved qwen3:8b + digest,
#      disk/memory, Phase 0.8 evidence integrity);
#   2. brings up ONLY the constrained local topology under a unique compose project;
#   3. confirms the network isolation invariants;
#   4. runs exactly one real qwen3:8b discovery + linked patched retest at temperature 0, seed 42,
#      context 8192, Contract V3, deterministic execution policy V1, existing budgets, no model-based
#      selection;
#   5. writes a unique, timestamped, checksummed evidence package;
#   6. leaves the stack running and prints the dashboard URL + evidence paths.
#
# It never contacts an external target, downloads a model, initializes Git, or touches unrelated
# Docker resources. Any failed invariant aborts before evidence is written.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PROJECT="aegis-management-demo"
COMPOSE=(-f docker-compose.yml -f docker-compose.ollama.yml -f docker-compose.dashboard.yml)
DC=(docker compose -p "$PROJECT" "${COMPOSE[@]}")

EXPECTED_MODEL="qwen3:8b"
EXPECTED_DIGEST_PREFIX="500a1f067a9f"
DASHBOARD_URL="http://127.0.0.1:8000"
OLLAMA_URL="http://127.0.0.1:11434"
PRIOR_MANIFEST="artifacts/phase-0.8-prior-evidence-manifest.sha256"

SNAPSHOT="$(mktemp)"
trap 'rm -f "$SNAPSHOT"' EXIT

log()  { echo "[demo] $*"; }
die()  { echo "[demo] ABORT: $*" >&2; exit 1; }

cleanup_project() {
  log "removing compose project '$PROJECT' only (no unrelated resources touched)"
  docker compose -p "$PROJECT" "${COMPOSE[@]}" down -v --remove-orphans
}

if [ "${1:-}" = "--cleanup" ] || [ "${1:-}" = "cleanup" ]; then
  cleanup_project
  log "cleanup complete."
  exit 0
fi

# --- Part B.2: preconditions --------------------------------------------------------------------
log "== preconditions =="

command -v docker >/dev/null 2>&1 || die "docker not found"
docker version --format '{{.Server.Version}}' >/dev/null 2>&1 || die "Docker daemon unavailable"
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 unavailable"
log "docker $(docker version --format '{{.Server.Version}}'), compose $(docker compose version --short 2>/dev/null)"

# Approved localhost Ollama endpoint (STOP condition if unavailable).
OLLAMA_VERSION="$(curl -s --max-time 5 "$OLLAMA_URL/api/version" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"
[ -n "$OLLAMA_VERSION" ] || die "approved localhost Ollama endpoint unavailable at $OLLAMA_URL"
log "ollama version $OLLAMA_VERSION"

# Approved model present at the exact recorded digest (STOP condition if absent).
DIGEST="$(curl -s --max-time 5 "$OLLAMA_URL/api/tags" \
  | tr ',' '\n' | grep -A2 "\"$EXPECTED_MODEL\"" | sed -n 's/.*"digest":"\([^"]*\)".*/\1/p' | head -1)"
if [ -z "$DIGEST" ]; then
  DIGEST="$(curl -s --max-time 5 "$OLLAMA_URL/api/tags" \
    | python3 -c "import sys,json;print(next((m.get('digest','') for m in json.load(sys.stdin).get('models',[]) if m.get('name')=='$EXPECTED_MODEL'),''))" 2>/dev/null)"
fi
[ -n "$DIGEST" ] || die "approved model $EXPECTED_MODEL not present in localhost Ollama"
case "$DIGEST" in
  "$EXPECTED_DIGEST_PREFIX"*) log "model $EXPECTED_MODEL digest ${DIGEST:0:16}… matches recorded" ;;
  *) die "model $EXPECTED_MODEL digest ${DIGEST:0:16}… != recorded $EXPECTED_DIGEST_PREFIX…" ;;
esac

# Disk + memory headroom (advisory floor; the constrained stack is small).
AVAIL_KB="$(df -k "$ROOT" | awk 'NR==2{print $4}')"
[ "${AVAIL_KB:-0}" -ge 1048576 ] || die "insufficient disk (<1 GiB free)"
log "disk free: $((AVAIL_KB/1024)) MiB"

# Localhost-only dashboard ingress must be free (or already ours).
if lsof -nP -iTCP:8000 -sTCP:LISTEN >/dev/null 2>&1; then
  log "note: something is listening on :8000 (idempotent re-up will reuse the demo dashboard)"
fi

# --- Preserve + verify existing evidence (do not trust the handoff) -----------------------------
log "== evidence integrity =="
# Snapshot every pre-existing artifact so we can prove nothing was mutated by this run.
( cd "$ROOT" && find artifacts -type f ! -name 'phase-0.9-demo-*' -print0 | sort -z \
    | xargs -0 shasum -a 256 ) > "$SNAPSHOT" 2>/dev/null
PRIOR_COUNT="$(wc -l < "$SNAPSHOT" | tr -d ' ')"
log "snapshotted $PRIOR_COUNT existing artifact checksums"
if [ -f "$PRIOR_MANIFEST" ]; then
  ( cd "$ROOT" && shasum -a 256 -c "$PRIOR_MANIFEST" >/dev/null 2>&1 ) \
    && log "Phase 0.8 prior-evidence manifest verified (47 files intact)" \
    || die "Phase 0.8 prior-evidence manifest verification FAILED"
fi

# --- Part B.3: bring up the constrained topology ------------------------------------------------
log "== bringing up constrained topology (project $PROJECT) =="
AI_PROVIDER=ollama \
AI_MODEL="$EXPECTED_MODEL" \
AI_ALLOWED_MODELS="qwen3:4b,qwen3:8b,foundation-sec:8b-q4" \
AI_CONTEXT_LENGTH=8192 \
AI_TEMPERATURE=0 \
AI_SEED=42 \
"${DC[@]}" up --build -d || die "compose up failed"

wait_health() { # service inner-url
  for _ in $(seq 1 60); do
    "${DC[@]}" exec -T "$1" python -c \
      "import urllib.request;urllib.request.urlopen('$2')" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}
wait_health control-plane "http://127.0.0.1:8000/health" || die "control-plane did not become healthy"
wait_health llm-gateway   "http://127.0.0.1:8080/health" || die "llm-gateway did not become healthy"
for _ in $(seq 1 60); do
  curl -s --max-time 3 "$DASHBOARD_URL/health" | grep -q LOCAL_LLM && break
  sleep 1
done
curl -s --max-time 3 "$DASHBOARD_URL/health" | grep -q LOCAL_LLM \
  || die "dashboard ingress not serving LOCAL_LLM control plane"

# --- Part B.4: confirm topology invariants ------------------------------------------------------
log "== topology invariants =="
TOPO_FAIL=0
topo_pass() { log "  PASS: $1"; }
topo_fail() { log "  FAIL: $1"; TOPO_FAIL=1; }

cp_exec() { "${DC[@]}" exec -T control-plane python -c "$1"; }
gw_exec() { "${DC[@]}" exec -T llm-gateway   python -c "$1"; }

# control plane cannot reach the internet
cp_exec "import urllib.request as u
try: u.urlopen('http://1.1.1.1',timeout=4); print('OPEN')
except Exception: print('BLOCKED')" | grep -q BLOCKED \
  && topo_pass "control-plane cannot reach the internet" \
  || topo_fail "control-plane reached the internet"

# control plane cannot reach the model endpoint (deny-all external egress)
cp_exec "import urllib.request as u
try: u.urlopen('http://host.docker.internal:11434/api/version',timeout=4); print('OPEN')
except Exception: print('BLOCKED')" | grep -q BLOCKED \
  && topo_pass "control-plane cannot reach the Ollama endpoint" \
  || topo_fail "control-plane reached the Ollama endpoint"

# gateway cannot reach the lab/target network
gw_exec "import urllib.request as u
try: u.urlopen('http://lab-api:8001/health',timeout=4); print('OPEN')
except Exception: print('BLOCKED')" | grep -q BLOCKED \
  && topo_pass "gateway isolated from the lab target network" \
  || topo_fail "gateway reached the lab target network"

# gateway CAN reach the pinned localhost Ollama path
gw_exec "import urllib.request as u;print(u.urlopen('http://host.docker.internal:11434/api/version',timeout=6).read().decode())" \
  | grep -q version \
  && topo_pass "gateway reaches approved localhost Ollama path" \
  || topo_fail "gateway cannot reach approved Ollama path"

# lab + control-plane services publish no host ports; only the dashboard publishes 127.0.0.1:8000.
# A published host port renders in .Ports as "IP:host->container/tcp" (the "->" arrow); an
# internal-only expose renders as "8001/tcp" with no arrow.
PORTS="$("${DC[@]}" ps --format '{{.Service}} {{.Ports}}' 2>/dev/null)"
if echo "$PORTS" | grep -E '^(control-plane|lab-api|llm-gateway) ' | grep -q '\->'; then
  topo_fail "a lab/control-plane service publishes a host port"
else
  topo_pass "lab/control-plane/gateway publish no host ports"
fi
# dashboard binds only to 127.0.0.1
DASH_PORTS="$(echo "$PORTS" | grep '^dashboard ')"
if echo "$DASH_PORTS" | grep -q '127.0.0.1:8000->'; then
  if echo "$DASH_PORTS" | grep -qE '0\.0\.0\.0|\[::\]|:::'; then
    topo_fail "dashboard is exposed beyond 127.0.0.1"
  else
    topo_pass "dashboard ingress binds only to 127.0.0.1:8000"
  fi
else
  topo_fail "dashboard ingress not bound to 127.0.0.1:8000"
fi

if [ "$TOPO_FAIL" -ne 0 ]; then
  die "topology invariants failed — refusing to run the demo"
fi
TOPO_RESULT="PASS"

# --- Part B.5/6: run one real qwen3:8b demonstration --------------------------------------------
log "== running live demonstration (real $EXPECTED_MODEL call) =="
RUN_ID="demo-$(date -u +%Y%m%dT%H%M%SZ)-$(head -c3 /dev/urandom | xxd -p)"
DEMO_OUT="$(mktemp)"
# errexit is intentionally off (set -uo pipefail only); the runner's exit code is checked explicitly.
DEMO_RUN_ID="$RUN_ID" \
DEMO_COMPOSE_PROJECT="$PROJECT" \
DEMO_DASHBOARD_URL="$DASHBOARD_URL" \
DEMO_TOPOLOGY_RESULT="$TOPO_RESULT" \
AEGIS_BASE_URL="$DASHBOARD_URL" \
python3 scripts/demo_runner.py | tee "$DEMO_OUT"
RUNNER_RC="${PIPESTATUS[0]}"
[ "$RUNNER_RC" -eq 0 ] || { rm -f "$DEMO_OUT"; die "demo runner failed (rc=$RUNNER_RC)"; }

DISCOVERY_ID="$(sed -n 's/^DEMO_DISCOVERY_ID=//p' "$DEMO_OUT")"
RETEST_ID="$(sed -n 's/^DEMO_RETEST_ID=//p' "$DEMO_OUT")"
rm -f "$DEMO_OUT"

# --- Verify no pre-existing evidence was mutated ------------------------------------------------
if ! ( cd "$ROOT" && shasum -a 256 -c "$SNAPSHOT" >/dev/null 2>&1 ); then
  die "a pre-existing artifact was modified during the run"
fi
log "confirmed: $PRIOR_COUNT pre-existing artifacts byte-identical"

# --- Part B.12: leave the stack up; print URLs + evidence ---------------------------------------
DEMO_VIEW="$DASHBOARD_URL/demo?discovery=$DISCOVERY_ID&retest=$RETEST_ID"
echo
log "================= MANAGEMENT DEMO READY ================="
log "  Engineering dashboard : $DASHBOARD_URL"
log "  Management demo view  : $DEMO_VIEW"
log "  Manifest              : artifacts/phase-0.9-demo-$RUN_ID.json"
log "  Summary               : artifacts/phase-0.9-demo-$RUN_ID.summary.md"
log "  Compose project       : $PROJECT (still running for presentation)"
log "  Clean up when done    : scripts/run_management_demo.sh --cleanup"
log "========================================================"
