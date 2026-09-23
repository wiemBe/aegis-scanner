#!/usr/bin/env bash
# DeepSeek initial acceptance orchestration (INTERNAL_LLM via the isolated llm-gateway).
#
# Execution order (matches the task's D..I):
#   D. Rebuild the gateway and control plane.
#   E. Verify the credential is present ONLY inside the gateway (never printed).
#   F. One provider-only smoke call (proves gateway->DeepSeek, zero target requests).
#   G. Only if the smoke succeeds, one full synthetic discovery + controller-constructed retest.
#   H. Save and checksum evidence.
#   (secret scan over DB, logs, audit, evidence, docker inspect, API responses)
#   I. Tear down the DeepSeek stack.
#
# The API key value is never printed, echoed, logged or committed. It is read from .env.gateway
# into a shell variable used only for absence assertions, never emitted.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PROJECT="aegis-deepseek"
STACK="-f docker-compose.yml -f docker-compose.deepseek.yml"
# Force the operator-authorized model into Compose's ${AI_MODEL} interpolation so it beats any value
# in the project .env (a shell export takes precedence over the .env file for interpolation).
export AI_MODEL="${DEEPSEEK_MODEL:-deepseek-v4-pro}"
export AI_ALLOWED_MODELS="${DEEPSEEK_ALLOWED_MODELS:-deepseek-v4-pro}"
EXPECTED_MODEL="$AI_MODEL"
PASS=0
FAIL=0
pass() { echo "  PASS  $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }

cleanup() {
  echo "== I. Teardown =="
  docker compose $STACK -p "$PROJECT" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [ ! -f "$ROOT/.env.gateway" ]; then
  echo "FATAL: .env.gateway (AI_AUTH_TOKEN=<deepseek key>) is required but absent." >&2
  exit 2
fi
# Read the key value for ABSENCE assertions only. Never printed.
KEY_VALUE="$(grep -E '^AI_AUTH_TOKEN=' "$ROOT/.env.gateway" | head -1 | cut -d= -f2-)"
if [ -z "$KEY_VALUE" ]; then
  echo "FATAL: AI_AUTH_TOKEN is empty in .env.gateway." >&2
  exit 2
fi

echo "== D. Build gateway + control plane =="
if ! docker compose $STACK -p "$PROJECT" build >/tmp/ds-build.log 2>&1; then
  echo "FATAL: build failed"; tail -20 /tmp/ds-build.log; exit 3
fi
echo "== Bring up stack (project $PROJECT) =="
if ! docker compose $STACK -p "$PROJECT" up -d >/tmp/ds-up.log 2>&1; then
  echo "FATAL: up failed"; tail -30 /tmp/ds-up.log; exit 3
fi

# Wait for control-plane + gateway health.
CP="$(docker compose $STACK -p "$PROJECT" ps -q control-plane)"
GW="$(docker compose $STACK -p "$PROJECT" ps -q llm-gateway)"
LAB="$(docker compose $STACK -p "$PROJECT" ps -q lab-api)"
PX="$(docker compose $STACK -p "$PROJECT" ps -q egress-proxy)"
ready=0
for _ in $(seq 1 40); do
  if docker exec "$CP" python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" >/dev/null 2>&1 \
     && docker exec "$GW" python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')" >/dev/null 2>&1; then
    ready=1; break
  fi
  sleep 1
done
[ "$ready" = "1" ] && pass "control-plane + gateway healthy (control-plane started WITHOUT the key)" \
  || { fail "stack did not become healthy"; docker compose $STACK -p "$PROJECT" logs --tail 40; exit 3; }

echo "== E. Credential isolation (value never printed) =="
key_absent_in() { # container label
  local cid="$1" label="$2"
  if docker inspect "$cid" 2>/dev/null | grep -qF "$KEY_VALUE"; then
    fail "credential FOUND in $label environment"; return 1
  fi
  pass "credential absent in $label"; return 0
}
key_absent_in "$CP" "control-plane"
key_absent_in "$LAB" "lab-api"
key_absent_in "$PX" "egress-proxy"
if docker inspect "$GW" 2>/dev/null | grep -qF "$KEY_VALUE"; then
  pass "credential present in llm-gateway (only)"
else
  fail "credential NOT present in llm-gateway (expected here)"
fi

echo "== F. Provider-only smoke (zero target requests) =="
# Snapshot lab-api access log lines before the smoke.
LAB_BEFORE="$(docker logs "$LAB" 2>&1 | grep -cE '"(GET|POST) /api/v1' || true)"
mkdir -p "$ROOT/artifacts"
if docker compose $STACK -p "$PROJECT" run --rm -T \
    -v "$ROOT":/work -w /work \
    -e GATEWAY_URL=http://llm-gateway:8080 \
    -e EXPECTED_MODEL="$EXPECTED_MODEL" \
    -e PYTHONPATH=/work/src \
    --entrypoint python control-plane scripts/deepseek_smoke.py \
    >"$ROOT/artifacts/deepseek-smoke.json" 2>/tmp/ds-smoke.err; then
  # keep only the final JSON line
  tail -1 "$ROOT/artifacts/deepseek-smoke.json" > "$ROOT/artifacts/deepseek-smoke.json.tmp" \
    && mv "$ROOT/artifacts/deepseek-smoke.json.tmp" "$ROOT/artifacts/deepseek-smoke.json"
  SMOKE_OK=1
else
  SMOKE_OK=0
fi
LAB_AFTER="$(docker logs "$LAB" 2>&1 | grep -cE '"(GET|POST) /api/v1' || true)"
if [ "$LAB_BEFORE" = "$LAB_AFTER" ]; then
  pass "no target /api/v1 requests during provider-only smoke ($LAB_BEFORE == $LAB_AFTER)"
else
  fail "target requests observed during smoke ($LAB_BEFORE -> $LAB_AFTER)"
fi
if [ "$SMOKE_OK" = "1" ] && grep -q '"smoke": "PASS"' "$ROOT/artifacts/deepseek-smoke.json"; then
  pass "smoke call PASS"
  echo "  smoke: $(cat "$ROOT/artifacts/deepseek-smoke.json")"
else
  fail "smoke call did not pass"
  echo "  smoke stderr:"; tail -5 /tmp/ds-smoke.err 2>/dev/null
  echo "  smoke out:"; cat "$ROOT/artifacts/deepseek-smoke.json" 2>/dev/null
  echo "NO-GO: smoke failed; discovery not attempted."
  # Still run the secret scan + evidence-of-failure before teardown.
fi

if grep -q '"smoke": "PASS"' "$ROOT/artifacts/deepseek-smoke.json" 2>/dev/null; then
  echo "== G. One full synthetic discovery + controller-constructed retest =="
  docker compose $STACK -p "$PROJECT" run --rm -T \
    -v "$ROOT":/work -w /work \
    -e AEGIS_BASE_URL=http://control-plane:8000 \
    -e GATEWAY_URL=http://llm-gateway:8080 \
    -e EXPECTED_MODEL="$EXPECTED_MODEL" \
    -e REQUESTED_MODEL="$EXPECTED_MODEL" \
    -e MODEL_TIMEOUT_SECONDS="${MODEL_TIMEOUT_SECONDS:-30}" \
    -e SMOKE_RESULT_PATH=/work/artifacts/deepseek-smoke.json \
    -e EVIDENCE_PATH=/work/artifacts/deepseek-initial-acceptance.json \
    -e PYTHONPATH=/work/src \
    --entrypoint python control-plane scripts/deepseek_initial_acceptance.py \
    2>/tmp/ds-acc.err | tee /tmp/ds-acc.out
  if [ -f "$ROOT/artifacts/deepseek-initial-acceptance.json" ]; then
    pass "discovery evidence written"
  else
    fail "discovery evidence not written"; tail -20 /tmp/ds-acc.err 2>/dev/null
  fi
fi

echo "== H. Checksum evidence =="
if [ -f "$ROOT/artifacts/deepseek-initial-acceptance.json" ]; then
  ( cd "$ROOT/artifacts" && shasum -a 256 deepseek-initial-acceptance.json > deepseek-initial-acceptance.json.sha256 )
  ( cd "$ROOT/artifacts" && shasum -a 256 deepseek-smoke.json > deepseek-smoke.json.sha256 )
  pass "evidence checksummed"
  cat "$ROOT/artifacts/deepseek-initial-acceptance.json.sha256"
fi

echo "== Secret scan (key value must appear NOWHERE) =="
scan_target() { # label command...
  local label="$1"; shift
  if "$@" 2>/dev/null | grep -qF "$KEY_VALUE"; then
    fail "credential FOUND in $label"
  else
    pass "credential absent in $label"
  fi
}
scan_target "evidence files" cat "$ROOT/artifacts/deepseek-initial-acceptance.json" "$ROOT/artifacts/deepseek-smoke.json"
scan_target "control-plane logs" docker logs "$CP"
scan_target "gateway logs" docker logs "$GW"
scan_target "lab-api logs" docker logs "$LAB"
scan_target "egress-proxy logs" docker logs "$PX"
# The key legitimately lives ONLY in the gateway's environment (env_file pattern), so it is
# expected to appear in the gateway's own docker inspect. We scan every OTHER container for absence;
# step E already asserted presence in the gateway and absence elsewhere.
scan_target "docker inspect (non-gateway)" docker inspect "$CP" "$LAB" "$PX"
# Control-plane DB + audit + API responses.
scan_target "control-plane DB" docker exec "$CP" sh -c 'cat /data/aegis.db 2>/dev/null | tr -c "[:print:]" " "'
scan_target "scans API response" docker exec "$CP" sh -c 'python -c "import urllib.request;print(urllib.request.urlopen(\"http://127.0.0.1:8000/api/scans\").read().decode())"'

echo
echo "== Summary: PASS=$PASS FAIL=$FAIL =="
if [ "$FAIL" -eq 0 ]; then echo "ACCEPTANCE CHECKS OK (see evidence for GO/NO-GO verdict)"; else echo "ACCEPTANCE HAD FAILURES"; fi
