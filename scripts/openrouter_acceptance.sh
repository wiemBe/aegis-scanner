#!/usr/bin/env bash
# OpenRouter/Qwen3.8 27B provider acceptance (PUBLIC_LLM_OPENROUTER via the isolated llm-gateway).
#
# Execution order:
#   D. Build + bring up the base stack with the OpenRouter overlay.
#   E. Prove the API key is readable ONLY inside the gateway (mounted file), never in the control
#      plane / lab-api / egress-proxy, and never in any container's environment.
#   F. One provider-only smoke call (proves gateway->OpenRouter, ZERO target requests).
#   H. Secret scan: the key value must appear in NO log, DB, API response or evidence file.
#   I. Tear down the stack.
#
# Full synthetic discovery is intentionally out of scope for this script (there is no
# openrouter_initial_acceptance.py); it validates the live provider route only, as the deployment
# guide's "one authorized synthetic scan" precondition requires.
#
# Unlike DeepSeek (an env token) the OpenRouter key is a read-only FILE mounted only into the
# gateway. Point OPENROUTER_API_KEY_SOURCE at its absolute path. The value is read locally for
# ABSENCE assertions only and is never printed, echoed, logged or committed; presence in the gateway
# is proven by digest comparison, not by printing the key.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PROJECT="aegis-openrouter"
STACK="-f docker-compose.yml -f docker-compose.openrouter.yml"
KEY_PATH_IN_GW="/run/secrets/openrouter-api-key"
EXPECTED_MODEL="${EXPECTED_MODEL:-qwen/qwen3.8-27b}"
PASS=0
FAIL=0
pass() { echo "  PASS  $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }

cleanup() {
  echo "== I. Teardown =="
  docker compose $STACK -p "$PROJECT" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

: "${OPENROUTER_API_KEY_SOURCE:?set OPENROUTER_API_KEY_SOURCE to the absolute key-file path}"
if [ ! -s "$OPENROUTER_API_KEY_SOURCE" ]; then
  echo "FATAL: OPENROUTER_API_KEY_SOURCE ($OPENROUTER_API_KEY_SOURCE) is missing or empty." >&2
  exit 2
fi
# Local digest of the source key for a value-free presence proof; the key itself is never emitted.
KEY_SHA="$(shasum -a 256 "$OPENROUTER_API_KEY_SOURCE" | cut -d' ' -f1)"
# Key value read for ABSENCE scans only. Never printed.
KEY_VALUE="$(cat "$OPENROUTER_API_KEY_SOURCE")"

echo "== D. Build + bring up stack (project $PROJECT) =="
if ! docker compose $STACK -p "$PROJECT" build >/tmp/or-build.log 2>&1; then
  echo "FATAL: build failed"; tail -20 /tmp/or-build.log; exit 3
fi
if ! docker compose $STACK -p "$PROJECT" up -d >/tmp/or-up.log 2>&1; then
  echo "FATAL: up failed"; tail -30 /tmp/or-up.log; exit 3
fi

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
# Present in the gateway, and it is the RIGHT key: compare digests, never the value.
GW_SHA="$(docker exec "$GW" python -c "import hashlib,pathlib; print(hashlib.sha256(pathlib.Path('$KEY_PATH_IN_GW').read_bytes()).hexdigest())" 2>/dev/null || true)"
if [ "$GW_SHA" = "$KEY_SHA" ]; then
  pass "key file present in llm-gateway (only) and digest matches the source"
else
  fail "gateway key file missing or digest mismatch"
fi
# Absent as a mounted file in every other service.
path_absent_in() { # cid label
  if docker exec "$1" sh -c "test -e $KEY_PATH_IN_GW" 2>/dev/null; then
    fail "key file unexpectedly present in $2"
  else
    pass "key file absent in $2"
  fi
}
path_absent_in "$CP" "control-plane"
path_absent_in "$LAB" "lab-api"
path_absent_in "$PX" "egress-proxy"
# The key must never appear in ANY container's environment (it is a file mount, not an env var).
if docker inspect "$CP" "$GW" "$LAB" "$PX" 2>/dev/null | grep -qF "$KEY_VALUE"; then
  fail "credential value FOUND in a container environment"
else
  pass "credential value absent from every container environment"
fi

echo "== F. Provider-only smoke (zero target requests) =="
LAB_BEFORE="$(docker logs "$LAB" 2>&1 | grep -cE '"(GET|POST) /api/v1' || true)"
mkdir -p "$ROOT/artifacts"
if docker compose $STACK -p "$PROJECT" run --rm -T \
    -v "$ROOT":/work -w /work \
    -e GATEWAY_URL=http://llm-gateway:8080 \
    -e EXPECTED_MODEL="$EXPECTED_MODEL" \
    -e PYTHONPATH=/work/src \
    --entrypoint python control-plane scripts/openrouter_smoke.py \
    >"$ROOT/artifacts/openrouter-smoke.json" 2>/tmp/or-smoke.err; then
  tail -1 "$ROOT/artifacts/openrouter-smoke.json" > "$ROOT/artifacts/openrouter-smoke.json.tmp" \
    && mv "$ROOT/artifacts/openrouter-smoke.json.tmp" "$ROOT/artifacts/openrouter-smoke.json"
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
if [ "$SMOKE_OK" = "1" ] && grep -q '"smoke": "PASS"' "$ROOT/artifacts/openrouter-smoke.json"; then
  pass "smoke call PASS"
  echo "  smoke: $(cat "$ROOT/artifacts/openrouter-smoke.json")"
else
  fail "smoke call did not pass"
  echo "  smoke stderr:"; tail -5 /tmp/or-smoke.err 2>/dev/null
  echo "  smoke out:"; cat "$ROOT/artifacts/openrouter-smoke.json" 2>/dev/null
fi

echo "== H. Secret scan (key value must appear NOWHERE) =="
scan_target() { # label command...
  local label="$1"; shift
  if "$@" 2>/dev/null | grep -qF "$KEY_VALUE"; then
    fail "credential FOUND in $label"
  else
    pass "credential absent in $label"
  fi
}
scan_target "smoke evidence" cat "$ROOT/artifacts/openrouter-smoke.json"
scan_target "control-plane logs" docker logs "$CP"
scan_target "gateway logs" docker logs "$GW"
scan_target "lab-api logs" docker logs "$LAB"
scan_target "egress-proxy logs" docker logs "$PX"
scan_target "control-plane DB" docker exec "$CP" sh -c 'cat /data/aegis.db 2>/dev/null | tr -c "[:print:]" " "'
scan_target "scans API response" docker exec "$CP" sh -c 'python -c "import urllib.request;print(urllib.request.urlopen(\"http://127.0.0.1:8000/api/scans\").read().decode())"'
if [ -f "$ROOT/artifacts/openrouter-smoke.json" ]; then
  ( cd "$ROOT/artifacts" && shasum -a 256 openrouter-smoke.json > openrouter-smoke.json.sha256 )
  pass "smoke evidence checksummed"
fi

echo
echo "== Summary: PASS=$PASS FAIL=$FAIL =="
if [ "$FAIL" -eq 0 ]; then echo "OPENROUTER ACCEPTANCE OK"; else echo "OPENROUTER ACCEPTANCE HAD FAILURES"; fi
[ "$FAIL" -eq 0 ]
