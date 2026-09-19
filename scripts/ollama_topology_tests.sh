#!/usr/bin/env bash
# Network-isolation, connectivity and secret-leakage checks for the local/private Ollama profile
# (AI_PROVIDER=ollama, mode LOCAL_LLM).
#
# Proves:
#   1. control-plane reports LOCAL_LLM; llm-gateway reports the ollama provider + exact model.
#   2. control-plane cannot reach the model endpoint (deny-all egress).
#   3. control-plane cannot reach the public internet.
#   4. llm-gateway CAN reach the pinned Ollama endpoint (native host via host-gateway).
#   5. llm-gateway cannot reach the lab/target network.
#   6. no service holds a provider credential (local Ollama needs none).
#   7. one live scan: model INPUT carries no credentials, balances or hidden reasoning.
#
# Requires native Ollama running with the model present. Uses a throwaway compose project (no host
# ports) to avoid colliding with a running deployment, then tears it down.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PROJECT="aegis-ollama-topo-$$"
MODEL="${AI_MODEL:-qwen3:4b}"
DC=(docker compose -p "$PROJECT" -f docker-compose.yml -f docker-compose.ollama.yml)
PASS=0
FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

cleanup() { "${DC[@]}" down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

cp() { "${DC[@]}" exec -T control-plane python -c "$1"; }
gw() { "${DC[@]}" exec -T llm-gateway python -c "$1"; }

echo "== bringing up throwaway Ollama stack ($PROJECT) =="
AI_MODEL="$MODEL" "${DC[@]}" up --build -d >/dev/null 2>&1
sleep 3

echo "== 1. mode + provider =="
cp "import urllib.request as u;import json;d=json.loads(u.urlopen('http://127.0.0.1:8000/health').read());print(d)" | grep -q "LOCAL_LLM" \
  && pass "control-plane reports LOCAL_LLM" || fail "control-plane not LOCAL_LLM"
cp "import urllib.request as u;print(u.urlopen('http://llm-gateway:8080/health').read().decode())" | grep -q "\"provider\": \"ollama\"\|\"provider\":\"ollama\"" \
  && pass "gateway reports ollama provider" || fail "gateway provider mismatch"

echo "== 2/3. control-plane deny-all egress =="
cp "import urllib.request as u
try: u.urlopen('http://host.docker.internal:11434/api/version',timeout=4);print('OPEN')
except Exception: print('BLOCKED')" | grep -q BLOCKED \
  && pass "control-plane cannot reach model endpoint" || fail "control-plane reached model endpoint"
cp "import urllib.request as u
try: u.urlopen('http://1.1.1.1',timeout=4);print('OPEN')
except Exception: print('BLOCKED')" | grep -q BLOCKED \
  && pass "control-plane cannot reach the internet" || fail "control-plane reached the internet"

echo "== 4. gateway reaches pinned Ollama endpoint =="
gw "import urllib.request as u;print(u.urlopen('http://host.docker.internal:11434/api/version',timeout=6).read().decode())" | grep -q "version" \
  && pass "gateway reaches Ollama /api/version" || fail "gateway cannot reach Ollama"

echo "== 5. gateway is not on the lab/target network =="
gw "import urllib.request as u
try: u.urlopen('http://lab-api:8001/health',timeout=4);print('OPEN')
except Exception: print('BLOCKED')" | grep -q BLOCKED \
  && pass "gateway cannot reach lab-api" || fail "gateway reached lab-api"

echo "== 6. no provider credential anywhere (local Ollama needs none) =="
leak=0
for svc in control-plane llm-gateway lab-api; do
  v="$("${DC[@]}" exec -T "$svc" printenv AI_AUTH_TOKEN 2>/dev/null || true)"
  [ -n "$v" ] && { fail "$svc has AI_AUTH_TOKEN set"; leak=1; }
done
[ "$leak" -eq 0 ] && pass "no service holds AI_AUTH_TOKEN"

echo "== 7. live scan: model input carries no secrets or hidden reasoning =="
report="$(cp "import urllib.request as u,json,time
req=u.Request('http://127.0.0.1:8000/api/scans',data=b'{\"target\":\"synthetic-bank-api\"}',
  headers={'Content-Type':'application/json'},method='POST')
sid=json.loads(u.urlopen(req).read())['id']
for _ in range(600):
    d=json.loads(u.urlopen('http://127.0.0.1:8000/api/scans/'+sid).read())
    if d['scan']['status'] not in ('QUEUED','RUNNING'): break
    time.sleep(0.5)
inp=json.dumps([e for e in d['audit'] if e['event'] in (
    'CANDIDATE_GENERATION_REQUEST','CANDIDATE_SELECTION_REQUEST')])
print('MODE='+str(d['scan']['mode']))
print('INPUT_LEAK='+str(any(m in inp for m in ('lab-token','synthetic-password','balance','1250.25','9875.5'))))
print('HIDDEN='+str(any(m in json.dumps(d).lower() for m in ('<think>','chain of thought'))))
")"
echo "$report" | grep -q "MODE=LOCAL_LLM" && pass "live scan ran under LOCAL_LLM" || fail "live scan not LOCAL_LLM"
echo "$report" | grep -q "INPUT_LEAK=False" && pass "no secret/balance in model input" || fail "secret/balance leaked into model input"
echo "$report" | grep -q "HIDDEN=False" && pass "no hidden reasoning stored" || fail "hidden reasoning present"

echo
echo "== $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
