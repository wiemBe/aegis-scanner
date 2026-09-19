#!/usr/bin/env bash
# Negative topology tests for the DEPRECATED public-provider (openai_responses) Squid egress
# profile. Public AI egress is NOT the intended deployment model; this profile is disabled by
# default. For the local/private Ollama path use scripts/ollama_topology_tests.sh instead.
#
# Proves, with mock provider traffic and NO real external model call:
#   1. Control plane cannot reach the public internet directly.
#   2. Control plane cannot reach the egress proxy.
#   3. LLM gateway cannot reach the lab API / target network.
#   4. LLM gateway can reach the provider ONLY through the proxy.
#   5. Proxy rejects a non-OpenAI hostname.
#   6. Proxy rejects direct-IP and non-443 destinations (and non-CONNECT methods).
#   7. No service other than llm-gateway receives AI_AUTH_TOKEN.
#   8. The API key value does not appear in logs, DB, audit, artifacts, or dashboard/API responses.
#   9. Heuristic discovery + patched retest still work while provider egress is disabled.
#
# The script builds two throwaway compose projects (no published host ports, so it never collides
# with a running deployment), runs the checks, and tears everything down.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PROV_PROJECT="aegis-topo-prov"
DEMO_PROJECT="aegis-topo-demo"
PROV="-f docker-compose.yml -f docker-compose.provider.yml -f docker-compose.mock-egress.yml"
DEMO="-f docker-compose.yml"
CREATED_GATEWAY_ENV=0
PASS=0
FAIL=0

pass() { echo "  PASS  $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL  $1"; FAIL=$((FAIL + 1)); }

cleanup() {
  echo "== Teardown =="
  docker compose $PROV -p "$PROV_PROJECT" down -v --remove-orphans >/dev/null 2>&1 || true
  docker compose $DEMO -p "$DEMO_PROJECT" down -v --remove-orphans >/dev/null 2>&1 || true
  if [ "$CREATED_GATEWAY_ENV" = "1" ]; then rm -f "$ROOT/.env.gateway"; fi
}
trap cleanup EXIT

# Ensure a gateway key exists for local validation (a clearly-fake sentinel; mock ignores it).
SENTINEL="sk-MOCK-LOCAL-VALIDATION-do-not-use-$(date +%s)"
if [ ! -f "$ROOT/.env.gateway" ]; then
  echo "AI_AUTH_TOKEN=$SENTINEL" > "$ROOT/.env.gateway"
  CREATED_GATEWAY_ENV=1
else
  SENTINEL="$(grep -E '^AI_AUTH_TOKEN=' "$ROOT/.env.gateway" | head -1 | cut -d= -f2-)"
fi

echo "== Generating local test CA =="
bash "$ROOT/scripts/gen_test_ca.sh"

echo "== Bringing up provider topology (project $PROV_PROJECT) =="
docker compose $PROV -p "$PROV_PROJECT" up --build -d
# Wait for control-plane + gateway health.
for _ in $(seq 1 40); do
  cp_state="$(docker compose $PROV -p "$PROV_PROJECT" ps control-plane --format '{{.State}}' 2>/dev/null)"
  [ "$cp_state" = "running" ] && break
  sleep 1
done

cid() { docker compose $PROV -p "$PROV_PROJECT" ps -q "$1"; }
CP="$(cid control-plane)"; GW="$(cid llm-gateway)"; PX="$(cid egress-proxy)"
LAB="$(cid lab-api)"; MOCK="$(cid mock-provider)"
for _ in $(seq 1 40); do
  docker exec "$CP" python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" >/dev/null 2>&1 && break
  sleep 1
done

# ---- helpers -------------------------------------------------------------------------------
tcp() { # container host port -> prints OPEN / CLOSED:<err>
  docker exec -i "$1" python - "$2" "$3" <<'PY'
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
try:
    socket.create_connection((host, port), timeout=6).close()
    print("OPEN")
except Exception as exc:  # noqa: BLE001
    print("CLOSED:" + type(exc).__name__)
PY
}

proxy_probe() { # container method target -> prints proxy HTTP status code (or 000)
  docker exec -i "$1" python - "$2" "$3" <<'PY'
import socket, sys
method, target = sys.argv[1], sys.argv[2]
try:
    s = socket.create_connection(("egress-proxy", 3128), timeout=6)
    if method == "CONNECT":
        req = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"
    else:
        req = f"{method} http://{target}/ HTTP/1.1\r\nHost: {target}\r\n\r\n"
    s.sendall(req.encode())
    line = s.recv(200).split(b"\r\n", 1)[0].decode(errors="replace")
    parts = line.split()
    print(parts[1] if len(parts) > 1 else "ERR")
except Exception:  # noqa: BLE001
    print("000")
PY
}

echo "== 1. Control plane cannot reach the public internet directly =="
for target in "1.1.1.1 443" "api.openai.com 443"; do
  set -- $target
  r="$(tcp "$CP" "$1" "$2")"
  [ "$r" != "OPEN" ] && pass "control-plane -> $1:$2 blocked ($r)" || fail "control-plane reached $1:$2"
done

echo "== 2. Control plane cannot reach the egress proxy =="
r="$(tcp "$CP" egress-proxy 3128)"
[ "$r" != "OPEN" ] && pass "control-plane -> egress-proxy:3128 blocked ($r)" || fail "control-plane reached egress-proxy"

echo "== 3. LLM gateway cannot reach the lab API / target network =="
# The gateway shares only planner-rpc with the control plane (for the RPC); it must not be able to
# reach the lab/target network at all.
r="$(tcp "$GW" lab-api 8001)"
[ "$r" != "OPEN" ] && pass "gateway -> lab-api:8001 blocked ($r)" || fail "gateway reached lab-api:8001"

echo "== 4. LLM gateway can reach the provider ONLY through the proxy =="
r="$(docker exec -i "$GW" python - <<'PY'
import httpx
try:
    httpx.get("https://api.openai.com/", trust_env=False, timeout=5)
    print("REACHED")
except Exception as exc:  # noqa: BLE001
    print("BLOCKED:" + type(exc).__name__)
PY
)"
[ "${r#BLOCKED}" != "$r" ] && pass "gateway direct -> api.openai.com blocked ($r)" || fail "gateway reached provider directly ($r)"
r="$(docker exec -i "$GW" python - <<'PY'
import httpx
try:
    resp = httpx.post("https://api.openai.com/v1/responses", json={}, headers={"Authorization": "Bearer x"},
                      proxy="http://egress-proxy:3128", verify="/certs/test-ca.pem", trust_env=False, timeout=15)
    print(f"OK:{resp.status_code}:{resp.json().get('status')}")
except Exception as exc:  # noqa: BLE001
    print("ERR:" + type(exc).__name__)
PY
)"
[ "${r#OK:200:completed}" != "$r" ] && pass "gateway -> proxy -> provider tunnel + TLS verify OK ($r)" || fail "gateway could not reach mock provider via proxy ($r)"

echo "== 5. Proxy rejects a non-OpenAI hostname =="
r="$(proxy_probe "$GW" CONNECT example.com:443)"
[ "$r" = "403" ] && pass "CONNECT example.com:443 -> 403" || fail "non-OpenAI host not denied (got $r)"

echo "== 6. Proxy rejects direct-IP, non-443, and non-CONNECT =="
r="$(proxy_probe "$GW" CONNECT 1.1.1.1:443)";       [ "$r" = "403" ] && pass "CONNECT 1.1.1.1:443 (direct IP) -> 403" || fail "direct-IP CONNECT not denied (got $r)"
r="$(proxy_probe "$GW" CONNECT api.openai.com:80)"; [ "$r" = "403" ] && pass "CONNECT api.openai.com:80 (non-443) -> 403" || fail "non-443 CONNECT not denied (got $r)"
r="$(proxy_probe "$GW" GET api.openai.com)";        [ "$r" = "403" ] && pass "GET via proxy (non-CONNECT) -> 403" || fail "non-CONNECT method not denied (got $r)"

echo "== 7. Only llm-gateway receives AI_AUTH_TOKEN =="
for svc in control-plane lab-api egress-proxy mock-provider; do
  v="$(docker exec "$(cid "$svc")" printenv AI_AUTH_TOKEN 2>/dev/null || true)"
  [ -z "$v" ] && pass "$svc has no AI_AUTH_TOKEN" || fail "$svc has AI_AUTH_TOKEN set"
done
v="$(docker exec "$GW" printenv AI_AUTH_TOKEN 2>/dev/null || true)"
[ -n "$v" ] && pass "llm-gateway has AI_AUTH_TOKEN" || fail "llm-gateway missing AI_AUTH_TOKEN"

echo "== 8. API key value does not leak (logs / DB / API responses) =="
# Drive one gateway-mode scan so audit records + DB + API responses exist.
docker exec -i "$CP" python - <<'PY'
import json, time, urllib.request
def post(path, data):
    req = urllib.request.Request("http://127.0.0.1:8000" + path, data=json.dumps(data).encode(),
                                 headers={"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req))
sid = post("/api/scans", {"target": "synthetic-bank-api"})["id"]
for _ in range(120):
    r = json.load(urllib.request.urlopen(f"http://127.0.0.1:8000/api/scans/{sid}"))
    if r["scan"]["status"] not in ("QUEUED", "RUNNING"):
        break
    time.sleep(0.25)
print("scan status:", r["scan"]["status"])
PY
leak=0
for svc in control-plane llm-gateway egress-proxy lab-api mock-provider; do
  if docker logs "$(cid "$svc")" 2>&1 | grep -qF "$SENTINEL"; then fail "$SENTINEL found in $svc logs"; leak=1; fi
done
# API responses (what the dashboard renders) + persisted DB.
if docker exec "$CP" python -c "
import json, urllib.request
scans = json.load(urllib.request.urlopen('http://127.0.0.1:8000/api/scans'))
blob = json.dumps(scans)
for s in scans:
    blob += json.dumps(json.load(urllib.request.urlopen('http://127.0.0.1:8000/api/scans/'+s['id'])))
import sys; sys.exit(0 if '$SENTINEL' not in blob else 1)
"; then :; else fail "$SENTINEL found in control-plane API/audit responses"; leak=1; fi
if docker exec "$CP" sh -c "grep -qF '$SENTINEL' /data/aegis.db 2>/dev/null"; then fail "$SENTINEL found in control-plane DB"; leak=1; fi
[ "$leak" = "0" ] && pass "no key value in logs / DB / API responses / audit"

echo "== 9. Heuristic discovery + patched retest work with provider egress disabled =="
docker compose $DEMO -p "$DEMO_PROJECT" up --build -d >/dev/null 2>&1
for _ in $(seq 1 40); do
  [ "$(docker compose $DEMO -p "$DEMO_PROJECT" ps control-plane --format '{{.State}}' 2>/dev/null)" = "running" ] && break
  sleep 1
done
DCP="$(docker compose $DEMO -p "$DEMO_PROJECT" ps -q control-plane)"
# Wait for uvicorn readiness (container "running" precedes the socket being accepted).
for _ in $(seq 1 40); do
  docker exec "$DCP" python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" >/dev/null 2>&1 && break
  sleep 1
done
if docker exec -i "$DCP" python - < "$ROOT/scripts/demo_e2e.py" >/tmp/aegis-demo-e2e.json 2>/tmp/aegis-demo-e2e.err; then
  pass "heuristic FAIL -> linked patched PASS (see /tmp/aegis-demo-e2e.json)"
else
  fail "heuristic discovery/retest failed ($(tail -1 /tmp/aegis-demo-e2e.err))"
fi

echo
echo "================= TOPOLOGY TEST SUMMARY ================="
echo "  PASSED: $PASS    FAILED: $FAIL"
echo "========================================================"
[ "$FAIL" -eq 0 ]
