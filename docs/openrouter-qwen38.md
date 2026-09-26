# OpenRouter + Qwen3.8 27B deployment

This is an explicit public-egress profile for Aegis. It uses the exact OpenRouter model ID
`qwen/qwen3.8-27b`; aliases, `:free` variants, router-selected models and additional allowlist
entries fail startup. The control plane never receives the API key. Only `llm-gateway` can read the
key file, and it reaches only a CONNECT proxy whose sole allowed destination is
`openrouter.ai:443`.

Each request uses strict `json_schema` output plus these OpenRouter provider preferences:

```json
{
  "require_parameters": true,
  "data_collection": "deny",
  "zdr": true
}
```

Local Pydantic validation remains authoritative and fails closed on malformed output, a changed
model identity, redirect, truncation, unexpected content type, oversized response or token-budget
breach. A hosted routed model has no content digest and Aegis records no deterministic seed claim.

## 1. Create the key file

Do not put the key in `.env`, Compose YAML, a command argument, chat, Git or an extension manifest.
On Fedora/RHEL, create a private file without echoing the value:

```bash
install -d -m 0700 "$HOME/.config/aegis-ai"
umask 077
read -rsp 'OpenRouter API key: ' AEGIS_OPENROUTER_KEY_INPUT
printf '%s' "$AEGIS_OPENROUTER_KEY_INPUT" > "$HOME/.config/aegis-ai/openrouter-api-key"
unset AEGIS_OPENROUTER_KEY_INPUT
chmod 0600 "$HOME/.config/aegis-ai/openrouter-api-key"
```

The Compose mount uses the SELinux `Z` relabel option. Use a dedicated copy of the key file because
that label is private to this container workload.

## 2. Configure prompts, agents and tools

Copy [`deploy/extensions/manifest.json`](../deploy/extensions/manifest.json) outside the checkout,
keep it owned by the deployment user and mode `0600` or `0640`, then set
`AEGIS_EXTENSION_MANIFEST_SOURCE` to its absolute path. The schema supports:

- `prompt_fragments`: bounded guidance with no URLs or credentials;
- `agent_profiles`: specializations of existing controller-owned roles and task types;
- `tool_bindings`: display aliases for capability/profile pairs already compiled into Aegis.

This manifest cannot load code, add commands or URLs, invent a capability, grant new authority or
bypass controller policy. Invalid, writable-by-group/others, symlinked or oversized manifests fail
startup. Validate changes before deployment:

```bash
python -c 'from aegis.extensions import load_extension_pack; load_extension_pack("/absolute/path/extensions.json")'
```

## 3. Development smoke deployment

```bash
export OPENROUTER_API_KEY_SOURCE="$HOME/.config/aegis-ai/openrouter-api-key"
export AEGIS_EXTENSION_MANIFEST_SOURCE="$PWD/deploy/extensions/manifest.json"

docker compose -f docker-compose.yml \
  -f docker-compose.openrouter.yml \
  -f docker-compose.dashboard.yml config --quiet

docker compose -f docker-compose.yml \
  -f docker-compose.openrouter.yml \
  -f docker-compose.dashboard.yml up --build -d

curl --fail http://127.0.0.1:8000/ready
docker compose -f docker-compose.yml -f docker-compose.openrouter.yml \
  -f docker-compose.dashboard.yml logs --tail=200 llm-gateway egress-proxy
```

The health endpoint proves process/config readiness; it intentionally does not spend OpenRouter
credits. Run one authorized synthetic-lab scan to validate the live account, balance, model
availability and structured-output route before accepting traffic.

## 4. Immutable Fedora/RHEL production deployment

Install Docker Engine with Compose v2 on the host. Use registry image references pinned by digest,
not tags. `AEGIS_IMAGE` is the same application image for the control plane, target and gateway;
`AEGIS_EGRESS_PROXY_IMAGE` is a reviewed Squid image; `AEGIS_DASHBOARD_IMAGE` is reviewed Nginx.

```bash
export AEGIS_IMAGE='registry.example.com/aegis@sha256:<64-lowercase-hex>'
export AEGIS_EGRESS_PROXY_IMAGE='registry.example.com/squid@sha256:<64-lowercase-hex>'
export AEGIS_DASHBOARD_IMAGE='registry.example.com/nginx@sha256:<64-lowercase-hex>'
export OPENROUTER_API_KEY_SOURCE="$HOME/.config/aegis-ai/openrouter-api-key"
export AEGIS_EXTENSION_MANIFEST_SOURCE=/opt/aegis/config/extensions.json

docker compose -p aegis-ai-openrouter \
  -f docker-compose.yml \
  -f docker-compose.openrouter.yml \
  -f docker-compose.dashboard.yml \
  -f docker-compose.prod.yml \
  -f docker-compose.openrouter.prod.yml \
  -f docker-compose.dashboard.prod.yml config --quiet

docker compose -p aegis-ai-openrouter \
  -f docker-compose.yml \
  -f docker-compose.openrouter.yml \
  -f docker-compose.dashboard.yml \
  -f docker-compose.prod.yml \
  -f docker-compose.openrouter.prod.yml \
  -f docker-compose.dashboard.prod.yml pull

docker compose -p aegis-ai-openrouter \
  -f docker-compose.yml \
  -f docker-compose.openrouter.yml \
  -f docker-compose.dashboard.yml \
  -f docker-compose.prod.yml \
  -f docker-compose.openrouter.prod.yml \
  -f docker-compose.dashboard.prod.yml up -d --no-build
```

Verify:

```bash
curl --fail http://127.0.0.1:8000/ready
docker compose -p aegis-ai-openrouter -f docker-compose.yml \
  -f docker-compose.openrouter.yml ps
curl --fail http://127.0.0.1:8000/api/extensions
```

Place host TLS termination/authentication in front of the loopback-only dashboard port when remote
access is required. Never publish the gateway, proxy, control-plane or synthetic target ports.

## 5. Update, rollback and stop

Update by changing only digest-pinned image values, running `config --quiet` and deploying with
`--no-build`. Preserve the previous three digests; rollback by restoring them and repeating `pull`
and `up -d --no-build`. The SQLite named volume is not removed by these commands.

To stop without deleting persistent data:

```bash
docker compose -p aegis-ai-openrouter \
  -f docker-compose.yml -f docker-compose.openrouter.yml \
  -f docker-compose.dashboard.yml -f docker-compose.prod.yml \
  -f docker-compose.openrouter.prod.yml -f docker-compose.dashboard.prod.yml down
```

Production acceptance remains conditional on an organization-approved public-data policy,
OpenRouter account privacy settings, an authorized synthetic scan, audit/log review, alert routing,
backup/restore evidence and an observed rollback rehearsal.
