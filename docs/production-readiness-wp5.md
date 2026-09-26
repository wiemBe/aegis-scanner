# Production Readiness Work Package 5 — Private Provider Deployment Path

Status: **IMPLEMENTED AND OFFLINE-VERIFIED; ENVIRONMENT VALIDATION REQUIRED**.

This work package closes the repository-level gap for a company-private, OpenAI-compatible provider
deployment. It does not claim that an operator's registry image, private endpoint, credential, TLS
chain, capacity, log pipeline, alert delivery, or staging environment has been validated.

## Deployment contract

[`docker-compose.private-provider.prod.yml`](../docker-compose.private-provider.prod.yml) is used
only with the base and immutable-image overlays. `control-plane`, `lab-api`, and `llm-gateway` run
the same fully qualified `sha256` image reference with no local build fallback. None of those three
publishes a host port; all three drop every Linux capability, retain `no-new-privileges`, and use
read-only root filesystems. The optional dashboard uses a separately required immutable digest,
drops all capabilities, and publishes only `127.0.0.1:8000`.

The control plane joins only `security-lab` and internal `planner-rpc`. The gateway joins only
`planner-rpc` and `provider-egress`; it never joins the target network. The gateway provider adapter
accepts one configured HTTPS origin, permits only its registered path, disables redirects and
ambient proxy inheritance, and binds one exact model id.

The dashboard joins the internal application network and a credential-free host-ingress bridge
needed for Docker's loopback publication. It contains no provider credential and is the only service
with a published port; the binding is exactly `127.0.0.1:8000`.

The provider bearer token is a read-only file mounted only at
`/run/secrets/aegis-provider-token` in `llm-gateway`. Its value is absent from Compose environments,
rendered config, commands, images, and the control plane. The gateway accepts either the existing
development-only environment token or the production file, never both. It rejects a missing,
non-regular, symlinked, empty, invalid-UTF-8, NUL-containing, or over-16-KiB file without returning
the path or value. The control-plane startup guard and readiness check reject either credential
source.

## Mandatory preflight

`python -m aegis.deploy.private_provider_preflight` validates both immutable images, the HTTPS
endpoint, bounded model id, and specific absolute credential source path. It always renders all
five Compose layers and then proves:

- all three services use the exact immutable digest and have no active `build`;
- no service publishes a host port;
- control plane and gateway carry the exact provider/model/RPC bindings;
- only the gateway refers to the credential file, as one read-only bind mount;
- control-plane, gateway, target, and egress network memberships match the required boundary.
- the dashboard image is immutable and its only publication is the exact loopback binding.

Docker/Compose absence, malformed input, render failure, missing services, unexpected environment,
network drift, credential drift, a mutable image, or ambiguous output fails closed. The preflight
does not read the token file, pull an image, contact a provider, or start a service.

## Staging gate

`python -m aegis.deploy.staging_gate` is a read-only loopback-only observer. `healthy` mode requires
liveness 200, readiness 200/true, and an available bounded metrics response for every sample.
`not-ready` mode requires liveness to remain 200 while readiness returns 503/false for every sample.
It stops on the first mismatch and records only timestamps, status codes, a fixed result code, and a
boolean; response bodies, URLs, headers, credentials, and raw exception text are excluded.

Fault injection remains an explicit platform/operator action. The application never damages its own
store to prove failure behavior. The runbook defines the required healthy soak → approved fault →
fail-closed observation → recovery sequence.

## Verification and remaining activation gates

Offline unit/contract tests cover input rejection, secret-safe errors, token-file resolution,
ambiguous credential rejection, immutable-image checks, exact topology, network/credential negative
controls, healthy soak behavior, fail-closed behavior, and bounded reports. A real Docker Compose
render of all five layers passes with placeholder non-secret inputs.

A provider-free real-Docker smoke on 2026-09-26 built the current application image, started the
base stack plus dashboard, and reached healthy state for all three services. Runtime inspection
confirmed the dashboard's dropped capabilities, read-only root filesystem, 128 MiB / 0.25 CPU / 64
PID limits, and `unless-stopped` policy. Its only publication was
`127.0.0.1:8000 -> 8080`; a three-sample loopback `healthy` staging gate returned liveness 200,
readiness 200/true, and metrics 200 on every sample. Teardown removed the test containers, two test
networks, volume, and locally built test images. This smoke used the offline heuristic provider; it
does not validate a private provider or registry image.

Before an operator may call the deployment production-ready, the actual environment must still
provide evidence for:

1. pulling and starting the approved registry digest;
2. private DNS/TLS/provider reachability and exact model identity;
3. the runbook's healthy soak, fail-closed fault observation, and recovery gate;
4. platform-owned log retention, metrics scraping, alert delivery, and incident response.

Until those environment-specific gates pass, the honest status is **DEPLOYMENT_PATH_READY / NOT YET
PRODUCTION-VALIDATED**. The product remains authorized only for its documented synthetic range and
approved private test environments; this work does not authorize external or production targets.
