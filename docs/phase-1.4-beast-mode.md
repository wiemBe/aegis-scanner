# Phase 1.4 — BEAST MODE controlled active adversarial testing

Technical subtitle: **Disposable AI Adversary Sandbox**.

Phase 1.4 is a SYNTHETIC_LAB-only implementation of unrestricted attack logic inside a strictly
bounded execution environment. The later TRUE ADVERSARY SHELL correction is authoritative: the
local model may choose arbitrary Bash syntax, installed tools and arguments, scripts, raw HTTP and
payloads. There is deliberately no command allowlist and the controller does not compile, rewrite
or substitute a command sequence. This phase does not enable Beast shell access for staging or
production.

Management wording: “Within a disposable and network-isolated attacker environment, the AI is
allowed to create and execute its own commands and payloads, adapt its attack strategy from observed
results, and produce evidence for independent verification.”

## Control boundary

The operator activates `BEAST_ACTIVE` only after a server-side preflight and exact typed phrase,
`BEAST Disposable Synthetic Bank Adversary Target`. The resulting lease is operator-, target-,
profile- and capability-bound; single-use; non-renewable by the model; at most 15 minutes; and
revoked at completion or emergency stop. `SAFE_PASSIVE` remains the default and `PRODUCTION_SAFE`
does not expose Phase 1.4 capabilities.

The command text is opaque data until the sandbox supervisor invokes `/bin/bash -c` under uid/gid
65532. The supervisor is root-owned and read-only, drops the child identity and groups, applies
rlimits, bounds wall time/output/artifacts, kills the command identity's entire process tree, scans
artifact metadata and destroys the run workspace. Its authorization secrets are absent from the
child environment and unreadable through `/proc` by the child identity.

The shell namespace has a read-only root, a quota-bound run workspace, no host mount, no Docker
socket and no project/model credential. `/tmp` and `/dev/shm` are root-only; HOME/TMP/XDG paths all
point into the run workspace. The sandbox has only the internal `beast-adversary` network. General
DNS is disabled and `beast-target` has a controller-owned static address. A narrow target gateway
bridges to the backend and independently enforces the exact path prefix, GET/HEAD/OPTIONS methods,
request total, rate, concurrency, transmitted bytes and received bytes. There is no public route.

```text
operator -> control plane -> one-purpose RPC relay -> root-owned supervisor
                                                     |
                                                     v uid/gid 65532
                                              arbitrary Bash command
                                                     |
                     no public route / static DNS -> exact target gateway -> synthetic fixture

model gateway ----> qwen3:8b (decision only; no target network)
verifier ---------> synthetic backend (fresh independent probes)
```

The relay is the only strictly required non-target service on the adversary network. It accepts only
the four typed supervisor RPC shapes, enforces a body limit and requires the supervisor token. The
untrusted child can reach the listener in its shared namespace but cannot authenticate to it,
signal the root supervisor or read its environment. This is a lab-grade container/process boundary,
not a production multi-tenant sandbox.

## Adaptive loop and authority

For each bounded decision the control plane sends qwen3:8b the objective, exact target origin/base
path, synthetic public account material, prior bounded observations, remaining budgets and a
controller-computed `objective_evidence_sufficient` fact. It sends no expected command. The model
returns either one arbitrary command or an explicit stop. Commands, results, normalized observations
and the next decision are linked by command/observation IDs and sequence numbers in the hash-chained
audit. A model or transport failure stays visible; no heuristic, mock or deterministic command
fallback exists.

The evidence-sufficient fact is a stop guard, not a finding verdict. Shell exit status, tool prose
and model prose never confirm a weakness. After an explicit model stop, `BeastVerifier` performs a
fresh deterministic probe and alone returns `CONFIRMED`, `PASS` or `VERIFIED`. Findings therefore
remain verifier-owned.

Supported synthetic scenarios are endpoint discovery, controlled information exposure, read-only
BOLA and safe injection. Each has vulnerable and patched targets. The public OpenAPI fixture exposes
ordinary endpoints but contains no `.git`, BOLA, injection or confirmation marker.

## Emergency stop and recovery

The permanent red stop control revokes the lease first, marks the run STOPPED, destroys the sandbox
session, kills the command identity, disarms target access and preserves all audit evidence. Checks
after every model/supervisor boundary prevent an in-flight result from overwriting STOPPED. An
emergency stop or failed cleanup blocks target reactivation. Clearing the block requires an explicit
operator restore action backed by a fresh deterministic health probe.

## Audit and honest limits

All activation, rejection, lease, command, output, artifact, boundary, verifier, cleanup and stop
events are retained in SQLite with a SHA-256 hash chain. The shell has no route or mount to it. This
is structured checksummed audit, **not an immutable external audit store**.

Phase 1.4 does not claim unrestricted autonomous pentesting, staging support, production readiness,
external callback/OAST support, state-changing operations or broad vulnerability coverage. ZAP
remains the Phase 1.3 passive profile; Nuclei and AEGIS_NATIVE retain their earlier bounded profiles.

## Acceptance

Primary acceptance is generated by `scripts/phase_1_4_acceptance.py` and must use the installed real
`qwen3:8b` through Ollama. It executes five isolated vulnerable and five patched trials per supported
scenario, retains exact model/runtime/digest/context/temperature/seed/token/timing provenance and
fails if commands are not model-authored, linked, adaptive, explicitly stopped and independently
verified. `scripts/phase_1_4_boundary_acceptance.py` performs destructive negative controls only
inside the sandbox. A failed model-adaptation requirement is NO-GO; deterministic commands are not
substituted.

The GO/NO-GO verdict and exact evidence filenames are recorded only after the live matrix and all
regression, topology, integrity, secret and visual gates finish.
