# Nuclei runner isolation

The `nuclei-runner` service joins only two `internal: true` networks:

```text
control-plane -- engine-rpc --> nuclei-runner -- nuclei-target --> lab-api
```

The runner is absent from `security-lab`, `planner-rpc` and `model-egress`. The control plane binds
port 8000 only to its fixed `security-lab` address, so it is not listening on `engine-rpc`. The
runner can connect to `lab-api:8001`; live checks show control-plane port 8000 refused, LLM gateway
and Ollama names unresolved, and public `1.1.1.1:443` blocked. No port is published to the host.

Container controls: UID/GID 10001, read-only root, 16 MiB `/work` tmpfs, all capabilities dropped,
`no-new-privileges`, one CPU, 512 MiB memory, 64 PIDs, 256 file descriptors, JSON logs capped at
two 1 MiB files, no bind/host mount, no Docker socket and no shell binary. The runner environment
contains no model, ProjectDiscovery, proxy, authentication or application credential. The Nuclei
child gets a new allowlisted environment rather than inherited variables.

The pinned v3.11.1 `nuclei -h` output used for flag review is preserved at
`tests/fixtures/nuclei-3.11.1-help.txt`. Enabled flags are defined only in
`src/aegis_nuclei/profile.py`; the same module rejects forbidden flags and shell metacharacters.

Docker's internal networks are the lab enforcement boundary. They are adequate for this bounded
local acceptance but are not a production-grade egress firewall or workload sandbox.
