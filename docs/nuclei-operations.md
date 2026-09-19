# Nuclei operations

## Start and inspect

```bash
docker compose -f docker-compose.yml -f docker-compose.nuclei.yml up -d --build
docker compose -f docker-compose.yml -f docker-compose.nuclei.yml ps
docker compose -f docker-compose.yml -f docker-compose.nuclei.yml logs nuclei-runner
```

Healthy startup includes `ready=True`, `failures=none` and
`signature_probe=SIGNED_VERIFIED`. The runner has no host port; readiness and execution are
available only to the control plane over `engine-rpc`.

Request the single capability with `POST /api/scans`:

```json
{"capability":"nuclei_scm_metadata_exposure_v1","variant":"vulnerable"}
```

For the patched synthetic route use `"variant":"patched"`. Do not add a URL, template, tool,
flag, header or credential: the strict request schema refuses those fields.

## Acceptance and gates

Run `scripts/phase_1_2_acceptance.py` inside the control-plane container with the internal control
plane and runner URLs. It performs five vulnerable and five patched trials, then the bounded
negative controls and proves that the runner execution counter increases only for the ten
authorized cases. Run the offline backend and frontend commands in `docs/runbook.md` as separate
gates.

## Failure handling

- `RUNNER_NOT_READY` / `SIGNATURE_NOT_VERIFIED`: stop; inspect boot attestation. Never bypass it.
- `ENGINE_*_MISMATCH`: rebuild only from reviewed pins; do not substitute a newer binary.
- `TEMPLATE_INTEGRITY_FAILURE`: compare checked-in bytes with the manifest and upstream commit.
- `OUTPUT_MALFORMED`, `OUTPUT_OVERSIZED`, timeout or non-zero exit: result is INCOMPLETE, never PASS.
- `OUT_OF_SCOPE_ORIGIN`, `UNAPPROVED_STATE_CHANGE`, `UNSUPPORTED_PROTOCOL`: expected controller
  policy rejection with zero runner execution and zero target traffic.

Changing a binary, template, flag, parser rule, target, budget or verifier requires a reviewed
version bump and rerunning the full matrix. Never run `nuclei -ut` or mount a user template tree.
