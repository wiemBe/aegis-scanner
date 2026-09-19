"""Entry point: ``python -m nuclei_runner``. All locations are fixed; nothing is configurable."""

from __future__ import annotations

import sys
from pathlib import Path

from aegis_nuclei.manifest import MANIFEST_PATH, load_manifest, manifest_digest
from nuclei_runner.attestation import RunnerState, attest
from nuclei_runner.execution import Executor
from nuclei_runner.server import serve

BINARY = Path("/opt/aegis-nuclei/bin/nuclei")
TEMPLATE_ROOT = Path("/opt/aegis-nuclei/templates")
WORK_ROOT = Path("/work")
LISTEN_HOST = "0.0.0.0"  # noqa: S104 - reachable only on the internal engine-rpc network
LISTEN_PORT = 8090


def main() -> int:
    state = RunnerState(
        manifest=load_manifest(MANIFEST_PATH),
        manifest_digest=manifest_digest(MANIFEST_PATH),
        binary=BINARY,
        template_root=TEMPLATE_ROOT,
        work_root=WORK_ROOT,
    )
    attest(state)
    sys.stderr.write(
        f"runner-boot ready={state.ready} failures={','.join(state.failure_codes) or 'none'} "
        f"signature_probe={state.signature_probe}\n"
    )
    server = serve(Executor(state), LISTEN_HOST, LISTEN_PORT)
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
