"""Entry point: ``python3 -m zap_runner``. All locations are fixed; nothing is configurable."""

from __future__ import annotations

import sys
from pathlib import Path

from aegis_zap.manifest import MANIFEST_PATH, load_manifest, manifest_digest
from zap_runner.attestation import RunnerPaths, RunnerState, attest, machine_arch
from zap_runner.execution import Executor
from zap_runner.guard_client import GuardClient
from zap_runner.server import serve

LISTEN_HOST = "0.0.0.0"  # noqa: S104 - reachable only on the internal zap-rpc network
LISTEN_PORT = 8092
GUARD_HOST = "zap-scope-guard"


def main() -> int:
    manifest = load_manifest(MANIFEST_PATH)
    java = manifest.engine.java.platforms.get(machine_arch())  # type: ignore[call-overload]
    paths = RunnerPaths(
        zap_root=Path("/zap"),
        jar=Path("/zap") / manifest.engine.jar.path,
        plugin_dir=Path("/zap/plugin"),
        java_home=Path(java.home if java else "/nonexistent"),
        work_root=Path("/work"),
        guard_control_url=f"http://{GUARD_HOST}:3129",
        guard_proxy_host=GUARD_HOST,
        guard_proxy_port=3128,
    )
    state = RunnerState(
        manifest=manifest,
        manifest_digest=manifest_digest(MANIFEST_PATH),
        paths=paths,
        guard=GuardClient(paths.guard_control_url),
    )
    attest(state)
    sys.stderr.write(
        f"runner-boot ready={state.ready} failures={','.join(state.failure_codes) or 'none'} "
        f"zap={state.engine().zap_version} java={state.java_runtime_version} "
        f"addonlist_verified={state.addonlist_verified}\n"
    )
    server = serve(Executor(state), LISTEN_HOST, LISTEN_PORT)
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
