"""Entry point: ``python3 -m zap_active_runner``. All locations are fixed and not configurable.

This process is the *supervisor*: it holds the admission client credential and never the
lease-signing secret, so the container that hosts the untrusted ZAP engine contains no signing
material. The credential is read once and removed from ``os.environ`` immediately; the ZAP child's
environment is constructed from scratch (:func:`aegis_zap.profile.child_environment`), so the
engine cannot present it even though it shares this container's network namespace.

The runner refuses to become READY when the admission component is missing or unreachable. There is
no unauthenticated fallback: with no admission component there is no lease, and with no lease there
is no execution.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from aegis_zap_active.manifest import MANIFEST_PATH, load_manifest, manifest_digest
from zap_active_runner.admission_client import DEFAULT_ADMISSION_URL, AdmissionClient
from zap_active_runner.attestation import ActiveRunnerState, attest
from zap_active_runner.execution import Executor
from zap_active_runner.server import serve
from zap_runner.attestation import RunnerPaths, machine_arch
from zap_runner.guard_client import GuardClient

LISTEN_HOST = "0.0.0.0"  # noqa: S104 - reachable only on the internal active-rpc network
LISTEN_PORT = 8093
GUARD_HOST = "zap-active-scope-guard"
CLIENT_ENV = "AEGIS_ZAP_ACTIVE_ADMISSION_CLIENT"
RUNNER_CLIENT_ENV = "AEGIS_ZAP_ACTIVE_RUNNER_CLIENT"
GUARD_CONTROL_ENV = "AEGIS_ZAP_GUARD_CONTROL_SECRET"
ADMISSION_URL_ENV = "AEGIS_ZAP_ACTIVE_ADMISSION_URL"
MIN_CLIENT_TOKEN_BYTES = 32


def main() -> int:
    client_token = (os.environ.pop(CLIENT_ENV, "") or "").strip()
    runner_client = (os.environ.pop(RUNNER_CLIENT_ENV, "") or "").strip()
    guard_control = (os.environ.pop(GUARD_CONTROL_ENV, "") or "").strip()
    admission_url = os.environ.get(ADMISSION_URL_ENV, DEFAULT_ADMISSION_URL)
    if len(client_token) < MIN_CLIENT_TOKEN_BYTES:
        sys.stderr.write(
            "active-runner-boot refused: missing or too-short admission client credential; "
            "ZAP Active cannot run without an authenticated lease\n"
        )
        return 2
    if len(runner_client) < MIN_CLIENT_TOKEN_BYTES:
        sys.stderr.write("active-runner-boot refused: missing controller RPC credential\n")
        return 2
    if len(guard_control) < MIN_CLIENT_TOKEN_BYTES:
        sys.stderr.write("active-runner-boot refused: missing guard control credential\n")
        return 2
    admission = AdmissionClient(admission_url, client_token)
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
    state = ActiveRunnerState(
        manifest=manifest,
        manifest_digest=manifest_digest(MANIFEST_PATH),
        paths=paths,
        guard=GuardClient(paths.guard_control_url, control_secret=guard_control),
    )
    attest(state)
    if not admission.reachable():
        state.ready = False
        state.failure_codes.append("ADMISSION_UNAVAILABLE")
    sys.stderr.write(
        f"active-runner-boot ready={state.ready} "
        f"failures={','.join(state.failure_codes) or 'none'} "
        f"zap={state.engine().zap_version} java={state.java_runtime_version} "
        f"addonlist_verified={state.addonlist_verified} "
        f"admission_reachable={admission.reachable()}\n"
    )
    server = serve(
        Executor(state, admission=admission), LISTEN_HOST, LISTEN_PORT, runner_client.encode()
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
