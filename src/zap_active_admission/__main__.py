"""Entry point: ``python3 -m zap_active_admission``.

This process is the only runner-side holder of the lease-signing secret. It refuses to start
without a real secret and a real client credential, which is what turns "ZAP Active is enabled but
misconfigured" into a stopped container rather than an unauthenticated scan.
"""

from __future__ import annotations

import os
import sys

from aegis_zap_active.lease import LeaseRejected, normalize_secret
from zap_active_admission.registry import STATE_DIR, AdmissionRegistry
from zap_active_admission.server import serve

LISTEN_HOST = "0.0.0.0"  # noqa: S104 - reachable only on the internal active-admission network
LISTEN_PORT = 8095
SECRET_ENV = "AEGIS_ZAP_ACTIVE_LEASE_SECRET"  # noqa: S105 - variable name, not a secret
CLIENT_ENV = "AEGIS_ZAP_ACTIVE_ADMISSION_CLIENT"
MIN_CLIENT_TOKEN_BYTES = 32


def main() -> int:
    try:
        secret = normalize_secret(os.environ.get(SECRET_ENV))
    except LeaseRejected:
        sys.stderr.write(
            "admission-boot refused: missing, empty, short or placeholder lease-signing secret\n"
        )
        return 2
    client = (os.environ.get(CLIENT_ENV) or "").strip()
    if len(client) < MIN_CLIENT_TOKEN_BYTES:
        sys.stderr.write("admission-boot refused: missing or too-short admission client token\n")
        return 2
    # The secret must never be readable from this process's environment once it is in memory: a
    # crash dump, a /proc read or an accidental subprocess must not carry it.
    os.environ.pop(SECRET_ENV, None)
    os.environ.pop(CLIENT_ENV, None)

    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)
    registry = AdmissionRegistry(secret)
    sys.stderr.write(
        f"admission-boot ready root_owned={registry.state_root_owned} "
        f"restart_revoked={registry.restart_revoked_total}\n"
    )
    server = serve(registry, client.encode(), LISTEN_HOST, LISTEN_PORT)
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
