"""Entry point: ``python -m zap_guard``. Ports and the origin allowlist are fixed constants."""

from __future__ import annotations

import os
import sys
import threading

from zap_guard.guard import GUARD_VERSION, GuardState, serve

LISTEN_HOST = "0.0.0.0"  # noqa: S104 - reachable only on the internal zap-egress network
PROXY_PORT = 3128
CONTROL_PORT = 3129
CONTROL_SECRET_ENV = "AEGIS_ZAP_GUARD_CONTROL_SECRET"  # noqa: S105 - environment variable name


def main() -> int:
    secret = os.environ.pop(CONTROL_SECRET_ENV, "").encode()
    if len(secret) < 32:
        sys.stderr.write("guard-boot refused: missing guard control credential\n")
        return 2
    state = GuardState(control_secret=secret)
    proxy, control = serve(state, LISTEN_HOST, PROXY_PORT, CONTROL_PORT)
    sys.stderr.write(
        f"guard-boot version={GUARD_VERSION} allowed_origins={','.join(state.allowed_origins)}\n"
    )
    thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    thread.start()
    try:
        control.serve_forever()
    finally:
        proxy.shutdown()
        proxy.server_close()
        control.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
