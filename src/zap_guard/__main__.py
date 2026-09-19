"""Entry point: ``python -m zap_guard``. Ports and the origin allowlist are fixed constants."""

from __future__ import annotations

import sys
import threading

from zap_guard.guard import GUARD_VERSION, GuardState, serve

LISTEN_HOST = "0.0.0.0"  # noqa: S104 - reachable only on the internal zap-egress network
PROXY_PORT = 3128
CONTROL_PORT = 3129


def main() -> int:
    state = GuardState()
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
