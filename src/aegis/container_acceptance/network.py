"""Internal, no-egress synthetic-range network lifecycle for Phase 2.8.

The range target runs on a docker network created with ``--internal`` (no gateway, no NAT, no
published port), so no container on it can reach a public network. Every interaction with the
target — setting the scenario arm on the control plane, the benign liveness check, and the worker's
bounded probes — happens from a short-lived helper container attached only to that internal network;
the host never routes to the target. Teardown removes the stack, its volumes and the network, and
the harness then proves zero leftovers by label.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from uuid import uuid4

from aegis.container_acceptance.contracts import CleanupProof, ContainerAcceptanceError
from aegis.container_acceptance.docker_cli import count_by_label, docker
from aegis.container_acceptance.images import require_pinned

SHOP_ALIAS = "aegis-shop"
SHOP_PORT = 8102
SQL_SCENARIO = "shop-catalog-query-v1"

# A hardened run spec shared by the target and every helper: unprivileged, read-only root fs, a
# small tmpfs for the only writable state, all Linux capabilities dropped, no new privileges.
_HARDENING = (
    "--user", "65532:65532", "--read-only",
    "--tmpfs", "/tmp:size=32m",  # noqa: S108 - docker tmpfs mount spec, not a host temp path
    "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
    "--pids-limit", "128", "--memory", "512m",
)


@dataclass
class InternalRange:
    """A controller-owned internal synthetic range: one shop target on a no-egress network."""

    range_image_ref: str
    label: str = field(default_factory=lambda: f"aegis.phase28={uuid4().hex[:12]}")
    _network: str = ""
    _shop: str = ""

    @property
    def network(self) -> str:
        return self._network

    def _run_id(self) -> str:
        return self.label.split("=", 1)[1]

    def create(self) -> None:
        image = require_pinned(self.range_image_ref)
        run_id = self._run_id()
        self._network = f"aegis-p28-{run_id}"
        self._shop = f"aegis-p28-shop-{run_id}"
        created = docker(
            "network", "create", "--internal", "--label", self.label, self._network, timeout=30
        )
        if created.returncode != 0:
            raise ContainerAcceptanceError(f"NETWORK_CREATE_FAILED:{created.stderr.strip()[:120]}")
        run = docker(
            "run", "-d", "--name", self._shop, "--network", self._network,
            "--network-alias", SHOP_ALIAS, "--label", self.label, *_HARDENING, image, timeout=60,
        )
        if run.returncode != 0:
            raise ContainerAcceptanceError(f"TARGET_RUN_FAILED:{run.stderr.strip()[:120]}")
        if not self._wait_healthy():
            raise ContainerAcceptanceError("TARGET_NOT_HEALTHY")

    def network_is_internal(self) -> bool:
        result = docker(
            "network", "inspect", self._network, "--format", "{{.Internal}}", timeout=20
        )
        return result.stdout.strip() == "true"

    def _helper_python(self, code: str, *, timeout: float = 30.0) -> tuple[int, str]:
        """Run one bounded python snippet in a helper container on the internal network."""

        result = docker(
            "run", "--rm", "--network", self._network, "--label", self.label, *_HARDENING,
            "-e", "HOME=/tmp", self.range_image_ref, "python", "-c", code, timeout=timeout,
        )
        return result.returncode, result.stdout.strip()

    def _wait_healthy(self, attempts: int = 20) -> bool:
        code = (
            "import urllib.request,sys\n"
            "for _ in range(20):\n"
            "  try:\n"
            f"    urllib.request.urlopen('http://{SHOP_ALIAS}:{SHOP_PORT}/health',timeout=2).read()\n"
            "    print('ok');sys.exit(0)\n"
            "  except Exception:\n"
            "    import time;time.sleep(0.5)\n"
            "sys.exit(1)\n"
        )
        rc, out = self._helper_python(code, timeout=40)
        return rc == 0 and out.endswith("ok")

    def benign_health(self) -> bool:
        """A benign liveness GET of /health (no query, no injection). Used by the verifier path."""

        rc, out = self._helper_python(
            "import urllib.request;"
            f"print(urllib.request.urlopen('http://{SHOP_ALIAS}:{SHOP_PORT}/health',timeout=3)"
            ".status)"
        )
        return rc == 0 and out.strip() == "200"

    def set_arm(self, arm: str) -> int:
        """Set the scenario arm on the control plane (controller ground truth); return its gen."""

        if arm not in {"vulnerable", "patched"}:
            raise ContainerAcceptanceError(f"UNKNOWN_ARM:{arm}")
        code = (
            "import urllib.request,json\n"
            f"body=json.dumps({{'mode':'{arm}'}}).encode()\n"
            f"r=urllib.request.Request('http://{SHOP_ALIAS}:{SHOP_PORT}/__control/scenarios/"
            f"{SQL_SCENARIO}',data=body,headers={{'Content-Type':'application/json'}},method='PUT')\n"
            "print(json.loads(urllib.request.urlopen(r,timeout=4).read())['generation'])\n"
        )
        rc, out = self._helper_python(code)
        if rc != 0 or not out.isdigit():
            raise ContainerAcceptanceError(f"SET_ARM_FAILED:{arm}:{out[:80]}")
        return int(out)

    def reset(self) -> bool:
        code = (
            "import urllib.request\n"
            f"r=urllib.request.Request('http://{SHOP_ALIAS}:{SHOP_PORT}/__control/reset',"
            "method='POST')\n"
            "print(urllib.request.urlopen(r,timeout=4).status)\n"
        )
        rc, out = self._helper_python(code)
        return rc == 0 and out.strip() == "200"

    def probe_count(self, q: str) -> tuple[int, int]:
        """Issue ONE bounded GET /api/products?q=<q> from a helper; return (status, row_count).

        This is the injection worker's own boolean-differential traffic (control / boolean-TRUE /
        boolean-FALSE), never the verifier's."""

        payload = json.dumps(q)
        code = (
            "import urllib.request,urllib.parse,json\n"
            f"q={payload}\n"
            f"u='http://{SHOP_ALIAS}:{SHOP_PORT}/api/products?'+urllib.parse.urlencode({{'q':q}})\n"
            "try:\n"
            "  resp=urllib.request.urlopen(u,timeout=4)\n"
            "  data=json.loads(resp.read());n=len(data.get('products',[]));print(resp.status,n)\n"
            "except urllib.error.HTTPError as e:\n"
            "  print(e.code,-1)\n"
        )
        rc, out = self._helper_python(code)
        parts = out.split()
        if rc != 0 or len(parts) != 2:
            raise ContainerAcceptanceError(f"PROBE_FAILED:{out[:80]}")
        return int(parts[0]), int(parts[1])

    def egress_blocked_proof(self) -> str:
        """Prove no public egress: a helper's TCP connect to TEST-NET-1 (192.0.2.1:443) must fail.

        192.0.2.0/24 (RFC 5737) is a documentation range that routes to no real host, so this
        touches no real service; on an ``--internal`` network the connect has no gateway and fails
        fast. Returns a short proof string."""

        code = (
            "import socket\n"
            "s=socket.socket();s.settimeout(3)\n"
            "try:\n"
            "  s.connect(('192.0.2.1',443));print('EGRESS_REACHABLE')\n"
            "except Exception as e:\n"
            "  print('EGRESS_BLOCKED:'+type(e).__name__)\n"
        )
        _rc, out = self._helper_python(code, timeout=20)
        return out.strip()[:120] or "EGRESS_PROOF_UNAVAILABLE"

    def cleanup(self) -> None:
        if self._shop:
            docker("rm", "-f", self._shop, timeout=30)
        if self._network:
            docker("network", "rm", self._network, timeout=30)

    def leftover_proof(self, *, was_internal: bool, egress_proof: str = "") -> CleanupProof:
        """Count objects still carrying this run's label after cleanup. ``was_internal`` is the
        value captured from :meth:`network_is_internal` BEFORE teardown."""

        return CleanupProof(
            stack_containers_remaining=count_by_label("container", self.label),
            volumes_remaining=count_by_label("volume", self.label),
            networks_remaining=count_by_label("network", self.label),
            network_was_internal=was_internal,
            egress_blocked_proof=egress_proof,
        )
