# syntax=docker/dockerfile:1.7
#
# Aegis ZAP active lease admission component (Phase 1.5).
#
# This is the runner-side authority for the single-use activation lease. It exists as a SEPARATE
# container for one reason: the untrusted ZAP engine runs inside the zap-active-runner container,
# and the lease-signing secret and the armed-lease registry must not live where that engine runs.
#
#   - it runs as root (uid 0) so its state directory can be root-owned and 0700. The ZAP process
#     runs unprivileged in a different container and has no filesystem path to it at all;
#   - it holds the ONLY runner-side copy of the lease-signing secret. The runner supervisor never
#     receives it, so the container hosting ZAP contains no signing material;
#   - every mutating call requires the supervisor's client credential, which is read once at boot
#     and removed from the environment. The ZAP child's environment is constructed from scratch, so
#     the engine cannot present it even though it shares the runner's network namespace;
#   - root here is a *narrowing*, not a privilege: the root filesystem is read-only, every Linux
#     capability is dropped, no-new-privileges is set, there is no shell, no package manager, no
#     host mount, no published port and the only writable path is a private tmpfs.
#
# Build (from the repository root):
#   docker build -f deploy/zap-active-admission/Dockerfile -t aegis-zap-active-admission:1.5.0 .

# Python 3.11 deliberately: the hash-locked dependency set (deploy/zap-runner/requirements.lock)
# is generated for the cp311 interpreter that ships inside the pinned ZAP image, so the admission
# component runs the SAME wheel set as the runner and pip --require-hashes verifies it byte-for-byte.
ARG PYTHON_IMAGE=python:3.11-slim@sha256:da047cb8f9d1d98e5c070f5300ba9f7274e33b8fc0e5be5ed88740aed1b95ba9
FROM ${PYTHON_IMAGE}
LABEL org.opencontainers.image.title="aegis-zap-active-admission" \
      org.opencontainers.image.version="1.5.0"
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/aegis-admission/lib

COPY deploy/zap-runner/requirements.lock /tmp/requirements.lock
RUN python3 -m pip install --no-cache-dir --no-deps --only-binary=:all: --require-hashes \
        --target /opt/aegis-admission/lib -r /tmp/requirements.lock \
    && rm /tmp/requirements.lock
COPY src/aegis_zap /opt/aegis-admission/lib/aegis_zap
COPY src/aegis_zap_active /opt/aegis-admission/lib/aegis_zap_active
COPY src/zap_active_admission /opt/aegis-admission/lib/zap_active_admission

# Root-owned read-only code; no package manager and no shell remain. This MUST stay the final RUN
# instruction (later RUN steps would need /bin/sh).
RUN find /opt/aegis-admission -type d -name __pycache__ -prune -exec rm -rf {} + \
    && rm -f /opt/aegis-admission/lib/aegis_zap_active/countersign_cli.py \
    && chown -R root:root /opt/aegis-admission \
    && chmod -R a-w /opt/aegis-admission \
    && pip uninstall -y -q pip setuptools wheel >/dev/null 2>&1 || true \
    && rm -f /bin/bash /bin/dash /bin/sh /usr/bin/sh /bin/rbash /usr/bin/rbash
USER 0:0
ENTRYPOINT ["python3", "-m", "zap_active_admission"]
