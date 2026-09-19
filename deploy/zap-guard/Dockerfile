# syntax=docker/dockerfile:1.7
#
# Aegis ZAP scope guard (Phase 1.3): a standard-library-only forward proxy + counter that is the
# ONLY network path between the zap-runner and the synthetic target.
#
# Build (from the repository root):
#   docker build -f deploy/zap-guard/Dockerfile -t aegis-zap-scope-guard:1.3.0 .

ARG PYTHON_IMAGE=python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9
FROM ${PYTHON_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/aegis-zap-guard/lib
COPY src/zap_guard /opt/aegis-zap-guard/lib/zap_guard
# Root-owned read-only code; unprivileged runtime user; no package manager and no shell remain.
# This MUST remain the final RUN instruction (later RUN steps would need /bin/sh).
RUN find /opt/aegis-zap-guard -type d -name __pycache__ -prune -exec rm -rf {} + \
    && chown -R root:root /opt/aegis-zap-guard \
    && chmod -R a-w /opt/aegis-zap-guard \
    && useradd --uid 10003 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin guard \
    && pip uninstall -y -q pip setuptools wheel >/dev/null 2>&1 || true \
    && rm -f /bin/bash /bin/dash /bin/sh /usr/bin/sh /bin/rbash /usr/bin/rbash
USER 10003:10003
ENTRYPOINT ["python", "-m", "zap_guard"]
