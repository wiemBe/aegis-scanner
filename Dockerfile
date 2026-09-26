FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY scripts ./scripts
ARG INSTALL_DEV=false
RUN if [ "$INSTALL_DEV" = "true" ]; then pip install --no-cache-dir '.[dev]'; else pip install --no-cache-dir .; fi

# Non-root runtime (WP2 / G-ROOT-1). A dedicated unprivileged system user/group with a fixed numeric
# UID/GID runs both the control-plane and lab-api services. No sudo, no extra capabilities, no Docker
# socket, no privileged mode. The application code under /app stays root-owned and read-only to this
# user; the only runtime-writable path is /data (the aegis-data named volume), so
# ScanStore.initialize() can create and open /data/aegis.db while the container root filesystem stays
# read_only. A fresh named volume inherits /data's ownership/mode from the image, so uid 10001 owns
# it. /tmp is provided by the compose tmpfs. Keep this the final instruction that touches ownership.
RUN groupadd --system --gid 10001 aegis \
    && useradd --system --uid 10001 --gid 10001 --no-create-home \
        --home-dir /nonexistent --shell /usr/sbin/nologin aegis \
    && mkdir -p /data \
    && chown 10001:10001 /data \
    && chmod 0700 /data
USER 10001:10001

# --no-access-log: suppress Uvicorn's raw access log (can leak paths/query strings); the app emits a
# bounded, secret-free structured request log instead (WP3 / G-OBS-1). Compose overrides this command.
CMD ["uvicorn", "aegis.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--timeout-graceful-shutdown", "12"]
