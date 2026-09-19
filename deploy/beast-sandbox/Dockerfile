# syntax=docker/dockerfile:1.7
# BEAST_ADVERSARY_SANDBOX_V1. Build-time network only; runtime Compose networks are internal.
ARG PYTHON_IMAGE=python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9

FROM ${PYTHON_IMAGE} AS nuclei
ARG TARGETARCH
ADD --checksum=sha256:8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07 \
    https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_arm64.zip \
    /fetch/linux_arm64.zip
ADD --checksum=sha256:ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6 \
    https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_amd64.zip \
    /fetch/linux_amd64.zip
RUN python - <<'PY'
import os, zipfile
arch = {"arm64": "linux_arm64", "amd64": "linux_amd64"}[os.environ["TARGETARCH"]]
with zipfile.ZipFile(f"/fetch/{arch}.zip") as source:
    source.extract("nuclei", "/out")
os.chmod("/out/nuclei", 0o555)
PY

FROM ${PYTHON_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       bash ca-certificates coreutils curl ffuf findutils gawk grep httpie iproute2 jq \
       nmap openssl procps sed sqlmap \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 beast-command \
    && useradd --uid 65532 --gid 65532 --no-create-home --home-dir /workspace \
       --shell /bin/bash beast-command \
    && mkdir -p /workspace \
    && chown root:root /workspace \
    && chmod 0700 /workspace
COPY --from=nuclei /out/nuclei /usr/local/bin/nuclei
WORKDIR /opt/aegis
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . \
    && find /opt/aegis -type d -name __pycache__ -prune -exec rm -rf {} + \
    && chown -R root:root /opt/aegis \
    && chmod -R a-w /opt/aegis
EXPOSE 8094
# uvloop intentionally disabled: its libuv spawn path cannot combine Docker's no-new-privileges
# boundary with the supervisor's per-command uid/gid drop. CPython's asyncio subprocess path can.
ENTRYPOINT ["uvicorn", "beast_sandbox.server:app", "--host", "0.0.0.0", "--port", "8094", "--loop", "asyncio"]
