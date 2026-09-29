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

# Phase 1.4-B web-recon tools. Pinned by version + SHA-256 in deploy/beast-sandbox/tools.lock.json
# (kept in sync by tests/test_beast_toolbox.py). Build-time network only; runtime networks are
# internal. Raw binaries (akca) are ADDed directly; ProjectDiscovery ships zips that ADD does not
# auto-extract, so they are unzipped explicitly like the nuclei stage above.
FROM ${PYTHON_IMAGE} AS webtools
ARG TARGETARCH
# akca v0.2.4 — Apache-2.0 (github:akha-security/akca)
ADD --checksum=sha256:265b1cb00a8ed7b8d5cfd4adcccd2e6929afb64f5f2bd2503310d6a53f230017 \
    https://github.com/akha-security/akca/releases/download/v0.2.4/akca-linux-amd64 /fetch/akca-amd64
ADD --checksum=sha256:401f4561bbaf7a7a88c3e5e1543cbab049a40ee1358e873dc4dd9f451626446a \
    https://github.com/akha-security/akca/releases/download/v0.2.4/akca-linux-arm64 /fetch/akca-arm64
# katana v1.7.0 — MIT (github:projectdiscovery/katana)
ADD --checksum=sha256:fe1142d92f418549338ea46d67a472124878482e225d279e9a42700c75d76a4d \
    https://github.com/projectdiscovery/katana/releases/download/v1.7.0/katana_1.7.0_linux_amd64.zip /fetch/katana-amd64.zip
ADD --checksum=sha256:9a6885fe9fda850129b110e0f079d42529b0693dd81b59c316f04084935300f0 \
    https://github.com/projectdiscovery/katana/releases/download/v1.7.0/katana_1.7.0_linux_arm64.zip /fetch/katana-arm64.zip
# httpx v1.12.0 — MIT (github:projectdiscovery/httpx)
ADD --checksum=sha256:9d8439e8b6c9aa7d1e2314817a392e00d5178da3af5652f7475f88868f418f76 \
    https://github.com/projectdiscovery/httpx/releases/download/v1.12.0/httpx_1.12.0_linux_amd64.zip /fetch/httpx-amd64.zip
ADD --checksum=sha256:fd7b123c1dfbc3d69f19f524e4eebcd6ec06b9a6cbd56813c76f11645197331e \
    https://github.com/projectdiscovery/httpx/releases/download/v1.12.0/httpx_1.12.0_linux_arm64.zip /fetch/httpx-arm64.zip
RUN python - <<'PY'
import os, shutil, zipfile
arch = {"arm64": "arm64", "amd64": "amd64"}[os.environ["TARGETARCH"]]
os.makedirs("/out", exist_ok=True)
shutil.copy(f"/fetch/akca-{arch}", "/out/akca")
for name in ("katana", "httpx"):
    with zipfile.ZipFile(f"/fetch/{name}-{arch}.zip") as source:
        source.extract(name, "/out")
for name in ("akca", "katana", "httpx"):
    os.chmod(f"/out/{name}", 0o555)
PY

FROM ${PYTHON_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       bash ca-certificates coreutils curl ffuf findutils gawk gobuster grep httpie iproute2 jq \
       nmap openssl procps sed sqlmap \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 beast-command \
    && useradd --uid 65532 --gid 65532 --no-create-home --home-dir /workspace \
       --shell /bin/bash beast-command \
    && mkdir -p /workspace \
    && chown root:root /workspace \
    && chmod 0700 /workspace
WORKDIR /opt/aegis
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir . \
    && find /opt/aegis -type d -name __pycache__ -prune -exec rm -rf {} + \
    && chown -R root:root /opt/aegis \
    && chmod -R a-w /opt/aegis
# Install pinned standalone binaries AFTER pip. The Python httpx dependency also exposes a console
# script named `httpx`; copying ProjectDiscovery's pinned binary last prevents that unrelated CLI
# from silently shadowing the assessment prober.
COPY --from=nuclei /out/nuclei /usr/local/bin/nuclei
COPY --from=webtools /out/akca /usr/local/bin/akca
COPY --from=webtools /out/katana /usr/local/bin/katana
COPY --from=webtools /out/httpx /usr/local/bin/httpx
EXPOSE 8094
# uvloop intentionally disabled: its libuv spawn path cannot combine Docker's no-new-privileges
# boundary with the supervisor's per-command uid/gid drop. CPython's asyncio subprocess path can.
ENTRYPOINT ["uvicorn", "beast_sandbox.server:app", "--host", "0.0.0.0", "--port", "8094", "--loop", "asyncio"]
