# syntax=docker/dockerfile:1.7
#
# Aegis isolated nuclei-runner (Phase 1.2).
#
# Supply chain:
#   - base image pinned by digest (python:3.12-slim);
#   - Nuclei v3.11.1 official release archives fetched by BuildKit with --checksum (the SHA-256
#     values published in nuclei_3.11.1_checksums.txt), then the extracted binary is verified
#     against the binary_sha256 pin in src/aegis_nuclei/manifest.json;
#   - Python dependencies installed from a hash-locked file (--require-hashes, wheels only);
#   - the admitted template set is copied from the reviewed, checked-in tree (byte-identical to
#     projectdiscovery/nuclei-templates v10.4.8). Nothing is downloaded at runtime.
#
# Build (from the repository root):
#   docker build -f deploy/nuclei-runner/Dockerfile -t aegis-nuclei-runner:1.2.0 .

ARG PYTHON_IMAGE=python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9

FROM ${PYTHON_IMAGE} AS fetch
ARG TARGETARCH
ADD --checksum=sha256:8044e3d9768ba0a744b2872c1a87e813006f013da97ca9f50f7661a4203bec07 \
    https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_arm64.zip \
    /fetch/linux_arm64.zip
ADD --checksum=sha256:ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6 \
    https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_amd64.zip \
    /fetch/linux_amd64.zip
COPY src/aegis_nuclei/manifest.json /fetch/manifest.json
RUN python - <<'PY'
import hashlib, json, os, zipfile
arch = {"arm64": "linux_arm64", "amd64": "linux_amd64"}[os.environ["TARGETARCH"]]
pin = json.load(open("/fetch/manifest.json"))["engine"]["artifacts"][arch]
archive = f"/fetch/{arch}.zip"
assert hashlib.sha256(open(archive, "rb").read()).hexdigest() == pin["asset_sha256"], "asset pin"
os.makedirs("/out", exist_ok=True)
with zipfile.ZipFile(archive) as zf:
    data = zf.read("nuclei")
assert hashlib.sha256(data).hexdigest() == pin["binary_sha256"], "binary pin"
with open("/out/nuclei", "wb") as handle:
    handle.write(data)
os.chmod("/out/nuclei", 0o555)
print("nuclei", arch, pin["binary_sha256"])
PY

FROM ${PYTHON_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/aegis-nuclei/lib
COPY deploy/nuclei-runner/requirements.lock /tmp/requirements.lock
RUN pip install --no-cache-dir --no-deps --only-binary=:all: --require-hashes \
        -r /tmp/requirements.lock \
    && rm /tmp/requirements.lock
COPY --from=fetch /out/nuclei /opt/aegis-nuclei/bin/nuclei
COPY deploy/nuclei-runner/templates /opt/aegis-nuclei/templates
COPY src/aegis_nuclei /opt/aegis-nuclei/lib/aegis_nuclei
COPY src/nuclei_runner /opt/aegis-nuclei/lib/nuclei_runner
# Root-owned, read-only code/binary/templates; an unprivileged runtime user; then remove the package
# manager and every shell so the running container has no interactive or scripted shell at all.
# This MUST remain the final RUN instruction (later RUN steps would need /bin/sh).
RUN find /opt/aegis-nuclei -type d -name __pycache__ -prune -exec rm -rf {} + \
    && chown -R root:root /opt/aegis-nuclei \
    && chmod -R a-w,go-w /opt/aegis-nuclei \
    && useradd --uid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin runner \
    && pip uninstall -y -q pip setuptools wheel >/dev/null 2>&1 || true \
    && rm -f /bin/bash /bin/dash /bin/sh /usr/bin/sh /bin/rbash /usr/bin/rbash
USER 10001:10001
WORKDIR /work
ENTRYPOINT ["python", "-m", "nuclei_runner"]
