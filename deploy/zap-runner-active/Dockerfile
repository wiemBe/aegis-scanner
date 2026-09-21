# syntax=docker/dockerfile:1.7
#
# Aegis isolated active zap-runner (Phase 1.5).
#
# Supply chain (identical base image and pins to Phase 1.3; the ONLY difference is the admitted
# add-on set):
#   - base image pinned by the SAME multi-architecture OCI index digest as Phase 1.3
#     (zaproxy/zap-stable 2.17.0); per-architecture manifest digests are in
#     src/aegis_zap_active/manifest.json (engine block copied verbatim from the passive manifest);
#   - the build VERIFIES the ZAP jar, the per-architecture JVM files and every admitted add-on
#     against the manifest pins and fails on any mismatch;
#   - the install plugin directory is pruned to EXACTLY the eleven manifest add-ons: the eight
#     Phase 1.3 add-ons plus the release reflected-XSS active rules add-on (ascanrules-release-83)
#     and its mandatory, NEUTRALISED forced dependencies (oast, database). The also-present
#     ascanrules-release-78 and every other add-on (spiders, scripting, fuzzing, GraphQL/SOAP/
#     Postman, HUD, client, ...) is deleted;
#   - the runner's Python dependencies are installed from the same hash-locked file (wheels only);
#   - nothing is downloaded or updated at runtime (no marketplace, no add-on install/update). OAST
#     services are inert: the runner has no network route except the scope guard.
#
# Build (from the repository root):
#   docker build -f deploy/zap-runner-active/Dockerfile -t aegis-zap-active-runner:1.5.0 .

ARG ZAP_IMAGE=zaproxy/zap-stable@sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef
FROM ${ZAP_IMAGE}
ARG ZAP_IMAGE
LABEL org.opencontainers.image.title="aegis-zap-active-runner" \
      org.opencontainers.image.version="1.5.0" \
      org.opencontainers.image.base.name="${ZAP_IMAGE}"
USER root

COPY src/aegis_zap_active/manifest.json /tmp/aegis-zap-active-manifest.json
RUN python3 - <<'PY'
import hashlib, json, os, platform
manifest = json.load(open("/tmp/aegis-zap-active-manifest.json"))
arch = {"aarch64": "linux_arm64", "x86_64": "linux_amd64"}[platform.machine()]

def sha(path):
    h = hashlib.sha256()
    with open(os.path.realpath(path), "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

engine = manifest["engine"]
assert sha("/zap/" + engine["jar"]["path"]) == engine["jar"]["sha256"], "zap jar pin"
java = engine["java"]["platforms"][arch]
assert sha(java["home"] + "/bin/java") == java["java_sha256"], "java pin"
assert sha(java["home"] + "/lib/server/libjvm.so") == java["libjvm_sha256"], "libjvm pin"
assert sha(java["home"] + "/release") == java["release_sha256"], "jvm release pin"
keep = {a["file"]: a["sha256"] for a in manifest["add_ons"]}
for name in sorted(os.listdir("/zap/plugin")):
    path = "/zap/plugin/" + name
    if name in keep:
        assert sha(path) == keep[name], "add-on pin " + name
    else:
        os.remove(path)
assert sorted(os.listdir("/zap/plugin")) == sorted(keep), "plugin set"
print("verified active", arch, engine["version"], sorted(keep))
PY

RUN apt-get purge -y -q firefox-esr x11vnc xvfb openbox obconf >/dev/null \
    && rm -rf /zap/webswing /zap/zap-api-scan.py /zap/zap-baseline.py /zap/zap-full-scan.py \
              /zap/zap_common.py /zap/zap-x.sh /zap/zap-webswing.sh /zap/zap.bat \
              /home/zap/.ZAP_D /home/zap/.mozilla /home/zap/.vnc /home/zap/.xinitrc \
              /var/lib/apt/lists/* /tmp/aegis-zap-active-manifest.json \
    && dpkg-query -W -f '${Package} ${Version}\n' | sort > /opt/aegis-zap-active-package-inventory.txt

COPY deploy/zap-runner/requirements.lock /tmp/requirements.lock
RUN python3 -m pip install --no-cache-dir --no-deps --only-binary=:all: --require-hashes \
        --target /opt/aegis-zap/lib -r /tmp/requirements.lock \
    && rm /tmp/requirements.lock
COPY src/aegis_zap /opt/aegis-zap/lib/aegis_zap
COPY src/aegis_zap_active /opt/aegis-zap/lib/aegis_zap_active
COPY src/zap_runner /opt/aegis-zap/lib/zap_runner
COPY src/zap_active_runner /opt/aegis-zap/lib/zap_active_runner

# Root-owned engine, add-ons and code; unprivileged runtime user; pip and every shell removed. This
# MUST remain the final RUN instruction (later RUN steps would need /bin/sh).
RUN find /opt/aegis-zap -type d -name __pycache__ -prune -exec rm -rf {} + \
    && rm -f /opt/aegis-zap/lib/aegis_zap_active/countersign_cli.py \
    && chown -R root:root /zap /opt/aegis-zap /opt/aegis-zap-active-package-inventory.txt \
    && chmod -R go-w /zap /opt/aegis-zap \
    && useradd --uid 10002 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin zaprunner \
    && rm -rf /usr/local/lib/python3.11/dist-packages/pip /usr/local/lib/python3.11/dist-packages/pip-* \
              /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.11 \
    && rm -f /bin/bash /bin/dash /bin/sh /usr/bin/sh /usr/bin/bash /usr/bin/dash /bin/rbash /usr/bin/rbash

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/aegis-zap/lib \
    HOME=/nonexistent
USER 10002:10002
WORKDIR /work
ENTRYPOINT ["python3", "-m", "zap_active_runner"]
