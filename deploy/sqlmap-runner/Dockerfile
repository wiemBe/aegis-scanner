# Phase 2.8 containerized SQLMap worker.
#
# Provenance (recorded in src/aegis/container_acceptance/images.py):
#   * base image  : python:3.12-slim pinned by immutable RepoDigest (never a mutable tag at build)
#   * sqlmap      : sqlmap 1.10.9 pure-python wheel, acquired host-side through the audited HTTPS
#                   proxy (`pip download sqlmap==1.10.9`), sha256 verified, then baked in with
#                   `--no-index` so the image BUILD performs zero network egress.
#
# The worker runs unprivileged, on a read-only root filesystem, with a bounded tmpfs for the only
# writable state (sqlmap's session/output). It has no shell entrypoint: the entrypoint is the sqlmap
# binary itself, so the controller supplies only a typed, rendered argv (never a shell string).
FROM python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

RUN groupadd --gid 65532 worker && useradd --uid 65532 --gid 65532 --no-create-home worker

# Baked, offline install of the verified wheel. sqlmap vendors its own dependencies, so --no-deps
# --no-index means no package index is contacted during the image build.
COPY sqlmap-1.10.9-py2.py3-none-any.whl /tmp/sqlmap-1.10.9-py2.py3-none-any.whl
RUN pip install --no-cache-dir --no-index --no-deps /tmp/sqlmap-1.10.9-py2.py3-none-any.whl \
    && rm -f /tmp/sqlmap-1.10.9-py2.py3-none-any.whl \
    && sqlmap --version

USER 65532:65532
WORKDIR /tmp
ENTRYPOINT ["sqlmap"]
