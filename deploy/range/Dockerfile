FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

RUN groupadd --gid 65532 range && useradd --uid 65532 --gid 65532 --no-create-home range
COPY pyproject.toml README.md ./
COPY src ./src
COPY scripts ./scripts
RUN pip install --no-cache-dir .

USER 65532:65532
CMD ["python", "-m", "aegis_range.ingress"]
