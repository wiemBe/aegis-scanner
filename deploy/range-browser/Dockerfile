FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

RUN apt-get update \
    && apt-get install --no-install-recommends --yes ca-certificates chromium \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 range \
    && useradd --uid 65532 --gid 65532 --no-create-home range
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

USER 65532:65532
CMD ["uvicorn", "aegis_range.shop_browser:app", "--host", "0.0.0.0", "--port", "8650"]
