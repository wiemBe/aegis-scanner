FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
ARG INSTALL_DEV=false
RUN if [ "$INSTALL_DEV" = "true" ]; then pip install --no-cache-dir '.[dev]'; else pip install --no-cache-dir .; fi

CMD ["uvicorn", "aegis.main:app", "--host", "0.0.0.0", "--port", "8000"]
