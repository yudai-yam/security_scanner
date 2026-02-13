# Multi-stage build for SecAudit
FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml .
COPY secaudit/ secaudit/

RUN pip install --no-cache-dir --prefix=/install .

# Runtime stage
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash secaudit

COPY --from=builder /install /usr/local

WORKDIR /workspace
USER secaudit

ENTRYPOINT ["secaudit"]
CMD ["--help"]
