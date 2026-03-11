# ---------------------------------------------------------------
# NetScaler SSL Automation — Dockerfile
# Multi-stage: builder installs deps, runtime is lean
# ---------------------------------------------------------------

# ---- Stage 1: Builder ----
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build deps for cryptography library
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install --no-cache-dir --prefix=/install -r requirements.txt


# ---- Stage 2: Runtime ----
FROM python:3.11-slim AS runtime

WORKDIR /app

# Runtime SSL libs only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy source
COPY src/        ./src/
COPY config/     ./config/
COPY tests/      ./tests/
COPY scripts/    ./scripts/

# Create state directory
RUN mkdir -p /app/state

# Non-root user for security
RUN useradd -m -u 1001 sslauto && chown -R sslauto /app
USER sslauto

# Default: show help
ENTRYPOINT ["python"]
CMD ["src/orchestrator.py", "--help"]
