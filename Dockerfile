# syntax=docker/dockerfile:1.9
# Wazuh MCP Server - Production-Grade Multi-Stage Build
# MCP-compliant remote server with SSE transport
# Optimized for security, performance, and OS-agnostic deployment

ARG PYTHON_VERSION=3.13
ARG BUILD_DATE
ARG VERSION=4.3.0

# Stage 1: Build dependencies
FROM python:${PYTHON_VERSION}-alpine AS builder

# Set build-time metadata
LABEL stage=builder

# Install build dependencies (minimal set for compiling Python C extensions)
RUN apk update && apk upgrade && apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    python3-dev \
    build-base \
    ca-certificates \
    && rm -rf /var/cache/apk/* /tmp/* /var/tmp/*

# Create build directory
WORKDIR /build

# Copy and install Python dependencies with latest pip
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --user --no-cache-dir --no-compile -r requirements.txt

# NOTE: image vulnerability scanning is done on the BUILT image in CI
# (docker-publish.yml runs `trivy image` and fails on HIGH/CRITICAL), not as a
# Dockerfile stage. The previous in-Dockerfile `scanner` stage was never part of
# the production target's build graph (and defaulted to exit-code 0), so it gave a
# false sense of scanning while never actually gating anything.

# Stage 2: Production image with latest Alpine
FROM python:${PYTHON_VERSION}-alpine AS production

LABEL stage=production

# Install minimal runtime dependencies
RUN apk update && apk upgrade && apk add --no-cache \
    tini \
    curl \
    ca-certificates \
    openssl \
    tzdata \
    jq \
    && rm -rf /var/cache/apk/* /tmp/* /var/tmp/* \
    && update-ca-certificates

# Security: Create non-root user with proper shell
RUN addgroup -g 1000 -S wazuh && \
    adduser -u 1000 -S wazuh -G wazuh -s /bin/sh

# Set up directory structure
WORKDIR /app
RUN mkdir -p /app/logs /app/data && \
    chown -R wazuh:wazuh /app

# Copy Python packages from builder
COPY --from=builder --chown=wazuh:wazuh /root/.local /home/wazuh/.local

# Copy application code
COPY --chown=wazuh:wazuh src/ ./src/
COPY --chown=wazuh:wazuh .env.example .env.example

# Security: Set proper permissions
RUN find /app -type d -exec chmod 755 {} \; && \
    find /app -type f -exec chmod 644 {} \; && \
    chmod 600 .env.example && \
    chmod +x /app/src/wazuh_mcp_server/*.py

# Switch to non-root user (numeric uid:gid so the host can resolve it)
USER 1000:1000

# Environment configuration
ENV PATH="/home/wazuh/.local/bin:${PATH}" \
    PYTHONPATH="/app/src:${PYTHONPATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    # Enable Python fault handler for crash diagnostics
    PYTHONFAULTHANDLER=1 \
    # Default to production settings
    MCP_HOST=0.0.0.0 \
    MCP_PORT=3000 \
    LOG_LEVEL=INFO \
    ENVIRONMENT=production

# Comprehensive health check with JSON validation and timeout handling
HEALTHCHECK --interval=15s --timeout=10s --start-period=45s --retries=5 \
    CMD ["sh", "-c", "curl -f --max-time 5 --retry 2 --retry-delay 1 -H 'Accept: application/json' http://localhost:3000/health | jq -e '.status == \"healthy\"' > /dev/null || exit 1"]

# Expose SSE port
EXPOSE 3000

# OCI-compliant metadata labels (latest spec)
LABEL org.opencontainers.image.title="Wazuh MCP Remote Server" \
      org.opencontainers.image.description="MCP-compliant remote server for Wazuh SIEM integration with SSE transport (main branch)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="https://github.com/gensecaihq/Wazuh-MCP-Server/tree/main" \
      org.opencontainers.image.url="https://github.com/gensecaihq/Wazuh-MCP-Server/tree/main" \
      org.opencontainers.image.documentation="https://github.com/gensecaihq/Wazuh-MCP-Server/blob/main/README.md" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="GenSec AI" \
      org.opencontainers.image.authors="GenSec AI <info@gensecai.com>" \
      org.opencontainers.image.ref.name="wazuh-main-server" \
      org.opencontainers.image.base.name="python:3.13-alpine"

# Use tini for proper signal handling
ENTRYPOINT ["tini", "--"]

# Run the MCP server using the main module
CMD ["python", "-m", "wazuh_mcp_server"]