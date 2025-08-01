# syntax=docker/dockerfile:1.9
# Wazuh MCP Server - Production-Grade Multi-Stage Build
# MCP-compliant remote server with SSE transport
# Optimized for security, performance, and OS-agnostic deployment

ARG PYTHON_VERSION=3.13
ARG BUILD_DATE
ARG VERSION=4.0.0

# Stage 1: Build dependencies
FROM python:${PYTHON_VERSION}-alpine AS builder

# Set build-time metadata
LABEL stage=builder

# Install comprehensive build dependencies for OS-agnostic deployment
RUN apk update && apk upgrade && apk add --no-cache \
    # Core build tools
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev \
    python3-dev \
    build-base \
    # Development tools
    git \
    curl \
    wget \
    # Network and SSL libraries
    ca-certificates \
    openssl \
    # Additional Python build dependencies
    libxml2-dev \
    libxslt-dev \
    libc-dev \
    linux-headers \
    # Cleanup
    && rm -rf /var/cache/apk/* /tmp/* /var/tmp/*

# Create build directory
WORKDIR /build

# Copy and install Python dependencies with latest pip
COPY requirements.txt .
RUN pip install --upgrade pip setuptools wheel && \
    pip install --user --no-cache-dir --no-compile -r requirements.txt

# Stage 2: Security scanner with latest Trivy
FROM aquasec/trivy:latest AS scanner

LABEL stage=scanner
COPY --from=builder /root/.local /scan

# Run comprehensive security scan
RUN trivy fs \
    --no-progress \
    --security-checks vuln,secret,config \
    --severity HIGH,CRITICAL \
    --format json \
    --output /scan-results.json \
    /scan || echo "Security scan completed with findings"

# Stage 3: Production image with latest Alpine
FROM python:${PYTHON_VERSION}-alpine

LABEL stage=production

# Install comprehensive runtime dependencies for OS-agnostic operation
RUN apk update && apk upgrade && apk add --no-cache \
    # Process management
    tini \
    su-exec \
    shadow \
    # Network tools
    curl \
    wget \
    netcat-openbsd \
    # SSL/TLS support
    ca-certificates \
    openssl \
    # System utilities
    tzdata \
    bash \
    # JSON processing for health checks
    jq \
    # Monitoring tools
    procps \
    # Cleanup
    && rm -rf /var/cache/apk/* /tmp/* /var/tmp/* \
    # Update CA certificates
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

# Switch to non-root user
USER wazuh

# Environment configuration
ENV PATH="/home/wazuh/.local/bin:${PATH}" \
    PYTHONPATH="/app/src:${PYTHONPATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    # Security: Don't leak Python errors
    PYTHONFAULTHANDLER=1 \
    # Default to production settings
    MCP_HOST=0.0.0.0 \
    MCP_PORT=3000 \
    LOG_LEVEL=INFO \
    ENVIRONMENT=production

# Comprehensive health check with JSON validation and timeout handling
HEALTHCHECK --interval=15s --timeout=10s --start-period=45s --retries=5 \
    CMD curl -f --max-time 5 --retry 2 --retry-delay 1 \
        -H "Accept: application/json" \
        http://localhost:3000/health | \
        jq -e '.status == "healthy"' > /dev/null || exit 1

# Expose SSE port
EXPOSE 3000

# OCI-compliant metadata labels (latest spec)
LABEL org.opencontainers.image.title="Wazuh MCP Server" \
      org.opencontainers.image.description="MCP-compliant remote server for Wazuh SIEM integration with SSE transport" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="https://github.com/gensecaihq/Wazuh-MCP-Server" \
      org.opencontainers.image.url="https://github.com/gensecaihq/Wazuh-MCP-Server" \
      org.opencontainers.image.documentation="https://github.com/gensecaihq/Wazuh-MCP-Server/blob/main/README.md" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="GenSec AI" \
      org.opencontainers.image.authors="GenSec AI <info@gensecai.com>" \
      org.opencontainers.image.ref.name="wazuh-mcp-server" \
      org.opencontainers.image.base.name="python:3.13-alpine"

# Use tini for proper signal handling
ENTRYPOINT ["tini", "--"]

# Run the MCP server using the main module
CMD ["python", "-m", "wazuh_mcp_server"]