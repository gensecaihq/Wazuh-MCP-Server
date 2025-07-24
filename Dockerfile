# Production-grade multi-stage Dockerfile for Wazuh MCP Server v3.0.0
# =======================================================================
# Build for linux/amd64, linux/arm64, and windows/amd64

# Build stage - using latest Python 3.12 on Debian 12 (bookworm)
FROM python:3.12-slim-bookworm as builder

# Set build arguments
ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG TARGETARCH

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    cargo \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Create build user
RUN useradd --create-home --shell /bin/bash builder
USER builder
WORKDIR /home/builder

# Copy requirements and install dependencies
COPY --chown=builder:builder requirements-prod.txt .
RUN python -m pip install --no-cache-dir --user -r requirements-prod.txt

# Production stage - using latest Python 3.12 on Debian 12 (bookworm)
FROM python:3.12-slim-bookworm as production

# Set metadata
LABEL maintainer="Wazuh MCP Server Project <info@wazuh-mcp-server.org>"
LABEL version="3.0.0"
LABEL description="Production-grade Remote MCP Server for Wazuh"
LABEL org.opencontainers.image.title="Wazuh MCP Server"
LABEL org.opencontainers.image.description="Remote Model Context Protocol server for Wazuh security platform"
LABEL org.opencontainers.image.version="3.0.0"
LABEL org.opencontainers.image.vendor="Wazuh MCP Server Project"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/wazuh-mcp-server/wazuh-mcp-server"

# Install minimal runtime dependencies for production
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    tini \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create application user and group
RUN groupadd --gid 1000 wazuh-mcp && \
    useradd --uid 1000 --gid 1000 --create-home --shell /bin/bash wazuh-mcp

# Set up application directories
WORKDIR /app
RUN mkdir -p /app/logs /app/config /app/data && \
    chown -R wazuh-mcp:wazuh-mcp /app

# Copy Python dependencies from builder
COPY --from=builder --chown=wazuh-mcp:wazuh-mcp /home/builder/.local /home/wazuh-mcp/.local

# Copy application code
COPY --chown=wazuh-mcp:wazuh-mcp src/ /app/src/
COPY --chown=wazuh-mcp:wazuh-mcp pyproject.toml /app/
COPY --chown=wazuh-mcp:wazuh-mcp README.md /app/
COPY --chown=wazuh-mcp:wazuh-mcp LICENSE /app/

# Copy Docker-specific scripts and embedded configurations
COPY --chown=wazuh-mcp:wazuh-mcp docker/ /app/docker/
COPY --chown=wazuh-mcp:wazuh-mcp config/ /app/embedded-config/
RUN chmod +x /app/docker/*.sh && \
    mkdir -p /app/templates && \
    chown -R wazuh-mcp:wazuh-mcp /app/embedded-config /app/templates

# Install application in development mode
USER wazuh-mcp
ENV PATH="/home/wazuh-mcp/.local/bin:$PATH"
RUN pip install --no-deps -e .

# Set environment variables
ENV PYTHONPATH="/app/src:$PYTHONPATH"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PIP_NO_CACHE_DIR=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

# Production configuration - minimal and secure
ENV MCP_SERVER_HOST=0.0.0.0
ENV MCP_SERVER_PORT=8443
ENV MCP_SERVER_MODE=auto
ENV MCP_TRANSPORT=sse
ENV WAZUH_API_VERIFY_SSL=true
ENV LOG_LEVEL=WARNING
ENV ENABLE_METRICS=false
ENV REDIS_ENABLED=false
# Self-contained mode
ENV SELF_CONTAINED=true
ENV AUTO_GENERATE_CONFIG=true
ENV PRESERVE_V2_COMPATIBILITY=true

# Security settings
ENV UMASK=0027
USER wazuh-mcp

# Expose only MCP port
EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f -k https://localhost:8443/health || exit 1

# Volume mounts
VOLUME ["/app/config", "/app/logs", "/app/data"]

# Use tini as init system for proper signal handling
ENTRYPOINT ["/usr/bin/tini", "--"]

# Default command
CMD ["/app/docker/entrypoint.sh"]