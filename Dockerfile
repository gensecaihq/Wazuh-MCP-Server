# syntax=docker/dockerfile:1.7
# Wazuh MCP Server - Production Docker Image
# Multi-stage build for minimal production image with latest security practices

# Build stage
FROM python:3.12-slim as builder

# Set build arguments with proper defaults
ARG BUILD_DATE
ARG VERSION=v2.0.0
ARG BUILD_ARCH=amd64
ARG DEBIAN_FRONTEND=noninteractive

# Add labels
LABEL maintainer="Wazuh MCP Server Team"
LABEL version="${VERSION}"
LABEL description="FastMCP-powered Wazuh SIEM integration server with dual transport support"
LABEL build-date="${BUILD_DATE}"

# Install system dependencies with security updates and package verification
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        gcc=4:12.2.0-3ubuntu1 \
        libc6-dev=2.37-0ubuntu2.2 \
        build-essential=12.9ubuntu3 \
    && apt-get autoremove -y \
    && apt-get autoclean

# Set working directory
WORKDIR /build

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies with security checks and caching
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --no-deps --user --upgrade pip setuptools wheel && \
    pip install --no-cache-dir --user --require-hashes --only-binary=all -r requirements.txt || \
    pip install --no-cache-dir --user -r requirements.txt

# Production stage with distroless approach
FROM python:3.12-slim as production

# Install minimal runtime dependencies with security updates
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        curl=7.88.1-10ubuntu0.6 \
        ca-certificates=20230311ubuntu0.22.04.1 \
        tini=0.19.0-1 \
    && apt-get autoremove -y \
    && apt-get autoclean \
    && update-ca-certificates

# Create non-root user with specific UID/GID for security
RUN groupadd -r -g 1000 wazuh && \
    useradd -r -u 1000 -g wazuh -d /app -s /sbin/nologin -c "Wazuh MCP Server" wazuh

# Set working directory and create necessary directories
WORKDIR /app
RUN mkdir -p /app/logs /app/config /app/tmp && \
    chmod 755 /app /app/logs /app/config /app/tmp

# Copy Python packages from builder with proper ownership
COPY --from=builder --chown=wazuh:wazuh /root/.local /home/wazuh/.local

# Copy application code with proper ownership and permissions
COPY --chown=wazuh:wazuh src/ ./src/
COPY --chown=wazuh:wazuh --chmod=755 wazuh-mcp-server ./
COPY --chown=wazuh:wazuh validate-production.py ./
COPY --chown=wazuh:wazuh .env.production ./

# Copy Docker-specific files with proper permissions
COPY --chown=wazuh:wazuh --chmod=755 docker/entrypoint.sh ./
COPY --chown=wazuh:wazuh docker/.env.docker ./.env

# Switch to non-root user
USER wazuh

# Add local Python packages to PATH
ENV PATH="/home/wazuh/.local/bin:${PATH}"
ENV PYTHONPATH="/app/src:${PYTHONPATH}"

# Set environment variables
ENV MCP_TRANSPORT=stdio
ENV MCP_HOST=0.0.0.0  
ENV MCP_PORT=3000
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Advanced health check with proper timeout and retries
HEALTHCHECK --interval=30s --timeout=15s --start-period=60s --retries=3 \
    CMD python3 -c "import sys; sys.path.insert(0, '/app/src'); from wazuh_mcp_server.config import WazuhConfig; WazuhConfig.from_env()" || exit 1

# Expose port for HTTP transport
EXPOSE 3000

# Use tini as init system and set entrypoint
ENTRYPOINT ["tini", "--", "./entrypoint.sh"]

# Default command with better defaults
CMD ["--stdio"]