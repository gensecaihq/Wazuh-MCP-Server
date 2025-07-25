# syntax=docker/dockerfile:1
# Wazuh MCP Server - Production Docker Image
# Multi-stage build for minimal production image

# Build stage
FROM python:3.11-slim as builder

# Set build arguments
ARG BUILD_DATE
ARG VERSION=v3-fastmcp-check

# Add labels
LABEL maintainer="Wazuh MCP Server Team"
LABEL version="${VERSION}"
LABEL description="FastMCP-powered Wazuh SIEM integration server with dual transport support"
LABEL build-date="${BUILD_DATE}"

# Install system dependencies for building
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN groupadd -r wazuh && useradd -r -g wazuh -d /app -s /bin/bash wazuh

# Set working directory
WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /root/.local /home/wazuh/.local

# Copy application code
COPY src/ ./src/
COPY wazuh-mcp-server ./
COPY validate-production.py ./
COPY .env.production ./

# Copy Docker-specific files
COPY docker/entrypoint.sh ./
COPY docker/.env.docker ./.env

# Set executable permissions
RUN chmod +x wazuh-mcp-server entrypoint.sh

# Change ownership to non-root user
RUN chown -R wazuh:wazuh /app

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

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import sys; sys.path.insert(0, '/app/src'); from wazuh_mcp_server.config import WazuhConfig; WazuhConfig.from_env()" || exit 1

# Expose port for HTTP transport
EXPOSE 3000

# Set entrypoint
ENTRYPOINT ["./entrypoint.sh"]

# Default command (can be overridden)
CMD ["--stdio"]