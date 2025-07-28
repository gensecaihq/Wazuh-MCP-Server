# syntax=docker/dockerfile:1.7
# Wazuh MCP Server - Production Docker Image

# Build arguments
ARG BUILD_DATE
ARG VERSION=2.0.0

FROM python:3.12-slim as builder

# Build stage - install dependencies
WORKDIR /build
COPY requirements.txt .
RUN pip install --user -r requirements.txt

# Production stage
FROM python:3.12-slim

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl tini && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 wazuh

# Set working directory
WORKDIR /app

# Copy Python packages and application code
COPY --from=builder /root/.local /home/wazuh/.local
COPY --chown=wazuh:wazuh src/ ./src/
COPY --chown=wazuh:wazuh --chmod=755 wazuh-mcp-server ./
COPY --chown=wazuh:wazuh --chmod=755 docker/entrypoint.sh ./
COPY --chown=wazuh:wazuh --chmod=755 validate-production.py ./
COPY --chown=wazuh:wazuh --chmod=755 test-functionality.py ./
COPY --chown=wazuh:wazuh config/wazuh.env.example ./config/
COPY --chown=wazuh:wazuh docker/.env.docker ./.env

# Switch to non-root user
USER wazuh

# Set environment
ENV PATH="/home/wazuh/.local/bin:${PATH}"
ENV PYTHONPATH="/app/src:${PYTHONPATH}"
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python3 -c "from src.wazuh_mcp_server.config import WazuhConfig; WazuhConfig.from_env()" || exit 1

# Expose port
EXPOSE 3000

# Add metadata labels
LABEL org.opencontainers.image.title="Wazuh MCP Server"
LABEL org.opencontainers.image.description="Production-grade FastMCP server for Wazuh SIEM integration"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.source="https://github.com/gensecaihq/Wazuh-MCP-Server"
LABEL org.opencontainers.image.licenses="MIT"
LABEL maintainer="GenSec AI HQ"

# Use tini and entrypoint - default to HTTP mode for web access
ENTRYPOINT ["tini", "--", "./entrypoint.sh"]
CMD ["--http"]