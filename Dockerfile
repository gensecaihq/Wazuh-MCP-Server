# syntax=docker/dockerfile:1.7
# Wazuh MCP Server - Production Docker Image
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

# Use tini and entrypoint
ENTRYPOINT ["tini", "--", "./entrypoint.sh"]
CMD ["--stdio"]