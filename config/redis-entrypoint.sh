#!/bin/bash
# Self-contained Redis entrypoint for Wazuh MCP Server v3.0.0
# ===========================================================
# Embedded Redis configuration with self-contained defaults

set -euo pipefail

# Default Redis password if not provided
REDIS_PASSWORD=${REDIS_PASSWORD:-redis-secret}

# Generate Redis configuration if template doesn't exist
if [[ -f "/usr/local/etc/redis/redis.conf.template" ]]; then
    # Use existing template
    cp /usr/local/etc/redis/redis.conf.template /tmp/redis.conf
    sed -i "s/\${REDIS_PASSWORD}/$REDIS_PASSWORD/g" /tmp/redis.conf
else
    # Generate self-contained configuration
    cat > /tmp/redis.conf << EOF
# Redis configuration for Wazuh MCP Server v3.0.0
bind 127.0.0.1
port 6379
maxmemory 256mb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000

# Security
requirepass $REDIS_PASSWORD
protected-mode yes

# Logging
loglevel notice
logfile ""

# Persistence
dir /data
dbfilename dump.rdb
appendonly yes
appendfilename "appendonly.aof"

# Performance
tcp-keepalive 300
timeout 0
tcp-backlog 511
databases 16
EOF
fi

# Ensure proper permissions
chmod 600 /tmp/redis.conf

# Start Redis with the configured file
exec redis-server /tmp/redis.conf