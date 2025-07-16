#!/bin/bash
# Redis Sentinel Entrypoint Script - Securely handles password configuration

set -e

# Default Redis password if not provided
REDIS_PASSWORD=${REDIS_PASSWORD:-redis-secret}

# Create temporary config file with password substitution
cp /usr/local/etc/redis/sentinel.conf.template /tmp/sentinel.conf

# Substitute the password placeholder
sed -i "s/\${REDIS_PASSWORD}/$REDIS_PASSWORD/g" /tmp/sentinel.conf

# Generate unique sentinel ID
SENTINEL_ID=$(cat /proc/sys/kernel/random/uuid | tr -d '-')
sed -i "s/\$(cat \/proc\/sys\/kernel\/random\/uuid | tr -d '-')/$SENTINEL_ID/g" /tmp/sentinel.conf

# Ensure proper permissions
chmod 600 /tmp/sentinel.conf

# Start Redis Sentinel with the configured file
exec redis-sentinel /tmp/sentinel.conf "$@"