#!/bin/bash
# Redis Entrypoint Script - Securely handles password configuration

set -e

# Default Redis password if not provided
REDIS_PASSWORD=${REDIS_PASSWORD:-redis-secret}

# Create temporary config file with password substitution
cp /usr/local/etc/redis/redis.conf.template /tmp/redis.conf

# Substitute the password placeholder
sed -i "s/\${REDIS_PASSWORD}/$REDIS_PASSWORD/g" /tmp/redis.conf

# Ensure proper permissions
chmod 600 /tmp/redis.conf

# Start Redis with the configured file
exec redis-server /tmp/redis.conf