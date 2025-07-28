#!/bin/bash
# One-liner deployment script for Wazuh MCP Server
# Usage: ./quick-deploy.sh WAZUH_HOST WAZUH_USER WAZUH_PASS

set -e

if [ $# -ne 3 ]; then
    echo "Usage: $0 WAZUH_HOST WAZUH_USER WAZUH_PASS"
    echo "Example: $0 wazuh.company.com admin mypassword"
    exit 1
fi

WAZUH_HOST="$1"
WAZUH_USER="$2" 
WAZUH_PASS="$3"

echo "🚀 Quick Deploy: Wazuh MCP Server"
echo "================================"

# Create minimal configuration
cat > .env.wazuh <<EOF
WAZUH_HOST=$WAZUH_HOST
WAZUH_USER=$WAZUH_USER
WAZUH_PASS=$WAZUH_PASS
WAZUH_PORT=55000
MCP_TRANSPORT=http
MCP_HOST=0.0.0.0
MCP_PORT=3000
VERIFY_SSL=true
ENVIRONMENT=production
PYTHONUNBUFFERED=1
EOF

echo "✅ Configuration created"

# Deploy
docker compose down --remove-orphans 2>/dev/null || true
docker compose up -d --build

echo "⏳ Starting server..."
sleep 8

if docker compose ps --services --filter "status=running" | grep -q "wazuh-mcp-server"; then
    echo "🎉 Deployment successful!"
    echo "🌐 Server: http://localhost:3000"
    echo "📋 Logs: docker compose logs -f"
else
    echo "❌ Deployment failed. Check logs: docker compose logs"
    exit 1
fi