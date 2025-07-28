#!/bin/bash
# Deploy Wazuh MCP Server using pre-built Docker image
# Usage: ./deploy-prebuilt.sh WAZUH_HOST WAZUH_USER WAZUH_PASS [MCP_PORT]

set -e

if [ $# -lt 3 ] || [ $# -gt 4 ]; then
    echo "Usage: $0 WAZUH_HOST WAZUH_USER WAZUH_PASS [MCP_PORT]"
    echo "Example: $0 wazuh.company.com admin mypassword 3000"
    exit 1
fi

WAZUH_HOST="$1"
WAZUH_USER="$2"
WAZUH_PASS="$3"
MCP_PORT="${4:-3000}"

IMAGE="ghcr.io/gensecaihq/wazuh-mcp-server:latest"
CONTAINER_NAME="wazuh-mcp-server"

echo "🚀 Deploying Wazuh MCP Server (Pre-Built Image)"
echo "==============================================="
echo "Image: $IMAGE"
echo "Wazuh Host: $WAZUH_HOST"
echo "User: $WAZUH_USER"
echo "Port: $MCP_PORT"
echo

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker first."
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "❌ Docker daemon not running. Please start Docker."
    exit 1
fi

echo "✅ Docker is available"

# Stop and remove existing container if it exists
if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "🛑 Stopping existing container..."
    docker stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
    docker rm "$CONTAINER_NAME" >/dev/null 2>&1 || true
fi

# Pull the latest image
echo "📥 Pulling latest image..."
docker pull "$IMAGE"

# Deploy the container
echo "🚀 Starting container..."
docker run -d \
    --name "$CONTAINER_NAME" \
    --restart unless-stopped \
    --init \
    -p "${MCP_PORT}:3000" \
    -e WAZUH_HOST="$WAZUH_HOST" \
    -e WAZUH_USER="$WAZUH_USER" \
    -e WAZUH_PASS="$WAZUH_PASS" \
    -e WAZUH_PORT=55000 \
    -e MCP_TRANSPORT=http \
    -e MCP_HOST=0.0.0.0 \
    -e MCP_PORT=3000 \
    -e VERIFY_SSL=true \
    -e ENVIRONMENT=production \
    -e PYTHONUNBUFFERED=1 \
    -e LOG_LEVEL=INFO \
    --memory=512m \
    --cpus=0.5 \
    "$IMAGE"

echo "⏳ Waiting for server to start..."
sleep 8

# Check if container is running
if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo "✅ Container is running!"
    
    # Test health endpoint
    echo "🏥 Testing health endpoint..."
    for i in {1..5}; do
        if curl -s "http://localhost:${MCP_PORT}/health" >/dev/null 2>&1; then
            echo "✅ Health check passed!"
            break
        elif [ $i -eq 5 ]; then
            echo "⚠️  Health check failed, but container is running"
        else
            echo "   Attempt $i/5... waiting"
            sleep 3
        fi
    done
    
    echo
    echo "🎉 Deployment successful!"
    echo
    echo "📊 Server Information:"
    echo "   🌐 Server URL: http://localhost:${MCP_PORT}"
    echo "   🏥 Health Check: http://localhost:${MCP_PORT}/health"
    echo "   🐳 Container: $CONTAINER_NAME"
    echo
    echo "📋 Management Commands:"
    echo "   View logs:     docker logs -f $CONTAINER_NAME"
    echo "   Stop server:   docker stop $CONTAINER_NAME"
    echo "   Restart:       docker restart $CONTAINER_NAME"
    echo "   Remove:        docker rm -f $CONTAINER_NAME"
    echo
    echo "🧪 Test Commands:"
    echo "   Health check:  curl http://localhost:${MCP_PORT}/health"
    echo "   Run tests:     docker exec $CONTAINER_NAME python3 test-functionality.py"
    echo "   Validation:    docker exec $CONTAINER_NAME python3 validate-production.py --quick"
    echo
else
    echo "❌ Container failed to start. Checking logs..."
    docker logs "$CONTAINER_NAME" --tail=20
    echo
    echo "💡 Troubleshooting:"
    echo "   1. Verify Wazuh host is accessible: ping $WAZUH_HOST"
    echo "   2. Check credentials are correct"
    echo "   3. Review container logs: docker logs $CONTAINER_NAME"
    exit 1
fi