#!/bin/bash
set -e

# Wazuh MCP Server Docker Entrypoint
# Handles initialization and transport mode selection

echo "🐳 Starting Wazuh MCP Server (Docker)"
echo "=================================="

# Show environment info
echo "Python version: $(python3 --version)"
echo "Transport mode: ${MCP_TRANSPORT:-stdio}"
echo "Working directory: $(pwd)"

# Validate critical environment variables
if [[ -z "${WAZUH_HOST}" ]]; then
    echo "❌ ERROR: WAZUH_HOST environment variable is required"
    echo "   Set it with: -e WAZUH_HOST=your-wazuh-server.com"
    exit 1
fi

if [[ -z "${WAZUH_USER}" ]]; then
    echo "❌ ERROR: WAZUH_USER environment variable is required"  
    echo "   Set it with: -e WAZUH_USER=your-api-user"
    exit 1
fi

if [[ -z "${WAZUH_PASS}" ]]; then
    echo "❌ ERROR: WAZUH_PASS environment variable is required"
    echo "   Set it with: -e WAZUH_PASS=your-password"
    exit 1
fi

echo "✅ Required Wazuh configuration found"
echo "   Host: ${WAZUH_HOST}:${WAZUH_PORT:-55000}"
echo "   User: ${WAZUH_USER}"

# Show transport configuration
if [[ "${MCP_TRANSPORT}" == "http" ]] || [[ "$1" == "--http" ]] || [[ "$1" == "--remote" ]]; then
    echo "🌐 HTTP/SSE transport mode"
    echo "   Listening on: ${MCP_HOST:-0.0.0.0}:${MCP_PORT:-3000}"
    echo "   Access URL: http://${MCP_HOST:-localhost}:${MCP_PORT:-3000}"
else
    echo "📱 STDIO transport mode (for Claude Desktop)"
fi

echo "=================================="

# Run production validation (quick check)
echo "🔍 Running quick validation..."
python3 validate-production.py --quick || {
    echo "⚠️  Validation warnings found, but continuing..."
}

# Handle different argument patterns
case "$1" in
    --http|--remote|--server)
        echo "🚀 Starting HTTP/SSE server..."
        export MCP_TRANSPORT=http
        exec ./wazuh-mcp-server --http
        ;;
    --stdio|--local)
        echo "🚀 Starting STDIO server..."
        export MCP_TRANSPORT=stdio
        exec ./wazuh-mcp-server --stdio
        ;;
    --help|-h)
        ./wazuh-mcp-server --help
        exit 0
        ;;
    "")
        # No arguments, use environment variable or default to stdio
        if [[ "${MCP_TRANSPORT}" == "http" ]]; then
            echo "🚀 Starting HTTP/SSE server (from MCP_TRANSPORT env)..."
            exec ./wazuh-mcp-server --http
        else
            echo "🚀 Starting STDIO server (default)..."
            exec ./wazuh-mcp-server --stdio
        fi
        ;;
    *)
        echo "❌ Unknown argument: $1"
        echo "Available options: --http, --stdio, --help"
        exit 1
        ;;
esac