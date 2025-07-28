#!/usr/bin/env bash
# Test HTTP/SSE mode functionality

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}Testing HTTP/SSE Mode${NC}"
echo -e "${BLUE}=====================${NC}\n"

# Check if server is running
echo -e "${YELLOW}1. Checking server status...${NC}"
if ! docker compose ps | grep -q "wazuh-mcp-server.*running"; then
    echo -e "${RED}✗ Server not running${NC}"
    echo -e "Start with: ${YELLOW}docker compose up -d${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Server is running${NC}"

# Wait for server to be ready
echo -e "\n${YELLOW}2. Waiting for HTTP server to be ready...${NC}"
for i in {1..30}; do
    if curl -s http://localhost:3000/health >/dev/null 2>&1; then
        echo -e "${GREEN}✓ HTTP server is ready${NC}"
        break
    fi
    echo -n "."
    sleep 2
done

# Test health endpoint
echo -e "\n${YELLOW}3. Testing health endpoint...${NC}"
response=$(curl -s http://localhost:3000/health || echo "FAILED")
if [[ "$response" == "FAILED" ]]; then
    echo -e "${RED}✗ Health endpoint failed${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Health endpoint responded${NC}"

# Test MCP info endpoint
echo -e "\n${YELLOW}4. Testing MCP info...${NC}"
if curl -s http://localhost:3000/mcp/info >/dev/null 2>&1; then
    echo -e "${GREEN}✓ MCP info endpoint works${NC}"
else
    echo -e "${YELLOW}⚠ MCP info endpoint may not be available${NC}"
fi

# Show server info
echo -e "\n${BLUE}Server Information:${NC}"
echo -e "URL: ${YELLOW}http://localhost:3000${NC}"
echo -e "Health: ${YELLOW}http://localhost:3000/health${NC}"

# Show transport mode
transport=$(docker compose exec -T wazuh-mcp-server env | grep MCP_TRANSPORT | cut -d= -f2 | tr -d '\r' || echo "unknown")
echo -e "Transport: ${YELLOW}${transport}${NC}"

echo -e "\n${GREEN}✓ HTTP/SSE mode test completed successfully!${NC}"